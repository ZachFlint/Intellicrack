/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Gates A-2 (the hex view really is a grid) and UX-4 (the row width is a
 * setting, not a constant).
 *
 * Both done-when checks are about what the running view does - an
 * `aria-activedescendant` that names a live element, a ruler and a row pool
 * that come back at a new width, an ArrowDown that moves by that width - so
 * reading the source as text could not answer either of them. This suite
 * therefore builds the grid for real against a node model, the technique
 * dom_accessibility.test.mjs already uses, extended by the few things a
 * virtualised view needs that a button does not: a `getBoundingClientRect`
 * that derives a row's size from the cells actually in it, frame and timer
 * queues that are flushed on demand instead of by the clock, and a `fetch`
 * standing in for the byte window the server would serve.
 *
 * grid.js imports api.js, which reads `document` and `window` at module scope,
 * which is why both globals are installed before the dynamic import rather
 * than after it. Nothing about the grid itself is stubbed: the class under
 * test is the real one, and every assertion below reads the DOM it produced.
 *
 * Run by gate.ps1 (or directly with node). Exits non-zero on failure.
 */

const failures = [];

function check(label, condition, detail) {
  if (!condition) {
    failures.push(`${label}: ${detail}`);
  }
}

/* ============================================================ the node model */

const ROW_HEIGHT_PX = 20;
const GUTTER_PX = 92;
const PANE_PADDING_PX = 25;
const HEX_CELL_PX = 22;
const ASCII_CELL_PX = 11;
const GROUP_GAP_PX = 7;

class FakeElement {
  constructor(tag) {
    this.localName = tag;
    this.tagName = tag.toUpperCase();
    this.className = '';
    this.textContent = '';
    this.hidden = false;
    this.tabIndex = -1;
    this.children = [];
    this.parent = null;
    this.attributes = new Map();
    this.listeners = new Map();
    this.dataset = {};
    this.style = {};
    this.clientHeight = 0;
    this.clientWidth = 0;
    this.scrollHeight = 0;
    this.scrollTop = 0;
    this.focused = false;
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  removeAttribute(name) {
    this.attributes.delete(name);
  }

  appendChild(node) {
    node.parent = this;
    this.children.push(node);
    return node;
  }

  append(...nodes) {
    for (const node of nodes) {
      this.appendChild(node);
    }
  }

  replaceChildren(...nodes) {
    for (const child of this.children) {
      child.parent = null;
    }
    this.children = [];
    this.append(...nodes);
  }

  remove() {
    if (this.parent === null) {
      return;
    }
    this.parent.children = this.parent.children.filter((node) => node !== this);
    this.parent = null;
  }

  contains(node) {
    for (let walk = node; walk !== null; walk = walk.parent) {
      if (walk === this) {
        return true;
      }
    }
    return false;
  }

  focus() {
    this.focused = true;
  }

  addEventListener(type, handler) {
    const bucket = this.listeners.get(type) ?? [];
    bucket.push(handler);
    this.listeners.set(type, bucket);
  }

  dispatch(type, event) {
    for (const handler of this.listeners.get(type) ?? []) {
      handler(event);
    }
    return event;
  }

  /* A row's size is derived from the cells it actually holds, so the widths the
     grid measures move with the classes it really wrote - including the group
     gap, which is what makes the row width non-linear in single bytes. */
  getBoundingClientRect() {
    let cells = 0;
    let gaps = 0;
    for (const node of descendants(this)) {
      if (node.className.split(' ').includes('hb-byte')) {
        cells += 1;
        if (node.className.split(' ').includes('is-group-end')) {
          gaps += 1;
        }
      }
    }
    return {
      height: ROW_HEIGHT_PX,
      width: GUTTER_PX + PANE_PADDING_PX + cells * (HEX_CELL_PX + ASCII_CELL_PX) + gaps * GROUP_GAP_PX,
    };
  }
}

function* descendants(node) {
  for (const child of node.children) {
    yield child;
    yield* descendants(child);
  }
}

const frames = [];
const timers = new Map();
let frameSequence = 0;
let timerSequence = 0;

function flushFrames() {
  for (let round = 0; round < 8 && frames.length > 0; round += 1) {
    const pending = frames.splice(0, frames.length);
    for (const callback of pending) {
      callback();
    }
  }
  if (frames.length > 0) {
    throw new Error('the grid kept scheduling frames: eight flushes did not settle the view');
  }
}

function runTimers() {
  const pending = [...timers.entries()];
  timers.clear();
  for (const [, callback] of pending) {
    callback();
  }
}

/** Let the fetch promises the grid is holding resolve, then repaint. */
async function settle() {
  for (let round = 0; round < 4; round += 1) {
    await new Promise((resolve) => globalThis.setTimeout(resolve, 0));
    flushFrames();
  }
}

const body = new FakeElement('body');

const documentStub = {
  body,
  createElement: (tag) => new FakeElement(tag),
  querySelector: () => null,
  getElementById(id) {
    for (const node of descendants(body)) {
      if (node.getAttribute('id') === id) {
        return node;
      }
    }
    return null;
  },
};

const windowStub = {
  location: { search: '' },
  devicePixelRatio: 1,
  requestAnimationFrame(callback) {
    frames.push(callback);
    frameSequence += 1;
    return frameSequence;
  },
  cancelAnimationFrame() {
    /* The grid clears its handle itself; nothing here needs to model the
       browser dropping a callback, because no test cancels a frame. */
  },
  setTimeout(callback) {
    timerSequence += 1;
    timers.set(timerSequence, callback);
    return timerSequence;
  },
  clearTimeout(id) {
    timers.delete(id);
  },
  addEventListener() {
    /* The grid listens on window for mouseup only, which no test dispatches. */
  },
};

const resizeCallbacks = [];

class FakeResizeObserver {
  constructor(callback) {
    resizeCallbacks.push(callback);
  }

  observe() {
    /* One grid observes one scroller; `resizeTo` below plays the browser's part
       and calls back everything that is observing. */
  }
}

/* ------------------------------------------------- the document the grid reads */

const DOCUMENT_LENGTH = 4096;
const HANDLE = 'doc-a';
const OTHER_HANDLE = 'doc-b';

function byteAt(offset) {
  return (offset * 7 + 3) & 0xff;
}

function hexAt(offset) {
  return byteAt(offset).toString(16).toUpperCase().padStart(2, '0');
}

let windowReads = 0;

globalThis.document = documentStub;
globalThis.window = windowStub;
globalThis.ResizeObserver = FakeResizeObserver;
globalThis.fetch = (path) => {
  const query = new URLSearchParams(path.slice(path.indexOf('?') + 1));
  const offset = Number(query.get('offset'));
  const length = Math.min(Number(query.get('length')), DOCUMENT_LENGTH - offset);
  let data = '';
  for (let index = 0; index < length; index += 1) {
    data += hexAt(offset + index);
  }
  windowReads += 1;
  return Promise.resolve({
    ok: true,
    json: () => Promise.resolve({ offset, length, generation: 1, document_length: DOCUMENT_LENGTH, data }),
  });
};

const grid_ = await import('../static/grid.js');
const { BYTES_PER_ROW, BYTES_PER_ROW_CHOICES, FIT_TO_WIDTH, HexGrid, caretRowTarget, fitBytesPerRow, normalizeBytesPerRow } = grid_;

/* ============================================== the arithmetic, on its own */

check(
  'caretRowTarget: ArrowDown moves one row at the default width',
  caretRowTarget('ArrowDown', 0, 16, 10) === 16,
  `expected 16, got ${caretRowTarget('ArrowDown', 0, 16, 10)}`,
);
check(
  'caretRowTarget: ArrowDown moves one row at 32 bytes',
  caretRowTarget('ArrowDown', 0, 32, 10) === 32,
  `expected 32, got ${caretRowTarget('ArrowDown', 0, 32, 10)}`,
);
check(
  'caretRowTarget: ArrowUp is the inverse of ArrowDown',
  caretRowTarget('ArrowUp', 96, 24, 10) === 72,
  `expected 72, got ${caretRowTarget('ArrowUp', 96, 24, 10)}`,
);
check(
  'caretRowTarget: Home lands on the start of the row the caret is in',
  caretRowTarget('Home', 77, 24, 10) === 72 && caretRowTarget('Home', 77, 16, 10) === 64,
  `expected 72 and 64, got ${caretRowTarget('Home', 77, 24, 10)} and ${caretRowTarget('Home', 77, 16, 10)}`,
);
check(
  'caretRowTarget: End lands on the last byte of that row',
  caretRowTarget('End', 77, 24, 10) === 95 && caretRowTarget('End', 77, 32, 10) === 95,
  `expected 95 and 95, got ${caretRowTarget('End', 77, 24, 10)} and ${caretRowTarget('End', 77, 32, 10)}`,
);
check(
  'caretRowTarget: a page is a screen of rows at the current width',
  caretRowTarget('PageDown', 0, 32, 20) === 640 && caretRowTarget('PageUp', 640, 32, 20) === 0,
  `expected 640 and 0, got ${caretRowTarget('PageDown', 0, 32, 20)} and ${caretRowTarget('PageUp', 640, 32, 20)}`,
);
check(
  'caretRowTarget: a key that does not move by rows leaves the caret alone',
  caretRowTarget('ArrowLeft', 41, 16, 10) === 41,
  `expected 41, got ${caretRowTarget('ArrowLeft', 41, 16, 10)}`,
);

const narrowProbe = GUTTER_PX + PANE_PADDING_PX + 8 * (HEX_CELL_PX + ASCII_CELL_PX);
const wideProbe = GUTTER_PX + PANE_PADDING_PX + 16 * (HEX_CELL_PX + ASCII_CELL_PX) + GROUP_GAP_PX;

check(
  'fitBytesPerRow: a pane two groups wide takes sixteen bytes',
  fitBytesPerRow(800, narrowProbe, wideProbe) === 16,
  `expected 16, got ${fitBytesPerRow(800, narrowProbe, wideProbe)}`,
);
check(
  'fitBytesPerRow: a wider pane takes more groups',
  fitBytesPerRow(2000, narrowProbe, wideProbe) === 48,
  `expected 48, got ${fitBytesPerRow(2000, narrowProbe, wideProbe)}`,
);
check(
  'fitBytesPerRow: a pane too narrow for one group still renders one',
  fitBytesPerRow(120, narrowProbe, wideProbe) === 8,
  `expected 8, got ${fitBytesPerRow(120, narrowProbe, wideProbe)}`,
);
check(
  'fitBytesPerRow: unusable probes fall back to the default width',
  fitBytesPerRow(800, 400, 400) === BYTES_PER_ROW && fitBytesPerRow(0, narrowProbe, wideProbe) === BYTES_PER_ROW,
  'a degenerate measurement must not produce a zero-wide or negative row',
);
check(
  'normalizeBytesPerRow: the offered widths survive and anything else does not',
  BYTES_PER_ROW_CHOICES.every((width) => normalizeBytesPerRow(width) === width)
    && normalizeBytesPerRow(FIT_TO_WIDTH) === FIT_TO_WIDTH
    && normalizeBytesPerRow(13) === BYTES_PER_ROW
    && normalizeBytesPerRow(undefined) === BYTES_PER_ROW,
  'a stored setting the view cannot honour has to collapse to the default width',
);

/* ================================================== the grid, actually built */

const live = new FakeElement('div');
live.setAttribute('id', 'live');
const root = new FakeElement('div');
body.append(root, live);

const carets = [];
const metrics = [];
const grid = new HexGrid(root, {
  onCaret: (caret) => carets.push(caret),
  onMetrics: (value) => metrics.push(value),
  onError: (error) => {
    failures.push(`the grid reported an error: ${error && error.message ? error.message : error}`);
  },
});

const editor = root.children[0];
const scroller = editor.children[1];
const viewport = scroller.children[1];
scroller.clientHeight = 400;
scroller.clientWidth = 800;

grid.setDocument({ handle: HANDLE, generation: 1, length: DOCUMENT_LENGTH });
flushFrames();
await settle();

function visibleRows() {
  return viewport.children.filter((row) => row.hidden === false);
}

function cellsOf(row, pane) {
  return [...descendants(row)].filter((node) => node.dataset.pane === pane);
}

function activeDescendant() {
  return scroller.getAttribute('aria-activedescendant');
}

function activeCell() {
  const id = activeDescendant();
  return id === null ? null : documentStub.getElementById(id);
}

/** Widen or narrow the pane the way the browser would: resize, then observe. */
async function resizeTo(width) {
  scroller.clientWidth = width;
  for (const callback of resizeCallbacks) {
    callback();
  }
  flushFrames();
  await settle();
}

function press(key, modifiers = {}) {
  let prevented = false;
  scroller.dispatch('keydown', {
    key,
    shiftKey: false,
    ctrlKey: false,
    altKey: false,
    metaKey: false,
    ...modifiers,
    preventDefault() {
      prevented = true;
    },
  });
  flushFrames();
  return prevented;
}

/* ------------------------------------------------------------------- A-2 */

check('the grid rendered rows at all', visibleRows().length > 1, `${visibleRows().length} rows are visible`);
check(
  'the byte window really was read through the api layer',
  windowReads > 0 && visibleRows()[0].children[1].children[0].textContent === hexAt(0),
  `after ${windowReads} window read(s) the first cell reads "${visibleRows()[0].children[1].children[0].textContent}", expected "${hexAt(0)}"`,
);

check(
  'the scroller still declares itself a grid',
  scroller.getAttribute('role') === 'grid' && scroller.getAttribute('aria-label') === 'Hex view',
  `role is ${scroller.getAttribute('role')}`,
);
check(
  'the rows are owned by something a grid may own',
  viewport.getAttribute('role') === 'rowgroup',
  `the element between the grid and its rows carries role ${viewport.getAttribute('role')}`,
);
check(
  'every rendered row is a row',
  visibleRows().every((row) => row.getAttribute('role') === 'row'),
  'a rendered row reached the page without role="row"',
);
check(
  'the rows say where they sit in a document only partly rendered',
  scroller.getAttribute('aria-rowcount') === String(DOCUMENT_LENGTH / BYTES_PER_ROW)
    && visibleRows()[0].getAttribute('aria-rowindex') === '1'
    && visibleRows()[1].getAttribute('aria-rowindex') === '2',
  `rowcount ${scroller.getAttribute('aria-rowcount')}, first two rowindexes `
    + `${visibleRows()[0].getAttribute('aria-rowindex')} and ${visibleRows()[1].getAttribute('aria-rowindex')}`,
);
check(
  'every byte and every glyph is a gridcell',
  visibleRows().every((row) => {
    const cells = [...descendants(row)].filter((node) => node.dataset.column !== undefined);
    return cells.length === BYTES_PER_ROW * 2 && cells.every((cell) => cell.getAttribute('role') === 'gridcell');
  }),
  'a rendered cell has no gridcell role',
);
check(
  'the panes inside a row do not stand between a row and its cells',
  visibleRows().every((row) => row.children[1].getAttribute('role') === 'presentation' && row.children[2].getAttribute('role') === 'presentation'),
  'the hex or ASCII pane is a generic element inside the row, which orphans every cell in it',
);
check(
  'the offset gutter is the row header',
  visibleRows().every((row) => row.children[0].getAttribute('role') === 'rowheader'),
  'the offset column has no rowheader role',
);

const allIds = [...descendants(body)].map((node) => node.getAttribute('id')).filter((id) => id !== null);
check(
  'no two elements claim the same id',
  new Set(allIds).size === allIds.length,
  `${allIds.length} ids but only ${new Set(allIds).size} distinct: a recycled row is still claiming offsets a visible row owns`,
);

check(
  'the caret starts on a live cell',
  activeCell() !== null && activeCell().dataset.column === '0' && activeCell().textContent === hexAt(0),
  `aria-activedescendant is ${activeDescendant()}, which resolves to ${activeCell() === null ? 'nothing' : activeCell().textContent}`,
);

const startId = activeDescendant();
check('ArrowRight is claimed by the grid', press('ArrowRight'), 'ArrowRight was left to the browser');
check(
  'a nibble step keeps the caret on the same cell',
  activeDescendant() === startId,
  `stepping to the low nibble moved aria-activedescendant from ${startId} to ${activeDescendant()}`,
);

press('ArrowRight');
check(
  'crossing a byte boundary moves aria-activedescendant to the next live cell',
  activeDescendant() !== startId && activeCell() !== null && activeCell().textContent === hexAt(1),
  `aria-activedescendant is ${activeDescendant()}, resolving to ${activeCell() === null ? 'nothing' : activeCell().textContent}, expected the cell reading ${hexAt(1)}`,
);

press('ArrowDown');
check(
  'arrowing down moves aria-activedescendant to a live element on the next row',
  activeCell() !== null
    && activeCell().textContent === hexAt(1 + BYTES_PER_ROW)
    && activeCell().parent.parent.getAttribute('aria-rowindex') === '2',
  `aria-activedescendant is ${activeDescendant()}, resolving to ${activeCell() === null ? 'nothing' : activeCell().textContent}`,
);
check(
  'the caret the grid publishes agrees with the cell it points at',
  grid.caret.offset === 1 + BYTES_PER_ROW,
  `caret offset ${grid.caret.offset}, expected ${1 + BYTES_PER_ROW}`,
);

runTimers();
check(
  'the caret is spoken through the one live region, offset and byte value together',
  live.textContent.includes(`0x${(1 + BYTES_PER_ROW).toString(16).toUpperCase().padStart(8, '0')}`)
    && live.textContent.includes(`byte ${hexAt(1 + BYTES_PER_ROW)}`)
    && live.textContent.includes('hex pane'),
  `the live region says "${live.textContent}"`,
);

const spokenOnce = live.textContent;
press('ArrowDown');
press('ArrowDown');
check(
  'the description is held back until the caret stops',
  live.textContent === spokenOnce,
  'the live region was rewritten on every keystroke instead of once the caret settled',
);
runTimers();
check(
  'and then describes where the caret ended up',
  live.textContent.includes(`byte ${hexAt(1 + BYTES_PER_ROW * 3)}`),
  `the live region says "${live.textContent}", expected the byte at offset ${1 + BYTES_PER_ROW * 3}`,
);

const beforeToggle = live.textContent;
grid.togglePane();
flushFrames();
runTimers();
check(
  'switching panes moves the active descendant into the ASCII pane and says so',
  activeCell() !== null && activeCell().dataset.pane === 'ascii' && live.textContent.includes('ascii pane') && live.textContent !== beforeToggle,
  `aria-activedescendant is ${activeDescendant()} and the live region says "${live.textContent}"`,
);
grid.togglePane();
flushFrames();

/* ------------------------------------------------------------------ UX-4 */

check(
  'the view starts at the compiled default',
  grid.bytesPerRow === BYTES_PER_ROW && grid.bytesPerRowSetting === BYTES_PER_ROW,
  `bytesPerRow ${grid.bytesPerRow}, setting ${grid.bytesPerRowSetting}`,
);

const rulerColumnsOf = () => editor.children[0].children[1].children;
check(
  'the ruler starts sixteen columns wide',
  rulerColumnsOf().length === BYTES_PER_ROW && rulerColumnsOf()[15].textContent === '0F',
  `${rulerColumnsOf().length} ruler columns, the last reading ${rulerColumnsOf()[rulerColumnsOf().length - 1].textContent}`,
);

grid.seek(0);
flushFrames();
await settle();
grid.bytesPerRowSetting = 32;
flushFrames();
await settle();

check(
  'the setting took',
  grid.bytesPerRow === 32 && grid.bytesPerRowSetting === 32,
  `bytesPerRow ${grid.bytesPerRow}, setting ${grid.bytesPerRowSetting}`,
);
check(
  'the ruler came back thirty-two columns wide',
  rulerColumnsOf().length === 32 && rulerColumnsOf()[31].textContent === '1F' && rulerColumnsOf()[7].className.includes('is-group-end'),
  `${rulerColumnsOf().length} ruler columns, the last reading ${rulerColumnsOf()[rulerColumnsOf().length - 1].textContent}`,
);
check(
  'the rows came back thirty-two bytes wide, in both panes',
  visibleRows().every((row) => cellsOf(row, 'hex').length === 32 && cellsOf(row, 'ascii').length === 32),
  `the first row holds ${cellsOf(visibleRows()[0], 'hex').length} hex cells and ${cellsOf(visibleRows()[0], 'ascii').length} glyphs`,
);
check(
  'the second row now starts a whole thirty-two bytes in',
  visibleRows()[1].children[0].textContent === '00000020' && visibleRows()[1].children[1].children[0].textContent === hexAt(32),
  `the second row is labelled ${visibleRows()[1].children[0].textContent} and opens with ${visibleRows()[1].children[1].children[0].textContent}`,
);
check(
  'the grid restated its shape to assistive technology',
  scroller.getAttribute('aria-colcount') === '65' && scroller.getAttribute('aria-rowcount') === String(DOCUMENT_LENGTH / 32),
  `colcount ${scroller.getAttribute('aria-colcount')}, rowcount ${scroller.getAttribute('aria-rowcount')}`,
);

check('the caret is back at the start of the document', grid.caret.offset === 0, `caret offset ${grid.caret.offset}`);
press('ArrowDown');
check(
  'ArrowDown moves thirty-two bytes',
  grid.caret.offset === 32,
  `caret offset ${grid.caret.offset}, expected 32`,
);
check(
  'and lands on the live cell that shows byte 0x20',
  activeCell() !== null && activeCell().textContent === hexAt(32) && activeCell().dataset.column === '0',
  `aria-activedescendant is ${activeDescendant()}, resolving to ${activeCell() === null ? 'nothing' : activeCell().textContent}`,
);
press('End');
check(
  'End walks to the last byte of a thirty-two byte row',
  grid.caret.offset === 63,
  `caret offset ${grid.caret.offset}, expected 63`,
);
press('Home');
check(
  'Home walks back to its first',
  grid.caret.offset === 32,
  `caret offset ${grid.caret.offset}, expected 32`,
);

const idsAfterResize = [...descendants(body)].map((node) => node.getAttribute('id')).filter((id) => id !== null);
check(
  'the rebuilt pool left no id behind',
  new Set(idsAfterResize).size === idsAfterResize.length,
  `${idsAfterResize.length} ids but only ${new Set(idsAfterResize).size} distinct after the row width changed`,
);
check(
  'the metrics report the width the view is really using',
  metrics[metrics.length - 1].bytesPerRow === 32 && metrics[metrics.length - 1].bytesPerRowSetting === 32,
  `the last metrics carried bytesPerRow ${metrics[metrics.length - 1].bytesPerRow}`,
);

/* -------------------------------------------------- persistence per document */

grid.setDocument({ handle: OTHER_HANDLE, generation: 1, length: DOCUMENT_LENGTH });
flushFrames();
await settle();
check(
  'a second document opens at the default width, not the first document\'s',
  grid.bytesPerRow === BYTES_PER_ROW && rulerColumnsOf().length === BYTES_PER_ROW,
  `bytesPerRow ${grid.bytesPerRow} with ${rulerColumnsOf().length} ruler columns`,
);

grid.setDocument({ handle: HANDLE, generation: 1, length: DOCUMENT_LENGTH });
flushFrames();
await settle();
check(
  'coming back to the first document restores the width it was read at',
  grid.bytesPerRow === 32 && rulerColumnsOf().length === 32 && cellsOf(visibleRows()[0], 'hex').length === 32,
  `bytesPerRow ${grid.bytesPerRow} with ${rulerColumnsOf().length} ruler columns`,
);

/* ---------------------------------------------------------- fit to width */

grid.bytesPerRowSetting = FIT_TO_WIDTH;
flushFrames();
await settle();
check(
  'fit-to-width measures the pane it has',
  grid.bytesPerRowSetting === FIT_TO_WIDTH && grid.bytesPerRow === 16,
  `an 800px pane fitted ${grid.bytesPerRow} bytes`,
);

await resizeTo(2000);
check(
  'and follows the pane when it grows',
  grid.bytesPerRow === 48 && rulerColumnsOf().length === 48 && cellsOf(visibleRows()[0], 'hex').length === 48,
  `a 2000px pane fitted ${grid.bytesPerRow} bytes with ${rulerColumnsOf().length} ruler columns`,
);
press('ArrowDown');
check(
  'a fitted row is a real row: ArrowDown moves by the fitted width',
  grid.caret.offset % 48 === 0 && grid.caret.offset > 0,
  `caret offset ${grid.caret.offset}, expected a multiple of 48`,
);

await resizeTo(800);
check(
  'and back down again',
  grid.bytesPerRow === 16 && cellsOf(visibleRows()[0], 'hex').length === 16,
  `a re-narrowed pane fitted ${grid.bytesPerRow} bytes`,
);

check(
  'the caret never stopped being published while all of that happened',
  carets.length > 0 && carets[carets.length - 1].pane === 'hex',
  `${carets.length} caret events, the last on pane ${carets.length > 0 ? carets[carets.length - 1].pane : 'none'}`,
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} grid view-semantics expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('grid view semantics (A-2, UX-4): all expectations held\n');
