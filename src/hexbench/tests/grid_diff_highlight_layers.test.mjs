/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Gates BE-1's grid-marking half: `grid.highlight(ranges, className)` must
 * compose the three `is-diff-*` classes onto real rendered cells, at the same
 * time as an unrelated layer (`is-hit`), without one layer clobbering another.
 *
 * This builds a real `HexGrid` against the node model `grid_view_semantics.
 * test.mjs` already uses, trimmed to what a highlight test needs: no keyboard,
 * no resize, no row-width switching. grid.js imports api.js, which reads
 * `document`/`window` at module scope, so both are installed before the
 * dynamic import.
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

  getBoundingClientRect() {
    return { height: 20, width: 800 };
  }
}

const frames = [];
let frameSequence = 0;

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
  getElementById: () => null,
};

const windowStub = {
  location: { search: '' },
  devicePixelRatio: 1,
  requestAnimationFrame(callback) {
    frames.push(callback);
    frameSequence += 1;
    return frameSequence;
  },
  cancelAnimationFrame() {},
  setTimeout(callback) {
    return globalThis.setTimeout(callback, 0);
  },
  clearTimeout(id) {
    globalThis.clearTimeout(id);
  },
  addEventListener() {},
};

class FakeResizeObserver {
  observe() {}
}

const DOCUMENT_LENGTH = 256;
const HANDLE = 'doc-a';

function byteAt(offset) {
  return (offset * 7 + 3) & 0xff;
}

function hexAt(offset) {
  return byteAt(offset).toString(16).toUpperCase().padStart(2, '0');
}

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
  return Promise.resolve({
    ok: true,
    json: () => Promise.resolve({ offset, length, generation: 1, document_length: DOCUMENT_LENGTH, data }),
  });
};

const grid_ = await import('../static/grid.js');
const { BYTES_PER_ROW, HexGrid } = grid_;

const live = new FakeElement('div');
live.setAttribute('id', 'live');
documentStub.getElementById = (id) => (id === 'live' ? live : null);
const root = new FakeElement('div');
body.append(root, live);

const grid = new HexGrid(root, {
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

function* descendants(node) {
  for (const child of node.children) {
    yield child;
    yield* descendants(child);
  }
}

function visibleRows() {
  return viewport.children.filter((row) => row.hidden === false);
}

function hexCellAt(offset) {
  const rowStart = offset - (offset % BYTES_PER_ROW);
  const column = offset - rowStart;
  const row = visibleRows().find((candidate) => candidate.dataset.start === String(rowStart));
  if (row === undefined) {
    return null;
  }
  for (const node of descendants(row)) {
    if (node.dataset.pane === 'hex' && node.dataset.column === String(column)) {
      return node;
    }
  }
  return null;
}

function classesOf(offset) {
  const cell = hexCellAt(offset);
  return cell === null ? [] : cell.className.split(' ').filter((name) => name !== '');
}

/* --------------------------------------------------------------------- BE-1 */

/* Three diff layers plus an unrelated search-hit layer, deliberately
   overlapping at a few bytes, the way a real diff and a real search result
   could coincide on screen at once. */
grid.highlight([{ offset: 0, length: 4 }], 'is-hit');
grid.highlight([{ offset: 2, length: 3 }], 'is-diff-added');
grid.highlight([{ offset: 10, length: 2 }], 'is-diff-removed');
grid.highlight([{ offset: 20, length: 5 }], 'is-diff-modified');
flushFrames();

check(
  'a byte outside every layer carries none of the highlight classes',
  !classesOf(30).some((name) => ['is-hit', 'is-diff-added', 'is-diff-removed', 'is-diff-modified'].includes(name)),
  `byte 30 carries ${classesOf(30).join(' ') || '(nothing)'}`,
);

check(
  'is-diff-added really lands on the grid (the wiring BE-1 is about)',
  classesOf(2).includes('is-diff-added') && classesOf(4).includes('is-diff-added') && !classesOf(5).includes('is-diff-added'),
  `byte 2: ${classesOf(2).join(' ')}; byte 4: ${classesOf(4).join(' ')}; byte 5: ${classesOf(5).join(' ')}`,
);
check(
  'is-diff-removed marks its own range and nowhere else',
  classesOf(10).includes('is-diff-removed') && classesOf(11).includes('is-diff-removed') && !classesOf(12).includes('is-diff-removed'),
  `byte 10: ${classesOf(10).join(' ')}; byte 12: ${classesOf(12).join(' ')}`,
);
check(
  'is-diff-modified marks its own range and nowhere else',
  classesOf(20).includes('is-diff-modified') && classesOf(24).includes('is-diff-modified') && !classesOf(25).includes('is-diff-modified'),
  `byte 20: ${classesOf(20).join(' ')}; byte 25: ${classesOf(25).join(' ')}`,
);

check(
  'the three diff layers compose with an unrelated is-hit layer instead of overwriting it (the defect a single overlay slot would produce)',
  classesOf(2).includes('is-hit') && classesOf(2).includes('is-diff-added'),
  `byte 2, inside both the search-hit range and the added-diff range, carries only "${classesOf(2).join(' ')}"`,
);
check(
  'a byte only in is-hit does not pick up a diff class it was never given',
  classesOf(0).includes('is-hit') && !classesOf(0).includes('is-diff-added') && !classesOf(0).includes('is-diff-removed') && !classesOf(0).includes('is-diff-modified'),
  `byte 0 carries "${classesOf(0).join(' ')}"`,
);

/* Clearing one diff layer (the shape `diffPanel.clearHighlights` and a fresh
   `compare()` both use: an empty range list) must drop only that layer. */
grid.highlight([], 'is-diff-added');
flushFrames();
check(
  'clearing one diff layer with an empty range list drops it and nothing else',
  !classesOf(2).includes('is-diff-added') && classesOf(2).includes('is-hit') && classesOf(10).includes('is-diff-removed') && classesOf(20).includes('is-diff-modified'),
  `after clearing is-diff-added, byte 2 carries "${classesOf(2).join(' ')}", byte 10 carries "${classesOf(10).join(' ')}", byte 20 carries "${classesOf(20).join(' ')}"`,
);

check(
  'hasHighlight reports a layer only while it holds ranges',
  grid.hasHighlight('is-diff-removed') === true && grid.hasHighlight('is-diff-added') === false,
  `hasHighlight('is-diff-removed') = ${grid.hasHighlight('is-diff-removed')}, hasHighlight('is-diff-added') = ${grid.hasHighlight('is-diff-added')}`,
);

/* A second, non-overlapping is-diff-added range (what a re-run compare()
   pushes) must fully replace the first rather than accumulate. */
grid.highlight([{ offset: 40, length: 1 }], 'is-diff-removed');
flushFrames();
check(
  're-calling highlight() for a class replaces its ranges rather than accumulating them',
  classesOf(40).includes('is-diff-removed') && !classesOf(10).includes('is-diff-removed'),
  `after re-highlighting is-diff-removed at byte 40, byte 40 carries "${classesOf(40).join(' ')}" and byte 10 carries "${classesOf(10).join(' ')}"`,
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} grid diff-highlight expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('grid.highlight diff-layer composition (BE-1): all expectations held\n');
