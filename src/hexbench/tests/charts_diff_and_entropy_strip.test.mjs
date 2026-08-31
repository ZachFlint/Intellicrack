/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Gates the pixel-level halves of BE-1 (the Diff panel's mini-map) and UX-1
 * (the live Entropy panel's caret strip): both are canvas, per the design
 * handoff's own rule that geometry is the spec and pixels are a sketch, so
 * this suite records every drawing call a real render makes and checks the
 * geometry rather than a screenshot.
 *
 * charts.js has no module-level DOM access, so the stub is assembled before a
 * dynamic import and is rich enough to answer a real render: a canvas 2d
 * context that records every call instead of drawing, a `getComputedStyle`
 * that hands back the design system's own light-palette values so drawn
 * colours can be told apart, and a `requestAnimationFrame` that runs
 * synchronously so `mountChart`'s first paint happens inside this script
 * rather than on a tick node never gets to run.
 *
 * Run by gate.ps1. Exits non-zero on the first failed expectation.
 */

const failures = [];

function check(label, condition, detail) {
  if (!condition) {
    failures.push(`${label}: ${detail}`);
  }
}

/* ------------------------------------------------------------- the document */

class FakeStyle {
  constructor() {
    this.properties = new Map();
  }

  setProperty(name, value) {
    this.properties.set(name, String(value));
  }

  getPropertyValue(name) {
    return this.properties.get(name) ?? '';
  }
}

/** A 2d context that records what was drawn instead of drawing it. */
class RecordingContext {
  constructor() {
    this.calls = [];
    this._fillStyle = '';
    this._strokeStyle = '';
    this._lineWidth = 1;
  }

  set fillStyle(value) {
    this._fillStyle = value;
  }

  get fillStyle() {
    return this._fillStyle;
  }

  set strokeStyle(value) {
    this._strokeStyle = value;
  }

  get strokeStyle() {
    return this._strokeStyle;
  }

  set lineWidth(value) {
    this._lineWidth = value;
  }

  get lineWidth() {
    return this._lineWidth;
  }

  setTransform() {}

  clearRect() {}

  fillRect(x, y, w, h) {
    this.calls.push({ op: 'fillRect', x, y, w, h, fillStyle: this._fillStyle });
  }

  beginPath() {
    this.calls.push({ op: 'beginPath' });
  }

  closePath() {}

  moveTo(x, y) {
    this.calls.push({ op: 'moveTo', x, y });
  }

  lineTo(x, y) {
    this.calls.push({ op: 'lineTo', x, y });
  }

  stroke() {
    this.calls.push({ op: 'stroke', strokeStyle: this._strokeStyle, lineWidth: this._lineWidth });
  }

  fill() {
    this.calls.push({ op: 'fill', fillStyle: this._fillStyle });
  }

  fillText(text, x, y) {
    this.calls.push({ op: 'fillText', text, x, y });
  }

  measureText(text) {
    return { width: String(text).length * 6 };
  }

  save() {}

  restore() {}

  setLineDash() {}

  drawImage() {}

  putImageData() {}

  createImageData(width, height) {
    return { data: new Uint8ClampedArray(width * height * 4) };
  }
}

class FakeElement {
  constructor(tag) {
    this.tagName = String(tag).toLowerCase();
    this.className = '';
    this.textContent = '';
    this.children = [];
    this.style = new FakeStyle();
    this.attributes = new Map();
    this.listeners = new Map();
    this.isConnected = true;
    if (this.tagName === 'canvas') {
      this.context = new RecordingContext();
    }
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  append(...nodes) {
    for (const node of nodes) {
      this.children.push(node);
    }
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
  }

  getContext() {
    return this.context;
  }

  getBoundingClientRect() {
    return { left: 0, top: 0, width: 640, height: 120 };
  }
}

class FakeObserver {
  observe() {}

  disconnect() {}
}

globalThis.document = {
  createElement: (tag) => new FakeElement(tag),
  documentElement: new FakeElement('html'),
  getElementById: () => null,
};
globalThis.window = {
  devicePixelRatio: 1,
  matchMedia: () => ({ addEventListener: () => undefined }),
};
globalThis.MutationObserver = FakeObserver;
globalThis.ResizeObserver = FakeObserver;
globalThis.requestAnimationFrame = (callback) => {
  callback();
  return 0;
};

const { CHART_TOKEN_FALLBACKS, diffTrackChart, entropyStripChart } = await import('../static/charts.js');

/* Every token these charts read resolves to the light palette's own value, so
   a fillRect/stroke recorded against `--hb-diff-added-bg` can be told apart
   from one recorded against `--hb-diff-removed-bg` without normalising colour
   notation. */
globalThis.getComputedStyle = () => ({
  getPropertyValue: (token) => CHART_TOKEN_FALLBACKS.get(token) ?? '',
});

function findCanvas(root) {
  for (const child of root.children) {
    if (child.tagName === 'canvas') {
      return child;
    }
    const nested = findCanvas(child);
    if (nested !== null) {
      return nested;
    }
  }
  return null;
}

function findAll(root, predicate) {
  const found = [];
  const walk = (node) => {
    if (predicate(node)) {
      found.push(node);
    }
    for (const child of node.children ?? []) {
      walk(child);
    }
  };
  walk(root);
  return found;
}

function near(actual, expected, tolerance = 1) {
  return Math.abs(actual - expected) <= tolerance;
}

/* ================================================================== BE-1 */
/* diffTrackChart: the Diff panel's mini-map. Geometry per the design
   handoff's Diff spec: 34px bands on --hb-surface-inset, positioned by
   offset, using the diff background tokens plus the A-8 shape marks, and a
   2px accent caret line overhanging the bands 2px top and bottom. */

const ADDED_BG = CHART_TOKEN_FALLBACKS.get('--hb-diff-added-bg');
const REMOVED_BG = CHART_TOKEN_FALLBACKS.get('--hb-diff-removed-bg');
const MODIFIED_BG = CHART_TOKEN_FALLBACKS.get('--hb-diff-modified-bg');
const SUCCESS = CHART_TOKEN_FALLBACKS.get('--hb-success');
const ERROR = CHART_TOKEN_FALLBACKS.get('--hb-error');
const WARNING = CHART_TOKEN_FALLBACKS.get('--hb-warning');
const ACCENT = CHART_TOKEN_FALLBACKS.get('--hb-accent');
const SURFACE_INSET = CHART_TOKEN_FALLBACKS.get('--hb-surface-inset');

const SPAN = 1000;
const regions = [
  { diff_type: 'inserted_b', offset_a: 0, length: 100 }, // added, at the start
  { diff_type: 'inserted_a', offset_a: 400, length: 50 }, // removed, mid-span
  { diff_type: 'modified', offset_a: 700, length: 200 }, // modified, near the end
  { diff_type: 'match', offset_a: 950, length: 50 }, // must never reach the strip at all
];

let pickedRegion = null;
const track = diffTrackChart(regions, { span: SPAN, caretOffset: 500, onPick: (region) => { pickedRegion = region; } });
const trackCanvas = findCanvas(track.element);

check('diffTrackChart mounted a real canvas', trackCanvas !== null, 'no <canvas> element was found in the mini-map tree');

const TOTAL_HEIGHT = 38; // 34px band + 2px overhang top and bottom
check(
  'the mini-map is 34px of band inside a 38px frame (2px caret overhang top and bottom)',
  trackCanvas.style.height === `${TOTAL_HEIGHT}px`,
  `canvas.style.height is "${trackCanvas.style.height}", expected "${TOTAL_HEIGHT}px"`,
);

const trackCalls = trackCanvas.context.calls;
const backgroundFill = trackCalls.find((call) => call.op === 'fillRect' && call.fillStyle === SURFACE_INSET);
check(
  'the mini-map is painted on --hb-surface-inset',
  backgroundFill !== undefined && backgroundFill.x === 0 && backgroundFill.y === 0 && backgroundFill.w === 640 && backgroundFill.h === TOTAL_HEIGHT,
  `expected a full-frame fillRect on ${SURFACE_INSET}, got ${JSON.stringify(backgroundFill)}`,
);

const addedBand = trackCalls.find((call) => call.op === 'fillRect' && call.fillStyle === ADDED_BG);
check(
  'the added region is banded at its offset, using --hb-diff-added-bg',
  addedBand !== undefined && near(addedBand.x, 0) && near(addedBand.w, 64) && addedBand.y === 2 && addedBand.h === 34,
  `expected a band near x=0 w=64 y=2 h=34, got ${JSON.stringify(addedBand)}`,
);
const removedBand = trackCalls.find((call) => call.op === 'fillRect' && call.fillStyle === REMOVED_BG);
check(
  'the removed region is banded at its offset (400/1000 of the span), using --hb-diff-removed-bg',
  removedBand !== undefined && near(removedBand.x, 256) && near(removedBand.w, 32),
  `expected a band near x=256 w=32, got ${JSON.stringify(removedBand)}`,
);
const modifiedBand = trackCalls.find((call) => call.op === 'fillRect' && call.fillStyle === MODIFIED_BG);
check(
  'the modified region is banded at its offset (700/1000 of the span), using --hb-diff-modified-bg',
  modifiedBand !== undefined && near(modifiedBand.x, 448) && near(modifiedBand.w, 128),
  `expected a band near x=448 w=128, got ${JSON.stringify(modifiedBand)}`,
);

check(
  'a match region never reaches the mini-map (it is the absence of a mark, not a fourth kind)',
  trackCalls.filter((call) => call.op === 'fillRect').length === 5, // background + added band + removed band + modified band + the added shape's left bar
  `expected exactly 5 fillRect calls (background, three bands, the added shape's left bar) with no fourth band for the match region, got ${trackCalls.filter((call) => call.op === 'fillRect').length}`,
);

const addedShapeBar = trackCalls.filter((call) => call.op === 'fillRect' && call.fillStyle === SUCCESS)[0];
check(
  'the added region carries the A-8 shape mark too: a 3px left bar in --hb-success, not colour alone',
  addedShapeBar !== undefined && near(addedShapeBar.x, 0) && addedShapeBar.w <= 3,
  `expected a <=3px bar near x=0 in ${SUCCESS}, got ${JSON.stringify(addedShapeBar)}`,
);
const removedStroke = trackCalls.find((call) => call.op === 'stroke' && call.strokeStyle === ERROR);
check(
  'the removed region carries its A-8 shape mark: a strike stroked in --hb-error',
  removedStroke !== undefined,
  `expected a stroke() call with strokeStyle ${ERROR}, found none among ${JSON.stringify(trackCalls.filter((call) => call.op === 'stroke'))}`,
);
const modifiedStroke = trackCalls.find((call) => call.op === 'stroke' && call.strokeStyle === WARNING);
check(
  'the modified region carries its A-8 shape mark: a double underline stroked in --hb-warning',
  modifiedStroke !== undefined,
  `expected a stroke() call with strokeStyle ${WARNING}, found none`,
);
const modifiedMoveTos = trackCalls.filter((call) => call.op === 'moveTo' && near(call.x, 448));
check(
  'the modified mark really is drawn as two lines (a double underline), not one',
  modifiedMoveTos.length === 2 && modifiedMoveTos[0].y !== modifiedMoveTos[1].y,
  `expected two moveTo calls at different y values near x=448, got ${JSON.stringify(modifiedMoveTos)}`,
);

const caretStroke = trackCalls.find((call) => call.op === 'stroke' && call.strokeStyle === ACCENT);
check(
  'the caret line is stroked in --hb-accent',
  caretStroke !== undefined && caretStroke.lineWidth === 2,
  `expected a 2px stroke in ${ACCENT}, got ${JSON.stringify(caretStroke)}`,
);
const caretMoveTo = trackCalls.find((call) => call.op === 'moveTo' && near(call.x, 320));
check(
  'the caret line sits at the caret offset (500/1000 of the span) and overhangs the full frame height',
  caretMoveTo !== undefined && caretMoveTo.y === 0,
  `expected the caret's moveTo near x=320 y=0, found ${JSON.stringify(trackCalls.filter((call) => call.op === 'moveTo'))}`,
);
const caretLineTo = trackCalls.find((call) => call.op === 'lineTo' && near(call.x, 320) && call.y === TOTAL_HEIGHT);
check(
  'the caret line runs the full 38px frame, overhanging the 34px band by 2px top and bottom',
  caretLineTo !== undefined,
  `expected a lineTo at x=320 y=${TOTAL_HEIGHT}, found ${JSON.stringify(trackCalls.filter((call) => call.op === 'lineTo'))}`,
);

/* Clicking a point inside the removed region's pixel range must resolve to
   that exact region - the mini-map's half of "clicking a region navigates
   the grid to it". */
trackCanvas.dispatch('click', { clientX: 270, clientY: 19 });
check(
  'clicking the strip inside a region\'s pixel range resolves to that region',
  pickedRegion !== null && pickedRegion.diff_type === 'inserted_a' && pickedRegion.offset_a === 400,
  `expected the removed region (offset_a 400), got ${JSON.stringify(pickedRegion)}`,
);

/* setCaret moves the marker without rebuilding the chart - the mechanism
   entropyPanel and the Diff panel both lean on so an arrow key or a document
   switch does not pay for a canvas teardown. */
const callsBeforeMove = trackCalls.length;
track.setCaret(900);
const newCaretMoveTo = trackCalls.slice(callsBeforeMove).find((call) => call.op === 'moveTo' && near(call.x, 576));
check(
  'setCaret repaints the caret line at its new offset (900/1000 of the span)',
  newCaretMoveTo !== undefined,
  `expected a fresh moveTo near x=576 after setCaret(900), found ${JSON.stringify(trackCalls.slice(callsBeforeMove))}`,
);

track.chart.destroy();

/* ================================================================== UX-1 */
/* entropyStripChart: the live per-caret Entropy panel body. Spec: a 92px
   canvas strip, a 1px accent vertical line at the caret with a small filled
   "caret" label at the top, and a caption "peak <v> at <offset> - mean <v> -
   click the strip to jump". */

const ENTROPY_BLOCK = 256;
const values = [1.2, 3.4, 7.9, 2.1, 0.5]; // peak at index 2 (7.9), mean 3.02
let seekOffset = null;
const strip = entropyStripChart(values, {
  blockSize: ENTROPY_BLOCK,
  documentLength: values.length * ENTROPY_BLOCK,
  caretOffset: 2 * ENTROPY_BLOCK + 10, // inside block index 2
  onSeek: (offset) => { seekOffset = offset; },
});
const stripCanvas = findCanvas(strip.element);

check('entropyStripChart mounted a real canvas', stripCanvas !== null, 'no <canvas> element was found in the entropy strip tree');
check(
  'the strip is 92px tall, per the Entropy dock-panel spec',
  stripCanvas.style.height === '92px',
  `canvas.style.height is "${stripCanvas.style.height}", expected "92px"`,
);

const captionNode = findAll(strip.element, (node) => String(node.className ?? '').split(/\s+/).includes('hb-canvasframe-caption'))[0];
check(
  'the caption reports the peak, its offset, the mean, and the click affordance',
  captionNode !== undefined && captionNode.textContent === 'peak 7.90 at 0x00000200 · mean 3.02 · click the strip to jump',
  `caption reads "${captionNode ? captionNode.textContent : '(none)'}"`,
);

const metaNode = findAll(strip.element, (node) => String(node.className ?? '').split(/\s+/).includes('hb-canvasframe-meta'))[0];
check(
  'the frame header names the range: 0.00 to 8.00 bits',
  metaNode !== undefined && metaNode.textContent === '0.00 – 8.00 bits',
  `meta reads "${metaNode ? metaNode.textContent : '(none)'}"`,
);
const titleNode = findAll(strip.element, (node) => node.tagName === 'span' && node.textContent === 'Shannon entropy')[0];
check('the frame is headed "Shannon entropy"', titleNode !== undefined, 'no header span reading "Shannon entropy" was found');

const axisNode = findAll(strip.element, (node) => String(node.className ?? '').split(/\s+/).includes('hb-axis'))[0];
check(
  'an hb-axis below the frame carries three offsets: start, middle, end',
  axisNode !== undefined && axisNode.children.length === 3
    && axisNode.children[0].textContent === '0x00000000'
    && axisNode.children[2].textContent === `0x${(values.length * ENTROPY_BLOCK).toString(16).toUpperCase().padStart(8, '0')}`,
  `axis children: ${axisNode ? JSON.stringify(axisNode.children.map((node) => node.textContent)) : '(none)'}`,
);

const STRIP_HEIGHT = 92;

/**
 * Find a vertical `moveTo(x, 0)` / `lineTo(x, STRIP_HEIGHT)` pair, stroked in
 * `--hb-accent`, among the calls recorded since `since`.
 *
 * `--hb-chart-line` (the entropy curve itself) happens to share `--hb-accent`'s
 * light-palette value, so matching on colour alone cannot tell the caret's
 * full-height vertical line apart from the curve's own stroke.
 */
function findCaretLine(calls, since = 0) {
  const window = calls.slice(since);
  for (let index = 0; index < window.length; index += 1) {
    const move = window[index];
    if (move.op !== 'moveTo' || move.y !== 0) {
      continue;
    }
    const line = window[index + 1];
    if (line === undefined || line.op !== 'lineTo' || line.x !== move.x || line.y !== STRIP_HEIGHT) {
      continue;
    }
    for (let ahead = index + 2; ahead < window.length; ahead += 1) {
      const stroke = window[ahead];
      if (stroke.op === 'beginPath') {
        break;
      }
      if (stroke.op === 'stroke' && stroke.strokeStyle === ACCENT) {
        return move;
      }
    }
  }
  return undefined;
}

const stripCalls = stripCanvas.context.calls;
const caretLine = findCaretLine(stripCalls);
check(
  'the caret is a 1px --hb-accent vertical line spanning the full 92px strip',
  caretLine !== undefined,
  `expected a moveTo(x,0)/lineTo(x,92) pair stroked in ${ACCENT}, got ${JSON.stringify(stripCalls)}`,
);
const caretLabel = stripCalls.find((call) => call.op === 'fillText' && call.text === 'caret');
check(
  'a small filled "caret" label sits at the top of the marker',
  caretLabel !== undefined && caretLabel.y < 16,
  `expected a fillText("caret", ..., y<16), got ${JSON.stringify(caretLabel)}`,
);

/* The caret index resolves from the caret offset through the block size:
   caretOffset 2*256+10 falls in block 2, so the line sits at block 2's x. */
const EXPECTED_CARET_X = (2 / (values.length - 1)) * 640;
check(
  'the caret line is positioned at the block the caret offset falls in',
  caretLine !== undefined && near(caretLine.x, EXPECTED_CARET_X + 0.5),
  `expected the caret line near x=${(EXPECTED_CARET_X + 0.5).toFixed(1)}, got x=${caretLine ? caretLine.x : '(none)'}`,
);

/* Clicking the strip moves the caret - UX-1's own done-when line. */
stripCanvas.dispatch('click', { clientX: 0, clientY: 40 });
check(
  'clicking the strip calls the seek callback (moves the caret)',
  seekOffset === 0,
  `expected onSeek(0) from a click at x=0, got ${seekOffset}`,
);

const callsBeforeSetCaret = stripCalls.length;
strip.setCaret(4 * ENTROPY_BLOCK);
const movedCaretLine = findCaretLine(stripCalls, callsBeforeSetCaret);
const EXPECTED_MOVED_X = 640; // block 4 of 5, the last point on the strip
check(
  'setCaret repaints the marker at its new position, without rebuilding the chart',
  movedCaretLine !== undefined && near(movedCaretLine.x, EXPECTED_MOVED_X + 0.5),
  `expected a fresh caret line near x=${EXPECTED_MOVED_X + 0.5} after setCaret(4*block), got ${movedCaretLine ? movedCaretLine.x : '(none)'}`,
);

const callsBeforeClear = stripCalls.length;
strip.setCaret(null);
const clearedCaretLine = findCaretLine(stripCalls, callsBeforeClear);
check(
  'setCaret(null) removes the marker (the panel\'s "no document" / no-caret state)',
  clearedCaretLine === undefined,
  `a caret line was still drawn after setCaret(null): ${JSON.stringify(stripCalls.slice(callsBeforeClear))}`,
);

strip.chart.destroy();

if (failures.length > 0) {
  process.stdout.write(`${failures.length} diff-track/entropy-strip geometry expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('diff mini-map and entropy strip geometry (BE-1, UX-1): all expectations held\n');
