/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Gates the byte histogram's move off canvas and onto elements, and gates the
 * text alternative the four charts that stay on canvas owe in exchange.
 *
 * histogramChart builds its markup through dom.js's element(), which reaches
 * for `document` only when it is called, so charts.js still imports under bare
 * node - but the chart itself cannot be built without a document. The stub
 * below is therefore assembled before a dynamic import (a static import would
 * hoist above it) and is rich enough to record a real tree: tag names, class
 * names, custom properties, titles and event listeners, so the assertions run
 * against what histogramChart actually built rather than against the stub.
 *
 * The stub deliberately answers the canvas surface too - getContext, the two
 * observers, matchMedia, requestAnimationFrame - even though a DOM histogram
 * needs none of it. That is so a revert to the canvas implementation gets far
 * enough to be caught by the "no canvas element anywhere" expectation below and
 * reported as a failed expectation, instead of dying on a missing global.
 *
 * Run by gate.ps1. Exits non-zero on the first failed expectation.
 */

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

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

const canvasContext = {
  setTransform: () => undefined,
  clearRect: () => undefined,
  fillRect: () => undefined,
  beginPath: () => undefined,
  moveTo: () => undefined,
  lineTo: () => undefined,
  stroke: () => undefined,
  fillText: () => undefined,
  drawImage: () => undefined,
  putImageData: () => undefined,
  createImageData: (width, height) => ({ data: new Uint8ClampedArray(width * height * 4) }),
};

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

  dispatch(type) {
    for (const handler of this.listeners.get(type) ?? []) {
      handler({ type });
    }
  }

  getContext() {
    return canvasContext;
  }

  getBoundingClientRect() {
    return { left: 0, top: 0, width: 640, height: 120 };
  }
}

class FakeObserver {
  observe() {
    return undefined;
  }

  disconnect() {
    return undefined;
  }
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
globalThis.getComputedStyle = () => ({ getPropertyValue: () => '' });
globalThis.MutationObserver = FakeObserver;
globalThis.ResizeObserver = FakeObserver;
globalThis.requestAnimationFrame = () => 0;

function walk(node, visit) {
  visit(node);
  for (const child of node.children ?? []) {
    walk(child, visit);
  }
}

function collect(root, predicate) {
  const found = [];
  walk(root, (node) => {
    if (predicate(node)) {
      found.push(node);
    }
  });
  return found;
}

function classesOf(node) {
  return String(node.className ?? '').split(/\s+/).filter((name) => name !== '');
}

function hasClass(node, name) {
  return classesOf(node).includes(name);
}

/** Slice out a `{ ... }` block whose header pattern ends on the opening brace. */
function extractBlock(source, headerPattern) {
  const match = source.match(headerPattern);
  if (match === null) {
    throw new Error(`pattern not found in charts.js: ${headerPattern}`);
  }
  const braceStart = match.index + match[0].length - 1;
  let depth = 1;
  let index = braceStart + 1;
  while (depth > 0 && index < source.length) {
    if (source[index] === '{') {
      depth += 1;
    } else if (source[index] === '}') {
      depth -= 1;
    }
    index += 1;
  }
  return source.slice(match.index, index);
}

const staticDir = fileURLToPath(new URL('../static/', import.meta.url));
const chartsSource = await readFile(`${staticDir}charts.js`, 'utf8');

const { byteTypeChart, histogramChart } = await import('../static/charts.js');

/* ------------------------------------------------- the histogram is elements */

const realistic = new Array(256).fill(0);
realistic[0x00] = 128;
realistic[0x09] = 12;
realistic[0x0a] = 96;
for (let value = 0x20; value < 0x7f; value += 1) {
  realistic[value] = 400 - (value - 0x20) * 3;
}
realistic[0x7f] = 3;
for (let value = 0x80; value < 0x100; value += 1) {
  realistic[value] = value % 7;
}

const histogram = histogramChart(realistic, { title: 'byte frequency' });

check('histogramChart returns a root element', histogram.element instanceof FakeElement, `expected an element, got ${typeof histogram.element}`);

const bars = collect(histogram.element, (node) => hasClass(node, 'hb-histogram-bar'));
check(
  'the histogram is 256 .hb-histogram-bar elements',
  bars.length === 256,
  `expected one bar element per byte value, found ${bars.length}`,
);

const missingHeight = bars.filter((bar) => bar.style.getPropertyValue('--hb-bar') === '');
check(
  'every bar carries its height as the --hb-bar custom property',
  bars.length === 256 && missingHeight.length === 0,
  `${missingHeight.length} of ${bars.length} bars never had --hb-bar set, so the stylesheet would render them at the 0 fallback`,
);
check(
  'every --hb-bar value is a number the stylesheet can multiply',
  bars.every((bar) => Number.isFinite(Number(bar.style.getPropertyValue('--hb-bar')))),
  'at least one --hb-bar resolved to something calc(var(--hb-bar) * 1%) cannot use',
);

const canvases = collect(histogram.element, (node) => node.tagName === 'canvas');
check(
  'the histogram contains no canvas element at all (the move off canvas)',
  canvases.length === 0,
  `the histogram tree still holds ${canvases.length} canvas element(s), so it is drawn as pixels again and its bars carry no title, no class modifier and no theme response`,
);
const histogramBlock = extractBlock(chartsSource, /export function histogramChart\(counts, options = \{\}\) \{/);
check(
  'histogramChart never constructs a Chart',
  !histogramBlock.includes('new Chart('),
  'histogramChart builds a Chart again, which is the canvas path it was moved off',
);
check(
  'histogramChart builds its bars through the shared element factory',
  /element\('div', `hb-histogram-bar \$\{/.test(histogramBlock),
  'the 256 bars are no longer built as .hb-histogram-bar elements carrying a class modifier',
);

/* -------------------------------------------------- bars carry a byte class */

function expectedModifier(value) {
  if (value === 0) {
    return 'bc-null';
  }
  if (value >= 0x20 && value < 0x7f) {
    return 'bc-print';
  }
  if (value < 0x20 || value === 0x7f) {
    return 'bc-ctrl';
  }
  return 'bc-high';
}

const BYTE_MODIFIERS = ['bc-null', 'bc-print', 'bc-ctrl', 'bc-high'];

function modifierOf(bar) {
  return classesOf(bar).find((name) => BYTE_MODIFIERS.includes(name)) ?? null;
}

const misclassified = [];
for (let value = 0; value < bars.length; value += 1) {
  const actual = modifierOf(bars[value]);
  if (actual !== expectedModifier(value)) {
    misclassified.push(`0x${value.toString(16).padStart(2, '0')} is ${actual} but should be ${expectedModifier(value)}`);
  }
}
check(
  'every bar carries the byte-class modifier its value calls for',
  bars.length === 256 && misclassified.length === 0,
  `${misclassified.length} bar(s) tinted wrong, first: ${misclassified[0] ?? 'n/a'}`,
);

const BOUNDARIES = [
  [0x00, 'bc-null'],
  [0x1f, 'bc-ctrl'],
  [0x20, 'bc-print'],
  [0x7e, 'bc-print'],
  [0x7f, 'bc-ctrl'],
  [0x80, 'bc-high'],
  [0xff, 'bc-high'],
];
for (const [value, expected] of BOUNDARIES) {
  const actual = bars.length === 256 ? modifierOf(bars[value]) : null;
  check(
    `byte 0x${value.toString(16).padStart(2, '0')} is tinted ${expected}`,
    actual === expected,
    `expected ${expected} at the class boundary, got ${actual}`,
  );
}

const printableBars = bars.filter((bar) => hasClass(bar, 'bc-print'));
check(
  'exactly the printable range is tinted bc-print',
  printableBars.length === 0x7f - 0x20,
  `expected ${0x7f - 0x20} printable bars (0x20 through 0x7e), got ${printableBars.length}`,
);
check(
  'exactly one bar is tinted bc-null',
  bars.filter((bar) => hasClass(bar, 'bc-null')).length === 1,
  'only byte 0x00 may be tinted as the null class',
);

const titled = bars.filter((bar) => typeof bar.title === 'string' && bar.title.startsWith('0x'));
check(
  'every bar names its own byte, so the reading is not pointer-only',
  titled.length === 256,
  `${256 - titled.length} bar(s) have no title, which is the whole reason a DOM histogram needs no hidden summary`,
);

/* ------------------------------------------- the toggle recomputes the bars */

const spiky = new Array(256).fill(0);
spiky[0x00] = 1;
spiky[0x20] = 10;
spiky[0x41] = 1000;

const scaled = histogramChart(spiky);
const scaledBars = collect(scaled.element, (node) => hasClass(node, 'hb-histogram-bar'));
const toggle = collect(scaled.element, (node) => node.tagName === 'button' && hasClass(node, 'hb-btn'))[0] ?? null;
const caption = collect(scaled.element, (node) => hasClass(node, 'hb-dim'))[0] ?? null;
const meta = collect(scaled.element, (node) => hasClass(node, 'hb-canvasframe-meta'))[0] ?? null;

check('the histogram offers a scale toggle', toggle !== null, 'no .hb-btn button was built, so log and linear cannot be switched between');
check('the histogram reports its peak', caption !== null, 'no .hb-dim caption was built');
check('the histogram frame carries a meta line', meta !== null, 'no .hb-canvasframe-meta was built');

const logHeights = scaledBars.map((bar) => bar.style.getPropertyValue('--hb-bar'));

check('the histogram starts on the log scale', toggle !== null && toggle.textContent === 'linear scale', `the toggle should offer the other scale, it reads "${toggle === null ? 'n/a' : toggle.textContent}"`);
check('the meta line names the scale in force', meta !== null && meta.textContent === '1011 bytes, log scale', `expected "1011 bytes, log scale", got "${meta === null ? 'n/a' : meta.textContent}"`);
check(
  'the peak caption reports the real peak, not the log-scaled one',
  caption !== null && caption.textContent === 'peak 1000 at 0x41',
  `expected "peak 1000 at 0x41", got "${caption === null ? 'n/a' : caption.textContent}"`,
);

if (toggle !== null) {
  toggle.dispatch('click');
}

const linearHeights = scaledBars.map((bar) => bar.style.getPropertyValue('--hb-bar'));
const moved = logHeights.filter((height, value) => height !== linearHeights[value]).length;

check(
  'switching to the linear scale actually recomputes the bar heights',
  moved > 0,
  'not a single --hb-bar changed when the scale was toggled, so the toggle relabels itself without redrawing',
);
check(
  'exactly the two buckets where log and linear differ moved',
  moved === 2,
  `with counts {0x00: 1, 0x20: 10, 0x41: 1000} only 0x00 and 0x20 can differ between the scales (the peak is 100% either way and an empty bucket is 0% either way), but ${moved} bar(s) changed`,
);
check(
  'the peak bucket is full height on both scales',
  logHeights[0x41] === '100.000' && linearHeights[0x41] === '100.000',
  `expected the tallest bucket at 100.000% on both scales, got log ${logHeights[0x41]} and linear ${linearHeights[0x41]}`,
);
check(
  'the linear scale plots 10 of 1000 as one percent',
  linearHeights[0x20] === '1.000',
  `expected "1.000" for a bucket holding a tenth of a percent of the peak's height, got "${linearHeights[0x20]}"`,
);
check(
  'the linear scale plots 1 of 1000 as a tenth of a percent',
  linearHeights[0x00] === '0.100',
  `expected "0.100", got "${linearHeights[0x00]}"`,
);
check(
  'the log scale lifts the 10-count bucket well clear of its linear height',
  Number(logHeights[0x20]) > 34.7 && Number(logHeights[0x20]) < 34.72,
  `log1p(10)/log1p(1000) is 34.708%, but the log scale plotted "${logHeights[0x20]}"`,
);
check(
  'the log scale lifts the 1-count bucket well clear of its linear height',
  Number(logHeights[0x00]) > 10.03 && Number(logHeights[0x00]) < 10.04,
  `log1p(1)/log1p(1000) is 10.033%, but the log scale plotted "${logHeights[0x00]}"`,
);
check(
  'the toggle now offers the way back',
  toggle !== null && toggle.textContent === 'logarithmic scale',
  `after switching to linear the button should offer "logarithmic scale", it reads "${toggle === null ? 'n/a' : toggle.textContent}"`,
);
check(
  'the meta line follows the scale',
  meta !== null && meta.textContent === '1011 bytes, linear scale',
  `expected "1011 bytes, linear scale", got "${meta === null ? 'n/a' : meta.textContent}"`,
);
check(
  'the peak caption still reports the real peak after the toggle',
  caption !== null && caption.textContent === 'peak 1000 at 0x41',
  `the peak is a property of the counts, not of the scale, but the caption reads "${caption === null ? 'n/a' : caption.textContent}"`,
);

/* --------------------------------------------------- the DOM charts' shape */

const histogramKeys = Object.keys(histogram).sort();
const byteTypeKeys = Object.keys(byteTypeChart([1, 2, 3, 4])).sort();

check(
  'histogramChart returns an element',
  histogramKeys.includes('element'),
  `expected an "element" key, got ${JSON.stringify(histogramKeys)}`,
);
check(
  'histogramChart returns no chart handle (there is no canvas to own)',
  !histogramKeys.includes('chart'),
  'histogramChart still hands back a Chart, which a caller would then have to destroy - a DOM histogram has nothing to unsubscribe',
);
check(
  'histogramChart matches byteTypeChart, the other DOM chart, exactly',
  JSON.stringify(histogramKeys) === JSON.stringify(byteTypeKeys),
  `the two DOM charts disagree on their return shape: ${JSON.stringify(histogramKeys)} against ${JSON.stringify(byteTypeKeys)}`,
);

/* ------------------------- the canvas charts still owe a text alternative */

const announcingBlock = extractBlock(chartsSource, /function announcing\(node, handler\) \{/);
check(
  'the announcing wrapper routes a caption through the page live region',
  /announce\(spoken\);/.test(announcingBlock),
  'announcing() no longer calls announce(), so wrapping a hover handler in it says nothing to a screen reader',
);
check(
  'the announcing wrapper speaks only on a real change',
  /if \(node\.textContent !== spoken\)/.test(announcingBlock),
  'announcing() no longer compares against the last spoken text, so a pointer crossing a strip re-announces on every pixel',
);

const CANVAS_CHARTS = [
  ['entropyMapChart', /export function entropyMapChart\(values, options = \{\}\) \{/],
  ['classificationChart', /export function classificationChart\(codes, options = \{\}\) \{/],
  ['diffMinimapChart', /export function diffMinimapChart\(regions, side, options = \{\}\) \{/],
  ['digramChart', /export function digramChart\(counts\) \{/],
];

for (const [name, pattern] of CANVAS_CHARTS) {
  const block = extractBlock(chartsSource, pattern);
  check(
    `${name} is still a canvas chart`,
    block.includes('new Chart('),
    `${name} no longer builds a Chart, so the canvas expectations below no longer describe it`,
  );
  check(
    `${name} builds a visually hidden summary`,
    /element\('p', 'hb-sr-only'/.test(block),
    `${name} draws pixels with no .hb-sr-only text alternative, so a screen reader is told nothing about the shape it plots`,
  );
  check(
    `${name} appends its summary to the tree it returns`,
    /container\.append\(summary,/.test(block),
    `${name} builds an .hb-sr-only summary but never appends it, so the alternative never reaches the page`,
  );
  check(
    `${name} routes its caption through announce()`,
    /onHover: announcing\(hover,/.test(block),
    `${name} writes its hover caption straight into the node without going through announcing(), so the running commentary is sighted-only`,
  );
}

if (failures.length > 0) {
  process.stdout.write(`${failures.length} histogram/canvas expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('histogram DOM rendering and canvas text alternatives: all expectations held\n');
