/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Zachary Flint
   This file is part of Intellicrack. See LICENSE for details.

   The analysis operations return shapes no table can carry usefully: one float
   per block, one code byte per block, 65536 digram counts, 256 byte frequencies.
   Each of those becomes a picture here.

   Which of the two a shape gets is decided by one rule, stated at each of the
   charts that follow it: DOM when the element count is bounded, canvas when it
   is not. A byte histogram is always 256 bars and a byte split is always four
   segments, so both are elements the stylesheet themes by itself; a diff can
   report tens of thousands of regions and the digram plane is 65536 cells, so
   both are pixels. The canvas charts pay for that with a text alternative, one
   visually hidden sentence each plus a caption routed to the live region.

   Two things every canvas chart in this file gets right and a naive one gets
   wrong. The backing store is sized in device pixels and the context is scaled
   by the device pixel ratio, so a 175% display draws sharp rather than
   resampled. And every colour is read from the design system's custom properties
   at draw time, so a theme toggle repaints rather than leaving a light-theme
   chart stranded on a dark page. */

import { announce, element } from './dom.js';


const DPR_FALLBACK = 1;
const MIN_CANVAS_PX = 8;
const DIGRAM_SIDE = 256;
const HISTOGRAM_BUCKETS = 256;
const ENTROPY_HEIGHT = 72;
const CLASSIFICATION_HEIGHT = 44;
const DIGRAM_MAX = 384;
const AXIS_FONT = '10px ui-monospace, "Cascadia Mono", "Consolas", monospace';
const AXIS_PAD = 16;
const MAX_ENTROPY_BITS = 8;
const HIGH_ENTROPY_BITS = 7;
const ENTROPY_DASH = [4, 3];
const CLASSIFICATION_CODES = 5;
const HEX_BASE = 16;
const RGB_MAX = 255;
const SHORT_HEX = 4;
const PERCENT = 100;
const TWO = 2;
const HEX_SIX = /^#[0-9a-f]{6}$/i;
const HEX_PAIR = 2;

const CLASSIFICATION_LEGEND = [
  { code: 0, token: '--hb-class-0', label: 'zero-filled' },
  { code: 1, token: '--hb-class-1', label: 'plaintext-like' },
  { code: 2, token: '--hb-class-2', label: 'moderate' },
  { code: 3, token: '--hb-class-3', label: 'entropy > 7.0' },
  { code: 4, token: '--hb-class-4', label: 'entropy 4.5 - 7.0' },
];

const ENTROPY_STOPS = ['--hb-accent', '--hb-info', '--hb-class-2', '--hb-class-4', '--hb-class-3'];

const MINIMAP_HEIGHT = 26;

/** Design-system colour token for each alignment region kind. */
export const DIFF_TOKENS = new Map([
  ['match', '--hb-class-0'],
  ['modified', '--hb-warning'],
  ['inserted_a', '--hb-error'],
  ['inserted_b', '--hb-success'],
]);

/* ------------------------------------------------------------------- theme */

const listeners = new Set();
let watching = false;

function notifyTheme() {
  for (const listener of [...listeners]) {
    listener();
  }
}

function startWatching() {
  if (watching) {
    return;
  }
  watching = true;
  new MutationObserver(notifyTheme).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme', 'class'] });
  const query = window.matchMedia('(prefers-color-scheme: dark)');
  query.addEventListener('change', notifyTheme);
}

/**
 * Call `handler` whenever the effective theme changes.
 *
 * Both routes are watched, because the shell's toggle stamps `data-theme` on the
 * root element while an untouched session follows the operating system.
 *
 * @param {() => void} handler Called after each theme change.
 * @returns {() => void} Removes the subscription.
 */
export function subscribeTheme(handler) {
  startWatching();
  listeners.add(handler);
  return () => listeners.delete(handler);
}

/* ------------------------------------------------------------------ colour */

function clampByte(value) {
  return Math.max(0, Math.min(RGB_MAX, Math.round(value)));
}

/**
 * Parse any colour the design system writes into a custom property.
 *
 * @param {string} text Colour text, hexadecimal or a functional rgb notation.
 * @returns {{r: number, g: number, b: number}} Channel values, black when unparsable.
 */
export function parseColor(text) {
  const value = String(text).trim();
  if (value.startsWith('#')) {
    const digits = value.slice(1);
    if (digits.length <= SHORT_HEX) {
      const [r, g, b] = [...digits.slice(0, 3)].map((digit) => Number.parseInt(digit + digit, HEX_BASE));
      return { r: r || 0, g: g || 0, b: b || 0 };
    }
    return {
      r: Number.parseInt(digits.slice(0, 2), HEX_BASE) || 0,
      g: Number.parseInt(digits.slice(2, 4), HEX_BASE) || 0,
      b: Number.parseInt(digits.slice(4, 6), HEX_BASE) || 0,
    };
  }
  const numbers = value.match(/-?\d*\.?\d+/g);
  if (numbers && numbers.length >= 3) {
    return { r: clampByte(Number(numbers[0])), g: clampByte(Number(numbers[1])), b: clampByte(Number(numbers[2])) };
  }
  return { r: 0, g: 0, b: 0 };
}

/**
 * Read one design-system custom property off an element's computed style.
 *
 * @param {HTMLElement} node Element whose computed style supplies the token.
 * @param {string} token Custom property name.
 * @param {string} [fallback] Returned when the property resolves to nothing.
 * @returns {string} The colour text, in whatever notation the stylesheet wrote.
 */
export function cssColor(node, token, fallback = '#808080') {
  const raw = getComputedStyle(node).getPropertyValue(token).trim();
  return raw === '' ? fallback : raw;
}

/**
 * One design-system colour token as a six-digit hexadecimal string.
 *
 * A colour input and a canvas gradient stop both need `#rrggbb` specifically,
 * which is not what the stylesheet necessarily wrote: a token may resolve to
 * `rgb(...)` or to a shorthand, and either reaches such a control as an empty
 * value rather than as an error.
 *
 * @param {string} token Custom property name.
 * @param {string} [fallback] Colour text used when the token resolves to nothing.
 * @param {HTMLElement} [node] Element whose computed style supplies the token.
 * @returns {string} The colour as `#rrggbb`, lower case.
 */
export function tokenHex(token, fallback = '#808080', node = null) {
  const raw = cssColor(node ?? document.documentElement, token, fallback);
  if (HEX_SIX.test(raw)) {
    return raw.toLowerCase();
  }
  const { r, g, b } = parseColor(raw);
  return `#${[r, g, b].map((channel) => channel.toString(HEX_BASE).padStart(HEX_PAIR, '0')).join('')}`;
}

function mix(first, second, ratio) {
  return {
    r: clampByte(first.r + (second.r - first.r) * ratio),
    g: clampByte(first.g + (second.g - first.g) * ratio),
    b: clampByte(first.b + (second.b - first.b) * ratio),
  };
}

function toCss(colour) {
  return `rgb(${colour.r} ${colour.g} ${colour.b})`;
}

/**
 * Build a colour ramp from a list of design-system tokens.
 *
 * @param {HTMLElement} node Element whose computed style supplies the tokens.
 * @param {string[]} tokens Custom property names, cool end first.
 * @returns {(position: number) => string} Maps 0-1 onto a CSS colour.
 */
export function buildRamp(node, tokens) {
  const stops = tokens.map((token) => parseColor(cssColor(node, token)));
  return (position) => {
    const clamped = Math.max(0, Math.min(1, position));
    const scaled = clamped * (stops.length - 1);
    const index = Math.min(stops.length - TWO, Math.floor(scaled));
    return toCss(mix(stops[index], stops[index + 1], scaled - index));
  };
}

/* ------------------------------------------------------------------ canvas */

function hex(value, digits) {
  return value.toString(HEX_BASE).toUpperCase().padStart(digits, '0');
}

/**
 * The data index a pointer position falls over in a bucketed strip chart.
 *
 * `length` is the number of buckets across the chart's width, not a fixed
 * constant, so an empty document (no blocks, no digrams) makes it 0; the
 * clamp `Math.max(0, Math.min(length - 1, ...))` would otherwise resolve to
 * index 0 on an empty array and hand the caller `undefined`.
 *
 * @param {number} length Number of buckets the chart is divided into.
 * @param {number} x Pointer x position in CSS pixels, relative to the canvas.
 * @param {number} width Canvas width in CSS pixels.
 * @returns {number|null} The bucket index, or null when there are no buckets.
 */
export function hoverIndex(length, x, width) {
  if (length === 0) {
    return null;
  }
  return Math.max(0, Math.min(length - 1, Math.floor((x / width) * length)));
}

/**
 * A framed canvas that stays sharp, stays themed, and reports what is under the
 * pointer.
 *
 * The draw callback receives a context already scaled to CSS pixels, so it never
 * has to know the device pixel ratio; the ratio is re-read on every render
 * because dragging a window between displays changes it.
 */
export class Chart {
  #frame;
  #canvas;
  #context;
  #body;
  #meta;
  #caption;
  #options;
  #width = 0;
  #height = 0;
  #unsubscribe;
  #observer;

  constructor(options) {
    this.#options = options;
    this.#frame = element('div', 'hb-canvasframe');

    const header = element('div', 'hb-canvasframe-header');
    header.appendChild(element('span', undefined, options.title));
    this.#meta = element('span', 'hb-canvasframe-meta', options.meta ?? '');
    header.appendChild(this.#meta);

    this.#body = element('div', options.grid === false ? 'hb-canvasframe-body is-plain' : 'hb-canvasframe-body');
    this.#canvas = document.createElement('canvas');
    this.#canvas.className = 'hb-canvas';
    this.#canvas.style.height = `${options.height}px`;
    this.#body.appendChild(this.#canvas);

    this.#caption = element('div', 'hb-canvasframe-caption', options.caption ?? '');
    this.#frame.append(header, this.#body);
    if (options.caption !== undefined) {
      this.#frame.appendChild(this.#caption);
    }

    const context = this.#canvas.getContext('2d');
    if (context === null) {
      throw new Error('this browser refused a 2d canvas context');
    }
    this.#context = context;

    this.#bindPointer();
    this.#unsubscribe = subscribeTheme(() => this.render());
    this.#observer = new ResizeObserver(() => this.render());
    this.#observer.observe(this.#body);
  }

  get element() {
    return this.#frame;
  }

  /** Replace the text in the frame header's right-hand slot. */
  setMeta(text) {
    this.#meta.textContent = text;
  }

  /** Replace the caption under the chart. */
  setCaption(text) {
    this.#caption.textContent = text;
  }

  #bindPointer() {
    const at = (event) => {
      const rect = this.#canvas.getBoundingClientRect();
      return { x: event.clientX - rect.left, y: event.clientY - rect.top, width: rect.width, height: rect.height };
    };
    if (typeof this.#options.onHover === 'function') {
      this.#canvas.addEventListener('mousemove', (event) => this.#options.onHover(at(event), this));
      this.#canvas.addEventListener('mouseleave', () => this.#options.onHover(null, this));
    }
    if (typeof this.#options.onClick === 'function') {
      this.#canvas.style.cursor = 'pointer';
      this.#canvas.addEventListener('click', (event) => this.#options.onClick(at(event), this));
    }
  }

  /**
   * Redraw at the size and the theme now in force.
   *
   * Nothing is drawn while the frame is detached or has no width, because a
   * zero-width backing store would be reallocated on the next layout anyway.
   */
  render() {
    if (!this.#frame.isConnected) {
      return;
    }
    const rect = this.#canvas.getBoundingClientRect();
    const width = Math.floor(rect.width);
    const height = this.#options.height;
    if (width < MIN_CANVAS_PX) {
      return;
    }
    const ratio = window.devicePixelRatio || DPR_FALLBACK;
    this.#canvas.width = Math.round(width * ratio);
    this.#canvas.height = Math.round(height * ratio);
    this.#width = width;
    this.#height = height;
    this.#context.setTransform(ratio, 0, 0, ratio, 0, 0);
    this.#context.clearRect(0, 0, width, height);
    this.#options.draw(this.#context, { width, height, node: this.#frame, chart: this });
  }

  get size() {
    return { width: this.#width, height: this.#height };
  }

  /** Stop listening for theme and size changes. */
  destroy() {
    this.#unsubscribe();
    this.#observer.disconnect();
  }
}

function mountChart(chart) {
  requestAnimationFrame(() => chart.render());
  return chart;
}

/**
 * Wrap a canvas chart's hover handler so the caption it writes is also spoken.
 *
 * A canvas says nothing to a screen reader, so the caption is the only reading
 * of what the pointer is over; sending it through the page's one polite live
 * region is what turns it from a sighted-only readout into the chart's running
 * commentary. The announcement is made only when the text actually changed,
 * because a pointer crossing a strip fires on every pixel and a live region
 * rewritten with the text it already holds is read out again by some screen
 * readers.
 *
 * @param {HTMLElement} node Caption element the handler writes into.
 * @param {(point: object|null, chart: Chart) => void} handler The chart's own hover handler.
 * @returns {(point: object|null, chart: Chart) => void} The same handler, now announcing.
 */
function announcing(node, handler) {
  let spoken = node.textContent;
  return (point, chart) => {
    handler(point, chart);
    if (node.textContent !== spoken) {
      spoken = node.textContent;
      announce(spoken);
    }
  };
}

/* ------------------------------------------------------------ entropy map */

/**
 * Draw one column per block, cool for ordered bytes and hot for random ones.
 *
 * @param {number[]} values Shannon entropy per block, in bits per byte.
 * @param {object} options Block size, document length and a seek callback.
 * @returns {{element: HTMLElement, chart: Chart}} The mounted chart.
 */
export function entropyMapChart(values, options = {}) {
  const { blockSize = 0, onSeek = null } = options;
  const container = element('div', 'hb-stack');
  const hover = element('div', 'hb-canvasframe-caption hb-mono', 'hover a column for its entropy');
  const summary = element('p', 'hb-sr-only', `Entropy profile: ${values.length} blocks of ${blockSize} bytes plotted from 0 to ${MAX_ENTROPY_BITS} bits per byte, with a dashed marker at the ${HIGH_ENTROPY_BITS} bit high-entropy threshold.`);

  const chart = new Chart({
    title: 'entropy map',
    meta: `${values.length} blocks of ${blockSize} B`,
    height: ENTROPY_HEIGHT,
    grid: false,
    draw: (context, { width, height }) => {
      context.strokeStyle = cssColor(container, '--hb-chart-grid', 'rgba(128,128,128,0.2)');
      context.beginPath();
      for (const fraction of [0.25, 0.5, 0.75]) {
        context.moveTo(0, height * fraction);
        context.lineTo(width, height * fraction);
      }
      context.stroke();

      if (values.length === 0) {
        return;
      }
      const ordinate = (value) => height - Math.max(0, Math.min(1, value / MAX_ENTROPY_BITS)) * height;
      const step = values.length === 1 ? width : width / (values.length - 1);
      const points = values.length === 1
        ? [{ x: 0, y: ordinate(values[0]) }, { x: width, y: ordinate(values[0]) }]
        : values.map((value, index) => ({ x: index * step, y: ordinate(value) }));

      context.beginPath();
      context.moveTo(0, height);
      for (const point of points) {
        context.lineTo(point.x, point.y);
      }
      context.lineTo(width, height);
      context.closePath();
      context.fillStyle = cssColor(container, '--hb-chart-fill', 'rgba(76,157,240,0.24)');
      context.fill();

      context.beginPath();
      context.moveTo(points[0].x, points[0].y);
      for (let index = 1; index < points.length; index += 1) {
        context.lineTo(points[index].x, points[index].y);
      }
      context.lineJoin = 'round';
      context.strokeStyle = cssColor(container, '--hb-chart-line', '#4c9df0');
      context.stroke();

      const threshold = ordinate(HIGH_ENTROPY_BITS);
      context.save();
      context.setLineDash(ENTROPY_DASH);
      context.strokeStyle = cssColor(container, '--hb-class-3', '#ef5f8c');
      context.beginPath();
      context.moveTo(0, threshold);
      context.lineTo(width, threshold);
      context.stroke();
      context.restore();
    },
    onHover: announcing(hover, (point) => {
      if (point === null) {
        hover.textContent = 'hover a column for its entropy';
        return;
      }
      const index = hoverIndex(values.length, point.x, point.width);
      hover.textContent = index === null
        ? 'no blocks to map — the document is empty'
        : `block ${index} at 0x${hex(index * blockSize, 8)} — ${values[index].toFixed(3)} bits/byte`;
    }),
    onClick: onSeek === null ? undefined : (point) => {
      const index = hoverIndex(values.length, point.x, point.width);
      if (index !== null) {
        onSeek(index * blockSize);
      }
    },
  });

  const scale = element('div', 'hb-strip-axis');
  scale.append(element('span', undefined, '0 bits'), element('span', undefined, '8 bits (random)'));
  container.append(summary, chart.element, scale, hover);
  return { element: container, chart: mountChart(chart) };
}

/* -------------------------------------------------- content classification */

/**
 * Draw the per-block classification codes with the fixed five-colour legend.
 *
 * @param {Uint8Array} codes One code byte per block.
 * @param {object} options Block size and a seek callback.
 * @returns {{element: HTMLElement, chart: Chart}} The mounted chart.
 */
export function classificationChart(codes, options = {}) {
  const { blockSize = 0, onSeek = null } = options;
  const container = element('div', 'hb-stack');
  const hover = element('div', 'hb-canvasframe-caption hb-mono', 'hover a block for its class');
  const summary = element('p', 'hb-sr-only', `Content classification: one column per block across ${codes.length} blocks of ${blockSize} bytes, each carrying a class code from 0 (${CLASSIFICATION_LEGEND[0].label}) to ${CLASSIFICATION_CODES - 1} (${CLASSIFICATION_LEGEND[CLASSIFICATION_CODES - 1].label}).`);

  const counts = new Array(CLASSIFICATION_CODES).fill(0);
  for (const code of codes) {
    if (code < CLASSIFICATION_CODES) {
      counts[code] += 1;
    }
  }

  const chart = new Chart({
    title: 'content classification',
    meta: `${codes.length} blocks of ${blockSize} B`,
    height: CLASSIFICATION_HEIGHT,
    grid: false,
    draw: (context, { width, height }) => {
      const colours = CLASSIFICATION_LEGEND.map((entry) => cssColor(container, entry.token));
      const step = width / Math.max(1, codes.length);
      for (let index = 0; index < codes.length; index += 1) {
        context.fillStyle = colours[codes[index]] ?? colours[0];
        context.fillRect(index * step, 0, Math.max(1, step + 1), height);
      }
    },
    onHover: announcing(hover, (point) => {
      if (point === null) {
        hover.textContent = 'hover a block for its class';
        return;
      }
      const index = hoverIndex(codes.length, point.x, point.width);
      if (index === null) {
        hover.textContent = 'no blocks to classify — the document is empty';
        return;
      }
      const entry = CLASSIFICATION_LEGEND[codes[index]];
      hover.textContent = `block ${index} at 0x${hex(index * blockSize, 8)} — ${codes[index]} ${entry ? entry.label : 'unknown code'}`;
    }),
    onClick: onSeek === null ? undefined : (point) => {
      const index = hoverIndex(codes.length, point.x, point.width);
      if (index !== null) {
        onSeek(index * blockSize);
      }
    },
  });

  const legend = element('div', 'hb-legend');
  for (const entry of CLASSIFICATION_LEGEND) {
    const item = element('span', 'hb-legend-item');
    const swatch = element('span', 'hb-legend-swatch');
    swatch.style.background = `var(${entry.token})`;
    item.append(swatch, element('span', 'hb-legend-code', String(entry.code)), element('span', 'hb-legend-label', entry.label));
    item.appendChild(element('span', 'hb-legend-note', `${counts[entry.code]}`));
    legend.appendChild(item);
  }

  container.append(summary, chart.element, legend, hover);
  return { element: container, chart: mountChart(chart) };
}

/* ----------------------------------------------------------- digram matrix */

/**
 * Draw the 256 by 256 digram counts as a log-scaled image.
 *
 * The counts arrive row major with `index = b0 * 256 + b1`, so a run of ASCII
 * text lights the printable quadrant and a compressed region fills the plane.
 *
 * @param {number[]} counts Exactly 65536 occurrence counts.
 * @returns {{element: HTMLElement, chart: Chart}} The mounted chart.
 */
export function digramChart(counts) {
  const container = element('div', 'hb-stack');
  const hover = element('div', 'hb-canvasframe-caption hb-mono', 'hover for the pair under the pointer');

  let peak = 0;
  let nonZero = 0;
  for (const count of counts) {
    if (count > peak) {
      peak = count;
    }
    if (count > 0) {
      nonZero += 1;
    }
  }
  const scale = Math.log1p(peak) || 1;
  const summary = element('p', 'hb-sr-only', `Digram matrix: a ${DIGRAM_SIDE} by ${DIGRAM_SIDE} grid of byte-pair counts, ${nonZero} of ${DIGRAM_SIDE * DIGRAM_SIDE} pairs seen, log-scaled from 0 to ${peak} occurrences.`);

  const offscreen = document.createElement('canvas');
  offscreen.width = DIGRAM_SIDE;
  offscreen.height = DIGRAM_SIDE;
  const offscreenContext = offscreen.getContext('2d');

  const chart = new Chart({
    title: 'digram matrix',
    meta: `${nonZero} of 65536 pairs seen, peak ${peak}`,
    height: DIGRAM_MAX,
    grid: false,
    draw: (context, { width, height }) => {
      if (offscreenContext === null) {
        return;
      }
      const ramp = buildRamp(container, ENTROPY_STOPS);
      const background = parseColor(cssColor(container, '--hb-surface-inset', '#101010'));
      const image = offscreenContext.createImageData(DIGRAM_SIDE, DIGRAM_SIDE);
      for (let index = 0; index < DIGRAM_SIDE * DIGRAM_SIDE; index += 1) {
        const count = counts[index] ?? 0;
        const pixel = index * 4;
        if (count === 0) {
          image.data[pixel] = background.r;
          image.data[pixel + 1] = background.g;
          image.data[pixel + 2] = background.b;
        } else {
          const colour = parseColor(ramp(Math.log1p(count) / scale));
          image.data[pixel] = colour.r;
          image.data[pixel + 1] = colour.g;
          image.data[pixel + 2] = colour.b;
        }
        image.data[pixel + 3] = RGB_MAX;
      }
      offscreenContext.putImageData(image, 0, 0);
      const side = Math.min(width - AXIS_PAD, height - AXIS_PAD);
      const left = (width - side) / TWO;
      context.imageSmoothingEnabled = false;
      context.drawImage(offscreen, left, 0, side, side);
      context.fillStyle = cssColor(container, '--hb-chart-axis', '#808080');
      context.font = AXIS_FONT;
      context.fillText('b1 →', left, side + AXIS_PAD - 4);
      context.fillText('↓ b0', Math.max(0, left - AXIS_PAD), AXIS_PAD - 4);
    },
    onHover: announcing(hover, (point) => {
      if (point === null) {
        hover.textContent = 'hover for the pair under the pointer';
        return;
      }
      const side = Math.min(point.width - AXIS_PAD, point.height - AXIS_PAD);
      const left = (point.width - side) / TWO;
      const first = Math.floor(((point.y) / side) * DIGRAM_SIDE);
      const second = Math.floor(((point.x - left) / side) * DIGRAM_SIDE);
      if (first < 0 || first >= DIGRAM_SIDE || second < 0 || second >= DIGRAM_SIDE) {
        hover.textContent = 'outside the matrix';
        return;
      }
      const count = counts[first * DIGRAM_SIDE + second] ?? 0;
      hover.textContent = `b0=0x${hex(first, 2)} b1=0x${hex(second, 2)} — ${count} occurrence${count === 1 ? '' : 's'}`;
    }),
  });

  container.append(summary, chart.element, hover);
  return { element: container, chart: mountChart(chart) };
}

/* --------------------------------------------------------- byte histogram */

function byteClassToken(value) {
  if (value === 0) {
    return '--hb-byte-null';
  }
  if (value >= 0x20 && value < 0x7f) {
    return '--hb-class-1';
  }
  if (value < 0x20 || value === 0x7f) {
    return '--hb-byte-control';
  }
  return '--hb-byte-high';
}

const BYTE_CLASS_MODIFIERS = new Map([
  ['--hb-byte-null', 'bc-null'],
  ['--hb-class-1', 'bc-print'],
  ['--hb-byte-control', 'bc-ctrl'],
  ['--hb-byte-high', 'bc-high'],
]);

/**
 * The tallest bucket in a byte histogram, or null when every bucket is empty.
 *
 * `Math.max(...counts, 1)` falls back to 1 for an all-zero histogram so the
 * chart's log/linear scale never divides by zero, but that same fallback used
 * as a caption value claims a byte occurs once when none does, and
 * `counts.indexOf(1)` then returns -1 - `hex(-1, 2)` prints the literal string
 * "-1" rather than a padded hex byte. Scale computation and the caption need
 * different answers for the empty case, so they are kept apart here.
 *
 * @param {number[]} counts Exactly 256 occurrence counts, indexed by byte value.
 * @returns {{peak: number, index: number}|null} The tallest bucket and its byte
 * value, or null when no byte occurs at all.
 */
export function histogramPeak(counts) {
  const peak = Math.max(...counts, 0);
  if (peak === 0) {
    return null;
  }
  return { peak, index: counts.indexOf(peak) };
}

const HISTOGRAM_IDLE = 'hover a bar for its byte value';

/**
 * Build the 256-bar frequency histogram as elements, with a logarithmic toggle.
 *
 * This one is DOM rather than canvas on purpose, by the rule the digram and the
 * diff mini-map are canvas by: the bucket count is fixed at 256 whatever the
 * document is, so the cost of one element per bar is bounded. What that buys is
 * everything the canvas versions have to re-do by hand. Each bar carries its own
 * title, so the reading of a bucket is not pointer-only. Each bar's colour is a
 * class modifier the stylesheet already owns, so a theme change re-resolves it
 * with no redraw and no theme subscription to unsubscribe from - which is why
 * this returns an element and nothing else.
 *
 * A linear histogram of a text file is one spike and 255 invisible bars, so the
 * toggle is part of the chart rather than an afterthought.
 *
 * @param {number[]} counts Exactly 256 occurrence counts, indexed by byte value.
 * @param {object} options Title shown in the frame header.
 * @returns {{element: HTMLElement}} The rendered histogram.
 */
export function histogramChart(counts, options = {}) {
  const { title = 'byte frequency' } = options;
  const container = element('div', 'hb-stack');
  const hover = element('div', 'hb-canvasframe-caption hb-mono', HISTOGRAM_IDLE);
  let logarithmic = true;

  const total = counts.reduce((sum, value) => sum + value, 0);
  const peakInfo = histogramPeak(counts);
  const scalePeak = peakInfo === null ? 1 : peakInfo.peak;

  const describe = (value) => {
    const count = counts[value] ?? 0;
    const share = total === 0 ? 0 : (count / total) * PERCENT;
    const glyph = value >= 0x20 && value < 0x7f ? ` '${String.fromCharCode(value)}'` : '';
    return `0x${hex(value, 2)}${glyph} — ${count} (${share.toFixed(2)}%)`;
  };

  const frame = element('div', 'hb-canvasframe');
  const header = element('div', 'hb-canvasframe-header');
  const meta = element('span', 'hb-canvasframe-meta', `${total} bytes, log scale`);
  header.append(element('span', undefined, title), meta);
  const body = element('div', 'hb-canvasframe-body is-plain');
  const plot = element('div', 'hb-histogram');

  const bars = [];
  for (let value = 0; value < HISTOGRAM_BUCKETS; value += 1) {
    const bar = element('div', `hb-histogram-bar ${BYTE_CLASS_MODIFIERS.get(byteClassToken(value))}`);
    bar.title = describe(value);
    bar.addEventListener('pointerenter', () => {
      hover.textContent = bar.title;
    });
    bar.addEventListener('pointerleave', () => {
      hover.textContent = HISTOGRAM_IDLE;
    });
    bars.push(bar);
    plot.appendChild(bar);
  }
  body.appendChild(plot);
  frame.append(header, body);

  const applyHeights = () => {
    const ceiling = logarithmic ? Math.log1p(scalePeak) : scalePeak;
    bars.forEach((bar, value) => {
      const count = counts[value] ?? 0;
      const measured = logarithmic ? Math.log1p(count) : count;
      const share = ceiling === 0 ? 0 : (measured / ceiling) * PERCENT;
      bar.style.setProperty('--hb-bar', share.toFixed(3));
    });
  };
  applyHeights();

  const axis = element('div', 'hb-axis');
  axis.append(element('span', undefined, '00'), element('span', undefined, '7F'), element('span', undefined, 'FF'));

  const controls = element('div', 'hb-row-flex');
  const toggle = element('button', 'hb-btn is-sm', 'linear scale');
  toggle.type = 'button';
  toggle.addEventListener('click', () => {
    logarithmic = !logarithmic;
    toggle.textContent = logarithmic ? 'linear scale' : 'logarithmic scale';
    meta.textContent = `${total} bytes, ${logarithmic ? 'log' : 'linear'} scale`;
    applyHeights();
  });
  controls.append(toggle, element('span', 'hb-dim', peakInfo === null
    ? 'no peak — the document is empty'
    : `peak ${peakInfo.peak} at 0x${hex(peakInfo.index, 2)}`));

  container.append(frame, axis, controls, hover);
  return { element: container };
}

/* -------------------------------------------------- byte type distribution */

const BYTE_TYPES = [
  { key: 'null', className: 'bc-null', label: 'null' },
  { key: 'printable', className: 'bc-print', label: 'printable' },
  { key: 'control', className: 'bc-ctrl', label: 'control' },
  { key: 'high', className: 'bc-high', label: 'high' },
];

/**
 * Draw the four-way byte split as one segmented bar with counts and shares.
 *
 * This one is DOM rather than canvas on purpose: the segments carry text, and
 * the design system already themes `.hb-segbar` in both palettes.
 *
 * @param {number[]} counts The null, printable, control and high counts.
 * @returns {{element: HTMLElement}} The rendered bar and its legend.
 */
export function byteTypeChart(counts) {
  const container = element('div', 'hb-stack');
  const total = counts.reduce((sum, value) => sum + value, 0);
  const bar = element('div', 'hb-segbar');
  const legend = element('div', 'hb-legend');

  BYTE_TYPES.forEach((type, index) => {
    const count = counts[index] ?? 0;
    const share = total === 0 ? 0 : (count / total) * PERCENT;
    const segment = element('div', `hb-segbar-seg ${type.className}`);
    segment.style.setProperty('--hb-seg', share.toFixed(3));
    segment.title = `${type.label}: ${count} bytes (${share.toFixed(2)}%)`;
    if (share > 6) {
      segment.textContent = `${share.toFixed(1)}%`;
    }
    bar.appendChild(segment);

    const item = element('span', 'hb-legend-item');
    const swatch = element('span', `hb-legend-swatch`);
    swatch.style.background = `var(${['--hb-byte-null', '--hb-class-1', '--hb-byte-control', '--hb-byte-high'][index]})`;
    item.append(swatch, element('span', 'hb-legend-label', type.label), element('span', 'hb-legend-note', `${count} (${share.toFixed(2)}%)`));
    legend.appendChild(item);
  });

  if (total === 0) {
    bar.appendChild(element('div', 'hb-segbar-seg', 'empty document'));
  }
  container.append(bar, legend);
  return { element: container };
}

/* --------------------------------------------------------------- diff strip */

function regionSpan(regions, key) {
  let span = 0;
  for (const region of regions) {
    span = Math.max(span, Number(region[key] ?? 0) + Number(region.length ?? 0));
  }
  return span;
}

function regionAt(regions, key, position) {
  let low = 0;
  let high = regions.length - 1;
  let best = null;
  while (low <= high) {
    const middle = (low + high) >> 1;
    const start = Number(regions[middle][key] ?? 0);
    if (start <= position) {
      best = regions[middle];
      low = middle + 1;
    } else {
      high = middle - 1;
    }
  }
  return best;
}

/**
 * Draw one side of a diff alignment as a colour-coded strip.
 *
 * A diff of two unrelated files can report tens of thousands of regions, so this
 * is a canvas rather than one element per region: the strip stays a single node
 * whatever the alignment costs, and a binary search answers what the pointer is
 * over.
 *
 * @param {object[]} regions Alignment regions carrying diff_type, offsets and length.
 * @param {string} side Which offset column to plot, "a" or "b".
 * @param {object} options Optional title and a callback given a region on click.
 * @returns {{element: HTMLElement, chart: Chart}} The mounted chart.
 */
export function diffMinimapChart(regions, side, options = {}) {
  const { title = `input ${side}`, onPick = null } = options;
  const key = side === 'a' ? 'offset_a' : 'offset_b';
  const ordered = [...regions].sort((left, right) => Number(left[key] ?? 0) - Number(right[key] ?? 0));
  const span = regionSpan(ordered, key);
  const container = element('div', 'hb-stack');
  const hover = element('div', 'hb-canvasframe-caption hb-mono', 'hover the strip for the region under the pointer');
  const summary = element('p', 'hb-sr-only', `Difference mini-map for ${title}: ${ordered.length} alignment regions laid out from offset 0 to ${span} bytes, each coloured by its difference kind.`);

  const positionOf = (point) => Math.max(0, Math.min(span, (point.x / point.width) * span));

  const chart = new Chart({
    title,
    meta: `${ordered.length} regions over ${span} B`,
    height: MINIMAP_HEIGHT,
    grid: false,
    draw: (context, { width, height }) => {
      const colours = new Map();
      for (const [kind, token] of DIFF_TOKENS) {
        colours.set(kind, cssColor(container, token));
      }
      context.fillStyle = cssColor(container, '--hb-surface-2', '#202020');
      context.fillRect(0, 0, width, height);
      if (span === 0) {
        return;
      }
      for (const region of ordered) {
        const start = (Number(region[key] ?? 0) / span) * width;
        const size = Math.max(1, (Number(region.length ?? 0) / span) * width);
        context.fillStyle = colours.get(String(region.diff_type)) ?? colours.get('match');
        context.fillRect(start, 0, size, height);
      }
    },
    onHover: announcing(hover, (point) => {
      if (point === null || span === 0) {
        hover.textContent = 'hover the strip for the region under the pointer';
        return;
      }
      const region = regionAt(ordered, key, positionOf(point));
      hover.textContent = region === null
        ? 'no region covers that position'
        : `${region.diff_type} — ${region.length} B at 0x${hex(Number(region[key] ?? 0), 8)}`;
    }),
    onClick: onPick === null ? undefined : (point) => {
      if (span === 0) {
        return;
      }
      const region = regionAt(ordered, key, positionOf(point));
      if (region !== null) {
        onPick(region);
      }
    },
  });

  container.append(summary, chart.element, hover);
  return { element: container, chart: mountChart(chart) };
}
