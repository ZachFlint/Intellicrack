/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Zachary Flint
   This file is part of Intellicrack. See LICENSE for details.

   The hex view. Two things here are not obvious and are load-bearing.

   The first is that the scroller's height is capped. Chromium refuses to make an
   element taller than roughly 33.5 million pixels, which at one row per twenty
   pixels runs out after about twenty-six megabytes of document. Above the cap the
   scroller is scaled: one pixel of scrollbar stands for many rows, so the first
   visible row is tracked directly and the scrollbar position is derived from it
   rather than the other way round. That is why the wheel and the arrow keys move
   a row counter and then push the scrollbar to match, instead of nudging
   scrollTop and reading the result back.

   The second is that the DOM is never rebuilt. A fixed pool of row elements is
   recycled, each cell's text and class list written only when it actually
   changes, and the bytes behind them come from a small cache of windows keyed by
   document generation, so a mutation invalidates exactly the stale windows and
   nothing else.

   The third is that the row width is a view setting rather than a constant, and
   the two things derived from it pull in opposite directions. The rendered DOM
   does depend on it, so changing it discards the row pool and the ruler columns
   and builds them again at the new width - the one moment this file is allowed
   to rebuild. The byte cache does not: a window holds the document's bytes, not
   a picture of them, so it stays keyed by generation alone and keeps answering
   after a width change. Only the quantum that chooses the next window's start
   offset moves with the width, which costs at most one extra read. */

import { callOp, isAborted, isBusy, readWindow, toHex } from './api.js';
import { announce, nextId } from './dom.js';

export const BYTES_PER_ROW = 16;

/** The fixed row widths offered beside fit-to-width. */
export const BYTES_PER_ROW_CHOICES = Object.freeze([8, 16, 24, 32]);

/** The row-width setting that measures the pane instead of naming a number. */
export const FIT_TO_WIDTH = 'fit';

const GROUP_SIZE = 8;
const MAX_SCROLLER_PX = 30_000_000;
const LAYOUT_UNIT_MAX_PX = 33_554_432;
const OVERSCAN_ROWS = 64;
const WINDOW_PAD_ROWS = 128;
const CACHE_LIMIT = 32;
const SPARE_ROWS = 2;
const FALLBACK_ROW_HEIGHT = 20;
const BUSY_RETRY_MS = 220;
const WHEEL_LINE_PX = 16;
const WHEEL_PAGE_ROWS = 24;
const FIT_MIN_BLOCKS = 1;
const FIT_MAX_BLOCKS = 8;
const CARET_SPEAK_MS = 140;

const PRINTABLE_LOW = 0x20;
const PRINTABLE_HIGH = 0x7e;
const HIGH_BYTE = 0x80;
const NIBBLE_HIGH = 0;
const NIBBLE_LOW = 1;
const HEX_RADIX = 16;
const BYTE_MASK = 0xff;
const LOW_MASK = 0x0f;
const HIGH_MASK = 0xf0;
const NIBBLE_BITS = 4;

const PANE_HEX = 'hex';
const PANE_ASCII = 'ascii';

const DOT = '·';
const UNKNOWN_HEX = `${DOT}${DOT}`;
const OFFSET_DIGITS = 8;

const LAYER_MARKERS = new Map([
  ['is-hit', { start: 'is-hit-start', end: '' }],
  ['is-field', { start: 'is-field-start', end: 'is-field-end' }],
]);

const IN_RANGE = 1;
const AT_START = 2;
const AT_END = 4;

function clamp(value, low, high) {
  if (value < low) {
    return low;
  }
  return value > high ? high : value;
}

/**
 * The row-relative caret keys, resolved as arithmetic on the current row width.
 *
 * Every one of these used to read a module constant, which is what fixed the
 * view at sixteen bytes. Taking the width as an argument is what makes the row
 * width a setting; keeping the whole calculation out of the class is what makes
 * it directly executable by the suite that gates it. The result is unclamped -
 * the caller owns the document bounds - and a key that does not move by rows
 * leaves the caret where it is.
 *
 * @param {string} key `event.key` of the keystroke.
 * @param {number} offset Byte offset the caret is on now.
 * @param {number} bytesPerRow Bytes rendered per row.
 * @param {number} fullRows Rows a page step covers.
 * @returns {number} Byte offset the key asks for, before clamping.
 */
export function caretRowTarget(key, offset, bytesPerRow, fullRows) {
  const column = offset % bytesPerRow;
  switch (key) {
    case 'ArrowUp':
      return offset - bytesPerRow;
    case 'ArrowDown':
      return offset + bytesPerRow;
    case 'PageUp':
      return offset - fullRows * bytesPerRow;
    case 'PageDown':
      return offset + fullRows * bytesPerRow;
    case 'Home':
      return offset - column;
    case 'End':
      return offset - column + bytesPerRow - 1;
    default:
      return offset;
  }
}

/**
 * The widest row of whole byte groups that fits in `availableWidth`.
 *
 * A row's width is linear in groups of eight but not in single bytes, because
 * every group but the last carries a gap: measuring one eight-byte row and one
 * sixteen-byte row therefore gives both the cost of a group and, by subtraction,
 * everything that is not a group - the offset gutter, the pane padding and the
 * gap the final group does not pay. That is why the fit is derived from two
 * probes rather than from a per-cell width read out of the stylesheet.
 *
 * @param {number} availableWidth Width the row has to fit into, in CSS pixels.
 * @param {number} narrowWidth Measured width of a row of `GROUP_SIZE` bytes.
 * @param {number} wideWidth Measured width of a row of `GROUP_SIZE * 2` bytes.
 * @returns {number} Bytes per row, a multiple of eight, or the default when the probes are unusable.
 */
export function fitBytesPerRow(availableWidth, narrowWidth, wideWidth) {
  const block = wideWidth - narrowWidth;
  if (!(block > 0) || !(availableWidth > 0)) {
    return BYTES_PER_ROW;
  }
  const fixed = narrowWidth - block;
  const blocks = Math.floor((availableWidth - fixed) / block);
  return clamp(blocks, FIT_MIN_BLOCKS, FIT_MAX_BLOCKS) * GROUP_SIZE;
}

/**
 * The stored row-width setting a value stands for.
 *
 * @param {number|string} value Setting to interpret.
 * @returns {number|string} One of `BYTES_PER_ROW_CHOICES`, `FIT_TO_WIDTH`, or the default width.
 */
export function normalizeBytesPerRow(value) {
  if (value === FIT_TO_WIDTH) {
    return FIT_TO_WIDTH;
  }
  const width = Number(value);
  return BYTES_PER_ROW_CHOICES.includes(width) ? width : BYTES_PER_ROW;
}

/* The single decision point for "does this key event move the caret between the
   hex and ASCII panes". It is a plain function of the event rather than a case
   in the keydown switch because Tab used to hold this job, which made the
   editor a keyboard trap: both Tab and Shift+Tab were swallowed, so a user who
   arrived here without a pointer could not reach the docks, the tab strip or
   the status bar again. Tab now belongs to the browser, and the pane switch
   answers to F6 and Ctrl+Tab. */
function switchesPane(event) {
  if (event.altKey || event.metaKey) {
    return false;
  }
  if (event.key === 'F6') {
    return !event.ctrlKey;
  }
  return event.key === 'Tab' && event.ctrlKey;
}

function normalizeRange(entry) {
  if (Array.isArray(entry)) {
    return { start: Number(entry[0]) || 0, length: Number(entry[1]) || 0 };
  }
  const start = Number(entry.offset ?? entry.start ?? 0) || 0;
  const length = Number(entry.length ?? entry.size ?? 0) || 0;
  return { start, length };
}

/** Sorted ranges answering "which of these sixteen bytes are covered" quickly. */
class RangeSet {
  #starts = [];
  #ends = [];
  #maxEnds = [];

  set(entries) {
    const ranges = [];
    for (const entry of entries ?? []) {
      const { start, length } = normalizeRange(entry);
      if (length > 0 && start >= 0) {
        ranges.push({ start, end: start + length });
      }
    }
    ranges.sort((left, right) => left.start - right.start);
    this.#starts = ranges.map((range) => range.start);
    this.#ends = ranges.map((range) => range.end);
    this.#maxEnds = [];
    let running = -1;
    for (const end of this.#ends) {
      running = Math.max(running, end);
      this.#maxEnds.push(running);
    }
  }

  get empty() {
    return this.#starts.length === 0;
  }

  get count() {
    return this.#starts.length;
  }

  /** Index of the first range that could still reach `offset`. */
  #firstCandidate(offset) {
    let low = 0;
    let high = this.#maxEnds.length;
    while (low < high) {
      const mid = (low + high) >> 1;
      if (this.#maxEnds[mid] > offset) {
        high = mid;
      } else {
        low = mid + 1;
      }
    }
    return low;
  }

  /** Write per-byte flags for one row into `flags`, which must hold sixteen entries. */
  fill(rowStart, flags) {
    flags.fill(0);
    if (this.#starts.length === 0) {
      return false;
    }
    const rowEnd = rowStart + flags.length;
    let touched = false;
    for (let index = this.#firstCandidate(rowStart); index < this.#starts.length; index += 1) {
      const start = this.#starts[index];
      if (start >= rowEnd) {
        break;
      }
      const end = this.#ends[index];
      if (end <= rowStart) {
        continue;
      }
      const from = Math.max(start, rowStart) - rowStart;
      const to = Math.min(end, rowEnd) - rowStart;
      for (let cell = from; cell < to; cell += 1) {
        flags[cell] |= IN_RANGE;
      }
      if (start >= rowStart) {
        flags[start - rowStart] |= AT_START;
      }
      if (end <= rowEnd) {
        flags[end - 1 - rowStart] |= AT_END;
      }
      touched = true;
    }
    return touched;
  }

  contains(offset) {
    for (let index = this.#firstCandidate(offset); index < this.#starts.length; index += 1) {
      if (this.#starts[index] > offset) {
        return false;
      }
      if (this.#ends[index] > offset) {
        return true;
      }
    }
    return false;
  }
}

/** A bounded set of byte windows, oldest evicted first. */
class WindowCache {
  #entries = new Map();
  #key = '';
  #chunks = [];

  reset(key) {
    if (key === this.#key) {
      return;
    }
    this.#key = key;
    this.#entries.clear();
    this.#chunks = [];
  }

  clear() {
    this.#entries.clear();
    this.#chunks = [];
  }

  has(offset) {
    return this.#entries.has(offset);
  }

  store(offset, bytes) {
    if (this.#entries.has(offset)) {
      this.#entries.delete(offset);
    }
    this.#entries.set(offset, bytes);
    while (this.#entries.size > CACHE_LIMIT) {
      const oldest = this.#entries.keys().next().value;
      this.#entries.delete(oldest);
    }
    this.#chunks = [...this.#entries.entries()].map(([start, data]) => ({ start, data })).sort((a, b) => a.start - b.start);
  }

  /** The chunk covering `offset`, or null. */
  chunkAt(offset) {
    for (const chunk of this.#chunks) {
      if (offset >= chunk.start && offset < chunk.start + chunk.data.length) {
        return chunk;
      }
    }
    return null;
  }

  byteAt(offset) {
    const chunk = this.chunkAt(offset);
    return chunk === null ? -1 : chunk.data[offset - chunk.start];
  }
}

function byteClass(value) {
  if (value === 0) {
    return 'bc-null';
  }
  if (value >= PRINTABLE_LOW && value <= PRINTABLE_HIGH) {
    return 'bc-print';
  }
  return value >= HIGH_BYTE ? 'bc-high' : 'bc-ctrl';
}

function asciiGlyph(value) {
  return value >= PRINTABLE_LOW && value <= PRINTABLE_HIGH ? String.fromCharCode(value) : DOT;
}

function offsetLabel(offset) {
  return offset.toString(HEX_RADIX).toUpperCase().padStart(OFFSET_DIGITS, '0');
}

function setText(element, text) {
  if (element.textContent !== text) {
    element.textContent = text;
  }
}

function setClass(element, className) {
  if (element.className !== className) {
    element.className = className;
  }
}

function setAttribute(element, name, value) {
  if (element.getAttribute(name) !== value) {
    element.setAttribute(name, value);
  }
}

/** The virtualized, editable hex view. */
export class HexGrid {
  #root;
  #onSelect;
  #onCaret;
  #onMetrics;
  #onDocument;
  #onError;

  #editor;
  #rulerHost;
  #rulerColumns = [];
  #scroller;
  #spacer;
  #viewport;
  #busy;
  #busyLabel;

  #rows = [];
  #rowHeight = 0;
  #rowWidth = 0;
  #bytesPerRow = BYTES_PER_ROW;
  #bytesPerRowSetting = BYTES_PER_ROW;
  #bytesPerRowByDocument = new Map();
  #fitNarrowPx = 0;
  #fitWidePx = 0;

  #document = null;
  #anchorRow = 0;
  #scale = 1;
  #scrollerCap = 0;
  #scrollerPx = 0;
  #capRatio = 0;
  #capConfirmed = false;
  #visibleRows = 1;
  #fullRows = 1;
  #suppressScroll = false;
  #frame = 0;

  #caretOffset = 0;
  #caretNibble = NIBBLE_HIGH;
  #caretPane = PANE_HEX;
  #selectionAnchor = null;
  #selectionFocus = null;
  #dragging = false;
  #insertMode = false;
  #focused = false;

  #layers = new Map();
  #layerFlags = new Map();
  #modified = new RangeSet();
  #modifiedRanges = [];
  #selectionSet = new RangeSet();

  #cache = new WindowCache();
  #fetchController = null;
  #fetchKey = '';
  #busyTimer = 0;
  #editChain = Promise.resolve();

  #cellIdPrefix = nextId('hbcell');
  #speakTimer = 0;

  constructor(root, handlers = {}) {
    this.#root = root;
    this.#onSelect = handlers.onSelect ?? (() => undefined);
    this.#onCaret = handlers.onCaret ?? (() => undefined);
    this.#onMetrics = handlers.onMetrics ?? (() => undefined);
    this.#onDocument = handlers.onDocument ?? (() => undefined);
    this.#onError = handlers.onError ?? (() => undefined);
    this.#build();
    this.#bind();
  }

  /* ---------------------------------------------------------------- build */

  #build() {
    this.#root.replaceChildren();

    this.#editor = document.createElement('div');
    this.#editor.className = 'hb-editor';

    const ruler = document.createElement('div');
    ruler.className = 'hb-ruler';
    const gutter = document.createElement('span');
    gutter.className = 'hb-ruler-gutter';
    gutter.textContent = 'OFFSET';
    const columns = document.createElement('span');
    columns.className = 'hb-ruler-cols';
    this.#rulerHost = columns;
    this.#renderRuler();
    const rulerAscii = document.createElement('span');
    rulerAscii.className = 'hb-ruler-ascii';
    rulerAscii.textContent = 'ASCII';
    ruler.append(gutter, columns, rulerAscii);

    this.#scroller = document.createElement('div');
    this.#scroller.className = 'hb-rows';
    this.#scroller.tabIndex = 0;
    this.#scroller.setAttribute('role', 'grid');
    this.#scroller.setAttribute('aria-label', 'Hex view');
    this.#scroller.setAttribute('aria-colcount', String(this.#columnCount()));

    this.#spacer = document.createElement('div');
    this.#spacer.className = 'hbx-spacer';
    this.#spacer.setAttribute('aria-hidden', 'true');

    /* The scroller carries role="grid", so the element between it and the rows
       has to be something a grid may own or the rows stop being the grid's.
       Same reason the two panes inside a row are presentational: a gridcell has
       to be a child of its row in the accessibility tree, not a grandchild. */
    this.#viewport = document.createElement('div');
    this.#viewport.className = 'hbx-viewport';
    this.#viewport.setAttribute('role', 'rowgroup');

    this.#busy = document.createElement('div');
    this.#busy.className = 'hbx-busy hb-busy';
    this.#busy.hidden = true;
    this.#busyLabel = document.createElement('div');
    this.#busyLabel.className = 'hb-busy-label';
    this.#busyLabel.textContent = 'reading';
    this.#busy.appendChild(this.#busyLabel);

    this.#scroller.append(this.#spacer, this.#viewport, this.#busy);
    this.#editor.append(ruler, this.#scroller);
    this.#root.appendChild(this.#editor);
  }

  #isGroupEnd(column) {
    return column % GROUP_SIZE === GROUP_SIZE - 1 && column !== this.#bytesPerRow - 1;
  }

  /** Columns the grid claims: the offset header plus one per byte in each pane. */
  #columnCount() {
    return 1 + this.#bytesPerRow * 2;
  }

  #renderRuler() {
    while (this.#rulerColumns.length > this.#bytesPerRow) {
      this.#rulerColumns.pop().remove();
    }
    while (this.#rulerColumns.length < this.#bytesPerRow) {
      const cell = document.createElement('span');
      this.#rulerHost.appendChild(cell);
      this.#rulerColumns.push(cell);
    }
    for (let column = 0; column < this.#rulerColumns.length; column += 1) {
      setClass(this.#rulerColumns[column], this.#isGroupEnd(column) ? 'hb-ruler-col is-group-end' : 'hb-ruler-col');
      setText(this.#rulerColumns[column], column.toString(HEX_RADIX).toUpperCase().padStart(2, '0'));
    }
  }

  /** The size a real row of `columns` bytes takes, measured off the live stylesheet. */
  #measureRow(columns) {
    const probe = document.createElement('div');
    probe.className = 'hb-row';
    probe.style.position = 'absolute';
    probe.style.left = '-10000px';
    probe.style.top = '0';
    probe.style.visibility = 'hidden';
    probe.style.pointerEvents = 'none';

    const gutter = document.createElement('span');
    gutter.className = 'hb-offset';
    gutter.textContent = offsetLabel(0);
    const hexPane = document.createElement('span');
    hexPane.className = 'hb-hexpane';
    const asciiPane = document.createElement('span');
    asciiPane.className = 'hb-asciipane';
    for (let column = 0; column < columns; column += 1) {
      const cell = document.createElement('span');
      cell.className = column % GROUP_SIZE === GROUP_SIZE - 1 && column !== columns - 1 ? 'hb-byte is-group-end' : 'hb-byte';
      cell.textContent = 'M0';
      hexPane.appendChild(cell);
      const glyph = document.createElement('span');
      glyph.className = 'hb-ascii';
      glyph.textContent = 'M';
      asciiPane.appendChild(glyph);
    }
    probe.append(gutter, hexPane, asciiPane);
    this.#editor.appendChild(probe);
    const rect = probe.getBoundingClientRect();
    probe.remove();
    return rect;
  }

  #measure() {
    const rect = this.#measureRow(this.#bytesPerRow);
    if (rect.height > 0) {
      this.#rowHeight = rect.height;
      this.#rowWidth = rect.width;
    }
  }

  /** Bytes per row the pane is currently wide enough for. */
  #measureFit() {
    if (this.#fitWidePx <= this.#fitNarrowPx) {
      this.#fitNarrowPx = this.#measureRow(GROUP_SIZE).width;
      this.#fitWidePx = this.#measureRow(GROUP_SIZE * 2).width;
    }
    return fitBytesPerRow(this.#scroller.clientWidth, this.#fitNarrowPx, this.#fitWidePx);
  }

  #buildRow() {
    const element = document.createElement('div');
    element.className = 'hb-row';
    element.setAttribute('role', 'row');
    const offset = document.createElement('span');
    offset.className = 'hb-offset';
    offset.setAttribute('role', 'rowheader');
    offset.setAttribute('aria-colindex', '1');
    const hexPane = document.createElement('span');
    hexPane.className = 'hb-hexpane';
    hexPane.setAttribute('role', 'presentation');
    const asciiPane = document.createElement('span');
    asciiPane.className = 'hb-asciipane';
    asciiPane.setAttribute('role', 'presentation');

    const hexCells = [];
    const asciiCells = [];
    for (let column = 0; column < this.#bytesPerRow; column += 1) {
      const cell = document.createElement('span');
      cell.className = 'hb-byte';
      cell.dataset.pane = PANE_HEX;
      cell.dataset.column = String(column);
      cell.setAttribute('role', 'gridcell');
      cell.setAttribute('aria-colindex', String(column + 2));
      hexPane.appendChild(cell);
      hexCells.push(cell);

      const glyph = document.createElement('span');
      glyph.className = 'hb-ascii';
      glyph.dataset.pane = PANE_ASCII;
      glyph.dataset.column = String(column);
      glyph.setAttribute('role', 'gridcell');
      glyph.setAttribute('aria-colindex', String(this.#bytesPerRow + column + 2));
      asciiPane.appendChild(glyph);
      asciiCells.push(glyph);
    }
    element.append(offset, hexPane, asciiPane);
    return { element, offset, hexCells, asciiCells, start: -1 };
  }

  /* ----------------------------------------------------------------- bind */

  #bind() {
    this.#scroller.addEventListener('scroll', () => {
      if (this.#suppressScroll) {
        this.#suppressScroll = false;
        this.#schedule();
        return;
      }
      const derived = this.#anchorFromScrollTop(this.#scroller.scrollTop);
      this.#anchorRow = clamp(derived, 0, this.#maxAnchorRow());
      this.#schedule();
    }, { passive: true });

    this.#scroller.addEventListener('wheel', (event) => {
      if (event.ctrlKey) {
        return;
      }
      event.preventDefault();
      this.#stepRows(this.#wheelRows(event));
    }, { passive: false });

    this.#scroller.addEventListener('mousedown', (event) => this.#onMouseDown(event));
    this.#scroller.addEventListener('mousemove', (event) => this.#onMouseMove(event));
    this.#scroller.addEventListener('dblclick', (event) => this.#onDoubleClick(event));
    window.addEventListener('mouseup', () => {
      this.#dragging = false;
    });

    this.#scroller.addEventListener('focus', () => {
      this.#focused = true;
      this.#schedule();
    });
    this.#scroller.addEventListener('blur', () => {
      this.#focused = false;
      this.#dragging = false;
      this.#schedule();
    });
    this.#scroller.addEventListener('keydown', (event) => this.#onKeyDown(event));

    const observer = new ResizeObserver(() => this.#schedule());
    observer.observe(this.#scroller);
  }

  #wheelRows(event) {
    const height = this.#rowHeightOrFallback();
    if (event.deltaMode === WheelEvent.DOM_DELTA_LINE) {
      return Math.round(event.deltaY);
    }
    if (event.deltaMode === WheelEvent.DOM_DELTA_PAGE) {
      return Math.round(event.deltaY) * WHEEL_PAGE_ROWS;
    }
    const rows = event.deltaY / height;
    if (rows > 0) {
      return Math.max(1, Math.round(rows));
    }
    if (rows < 0) {
      return Math.min(-1, Math.round(rows));
    }
    return Math.round(event.deltaY / WHEEL_LINE_PX);
  }

  /* ------------------------------------------------------------- geometry */

  #rowHeightOrFallback() {
    return this.#rowHeight > 0 ? this.#rowHeight : FALLBACK_ROW_HEIGHT;
  }

  get #documentLength() {
    return this.#document ? this.#document.length : 0;
  }

  #totalRows() {
    return Math.max(1, Math.ceil(this.#documentLength / this.#bytesPerRow));
  }

  #maxAnchorRow() {
    return Math.max(0, this.#totalRows() - this.#fullRows);
  }

  #stepRows(delta) {
    if (delta === 0) {
      return;
    }
    this.#anchorRow = clamp(this.#anchorRow + delta, 0, this.#maxAnchorRow());
    this.#syncScrollTop();
    this.#schedule();
  }

  /**
   * The scrollable pixel range, which is shorter than the scroller by one viewport.
   *
   * Mapping has to run between ranges, not between raw pixel counts: the last
   * scroll position is `scrollerPx - clientHeight`, and it has to mean the last
   * row rather than a row one scaled viewport short of it. Dividing raw
   * scrollTop by the scale instead loses `fullRows * (scale - 1)` rows off the
   * end of the document, which are then unreachable by the scrollbar.
   */
  #scrollRangePx() {
    return Math.max(0, this.#scrollerPx - this.#scroller.clientHeight);
  }

  #anchorFromScrollTop(scrollTop) {
    const range = this.#scrollRangePx();
    const rows = this.#maxAnchorRow();
    if (range <= 0 || rows <= 0) {
      return 0;
    }
    return Math.round((scrollTop / range) * rows);
  }

  #scrollTopFromAnchor(anchorRow) {
    const range = this.#scrollRangePx();
    const rows = this.#maxAnchorRow();
    if (range <= 0 || rows <= 0) {
      return 0;
    }
    return (clamp(anchorRow, 0, rows) / rows) * range;
  }

  #syncScrollTop() {
    const target = Math.round(this.#scrollTopFromAnchor(this.#anchorRow));
    if (Math.abs(this.#scroller.scrollTop - target) < 1) {
      return;
    }
    this.#suppressScroll = true;
    this.#scroller.scrollTop = target;
  }

  #ensureVisible(offset) {
    const row = Math.floor(offset / this.#bytesPerRow);
    const last = this.#anchorRow + this.#fullRows - 1;
    if (row < this.#anchorRow) {
      this.#anchorRow = row;
    } else if (row > last) {
      this.#anchorRow = row - this.#fullRows + 1;
    } else {
      return;
    }
    this.#anchorRow = clamp(this.#anchorRow, 0, this.#maxAnchorRow());
    this.#syncScrollTop();
  }

  /* ---------------------------------------------------------------- state */

  /** Point the grid at a document, resetting caches when it has moved on. */
  setDocument(info) {
    const previous = this.#document;
    this.#document = info;
    if (!info) {
      this.#cache.clear();
      this.#caretOffset = 0;
      this.#clearSelection();
      this.#schedule();
      return;
    }
    const changedDocument = !previous || previous.handle !== info.handle;
    if (changedDocument) {
      this.#applySetting(this.#bytesPerRowByDocument.get(info.handle) ?? BYTES_PER_ROW);
      this.#cache.reset(`${info.handle}:${info.generation}`);
      this.#modifiedRanges = [];
      this.#modified.set([]);
      this.#layers.clear();
      this.#layerFlags.clear();
      this.#anchorRow = 0;
      this.#caretOffset = 0;
      this.#caretNibble = NIBBLE_HIGH;
      this.#clearSelection();
      this.#syncScrollTop();
    } else if (previous.generation !== info.generation) {
      this.#cache.reset(`${info.handle}:${info.generation}`);
    }
    this.#caretOffset = clamp(this.#caretOffset, 0, Math.max(0, info.length));
    this.#schedule();
  }

  get document() {
    return this.#document;
  }

  /** Caret position: byte offset, which nibble within it, and which pane owns it. */
  get caret() {
    return { offset: this.#caretOffset, nibble: this.#caretNibble, pane: this.#caretPane };
  }

  /** Current selection, or null when nothing is selected. */
  get selection() {
    if (this.#selectionAnchor === null || this.#selectionFocus === null) {
      return null;
    }
    const start = Math.min(this.#selectionAnchor, this.#selectionFocus);
    const end = Math.max(this.#selectionAnchor, this.#selectionFocus) + 1;
    return { start, end, length: end - start };
  }

  get insertMode() {
    return this.#insertMode;
  }

  set insertMode(value) {
    this.#insertMode = Boolean(value);
    this.#emitCaret();
  }

  /** Bytes the view is actually rendering per row, fit-to-width already resolved. */
  get bytesPerRow() {
    return this.#bytesPerRow;
  }

  /** The chosen row width: one of `BYTES_PER_ROW_CHOICES`, or `FIT_TO_WIDTH`. */
  get bytesPerRowSetting() {
    return this.#bytesPerRowSetting;
  }

  /**
   * Choose the row width, for this document, until it is chosen again.
   *
   * The choice is remembered against the document rather than against the view,
   * because it is a property of what is being read - a 24-byte record is 24
   * bytes wide in every session - and switching tabs would otherwise carry one
   * document's layout onto the next.
   */
  set bytesPerRowSetting(value) {
    this.#applySetting(value);
    this.#schedule();
  }

  #applySetting(value) {
    const setting = normalizeBytesPerRow(value);
    this.#bytesPerRowSetting = setting;
    if (this.#document) {
      this.#bytesPerRowByDocument.set(this.#document.handle, setting);
    }
    this.#applyWidth(setting === FIT_TO_WIDTH ? this.#measureFit() : setting);
  }

  /**
   * Move the view to `width` bytes per row.
   *
   * This is the one place the grid throws its DOM away: every row in the pool
   * holds a fixed number of cells, so a new width means new rows. The byte cache
   * survives untouched - the bytes did not change, only how many of them sit on
   * a line - and the top of the view is held by byte offset rather than by row
   * index so the reader stays where they were looking.
   */
  #applyWidth(width) {
    if (width === this.#bytesPerRow) {
      return;
    }
    const topByte = this.#anchorRow * this.#bytesPerRow;
    this.#bytesPerRow = width;
    this.#anchorRow = Math.floor(topByte / width);
    this.#renderRuler();
    this.#rows = [];
    this.#viewport.replaceChildren();
    for (const className of this.#layerFlags.keys()) {
      this.#layerFlags.set(className, new Uint8Array(width));
    }
    this.#scroller.setAttribute('aria-colcount', String(this.#columnCount()));
  }

  /** Scroll rows so `offset` is on screen and put the caret on it. */
  seek(offset) {
    const target = clamp(Math.floor(offset), 0, Math.max(0, this.#documentLength));
    this.#caretOffset = target;
    this.#caretNibble = NIBBLE_HIGH;
    this.#ensureVisible(target);
    this.#emitCaret();
    this.#schedule();
  }

  /** Select `length` bytes from `offset`, leaving the caret at the start. */
  select(offset, length) {
    if (length <= 0 || this.#documentLength <= 0) {
      this.#clearSelection();
      this.seek(offset);
      return;
    }
    const total = this.#documentLength;
    const start = clamp(Math.floor(offset), 0, total - 1);
    const end = clamp(start + Math.floor(length) - 1, start, total - 1);
    this.#selectionAnchor = start;
    this.#selectionFocus = end;
    this.#caretOffset = start;
    this.#caretNibble = NIBBLE_HIGH;
    this.#refreshSelectionSet();
    this.#ensureVisible(start);
    this.#emitSelection();
    this.#emitCaret();
    this.#schedule();
  }

  /**
   * Paint a set of ranges with one of the design system's overlay classes.
   *
   * Passing an empty list removes the layer. The overlay classes compose, so a
   * byte can be a search hit inside a template field inside a selection and show
   * all three.
   */
  highlight(ranges, className) {
    if (!ranges || ranges.length === 0) {
      this.#layers.delete(className);
      this.#layerFlags.delete(className);
    } else {
      const set = this.#layers.get(className) ?? new RangeSet();
      set.set(ranges);
      this.#layers.set(className, set);
      this.#layerFlags.set(className, new Uint8Array(this.#bytesPerRow));
    }
    this.#schedule();
  }

  /** Every range currently painted with `className`. */
  hasHighlight(className) {
    return this.#layers.has(className);
  }

  /** Remember that these bytes were edited in this session. */
  markModified(offset, length) {
    if (length <= 0) {
      return;
    }
    this.#modifiedRanges.push({ start: offset, length });
    this.#modified.set(this.#modifiedRanges);
  }

  /** Drop every cached window and repaint from the server. */
  invalidate() {
    this.#cache.clear();
    this.#fetchKey = '';
    this.#schedule();
  }

  /** Put keyboard focus on the view. */
  focus() {
    this.#scroller.focus();
  }

  /** Move the caret between the hex and the ASCII pane. */
  togglePane() {
    this.#caretPane = this.#caretPane === PANE_HEX ? PANE_ASCII : PANE_HEX;
    this.#caretNibble = NIBBLE_HIGH;
    this.#emitCaret();
    this.#schedule();
  }

  #clearSelection() {
    this.#selectionAnchor = null;
    this.#selectionFocus = null;
    this.#selectionSet.set([]);
    this.#emitSelection();
  }

  #refreshSelectionSet() {
    const selection = this.selection;
    this.#selectionSet.set(selection === null ? [] : [{ start: selection.start, length: selection.length }]);
  }

  #emitSelection() {
    this.#onSelect(this.selection);
  }

  #emitCaret() {
    this.#syncActiveDescendant();
    this.#speakCaret();
    this.#onCaret({ ...this.caret, insertMode: this.#insertMode });
  }

  /** The id the caret's cell carries while it is rendered, in the pane that owns the caret. */
  #caretCellId() {
    return this.#cellId(this.#caretPane, this.#caretOffset);
  }

  #cellId(pane, offset) {
    return `${this.#cellIdPrefix}-${pane}-${offset}`;
  }

  /** The rendered element under the caret, or null while the caret is scrolled out of the pool. */
  #caretCell() {
    const column = this.#caretOffset % this.#bytesPerRow;
    const rowStart = this.#caretOffset - column;
    for (const row of this.#rows) {
      if (row.start === rowStart && !row.element.hidden) {
        return this.#caretPane === PANE_ASCII ? row.asciiCells[column] : row.hexCells[column];
      }
    }
    return null;
  }

  /**
   * Point the grid at the cell the caret is on.
   *
   * The attribute has to name an element that exists, so it is dropped rather
   * than left pointing into the pool whenever the caret's row is not currently
   * rendered - which happens for the frame between a seek and the paint that
   * catches up with it. #paint calls this again once the row is really there.
   */
  #syncActiveDescendant() {
    const cell = this.#caretCell();
    if (cell === null) {
      this.#scroller.removeAttribute('aria-activedescendant');
      return;
    }
    const id = this.#caretCellId();
    if (this.#scroller.getAttribute('aria-activedescendant') !== id) {
      this.#scroller.setAttribute('aria-activedescendant', id);
    }
  }

  /**
   * Say where the caret is, once the caret has stopped moving.
   *
   * Held back deliberately: arrowing across a row fires this on every keystroke
   * and a live region that restarts mid-word says nothing useful. Only the caret
   * is spoken here - the selection and the hit count are announced by the status
   * bar, and saying them twice is worse than saying them once.
   */
  #speakCaret() {
    if (this.#speakTimer !== 0) {
      window.clearTimeout(this.#speakTimer);
    }
    this.#speakTimer = window.setTimeout(() => {
      this.#speakTimer = 0;
      announce(this.#caretDescription());
    }, CARET_SPEAK_MS);
  }

  #caretDescription() {
    const offset = this.#caretOffset;
    const parts = [`offset 0x${offsetLabel(offset)}`];
    const value = offset < this.#documentLength ? this.#cache.byteAt(offset) : -1;
    if (value >= 0) {
      parts.push(`byte ${toHex(Uint8Array.of(value))}`);
      if (value >= PRINTABLE_LOW && value <= PRINTABLE_HIGH) {
        parts.push(`character ${asciiGlyph(value)}`);
      }
    } else if (offset >= this.#documentLength) {
      parts.push('end of document');
    }
    parts.push(`${this.#caretPane} pane`);
    if (this.#insertMode) {
      parts.push('insert');
    }
    return parts.join(', ');
  }

  /* ---------------------------------------------------------------- input */

  #cellFromEvent(event) {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
      return null;
    }
    const cell = target.closest('[data-column]');
    if (!cell || !this.#scroller.contains(cell)) {
      return null;
    }
    const row = cell.closest('.hb-row');
    if (!row || row.dataset.start === undefined) {
      return null;
    }
    const start = Number(row.dataset.start);
    const column = Number(cell.dataset.column);
    const offset = start + column;
    if (offset >= this.#documentLength) {
      return null;
    }
    const rect = cell.getBoundingClientRect();
    const nibble = event.clientX - rect.left > rect.width / 2 ? NIBBLE_LOW : NIBBLE_HIGH;
    return { offset, pane: cell.dataset.pane, nibble };
  }

  #onMouseDown(event) {
    if (event.button !== 0) {
      return;
    }
    const hit = this.#cellFromEvent(event);
    if (hit === null) {
      return;
    }
    this.#scroller.focus({ preventScroll: true });
    this.#caretPane = hit.pane;
    this.#caretNibble = hit.pane === PANE_HEX ? hit.nibble : NIBBLE_HIGH;
    if (event.shiftKey && this.#selectionAnchor !== null) {
      this.#selectionFocus = hit.offset;
    } else {
      this.#selectionAnchor = hit.offset;
      this.#selectionFocus = hit.offset;
    }
    this.#caretOffset = hit.offset;
    this.#dragging = true;
    this.#refreshSelectionSet();
    this.#emitSelection();
    this.#emitCaret();
    this.#schedule();
  }

  #onMouseMove(event) {
    if (!this.#dragging) {
      return;
    }
    const hit = this.#cellFromEvent(event);
    if (hit === null) {
      return;
    }
    this.#selectionFocus = hit.offset;
    this.#caretOffset = hit.offset;
    this.#refreshSelectionSet();
    this.#emitSelection();
    this.#emitCaret();
    this.#schedule();
  }

  #onDoubleClick(event) {
    const hit = this.#cellFromEvent(event);
    if (hit === null) {
      return;
    }
    this.select(hit.offset, 1);
  }

  #onKeyDown(event) {
    if (switchesPane(event)) {
      event.preventDefault();
      this.togglePane();
      return;
    }
    if (event.ctrlKey || event.altKey || event.metaKey) {
      this.#onModifiedKey(event);
      return;
    }
    const extend = event.shiftKey;
    switch (event.key) {
      case 'ArrowLeft': {
        event.preventDefault();
        const step = this.#stepLeft();
        this.#moveCaret(step.offset, extend, step.nibble);
        return;
      }
      case 'ArrowRight': {
        event.preventDefault();
        const step = this.#stepRight();
        this.#moveCaret(step.offset, extend, step.nibble);
        return;
      }
      case 'ArrowUp':
      case 'ArrowDown':
      case 'PageUp':
      case 'PageDown':
      case 'Home':
      case 'End':
        event.preventDefault();
        this.#moveCaret(this.#rowTarget(event.key), extend);
        return;
      case 'Insert':
        event.preventDefault();
        this.insertMode = !this.#insertMode;
        return;
      case 'Escape':
        this.#clearSelection();
        this.#schedule();
        return;
      case 'Backspace':
        event.preventDefault();
        this.#deleteBackward();
        return;
      case 'Delete':
        event.preventDefault();
        this.#deleteForward();
        return;
      default:
        break;
    }
    if (event.key.length === 1) {
      this.#typeCharacter(event);
    }
  }

  #onModifiedKey(event) {
    if (!event.ctrlKey || event.altKey) {
      return;
    }
    if (event.key === 'Home') {
      event.preventDefault();
      this.#moveCaret(0, event.shiftKey);
    } else if (event.key === 'End') {
      event.preventDefault();
      this.#moveCaret(Math.max(0, this.#documentLength - 1), event.shiftKey);
    } else if (event.key === 'a' || event.key === 'A') {
      event.preventDefault();
      this.select(0, this.#documentLength);
    }
  }

  #rowTarget(key) {
    return caretRowTarget(key, this.#caretOffset, this.#bytesPerRow, this.#fullRows);
  }

  #stepLeft() {
    if (this.#caretPane === PANE_HEX && this.#caretNibble === NIBBLE_LOW) {
      return { offset: this.#caretOffset, nibble: NIBBLE_HIGH };
    }
    return { offset: this.#caretOffset - 1, nibble: NIBBLE_LOW };
  }

  #stepRight() {
    if (this.#caretPane === PANE_HEX && this.#caretNibble === NIBBLE_HIGH) {
      return { offset: this.#caretOffset, nibble: NIBBLE_LOW };
    }
    return { offset: this.#caretOffset + 1, nibble: NIBBLE_HIGH };
  }

  #moveCaret(target, extend, nibble) {
    const last = Math.max(0, this.#documentLength - 1);
    const next = clamp(target, 0, last);
    if (nibble !== undefined) {
      this.#caretNibble = nibble;
    } else if (next !== this.#caretOffset) {
      this.#caretNibble = NIBBLE_HIGH;
    }
    this.#caretOffset = next;
    if (extend) {
      this.#selectionAnchor ??= next;
      this.#selectionFocus = next;
      this.#refreshSelectionSet();
      this.#emitSelection();
    } else if (this.#selectionAnchor !== null) {
      this.#clearSelection();
    }
    this.#ensureVisible(next);
    this.#emitCaret();
    this.#schedule();
  }

  /* --------------------------------------------------------------- edits */

  #queue(work) {
    this.#editChain = this.#editChain.then(work, work).catch((error) => {
      if (!isAborted(error)) {
        this.#onError(error);
      }
    });
    return this.#editChain;
  }

  async #run(name, args) {
    const result = await callOp(name, { handle: this.#document.handle, arguments: args });
    if (result.document) {
      this.setDocument(result.document);
      this.#onDocument(result.document);
    }
    return result;
  }

  async #byteAt(offset) {
    const cached = this.#cache.byteAt(offset);
    if (cached >= 0) {
      return cached;
    }
    const result = await callOp('read_byte', { handle: this.#document.handle, arguments: { offset } });
    return Number(result.value);
  }

  /** Overwrite one byte, extending the document when the caret sits past its end. */
  writeByte(offset, value) {
    if (!this.#document) {
      return Promise.resolve();
    }
    const hex = toHex(Uint8Array.of(value & BYTE_MASK));
    const past = offset >= this.#documentLength;
    return this.#queue(async () => {
      await this.#run(past ? 'insert_bytes' : 'write_bytes', { offset: Math.min(offset, this.#documentLength), data: hex });
      this.markModified(offset, 1);
    });
  }

  /** Insert bytes at `offset`, pushing everything after it along. */
  insertBytes(offset, bytes) {
    if (!this.#document || bytes.length === 0) {
      return Promise.resolve();
    }
    const hex = toHex(bytes);
    return this.#queue(async () => {
      await this.#run('insert_bytes', { offset: clamp(offset, 0, this.#documentLength), data: hex });
      this.markModified(offset, bytes.length);
    });
  }

  /** Overwrite bytes at `offset`. */
  writeBytes(offset, bytes) {
    if (!this.#document || bytes.length === 0) {
      return Promise.resolve();
    }
    const hex = toHex(bytes);
    return this.#queue(async () => {
      await this.#run('write_bytes', { offset, data: hex });
      this.markModified(offset, bytes.length);
    });
  }

  /** Remove `length` bytes at `offset`. */
  deleteBytes(offset, length) {
    if (!this.#document || length <= 0) {
      return Promise.resolve();
    }
    return this.#queue(async () => {
      await this.#run('delete_bytes', { offset, length });
      this.#clearSelection();
      this.#caretOffset = clamp(offset, 0, Math.max(0, this.#documentLength));
    });
  }

  #deleteBackward() {
    const selection = this.selection;
    if (selection !== null) {
      this.deleteBytes(selection.start, selection.length);
      return;
    }
    if (this.#caretOffset > 0) {
      const target = this.#caretOffset - 1;
      this.deleteBytes(target, 1);
    }
  }

  #deleteForward() {
    const selection = this.selection;
    if (selection !== null) {
      this.deleteBytes(selection.start, selection.length);
      return;
    }
    if (this.#caretOffset < this.#documentLength) {
      this.deleteBytes(this.#caretOffset, 1);
    }
  }

  #typeCharacter(event) {
    if (!this.#document) {
      return;
    }
    if (this.#caretPane === PANE_HEX) {
      const digit = Number.parseInt(event.key, HEX_RADIX);
      if (Number.isNaN(digit) || !/^[0-9a-fA-F]$/.test(event.key)) {
        return;
      }
      event.preventDefault();
      this.#typeNibble(digit);
      return;
    }
    const code = event.key.codePointAt(0);
    if (code === undefined || code > BYTE_MASK) {
      return;
    }
    event.preventDefault();
    this.#typeByte(code);
  }

  /**
   * Edit one nibble under the caret.
   *
   * The caret advances here rather than after the write completes. A person can
   * out-type a round trip, and a second keystroke that read the caret back
   * before the first had moved it would write its digit into the nibble the
   * first one had just filled.
   */
  #typeNibble(digit) {
    const offset = this.#caretOffset;
    const nibble = this.#caretNibble;
    const total = this.#documentLength;
    const insertingNew = (this.#insertMode && nibble === NIBBLE_HIGH) || offset >= total;

    if (nibble === NIBBLE_HIGH || insertingNew) {
      this.#caretNibble = NIBBLE_LOW;
    } else {
      this.#caretNibble = NIBBLE_HIGH;
      this.#caretOffset = clamp(offset + 1, 0, total);
      this.#ensureVisible(this.#caretOffset);
    }
    this.#emitCaret();
    this.#schedule();

    if (insertingNew) {
      this.#queue(async () => {
        await this.#run('insert_bytes', { offset: Math.min(offset, this.#documentLength), data: toHex(Uint8Array.of(digit << NIBBLE_BITS)) });
        this.markModified(offset, 1);
      });
      return;
    }
    this.#queue(async () => {
      const current = await this.#byteAt(offset);
      const merged = nibble === NIBBLE_HIGH ? (digit << NIBBLE_BITS) | (current & LOW_MASK) : (current & HIGH_MASK) | digit;
      await this.#run('write_bytes', { offset, data: toHex(Uint8Array.of(merged)) });
      this.markModified(offset, 1);
    });
  }

  #typeByte(value) {
    const offset = this.#caretOffset;
    const total = this.#documentLength;
    const insertingNew = this.#insertMode || offset >= total;
    const newTotal = insertingNew ? total + 1 : total;
    this.#caretOffset = clamp(offset + 1, 0, newTotal);
    this.#caretNibble = NIBBLE_HIGH;
    this.#ensureVisible(this.#caretOffset);
    this.#emitCaret();
    this.#schedule();
    this.#queue(async () => {
      await this.#run(insertingNew ? 'insert_bytes' : 'write_bytes', {
        offset: Math.min(offset, this.#documentLength),
        data: toHex(Uint8Array.of(value & BYTE_MASK)),
      });
      this.markModified(offset, 1);
    });
  }

  /* --------------------------------------------------------------- render */

  #schedule() {
    if (this.#frame !== 0) {
      return;
    }
    this.#frame = window.requestAnimationFrame(() => {
      this.#frame = 0;
      this.#render();
    });
  }

  /**
   * How tall the scroller is allowed to grow, in CSS pixels.
   *
   * The engine's real ceiling is its fixed-point layout range divided by the
   * device pixel ratio, so a display at 175% caps out near 19.2M rather than
   * 33.5M. Guessing high is not harmless: the browser clamps the spacer
   * silently, and every scrollTop the grid computes from the unclamped height
   * then points at the wrong row. The ratio gives a sound starting figure and
   * #sizeScroller confirms it against what the browser actually did.
   */
  #scrollerCapPx() {
    const ratio = Math.max(1, window.devicePixelRatio || 1);
    if (this.#capRatio !== ratio) {
      this.#capRatio = ratio;
      this.#scrollerCap = Math.min(MAX_SCROLLER_PX, Math.floor(LAYOUT_UNIT_MAX_PX / ratio));
      this.#capConfirmed = false;
    }
    return this.#scrollerCap;
  }

  #writeSpacer(px) {
    const text = `${Math.floor(px)}px`;
    if (this.#spacer.style.height !== text) {
      this.#spacer.style.height = text;
    }
  }

  #sizeScroller(realPx, viewHeight) {
    const cap = this.#scrollerCapPx();
    let cappedPx = Math.min(realPx, cap);
    this.#writeSpacer(Math.max(cappedPx, viewHeight));
    if (this.#capConfirmed || cappedPx < cap) {
      return cappedPx;
    }
    this.#capConfirmed = true;
    const achieved = this.#scroller.scrollHeight;
    if (achieved > viewHeight && achieved < cappedPx - 1) {
      this.#scrollerCap = achieved;
      cappedPx = Math.min(realPx, achieved);
      this.#writeSpacer(Math.max(cappedPx, viewHeight));
    }
    return cappedPx;
  }

  #render() {
    if (this.#rowHeight === 0) {
      this.#measure();
    }
    if (this.#bytesPerRowSetting === FIT_TO_WIDTH) {
      this.#applyWidth(this.#measureFit());
    }
    const height = this.#rowHeightOrFallback();
    const viewHeight = this.#scroller.clientHeight;
    this.#visibleRows = Math.max(1, Math.ceil(viewHeight / height) + 1);
    this.#fullRows = Math.max(1, Math.floor(viewHeight / height));

    const totalRows = this.#totalRows();
    if (this.#scroller.getAttribute('aria-rowcount') !== String(totalRows)) {
      this.#scroller.setAttribute('aria-rowcount', String(totalRows));
    }
    const realPx = totalRows * height;
    const scrollerPx = this.#sizeScroller(realPx, viewHeight);
    this.#scrollerPx = scrollerPx;
    this.#scale = realPx > 0 && scrollerPx > 0 ? realPx / scrollerPx : 1;

    if (this.#rowWidth > 0) {
      const spacerWidth = `${Math.ceil(this.#rowWidth)}px`;
      if (this.#spacer.style.width !== spacerWidth) {
        this.#spacer.style.width = spacerWidth;
      }
    }

    this.#anchorRow = clamp(this.#anchorRow, 0, this.#maxAnchorRow());
    const anchorPx = this.#scrollTopFromAnchor(this.#anchorRow);
    if (Math.abs(this.#scroller.scrollTop - anchorPx) >= height) {
      this.#syncScrollTop();
    }
    this.#viewport.style.transform = `translateY(${anchorPx}px)`;

    this.#paint(this.#syncPool());
    this.#ensureData();
    this.#emitMetrics();
  }

  #syncPool() {
    const wanted = this.#visibleRows + SPARE_ROWS;
    while (this.#rows.length < wanted) {
      const row = this.#buildRow();
      this.#rows.push(row);
      this.#viewport.appendChild(row.element);
    }
    return wanted;
  }

  #paint(wanted) {
    const total = this.#documentLength;
    const totalRows = this.#totalRows();
    const selection = this.selection;
    const caretRow = Math.floor(this.#caretOffset / this.#bytesPerRow);
    const caretColumn = this.#caretOffset % this.#bytesPerRow;

    for (let index = 0; index < this.#rulerColumns.length; index += 1) {
      const base = this.#isGroupEnd(index) ? 'hb-ruler-col is-group-end' : 'hb-ruler-col';
      setClass(this.#rulerColumns[index], index === caretColumn ? `${base} is-current` : base);
    }

    const selectionFlags = new Uint8Array(this.#bytesPerRow);
    const modifiedFlags = new Uint8Array(this.#bytesPerRow);
    const bookmarks = this.#layers.get('is-bookmarked') ?? null;

    for (let slot = 0; slot < this.#rows.length; slot += 1) {
      const row = this.#rows[slot];
      const rowIndex = this.#anchorRow + slot;
      const rowStart = rowIndex * this.#bytesPerRow;
      const useless = slot >= wanted || (rowIndex >= totalRows && total > 0);
      if (row.element.hidden !== useless) {
        row.element.hidden = useless;
      }
      if (useless) {
        this.#retireRow(row);
        continue;
      }
      row.element.dataset.start = String(rowStart);
      row.start = rowStart;
      setAttribute(row.element, 'aria-rowindex', String(rowIndex + 1));

      setText(row.offset, offsetLabel(rowStart));
      const marked = bookmarks !== null && !bookmarks.empty && this.#rowHasBookmark(bookmarks, rowStart);
      setClass(row.offset, marked ? 'hb-offset is-marked' : 'hb-offset');
      setClass(row.element, rowIndex === caretRow ? 'hb-row is-current' : 'hb-row');

      this.#selectionSet.fill(rowStart, selectionFlags);
      this.#modified.fill(rowStart, modifiedFlags);
      for (const [className, set] of this.#layers) {
        set.fill(rowStart, this.#layerFlags.get(className));
      }

      for (let column = 0; column < this.#bytesPerRow; column += 1) {
        const offset = rowStart + column;
        const beyond = offset >= total;
        const value = beyond ? -1 : this.#cache.byteAt(offset);
        const shared = this.#cellState(column, offset, value, beyond, selection, selectionFlags, modifiedFlags);
        const hexCell = row.hexCells[column];
        const asciiCell = row.asciiCells[column];

        setText(hexCell, value >= 0 ? toHex(Uint8Array.of(value)) : beyond ? '' : UNKNOWN_HEX);
        setText(asciiCell, value >= 0 ? asciiGlyph(value) : beyond ? '' : DOT);
        setClass(hexCell, this.#hexClass(column, offset, value, beyond, shared));
        setClass(asciiCell, this.#asciiClass(offset, value, beyond, shared));
        setAttribute(hexCell, 'id', this.#cellId(PANE_HEX, offset));
        setAttribute(asciiCell, 'id', this.#cellId(PANE_ASCII, offset));
      }
    }
    this.#syncActiveDescendant();
  }

  /**
   * Take a row out of service, ids and all.
   *
   * A cell's id names the offset it is showing, so a hidden row that keeps the
   * ids it had last time is a second element claiming offsets a visible row now
   * owns - and `aria-activedescendant` would be free to resolve to the hidden
   * one.
   */
  #retireRow(row) {
    if (row.start === -1) {
      return;
    }
    row.start = -1;
    for (let column = 0; column < row.hexCells.length; column += 1) {
      row.hexCells[column].removeAttribute('id');
      row.asciiCells[column].removeAttribute('id');
    }
  }

  #rowHasBookmark(bookmarks, rowStart) {
    for (let column = 0; column < this.#bytesPerRow; column += 1) {
      if (bookmarks.contains(rowStart + column)) {
        return true;
      }
    }
    return false;
  }

  #cellState(column, offset, value, beyond, selection, selectionFlags, modifiedFlags) {
    let classes = '';
    if (!beyond && value < 0) {
      classes += ' hb-dim';
    } else if (!beyond) {
      classes += ` ${byteClass(value)}`;
    }
    for (const [className, set] of this.#layers) {
      if (set.empty) {
        continue;
      }
      const flags = this.#layerFlags.get(className)[column];
      if ((flags & IN_RANGE) === 0) {
        continue;
      }
      classes += ` ${className}`;
      const markers = LAYER_MARKERS.get(className);
      if (markers) {
        if (markers.start && (flags & AT_START) !== 0) {
          classes += ` ${markers.start}`;
        }
        if (markers.end && (flags & AT_END) !== 0) {
          classes += ` ${markers.end}`;
        }
      }
    }
    if ((modifiedFlags[column] & IN_RANGE) !== 0) {
      classes += ' is-modified';
    }
    if (selection !== null && (selectionFlags[column] & IN_RANGE) !== 0) {
      classes += this.#focused ? ' is-selected' : ' is-selected-inactive';
    }
    return classes;
  }

  #hexClass(column, offset, value, beyond, shared) {
    let classes = 'hb-byte';
    if (this.#isGroupEnd(column)) {
      classes += ' is-group-end';
    }
    classes += shared;
    const showCaret = offset === this.#caretOffset && (!beyond || offset === this.#documentLength);
    if (showCaret) {
      if (this.#caretPane !== PANE_HEX) {
        classes += ' is-caret-inactive';
      } else if (!this.#focused) {
        classes += ' is-caret-inactive';
      } else {
        classes += this.#caretNibble === NIBBLE_HIGH ? ' is-nibble-left' : ' is-nibble-right';
      }
    }
    return classes;
  }

  #asciiClass(offset, value, beyond, shared) {
    let classes = `hb-ascii${shared}`;
    if (offset === this.#caretOffset && (!beyond || offset === this.#documentLength)) {
      if (this.#caretPane === PANE_ASCII) {
        classes += this.#focused ? ' is-caret' : ' is-caret-inactive';
      } else {
        classes += ' is-caret-inactive';
      }
    }
    return classes;
  }

  /* ----------------------------------------------------------------- data */

  #ensureData() {
    if (!this.#document || this.#documentLength === 0) {
      this.#setBusy(false);
      return;
    }
    const quantum = OVERSCAN_ROWS * this.#bytesPerRow;
    const spec = (this.#anchorRow - OVERSCAN_ROWS) * this.#bytesPerRow;
    const quantized = Math.max(0, Math.floor(spec / quantum) * quantum);
    const length = (this.#visibleRows + WINDOW_PAD_ROWS) * this.#bytesPerRow;
    const key = `${this.#document.handle}:${this.#document.generation}:${quantized}`;

    if (this.#cache.has(quantized) || key === this.#fetchKey) {
      if (this.#cache.has(quantized)) {
        this.#setBusy(false);
      }
      return;
    }
    this.#fetchController?.abort();
    const controller = new AbortController();
    this.#fetchController = controller;
    this.#fetchKey = key;
    const generation = this.#document.generation;
    const handle = this.#document.handle;

    readWindow(handle, quantized, length, { signal: controller.signal })
      .then((window_) => {
        this.#fetchKey = '';
        if (!this.#document || this.#document.handle !== handle || this.#document.generation !== generation) {
          return;
        }
        this.#cache.reset(`${handle}:${generation}`);
        this.#cache.store(window_.offset, window_.bytes);
        this.#setBusy(false);
        this.#schedule();
      })
      .catch((error) => {
        this.#fetchKey = '';
        if (isAborted(error)) {
          return;
        }
        if (isBusy(error)) {
          this.#setBusy(true);
          this.#retryLater();
          return;
        }
        this.#onError(error);
      });
  }

  #retryLater() {
    if (this.#busyTimer !== 0) {
      return;
    }
    this.#busyTimer = window.setTimeout(() => {
      this.#busyTimer = 0;
      this.#schedule();
    }, BUSY_RETRY_MS);
  }

  #setBusy(busy) {
    if (this.#busy.hidden !== !busy) {
      this.#busy.hidden = !busy;
    }
  }

  /** What the scroller currently is: scale, the top row, the row width, and how coarse a pixel has become. */
  get metrics() {
    return {
      scale: this.#scale,
      scaled: this.#scale > 1,
      bytesPerPixel: (this.#scale * this.#bytesPerRow) / this.#rowHeightOrFallback(),
      bytesPerRow: this.#bytesPerRow,
      bytesPerRowSetting: this.#bytesPerRowSetting,
      topRow: this.#anchorRow,
      visibleRows: this.#visibleRows,
      fullRows: this.#fullRows,
      totalRows: this.#totalRows(),
      rowHeight: this.#rowHeight,
      maxScrollerPx: this.#scrollerCap,
    };
  }

  #emitMetrics() {
    this.#onMetrics(this.metrics);
  }
}
