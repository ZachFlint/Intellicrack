/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Zachary Flint
   This file is part of Intellicrack. See LICENSE for details.

   How each operation's return value is shown.

   The default is renderGeneric, and it is the default on purpose: a method added
   to the Rust crate renders as a readable JSON tree with a hex-and-ASCII view of
   any bytes the moment the catalogue sees it, with nothing here to change. The
   bespoke renderers below exist where the generic view would be actively
   misleading rather than merely plain - a search result whose matched bytes the
   engine threw away, a patch list that may hold overlapping entries, a binary
   export that JSON would corrupt. */

import { callOpRaw, isTaggedBytes, readWindow, taggedBytes, toHex } from './api.js';
import { DIFF_TOKENS, byteTypeChart, classificationChart, diffMinimapChart, digramChart, entropyMapChart, histogramChart } from './charts.js';
import { asciiFor, element, hexOf, humanSize } from './forms.js';
import { compactScalar } from './scalar.js';
import { describeProtection, describeState, isSnapshotable, protectionTone, stateTone } from './win32.js';


const DUMP_COLUMNS = 16;
const OFFSET_DIGITS = 8;
const PREVIEW_BYTES = 24;
const MAX_DUMP_ROWS = 256;
const MAX_TREE_NODES = 4000;
const STRING_PREVIEW = 240;
const TITLE_PREVIEW = 2000;
const VIRTUAL_ROW_PX = 24;
const VIRTUAL_OVERSCAN = 12;
const JSON_CHILD_LIMIT = 400;
const HALF = 2;
const BYTE_MASK = 0xff;
const CLASSIFICATION_BLOCK = 4096;
const ENTROPY_BLOCK = 4096;
const SNAPSHOT_CAP = 16777216;
const MAX_INLINE_BYTES = 4096;

const SOURCE_DATA = 'source_data';

const EXPORT_EXTENSIONS = new Map([
  ['export_patches_ips', 'ips'],
  ['export_patches_ips32', 'ips32'],
  ['export_patches_bps', 'bps'],
  ['export_patches_bps_from_path', 'bps'],
  ['export_patches_ups', 'ups'],
  ['export_patches_ups_from_path', 'ups'],
  ['export_patches_cod', 'cod'],
]);

const SEARCH_OPERATIONS = [
  'search_bytes',
  'search_hex',
  'search_numeric',
  'search_numeric_float',
  'search_numeric_range',
  'search_regex',
  'search_text',
  'search_text_encoded',
];

const DIFF_TONES = new Map([
  ['match', ''],
  ['modified', 'is-warning'],
  ['inserted_a', 'is-error'],
  ['inserted_b', 'is-success'],
]);

/* ------------------------------------------------------------- primitives */

function offsetText(value) {
  return `0x${hexOf(value, OFFSET_DIGITS)}`;
}

function banner(kind, title, detail) {
  const node = element('div', `hb-banner is-${kind}`);
  const glyph = { error: '!', warning: '△', success: '✓', info: 'i' }[kind] ?? 'i';
  node.appendChild(element('span', 'hb-banner-glyph', glyph));
  const body = element('div', 'hb-banner-body');
  body.appendChild(element('div', 'hb-banner-title', title));
  if (detail) {
    body.appendChild(element('div', 'hb-banner-detail', detail));
  }
  node.appendChild(body);
  return node;
}

/**
 * A framed message for an operation that failed.
 *
 * @param {Error} error The failure, ideally a DispatchError carrying a kind.
 * @returns {HTMLElement} The rendered banner.
 */
export function renderError(error) {
  const kind = error && typeof error.kind === 'string' ? error.kind : 'internal';
  const node = element('div', `hb-error-banner err-${kind}`);
  node.appendChild(element('span', 'hb-error-kind', kind));
  node.appendChild(element('div', 'hb-error-message', String(error && error.message ? error.message : error)));
  return node;
}

/**
 * An empty-state block with a title and an explanation.
 *
 * @param {string} title Headline.
 * @param {string} hint Sentence explaining what would fill the space.
 * @param {string} [glyph] Single character shown in the frame.
 * @returns {HTMLElement} The rendered block.
 */
export function emptyState(title, hint, glyph = '□') {
  const node = element('div', 'hb-empty');
  node.appendChild(element('div', 'hb-empty-icon', glyph));
  node.appendChild(element('div', 'hb-empty-title', title));
  node.appendChild(element('div', 'hb-empty-hint', hint));
  return node;
}

function table(headings) {
  const node = element('table', 'hb-table');
  const head = document.createElement('thead');
  const row = document.createElement('tr');
  for (const heading of headings) {
    const cell = element('th', heading.className, heading.label);
    row.appendChild(cell);
    heading.node = cell;
  }
  head.appendChild(row);
  const body = document.createElement('tbody');
  node.append(head, body);
  return { node, body };
}

function cell(text, className) {
  return element('td', className, text);
}

function actionButton(label, title, onClick, variant = 'hb-btn is-sm') {
  const node = element('button', variant, label);
  node.type = 'button';
  if (title) {
    node.title = title;
  }
  node.addEventListener('click', onClick);
  return node;
}

/**
 * Render bytes as an offset, hexadecimal and ASCII dump.
 *
 * @param {Uint8Array} bytes The bytes to show.
 * @param {number} [baseOffset] Offset the first byte sits at in the document.
 * @param {number} [rowLimit] Maximum rows before the dump is cut short.
 * @returns {HTMLElement} The rendered dump.
 */
export function hexDump(bytes, baseOffset = 0, rowLimit = MAX_DUMP_ROWS) {
  const node = element('div', 'hb-payload');
  const rows = Math.ceil(bytes.length / DUMP_COLUMNS);
  const shown = Math.min(rows, rowLimit);
  for (let row = 0; row < shown; row += 1) {
    const start = row * DUMP_COLUMNS;
    const slice = bytes.subarray(start, start + DUMP_COLUMNS);
    const line = element('div', 'hb-payload-row');
    line.appendChild(element('span', 'hb-payload-off', hexOf(baseOffset + start, OFFSET_DIGITS)));
    const hexText = [...slice].map((value) => hexOf(value, HALF)).join(' ').padEnd(DUMP_COLUMNS * 3 - 1, ' ');
    line.appendChild(element('span', 'hb-payload-hex', hexText));
    line.appendChild(element('span', 'hb-payload-ascii', [...slice].map(asciiFor).join('')));
    node.appendChild(line);
  }
  if (rows > shown) {
    const line = element('div', 'hb-payload-row');
    line.appendChild(element('span', 'hb-payload-off', '…'));
    line.appendChild(element('span', 'hb-payload-hex', `${bytes.length - shown * DUMP_COLUMNS} further bytes not shown`));
    node.appendChild(line);
  }
  return node;
}

function download(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function documentStem(ctx) {
  const label = ctx.document?.label ?? 'document';
  return label.replace(/[^A-Za-z0-9._-]+/g, '_');
}

/* --------------------------------------------------------------- generic */

function jsonTree(value, key, depth, into) {
  const container = into ?? element('div', 'hb-json');
  const row = element('div', 'hb-json-row');
  row.style.setProperty('--hb-json-depth', String(depth));

  const bytes = isTaggedBytes(value);
  const branch = !bytes && value !== null && typeof value === 'object';
  const toggle = element('span', branch ? 'hb-json-toggle' : 'hb-json-toggle is-leaf');
  row.appendChild(toggle);
  if (key !== null) {
    row.append(element('span', 'hb-json-key', key), element('span', 'hb-json-punct', ':'));
  }

  if (bytes) {
    const preview = value.__bytes__.slice(0, 64).toUpperCase();
    row.appendChild(element('span', 'hb-json-bytes', preview + (value.__bytes__.length > 64 ? '…' : '')));
    row.appendChild(element('span', 'hb-json-count', `${value.length} bytes${value.truncated ? ', truncated' : ''}`));
    container.appendChild(row);
    return container;
  }
  if (value === null || value === undefined) {
    row.appendChild(element('span', 'hb-json-null', 'null'));
    container.appendChild(row);
    return container;
  }
  if (typeof value === 'string') {
    row.appendChild(element('span', 'hb-json-str', JSON.stringify(value)));
    container.appendChild(row);
    return container;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    row.appendChild(element('span', typeof value === 'number' ? 'hb-json-num' : 'hb-json-bool', String(value)));
    container.appendChild(row);
    return container;
  }

  const entries = Array.isArray(value) ? value.map((item, index) => [String(index), item]) : Object.entries(value);
  row.append(
    element('span', 'hb-json-punct', Array.isArray(value) ? '[' : '{'),
    element('span', 'hb-json-count', `${entries.length} ${entries.length === 1 ? 'entry' : 'entries'}`),
  );
  container.appendChild(row);

  const children = element('div');
  for (const [childKey, childValue] of entries.slice(0, JSON_CHILD_LIMIT)) {
    jsonTree(childValue, childKey, depth + 1, children);
  }
  if (entries.length > JSON_CHILD_LIMIT) {
    const more = element('div', 'hb-json-row');
    more.style.setProperty('--hb-json-depth', String(depth + 1));
    more.append(element('span', 'hb-json-toggle is-leaf'), element('span', 'hb-json-count', `${entries.length - JSON_CHILD_LIMIT} more not shown`));
    children.appendChild(more);
  }
  container.appendChild(children);
  toggle.addEventListener('click', () => {
    children.hidden = toggle.classList.toggle('is-collapsed');
  });
  return container;
}

function rawDownloadRow(name, result, ctx) {
  if (!result.raw_available) {
    return null;
  }
  const row = element('div', 'hb-row-flex');
  row.appendChild(element('span', 'hb-dim', `${humanSize(result.raw_length)} of binary available undecorated`));
  row.appendChild(actionButton('download', 'Fetch the untruncated bytes through the raw sidecar', () => {
    ctx.raw(name, ctx.args ?? {}, ctx.handle)
      .then((buffer) => download(new Blob([buffer], { type: 'application/octet-stream' }), `${documentStem(ctx)}.${EXPORT_EXTENSIONS.get(name) ?? 'bin'}`))
      .catch((error) => ctx.toast('error', 'Download failed', error.message));
  }));
  return row;
}

/**
 * The default view: a JSON tree, bytes as hex with an ASCII gutter, and an
 * explicit warning when the payload was cut short in transport.
 *
 * @param {string} name Operation name.
 * @param {object} result The invocation result.
 * @param {object} ctx Callbacks and the current document.
 * @returns {HTMLElement} The rendered view.
 */
export function renderGeneric(name, result, ctx) {
  const root = element('div', 'hb-stack');
  const value = result.value;

  if (isTaggedBytes(value)) {
    if (value.truncated) {
      root.appendChild(banner(
        'truncated',
        `${value.length} bytes returned, ${value.__bytes__.length / HALF} carried inline`,
        `The JSON encoding caps a byte payload at ${MAX_INLINE_BYTES} bytes. Download the raw form for the whole thing.`,
      ));
    }
    const bytes = taggedBytes(value);
    root.appendChild(hexDump(bytes, 0));
  } else if (value === null) {
    root.appendChild(banner('success', `${name} returned nothing`, 'The operation completed; it has no return value.'));
  } else if (typeof value === 'object') {
    root.appendChild(jsonTree(value, null, 0, null));
  } else {
    const card = element('div', 'hb-payload');
    const line = element('div', 'hb-payload-row');
    line.appendChild(element('span', 'hb-payload-hex', String(value)));
    card.appendChild(line);
    root.appendChild(card);
  }

  const raw = rawDownloadRow(name, result, ctx);
  if (raw !== null) {
    root.appendChild(raw);
  }
  return root;
}

/* ---------------------------------------------------------------- search */

function renderSearch(name, result, ctx) {
  const hits = Array.isArray(result.value) ? result.value : [];
  const root = element('div', 'hb-stack');

  if (hits.length === 0) {
    root.appendChild(emptyState('No matches', `${name} found nothing in this document.`, '⌕'));
    return root;
  }

  ctx.setHits(hits);

  const header = element('div', 'hb-row-flex');
  header.appendChild(element('span', 'hb-badge is-accent', `${hits.length} match${hits.length === 1 ? '' : 'es'}`));
  header.appendChild(element('span', 'hb-dim', 'the engine discards the matched bytes, so each row re-reads them from the document'));
  header.appendChild(element('span', 'hb-grow'));

  let cursor = 0;
  const rows = [];
  const focus = (index) => {
    if (rows.length === 0) {
      return;
    }
    cursor = (index + rows.length) % rows.length;
    for (const entry of rows) {
      entry.classList.remove('is-selected');
    }
    rows[cursor].classList.add('is-selected');
    rows[cursor].scrollIntoView({ block: 'nearest' });
    const [offset, length] = hits[cursor];
    ctx.select(offset, length);
  };
  header.appendChild(actionButton('previous', 'Select the previous match', () => focus(cursor - 1)));
  header.appendChild(actionButton('next', 'Select the next match', () => focus(cursor + 1)));
  header.appendChild(actionButton('clear', 'Remove the highlight layer', () => {
    ctx.setHits([]);
    ctx.toast('info', 'Cleared', 'The match highlight layer was removed.');
  }));
  root.appendChild(header);

  const built = table([
    { label: '#', className: 'is-numeric' },
    { label: 'offset', className: 'is-mono' },
    { label: 'length', className: 'is-numeric' },
    { label: 'bytes', className: 'is-mono is-wide' },
    { label: 'text', className: 'is-mono' },
  ]);

  const lazy = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) {
        continue;
      }
      lazy.unobserve(entry.target);
      const row = entry.target;
      const offset = Number(row.dataset.offset);
      const length = Number(row.dataset.length);
      readWindow(ctx.handle, offset, Math.min(length, PREVIEW_BYTES))
        .then((window) => {
          const bytes = window.bytes;
          row.querySelector('[data-role="bytes"]').textContent = [...bytes].map((value) => hexOf(value, HALF)).join(' ') + (length > bytes.length ? ' …' : '');
          row.querySelector('[data-role="text"]').textContent = [...bytes].map(asciiFor).join('');
        })
        .catch((error) => {
          row.querySelector('[data-role="bytes"]').textContent = error.message;
        });
    }
  }, { root: null, rootMargin: '120px' });

  hits.forEach(([offset, length], index) => {
    const row = document.createElement('tr');
    row.dataset.offset = String(offset);
    row.dataset.length = String(length);
    row.append(
      cell(String(index + 1), 'is-numeric'),
      cell(offsetText(offset), 'is-mono is-primary'),
      cell(String(length), 'is-numeric'),
    );
    const bytesCell = cell('…', 'is-mono is-wide');
    bytesCell.dataset.role = 'bytes';
    const textCell = cell('', 'is-mono');
    textCell.dataset.role = 'text';
    row.append(bytesCell, textCell);
    row.addEventListener('click', () => focus(index));
    built.body.appendChild(row);
    rows.push(row);
    lazy.observe(row);
  });

  root.appendChild(built.node);
  focus(0);
  return root;
}

function renderReplace(name, result, ctx) {
  const count = Number(result.value ?? 0);
  const root = element('div', 'hb-stack');
  root.appendChild(banner(
    count > 0 ? 'success' : 'info',
    `${count} occurrence${count === 1 ? '' : 's'} replaced`,
    count > 0
      ? 'A replacement of a different length resizes the document, so every offset after the first hit has moved.'
      : 'Nothing in the document matched the pattern.',
  ));
  if (count > 0) {
    const row = element('div', 'hb-row-flex');
    row.appendChild(actionButton('reload the view', 'Drop cached windows and re-read the document', () => ctx.refresh()));
    root.appendChild(row);
  }
  return root;
}

/* -------------------------------------------------------------- templates */

function templateNode(field, depth, ctx, budget) {
  const fragment = document.createDocumentFragment();
  if (budget.count >= MAX_TREE_NODES) {
    return fragment;
  }
  budget.count += 1;

  const node = element('div', 'hb-tree-node');
  node.style.setProperty('--hb-tree-depth', String(depth));
  node.appendChild(element('span', 'hb-tree-indent'));

  const children = Array.isArray(field.children) ? field.children : [];
  const twisty = element('span', children.length > 0 ? 'hb-tree-twisty is-open' : 'hb-tree-twisty is-leaf');
  node.appendChild(twisty);

  const mark = element('span', 'hb-tree-mark');
  if (typeof field.color === 'string' && field.color !== '') {
    mark.style.background = field.color;
    mark.title = field.color;
  }
  node.appendChild(mark);

  node.appendChild(element('span', 'hb-tree-label', field.name ?? '(unnamed)'));
  node.appendChild(element('span', 'hb-tree-type', `${field.size} B`));
  node.appendChild(element('span', 'hb-tree-value', String(field.display_value ?? '')));

  if (field.validation_passed === true) {
    node.appendChild(element('span', 'hb-badge is-success', 'pass'));
  } else if (field.validation_passed === false) {
    node.appendChild(element('span', 'hb-badge is-error', 'fail'));
  } else {
    node.appendChild(element('span', 'hb-badge', 'n/a'));
  }

  node.appendChild(element('span', 'hb-tree-offset', offsetText(field.offset ?? 0)));
  const bytes = taggedBytes(field.raw_bytes);
  if (bytes !== null && bytes.length > 0) {
    node.title = `${field.description ?? ''}\n${toHex(bytes)}`;
  } else if (field.description) {
    node.title = field.description;
  }

  node.addEventListener('click', () => {
    for (const selected of node.parentElement?.querySelectorAll('.hb-tree-node.is-selected') ?? []) {
      selected.classList.remove('is-selected');
    }
    node.classList.add('is-selected');
    ctx.select(field.offset ?? 0, Math.max(1, field.size ?? 1));
  });
  fragment.appendChild(node);

  if (children.length > 0) {
    const holder = element('div');
    for (const child of children) {
      holder.appendChild(templateNode(child, depth + 1, ctx, budget));
    }
    fragment.appendChild(holder);
    twisty.addEventListener('click', (event) => {
      event.stopPropagation();
      holder.hidden = !twisty.classList.toggle('is-open');
    });
  }
  return fragment;
}

function renderTemplate(name, result, ctx) {
  const fields = Array.isArray(result.value) ? result.value : [];
  const root = element('div', 'hb-stack');
  if (fields.length === 0) {
    root.appendChild(emptyState('The template matched no fields', 'Applying a template past the end of the document produces an empty field list.', '⊞'));
    return root;
  }

  const budget = { count: 0 };
  const tree = element('div', 'hb-tree');
  let span = 0;
  for (const field of fields) {
    tree.appendChild(templateNode(field, 0, ctx, budget));
    span = Math.max(span, (field.offset ?? 0) + (field.size ?? 0));
  }

  const header = element('div', 'hb-row-flex');
  header.appendChild(element('span', 'hb-badge is-accent', `${budget.count} field${budget.count === 1 ? '' : 's'}`));
  header.appendChild(element('span', 'hb-dim', `covering ${offsetText(fields[0].offset ?? 0)} to ${offsetText(span)}`));
  header.appendChild(element('span', 'hb-grow'));
  header.appendChild(actionButton('select the whole structure', 'Select every byte the template covers', () => {
    ctx.select(fields[0].offset ?? 0, Math.max(1, span - (fields[0].offset ?? 0)));
  }));
  root.append(header, tree);
  if (budget.count >= MAX_TREE_NODES) {
    root.appendChild(banner('warning', 'Tree cut short', `Only the first ${MAX_TREE_NODES} fields are drawn.`));
  }
  return root;
}

/* -------------------------------------------------------------- inspector */

function scalarCell(raw) {
  const { text, full } = compactScalar(raw);
  const cell = element('td', 'hb-kv-value', text);
  if (full !== null) {
    cell.title = full;
    cell.classList.add('is-compacted');
  }
  return cell;
}

function renderInspect(name, result, ctx) {
  const value = result.value;
  const keys = value === null || typeof value !== 'object' ? [] : Object.keys(value);
  if (keys.length === 0) {
    return emptyState(
      'Offset at or past the end of the document',
      'The inspector returns an empty mapping when no byte remains to interpret, so there is nothing to show rather than nothing that fits.',
      '⌷',
    );
  }
  const root = element('div', 'hb-stack');
  const header = element('div', 'hb-row-flex');
  header.appendChild(element('span', 'hb-badge is-accent', `${keys.length} interpretations`));
  header.appendChild(element('span', 'hb-dim', 'the key set narrows as fewer bytes remain'));
  root.appendChild(header);

  const node = element('table', 'hb-kv');
  const body = document.createElement('tbody');
  for (const key of keys.sort((left, right) => left.localeCompare(right))) {
    const row = document.createElement('tr');
    row.append(element('td', 'hb-kv-key', key), scalarCell(value[key]));
    body.appendChild(row);
  }
  node.appendChild(body);
  root.appendChild(node);
  return root;
}

/* ---------------------------------------------------------------- strings */

/**
 * Put a scrolling window of rows into a table body and keep it there.
 *
 * Only the rows the viewport can show are built; the rest of the scroll height
 * comes from a padding row above and below. Result sets here are engine-sized
 * rather than page-sized - a diff of two unrelated files reports thousands of
 * regions - so building every row would cost more than the panel is worth.
 *
 * @param {HTMLElement} scroller The scrolling container holding the table.
 * @param {HTMLElement} body The tbody rows are written into.
 * @param {() => object[]} source Reads the currently visible row objects.
 * @param {(entry: object, index: number) => HTMLElement} buildRow Builds one tr.
 * @returns {() => void} Repaints the window; call it after changing the source.
 */
function virtualize(scroller, body, source, buildRow) {
  const paint = () => {
    const rows = source();
    const first = Math.max(0, Math.floor(scroller.scrollTop / VIRTUAL_ROW_PX) - VIRTUAL_OVERSCAN);
    const count = Math.ceil(scroller.clientHeight / VIRTUAL_ROW_PX) + VIRTUAL_OVERSCAN * HALF;
    body.replaceChildren();
    const head = document.createElement('tr');
    head.style.height = `${first * VIRTUAL_ROW_PX}px`;
    body.appendChild(head);
    rows.slice(first, first + count).forEach((entry, offset) => {
      body.appendChild(buildRow(entry, first + offset));
    });
    const tail = document.createElement('tr');
    tail.style.height = `${Math.max(0, (rows.length - first - count) * VIRTUAL_ROW_PX)}px`;
    body.appendChild(tail);
  };
  scroller.addEventListener('scroll', paint);
  requestAnimationFrame(paint);
  return paint;
}

/**
 * Truncate text on a code-point boundary rather than a UTF-16 code-unit one.
 *
 * `String.prototype.slice` counts code units, so a limit that lands between the
 * two halves of a surrogate pair leaves an unpaired surrogate at the end - a
 * supplementary-plane character (an emoji, a rare CJK-extension glyph) renders
 * as a replacement glyph instead of being dropped whole.
 *
 * @param {string} text Source text.
 * @param {number} limit Maximum number of code points to keep.
 * @returns {string} `text` unchanged if it already fits, otherwise the first
 * `limit` code points.
 */
export function sliceCodePoints(text, limit) {
  if (text.length <= limit) {
    return text;
  }
  const points = Array.from(text);
  return points.length <= limit ? text : points.slice(0, limit).join('');
}

function scrollHost(maxHeight) {
  const scroller = element('div', 'hb-scroll');
  scroller.style.maxHeight = maxHeight;
  scroller.style.overflow = 'auto';
  return scroller;
}

function renderStrings(name, result, ctx) {
  const strings = Array.isArray(result.value) ? result.value : [];
  const root = element('div', 'hb-stack');
  if (strings.length === 0) {
    root.appendChild(emptyState('No strings extracted', 'Nothing in the document met the minimum length in the encodings that were enabled.', '≡'));
    return root;
  }

  const header = element('div', 'hb-row-flex');
  header.appendChild(element('span', 'hb-badge is-accent', `${strings.length} strings`));
  const filter = document.createElement('input');
  filter.type = 'text';
  filter.className = 'hb-input';
  filter.placeholder = 'filter by content or encoding';
  filter.spellcheck = false;
  header.append(filter);
  root.appendChild(header);

  const built = table([
    { label: 'offset', className: 'is-mono' },
    { label: 'length', className: 'is-numeric' },
    { label: 'encoding', className: '' },
    { label: 'content', className: 'is-mono is-wide' },
  ]);

  const scroller = scrollHost('340px');
  let visible = strings;

  const paint = virtualize(scroller, built.body, () => visible, (entry) => {
    const row = document.createElement('tr');
    const content = String(entry.content ?? '');
    row.append(
      cell(offsetText(entry.offset ?? 0), 'is-mono is-primary'),
      cell(String(entry.length ?? content.length), 'is-numeric'),
      cell(String(entry.encoding ?? ''), ''),
      cell(content.length > STRING_PREVIEW ? `${sliceCodePoints(content, STRING_PREVIEW)}…` : content, 'is-mono is-wide'),
    );
    row.title = sliceCodePoints(content, TITLE_PREVIEW);
    row.addEventListener('click', () => ctx.select(entry.offset ?? 0, Math.max(1, entry.length ?? 1)));
    return row;
  });

  filter.addEventListener('input', () => {
    const needle = filter.value.trim().toLowerCase();
    visible = needle === ''
      ? strings
      : strings.filter((entry) => String(entry.content ?? '').toLowerCase().includes(needle) || String(entry.encoding ?? '').toLowerCase().includes(needle));
    scroller.scrollTop = 0;
    paint();
  });

  scroller.appendChild(built.node);
  root.appendChild(scroller);
  return root;
}

/* ---------------------------------------------------------------- patches */

/**
 * Overlay raw `get_patches` entries in order and coalesce contiguous runs.
 *
 * An entry whose inline payload was capped by the transport layer (`codec.py`'s
 * `_MAX_INLINE_BYTES`) only contributes its first `_MAX_INLINE_BYTES` bytes here
 * - the caller is told this happened via `truncated` so it can warn rather than
 * silently under-report the patched range.
 *
 * @param {Array<[number, object]>} entries Raw `[offset, taggedBytes]` records.
 * @returns {{merged: Array<{offset: number, values: number[]}>, truncated: boolean}} The
 * coalesced runs and whether any contributing entry was cut short in transport.
 */
export function mergePatches(entries) {
  const bytes = new Map();
  let truncated = false;
  for (const [offset, tagged] of entries) {
    const data = taggedBytes(tagged);
    if (data === null) {
      continue;
    }
    if (tagged?.truncated) {
      truncated = true;
    }
    for (let index = 0; index < data.length; index += 1) {
      bytes.set(offset + index, data[index]);
    }
  }
  const offsets = [...bytes.keys()].sort((left, right) => left - right);
  const merged = [];
  let run = null;
  for (const offset of offsets) {
    if (run !== null && offset === run.offset + run.values.length) {
      run.values.push(bytes.get(offset));
      continue;
    }
    run = { offset, values: [bytes.get(offset)] };
    merged.push(run);
  }
  return { merged, truncated };
}

function renderPatches(name, result, ctx) {
  const entries = Array.isArray(result.value) ? result.value : [];
  const root = element('div', 'hb-stack');
  if (entries.length === 0) {
    root.appendChild(emptyState('No patches recorded', 'Every byte in this document still matches what was loaded.', '◫'));
    return root;
  }

  const { merged, truncated } = mergePatches(entries);
  root.appendChild(banner(
    'warning',
    `${entries.length} raw entr${entries.length === 1 ? 'y' : 'ies'}, ${merged.length} after merging`,
    'get_patches is unmerged — it may contain overlapping or duplicate entries, one per write, in the order they were made.',
  ));
  if (truncated) {
    root.appendChild(banner(
      'truncated',
      'The merged view understates one or more entries',
      `A patch entry larger than ${MAX_INLINE_BYTES} bytes is capped at ${MAX_INLINE_BYTES} bytes in transport, so the merged view only reflects that entry's first ${MAX_INLINE_BYTES} bytes. Switch to raw entries or export the patches to see the full range.`,
    ));
  }

  const controls = element('div', 'hb-row-flex');
  const built = table([
    { label: '#', className: 'is-numeric' },
    { label: 'offset', className: 'is-mono' },
    { label: 'length', className: 'is-numeric' },
    { label: 'bytes', className: 'is-mono is-wide' },
  ]);

  let showMerged = false;
  const paint = () => {
    built.body.replaceChildren();
    const rows = showMerged
      ? merged.map((run, index) => [index, run.offset, run.values.length, run.values])
      : entries.map(([offset, tagged], index) => [index, offset, tagged?.length ?? 0, [...(taggedBytes(tagged) ?? [])]]);
    for (const [index, offset, length, values] of rows) {
      const row = document.createElement('tr');
      const preview = values.slice(0, PREVIEW_BYTES).map((value) => hexOf(value & BYTE_MASK, HALF)).join(' ');
      row.append(
        cell(String(index + 1), 'is-numeric'),
        cell(offsetText(offset), 'is-mono is-primary'),
        cell(String(length), 'is-numeric'),
        cell(values.length > PREVIEW_BYTES ? `${preview} …` : preview, 'is-mono is-wide'),
      );
      row.addEventListener('click', () => ctx.select(offset, Math.max(1, length)));
      built.body.appendChild(row);
    }
  };

  const toggle = actionButton('show merged view', 'Overlay the entries in order and coalesce the runs', () => {
    showMerged = !showMerged;
    toggle.textContent = showMerged ? 'show raw entries' : 'show merged view';
    toggle.classList.toggle('is-primary', showMerged);
    paint();
  });
  controls.append(toggle, element('span', 'hb-dim', 'the merged view is computed here; the engine reports the raw list'));
  root.append(controls, built.node);
  paint();
  return root;
}

function renderExportBinary(name, result, ctx) {
  const root = element('div', 'hb-stack');
  const extension = EXPORT_EXTENSIONS.get(name) ?? 'bin';
  root.appendChild(banner(
    'info',
    `${result.raw_length} byte ${extension.toUpperCase()} patch`,
    `The JSON route caps a byte payload at ${MAX_INLINE_BYTES} bytes; a patch fetched that way would be silently corrupt. This download uses the raw sidecar.`,
  ));
  const row = element('div', 'hb-row-flex');
  const save = actionButton(`download .${extension}`, 'Fetch the untruncated bytes and save them', () => {
    ctx.raw(name, ctx.args ?? {}, ctx.handle)
      .then((buffer) => {
        download(new Blob([buffer], { type: 'application/octet-stream' }), `${documentStem(ctx)}.${extension}`);
        ctx.toast('success', 'Saved', `${buffer.byteLength} bytes written as .${extension}`);
      })
      .catch((error) => ctx.toast('error', 'Download failed', error.message));
  }, 'hb-btn is-sm is-primary');
  row.appendChild(save);
  root.append(row);
  if (SOURCE_DATA in (ctx.args ?? {})) {
    const source = String(ctx.args[SOURCE_DATA] ?? '');
    root.appendChild(banner(
      source === '' ? 'warning' : 'info',
      source === ''
        ? 'The source was empty, so this patch rebuilds the document from nothing'
        : `The source was ${source.length / HALF} bytes`,
      `${extension.toUpperCase()} records the difference from a source image. Point ${SOURCE_DATA} at the original file to get a patch that carries only the edits.`,
    ));
  }
  const bytes = taggedBytes(result.value);
  if (bytes !== null) {
    root.appendChild(hexDump(bytes, 0, 12));
  }
  return root;
}

function renderExportJson(name, result, ctx) {
  const text = String(result.value ?? '');
  const root = element('div', 'hb-stack');
  const area = document.createElement('textarea');
  area.className = 'hb-textarea is-mono';
  area.readOnly = true;
  area.value = text;
  area.rows = Math.min(18, Math.max(4, text.split('\n').length));
  const templateName = typeof ctx.args?.name === 'string' ? ctx.args.name : null;
  const filename = templateName === null
    ? `${documentStem(ctx)}.patches.json`
    : `${templateName}.template.json`;
  const row = element('div', 'hb-row-flex');
  row.appendChild(actionButton('download .json', `Save as ${filename}`, () => {
    download(new Blob([text], { type: 'application/json' }), filename);
  }));
  row.appendChild(actionButton('copy', 'Copy the JSON to the clipboard', () => {
    navigator.clipboard.writeText(text).then(
      () => ctx.toast('success', 'Copied', `${text.length} characters`),
      (error) => ctx.toast('error', 'Copy failed', error.message),
    );
  }));
  root.append(area, row);
  return root;
}

function renderImport(name, result, ctx) {
  const count = Number(result.value ?? 0);
  const root = element('div', 'hb-stack');
  root.appendChild(banner(
    'warning',
    `${count} patch record${count === 1 ? '' : 's'} applied — the document was replaced`,
    'Importing replaces the whole document and resets the undo stack, and file_path() is now null, so saving needs an explicit path.',
  ));
  const row = element('div', 'hb-row-flex');
  row.appendChild(actionButton('refresh everything', 'Drop every cached window and re-read the document', () => {
    ctx.refresh();
  }, 'hb-btn is-sm is-primary'));
  row.appendChild(actionButton('save as…', 'Choose the path the replaced document should be written to', () => ctx.openOperation('save_as')));
  root.appendChild(row);
  ctx.refresh();
  return root;
}

/* -------------------------------------------------------- process memory */

function renderRegions(name, result, ctx) {
  const regions = Array.isArray(result.value) ? result.value : [];
  const root = element('div', 'hb-stack');
  if (regions.length === 0) {
    root.appendChild(emptyState('No regions reported', 'The process exposed no memory regions, or the query was refused.', '▤'));
    return root;
  }

  let committed = 0;
  for (const [, , , state] of regions) {
    if (describeState(state).committed) {
      committed += 1;
    }
  }
  const header = element('div', 'hb-row-flex');
  header.append(
    element('span', 'hb-badge is-accent', `${regions.length} regions`),
    element('span', 'hb-badge is-success', `${committed} committed`),
    element('span', 'hb-dim', 'protection and state arrive as raw Win32 constants and are decoded here'),
  );
  root.appendChild(header);

  const built = table([
    { label: 'base', className: 'is-mono' },
    { label: 'size', className: 'is-numeric' },
    { label: 'protection', className: '' },
    { label: 'state', className: '' },
    { label: '', className: '' },
  ]);

  for (const [base, size, protection, state] of regions) {
    const decoded = describeProtection(protection);
    const row = document.createElement('tr');
    row.append(cell(offsetText(base), 'is-mono is-primary'), cell(humanSize(size), 'is-numeric'));

    const protectionCell = document.createElement('td');
    const badge = element('span', `hb-badge is-mono ${protectionTone(protection)}`.trim(), decoded.access);
    badge.title = `0x${hexOf(protection)} — ${decoded.text}`;
    protectionCell.appendChild(badge);
    for (const modifier of decoded.modifiers) {
      protectionCell.appendChild(element('span', 'hb-badge is-mono', modifier.replace('PAGE_', '')));
    }
    row.appendChild(protectionCell);

    const stateCell = document.createElement('td');
    const stateBadge = element('span', `hb-badge is-mono ${stateTone(state)}`.trim(), describeState(state).name);
    stateBadge.title = `0x${hexOf(state)}`;
    stateCell.appendChild(stateBadge);
    row.appendChild(stateCell);

    const actionCell = document.createElement('td');
    if (isSnapshotable(protection, state)) {
      actionCell.appendChild(actionButton('snapshot', `Copy ${humanSize(Math.min(size, SNAPSHOT_CAP))} into a new document`, () => {
        const span = Math.min(size, SNAPSHOT_CAP);
        const warning = span < size
          ? `This region is ${humanSize(size)}; only the first ${humanSize(span)} will be copied. Continue?`
          : `Copy ${humanSize(span)} from ${offsetText(base)} into a new document?`;
        if (!window.confirm(warning)) {
          return;
        }
        ctx.run('from_process_memory', { pid: ctx.args?.pid ?? 0, address: base, size: span }, null)
          .then(() => ctx.toast('success', 'Snapshot taken', `${humanSize(span)} from ${offsetText(base)} — a static copy, not a live view.`))
          .catch((error) => ctx.toast('error', 'Snapshot failed', error.message));
      }));
    } else {
      actionCell.appendChild(element('span', 'hb-dim', 'not readable'));
    }
    row.appendChild(actionCell);
    built.body.appendChild(row);
  }
  root.appendChild(built.node);
  return root;
}

/* ------------------------------------------------------------- pe checksum */

function renderChecksum(name, result, ctx) {
  const value = result.value ?? {};
  const root = element('div', 'hb-stack');
  const valid = value.valid === true;
  root.appendChild(banner(
    valid ? 'success' : 'error',
    valid ? 'The stored checksum matches' : 'The stored checksum is wrong',
    valid ? 'Nothing to repair.' : 'Writing the calculated value over the stored one makes the header consistent again.',
  ));

  const kv = element('table', 'hb-kv');
  const body = document.createElement('tbody');
  for (const [key, rendered] of [
    ['stored', `0x${hexOf(Number(value.stored ?? 0), OFFSET_DIGITS)} · ${value.stored}`],
    ['calculated', `0x${hexOf(Number(value.calculated ?? 0), OFFSET_DIGITS)} · ${value.calculated}`],
    ['offset', offsetText(Number(value.offset ?? 0))],
    ['valid', String(value.valid)],
  ]) {
    const row = document.createElement('tr');
    row.append(element('td', 'hb-kv-key', key), element('td', valid || key !== 'stored' ? 'hb-kv-value' : 'hb-kv-value is-accent', rendered));
    body.appendChild(row);
  }
  kv.appendChild(body);
  root.appendChild(kv);

  const row = element('div', 'hb-row-flex');
  row.appendChild(actionButton('go to the checksum field', 'Select the four bytes that hold it', () => ctx.select(Number(value.offset ?? 0), 4)));
  if (!valid) {
    row.appendChild(actionButton('repair', 'Write the calculated checksum into the header', () => {
      ctx.run('repair_pe_checksum', {}, ctx.handle)
        .then(() => ctx.toast('success', 'Repaired', 'The header now carries the calculated checksum.'))
        .catch((error) => ctx.toast('error', 'Repair failed', error.message));
    }, 'hb-btn is-sm is-primary'));
  }
  root.appendChild(row);
  return root;
}

/* -------------------------------------------------------------------- diff */

function diffTone(kind) {
  return DIFF_TONES.get(kind) ?? '';
}

function renderDiff(name, result, ctx) {
  const value = result.value ?? {};
  const regions = Array.isArray(value.regions) ? value.regions : [];
  const root = element('div', 'hb-stack');

  root.appendChild(banner(
    value.files_identical ? 'success' : 'warning',
    value.files_identical ? 'The two inputs are identical' : `${value.total_differences} difference${value.total_differences === 1 ? '' : 's'}`,
    `${regions.length} region${regions.length === 1 ? '' : 's'} in the alignment.`,
  ));

  const focus = (region) => {
    ctx.select(region.offset_a ?? 0, Math.max(1, region.length ?? 1));
    ctx.toast('info', String(region.diff_type), `a at ${offsetText(region.offset_a ?? 0)}, b at ${offsetText(region.offset_b ?? 0)}, ${region.length} bytes`);
  };

  const maps = element('div', 'hb-stack');
  maps.appendChild(diffMinimapChart(regions, 'a', { title: 'first input', onPick: focus }).element);
  maps.appendChild(diffMinimapChart(regions, 'b', { title: 'second input', onPick: focus }).element);
  root.appendChild(maps);

  const legend = element('div', 'hb-legend');
  for (const [kind, description] of Object.entries(ctx.reference?.diff_types ?? {})) {
    const item = element('span', 'hb-legend-item');
    const swatch = element('span', 'hb-legend-swatch');
    swatch.style.background = `var(${DIFF_TOKENS.get(kind) ?? '--hb-class-0'})`;
    item.append(swatch, element('span', 'hb-legend-label', kind));
    item.title = description;
    legend.appendChild(item);
  }
  root.appendChild(legend);

  const kinds = element('div', 'hb-row-flex');
  const shown = new Set(Object.keys(ctx.reference?.diff_types ?? {}));
  const built = table([
    { label: 'kind', className: '' },
    { label: 'offset a', className: 'is-mono' },
    { label: 'offset b', className: 'is-mono' },
    { label: 'length', className: 'is-numeric' },
  ]);
  const scroller = scrollHost('300px');

  const paint = virtualize(
    scroller,
    built.body,
    () => regions.filter((region) => shown.has(String(region.diff_type))),
    (region) => {
      const row = document.createElement('tr');
      const kindCell = document.createElement('td');
      kindCell.appendChild(element('span', `hb-badge ${diffTone(String(region.diff_type))}`.trim(), String(region.diff_type)));
      row.append(
        kindCell,
        cell(offsetText(region.offset_a ?? 0), 'is-mono'),
        cell(offsetText(region.offset_b ?? 0), 'is-mono'),
        cell(String(region.length ?? 0), 'is-numeric'),
      );
      if (region.diff_type !== 'match') {
        row.classList.add('is-muted');
      }
      row.addEventListener('click', () => focus(region));
      return row;
    },
  );

  for (const kind of shown) {
    const toggle = actionButton(kind, `Show or hide ${kind} regions`, () => {
      if (shown.has(kind)) {
        shown.delete(kind);
        toggle.classList.remove('is-primary');
      } else {
        shown.add(kind);
        toggle.classList.add('is-primary');
      }
      scroller.scrollTop = 0;
      paint();
    }, 'hb-btn is-sm is-primary');
    kinds.appendChild(toggle);
  }
  root.appendChild(kinds);

  scroller.appendChild(built.node);
  root.appendChild(scroller);
  return root;
}

/* ------------------------------------------------------------ sorted lists */

function sortableTable(headings, rows, ctx, useAction) {
  const built = table(headings.map((label, index) => ({ label, className: index === 0 ? 'is-mono is-sortable' : 'is-sortable' })));
  let column = 0;
  let ascending = true;

  const paint = () => {
    const ordered = [...rows].sort((left, right) => {
      const first = left[column];
      const second = right[column];
      const order = typeof first === 'number' && typeof second === 'number' ? first - second : String(first).localeCompare(String(second));
      return ascending ? order : -order;
    });
    built.body.replaceChildren();
    for (const row of ordered) {
      const node = document.createElement('tr');
      row.forEach((item, index) => node.appendChild(cell(String(item), index === 0 ? 'is-mono is-primary' : index === row.length - 1 ? 'is-wide' : '')));
      if (useAction) {
        const actionCell = document.createElement('td');
        actionCell.appendChild(actionButton('use', useAction.title, () => useAction.run(row)));
        node.appendChild(actionCell);
      }
      built.body.appendChild(node);
    }
  };

  const head = built.node.querySelector('thead tr');
  [...head.children].forEach((cellNode, index) => {
    cellNode.addEventListener('click', () => {
      ascending = column === index ? !ascending : true;
      column = index;
      for (const other of head.children) {
        other.classList.remove('is-sort-asc', 'is-sort-desc');
      }
      cellNode.classList.add(ascending ? 'is-sort-asc' : 'is-sort-desc');
      paint();
    });
  });
  if (useAction) {
    head.appendChild(element('th', '', ''));
  }
  paint();
  return built.node;
}

function renderTransformList(name, result, ctx) {
  const rows = (Array.isArray(result.value) ? result.value : []).map(([transform, category, description]) => [transform, category, description]);
  const root = element('div', 'hb-stack');
  root.appendChild(element('div', 'hb-op-hint', 'Every parameter of a transform is raw bytes, including the ones spelled as words.'));
  root.appendChild(sortableTable(['name', 'category', 'description'], rows, ctx, {
    title: 'Open transform_data with this transform selected',
    run: (row) => ctx.openOperation('transform_data', { name: row[0] }),
  }));
  return root;
}

function renderTemplateList(name, result, ctx) {
  const value = Array.isArray(result.value) ? result.value : [];
  const detailed = name === 'list_templates_detailed';
  const rows = detailed
    ? value.map(([template, description, category, fields]) => [template, category, fields, description])
    : value.map(([template, description]) => [template, description]);
  const root = element('div', 'hb-stack');
  root.appendChild(element('span', 'hb-badge is-accent', `${rows.length} templates`));
  root.appendChild(sortableTable(
    detailed ? ['name', 'category', 'fields', 'description'] : ['name', 'description'],
    rows,
    ctx,
    { title: 'Apply this template at the caret', run: (row) => ctx.openOperation('apply_template', { name: row[0], offset: ctx.caret ?? 0 }) },
  ));
  return root;
}

function renderEncodingList(name, result, ctx) {
  const rows = (Array.isArray(result.value) ? result.value : []).map(([code, label]) => [code, label]);
  const root = element('div', 'hb-stack');
  root.appendChild(element('span', 'hb-badge is-accent', `${rows.length} encodings`));
  root.appendChild(sortableTable(['code', 'name'], rows, ctx, {
    title: 'Decode the selection with this encoding',
    run: (row) => ctx.openOperation('decode_text', { offset: ctx.caret ?? 0, length: Math.max(1, ctx.selection ?? 1), encoding: row[0] }),
  }));
  return root;
}

/* ------------------------------------------------------------- transforms */

/**
 * Decide what a transform's write-back button should offer.
 *
 * `result.value.length` carries the transform's true output length even when
 * the inline `__bytes__` payload was capped in transport (`codec.py`'s
 * `_MAX_INLINE_BYTES`), so a caller must not treat the capped array itself as
 * the whole result: writing it verbatim would silently leave the tail of the
 * source range holding pre-transform bytes with nothing on screen to say so.
 *
 * @param {object|null} resultValue The raw `transform_data` return value.
 * @param {number} sourceLength Length of the range the transform was run over.
 * @returns {{trueLength: number, truncated: boolean, note: string|null}} The
 * button's true byte count, whether the inline payload was capped, and the
 * dim note to show beside it, if any.
 */
export function writeBackPlan(resultValue, sourceLength) {
  const truncated = Boolean(resultValue?.truncated);
  const trueLength = Number(resultValue?.length ?? 0);
  const resized = trueLength !== sourceLength;
  let note = null;
  if (truncated && resized) {
    note = `the output is ${trueLength} bytes, only the first ${MAX_INLINE_BYTES} of which arrived inline, and the source range is ${sourceLength}; the untruncated bytes are fetched before writing, which overwrites rather than resizes`;
  } else if (truncated) {
    note = `only the first ${MAX_INLINE_BYTES} of ${trueLength} output bytes arrived inline; the untruncated bytes are fetched before writing`;
  } else if (resized) {
    note = `the output is ${trueLength} bytes and the source range is ${sourceLength}; writing overwrites rather than resizes`;
  }
  return { trueLength, truncated, note };
}

function renderTransform(name, result, ctx) {
  const root = element('div', 'hb-stack');
  const args = ctx.args ?? {};
  const output = taggedBytes(result.value);

  if (result.value?.truncated) {
    root.appendChild(banner('truncated', `${result.value.length} bytes produced, ${MAX_INLINE_BYTES} carried inline`, 'Download the raw form to keep the whole result.'));
  }

  const columns = element('div', 'hb-row-flex');
  columns.style.alignItems = 'flex-start';

  const inputPane = element('div', 'hb-grow hb-stack');
  inputPane.appendChild(element('div', 'hb-panel-subtitle', `input — ${args.length ?? 0} bytes at ${offsetText(args.offset ?? 0)}`));
  const inputBody = element('div');
  inputBody.appendChild(element('div', 'hb-dim', 'reading…'));
  inputPane.appendChild(inputBody);

  const outputPane = element('div', 'hb-grow hb-stack');
  outputPane.appendChild(element('div', 'hb-panel-subtitle', `output — ${result.value?.length ?? 0} bytes`));
  outputPane.appendChild(output === null ? element('div', 'hb-dim', 'the transform returned no bytes') : hexDump(output, 0, 32));
  columns.append(inputPane, outputPane);
  root.appendChild(columns);

  if (ctx.handle && (args.length ?? 0) > 0) {
    readWindow(ctx.handle, args.offset ?? 0, Math.min(args.length, 512))
      .then((window) => inputBody.replaceChildren(hexDump(window.bytes, args.offset ?? 0, 32)))
      .catch((error) => inputBody.replaceChildren(renderError(error)));
  } else {
    inputBody.replaceChildren(element('div', 'hb-dim', 'no input range recorded'));
  }

  if (output !== null && ctx.handle) {
    const plan = writeBackPlan(result.value, args.length ?? 0);
    const row = element('div', 'hb-row-flex');
    row.appendChild(actionButton(`write ${plan.trueLength} bytes back at ${offsetText(args.offset ?? 0)}`, 'Overwrite the source range with the transform output', () => {
      const write = (bytes) => ctx.run('write_bytes', { offset: args.offset ?? 0, data: toHex(bytes).toLowerCase() }, ctx.handle)
        .then(() => {
          ctx.toast('success', 'Written', `${bytes.length} bytes at ${offsetText(args.offset ?? 0)}`);
          ctx.refresh();
        })
        .catch((error) => ctx.toast('error', 'Write failed', error.message));
      if (plan.truncated) {
        ctx.raw(name, args, ctx.handle)
          .then((buffer) => write(new Uint8Array(buffer)))
          .catch((error) => ctx.toast('error', 'Write failed', error.message));
      } else {
        write(output);
      }
    }, 'hb-btn is-sm is-primary'));
    if (plan.note !== null) {
      row.appendChild(element('span', 'hb-dim', plan.note));
    }
    root.appendChild(row);
  }
  const raw = rawDownloadRow(name, result, ctx);
  if (raw !== null) {
    root.appendChild(raw);
  }
  return root;
}

/* ---------------------------------------------------------------- hashing */

function digestSpan(args) {
  if (args?.start !== undefined) {
    return [Number(args.start), Number(args.end)];
  }
  const pair = args?.byte_range;
  if (Array.isArray(pair) && pair.length === 2) {
    return [Number(pair[0]), Number(pair[1])];
  }
  return null;
}

function renderDigest(name, result, ctx) {
  const digest = String(result.value ?? '');
  const root = element('div', 'hb-stack');
  const card = element('div', 'hb-payload');
  const line = element('div', 'hb-payload-row');
  line.appendChild(element('span', 'hb-payload-off', `${digest.length / HALF} B`));
  line.appendChild(element('span', 'hb-payload-hex', digest));
  card.appendChild(line);
  const span = digestSpan(ctx.args);
  const scope = span === null
    ? 'the whole document'
    : `${offsetText(span[0])}…${offsetText(span[1])}`;
  const row = element('div', 'hb-row-flex');
  row.appendChild(element('span', 'hb-dim', `${ctx.args?.algorithm ?? name} over ${scope}`));
  if (span !== null && span[1] <= span[0]) {
    root.appendChild(banner(
      'warning',
      'The requested range is empty',
      'This digest covers no bytes at all: it is what the algorithm produces for an empty input, not a reading of the document.',
    ));
  }
  row.appendChild(element('span', 'hb-grow'));
  row.appendChild(actionButton('copy', 'Copy the digest to the clipboard', () => {
    navigator.clipboard.writeText(digest).then(
      () => ctx.toast('success', 'Copied', digest.slice(0, 24)),
      (error) => ctx.toast('error', 'Copy failed', error.message),
    );
  }));
  root.append(card, row);
  return root;
}

/* ----------------------------------------------------------------- charts */

function renderEntropyMap(name, result, ctx) {
  const values = Array.isArray(result.value) ? result.value.map(Number) : [];
  if (values.length === 0) {
    return emptyState('No blocks to map', 'The document is shorter than one block.', '▁');
  }
  const blockSize = ctx.args?.block_size ?? ENTROPY_BLOCK;
  return entropyMapChart(values, { blockSize, onSeek: (offset) => ctx.seek(offset) }).element;
}

function renderClassification(name, result, ctx) {
  const root = element('div', 'hb-stack');
  const blockSize = ctx.args?.block_size ?? CLASSIFICATION_BLOCK;
  const inline = taggedBytes(result.value);
  const holder = element('div');
  holder.appendChild(element('div', 'hb-dim', 'fetching the untruncated code map…'));
  root.appendChild(holder);

  ctx.raw(name, { block_size: blockSize }, ctx.handle)
    .then((buffer) => {
      const codes = new Uint8Array(buffer);
      holder.replaceChildren(classificationChart(codes, { blockSize, onSeek: (offset) => ctx.seek(offset) }).element);
    })
    .catch((error) => {
      const fallback = element('div', 'hb-stack');
      fallback.appendChild(renderError(error));
      if (inline !== null) {
        fallback.appendChild(classificationChart(inline, { blockSize, onSeek: (offset) => ctx.seek(offset) }).element);
      }
      holder.replaceChildren(fallback);
    });

  if (inline?.length !== undefined && result.value?.truncated) {
    root.appendChild(banner(
      'info',
      'One code byte per block outgrows the inline cap quickly',
      'A gigabyte at 64 KB blocks is 16384 codes, four times what JSON carries inline, so the map is read through the raw sidecar.',
    ));
  }
  return root;
}

function renderDigram(name, result, ctx) {
  const counts = Array.isArray(result.value) ? result.value : [];
  if (counts.length === 0) {
    return emptyState('No digrams', 'The document has fewer than two bytes.', '▦');
  }
  return digramChart(counts).element;
}

function renderDistribution(name, result, ctx) {
  const value = Array.isArray(result.value) ? result.value : [];
  const counts = name === 'byte_statistics'
    ? Object.assign(new Array(256).fill(0), Object.fromEntries(value.map(([byte, count]) => [byte, count])))
    : value.map(Number);
  return histogramChart(counts, { title: name.replace(/_/g, ' ') }).element;
}

function renderByteTypes(name, result, ctx) {
  const counts = (Array.isArray(result.value) ? result.value : [0, 0, 0, 0]).map(Number);
  const root = element('div', 'hb-stack');
  root.appendChild(byteTypeChart(counts).element);
  root.appendChild(element('div', 'hb-op-hint', 'null is 0x00, printable is 0x20 to 0x7E, control is everything else below 0x80, high is 0x80 and above.'));
  return root;
}

/* --------------------------------------------------------- addressing etc */

function renderVaMappings(name, result, ctx) {
  const rows = Array.isArray(result.value) ? result.value : [];
  const root = element('div', 'hb-stack');
  if (rows.length === 0) {
    root.appendChild(emptyState('No mappings', 'Add one to translate between file offsets and virtual addresses.', '⇄'));
    return root;
  }
  const built = table([
    { label: '#', className: 'is-numeric' },
    { label: 'file offset', className: 'is-mono' },
    { label: 'virtual address', className: 'is-mono' },
    { label: 'length', className: 'is-numeric' },
  ]);
  rows.forEach(([offset, va, length], index) => {
    const row = document.createElement('tr');
    row.append(
      cell(String(index), 'is-numeric'),
      cell(offsetText(offset), 'is-mono is-primary'),
      cell(offsetText(va), 'is-mono'),
      cell(humanSize(length), 'is-numeric'),
    );
    row.addEventListener('click', () => ctx.select(offset, Math.max(1, length)));
    built.body.appendChild(row);
  });
  root.appendChild(built.node);
  return root;
}

function renderNullableAddress(name, result, ctx) {
  const value = result.value;
  if (value === null) {
    return banner('warning', `${name} returned null`, 'No mapping covers that address, which is a different answer from the address zero.');
  }
  const root = element('div', 'hb-stack');
  const card = element('div', 'hb-payload');
  const line = element('div', 'hb-payload-row');
  line.appendChild(element('span', 'hb-payload-off', 'value'));
  line.appendChild(element('span', 'hb-payload-hex', `${offsetText(Number(value))} · ${value}`));
  card.appendChild(line);
  root.appendChild(card);
  if (name === 'va_to_file_offset') {
    const row = element('div', 'hb-row-flex');
    row.appendChild(actionButton('go there', 'Move the caret to the translated offset', () => ctx.seek(Number(value))));
    root.appendChild(row);
  }
  return root;
}

function renderBookmarkList(name, result, ctx) {
  const value = Array.isArray(result.value) ? result.value : [];
  const rows = name === 'list_bookmarks'
    ? value.map(([offset, length, label, color]) => ({ offset, length, label, color }))
    : value;
  const root = element('div', 'hb-stack');
  if (rows.length === 0) {
    root.appendChild(emptyState('No bookmarks', 'Add one to keep a named position in this document.', '⚑'));
    return root;
  }
  const built = table([
    { label: '#', className: 'is-numeric' },
    { label: '', className: '' },
    { label: 'label', className: 'is-wide' },
    { label: 'offset', className: 'is-mono' },
    { label: 'length', className: 'is-numeric' },
  ]);
  rows.forEach((entry, index) => {
    const row = document.createElement('tr');
    const swatchCell = document.createElement('td');
    const swatch = element('span', 'hb-swatch');
    swatch.style.background = entry.color;
    swatch.title = entry.color;
    swatchCell.appendChild(swatch);
    row.append(
      cell(String(index), 'is-numeric'),
      swatchCell,
      cell(entry.label, 'is-wide is-primary'),
      cell(offsetText(entry.offset), 'is-mono'),
      cell(String(entry.length), 'is-numeric'),
    );
    row.addEventListener('click', () => ctx.select(entry.offset, Math.max(1, entry.length)));
    built.body.appendChild(row);
  });
  root.appendChild(built.node);
  return root;
}

function renderRead(name, result, ctx) {
  const bytes = taggedBytes(result.value);
  if (bytes === null) {
    return renderGeneric(name, result, ctx);
  }
  const root = element('div', 'hb-stack');
  if (result.value.truncated) {
    root.appendChild(banner('truncated', `${result.value.length} bytes read, ${MAX_INLINE_BYTES} shown`, 'Use the raw download for the whole range.'));
  }
  root.appendChild(hexDump(bytes, ctx.args?.offset ?? 0));
  const raw = rawDownloadRow(name, result, ctx);
  if (raw !== null) {
    root.appendChild(raw);
  }
  return root;
}

function renderDecodedText(name, result, ctx) {
  const root = element('div', 'hb-stack');
  const area = document.createElement('textarea');
  area.className = 'hb-textarea is-mono';
  area.readOnly = true;
  area.value = String(result.value ?? '');
  root.append(element('div', 'hb-op-hint', `decoded as ${ctx.args?.encoding ?? 'the requested encoding'}; U+FFFD marks a byte the encoding could not carry`), area);
  return root;
}

/* -------------------------------------------------------------- registry */

const RENDERERS = new Map([
  ...SEARCH_OPERATIONS.map((name) => [name, renderSearch]),
  ['replace_bytes', renderReplace],
  ['apply_template', renderTemplate],
  ['inspect_at', renderInspect],
  ['extract_strings', renderStrings],
  ['get_patches', renderPatches],
  ['export_patches_ips', renderExportBinary],
  ['export_patches_ips32', renderExportBinary],
  ['export_patches_bps', renderExportBinary],
  ['export_patches_bps_from_path', renderExportBinary],
  ['export_patches_ups', renderExportBinary],
  ['export_patches_ups_from_path', renderExportBinary],
  ['export_patches_cod', renderExportBinary],
  ['export_patches_json', renderExportJson],
  ['export_template_json', renderExportJson],
  ['import_patches_ips', renderImport],
  ['import_patches_bps', renderImport],
  ['import_patches_ups', renderImport],
  ['list_process_memory_regions', renderRegions],
  ['verify_pe_checksum', renderChecksum],
  ['diff_files', renderDiff],
  ['diff_bytes', renderDiff],
  ['list_transforms', renderTransformList],
  ['list_templates', renderTemplateList],
  ['list_templates_detailed', renderTemplateList],
  ['list_encodings', renderEncodingList],
  ['transform_data', renderTransform],
  ['compute_hash', renderDigest],
  ['compute_hash_range', renderDigest],
  ['compute_hash_custom_crc', renderDigest],
  ['entropy_map', renderEntropyMap],
  ['content_classification', renderClassification],
  ['digram_matrix', renderDigram],
  ['byte_distribution_full', renderDistribution],
  ['byte_statistics', renderDistribution],
  ['byte_type_distribution', renderByteTypes],
  ['list_va_mappings', renderVaMappings],
  ['file_offset_to_va', renderNullableAddress],
  ['va_to_file_offset', renderNullableAddress],
  ['get_bookmarks', renderBookmarkList],
  ['list_bookmarks', renderBookmarkList],
  ['read', renderRead],
  ['decode_text', renderDecodedText],
  ['encode_text_to_bytes', renderRead],
]);

/** Names of every operation that has a view written for it rather than the default. */
export function bespokeOperations() {
  return [...RENDERERS.keys()].sort();
}

/**
 * Render one operation's result.
 *
 * @param {string} name Operation name.
 * @param {object} result The invocation result the server returned.
 * @param {object} ctx Document state and the callbacks a view may need.
 * @returns {HTMLElement} The rendered view.
 */
export function renderResult(name, result, ctx) {
  const renderer = RENDERERS.get(name) ?? renderGeneric;
  try {
    return renderer(name, result, ctx);
  } catch (error) {
    const root = element('div', 'hb-stack');
    root.appendChild(banner('error', `The ${name} view failed`, String(error && error.message ? error.message : error)));
    root.appendChild(renderGeneric(name, result, ctx));
    return root;
  }
}

/**
 * Fetch an operation's untruncated binary result.
 *
 * @param {string} name Operation name.
 * @param {object} args Argument object.
 * @param {string|null} handle Document handle, when the operation needs one.
 * @returns {Promise<ArrayBuffer>} The raw payload.
 */
export function fetchRaw(name, args, handle) {
  return callOpRaw(name, args, { handle });
}

export { banner, download, table, cell, actionButton, offsetText };
