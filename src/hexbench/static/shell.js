/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Zachary Flint
   This file is part of Intellicrack. See LICENSE for details.

   The chrome around the grid: menus, toolbar, document tabs, docks, dialogs and
   the status bar.

   Every menu entry, every toolbar button and every keyboard shortcut resolves to
   the same command table, so a command's enabled state is decided once and the
   three surfaces can never disagree about it. Panels are not built here; docks
   host whatever has been handed to registerPanel, which is how the panel modules
   plug in without this file knowing what they are. */

import { callOp, closeDocument, createDocument, DispatchError, getReference, listDocuments, listJobs, shutdown, taggedBytes, toHex } from './api.js';
import { tokenHex } from './charts.js';
import { announce, applyTabStripRoles, decorativeGlyph, element, iconButton, nextId, trapFocus, wireTabStrip } from './dom.js';
import { BYTES_PER_ROW, HexGrid } from './grid.js';


const ENTROPY_DEBOUNCE_MS = 350;
const INSPECT_DEBOUNCE_MS = 90;
const TOAST_MS = 5200;
const ACTIVITY_REFRESH_MS = 2000;
const MIN_DOCK_PX = 140;
const MAX_DOCK_FRACTION = 0.7;
const MIN_EDITOR_PX = 160;
const DEFAULT_DOCK_PX = 240;
const HEX_RADIX = 16;
const DEFAULT_MAX_RESULTS = 4096;
const DEFAULT_MIN_STRING = 5;
const DEFAULT_STRING_LIMIT = 512;
const DEFAULT_NUMERIC_WIDTH = 4;
const VA_DEBOUNCE_MS = 90;
const NUMERIC_SEARCH_RADIX = 16;
const BINARY_SEARCH_RADIX = 2;
const DECIMAL_SEARCH_RADIX = 10;
const JSON_INDENT_LIMIT = 400;
const BYTE_MASK = 0xff;
const KIBIBYTE = 1024;
const SIZE_UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
const ENTROPY_DIGITS = 3;
const PREVIEW_BYTES = 4096;
const BOOKMARK_COLOR_TOKEN = '--hb-bookmark';
const LIVE_REGION_ID = 'live';
const SPLITTER_STEP_PX = 16;
const SPLITTER_PAGE_PX = 64;
const MAX_BIT_INDEX = 7;
const CONTEXT_MENU_MARGIN = 4;

const HEX_PATTERN = /^[0-9a-fA-F\s_,:-]*$/;
const HEX_SEARCH_PATTERN = /^[0-9a-fA-F?\s_,:-]*$/;

/** True when text is a well-formed literal hex pattern (fill, insert, replace): digit pairs and separators only. */
export function isValidHexPattern(text) {
  return HEX_PATTERN.test(text);
}

/** True when text is well-formed for a hex-mode search: the above plus `?` as a nibble wildcard, which only search_hex understands. */
export function isValidHexSearchPattern(text) {
  return HEX_SEARCH_PATTERN.test(text);
}

function hex(value, digits = 0) {
  return value.toString(HEX_RADIX).toUpperCase().padStart(digits, '0');
}

/** What to tell the user after `copySelection` returns: whether the copy actually covered the whole selection. */
export function copyResultToast(copiedLength, selectionLength, limit = PREVIEW_BYTES) {
  if (copiedLength < selectionLength) {
    return {
      kind: 'warning',
      title: 'Copied (truncated)',
      detail: `${copiedLength} of ${selectionLength} bytes copied as hexadecimal (selection exceeds the ${limit}-byte copy limit).`,
    };
  }
  return { kind: 'success', title: 'Copied', detail: `${copiedLength} bytes as hexadecimal.` };
}

/**
 * What `#entropy` should become after one debounced entropy refresh settles.
 *
 * A reply is stale once the active document has moved on to a different
 * handle or generation than the one the request was made against; a stale
 * reply must be dropped rather than overwriting whatever a newer request
 * already produced. A non-stale failure must reset the value rather than
 * leaving whatever was computed before the edit that triggered the refresh.
 */
export function nextEntropyState(outcome, request, active) {
  const stale = !active || active.handle !== request.handle || active.generation !== request.generation;
  if (stale) {
    return { changed: false, value: null };
  }
  return { changed: true, value: outcome.ok ? outcome.value : null };
}

function humanSize(bytes) {
  let value = bytes;
  let unit = 0;
  while (value >= KIBIBYTE && unit < SIZE_UNITS.length - 1) {
    value /= KIBIBYTE;
    unit += 1;
  }
  const rendered = unit === 0 ? String(bytes) : value.toFixed(value < 10 ? 2 : 1);
  return `${rendered} ${SIZE_UNITS[unit]}`;
}

/**
 * How much of the file one scrollbar pixel now covers.
 *
 * Rounding this to a whole byte would print "1 B" for a scroller that actually
 * skips 1.4 bytes a pixel, which reads as though nothing were scaled at all.
 */
function perPixelSize(bytes) {
  if (bytes >= KIBIBYTE) {
    return humanSize(bytes);
  }
  return `${bytes < 10 ? bytes.toFixed(1) : String(Math.round(bytes))} B`;
}

/**
 * What every status item should read, or null for an item with nothing to say.
 *
 * The bar is three tiers: where the caret is, what has been measured, and the
 * document's condition on the right. Null here means hide the item, never print
 * a placeholder - a bar of em dashes reads as ten broken readouts rather than as
 * a session that has not measured anything yet, and the dashes crowd out the
 * three or four values that do mean something.
 *
 * @param {Object} state Everything the bar reads.
 * @param {Object|null} state.document The active document, or null when nothing is open.
 * @param {{offset: number, pane: string, nibble: number}} state.caret Where the caret sits.
 * @param {{start: number, length: number}|null} state.selection The grid selection, or null.
 * @param {number|null} state.entropy The last entropy reading, or null when there is none.
 * @param {number|null} [state.va] The virtual address a mapping resolves the caret to, or null
 * when no mapping covers it (BE-2). Defaults to null so callers that predate VA mapping still work.
 * @param {number} state.hits How many search hits are held.
 * @param {number} state.hitIndex Which hit is current, zero-based.
 * @param {boolean} state.insertMode Whether the grid inserts rather than overwrites.
 * @param {boolean} state.busy Whether an operation is in flight.
 * @param {{scaled: boolean, bytesPerPixel: number}} state.metrics What one scrollbar pixel covers.
 * @returns {Object<string, string|null>} One entry per status value, null where the item must be hidden.
 */
export function statusReadout(state) {
  const { document: active, caret, selection, entropy, va = null, hits, hitIndex, insertMode, busy, metrics } = state;
  return {
    offset: active ? `0x${hex(caret.offset, 8)} · ${caret.offset}` : null,
    va: va === null ? null : `0x${hex(va, 8)} · ${va}`,
    pane: active ? `${caret.pane}${caret.pane === 'hex' ? (caret.nibble === 0 ? ' hi' : ' lo') : ''}` : null,
    selection: selection === null ? null : `${selection.length} B @ 0x${hex(selection.start, 8)}`,
    size: active ? `${humanSize(active.length)} · ${active.length}` : null,
    entropy: entropy === null ? null : entropy.toFixed(ENTROPY_DIGITS),
    hits: hits === 0 ? null : `${hitIndex + 1}/${hits}`,
    scale: metrics.scaled ? `1 px ≈ ${perPixelSize(metrics.bytesPerPixel)}` : null,
    modified: active && active.modified ? 'modified' : null,
    mode: active ? (insertMode ? 'INS' : 'OVR') : null,
    state: busy ? 'working' : 'ready',
  };
}

/**
 * What `#va` should become after one debounced VA-mapping lookup settles.
 *
 * Mirrors {@link nextEntropyState}: a reply is stale once the active document
 * has moved on to a different handle or generation, or the caret has moved
 * since the lookup was issued, and a stale reply must be dropped rather than
 * overwriting whatever a newer lookup already produced. A failure (or "no
 * mapping covers this offset", which the engine reports as `null` rather than
 * as an error) resets the value instead of leaving a stale reading on screen.
 *
 * @param {{ok: boolean, value?: number|null}} outcome The lookup's outcome.
 * @param {{handle: string, generation: number, offset: number}} request What the lookup was issued for.
 * @param {{handle: string, generation: number}|null} active The document that is active now.
 * @param {number} caretOffset Where the caret is now.
 * @returns {{changed: boolean, value: number|null}} Whether `#va` should change, and to what.
 */
export function nextVaState(outcome, request, active, caretOffset) {
  const stale = !active || active.handle !== request.handle || active.generation !== request.generation || caretOffset !== request.offset;
  if (stale) {
    return { changed: false, value: null };
  }
  return { changed: true, value: outcome.ok && outcome.value !== null && outcome.value !== undefined ? Number(outcome.value) : null };
}

/**
 * Take one element of the status bar out of the bar, or put it back.
 *
 * The attribute alone is not enough here. `.hb-status-item` declares a display
 * of its own, and an author declaration outranks the attribute's, so an item
 * the shell believes it has hidden would keep its place in the row and print an
 * empty key. The attribute is still set, because that is what keeps the item
 * out of the accessibility tree as well as out of the layout.
 *
 * @param {HTMLElement} node Item or separator to show or hide.
 * @param {boolean} hidden Whether it should be gone.
 * @returns {void}
 */
function hideStatusNode(node, hidden) {
  node.hidden = hidden;
  node.style.display = hidden ? 'none' : '';
}

/** Offsets are always hexadecimal, with or without an 0x prefix. */
function parseOffset(text) {
  const trimmed = String(text).trim().replace(/^0x/i, '').replace(/[\s_]/g, '');
  if (trimmed === '' || !/^[0-9a-fA-F]+$/.test(trimmed)) {
    return null;
  }
  const value = Number.parseInt(trimmed, HEX_RADIX);
  return Number.isFinite(value) && value >= 0 ? value : null;
}

const NUMERIC_SEARCH_PATTERN = /^-?(0x[0-9a-f]+|0b[01]+|\d+)$/i;

/**
 * Parse a numeric search field: decimal, `0x` hexadecimal or `0b` binary, with
 * an optional leading minus for a signed search.
 *
 * @param {string} text Field text.
 * @returns {number|null} The parsed integer, or null when the text is not one
 * of the three accepted forms.
 */
export function parseSearchInt(text) {
  const trimmed = String(text).trim().replace(/[\s_]/g, '');
  if (!NUMERIC_SEARCH_PATTERN.test(trimmed)) {
    return null;
  }
  const negative = trimmed.startsWith('-');
  const body = negative ? trimmed.slice(1) : trimmed;
  let value;
  if (/^0x/i.test(body)) {
    value = Number.parseInt(body.slice(2), NUMERIC_SEARCH_RADIX);
  } else if (/^0b/i.test(body)) {
    value = Number.parseInt(body.slice(2), BINARY_SEARCH_RADIX);
  } else {
    value = Number.parseInt(body, DECIMAL_SEARCH_RADIX);
  }
  if (!Number.isSafeInteger(value)) {
    return null;
  }
  return negative ? -value : value;
}


/**
 * The one polite live region the page speaks through, created if the document did not declare it.
 *
 * `announce` is deliberately tolerant of a missing region, which means a page
 * that never declares one stays silent without ever failing. Building it here
 * rather than relying on the markup keeps that from being the normal case.
 */
function liveRegion() {
  const existing = document.getElementById(LIVE_REGION_ID);
  if (existing !== null) {
    return existing;
  }
  const region = element('div', 'hb-sr-only', undefined, { id: LIVE_REGION_ID, 'aria-live': 'polite' });
  document.body.appendChild(region);
  return region;
}

/* ------------------------------------------------------------------ toasts */

class ToastStack {
  #host;

  constructor(host) {
    this.#host = host;
  }

  show(kind, title, detail) {
    const toast = element('div', `hb-toast is-${kind}`);
    const glyph = decorativeGlyph(kind === 'error' ? '!' : kind === 'warning' ? '△' : kind === 'success' ? '✓' : 'i', 'hb-toast-glyph');
    const body = element('div', 'hb-toast-body');
    body.appendChild(element('div', 'hb-toast-title', title));
    if (detail) {
      body.appendChild(element('div', 'hb-toast-detail', detail));
    }
    const close = iconButton('✕', 'Dismiss notification', () => toast.remove(), 'hb-toast-close');
    toast.append(glyph, body, close);
    this.#host.appendChild(toast);
    window.setTimeout(() => toast.remove(), TOAST_MS);
    announce(detail ? `${title}. ${detail}` : title);
  }
}

/* ------------------------------------------------------------- json render */

function renderJson(value, key = null, depth = 0, into = null) {
  const container = into ?? element('div', 'hb-json');
  const row = element('div', 'hb-json-row');
  row.style.setProperty('--hb-json-depth', String(depth));

  const isBytes = Boolean(value) && typeof value === 'object' && typeof value.__bytes__ === 'string';
  const isBranch = !isBytes && value !== null && typeof value === 'object';
  const toggle = element('span', isBranch ? 'hb-json-toggle' : 'hb-json-toggle is-leaf');
  row.appendChild(toggle);

  if (key !== null) {
    row.appendChild(element('span', 'hb-json-key', key));
    row.appendChild(element('span', 'hb-json-punct', ':'));
  }

  if (isBytes) {
    const preview = value.__bytes__.slice(0, 64).toUpperCase();
    const suffix = value.__bytes__.length > 64 ? '…' : '';
    row.appendChild(element('span', 'hb-json-bytes', `${preview}${suffix}`));
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
  if (typeof value === 'number') {
    row.appendChild(element('span', 'hb-json-num', String(value)));
    container.appendChild(row);
    return container;
  }
  if (typeof value === 'boolean') {
    row.appendChild(element('span', 'hb-json-bool', String(value)));
    container.appendChild(row);
    return container;
  }

  const entries = Array.isArray(value) ? value.map((item, index) => [String(index), item]) : Object.entries(value);
  row.appendChild(element('span', 'hb-json-punct', Array.isArray(value) ? '[' : '{'));
  row.appendChild(element('span', 'hb-json-count', `${entries.length} ${entries.length === 1 ? 'entry' : 'entries'}`));
  container.appendChild(row);

  const children = element('div');
  for (const [childKey, childValue] of entries.slice(0, JSON_INDENT_LIMIT)) {
    renderJson(childValue, childKey, depth + 1, children);
  }
  if (entries.length > JSON_INDENT_LIMIT) {
    const more = element('div', 'hb-json-row');
    more.style.setProperty('--hb-json-depth', String(depth + 1));
    more.appendChild(element('span', 'hb-json-toggle is-leaf'));
    more.appendChild(element('span', 'hb-json-count', `${entries.length - JSON_INDENT_LIMIT} more not shown`));
    children.appendChild(more);
  }
  container.appendChild(children);

  toggle.addEventListener('click', () => {
    const collapsed = toggle.classList.toggle('is-collapsed');
    children.hidden = collapsed;
  });
  return container;
}

const ARGUMENT_DEFAULTS = new Map([
  ['int', 0],
  ['float', 0],
  ['bool', false],
  ['text', ''],
  ['bytes', ''],
  ['int_pair', [0, 0]],
  ['bool_pair', [false, false]],
  ['bytes_map', {}],
  ['bookmark', () => ({ offset: 0, length: 1, label: '', color: tokenHex(BOOKMARK_COLOR_TOKEN) })],
]);

/** Cache key for a panel keyed on the caret: the document's handle and generation, not merely the offset. */
export function inspectorCacheKey(doc, offset) {
  return doc ? `${doc.handle}:${doc.generation}:${offset}` : null;
}

function defaultArgument(kind) {
  const value = ARGUMENT_DEFAULTS.get(kind);
  if (typeof value === 'function') {
    return value();
  }
  return Array.isArray(value) ? [...value] : (value !== null && typeof value === 'object' ? { ...value } : value);
}

/* ------------------------------------------------------------------ dialog */

class DialogHost {
  #host;
  #overlay = null;
  #trap = null;

  constructor(host) {
    this.#host = host;
  }

  get isOpen() {
    return this.#overlay !== null;
  }

  /**
   * Take the current overlay down.
   *
   * Every way out of either dialog - the scrim, the close button, the footer
   * button, Escape, and one dialog opening over another - lands here, which is
   * what makes this the one place the focus trap has to be released.
   */
  close() {
    this.#trap?.release();
    this.#trap = null;
    this.#overlay?.remove();
    this.#overlay = null;
  }

  /** Show a form and resolve with its values, or with null when dismissed. */
  form(spec) {
    return new Promise((resolve) => {
      this.close();
      const titleId = nextId('hb-dialog-title');
      const overlay = element('div', 'hbx-overlay', undefined, { role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleId });
      const scrim = element('div', 'hb-scrim');
      const dialog = element('div', 'hb-dialog');

      const header = element('div', 'hb-dialog-header');
      const title = element('span', 'hb-dialog-title', spec.title);
      title.id = titleId;
      header.appendChild(title);
      const closeButton = iconButton('✕', `Close the ${spec.title} dialog`, undefined, 'hb-dialog-close');
      header.appendChild(closeButton);

      const body = element('div', 'hb-dialog-body');
      const controls = new Map();
      for (const field of spec.fields ?? []) {
        body.appendChild(this.#field(field, controls));
      }
      if (spec.note) {
        body.appendChild(element('div', 'hb-op-hint', spec.note));
      }

      const footer = element('div', 'hb-dialog-footer');
      const cancel = element('button', 'hb-btn is-ghost', 'Cancel');
      cancel.type = 'button';
      const confirm = element('button', 'hb-btn is-primary', spec.confirmLabel ?? 'Run');
      confirm.type = 'button';
      footer.append(cancel, confirm);

      dialog.append(header, body, footer);
      overlay.append(scrim, dialog);
      this.#host.appendChild(overlay);
      this.#overlay = overlay;
      this.#trap = trapFocus(overlay);

      const finish = (values) => {
        this.close();
        resolve(values);
      };
      const collect = () => {
        const values = {};
        for (const [name, control] of controls) {
          values[name] = control.type === 'checkbox' ? control.checked : control.value;
        }
        return values;
      };

      scrim.addEventListener('mousedown', () => finish(null));
      cancel.addEventListener('click', () => finish(null));
      closeButton.addEventListener('click', () => finish(null));
      confirm.addEventListener('click', () => finish(collect()));
      overlay.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
          event.preventDefault();
          finish(null);
        } else if (event.key === 'Enter' && !(event.target instanceof HTMLTextAreaElement)) {
          event.preventDefault();
          finish(collect());
        }
      });

      const first = controls.values().next().value;
      if (first) {
        first.focus();
        if (typeof first.select === 'function') {
          first.select();
        }
      } else {
        confirm.focus();
      }
    });
  }

  #field(field, controls) {
    const wrapper = element('div', 'hb-arg');
    const label = element('label', 'hb-arg-label');
    label.appendChild(element('span', 'hb-arg-name', field.label));
    if (field.hintType) {
      label.appendChild(element('span', 'hb-arg-type', field.hintType));
    }
    wrapper.appendChild(label);

    const control = element('div', 'hb-arg-control');
    let input;
    if (field.type === 'select') {
      input = document.createElement('select');
      input.className = 'hb-select';
      for (const option of field.options ?? []) {
        const node = document.createElement('option');
        node.value = option.value;
        node.textContent = option.label;
        input.appendChild(node);
      }
      input.value = field.value ?? (field.options?.[0]?.value ?? '');
    } else if (field.type === 'check') {
      input = document.createElement('input');
      input.type = 'checkbox';
      input.className = 'hb-check-box';
      input.checked = Boolean(field.value);
    } else if (field.type === 'textarea') {
      input = document.createElement('textarea');
      input.className = field.mono ? 'hb-textarea is-mono' : 'hb-textarea';
      input.value = field.value ?? '';
    } else {
      input = document.createElement('input');
      input.type = 'text';
      input.className = field.mono ? 'hb-input is-mono' : 'hb-input';
      input.value = field.value ?? '';
      input.spellcheck = false;
      input.autocomplete = 'off';
    }
    if (field.placeholder) {
      input.placeholder = field.placeholder;
    }
    control.appendChild(input);
    wrapper.appendChild(control);
    if (field.hint) {
      wrapper.appendChild(element('div', 'hb-arg-hint', field.hint));
    }
    controls.set(field.name, input);
    return wrapper;
  }

  /** Show a read-only result, rendered as a JSON tree. */
  result(title, meta, value) {
    this.close();
    const titleId = nextId('hb-dialog-title');
    const overlay = element('div', 'hbx-overlay', undefined, { role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleId });
    const scrim = element('div', 'hb-scrim');
    const dialog = element('div', 'hb-dialog hbx-dialog-wide');

    const header = element('div', 'hb-dialog-header');
    const heading = element('span', 'hb-dialog-title', title);
    heading.id = titleId;
    header.appendChild(heading);
    const closeButton = iconButton('✕', `Close the ${title} dialog`, undefined, 'hb-dialog-close');
    header.appendChild(closeButton);

    const body = element('div', 'hb-dialog-body');
    const result = element('div', 'hb-result');
    const resultHeader = element('div', 'hb-result-header');
    resultHeader.appendChild(element('span', 'hb-result-title', 'result'));
    const resultMeta = element('span', 'hb-result-meta');
    resultMeta.appendChild(element('span', undefined, meta));
    resultHeader.appendChild(resultMeta);
    const resultBody = element('div', 'hb-result-body');
    resultBody.appendChild(renderJson(value));
    result.append(resultHeader, resultBody);
    body.appendChild(result);

    const footer = element('div', 'hb-dialog-footer');
    const done = element('button', 'hb-btn is-primary', 'Close');
    done.type = 'button';
    footer.appendChild(done);

    dialog.append(header, body, footer);
    overlay.append(scrim, dialog);
    this.#host.appendChild(overlay);
    this.#overlay = overlay;
    this.#trap = trapFocus(overlay);

    const dismiss = () => this.close();
    scrim.addEventListener('mousedown', dismiss);
    closeButton.addEventListener('click', dismiss);
    done.addEventListener('click', dismiss);
    overlay.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        dismiss();
      }
    });
    done.focus();
  }
}

/* -------------------------------------------------------------------- dock */

class Dock {
  #root;
  #tabs;
  #body;
  #label;
  #panels = [];
  #active = '';
  #mounted = new Map();

  constructor(root, label) {
    this.#root = root;
    this.#label = label;
    this.#tabs = root.querySelector('.hb-dock-tabs');
    this.#body = root.querySelector('.hb-dock-body');
    this.#tabs.addEventListener('click', (event) => {
      const target = event.target;
      if (!(target instanceof HTMLElement)) {
        return;
      }
      const tab = target.closest('.hb-dock-tab');
      if (tab && tab.dataset.panel) {
        this.activate(tab.dataset.panel);
      }
    });
    wireTabStrip(this.#tabs, { keyAttribute: 'panel', onActivate: (id) => this.activate(id) });
  }

  get activeId() {
    return this.#active;
  }

  add(panel) {
    this.#panels = this.#panels.filter((existing) => existing.id !== panel.id);
    this.#panels.push(panel);
    this.#panels.sort((left, right) => (left.order ?? 100) - (right.order ?? 100));
    if (this.#active === '') {
      this.#active = panel.id;
    }
    this.renderTabs();
    this.renderBody();
  }

  remove(id) {
    this.#panels = this.#panels.filter((panel) => panel.id !== id);
    this.#mounted.delete(id);
    if (this.#active === id) {
      this.#active = this.#panels[0]?.id ?? '';
    }
    this.renderTabs();
    this.renderBody();
  }

  activate(id) {
    if (this.#active === id) {
      return;
    }
    this.#active = id;
    this.renderTabs();
    this.renderBody();
  }

  renderTabs() {
    this.#tabs.replaceChildren();
    for (const panel of this.#panels) {
      const tab = element('button', panel.id === this.#active ? 'hb-dock-tab is-active' : 'hb-dock-tab');
      tab.type = 'button';
      tab.dataset.panel = panel.id;
      tab.appendChild(document.createTextNode(panel.title));
      const count = typeof panel.count === 'function' ? panel.count() : null;
      if (count !== null && count !== undefined) {
        tab.appendChild(element('span', 'hb-dock-tab-count', String(count), {
          'aria-label': `${count} ${panel.title.toLowerCase()}`,
        }));
      }
      this.#tabs.appendChild(tab);
    }
    applyTabStripRoles(this.#tabs, {
      keyAttribute: 'panel',
      activeKey: this.#active === '' ? null : this.#active,
      panel: this.#body,
      label: this.#label,
    });
  }

  renderBody() {
    this.#body.replaceChildren();
    if (this.#panels.length === 0) {
      const empty = element('div', 'hb-empty');
      empty.appendChild(element('div', 'hb-empty-icon', '□'));
      empty.appendChild(element('div', 'hb-empty-title', 'No panels here yet'));
      empty.appendChild(element('div', 'hb-empty-hint', 'Panels register themselves with window.hexbench.registerPanel.'));
      this.#body.appendChild(empty);
      return;
    }
    const panel = this.#panels.find((entry) => entry.id === this.#active) ?? this.#panels[0];
    let host = this.#mounted.get(panel.id);
    if (!host) {
      host = element('div', 'hb-panel');
      this.#mounted.set(panel.id, host);
      panel.mount(host);
    }
    this.#body.appendChild(host);
  }

  update(context) {
    for (const panel of this.#panels) {
      if (panel.id === this.#active && typeof panel.update === 'function' && this.#mounted.has(panel.id)) {
        panel.update(context);
      }
    }
    this.renderTabs();
  }

  setVisible(visible) {
    this.#root.hidden = !visible;
  }

  get visible() {
    return !this.#root.hidden;
  }
}

/* ----------------------------------------------------------------- command */

const MENUS = [
  {
    id: 'file',
    items: ['file.new', 'file.open', 'file.openBytes', 'file.attach', '-', 'file.save', 'file.saveAs', '-', 'file.close', 'file.exit'],
  },
  {
    id: 'edit',
    items: [
      'edit.undo', 'edit.redo', '-', 'edit.selectAll', 'edit.copyHex', 'edit.paste', '-',
      'edit.fill', 'edit.copyBlock', 'edit.moveBlock', 'edit.swapBlocks', 'edit.insert', 'edit.delete', '-',
      'edit.toggleInsert',
    ],
  },
  {
    id: 'view',
    items: ['view.goto', '-', 'view.dockRight', 'view.dockBottom', '-', 'view.theme', 'view.refresh'],
  },
  {
    id: 'search',
    items: ['search.find', 'search.findNext', 'search.findPrev', '-', 'search.replace', '-', 'search.clear'],
  },
  {
    id: 'analyze',
    items: [
      'analyze.entropy', 'analyze.byteTypes', 'analyze.classification', 'analyze.digram', '-',
      'analyze.strings', 'analyze.hash', '-', 'analyze.pe', 'analyze.inspect', '-',
      'analyze.templates', 'analyze.applyTemplate', 'analyze.registerTemplate', 'analyze.removeTemplate', 'analyze.exportTemplate',
    ],
  },
  {
    id: 'patch',
    items: ['patch.list', 'patch.export', '-', 'patch.import', '-', 'patch.repairPe'],
  },
  {
    id: 'tools',
    items: [
      'tools.palette', 'tools.operation', 'tools.jobs', 'tools.reference', '-',
      'tools.transforms', 'tools.applyTransform', '-',
      'tools.encodings', 'tools.decodeText',
    ],
  },
  {
    id: 'help',
    items: ['help.keys', 'help.about'],
  },
];

/**
 * The grid's context menu: the block operations that already need a selection
 * (mirroring the Edit menu's own subset), plus the bit toggles, which act on
 * the caret rather than the selection and so have no home in that subset.
 */
const GRID_CONTEXT_MENU_ITEMS = [
  'edit.fill', 'edit.copyBlock', 'edit.moveBlock', 'edit.swapBlocks', '-',
  'edit.getBit', 'edit.setBit', 'edit.toggleBit',
];

const PATCH_PATH_SUFFIX = '_from_path';

/**
 * A human label for one export/import patch operation, derived from its own
 * name rather than a hand-written table - which is what lets the Patch menu's
 * format select track the engine instead of a list somebody typed out.
 *
 * @param {string} name Catalogued operation name, e.g. `export_patches_bps_from_path`.
 * @param {string} prefix The `export_patches_` or `import_patches_` prefix to strip.
 * @returns {string} A short, uppercase label for the format select.
 */
export function patchFormatLabel(name, prefix) {
  const suffix = name.slice(prefix.length);
  if (suffix.endsWith(PATCH_PATH_SUFFIX)) {
    return `${suffix.slice(0, -PATCH_PATH_SUFFIX.length).toUpperCase()} (from a source path)`;
  }
  return suffix.toUpperCase();
}

const SHORTCUTS = [
  { combo: 'ctrl+shift+p', command: 'tools.palette' },
  { combo: 'ctrl+g', command: 'view.goto' },
  { combo: 'ctrl+f', command: 'search.find' },
  { combo: 'ctrl+h', command: 'search.replace' },
  { combo: 'f3', command: 'search.findNext' },
  { combo: 'shift+f3', command: 'search.findPrev' },
  { combo: 'ctrl+z', command: 'edit.undo' },
  { combo: 'ctrl+y', command: 'edit.redo' },
  { combo: 'ctrl+s', command: 'file.save' },
  { combo: 'ctrl+shift+s', command: 'file.saveAs' },
  { combo: 'ctrl+o', command: 'file.open' },
  { combo: 'ctrl+n', command: 'file.new' },
  { combo: 'ctrl+w', command: 'file.close' },
  { combo: 'ctrl+c', command: 'edit.copyHex' },
  { combo: 'ctrl+v', command: 'edit.paste' },
];

/**
 * Commands whose key the hex view handles inside its own keydown, and only there.
 *
 * Each of these is a different operation depending on where the caret is, so the
 * grid keeps them rather than the window: Delete removes the byte in front of
 * the caret, Ctrl+A selects the whole document being viewed, Insert flips the
 * grid's own typing mode. The menu and Help print them with the pane they work
 * in rather than as window-wide keys, which is what they would otherwise read
 * as from a dock panel where pressing them does nothing.
 */
const EDITOR_SCOPED_SHORTCUTS = new Set(['edit.selectAll', 'edit.delete', 'edit.toggleInsert']);

const EDITOR_SCOPE_SUFFIX = ' · editor';

/** Operations that change which VA mappings cover the caret, so the status-bar reading needs a fresh lookup. */
const VA_MAPPING_MUTATIONS = new Set(['add_va_mapping', 'remove_va_mapping']);

/**
 * How a command's shortcut is advertised in the menus.
 *
 * @param {{id: string, shortcut: string}} command The command being rendered.
 * @returns {string} The shortcut text, marked with its scope when the grid owns the key.
 */
export function shortcutText(command) {
  if (command.shortcut === '') {
    return '';
  }
  return EDITOR_SCOPED_SHORTCUTS.has(command.id) ? `${command.shortcut}${EDITOR_SCOPE_SUFFIX}` : command.shortcut;
}

/**
 * Whether a bound shortcut should run given what currently has focus.
 *
 * `typing` alone still lets any ctrl-combo through, so Ctrl+S/Ctrl+F keep
 * working while a field has focus. The two clipboard combos are the exception,
 * and they are not the same exception: a paste always belongs to the field the
 * caret is in, while a copy only has to stand aside when that field has a
 * selection of its own to copy - with nothing selected there, copying what the
 * hex grid has selected is the only reading left.
 */
export function shouldRunShortcut(combo, context) {
  const { typing, hasTextSelection, gridSelection } = context;
  if (typing && !combo.startsWith('ctrl+')) {
    return false;
  }
  if (typing && combo === 'ctrl+v') {
    return false;
  }
  if (typing && combo === 'ctrl+c' && hasTextSelection) {
    return false;
  }
  if (combo === 'ctrl+c' && gridSelection === null) {
    return false;
  }
  return true;
}

function comboOf(event) {
  const parts = [];
  if (event.ctrlKey || event.metaKey) {
    parts.push('ctrl');
  }
  if (event.shiftKey) {
    parts.push('shift');
  }
  if (event.altKey) {
    parts.push('alt');
  }
  parts.push(event.key.toLowerCase());
  return parts.join('+');
}

/* ------------------------------------------------------------ menubar keys */

/** The entries of a popup: its own children carrying the menuitem role, so separators are left out. */
function menuEntriesOf(popup) {
  return [...popup.children].filter((node) => node.getAttribute('role') === 'menuitem');
}

/** A disabled entry is skipped by every movement below rather than focused, which is what `aria-disabled` promises. */
function menuEntryIsEnabled(entry) {
  return entry.getAttribute('aria-disabled') !== 'true';
}

/** The label an entry is announced and typed to, which is its own text without the shortcut beside it. */
function menuEntryLabel(entry) {
  const label = entry.querySelector('.hb-menu-entry-label');
  return (label === null ? entry.textContent : label.textContent) ?? '';
}

/** The entry `step` places from `from` that can hold focus, wrapping; -1 when the menu has no enabled entry at all. */
function nextMenuEntry(entries, from, step) {
  const count = entries.length;
  for (let move = 1; move <= count; move += 1) {
    const index = (((from + (step * move)) % count) + count) % count;
    if (menuEntryIsEnabled(entries[index])) {
      return index;
    }
  }
  return -1;
}

/** The next enabled entry after `from` whose label starts with `character`, wrapping; -1 when none does. */
function menuTypeaheadEntry(entries, character, from) {
  const wanted = character.toLowerCase();
  for (let move = 1; move <= entries.length; move += 1) {
    const index = (from + move) % entries.length;
    const entry = entries[index];
    if (menuEntryIsEnabled(entry) && menuEntryLabel(entry).trim().toLowerCase().startsWith(wanted)) {
      return index;
    }
  }
  return -1;
}

/**
 * Give the menu bar the keyboard the menubar role has been promising.
 *
 * One listener on the bar rather than one per control: the popups are built
 * inside the bar, so the same handler sees a key pressed on a closed menu's
 * button and one pressed on an entry of the open menu, and the two halves of
 * the contract stay next to each other.
 *
 * Enter and Space on an entry are deliberately left alone. An entry is a real
 * button carrying its own click listener, so the browser already activates it;
 * claiming the key here would run the command twice. On a menu *button* they
 * are claimed, because there the browser's click would toggle the menu shut
 * again the moment this opened it.
 *
 * @param {HTMLElement} menubar Element carrying `role="menubar"`.
 * @param {Object} controller How the bar's owner opens, closes and finds its menus.
 * @param {() => HTMLElement[]} controller.buttons The menu buttons, in visual order.
 * @param {() => number} controller.openIndex Index of the open menu, or -1 when none is open.
 * @param {() => HTMLElement|null} controller.popup The open menu's popup, or null.
 * @param {(index: number) => void} controller.open Opens the menu at `index`, building its entries.
 * @param {(returnFocus: boolean) => void} controller.close Shuts whichever menu is open.
 * @returns {void}
 */
export function bindMenubarKeys(menubar, controller) {
  const setRoving = (index) => {
    const buttons = controller.buttons();
    for (const [at, button] of buttons.entries()) {
      button.setAttribute('tabindex', at === index ? '0' : '-1');
    }
    return buttons[index] ?? null;
  };

  const focusButton = (index) => {
    setRoving(index)?.focus();
  };

  const openAt = (index, edge) => {
    setRoving(index);
    controller.open(index);
    const popup = controller.popup();
    if (popup === null) {
      return;
    }
    const entries = menuEntriesOf(popup);
    const target = edge === 'last' ? nextMenuEntry(entries, 0, -1) : nextMenuEntry(entries, -1, 1);
    if (target !== -1) {
      entries[target].focus();
    }
  };

  const stepMenu = (index, step, isOpen) => {
    const count = controller.buttons().length;
    if (count === 0) {
      return;
    }
    const next = (((index + step) % count) + count) % count;
    if (isOpen) {
      openAt(next, 'first');
    } else {
      focusButton(next);
    }
  };

  const onButtonKey = (event, index) => {
    const isOpen = controller.openIndex() !== -1;
    const last = controller.buttons().length - 1;
    switch (event.key) {
      case 'ArrowRight':
        event.preventDefault();
        stepMenu(index, 1, isOpen);
        return;
      case 'ArrowLeft':
        event.preventDefault();
        stepMenu(index, -1, isOpen);
        return;
      case 'Home':
        event.preventDefault();
        if (isOpen) {
          openAt(0, 'first');
        } else {
          focusButton(0);
        }
        return;
      case 'End':
        event.preventDefault();
        if (isOpen) {
          openAt(last, 'first');
        } else {
          focusButton(last);
        }
        return;
      case 'ArrowDown':
      case 'Enter':
      case ' ':
        event.preventDefault();
        openAt(index, 'first');
        return;
      case 'ArrowUp':
        event.preventDefault();
        openAt(index, 'last');
        return;
      case 'Escape':
        if (isOpen) {
          event.preventDefault();
          controller.close(true);
        }
        return;
      default:
        break;
    }
  };

  const onEntryKey = (event, entries, index) => {
    const move = (target) => {
      event.preventDefault();
      if (target !== -1) {
        entries[target].focus();
      }
    };
    switch (event.key) {
      case 'ArrowDown':
        move(nextMenuEntry(entries, index, 1));
        return;
      case 'ArrowUp':
        move(nextMenuEntry(entries, index, -1));
        return;
      case 'Home':
        move(nextMenuEntry(entries, -1, 1));
        return;
      case 'End':
        move(nextMenuEntry(entries, 0, -1));
        return;
      case 'ArrowRight':
        event.preventDefault();
        stepMenu(controller.openIndex(), 1, true);
        return;
      case 'ArrowLeft':
        event.preventDefault();
        stepMenu(controller.openIndex(), -1, true);
        return;
      case 'Escape':
        event.preventDefault();
        controller.close(true);
        return;
      case 'Enter':
      case ' ':
        return;
      default:
        break;
    }
    if (event.key.length === 1 && !event.ctrlKey && !event.altKey && !event.metaKey) {
      const found = menuTypeaheadEntry(entries, event.key, index);
      if (found !== -1) {
        event.preventDefault();
        entries[found].focus();
      }
    }
  };

  menubar.addEventListener('focusin', (event) => {
    const index = controller.buttons().indexOf(event.target);
    if (index !== -1) {
      setRoving(index);
    }
  });

  menubar.addEventListener('keydown', (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
      return;
    }
    const index = controller.buttons().indexOf(target);
    if (index !== -1) {
      onButtonKey(event, index);
      return;
    }
    const popup = controller.popup();
    if (popup === null || !popup.contains(target)) {
      return;
    }
    const entries = menuEntriesOf(popup);
    const at = entries.findIndex((entry) => entry === target || entry.contains(target));
    if (at !== -1) {
      onEntryKey(event, entries, at);
    }
  });
}

/* ------------------------------------------------------------ blank screen */

const BLANK_TITLE = 'Nothing open.';

const BLANK_LEDE = 'Open a file, attach to a running process, or drop bytes straight in. Everything else in the window stays disabled until one of those happens.';

const BLANK_DROP_HINT = 'drop a file anywhere in this window';

const BLANK_PALETTE_KEY = 'Ctrl+Shift+P';

const BLANK_PALETTE_HINT = ' command palette';

const BLANK_ACTIONS = [
  { glyph: '▤', title: 'Open a path', note: 'Ctrl+O', command: 'file.open' },
  { glyph: '◎', title: 'Attach to a process', note: 'read or write live memory', command: 'file.attach' },
  { glyph: '⌸', title: 'Paste bytes', note: 'hex, base64 or raw', command: 'edit.paste' },
];

const PASTE_FORMATS = [
  { value: 'hex', label: 'hex' },
  { value: 'base64', label: 'base64' },
  { value: 'raw', label: 'raw' },
];

const DECIMAL_PATTERN = /^[0-9]+$/;
const HEX_DIGIT_PATTERN = /^[0-9a-fA-F]*$/;
const DECIMAL_RADIX = 10;
const NIBBLES_PER_BYTE = 2;

/**
 * Hexadecimal for text pasted in one of the three formats the paste dialog offers.
 *
 * The conversion happens here rather than in the engine because `open_bytes`
 * takes hexadecimal and nothing else, so base64 and raw text have to become hex
 * on this side of the wire either way. Malformed input is reported rather than
 * repaired: half a byte of hex is as likely to be a truncated paste as a typo,
 * and silently dropping the odd nibble would open a document the user did not
 * copy.
 *
 * @param {string} text What the user typed or pasted.
 * @param {string} format One of `hex`, `base64` or `raw`.
 * @returns {{ok: true, hex: string}|{ok: false, reason: string}} The hexadecimal, or why the text is not usable.
 */
export function hexFromPastedText(text, format) {
  if (format === 'raw') {
    return { ok: true, hex: toHex(new TextEncoder().encode(text)) };
  }
  if (format === 'base64') {
    const compact = text.replace(/\s/g, '');
    let binary;
    try {
      binary = atob(compact);
    } catch {
      return { ok: false, reason: 'That is not base64: it holds characters outside the alphabet, or its length is not a whole number of quanta.' };
    }
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index) & BYTE_MASK;
    }
    return { ok: true, hex: toHex(bytes) };
  }
  const compact = text.replace(/0x/gi, '').replace(/[\s_,:-]/g, '');
  if (!HEX_DIGIT_PATTERN.test(compact)) {
    return { ok: false, reason: 'A hex paste takes pairs of hex digits and separators, and nothing else.' };
  }
  if (compact.length % NIBBLES_PER_BYTE !== 0) {
    return { ok: false, reason: `A hex paste needs whole bytes; ${compact.length} digits leaves the last one half written.` };
  }
  return { ok: true, hex: compact.toUpperCase() };
}

/**
 * True when a drag is carrying files rather than a selection being moved about.
 *
 * The window-wide handlers cancel the browser's default, which for a file is
 * navigating away from the application entirely. Cancelling every drag instead
 * would also take away dragging text inside an input, so the type list decides.
 *
 * @param {DataTransfer|null} transfer The drag's payload description.
 * @returns {boolean} Whether at least one file is being dragged.
 */
export function carriesFiles(transfer) {
  if (!transfer) {
    return false;
  }
  const types = transfer.types;
  return types ? [...types].includes('Files') : false;
}

/* ------------------------------------------------------------------- shell */

/** The whole application outside the grid. */
export class Shell {
  #nodes;
  #grid;
  #toasts;
  #dialogs;
  #dockRight;
  #dockBottom;
  #palette = null;

  #documents = [];
  #active = null;
  #commands = new Map();
  #menus = [];
  #openMenu = null;
  #contextMenu = null;
  #listeners = new Map();

  #hits = [];
  #hitIndex = -1;
  #lastSearch = null;
  #entropyTimer = 0;
  #entropy = null;
  #vaTimer = 0;
  #va = null;
  #catalog = null;
  #operationIndex = new Map();
  #metrics = { scaled: false, bytesPerPixel: 1 };
  #dockRequest = { right: DEFAULT_DOCK_PX, bottom: DEFAULT_DOCK_PX };
  #workspaceObserver = null;
  #busyCount = 0;
  #panels = new Map();
  #blank = null;
  #editorFrame = null;
  #gotoField = null;

  constructor(nodes) {
    liveRegion();
    this.#nodes = nodes;
    this.#toasts = new ToastStack(nodes.toasts);
    this.#dialogs = new DialogHost(nodes.overlays);
    this.#dockRight = new Dock(nodes.dockRight, 'Right dock panels');
    this.#dockBottom = new Dock(nodes.dockBottom, 'Bottom dock panels');
    this.#grid = new HexGrid(nodes.editorHost, {
      onSelect: (selection) => this.#onSelection(selection),
      onCaret: (caret) => this.#onCaret(caret),
      onMetrics: (metrics) => this.#onMetrics(metrics),
      onDocument: (info) => this.#onDocumentChanged(info),
      onError: (error) => this.reportError(error),
    });
    this.#editorFrame = nodes.editorHost.querySelector('.hb-editor');
    this.#defineCommands();
    this.#buildMenus();
    this.#bindToolbar();
    this.#bindTabs();
    this.#bindSplitters();
    this.#bindKeyboard();
    this.#bindFileDrop();
    this.#bindGridContextMenu();
    this.#registerBuiltinPanels();
    this.#applyDockLayout();
    this.#showBlank(true);
    this.#renderStatus();
    this.on('operation', ({ name }) => {
      if (VA_MAPPING_MUTATIONS.has(name)) {
        this.#scheduleVa();
      }
    });
  }

  get grid() {
    return this.#grid;
  }

  get documents() {
    return this.#documents;
  }

  get activeDocument() {
    return this.#active;
  }

  get toasts() {
    return this.#toasts;
  }

  get dialogs() {
    return this.#dialogs;
  }

  attachPalette(palette) {
    this.#palette = palette;
  }

  /* --------------------------------------------------------------- events */

  on(name, handler) {
    const bucket = this.#listeners.get(name) ?? [];
    bucket.push(handler);
    this.#listeners.set(name, bucket);
  }

  off(name, handler) {
    const bucket = this.#listeners.get(name);
    if (bucket) {
      this.#listeners.set(name, bucket.filter((entry) => entry !== handler));
    }
  }

  emit(name, detail) {
    for (const handler of this.#listeners.get(name) ?? []) {
      try {
        handler(detail);
      } catch (error) {
        this.reportError(error);
      }
    }
  }

  /* ---------------------------------------------------------------- panels */

  /** Put a panel in one of the docks; a repeat registration replaces the old one. */
  registerPanel(panel) {
    this.#panels.set(panel.id, panel);
    const dock = panel.dock === 'bottom' ? this.#dockBottom : this.#dockRight;
    dock.add(panel);
    dock.update(this.context());
  }

  /** Take a panel back out of its dock. */
  unregisterPanel(id) {
    const panel = this.#panels.get(id);
    if (!panel) {
      return;
    }
    this.#panels.delete(id);
    (panel.dock === 'bottom' ? this.#dockBottom : this.#dockRight).remove(id);
  }

  /** Everything a panel needs to render itself. */
  context() {
    return {
      document: this.#active,
      documents: this.#documents,
      caret: this.#grid.caret,
      selection: this.#grid.selection,
      hits: this.#hits,
      shell: this,
      grid: this.#grid,
    };
  }

  #registerBuiltinPanels() {
    this.registerPanel(this.#inspectorPanel());
    this.registerPanel(this.#activityPanel());
  }

  #inspectorPanel() {
    let body = null;
    let subtitle = null;
    let timer = 0;
    let lastKey = null;
    const render = (rows) => {
      body.replaceChildren();
      if (rows === null) {
        const empty = element('div', 'hb-empty');
        empty.appendChild(element('div', 'hb-empty-title', 'Nothing under the caret'));
        empty.appendChild(element('div', 'hb-empty-hint', 'Open a document and place the caret to read the bytes as every type that still fits.'));
        body.appendChild(empty);
        return;
      }
      const table = element('table', 'hb-kv');
      const tbody = document.createElement('tbody');
      for (const [key, value] of rows) {
        const tr = document.createElement('tr');
        tr.appendChild(element('td', 'hb-kv-key', key));
        tr.appendChild(element('td', 'hb-kv-value', value));
        tbody.appendChild(tr);
      }
      table.appendChild(tbody);
      body.appendChild(table);
    };
    return {
      id: 'shell.inspector',
      title: 'Inspector',
      dock: 'right',
      order: 10,
      mount: (host) => {
        const header = element('div', 'hb-panel-header');
        subtitle = element('span', 'hb-panel-subtitle', 'no caret');
        header.appendChild(subtitle);
        body = element('div', 'hb-panel-body is-padded');
        host.append(header, body);
        render(null);
      },
      update: (context) => {
        if (!context.document || body === null) {
          lastKey = null;
          render(null);
          return;
        }
        const offset = context.caret.offset;
        const key = inspectorCacheKey(context.document, offset);
        if (key === lastKey) {
          return;
        }
        lastKey = key;
        subtitle.textContent = `at 0x${hex(offset, 8)}`;
        window.clearTimeout(timer);
        timer = window.setTimeout(() => {
          callOp('inspect_at', { handle: context.document.handle, arguments: { offset } })
            .then((result) => {
              const value = result.value ?? {};
              const rows = Object.entries(value).sort(([left], [right]) => left.localeCompare(right));
              render(rows.length === 0 ? null : rows);
            })
            .catch(() => render(null));
        }, INSPECT_DEBOUNCE_MS);
      },
    };
  }

  #activityPanel() {
    let body = null;
    let subtitle = null;
    let jobCount = 0;
    let lastRefresh = 0;
    const refresh = () => {
      if (body === null) {
        return;
      }
      lastRefresh = performance.now();
      listJobs()
        .then((payload) => {
          jobCount = payload.jobs.length;
          body.replaceChildren();
          const table = element('table', 'hb-table');
          const thead = document.createElement('thead');
          const headRow = document.createElement('tr');
          for (const heading of ['Operation', 'State', 'Handle', 'Submitted']) {
            headRow.appendChild(element('th', heading === 'Operation' ? 'is-mono' : '', heading));
          }
          thead.appendChild(headRow);
          const tbody = document.createElement('tbody');
          for (const job of [...payload.jobs].reverse()) {
            const tr = document.createElement('tr');
            tr.appendChild(element('td', 'is-primary', job.operation));
            const state = document.createElement('td');
            const badge = element('span', `hb-badge is-${job.state === 'failed' ? 'error' : job.state === 'done' ? 'success' : 'info'}`, job.state);
            state.appendChild(badge);
            tr.appendChild(state);
            tr.appendChild(element('td', '', job.handle ?? '—'));
            tr.appendChild(element('td', '', new Date(job.submitted_at * 1000).toLocaleTimeString()));
            tbody.appendChild(tr);
          }
          table.append(thead, tbody);
          if (payload.jobs.length === 0) {
            const empty = element('div', 'hb-empty');
            empty.appendChild(element('div', 'hb-empty-title', 'No background jobs yet'));
            empty.appendChild(element('div', 'hb-empty-hint', 'Operations run on the request thread unless they are submitted asynchronously.'));
            body.appendChild(empty);
          } else {
            body.appendChild(table);
          }
          subtitle.textContent = `${payload.exercised.length} of ${payload.operation_count} operations exercised this session`;
        })
        .catch((error) => this.reportError(error));
    };
    return {
      id: 'shell.activity',
      title: 'Activity',
      dock: 'bottom',
      order: 90,
      count: () => (jobCount === 0 ? null : jobCount),
      mount: (host) => {
        const header = element('div', 'hb-panel-header');
        subtitle = element('span', 'hb-panel-subtitle', 'no runs yet');
        header.appendChild(subtitle);
        const actions = element('div', 'hb-panel-actions');
        actions.appendChild(iconButton('⟳', 'Refresh', refresh, 'hb-panel-action'));
        header.appendChild(actions);
        body = element('div', 'hb-panel-body');
        host.append(header, body);
        refresh();
      },
      update: () => {
        if (performance.now() - lastRefresh > ACTIVITY_REFRESH_MS) {
          refresh();
        }
      },
    };
  }

  /* -------------------------------------------------------------- commands */

  #define(id, label, shortcut, run, enabled) {
    this.#commands.set(id, { id, label, shortcut, run, enabled: enabled ?? (() => true) });
  }

  #defineCommands() {
    const hasDocument = () => this.#active !== null;
    const hasSelection = () => this.#grid.selection !== null;

    this.#define('file.new', 'New document', 'Ctrl+N', () => this.newDocument());
    this.#define('file.open', 'Open path…', 'Ctrl+O', () => this.openPath());
    this.#define('file.openBytes', 'Open file contents…', '', () => this.openLocalBytes());
    this.#define('file.attach', 'Attach to a process…', '', () => this.attachProcess());
    this.#define('file.save', 'Save', 'Ctrl+S', () => this.save(false), hasDocument);
    this.#define('file.saveAs', 'Save as…', 'Ctrl+Shift+S', () => this.save(true), hasDocument);
    this.#define('file.close', 'Close document', 'Ctrl+W', () => this.closeActive(), hasDocument);
    this.#define('file.exit', 'Exit', '', () => this.exit());

    this.#define('edit.undo', 'Undo', 'Ctrl+Z', () => this.runOnDocument('undo', {}), () => Boolean(this.#active?.can_undo));
    this.#define('edit.redo', 'Redo', 'Ctrl+Y', () => this.runOnDocument('redo', {}), () => Boolean(this.#active?.can_redo));
    this.#define('edit.selectAll', 'Select all', 'Ctrl+A', () => this.#grid.select(0, this.#active?.length ?? 0), hasDocument);
    this.#define('edit.copyHex', 'Copy selection as hex', 'Ctrl+C', () => this.copySelection(), hasSelection);
    this.#define('edit.paste', 'Paste bytes…', 'Ctrl+V', () => this.pasteBytes());
    this.#define('edit.fill', 'Fill selection…', '', () => this.fillSelection(), hasSelection);
    this.#define('edit.copyBlock', 'Copy block…', '', () => this.copyBlock(), hasSelection);
    this.#define('edit.moveBlock', 'Move block…', '', () => this.moveBlock(), hasSelection);
    this.#define('edit.swapBlocks', 'Swap blocks…', '', () => this.swapBlocks(), hasSelection);
    this.#define('edit.insert', 'Insert bytes…', '', () => this.insertBytes(), hasDocument);
    this.#define('edit.delete', 'Delete selection', 'Del', () => this.deleteSelection(), hasSelection);
    this.#define('edit.getBit', 'Get bit…', '', () => this.getBitAt(), hasDocument);
    this.#define('edit.setBit', 'Set bit…', '', () => this.setBitAt(), hasDocument);
    this.#define('edit.toggleBit', 'Toggle bit…', '', () => this.toggleBitAt(), hasDocument);
    this.#define('edit.toggleInsert', 'Insert / overwrite', 'Ins', () => {
      this.#grid.insertMode = !this.#grid.insertMode;
      this.#renderStatus();
    });

    this.#define('view.goto', 'Go to offset…', 'Ctrl+G', () => this.gotoOffset(), hasDocument);
    this.#define('view.dockRight', 'Right dock', '', () => this.toggleDock('right'));
    this.#define('view.dockBottom', 'Bottom dock', '', () => this.toggleDock('bottom'));
    this.#define('view.theme', 'Toggle theme', '', () => this.toggleTheme());
    this.#define('view.refresh', 'Reload document', '', () => this.refresh(), hasDocument);

    this.#define('search.find', 'Find…', 'Ctrl+F', () => this.find(), hasDocument);
    this.#define('search.findNext', 'Find next', 'F3', () => this.stepHit(1), () => this.#hits.length > 0);
    this.#define('search.findPrev', 'Find previous', 'Shift+F3', () => this.stepHit(-1), () => this.#hits.length > 0);
    this.#define('search.replace', 'Replace…', 'Ctrl+H', () => this.replace(), hasDocument);
    this.#define('search.clear', 'Clear results', '', () => this.clearHits(), () => this.#hits.length > 0);

    this.#define('analyze.entropy', 'Shannon entropy', '', () => this.#focusBottomPanel('panels.entropy'), hasDocument);
    this.#define('analyze.byteTypes', 'Byte type distribution', '', () => this.#focusBottomPanel('panels.byteTypes'), hasDocument);
    this.#define('analyze.classification', 'Content classification', '', () => this.#focusBottomPanel('panels.classification'), hasDocument);
    this.#define('analyze.digram', 'Digram matrix', '', () => this.#focusBottomPanel('panels.digram'), hasDocument);
    this.#define('analyze.strings', 'Extract strings', '', () => this.extractStrings(), hasDocument);
    this.#define('analyze.hash', 'Compute hash…', '', () => this.computeHash(), hasDocument);
    this.#define('analyze.pe', 'Verify PE checksum', '', () => this.showResult('verify_pe_checksum', {}), hasDocument);
    this.#define('analyze.inspect', 'Inspect at caret', '', () => this.showResult('inspect_at', { offset: this.#grid.caret.offset }), hasDocument);

    this.#define('analyze.templates', 'Templates', '', () => this.#focusRightPanel('panels.templates'), hasDocument);
    this.#define('analyze.applyTemplate', 'Apply template…', '', () => this.openOperation('apply_template'), hasDocument);
    this.#define('analyze.registerTemplate', 'Register template (JSON)…', '', () => this.openOperation('register_json_template'), hasDocument);
    this.#define('analyze.removeTemplate', 'Remove template…', '', () => this.openOperation('remove_template'), hasDocument);
    this.#define('analyze.exportTemplate', 'Export template (JSON)…', '', () => this.openOperation('export_template_json'), hasDocument);

    this.#define('patch.list', 'List patches', '', () => this.showResult('get_patches', {}), hasDocument);
    this.#define('patch.export', 'Export patches…', '', () => this.#transferPatches('export'), hasDocument);
    this.#define('patch.import', 'Import patches…', '', () => this.#transferPatches('import'), hasDocument);
    this.#define('patch.repairPe', 'Repair PE checksum', '', () => this.runOnDocument('repair_pe_checksum', {}), hasDocument);

    this.#define('tools.palette', 'Command palette', 'Ctrl+Shift+P', () => this.#palette?.open(''));
    this.#define('tools.operation', 'Operation browser…', '', () => this.openOperation(''));
    this.#define('tools.jobs', 'Activity log', '', () => {
      this.#dockBottom.setVisible(true);
      this.#dockBottom.activate('shell.activity');
      this.#applyDockLayout();
    });
    this.#define('tools.reference', 'Engine reference', '', () => this.showReference());

    this.#define('tools.transforms', 'List transforms', '', () => this.openOperation('list_transforms'));
    this.#define('tools.applyTransform', 'Transform data…', '', () => this.openOperation('transform_data'), hasDocument);
    this.#define('tools.encodings', 'List encodings', '', () => this.openOperation('list_encodings'));
    this.#define('tools.decodeText', 'Decode text…', '', () => this.openOperation('decode_text'), hasDocument);

    this.#define('help.keys', 'Keyboard shortcuts', '', () => this.showShortcuts());
    this.#define('help.about', 'About Hexbench', '', () => this.showAbout());
  }

  /** Run a command by identifier, if it is currently enabled. */
  run(id) {
    const command = this.#commands.get(id);
    if (!command || !command.enabled()) {
      return;
    }
    const outcome = command.run();
    if (outcome && typeof outcome.catch === 'function') {
      outcome.catch((error) => this.reportError(error));
    }
  }

  /* ----------------------------------------------------------------- menus */

  #buildMenus() {
    this.#nodes.menubar.setAttribute('role', 'menubar');
    for (const menu of MENUS) {
      const holder = this.#nodes.menubar.querySelector(`[data-menu="${menu.id}"]`);
      if (!holder) {
        continue;
      }
      const button = holder.querySelector('.hb-menu-item');
      button.setAttribute('role', 'menuitem');
      button.setAttribute('aria-haspopup', 'true');
      button.setAttribute('aria-expanded', 'false');
      button.setAttribute('tabindex', this.#menus.length === 0 ? '0' : '-1');
      const popup = element('div', 'hb-menu-popup', undefined, { role: 'menu', 'aria-label': button.textContent });
      popup.hidden = true;
      holder.appendChild(popup);
      this.#menus.push({ id: menu.id, holder, button, popup });
      button.addEventListener('click', (event) => {
        event.stopPropagation();
        this.#toggleMenu(menu.id, holder, button, popup);
      });
      button.addEventListener('mouseenter', () => {
        if (this.#openMenu !== null && this.#openMenu.id !== menu.id) {
          this.#toggleMenu(menu.id, holder, button, popup, true);
        }
      });
    }
    bindMenubarKeys(this.#nodes.menubar, {
      buttons: () => this.#menus.map((menu) => menu.button),
      openIndex: () => this.#menus.findIndex((menu) => menu.id === this.#openMenu?.id),
      popup: () => this.#openMenu?.popup ?? null,
      open: (index) => this.#openMenuAt(index),
      close: (returnFocus) => this.#closeMenu(returnFocus),
    });
    document.addEventListener('click', () => {
      this.#closeMenu(false);
      this.#closeContextMenu(false);
    });
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        this.#closeMenu();
        this.#closeContextMenu();
      }
    });
  }

  /** Open the menu at `index` whatever is open now, which is what every keyboard route into a menu wants. */
  #openMenuAt(index) {
    const menu = this.#menus[index];
    if (menu) {
      this.#toggleMenu(menu.id, menu.holder, menu.button, menu.popup, true);
    }
  }

  #toggleMenu(id, holder, button, popup, force = false) {
    const alreadyOpen = this.#openMenu !== null && this.#openMenu.id === id;
    this.#closeMenu(false);
    if (alreadyOpen && !force) {
      return;
    }
    const spec = MENUS.find((menu) => menu.id === id);
    this.#populateMenuEntries(popup, spec.items, () => this.#closeMenu());
    popup.hidden = false;
    button.classList.add('is-open');
    button.setAttribute('aria-expanded', 'true');
    this.#openMenu = { id, button, popup };
  }

  /**
   * Fill a menu popup with the entries `items` names, each wired to close `close`
   * before running its command.
   *
   * Shared by the menubar's own popups and the grid's context menu, so the
   * entry markup - the role, the disabled marking, the label element and the
   * shortcut text - can never drift between the two surfaces.
   *
   * @param {HTMLElement} popup Popup element to fill, carrying `role="menu"`.
   * @param {string[]} items Command identifiers in display order; `'-'` renders a separator.
   * @param {() => void} close Closes whichever popup owns these entries, called before the command runs.
   * @returns {void}
   */
  #populateMenuEntries(popup, items, close) {
    popup.replaceChildren();
    for (const entry of items) {
      if (entry === '-') {
        popup.appendChild(element('div', 'hb-menu-sep', undefined, { role: 'separator' }));
        continue;
      }
      const command = this.#commands.get(entry);
      if (!command) {
        continue;
      }
      const enabled = command.enabled();
      const item = element('button', enabled ? 'hb-menu-entry' : 'hb-menu-entry is-disabled', undefined, { type: 'button', role: 'menuitem', tabindex: '-1' });
      item.appendChild(element('span', 'hb-menu-entry-label', command.label));
      item.appendChild(element('span', 'hb-menu-shortcut', shortcutText(command)));
      if (enabled) {
        item.addEventListener('click', (event) => {
          event.stopPropagation();
          close();
          this.run(command.id);
        });
      } else {
        item.setAttribute('aria-disabled', 'true');
      }
      popup.appendChild(item);
    }
  }

  /**
   * Shut whichever menu is open.
   *
   * Focus goes back to the trigger by default, because the keyboard has nowhere
   * else to be once the popup it was standing in disappears. The two paths that
   * pass `false` are the ones where something else has already claimed focus:
   * a click somewhere in the page, and one menu opening as another closes.
   */
  #closeMenu(returnFocus = true) {
    if (this.#openMenu === null) {
      return;
    }
    const { button, popup } = this.#openMenu;
    popup.hidden = true;
    button.classList.remove('is-open');
    button.setAttribute('aria-expanded', 'false');
    this.#openMenu = null;
    if (returnFocus && button.isConnected) {
      button.focus();
    }
  }

  /* --------------------------------------------------------- context menu */

  /**
   * Give the grid a context menu.
   *
   * The browser already turns a right-click, the ContextMenu key and
   * Shift+F10 into one `contextmenu` event fired at whatever holds focus, so
   * one listener on the editor frame answers all three routes into the menu
   * without grid.js knowing this exists.
   *
   * @returns {void}
   */
  #bindGridContextMenu() {
    this.#editorFrame?.addEventListener('contextmenu', (event) => {
      if (this.#active === null) {
        return;
      }
      event.preventDefault();
      this.#openGridContextMenu(Math.max(0, event.clientX), Math.max(0, event.clientY));
    });
  }

  /**
   * Open the grid's context menu, anchored near a viewport position.
   *
   * The entries are populated by the same {@link Shell#populateMenuEntries}
   * loop the menubar's own popups use, so label, shortcut and enabled state
   * can never disagree between the two surfaces. Keyboard movement inside it
   * is A-3's own `bindMenubarKeys`, given a controller with no buttons of its
   * own: every key that would normally route through a menu button falls
   * straight through to the entry-navigation half of that contract instead of
   * a second implementation of the same rules.
   *
   * @param {number} clientX Viewport X to anchor the popup near.
   * @param {number} clientY Viewport Y to anchor the popup near.
   * @returns {void}
   */
  #openGridContextMenu(clientX, clientY) {
    this.#closeMenu(false);
    this.#closeContextMenu(false);
    const popup = element('div', 'hb-menu-popup', undefined, { role: 'menu', 'aria-label': 'Selection actions', tabindex: '-1' });
    this.#populateMenuEntries(popup, GRID_CONTEXT_MENU_ITEMS, () => this.#closeContextMenu());
    popup.style.visibility = 'hidden';
    popup.style.position = 'fixed';
    popup.style.left = '0px';
    popup.style.top = '0px';
    this.#nodes.overlays.appendChild(popup);
    this.#contextMenu = { popup };
    const rect = popup.getBoundingClientRect();
    const left = Math.max(CONTEXT_MENU_MARGIN, Math.min(clientX, window.innerWidth - rect.width - CONTEXT_MENU_MARGIN));
    const top = Math.max(CONTEXT_MENU_MARGIN, Math.min(clientY, window.innerHeight - rect.height - CONTEXT_MENU_MARGIN));
    popup.style.left = `${left}px`;
    popup.style.top = `${top}px`;
    popup.style.visibility = '';
    bindMenubarKeys(popup, {
      buttons: () => [],
      openIndex: () => -1,
      popup: () => popup,
      open: () => {},
      close: (returnFocus) => this.#closeContextMenu(returnFocus),
    });
    const entries = [...popup.children].filter((node) => node.getAttribute('role') === 'menuitem');
    const first = entries.find((entry) => entry.getAttribute('aria-disabled') !== 'true');
    (first ?? popup).focus();
  }

  /**
   * Shut the grid's context menu, the way {@link Shell#closeMenu} shuts the menubar's.
   *
   * @param {boolean} [returnFocus] Whether to send focus back to the grid.
   * @returns {void}
   */
  #closeContextMenu(returnFocus = true) {
    if (this.#contextMenu === null) {
      return;
    }
    const { popup } = this.#contextMenu;
    popup.remove();
    this.#contextMenu = null;
    if (returnFocus) {
      this.#grid.focus();
    }
  }

  /* --------------------------------------------------------------- toolbar */

  #bindToolbar() {
    this.#nodes.toolbar.addEventListener('click', (event) => {
      const target = event.target;
      if (!(target instanceof HTMLElement)) {
        return;
      }
      const button = target.closest('[data-command]');
      if (button) {
        this.run(button.dataset.command);
      }
    });
    this.#gotoField = this.#nodes.toolbar.querySelector('#toolbar-goto');
    this.#gotoField.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter') {
        return;
      }
      event.preventDefault();
      const offset = parseOffset(this.#gotoField.value);
      if (offset === null) {
        this.#toasts.show('warning', 'Not an offset', `"${this.#gotoField.value}" is not a hexadecimal offset.`);
        return;
      }
      this.#jumpTo(offset);
    });
  }

  /**
   * Take the caret to `offset` and leave the toolbar field saying so.
   *
   * The field and the Go to dialog answer the same question, so whichever one
   * was used, both end up showing the offset the view is actually at rather
   * than one of them still showing the last thing typed into it.
   *
   * @param {number} offset Where to put the caret.
   * @returns {void}
   */
  #jumpTo(offset) {
    if (this.#gotoField !== null) {
      this.#gotoField.value = hex(offset, 8);
    }
    this.#grid.seek(offset);
    this.#grid.focus();
  }

  #syncToolbar() {
    for (const button of this.#nodes.toolbar.querySelectorAll('[data-command]')) {
      const command = this.#commands.get(button.dataset.command);
      button.disabled = Boolean(command) && !command.enabled();
    }
    const insert = this.#nodes.toolbar.querySelector('[data-command="edit.toggleInsert"]');
    insert?.classList.toggle('is-active', this.#grid.insertMode);
  }

  /* ------------------------------------------------------------------ tabs */

  #bindTabs() {
    this.#nodes.tabstrip.addEventListener('click', (event) => {
      const target = event.target;
      if (!(target instanceof HTMLElement)) {
        return;
      }
      const close = target.closest('.hb-tab-close');
      if (close) {
        event.stopPropagation();
        this.close(close.dataset.handle);
        return;
      }
      const tab = target.closest('.hb-tab');
      if (tab) {
        this.activate(tab.dataset.handle);
      }
    });
    this.#nodes.tabstrip.addEventListener('auxclick', (event) => {
      if (event.button !== 1) {
        return;
      }
      const target = event.target;
      if (!(target instanceof HTMLElement)) {
        return;
      }
      const tab = target.closest('.hb-tab');
      if (tab) {
        event.preventDefault();
        this.close(tab.dataset.handle);
      }
    });
    wireTabStrip(this.#nodes.tabstrip, {
      keyAttribute: 'handle',
      onActivate: (handle) => this.activate(handle),
      onClose: (handle) => this.close(handle),
      ignoreSelector: '.hb-tab-close',
    });
  }

  #renderTabs() {
    this.#nodes.tabstrip.replaceChildren();
    for (const info of this.#documents) {
      const active = this.#active !== null && info.handle === this.#active.handle;
      const tab = element('div', active ? 'hb-tab is-active' : 'hb-tab', undefined, {
        'aria-label': info.label,
      });
      tab.dataset.handle = info.handle;
      tab.title = info.path ?? `${info.origin} · ${humanSize(info.length)}`;
      tab.appendChild(decorativeGlyph(info.path ? '▤' : '◇', 'hb-tab-icon'));
      tab.appendChild(element('span', 'hb-tab-title', info.label));
      if (info.modified) {
        tab.appendChild(element('span', 'hb-tab-dirty'));
      }
      const close = iconButton('✕', `Close ${info.label}`, undefined, 'hb-tab-close');
      close.dataset.handle = info.handle;
      /* Out of the tab order on purpose: the strip is one tab stop, and a close
         button per document would make it a dozen. Delete closes the focused
         tab instead, which is what the strip's keyboard contract routes there. */
      close.tabIndex = -1;
      tab.appendChild(close);
      this.#nodes.tabstrip.appendChild(tab);
    }
    if (this.#documents.length === 0) {
      this.#nodes.tabstrip.appendChild(element('span', 'hb-tabstrip-overflow', 'no documents open'));
    }
    applyTabStripRoles(this.#nodes.tabstrip, {
      keyAttribute: 'handle',
      activeKey: this.#active?.handle ?? null,
      panel: this.#nodes.editorHost,
      label: 'Open documents',
    });
  }

  /* ------------------------------------------------------------- splitters */

  #bindSplitters() {
    this.#readDockDefaults();
    this.#drag(this.#nodes.splitterV, (event, rect) => {
      this.#dockRequest.right = rect.right - event.clientX;
      this.#clampDocks();
    });
    this.#drag(this.#nodes.splitterH, (event, rect) => {
      this.#dockRequest.bottom = rect.bottom - event.clientY;
      this.#clampDocks();
    });
    this.#splitterKeys(this.#nodes.splitterV, 'right');
    this.#splitterKeys(this.#nodes.splitterH, 'bottom');
    this.#workspaceObserver = new ResizeObserver(() => this.#clampDocks());
    this.#workspaceObserver.observe(this.#nodes.workspace);
    this.#clampDocks();
  }

  /**
   * Make one splitter operable from the keyboard.
   *
   * The step starts from the size actually in force rather than from the
   * remembered request, so a dock whose stored size the window is currently too
   * small to honour moves by one step from where it is instead of jumping back
   * out to a size it cannot have.
   */
  #splitterKeys(handle, side) {
    handle.tabIndex = 0;
    handle.addEventListener('keydown', (event) => {
      const rect = this.#nodes.workspace.getBoundingClientRect();
      const extent = side === 'bottom' ? rect.height : rect.width;
      if (extent <= 0) {
        return;
      }
      const grow = side === 'bottom' ? 'ArrowUp' : 'ArrowLeft';
      const shrink = side === 'bottom' ? 'ArrowDown' : 'ArrowRight';
      const current = this.#fitDock(this.#dockRequest[side], extent);
      let next;
      if (event.key === grow) {
        next = current + SPLITTER_STEP_PX;
      } else if (event.key === shrink) {
        next = current - SPLITTER_STEP_PX;
      } else if (event.key === 'PageUp') {
        next = current + SPLITTER_PAGE_PX;
      } else if (event.key === 'PageDown') {
        next = current - SPLITTER_PAGE_PX;
      } else if (event.key === 'Home') {
        next = this.#fitDock(0, extent);
      } else if (event.key === 'End') {
        next = this.#fitDock(Number.POSITIVE_INFINITY, extent);
      } else {
        return;
      }
      event.preventDefault();
      this.#dockRequest[side] = next;
      this.#clampDocks();
    });
  }

  #readDockDefaults() {
    const styles = getComputedStyle(this.#nodes.workspace);
    const right = Number.parseFloat(styles.getPropertyValue('--hb-dock-right-w'));
    const bottom = Number.parseFloat(styles.getPropertyValue('--hb-dock-bottom-h'));
    this.#dockRequest.right = Number.isFinite(right) ? right : DEFAULT_DOCK_PX;
    this.#dockRequest.bottom = Number.isFinite(bottom) ? bottom : DEFAULT_DOCK_PX;
  }

  /**
   * How large a dock may actually be, given the room the workspace has.
   *
   * The size the user dragged to is remembered separately from the size in
   * force, so shrinking the window borrows space from the dock and growing it
   * again hands that space back rather than stranding the dock at whatever the
   * smallest window happened to allow. The editor keeps a floor either way: a
   * dock at its stored 240px inside a 299px workspace would leave the grid a
   * couple of rows, which is not an editor any more.
   */
  #fitDock(requested, extent) {
    const ceiling = Math.max(0, Math.min(extent * MAX_DOCK_FRACTION, extent - MIN_EDITOR_PX));
    return Math.max(Math.min(requested, ceiling), Math.min(MIN_DOCK_PX, ceiling));
  }

  #clampDocks() {
    const workspace = this.#nodes.workspace;
    const rect = workspace.getBoundingClientRect();
    const write = (name, value) => {
      const text = `${Math.round(value)}px`;
      if (workspace.style.getPropertyValue(name) !== text) {
        workspace.style.setProperty(name, text);
      }
    };
    if (rect.width > 0) {
      const right = this.#fitDock(this.#dockRequest.right, rect.width);
      write('--hb-dock-right-w', right);
      this.#describeSplitter(this.#nodes.splitterV, right, rect.width);
    }
    if (rect.height > 0) {
      const bottom = this.#fitDock(this.#dockRequest.bottom, rect.height);
      write('--hb-dock-bottom-h', bottom);
      this.#describeSplitter(this.#nodes.splitterH, bottom, rect.height);
    }
  }

  /**
   * Publish what a splitter can currently be dragged to.
   *
   * The two ends come out of `#fitDock` itself rather than out of the constants
   * it is built from, so the range assistive technology reads is the same range
   * the drag and the arrow keys are held to, whatever the workspace happens to
   * allow right now.
   */
  #describeSplitter(handle, value, extent) {
    handle.setAttribute('aria-valuenow', String(Math.round(value)));
    handle.setAttribute('aria-valuemin', String(Math.round(this.#fitDock(0, extent))));
    handle.setAttribute('aria-valuemax', String(Math.round(this.#fitDock(Number.POSITIVE_INFINITY, extent))));
  }

  #drag(handle, apply) {
    handle.addEventListener('mousedown', (event) => {
      event.preventDefault();
      handle.classList.add('is-dragging');
      const rect = this.#nodes.workspace.getBoundingClientRect();
      const move = (moveEvent) => apply(moveEvent, rect);
      const stop = () => {
        handle.classList.remove('is-dragging');
        window.removeEventListener('mousemove', move);
        window.removeEventListener('mouseup', stop);
      };
      window.addEventListener('mousemove', move);
      window.addEventListener('mouseup', stop);
    });
  }

  /** Show or hide one of the docks. */
  toggleDock(side) {
    const dock = side === 'bottom' ? this.#dockBottom : this.#dockRight;
    dock.setVisible(!dock.visible);
    this.#applyDockLayout();
  }

  #applyDockLayout() {
    const workspace = this.#nodes.workspace;
    this.#nodes.splitterV.hidden = !this.#dockRight.visible;
    this.#nodes.splitterH.hidden = !this.#dockBottom.visible;
    workspace.style.gridTemplateColumns = this.#dockRight.visible
      ? 'minmax(0, 1fr) var(--hb-splitter-size) var(--hb-dock-right-w)'
      : 'minmax(0, 1fr) 0 0';
    workspace.style.gridTemplateRows = this.#dockBottom.visible
      ? 'minmax(0, 1fr) var(--hb-splitter-size) var(--hb-dock-bottom-h)'
      : 'minmax(0, 1fr) 0 0';
  }

  /**
   * Reveal the bottom dock and switch it to one of its panels, by id.
   *
   * The four spatial analyses route here instead of into a modal: each is a
   * view of the bytes on screen, so the panel that already exists for it -
   * registered by `panels.js` before this command can ever run - is what
   * should be in front, not a fresh dump of the same call's return value.
   *
   * @param {string} id A panel identifier registered with the bottom dock.
   * @returns {void}
   */
  #focusBottomPanel(id) {
    this.#dockBottom.setVisible(true);
    this.#dockBottom.activate(id);
    this.#applyDockLayout();
  }

  /** The right-dock counterpart of {@link Shell#focusBottomPanel}, for the menu entries BE-5 gives Templates. */
  #focusRightPanel(id) {
    this.#dockRight.setVisible(true);
    this.#dockRight.activate(id);
    this.#applyDockLayout();
  }

  /* -------------------------------------------------------------- keyboard */

  #bindKeyboard() {
    window.addEventListener('keydown', (event) => {
      const combo = comboOf(event);
      if (combo === 'ctrl+shift+p') {
        event.preventDefault();
        this.run('tools.palette');
        return;
      }
      if (this.#dialogs.isOpen || this.#palette?.isOpen) {
        return;
      }
      const binding = SHORTCUTS.find((entry) => entry.combo === combo);
      if (!binding) {
        return;
      }
      const target = event.target;
      const typing = target instanceof HTMLElement
        && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.tagName === 'SELECT');
      const nativeSelection = typing ? document.getSelection() : null;
      const context = {
        typing,
        hasTextSelection: Boolean(nativeSelection && !nativeSelection.isCollapsed),
        gridSelection: this.#grid.selection,
      };
      if (!shouldRunShortcut(combo, context)) {
        return;
      }
      event.preventDefault();
      this.run(binding.command);
    });
  }

  /* ------------------------------------------------------------- file drop */

  /**
   * Let a file dropped anywhere in the window open as a document.
   *
   * Both halves are needed and neither is optional: without the `dragover`
   * handler the drop never fires at all, and without the `drop` handler the
   * browser navigates the window to the dropped file and the application is
   * gone. The listeners sit on the window rather than on the editor so the
   * gesture works over the docks and the status bar too, which is what the
   * blank screen promises.
   */
  #bindFileDrop() {
    window.addEventListener('dragover', (event) => {
      if (!carriesFiles(event.dataTransfer)) {
        return;
      }
      event.preventDefault();
      event.dataTransfer.dropEffect = 'copy';
    });
    window.addEventListener('drop', (event) => {
      if (!carriesFiles(event.dataTransfer)) {
        return;
      }
      event.preventDefault();
      const file = event.dataTransfer.files?.[0];
      if (!file) {
        return;
      }
      this.openFile(file).catch((error) => this.reportError(error));
    });
  }

  /* ----------------------------------------------------------- blank screen */

  /**
   * Put the blank screen up in place of the grid, or take it back down.
   *
   * The grid stays built and mounted throughout; only its visibility moves.
   * Tearing it down and rebuilding it would throw away the window cache and the
   * measured row height, and the height cannot be re-measured while the editor
   * is hidden, so a rebuilt grid would come back not knowing how tall a row is.
   * The display is set inline because `.hb-editor` declares `display: flex`,
   * which the `hidden` attribute alone does not outrank.
   *
   * @param {boolean} visible Whether there is no document to show.
   * @returns {void}
   */
  #showBlank(visible) {
    if (this.#editorFrame !== null) {
      this.#editorFrame.style.display = visible ? 'none' : '';
    }
    if (!visible) {
      this.#blank?.remove();
      return;
    }
    this.#blank ??= this.#buildBlank();
    if (this.#blank.isConnected) {
      return;
    }
    this.#nodes.editorHost.appendChild(this.#blank);
    this.#focusBlank();
  }

  /**
   * Hand the keyboard to the blank screen's first action.
   *
   * Only when nothing else has claimed it: whatever hid the grid also stranded
   * focus on the body or inside the element that just went away, and leaving it
   * there would open the application with no keyboard position at all. A focus
   * the user has already put somewhere reachable is left where it is.
   */
  #focusBlank() {
    const active = document.activeElement;
    const stranded = active === null
      || active === document.body
      || (this.#editorFrame !== null && this.#editorFrame.contains(active));
    if (stranded) {
      this.#blank.querySelector('.hb-blank-action')?.focus();
    }
  }

  #buildBlank() {
    const root = element('div', 'hb-blank');

    const head = element('div', 'hb-blank-head');
    head.append(element('h1', 'hb-blank-title', BLANK_TITLE), element('p', 'hb-blank-lede', BLANK_LEDE));

    const actions = element('div', 'hb-blank-actions');
    for (const action of BLANK_ACTIONS) {
      const button = element('button', 'hb-blank-action', undefined, { type: 'button' });
      button.append(
        decorativeGlyph(action.glyph, 'hb-blank-action-glyph'),
        element('span', 'hb-blank-action-title', action.title),
        element('span', 'hb-blank-action-note', action.note),
      );
      button.addEventListener('click', () => this.run(action.command));
      actions.appendChild(button);
    }

    const hints = element('div', 'hb-blank-hints');
    hints.appendChild(element('span', undefined, BLANK_DROP_HINT));
    const palette = element('span');
    palette.append(element('span', 'hb-blank-key', BLANK_PALETTE_KEY), document.createTextNode(BLANK_PALETTE_HINT));
    hints.appendChild(palette);

    root.append(head, actions, hints);
    return root;
  }

  /* ------------------------------------------------------------- documents */

  /** Read the open document list back from the server and repaint the tabs. */
  async reload(preferred = null) {
    this.#documents = await listDocuments();
    const wanted = preferred ?? this.#active?.handle ?? this.#documents.at(-1)?.handle ?? null;
    const found = this.#documents.find((info) => info.handle === wanted) ?? this.#documents.at(-1) ?? null;
    this.#setActive(found);
  }

  #setActive(info) {
    const changed = info?.handle !== this.#active?.handle;
    this.#active = info;
    this.#showBlank(!info);
    this.#grid.setDocument(info);
    if (changed) {
      this.clearHits();
      this.#entropy = null;
      this.#va = null;
    }
    this.#renderTabs();
    this.#scheduleEntropy();
    this.#scheduleVa();
    this.#renderStatus();
    this.#updateDocks();
    this.emit('document', info);
  }

  /** Bring one open document to the front. */
  activate(handle) {
    const info = this.#documents.find((entry) => entry.handle === handle);
    if (info) {
      this.#setActive(info);
      this.#grid.focus();
    }
  }

  /** Close one open document. */
  async close(handle) {
    await closeDocument(handle);
    await this.reload();
  }

  async closeActive() {
    if (this.#active) {
      await this.close(this.#active.handle);
    }
  }

  async newDocument() {
    const info = await createDocument();
    await this.reload(info.handle);
    this.#toasts.show('success', 'New document', 'An empty in-memory document is open.');
  }

  async openPath() {
    const values = await this.#dialogs.form({
      title: 'Open a file',
      confirmLabel: 'Open',
      note: 'The path is resolved by the server process, so it must exist on this machine.',
      fields: [{ name: 'path', label: 'path', hintType: 'str', mono: true, placeholder: 'D:\\samples\\target.exe' }],
    });
    if (values === null || !values.path.trim()) {
      return;
    }
    const result = await callOp('open', { arguments: { path: values.path.trim() } });
    await this.reload(result.created_handle);
    this.#toasts.show('success', 'Opened', values.path.trim());
  }

  /** Read a file the browser can see and hand its bytes to the engine. */
  openLocalBytes() {
    const picker = document.createElement('input');
    picker.type = 'file';
    picker.addEventListener('change', () => {
      const file = picker.files?.[0];
      if (!file) {
        return;
      }
      this.openFile(file).catch((error) => this.reportError(error));
    });
    picker.click();
  }

  /**
   * Hand one browser `File` to the engine, whichever gesture produced it.
   *
   * The file picker and the window-wide drop both arrive here, so a dropped
   * file and a chosen one open by the same call and report the same thing.
   *
   * @param {File} file The file to read.
   * @returns {Promise<void>} Settles once the document is open and announced.
   */
  async openFile(file) {
    const buffer = await file.arrayBuffer();
    const result = await callOp('open_bytes', { arguments: { data: toHex(new Uint8Array(buffer)) } });
    await this.reload(result.created_handle);
    this.#toasts.show('success', 'Opened', `${file.name} (${humanSize(file.size)})`);
  }

  /**
   * Ask for a process and list what its address space is made of.
   *
   * The listing is where an attach actually starts: each readable region the
   * result carries offers to snapshot itself into a document, which is the only
   * way bytes come out of another process. Nothing is copied by listing.
   *
   * @returns {Promise<void>} Settles once the regions have been shown, or the dialog dismissed.
   */
  async attachProcess() {
    const values = await this.#dialogs.form({
      title: 'Attach to a process',
      confirmLabel: 'List regions',
      note: 'The process is opened by the server process, so it must be one this machine will let it read.',
      fields: [{ name: 'pid', label: 'pid', hintType: 'int', mono: true, placeholder: '8124' }],
    });
    if (values === null || values.pid.trim() === '') {
      return;
    }
    const text = values.pid.trim();
    if (!DECIMAL_PATTERN.test(text)) {
      this.#toasts.show('warning', 'Not a process id', `"${text}" is not a decimal process id.`);
      return;
    }
    const pid = Number.parseInt(text, DECIMAL_RADIX);
    this.#setBusy(true);
    let result;
    try {
      result = await callOp('list_process_memory_regions', { arguments: { pid } });
    } finally {
      this.#setBusy(false);
    }
    this.emit('operation', { name: 'list_process_memory_regions', result });
    this.#dialogs.result('list_process_memory_regions', `pid ${pid} · ${result.duration_ms.toFixed(2)} ms`, result.value);
  }

  async save(forcePath) {
    if (!this.#active) {
      return;
    }
    let path = this.#active.path;
    if (forcePath || !path) {
      const values = await this.#dialogs.form({
        title: forcePath ? 'Save as' : 'Save',
        confirmLabel: 'Save',
        note: 'save and save_as are the same call; both always need an explicit path.',
        fields: [{ name: 'path', label: 'path', hintType: 'str', mono: true, value: path ?? '' }],
      });
      if (values === null || !values.path.trim()) {
        return;
      }
      path = values.path.trim();
    }
    await this.runOnDocument('save_as', { path });
    this.#toasts.show('success', 'Saved', path);
  }

  async refresh() {
    this.#grid.invalidate();
    await this.reload();
  }

  /**
   * Ask the server process to stop, then let the embedding shell close the window.
   *
   * `window.close()` alone is a silent no-op for a top-level window a script
   * did not itself open with `window.open()`, which is every window hexbench
   * runs in. Stopping the server first is the part that actually ends the
   * session; closing the tab afterward is best-effort on top of that.
   */
  async exit() {
    await shutdown();
    window.close();
  }

  /* ------------------------------------------------------------ operations */

  /** Run an operation against the active document and fold the result back in. */
  async runOnDocument(name, args) {
    if (!this.#active) {
      return null;
    }
    this.#setBusy(true);
    try {
      const result = await callOp(name, { handle: this.#active.handle, arguments: args });
      if (result.document) {
        this.#applyDocument(result.document);
      }
      this.emit('operation', { name, result });
      return result;
    } finally {
      this.#setBusy(false);
    }
  }

  #applyDocument(info) {
    this.#documents = this.#documents.map((entry) => (entry.handle === info.handle ? info : entry));
    if (this.#active && this.#active.handle === info.handle) {
      this.#active = info;
      this.#grid.setDocument(info);
      this.#scheduleEntropy();
      this.#scheduleVa();
    }
    this.#renderTabs();
    this.#renderStatus();
    this.#updateDocks();
  }

  #onDocumentChanged(info) {
    this.#applyDocument(info);
  }

  /** Run an operation and show its return value. */
  async showResult(name, args) {
    const result = await this.runOnDocument(name, args);
    if (result === null) {
      return;
    }
    this.#dialogs.result(name, `${result.duration_ms.toFixed(2)} ms`, result.value);
  }

  /** Take the catalogue, so operations can be described without another fetch. */
  setCatalog(catalog) {
    this.#catalog = catalog;
    this.#operationIndex = new Map(catalog.operations.map((operation) => [operation.name, operation]));
  }

  get catalog() {
    return this.#catalog;
  }

  /** The catalogue entry for one operation, or null. */
  operation(name) {
    return this.#operationIndex.get(name) ?? null;
  }

  /**
   * Hand a named operation to whatever is currently building argument forms.
   *
   * The hook lives on `window.hexbench` rather than here so a panel module can
   * replace it wholesale; the fallback assigned at start-up is
   * {@link Shell#promptOperation}.
   */
  openOperation(name) {
    const hook = window.hexbench?.openOperation;
    if (typeof hook === 'function') {
      hook(name);
      return;
    }
    this.promptOperation(name);
  }

  /**
   * The standalone argument form: one JSON object for the whole parameter list.
   *
   * This is what runs when no richer form has been registered. It is generated
   * from the catalogue, so it reaches every operation including the ones whose
   * parameters are byte maps or bookmarks.
   */
  async promptOperation(name) {
    const operation = this.operation(name);
    if (operation === null) {
      this.#palette?.open(name);
      return;
    }
    const skeleton = {};
    for (const parameter of operation.parameters) {
      skeleton[parameter.name] = defaultArgument(parameter.kind);
    }
    const values = await this.#dialogs.form({
      title: operation.name,
      confirmLabel: operation.mutating ? 'Run (mutates)' : 'Run',
      note: `${operation.receiver} · ${operation.group} · returns ${operation.returns}`,
      fields: [{
        name: 'arguments',
        label: 'arguments',
        hintType: 'json',
        type: 'textarea',
        mono: true,
        value: JSON.stringify(skeleton, null, 2),
        hint: 'A JSON object keyed by parameter name. Byte parameters are hexadecimal strings; a byte map is an object of them.',
      }],
    });
    if (values === null) {
      return;
    }
    let args;
    try {
      args = JSON.parse(values.arguments);
    } catch (error) {
      this.#toasts.show('warning', 'Not valid JSON', String(error.message));
      return;
    }
    await this.invoke(operation, args);
  }

  /** Run any catalogued operation, routing document, factory and static calls correctly. */
  async invoke(operation, args) {
    this.#setBusy(true);
    try {
      const handle = operation.receiver === 'document' ? this.#active?.handle ?? null : null;
      if (operation.receiver === 'document' && handle === null) {
        this.#toasts.show('warning', 'No document', `${operation.name} acts on an open document.`);
        return null;
      }
      const result = await callOp(operation.name, { handle, arguments: args });
      if (result.created_handle) {
        await this.reload(result.created_handle);
      } else if (result.document) {
        this.#applyDocument(result.document);
      }
      this.emit('operation', { name: operation.name, result });
      this.#dialogs.result(operation.name, `${result.duration_ms.toFixed(2)} ms`, result.value);
      return result;
    } finally {
      this.#setBusy(false);
    }
  }

  async showReference() {
    const reference = await getReference();
    this.#dialogs.result('engine reference', 'static facts', reference);
  }

  /* ----------------------------------------------------------------- patches */

  /**
   * Offer every export or import patch format the engine currently
   * publishes, then hand the chosen one to {@link Shell#openOperation}.
   *
   * The format list comes from the catalogue rather than a written-out pair,
   * so a format the engine adds - or drops - is reachable the moment the
   * catalogue reports it. The generic argument dialog that `openOperation`
   * opens next reads that same operation's real parameter list, which is
   * exactly what makes the source-file argument appear only for the formats
   * that declare one (`export_patches_bps`'s `source_data`, `_from_path`'s
   * `source_path`) and stay absent for the formats that take none.
   *
   * @param {'export'|'import'} direction Which half of the Patch menu asked.
   * @returns {Promise<void>} Resolves once the format is chosen and handed on, or the picker is dismissed.
   */
  async #transferPatches(direction) {
    const prefix = direction === 'export' ? 'export_patches_' : 'import_patches_';
    const operations = (this.#catalog?.operations ?? []).filter((operation) => operation.name.startsWith(prefix));
    if (operations.length === 0) {
      this.#toasts.show('warning', 'No patch formats', `The engine publishes no ${direction} operations for patches.`);
      return;
    }
    const values = await this.#dialogs.form({
      title: direction === 'export' ? 'Export patches' : 'Import patches',
      confirmLabel: 'Next',
      note: 'Every format the engine currently publishes for this direction.',
      fields: [{
        name: 'format',
        label: 'format',
        type: 'select',
        value: operations[0].name,
        options: operations.map((operation) => ({ value: operation.name, label: patchFormatLabel(operation.name, prefix) })),
      }],
    });
    if (values === null) {
      return;
    }
    this.openOperation(values.format);
  }

  /* ---------------------------------------------------------------- search */

  async find() {
    const values = await this.#dialogs.form({
      title: 'Find',
      confirmLabel: 'Search',
      fields: [
        {
          name: 'mode',
          label: 'kind',
          type: 'select',
          value: this.#lastSearch?.mode ?? 'hex',
          options: [
            { value: 'hex', label: 'Hex bytes' },
            { value: 'text', label: 'Text' },
            { value: 'regex', label: 'Regular expression' },
            { value: 'numeric', label: 'Numeric integer' },
            { value: 'numeric_float', label: 'Numeric float' },
            { value: 'numeric_range', label: 'Numeric range' },
          ],
        },
        {
          name: 'needle',
          label: 'pattern',
          mono: true,
          value: this.#lastSearch?.needle ?? '',
          hint: 'Also the numeric value to match, or the lower bound for a range search.',
        },
        { name: 'rangeEnd', label: 'range end', mono: true, value: '', hint: 'Upper bound of the range. Used by numeric range search only.' },
        {
          name: 'encoding',
          label: 'encoding',
          type: 'select',
          value: 'utf-8',
          options: [
            { value: 'utf-8', label: 'utf-8' },
            { value: 'utf-16le', label: 'utf-16le' },
            { value: 'utf-16be', label: 'utf-16be' },
            { value: 'ascii', label: 'ascii' },
            { value: 'iso-8859-1', label: 'iso-8859-1' },
          ],
          hint: 'Used by the text search only.',
        },
        { name: 'sensitive', label: 'case sensitive', type: 'check', value: true },
        {
          name: 'size',
          label: 'width',
          type: 'select',
          value: String(DEFAULT_NUMERIC_WIDTH),
          options: [1, 2, 4, 8].map((width) => ({ value: String(width), label: `${width} byte${width === 1 ? '' : 's'}` })),
          hint: 'Used by numeric search only.',
        },
        { name: 'signed', label: 'signed', type: 'check', value: true, hint: 'Used by numeric integer and range search only.' },
        { name: 'bigEndian', label: 'big-endian', type: 'check', value: false, hint: 'Used by numeric search only; unchecked is little-endian.' },
        { name: 'tolerance', label: 'tolerance', mono: true, value: '0', hint: 'Used by numeric float search only, as the maximum allowed difference.' },
        { name: 'alignment', label: 'alignment', mono: true, value: '1', hint: 'Used by numeric search only; a match must start on a multiple of this.' },
        { name: 'limit', label: 'max results', mono: true, value: String(DEFAULT_MAX_RESULTS) },
      ],
    });
    if (values === null || values.needle === '') {
      return;
    }
    const limit = Number.parseInt(values.limit, 10) || DEFAULT_MAX_RESULTS;
    this.#lastSearch = { mode: values.mode, needle: values.needle };
    let result;
    if (values.mode === 'hex') {
      if (!isValidHexSearchPattern(values.needle)) {
        this.#toasts.show('warning', 'Not hexadecimal', 'A hex search takes pairs of hex digits, or ?? as a wildcard nibble.');
        return;
      }
      result = await this.runOnDocument('search_hex', { pattern: values.needle, max_results: limit });
    } else if (values.mode === 'regex') {
      result = await this.runOnDocument('search_regex', { pattern: values.needle, max_results: limit });
    } else if (values.mode === 'numeric' || values.mode === 'numeric_range') {
      const size = Number.parseInt(values.size, 10) || DEFAULT_NUMERIC_WIDTH;
      const alignment = Number.parseInt(values.alignment, 10) || 1;
      const low = parseSearchInt(values.needle);
      if (low === null) {
        this.#toasts.show('warning', 'Not an integer', 'A numeric search takes a decimal, 0x or 0b integer.');
        return;
      }
      if (values.mode === 'numeric') {
        result = await this.runOnDocument('search_numeric', { value: low, size, signed: values.signed, big_endian: values.bigEndian, alignment, max_results: limit });
      } else {
        const high = parseSearchInt(values.rangeEnd);
        if (high === null) {
          this.#toasts.show('warning', 'Not an integer', 'A numeric range search takes a decimal, 0x or 0b integer as its upper bound.');
          return;
        }
        result = await this.runOnDocument('search_numeric_range', { value_range: [low, high], size, signed: values.signed, big_endian: values.bigEndian, alignment, max_results: limit });
      }
    } else if (values.mode === 'numeric_float') {
      const size = Number.parseInt(values.size, 10) || DEFAULT_NUMERIC_WIDTH;
      const alignment = Number.parseInt(values.alignment, 10) || 1;
      const value = Number.parseFloat(values.needle);
      if (!Number.isFinite(value)) {
        this.#toasts.show('warning', 'Not a number', 'A numeric float search takes a finite decimal number.');
        return;
      }
      const tolerance = Number.parseFloat(values.tolerance);
      result = await this.runOnDocument('search_numeric_float', {
        value,
        size,
        big_endian: values.bigEndian,
        tolerance: Number.isFinite(tolerance) ? tolerance : 0,
        alignment,
        max_results: limit,
      });
    } else {
      result = await this.runOnDocument('search_text', {
        text: values.needle,
        encoding: values.encoding,
        case_sensitive: values.sensitive,
        max_results: limit,
      });
    }
    this.setHits(result?.value ?? []);
  }

  /**
   * Take a list of `(offset, length)` pairs as the current result set.
   *
   * The engine discards the matched bytes, so nothing here carries them; the grid
   * re-reads them through the window endpoint like any other visible byte.
   */
  setHits(pairs) {
    this.#hits = pairs.map(([offset, length]) => ({ offset, length }));
    this.#hitIndex = this.#hits.length > 0 ? 0 : -1;
    this.#grid.highlight(this.#hits, 'is-hit');
    if (this.#hits.length === 0) {
      this.#toasts.show('info', 'No matches', 'Nothing in this document matches.');
    } else {
      this.#grid.select(this.#hits[0].offset, this.#hits[0].length);
      const plural = this.#hits.length === 1 ? 'match' : 'matches';
      this.#toasts.show('success', `${this.#hits.length} ${plural}`, `First at 0x${hex(this.#hits[0].offset, 8)}.`);
    }
    this.emit('hits', this.#hits);
    this.#renderStatus();
    this.#updateDocks();
  }

  clearHits() {
    this.#hits = [];
    this.#hitIndex = -1;
    this.#grid.highlight([], 'is-hit');
    this.emit('hits', this.#hits);
    this.#renderStatus();
    this.#updateDocks();
  }

  stepHit(delta) {
    if (this.#hits.length === 0) {
      return;
    }
    this.#hitIndex = (this.#hitIndex + delta + this.#hits.length) % this.#hits.length;
    const hit = this.#hits[this.#hitIndex];
    this.#grid.select(hit.offset, hit.length);
    this.#grid.focus();
    this.#renderStatus();
  }

  async replace() {
    const values = await this.#dialogs.form({
      title: 'Replace bytes',
      confirmLabel: 'Replace all',
      note: 'Both fields are hexadecimal. A replacement of a different length resizes the document.',
      fields: [
        { name: 'find', label: 'find', mono: true, value: this.#lastSearch?.mode === 'hex' ? this.#lastSearch.needle : '' },
        { name: 'replace', label: 'replace with', mono: true, value: '' },
      ],
    });
    if (values === null || values.find.trim() === '') {
      return;
    }
    if (!isValidHexPattern(values.find) || !isValidHexPattern(values.replace)) {
      this.#toasts.show('warning', 'Not hexadecimal', 'Both patterns must be pairs of hex digits.');
      return;
    }
    const result = await this.runOnDocument('replace_bytes', {
      pattern: values.find.replace(/[\s_,:-]/g, ''),
      replacement: values.replace.replace(/[\s_,:-]/g, ''),
    });
    this.#grid.invalidate();
    this.#toasts.show('success', 'Replaced', `${result.value} occurrence${result.value === 1 ? '' : 's'}.`);
  }

  /* ----------------------------------------------------------------- edits */

  async gotoOffset() {
    const typed = this.#gotoField === null ? null : parseOffset(this.#gotoField.value);
    const values = await this.#dialogs.form({
      title: 'Go to offset',
      confirmLabel: 'Go',
      note: 'Offsets are hexadecimal.',
      fields: [{ name: 'offset', label: 'offset', mono: true, value: hex(typed ?? this.#grid.caret.offset, 8) }],
    });
    if (values === null) {
      return;
    }
    const offset = parseOffset(values.offset);
    if (offset === null) {
      this.#toasts.show('warning', 'Not an offset', `"${values.offset}" is not a hexadecimal offset.`);
      return;
    }
    this.#jumpTo(offset);
  }

  async fillSelection() {
    const selection = this.#grid.selection;
    if (selection === null) {
      return;
    }
    const values = await this.#dialogs.form({
      title: 'Fill selection',
      confirmLabel: 'Fill',
      note: `${selection.length} bytes at 0x${hex(selection.start, 8)} will be overwritten by the repeated pattern.`,
      fields: [{ name: 'pattern', label: 'pattern', mono: true, value: '00' }],
    });
    if (values === null || values.pattern.trim() === '') {
      return;
    }
    await this.runOnDocument('fill_block', {
      offset: selection.start,
      length: selection.length,
      pattern: values.pattern.replace(/[\s_,:-]/g, ''),
    });
    this.#grid.markModified(selection.start, selection.length);
    this.#grid.invalidate();
  }

  /** Overwrite the destination with the selection's bytes, prefilled from it the way {@link Shell#fillSelection} is. */
  async copyBlock() {
    const selection = this.#grid.selection;
    if (selection === null) {
      return;
    }
    const values = await this.#dialogs.form({
      title: 'Copy block',
      confirmLabel: 'Copy',
      note: `${selection.length} bytes at 0x${hex(selection.start, 8)} will be copied to the destination offset below, overwriting what is there.`,
      fields: [{ name: 'dstOffset', label: 'destination offset', mono: true, value: hex(this.#grid.caret.offset, 8) }],
    });
    if (values === null) {
      return;
    }
    const dstOffset = parseOffset(values.dstOffset);
    if (dstOffset === null) {
      this.#toasts.show('warning', 'Not an offset', `"${values.dstOffset}" is not a hexadecimal offset.`);
      return;
    }
    await this.runOnDocument('copy_block', { src_offset: selection.start, length: selection.length, dst_offset: dstOffset });
    this.#grid.markModified(dstOffset, selection.length);
    this.#grid.invalidate();
  }

  /** Move the selection to the destination, prefilled from it the way {@link Shell#fillSelection} is. */
  async moveBlock() {
    const selection = this.#grid.selection;
    if (selection === null) {
      return;
    }
    const values = await this.#dialogs.form({
      title: 'Move block',
      confirmLabel: 'Move',
      note: `${selection.length} bytes at 0x${hex(selection.start, 8)} will be moved to the destination offset below.`,
      fields: [{ name: 'dstOffset', label: 'destination offset', mono: true, value: hex(this.#grid.caret.offset, 8) }],
    });
    if (values === null) {
      return;
    }
    const dstOffset = parseOffset(values.dstOffset);
    if (dstOffset === null) {
      this.#toasts.show('warning', 'Not an offset', `"${values.dstOffset}" is not a hexadecimal offset.`);
      return;
    }
    await this.runOnDocument('move_block', { src_offset: selection.start, length: selection.length, dst_offset: dstOffset });
    this.#grid.invalidate();
  }

  /**
   * Swap the selection with another block of the same length, prefilled from
   * it the way {@link Shell#fillSelection} is.
   *
   * The engine requires the two blocks to be the same length, so block B's
   * length is not asked for; it is always the selection's.
   */
  async swapBlocks() {
    const selection = this.#grid.selection;
    if (selection === null) {
      return;
    }
    const values = await this.#dialogs.form({
      title: 'Swap blocks',
      confirmLabel: 'Swap',
      note: `Block A is ${selection.length} bytes at 0x${hex(selection.start, 8)}. Block B below must be the same length.`,
      fields: [{ name: 'offsetB', label: 'block B offset', mono: true, value: hex(this.#grid.caret.offset, 8) }],
    });
    if (values === null) {
      return;
    }
    const offsetB = parseOffset(values.offsetB);
    if (offsetB === null) {
      this.#toasts.show('warning', 'Not an offset', `"${values.offsetB}" is not a hexadecimal offset.`);
      return;
    }
    await this.runOnDocument('swap_blocks', { offset_a: selection.start, len_a: selection.length, offset_b: offsetB, len_b: selection.length });
    this.#grid.invalidate();
  }

  /** Validate a bit-editing offset/index pair, toasting and returning null when either is malformed. */
  #readBitTarget(values) {
    const offset = parseOffset(values.offset);
    const bitIndex = Number.parseInt(values.bitIndex, 10);
    if (offset === null || !Number.isInteger(bitIndex) || bitIndex < 0 || bitIndex > MAX_BIT_INDEX) {
      this.#toasts.show('warning', 'Invalid bit', 'The offset must be hexadecimal and the bit index 0-7.');
      return null;
    }
    return { offset, bitIndex };
  }

  /** Read one bit and show it, prefilled from the caret. */
  async getBitAt() {
    const values = await this.#dialogs.form({
      title: 'Get bit',
      confirmLabel: 'Read',
      fields: [
        { name: 'offset', label: 'offset', mono: true, value: hex(this.#grid.caret.offset, 8) },
        { name: 'bitIndex', label: 'bit index (0-7)', mono: true, value: '0' },
      ],
    });
    if (values === null) {
      return;
    }
    const target = this.#readBitTarget(values);
    if (target === null) {
      return;
    }
    await this.showResult('get_bit', { offset: target.offset, bit_index: target.bitIndex });
  }

  /** Set or clear one bit, prefilled from the caret. */
  async setBitAt() {
    const values = await this.#dialogs.form({
      title: 'Set bit',
      confirmLabel: 'Set',
      fields: [
        { name: 'offset', label: 'offset', mono: true, value: hex(this.#grid.caret.offset, 8) },
        { name: 'bitIndex', label: 'bit index (0-7)', mono: true, value: '0' },
        { name: 'value', label: 'value (checked sets, unchecked clears)', type: 'check', value: true },
      ],
    });
    if (values === null) {
      return;
    }
    const target = this.#readBitTarget(values);
    if (target === null) {
      return;
    }
    await this.runOnDocument('set_bit', { offset: target.offset, bit_index: target.bitIndex, value: values.value });
    this.#grid.markModified(target.offset, 1);
    this.#grid.invalidate();
  }

  /** Flip one bit and show its new value, prefilled from the caret. */
  async toggleBitAt() {
    const values = await this.#dialogs.form({
      title: 'Toggle bit',
      confirmLabel: 'Toggle',
      fields: [
        { name: 'offset', label: 'offset', mono: true, value: hex(this.#grid.caret.offset, 8) },
        { name: 'bitIndex', label: 'bit index (0-7)', mono: true, value: '0' },
      ],
    });
    if (values === null) {
      return;
    }
    const target = this.#readBitTarget(values);
    if (target === null) {
      return;
    }
    await this.showResult('toggle_bit', { offset: target.offset, bit_index: target.bitIndex });
    this.#grid.markModified(target.offset, 1);
    this.#grid.invalidate();
  }

  async insertBytes() {
    const caret = this.#grid.caret;
    const values = await this.#dialogs.form({
      title: 'Insert bytes',
      confirmLabel: 'Insert',
      note: `Inserted at 0x${hex(caret.offset, 8)}, pushing everything after it along.`,
      fields: [{ name: 'data', label: 'data', mono: true, type: 'textarea', value: '' }],
    });
    if (values === null || values.data.trim() === '') {
      return;
    }
    await this.runOnDocument('insert_bytes', { offset: caret.offset, data: values.data.replace(/[\s_,:-]/g, '') });
    this.#grid.invalidate();
  }

  async deleteSelection() {
    const selection = this.#grid.selection;
    if (selection === null) {
      return;
    }
    await this.runOnDocument('delete_bytes', { offset: selection.start, length: selection.length });
    this.#grid.invalidate();
  }

  async copySelection() {
    const selection = this.#grid.selection;
    if (selection === null || !this.#active) {
      return;
    }
    const span = Math.min(selection.length, PREVIEW_BYTES);
    const result = await this.runOnDocument('read', { offset: selection.start, length: span });
    const bytes = taggedBytes(result.value);
    if (bytes === null) {
      return;
    }
    const text = [...bytes].map((value) => hex(value & BYTE_MASK, 2)).join(' ');
    await navigator.clipboard.writeText(text);
    const toast = copyResultToast(bytes.length, selection.length);
    this.#toasts.show(toast.kind, toast.title, toast.detail);
  }

  /**
   * Open whatever is on the clipboard, or whatever the user types, as a document.
   *
   * The clipboard read is a courtesy and not a requirement: a browser that has
   * not been given clipboard permission rejects it, which is the ordinary case
   * rather than a failure, so the dialog simply opens empty and the user pastes
   * into it by hand.
   *
   * @returns {Promise<void>} Settles once the document is open, or the dialog dismissed.
   */
  async pasteBytes() {
    let clipboard = '';
    try {
      clipboard = await navigator.clipboard.readText();
    } catch {
      clipboard = '';
    }
    const values = await this.#dialogs.form({
      title: 'Paste bytes',
      confirmLabel: 'Open',
      note: 'The text becomes a new in-memory document. It is never written anywhere until you save it.',
      fields: [
        { name: 'text', label: 'bytes', type: 'textarea', mono: true, value: clipboard },
        { name: 'format', label: 'format', type: 'select', value: 'hex', options: PASTE_FORMATS },
      ],
    });
    if (values === null || values.text.trim() === '') {
      return;
    }
    const converted = hexFromPastedText(values.text, values.format);
    if (!converted.ok) {
      this.#toasts.show('warning', `Not ${values.format}`, converted.reason);
      return;
    }
    if (converted.hex === '') {
      this.#toasts.show('warning', 'Nothing to open', `Read as ${values.format}, that text carries no bytes.`);
      return;
    }
    const result = await callOp('open_bytes', { arguments: { data: converted.hex } });
    await this.reload(result.created_handle);
    const length = converted.hex.length / NIBBLES_PER_BYTE;
    this.#toasts.show('success', 'Pasted', `${length} byte${length === 1 ? '' : 's'} from ${values.format}.`);
  }

  async extractStrings() {
    await this.showResult('extract_strings', {
      min_length: DEFAULT_MIN_STRING,
      include_ascii: true,
      include_utf16: true,
      max_results: DEFAULT_STRING_LIMIT,
    });
  }

  async computeHash() {
    const values = await this.#dialogs.form({
      title: 'Compute hash',
      confirmLabel: 'Compute',
      fields: [
        {
          name: 'algorithm',
          label: 'algorithm',
          type: 'select',
          options: ['md5', 'sha1', 'sha256', 'sha512', 'crc32', 'crc64', 'blake3'].map((name) => ({ value: name, label: name })),
        },
      ],
    });
    if (values === null) {
      return;
    }
    await this.showResult('compute_hash', { algorithm: values.algorithm });
  }

  /* ------------------------------------------------------------------ help */

  showShortcuts() {
    const rows = SHORTCUTS.map((entry) => [entry.combo, this.#commands.get(entry.command)?.label ?? entry.command]);
    for (const id of EDITOR_SCOPED_SHORTCUTS) {
      const command = this.#commands.get(id);
      if (command) {
        rows.push([`${command.shortcut.toLowerCase()} (editor)`, command.label]);
      }
    }
    rows.push(
      ['arrows', 'Move the caret'],
      ['shift+arrows', 'Extend the selection'],
      ['page up / page down', 'Move a screen'],
      ['home / end', 'Start and end of the row'],
      ['ctrl+home / ctrl+end', 'Start and end of the document'],
      ['f6 / ctrl+tab', 'Move between the hex and ASCII panes'],
      ['tab / shift+tab', 'Leave the editor for the rest of the window'],
      ['backspace', 'Remove the byte before the caret'],
      ['0-9 a-f', 'Edit a nibble in the hex pane'],
    );
    this.#dialogs.result('keyboard', `${rows.length} bindings`, Object.fromEntries(rows));
  }

  showAbout() {
    this.#dialogs.result('Hexbench', 'session', {
      engine: 'intellicrack_hexcore',
      documents: this.#documents.length,
      theme: document.documentElement.dataset.theme ?? 'light',
      bytes_per_row: BYTES_PER_ROW,
    });
  }

  /** Flip between the light and the dark token set, starting from what is showing. */
  toggleTheme() {
    const root = document.documentElement;
    const current = root.dataset.theme ?? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    root.dataset.theme = current === 'dark' ? 'light' : 'dark';
    this.emit('theme', root.dataset.theme);
  }

  /* ----------------------------------------------------------- status bar */

  #onSelection(selection) {
    this.#renderStatus();
    this.#updateDocks();
    this.emit('selection', selection);
  }

  #onCaret(caret) {
    this.#renderStatus();
    this.#updateDocks();
    this.#scheduleVa();
    this.emit('caret', caret);
  }

  #onMetrics(metrics) {
    const changed = metrics.scaled !== this.#metrics.scaled
      || Math.abs(metrics.bytesPerPixel - this.#metrics.bytesPerPixel) > Number.EPSILON;
    this.#metrics = metrics;
    if (changed) {
      this.#renderStatus();
    }
  }

  #updateDocks() {
    const context = this.context();
    this.#dockRight.update(context);
    this.#dockBottom.update(context);
  }

  #scheduleEntropy() {
    window.clearTimeout(this.#entropyTimer);
    if (!this.#active || this.#active.length === 0) {
      this.#entropy = null;
      return;
    }
    const request = { handle: this.#active.handle, generation: this.#active.generation };
    const applyOutcome = (outcome) => {
      const active = this.#active ? { handle: this.#active.handle, generation: this.#active.generation } : null;
      const next = nextEntropyState(outcome, request, active);
      if (next.changed) {
        this.#entropy = next.value;
        this.#renderStatus();
      }
    };
    this.#entropyTimer = window.setTimeout(() => {
      callOp('entropy', { handle: request.handle, arguments: {} })
        .then((result) => applyOutcome({ ok: true, value: result.value }))
        .catch(() => applyOutcome({ ok: false }));
    }, ENTROPY_DEBOUNCE_MS);
  }

  /**
   * Debounce a `file_offset_to_va` lookup for the caret's current offset.
   *
   * A mapping without any coverage is not an error - the engine reports it as
   * `null` - so BE-2's status-bar item follows UX-3's rule for an unmeasured
   * value: hidden rather than printed as a placeholder, via {@link nextVaState}
   * resetting `#va` to null on both "no mapping" and an outright failure.
   */
  #scheduleVa() {
    window.clearTimeout(this.#vaTimer);
    if (!this.#active) {
      if (this.#va !== null) {
        this.#va = null;
        this.#renderStatus();
      }
      return;
    }
    const request = { handle: this.#active.handle, generation: this.#active.generation, offset: this.#grid.caret.offset };
    const applyOutcome = (outcome) => {
      const active = this.#active ? { handle: this.#active.handle, generation: this.#active.generation } : null;
      const next = nextVaState(outcome, request, active, this.#grid.caret.offset);
      if (next.changed) {
        this.#va = next.value;
        this.#renderStatus();
      }
    };
    this.#vaTimer = window.setTimeout(() => {
      callOp('file_offset_to_va', { handle: request.handle, arguments: { offset: request.offset } })
        .then((result) => applyOutcome({ ok: true, value: result.value }))
        .catch(() => applyOutcome({ ok: false }));
    }, VA_DEBOUNCE_MS);
  }

  #setBusy(busy) {
    const wasBusy = this.#busyCount > 0;
    this.#busyCount = Math.max(0, this.#busyCount + (busy ? 1 : -1));
    const isBusy = this.#busyCount > 0;
    if (isBusy !== wasBusy) {
      announce(isBusy ? 'Working' : 'Ready');
    }
    this.#renderStatus();
  }

  #renderStatus() {
    const nodes = this.#nodes.status;
    const readout = statusReadout({
      document: this.#active,
      caret: this.#grid.caret,
      selection: this.#grid.selection,
      entropy: this.#entropy,
      va: this.#va,
      hits: this.#hits.length,
      hitIndex: this.#hitIndex,
      insertMode: this.#grid.insertMode,
      busy: this.#busyCount > 0,
      metrics: this.#metrics,
    });

    for (const [name, value] of Object.entries(readout)) {
      const node = nodes[name];
      hideStatusNode(node.closest('.hb-status-item'), value === null);
      if (value !== null) {
        node.textContent = value;
      }
    }
    this.#trimStatusSeparators();

    nodes.modifiedItem.classList.toggle('is-warning', readout.modified !== null);
    nodes.dot.className = this.#busyCount > 0 ? 'hb-status-dot is-busy' : 'hb-status-dot is-ready';

    this.#syncToolbar();
  }

  /**
   * Hide the separators the hidden items leave stranded.
   *
   * Whole tiers empty out in an ordinary session, and a rule that hid only the
   * items would leave the bar starting on a bare hairline or printing two of
   * them side by side. A separator earns its place only when it has a visible
   * item on both sides of it, where "side" ends at the next separator or at the
   * spacer that pushes the right-hand tier away - which is why the spacer counts
   * as a boundary and not as a gap the scan can look across.
   */
  #trimStatusSeparators() {
    const bar = this.#nodes.status.offset.closest('.hb-statusbar');
    if (bar === null) {
      return;
    }
    const children = [...bar.children];
    const isSeparator = (node) => node.classList.contains('hb-status-sep');
    const isBoundary = (node) => isSeparator(node) || node.classList.contains('hb-status-grow');
    const itemBeside = (from, step) => {
      for (let index = from; index >= 0 && index < children.length; index += step) {
        if (isBoundary(children[index])) {
          return false;
        }
        if (!children[index].hidden) {
          return true;
        }
      }
      return false;
    };
    for (const [index, child] of children.entries()) {
      if (isSeparator(child)) {
        hideStatusNode(child, !(itemBeside(index - 1, -1) && itemBeside(index + 1, 1)));
      }
    }
  }

  /** Surface a failure to the user without losing its classification. */
  reportError(error) {
    if (error instanceof DispatchError) {
      this.#toasts.show('error', error.kind, error.message);
      return;
    }
    this.#toasts.show('error', 'unexpected', String(error && error.message ? error.message : error));
  }
}
