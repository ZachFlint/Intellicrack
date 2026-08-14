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
const JSON_INDENT_LIMIT = 400;
const BYTE_MASK = 0xff;
const KIBIBYTE = 1024;
const SIZE_UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
const ENTROPY_DIGITS = 3;
const PREVIEW_BYTES = 4096;
const CLASSIFICATION_BLOCK = 4096;

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

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== undefined) {
    node.textContent = text;
  }
  return node;
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

/* ------------------------------------------------------------------ toasts */

class ToastStack {
  #host;

  constructor(host) {
    this.#host = host;
  }

  show(kind, title, detail) {
    const toast = element('div', `hb-toast is-${kind}`);
    const glyph = element('span', 'hb-toast-glyph', kind === 'error' ? '!' : kind === 'warning' ? '△' : kind === 'success' ? '✓' : 'i');
    const body = element('div', 'hb-toast-body');
    body.appendChild(element('div', 'hb-toast-title', title));
    if (detail) {
      body.appendChild(element('div', 'hb-toast-detail', detail));
    }
    const close = element('button', 'hb-toast-close', '✕');
    close.type = 'button';
    close.addEventListener('click', () => toast.remove());
    toast.append(glyph, body, close);
    this.#host.appendChild(toast);
    window.setTimeout(() => toast.remove(), TOAST_MS);
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
  ['bookmark', { offset: 0, length: 1, label: '', color: '#4c8dff' }],
]);

/** Cache key for a panel keyed on the caret: the document's handle and generation, not merely the offset. */
export function inspectorCacheKey(doc, offset) {
  return doc ? `${doc.handle}:${doc.generation}:${offset}` : null;
}

function defaultArgument(kind) {
  const value = ARGUMENT_DEFAULTS.get(kind);
  return Array.isArray(value) ? [...value] : (value !== null && typeof value === 'object' ? { ...value } : value);
}

/* ------------------------------------------------------------------ dialog */

class DialogHost {
  #host;
  #overlay = null;

  constructor(host) {
    this.#host = host;
  }

  get isOpen() {
    return this.#overlay !== null;
  }

  close() {
    this.#overlay?.remove();
    this.#overlay = null;
  }

  /** Show a form and resolve with its values, or with null when dismissed. */
  form(spec) {
    return new Promise((resolve) => {
      this.close();
      const overlay = element('div', 'hbx-overlay');
      const scrim = element('div', 'hb-scrim');
      const dialog = element('div', 'hb-dialog');

      const header = element('div', 'hb-dialog-header');
      header.appendChild(element('span', 'hb-dialog-title', spec.title));
      const closeButton = element('button', 'hb-dialog-close', '✕');
      closeButton.type = 'button';
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
    const overlay = element('div', 'hbx-overlay');
    const scrim = element('div', 'hb-scrim');
    const dialog = element('div', 'hb-dialog hbx-dialog-wide');

    const header = element('div', 'hb-dialog-header');
    header.appendChild(element('span', 'hb-dialog-title', title));
    const closeButton = element('button', 'hb-dialog-close', '✕');
    closeButton.type = 'button';
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
  #panels = [];
  #active = '';
  #mounted = new Map();

  constructor(root) {
    this.#root = root;
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
        tab.appendChild(element('span', 'hb-dock-tab-count', String(count)));
      }
      this.#tabs.appendChild(tab);
    }
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
    items: ['file.new', 'file.open', 'file.openBytes', '-', 'file.save', 'file.saveAs', '-', 'file.close', 'file.exit'],
  },
  {
    id: 'edit',
    items: ['edit.undo', 'edit.redo', '-', 'edit.selectAll', 'edit.copyHex', '-', 'edit.fill', 'edit.insert', 'edit.delete', '-', 'edit.toggleInsert'],
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
    items: ['analyze.entropy', 'analyze.byteTypes', 'analyze.classification', 'analyze.digram', '-', 'analyze.strings', 'analyze.hash', '-', 'analyze.pe', 'analyze.inspect'],
  },
  {
    id: 'patch',
    items: ['patch.list', 'patch.exportJson', 'patch.exportIps', '-', 'patch.import', '-', 'patch.repairPe'],
  },
  {
    id: 'tools',
    items: ['tools.palette', 'tools.operation', 'tools.jobs', 'tools.reference'],
  },
  {
    id: 'help',
    items: ['help.keys', 'help.about'],
  },
];

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
];

/**
 * Whether a bound shortcut should run given what currently has focus.
 *
 * `typing` alone still lets any ctrl-combo through, so Ctrl+S/Ctrl+F keep
 * working while a field has focus. But a clipboard combo typed into a field
 * that has its own non-collapsed text selection must defer to the field's
 * native handling instead of preempting it for whatever the hex grid has
 * selected.
 */
export function shouldRunShortcut(combo, context) {
  const { typing, hasTextSelection, gridSelection } = context;
  if (typing && !combo.startsWith('ctrl+')) {
    return false;
  }
  const nativeClipboardCombo = combo === 'ctrl+c' || combo === 'ctrl+x' || combo === 'ctrl+v';
  if (typing && nativeClipboardCombo && hasTextSelection) {
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
  #openMenu = null;
  #listeners = new Map();

  #hits = [];
  #hitIndex = -1;
  #lastSearch = null;
  #entropyTimer = 0;
  #entropy = null;
  #catalog = null;
  #operationIndex = new Map();
  #metrics = { scaled: false, bytesPerPixel: 1 };
  #dockRequest = { right: DEFAULT_DOCK_PX, bottom: DEFAULT_DOCK_PX };
  #workspaceObserver = null;
  #busyCount = 0;
  #panels = new Map();

  constructor(nodes) {
    this.#nodes = nodes;
    this.#toasts = new ToastStack(nodes.toasts);
    this.#dialogs = new DialogHost(nodes.overlays);
    this.#dockRight = new Dock(nodes.dockRight);
    this.#dockBottom = new Dock(nodes.dockBottom);
    this.#grid = new HexGrid(nodes.editorHost, {
      onSelect: (selection) => this.#onSelection(selection),
      onCaret: (caret) => this.#onCaret(caret),
      onMetrics: (metrics) => this.#onMetrics(metrics),
      onDocument: (info) => this.#onDocumentChanged(info),
      onError: (error) => this.reportError(error),
    });
    this.#defineCommands();
    this.#buildMenus();
    this.#bindToolbar();
    this.#bindTabs();
    this.#bindSplitters();
    this.#bindKeyboard();
    this.#registerBuiltinPanels();
    this.#applyDockLayout();
    this.#renderStatus();
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
        const reload = element('button', 'hb-panel-action', '⟳');
        reload.type = 'button';
        reload.title = 'Refresh';
        reload.addEventListener('click', refresh);
        actions.appendChild(reload);
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
    this.#define('file.save', 'Save', 'Ctrl+S', () => this.save(false), hasDocument);
    this.#define('file.saveAs', 'Save as…', 'Ctrl+Shift+S', () => this.save(true), hasDocument);
    this.#define('file.close', 'Close document', 'Ctrl+W', () => this.closeActive(), hasDocument);
    this.#define('file.exit', 'Exit', '', () => this.exit());

    this.#define('edit.undo', 'Undo', 'Ctrl+Z', () => this.runOnDocument('undo', {}), () => Boolean(this.#active?.can_undo));
    this.#define('edit.redo', 'Redo', 'Ctrl+Y', () => this.runOnDocument('redo', {}), () => Boolean(this.#active?.can_redo));
    this.#define('edit.selectAll', 'Select all', 'Ctrl+A', () => this.#grid.select(0, this.#active?.length ?? 0), hasDocument);
    this.#define('edit.copyHex', 'Copy selection as hex', 'Ctrl+C', () => this.copySelection(), hasSelection);
    this.#define('edit.fill', 'Fill selection…', '', () => this.fillSelection(), hasSelection);
    this.#define('edit.insert', 'Insert bytes…', '', () => this.insertBytes(), hasDocument);
    this.#define('edit.delete', 'Delete selection', 'Del', () => this.deleteSelection(), hasSelection);
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

    this.#define('analyze.entropy', 'Shannon entropy', '', () => this.showResult('entropy', {}), hasDocument);
    this.#define('analyze.byteTypes', 'Byte type distribution', '', () => this.showResult('byte_type_distribution', {}), hasDocument);
    this.#define('analyze.classification', 'Content classification', '', () => this.showResult('content_classification', { block_size: CLASSIFICATION_BLOCK }), hasDocument);
    this.#define('analyze.digram', 'Digram matrix', '', () => this.showResult('digram_matrix', {}), hasDocument);
    this.#define('analyze.strings', 'Extract strings', '', () => this.extractStrings(), hasDocument);
    this.#define('analyze.hash', 'Compute hash…', '', () => this.computeHash(), hasDocument);
    this.#define('analyze.pe', 'Verify PE checksum', '', () => this.showResult('verify_pe_checksum', {}), hasDocument);
    this.#define('analyze.inspect', 'Inspect at caret', '', () => this.showResult('inspect_at', { offset: this.#grid.caret.offset }), hasDocument);

    this.#define('patch.list', 'List patches', '', () => this.showResult('get_patches', {}), hasDocument);
    this.#define('patch.exportJson', 'Export patches as JSON', '', () => this.showResult('export_patches_json', {}), hasDocument);
    this.#define('patch.exportIps', 'Export patches as IPS', '', () => this.showResult('export_patches_ips', {}), hasDocument);
    this.#define('patch.import', 'Import patches…', '', () => this.openOperation('import_patches_ips'), hasDocument);
    this.#define('patch.repairPe', 'Repair PE checksum', '', () => this.runOnDocument('repair_pe_checksum', {}), hasDocument);

    this.#define('tools.palette', 'Command palette', 'Ctrl+Shift+P', () => this.#palette?.open(''));
    this.#define('tools.operation', 'Operation browser…', '', () => this.openOperation(''));
    this.#define('tools.jobs', 'Activity log', '', () => {
      this.#dockBottom.setVisible(true);
      this.#dockBottom.activate('shell.activity');
      this.#applyDockLayout();
    });
    this.#define('tools.reference', 'Engine reference', '', () => this.showReference());

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
    for (const menu of MENUS) {
      const holder = this.#nodes.menubar.querySelector(`[data-menu="${menu.id}"]`);
      if (!holder) {
        continue;
      }
      const button = holder.querySelector('.hb-menu-item');
      const popup = element('div', 'hb-menu-popup');
      popup.hidden = true;
      holder.appendChild(popup);
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
    document.addEventListener('click', () => this.#closeMenu());
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        this.#closeMenu();
      }
    });
  }

  #toggleMenu(id, holder, button, popup, force = false) {
    const alreadyOpen = this.#openMenu !== null && this.#openMenu.id === id;
    this.#closeMenu();
    if (alreadyOpen && !force) {
      return;
    }
    const spec = MENUS.find((menu) => menu.id === id);
    popup.replaceChildren();
    for (const entry of spec.items) {
      if (entry === '-') {
        popup.appendChild(element('div', 'hb-menu-sep'));
        continue;
      }
      const command = this.#commands.get(entry);
      if (!command) {
        continue;
      }
      const enabled = command.enabled();
      const item = element('button', enabled ? 'hb-menu-entry' : 'hb-menu-entry is-disabled');
      item.type = 'button';
      item.appendChild(element('span', 'hb-menu-entry-label', command.label));
      item.appendChild(element('span', 'hb-menu-shortcut', command.shortcut));
      if (enabled) {
        item.addEventListener('click', (event) => {
          event.stopPropagation();
          this.#closeMenu();
          this.run(command.id);
        });
      }
      popup.appendChild(item);
    }
    popup.hidden = false;
    button.classList.add('is-open');
    this.#openMenu = { id, button, popup };
  }

  #closeMenu() {
    if (this.#openMenu === null) {
      return;
    }
    this.#openMenu.popup.hidden = true;
    this.#openMenu.button.classList.remove('is-open');
    this.#openMenu = null;
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
    const jump = this.#nodes.toolbar.querySelector('#toolbar-goto');
    jump.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter') {
        return;
      }
      event.preventDefault();
      const offset = parseOffset(jump.value);
      if (offset === null) {
        this.#toasts.show('warning', 'Not an offset', `"${jump.value}" is not a hexadecimal offset.`);
        return;
      }
      this.#grid.seek(offset);
      this.#grid.focus();
    });
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
  }

  #renderTabs() {
    this.#nodes.tabstrip.replaceChildren();
    for (const info of this.#documents) {
      const active = this.#active !== null && info.handle === this.#active.handle;
      const tab = element('div', active ? 'hb-tab is-active' : 'hb-tab');
      tab.dataset.handle = info.handle;
      tab.title = info.path ?? `${info.origin} · ${humanSize(info.length)}`;
      tab.appendChild(element('span', 'hb-tab-icon', info.path ? '▤' : '◇'));
      tab.appendChild(element('span', 'hb-tab-title', info.label));
      if (info.modified) {
        tab.appendChild(element('span', 'hb-tab-dirty'));
      }
      const close = element('button', 'hb-tab-close', '✕');
      close.type = 'button';
      close.dataset.handle = info.handle;
      close.title = 'Close';
      tab.appendChild(close);
      this.#nodes.tabstrip.appendChild(tab);
    }
    if (this.#documents.length === 0) {
      this.#nodes.tabstrip.appendChild(element('span', 'hb-tabstrip-overflow', 'no documents open'));
    }
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
    this.#workspaceObserver = new ResizeObserver(() => this.#clampDocks());
    this.#workspaceObserver.observe(this.#nodes.workspace);
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
      write('--hb-dock-right-w', this.#fitDock(this.#dockRequest.right, rect.width));
    }
    if (rect.height > 0) {
      write('--hb-dock-bottom-h', this.#fitDock(this.#dockRequest.bottom, rect.height));
    }
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
    this.#grid.setDocument(info);
    if (changed) {
      this.clearHits();
      this.#entropy = null;
    }
    this.#renderTabs();
    this.#scheduleEntropy();
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
      file.arrayBuffer()
        .then((buffer) => callOp('open_bytes', { arguments: { data: toHex(new Uint8Array(buffer)) } }))
        .then((result) => this.reload(result.created_handle))
        .then(() => this.#toasts.show('success', 'Opened', `${file.name} (${humanSize(file.size)})`))
        .catch((error) => this.reportError(error));
    });
    picker.click();
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
          ],
        },
        { name: 'needle', label: 'pattern', mono: true, value: this.#lastSearch?.needle ?? '' },
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
    const values = await this.#dialogs.form({
      title: 'Go to offset',
      confirmLabel: 'Go',
      note: 'Offsets are hexadecimal.',
      fields: [{ name: 'offset', label: 'offset', mono: true, value: hex(this.#grid.caret.offset, 8) }],
    });
    if (values === null) {
      return;
    }
    const offset = parseOffset(values.offset);
    if (offset === null) {
      this.#toasts.show('warning', 'Not an offset', `"${values.offset}" is not a hexadecimal offset.`);
      return;
    }
    this.#grid.seek(offset);
    this.#grid.focus();
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
    rows.push(
      ['arrows', 'Move the caret'],
      ['shift+arrows', 'Extend the selection'],
      ['page up / page down', 'Move a screen'],
      ['home / end', 'Start and end of the row'],
      ['ctrl+home / ctrl+end', 'Start and end of the document'],
      ['tab', 'Move between the hex and ASCII panes'],
      ['ins', 'Insert or overwrite'],
      ['backspace / delete', 'Remove bytes'],
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

  #setBusy(busy) {
    this.#busyCount += busy ? 1 : -1;
    this.#busyCount = Math.max(0, this.#busyCount);
    this.#renderStatus();
  }

  #renderStatus() {
    const nodes = this.#nodes.status;
    const caret = this.#grid.caret;
    const selection = this.#grid.selection;

    nodes.offset.textContent = this.#active ? `0x${hex(caret.offset, 8)} · ${caret.offset}` : '—';
    nodes.pane.textContent = `${caret.pane}${caret.pane === 'hex' ? (caret.nibble === 0 ? ' hi' : ' lo') : ''}`;
    nodes.selection.textContent = selection === null
      ? 'none'
      : `${selection.length} B @ 0x${hex(selection.start, 8)}`;
    nodes.size.textContent = this.#active ? `${humanSize(this.#active.length)} · ${this.#active.length}` : '—';
    nodes.mode.textContent = this.#grid.insertMode ? 'INS' : 'OVR';
    nodes.entropy.textContent = this.#entropy === null ? '—' : this.#entropy.toFixed(ENTROPY_DIGITS);
    nodes.hits.textContent = this.#hits.length === 0
      ? '—'
      : `${this.#hitIndex + 1}/${this.#hits.length}`;

    const modified = Boolean(this.#active?.modified);
    nodes.modifiedItem.classList.toggle('is-warning', modified);
    nodes.modified.textContent = modified ? 'modified' : 'clean';

    if (this.#metrics.scaled) {
      nodes.scaleItem.hidden = false;
      nodes.scale.textContent = `1 px ≈ ${perPixelSize(this.#metrics.bytesPerPixel)}`;
    } else {
      nodes.scaleItem.hidden = true;
    }

    nodes.dot.className = this.#busyCount > 0 ? 'hb-status-dot is-busy' : 'hb-status-dot is-ready';
    nodes.state.textContent = this.#busyCount > 0 ? 'working' : 'ready';

    this.#syncToolbar();
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
