/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Zachary Flint
   This file is part of Intellicrack. See LICENSE for details.

   One editor per ValueKind, and a form assembled from the catalogue rather than
   written per operation. That is what makes the coverage claim hold: an
   operation added to the Rust crate gets a working form the moment the catalogue
   sees it, with no code here to update.

   Two rules the engine imposes and this file obeys. Every value in a transform's
   params mapping is raw bytes, including the ones that read as words, so the AES
   padding select emits the literal ASCII bytes of pkcs7 rather than the string
   pkcs7. And the enumerated fields take their options from live calls -
   list_encodings, list_transforms, list_templates - so the options cannot drift
   from what the engine will actually accept. */

import { callOp, fromHex, readWindow, toHex } from './api.js';


const HEX_RADIX = 16;
const KIBIBYTE = 1024;
const SIZE_UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
const IMPORT_CAP = 1048576;
const DEFAULT_BLOCK_SIZE = 4096;
const DEFAULT_MAX_RESULTS = 4096;
const DEFAULT_MIN_LENGTH = 5;
const DEFAULT_NUMERIC_WIDTH = 4;
const DEFAULT_CHUNK_HINT = 65536;
const DEFAULT_BUDGET_HINT = 268435456;
const DEFAULT_SNAPSHOT_SIZE = 65536;
const DEFAULT_LENGTH = 16;
const DEFAULT_COLOR = '#6d28d9';
const ASCII_PRINT_LOW = 0x20;
const ASCII_PRINT_HIGH = 0x7e;
const CRC32_POLY = 0x04c11db7;
const CRC32_INIT = 0xffffffff;
const CRC32_WIDTH = 32;

const CARET_PARAMETERS = new Set(['offset', 'src_offset', 'dst_offset', 'offset_a', 'offset_b', 'file_offset', 'start', 'address']);
const SELECTION_LENGTH_PARAMETERS = new Set(['length', 'len_a', 'len_b']);
const SPAN_PARAMETERS = new Set(['byte_range']);

const ENCODING_PARAMETER = 'encoding';
const ALGORITHM_PARAMETER = 'algorithm';
const TEMPLATE_OPERATIONS = new Set(['apply_template', 'export_template_json', 'remove_template']);
const TRANSFORM_OPERATION = 'transform_data';
const TRANSFORM_PARAMS = 'params';
const CUSTOM_CRC_OPERATION = 'compute_hash_custom_crc';

const DEFAULT_OVERRIDES = new Map([
  ['block_size', DEFAULT_BLOCK_SIZE],
  ['max_results', DEFAULT_MAX_RESULTS],
  ['min_length', DEFAULT_MIN_LENGTH],
  ['include_ascii', true],
  ['include_utf16', true],
  ['case_sensitive', true],
  ['alignment', 1],
  ['bit_index', 0],
  ['tolerance', 0],
  ['search_numeric.size', DEFAULT_NUMERIC_WIDTH],
  ['search_numeric_float.size', DEFAULT_NUMERIC_WIDTH],
  ['search_numeric_range.size', DEFAULT_NUMERIC_WIDTH],
  ['from_process_memory.size', DEFAULT_SNAPSHOT_SIZE],
  ['set_chunk_size_hint.size', DEFAULT_CHUNK_HINT],
  ['set_memory_budget_hint.budget', DEFAULT_BUDGET_HINT],
  ['compute_hash_custom_crc.poly', CRC32_POLY],
  ['compute_hash_custom_crc.init', CRC32_INIT],
  ['compute_hash_custom_crc.width', CRC32_WIDTH],
  ['compute_hash_custom_crc.xorout', CRC32_INIT],
  ['compute_hash_custom_crc.reflect', [true, true]],
]);

/** Raised when a control holds something the engine cannot be sent. */
export class FormError extends Error {
  constructor(message, parameter) {
    super(message);
    this.name = 'FormError';
    this.parameter = parameter;
  }
}

/* ------------------------------------------------------------- primitives */

/**
 * Create an element, optionally with a class and text content.
 *
 * @param {string} tag Tag name.
 * @param {string} [className] Class attribute.
 * @param {string} [text] Text content.
 * @returns {HTMLElement} The new element.
 */
export function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== undefined) {
    node.textContent = text;
  }
  return node;
}

/**
 * Uppercase hexadecimal, zero padded.
 *
 * @param {number} value Value to render.
 * @param {number} [digits] Minimum digit count.
 * @returns {string} The rendered value.
 */
export function hexOf(value, digits = 0) {
  return Math.trunc(value).toString(HEX_RADIX).toUpperCase().padStart(digits, '0');
}

/**
 * A byte count in the largest unit that keeps it readable.
 *
 * @param {number} bytes Count of bytes.
 * @returns {string} The rendered size.
 */
export function humanSize(bytes) {
  let value = bytes;
  let unit = 0;
  while (value >= KIBIBYTE && unit < SIZE_UNITS.length - 1) {
    value /= KIBIBYTE;
    unit += 1;
  }
  return unit === 0 ? `${bytes} B` : `${value.toFixed(value < 10 ? 2 : 1)} ${SIZE_UNITS[unit]}`;
}

/**
 * The printable character for a byte, or a placeholder.
 *
 * @param {number} byte Byte value.
 * @returns {string} A single character.
 */
export function asciiFor(byte) {
  return byte >= ASCII_PRINT_LOW && byte <= ASCII_PRINT_HIGH ? String.fromCharCode(byte) : '.';
}

/**
 * Hexadecimal for the UTF-8 encoding of a string.
 *
 * @param {string} text Text to encode.
 * @returns {string} Hexadecimal bytes.
 */
export function asciiToHex(text) {
  return toHex(new TextEncoder().encode(text));
}

/**
 * The text a hexadecimal byte string decodes to, with unprintables replaced.
 *
 * @param {string} hexText Hexadecimal bytes.
 * @returns {string} Readable rendering of the bytes.
 */
export function hexToAscii(hexText) {
  return [...fromHex(hexText)].map(asciiFor).join('');
}

function parseInteger(text, name) {
  const trimmed = String(text).trim().replace(/[\s_]/g, '');
  if (trimmed === '') {
    throw new FormError(`${name} is required`, name);
  }
  const negative = trimmed.startsWith('-');
  const body = negative ? trimmed.slice(1) : trimmed;
  let value;
  if (/^0x[0-9a-f]+$/i.test(body)) {
    value = Number.parseInt(body.slice(2), HEX_RADIX);
  } else if (/^0b[01]+$/i.test(body)) {
    value = Number.parseInt(body.slice(2), 2);
  } else if (/^\d+$/.test(body)) {
    value = Number.parseInt(body, 10);
  } else {
    throw new FormError(`${name}: "${text}" is not a decimal, 0x or 0b integer`, name);
  }
  if (!Number.isSafeInteger(value)) {
    throw new FormError(`${name}: ${text} is outside the range JavaScript can carry exactly`, name);
  }
  return negative ? -value : value;
}

function normaliseHex(text, name) {
  const compact = String(text).replace(/0x/gi, '').replace(/[\s_,:;-]/g, '');
  if (compact === '') {
    return '';
  }
  if (!/^[0-9a-f]+$/i.test(compact)) {
    throw new FormError(`${name}: "${text}" contains characters that are not hexadecimal digits`, name);
  }
  if (compact.length % 2 !== 0) {
    throw new FormError(`${name}: hexadecimal needs an even number of digits, got ${compact.length}`, name);
  }
  return compact.toLowerCase();
}

function button(label, title, onClick) {
  const node = element('button', 'hb-btn is-sm is-ghost', label);
  node.type = 'button';
  if (title) {
    node.title = title;
  }
  node.addEventListener('click', onClick);
  return node;
}

function textInput(value, mono = true) {
  const input = document.createElement('input');
  input.type = 'text';
  input.className = mono ? 'hb-input is-mono' : 'hb-input';
  input.spellcheck = false;
  input.autocomplete = 'off';
  input.value = value;
  return input;
}

function selectInput(options, value) {
  const select = document.createElement('select');
  select.className = 'hb-select';
  for (const option of options) {
    const node = document.createElement('option');
    node.value = option.value;
    node.textContent = option.label;
    if (option.title) {
      node.title = option.title;
    }
    select.appendChild(node);
  }
  if (value !== undefined && options.some((option) => option.value === value)) {
    select.value = value;
  }
  return select;
}

function checkbox(label, checked) {
  const wrapper = element('label', checked ? 'hb-check is-checked' : 'hb-check');
  const box = document.createElement('input');
  box.type = 'checkbox';
  box.className = 'hb-check-box';
  box.checked = checked;
  box.addEventListener('change', () => wrapper.classList.toggle('is-checked', box.checked));
  wrapper.append(box, element('span', undefined, label));
  return { wrapper, box };
}

/* ------------------------------------------------------------ suggestions */

let encodingsPromise = null;
let transformsPromise = null;
let templatesPromise = null;

/** Forget the cached option lists so the next form re-reads them from the engine. */
export function clearSuggestionCache() {
  encodingsPromise = null;
  transformsPromise = null;
  templatesPromise = null;
}

function listEncodings() {
  encodingsPromise ??= callOp('list_encodings').then((result) => result.value);
  return encodingsPromise;
}

function listTransforms() {
  transformsPromise ??= callOp('list_transforms').then((result) => result.value);
  return transformsPromise;
}

function listTemplates(handle) {
  if (!handle) {
    return Promise.resolve([]);
  }
  templatesPromise ??= callOp('list_templates', { handle }).then((result) => result.value);
  return templatesPromise;
}

/**
 * Fetch every option list a form for this operation will need.
 *
 * Callers that show a modal await this first so the selects are already
 * populated when the dialog appears, rather than filling in underneath the
 * pointer.
 *
 * @param {object} operation Catalogue entry.
 * @param {object} context Current handle, caret, selection and open documents.
 * @returns {Promise<void>} Resolves once every list this form needs has arrived.
 */
export function primeSuggestions(operation, context) {
  const wanted = [];
  for (const parameter of operation.parameters) {
    if (parameter.name === ENCODING_PARAMETER) {
      wanted.push(listEncodings());
    }
    if (operation.name === TRANSFORM_OPERATION) {
      wanted.push(listTransforms());
    }
    if (TEMPLATE_OPERATIONS.has(operation.name) && parameter.name === 'name') {
      wanted.push(listTemplates(context.handle));
    }
  }
  return Promise.all(wanted).then(() => undefined);
}

function fillSelectLater(select, load, chosen) {
  select.disabled = true;
  select.replaceChildren(new Option('loading…', ''));
  load()
    .then((options) => {
      select.replaceChildren();
      for (const option of options) {
        const node = document.createElement('option');
        node.value = option.value;
        node.textContent = option.label;
        if (option.title) {
          node.title = option.title;
        }
        select.appendChild(node);
      }
      if (options.length === 0) {
        select.appendChild(new Option('no options available', ''));
      } else {
        select.value = options.some((option) => option.value === chosen) ? chosen : options[0].value;
        select.disabled = false;
      }
      select.dispatchEvent(new Event('change'));
    })
    .catch((error) => {
      select.replaceChildren(new Option(`unavailable: ${error.message}`, ''));
    });
}

/* ---------------------------------------------------------------- editors */

function defaultFor(operation, parameter, context) {
  const supplied = context.initial?.[parameter.name];
  if (supplied !== undefined) {
    return supplied;
  }
  const scoped = DEFAULT_OVERRIDES.get(`${operation.name}.${parameter.name}`);
  if (scoped !== undefined) {
    return scoped;
  }
  const named = DEFAULT_OVERRIDES.get(parameter.name);
  if (named !== undefined) {
    return named;
  }
  if (CARET_PARAMETERS.has(parameter.name) && parameter.kind === 'int') {
    if (context.selectionStart !== null && context.selectionStart !== undefined) {
      return context.selectionStart;
    }
    return context.caret ?? 0;
  }
  if (SELECTION_LENGTH_PARAMETERS.has(parameter.name) && parameter.kind === 'int') {
    return context.selection > 0 ? context.selection : DEFAULT_LENGTH;
  }
  if (SPAN_PARAMETERS.has(parameter.name) && parameter.kind === 'int_pair') {
    if (context.selectionStart !== null && context.selectionStart !== undefined) {
      return [context.selectionStart, context.selectionEnd];
    }
    return [0, context.length ?? 0];
  }
  switch (parameter.kind) {
    case 'int':
      return 0;
    case 'float':
      return 0;
    case 'bool':
      return false;
    case 'int_pair':
      return [0, 0];
    case 'bool_pair':
      return [false, false];
    case 'bookmark':
      return {};
    default:
      return '';
  }
}

function intEditor(operation, parameter, context, initial) {
  const row = element('div', 'hb-field-row');
  const input = textInput(String(initial));
  const echo = element('span', 'hb-dim hb-mono hb-nowrap');
  const refresh = () => {
    try {
      const value = parseInteger(input.value, parameter.name);
      echo.textContent = value < 0 ? String(value) : `0x${hexOf(value)}`;
    } catch {
      echo.textContent = '—';
    }
  };
  input.addEventListener('input', refresh);
  refresh();
  row.append(input, echo);

  if (CARET_PARAMETERS.has(parameter.name)) {
    row.appendChild(button('caret', 'Use the caret offset', () => {
      input.value = String(context.caret ?? 0);
      refresh();
    }));
  }
  if (SELECTION_LENGTH_PARAMETERS.has(parameter.name)) {
    row.appendChild(button('selection', 'Use the selection length', () => {
      input.value = String(context.selection ?? 0);
      refresh();
    }));
  }
  if (parameter.name === 'end') {
    row.appendChild(button('selection end', 'Use the end of the selection', () => {
      input.value = String((context.caret ?? 0) + (context.selection ?? 0));
      refresh();
    }));
  }
  if (operation.name === CUSTOM_CRC_OPERATION && parameter.name === 'width') {
    const widths = (context.reference?.custom_crc_widths ?? [8, 16, 32, 64]).map((width) => ({ value: String(width), label: `${width} bit` }));
    const select = selectInput(widths, String(initial));
    select.addEventListener('change', () => {
      input.value = select.value;
      refresh();
    });
    row.appendChild(select);
  }
  return { node: row, read: () => parseInteger(input.value, parameter.name), focus: () => input.focus() };
}

function floatEditor(parameter, initial) {
  const input = textInput(String(initial));
  return {
    node: input,
    read: () => {
      const value = Number.parseFloat(input.value);
      if (!Number.isFinite(value)) {
        throw new FormError(`${parameter.name}: "${input.value}" is not a finite number`, parameter.name);
      }
      return value;
    },
    focus: () => input.focus(),
  };
}

function boolEditor(parameter, initial) {
  const { wrapper, box } = checkbox(parameter.name, Boolean(initial));
  return { node: wrapper, read: () => box.checked, focus: () => box.focus() };
}

function enumeratedTextEditor(operation, parameter, context, initial) {
  const select = document.createElement('select');
  select.className = 'hb-select';
  if (parameter.name === ENCODING_PARAMETER) {
    fillSelectLater(select, () => listEncodings().then((rows) => rows.map(([value, label]) => ({ value, label: `${value} — ${label}` }))), initial || 'utf-8');
  } else if (parameter.name === ALGORITHM_PARAMETER) {
    const algorithms = context.reference?.hash_algorithms ?? [];
    fillSelectLater(select, () => Promise.resolve(algorithms.map((name) => ({ value: name, label: name }))), initial || 'sha256');
  } else if (operation.name === TRANSFORM_OPERATION) {
    fillSelectLater(
      select,
      () => listTransforms().then((rows) => rows.map(([value, category, description]) => ({ value, label: `${value} (${category})`, title: description }))),
      initial || 'xor_single',
    );
  } else {
    fillSelectLater(
      select,
      () => listTemplates(context.handle).then((rows) => rows.map(([value, description]) => ({ value, label: value, title: description }))),
      initial,
    );
  }
  return {
    node: select,
    read: () => {
      if (select.value === '') {
        throw new FormError(`${parameter.name}: no option is selected`, parameter.name);
      }
      return select.value;
    },
    focus: () => select.focus(),
    watch: (handler) => select.addEventListener('change', () => handler(select.value)),
    current: () => select.value,
  };
}

function isEnumerated(operation, parameter) {
  if (parameter.kind !== 'text') {
    return false;
  }
  if (parameter.name === ENCODING_PARAMETER || parameter.name === ALGORITHM_PARAMETER) {
    return true;
  }
  if (operation.name === TRANSFORM_OPERATION && parameter.name === 'name') {
    return true;
  }
  return TEMPLATE_OPERATIONS.has(operation.name) && parameter.name === 'name';
}

function textEditor(operation, parameter, context, initial) {
  if (isEnumerated(operation, parameter)) {
    return enumeratedTextEditor(operation, parameter, context, initial);
  }
  const multiline = parameter.name === 'json_str';
  const input = multiline ? document.createElement('textarea') : textInput(String(initial), false);
  if (multiline) {
    input.className = 'hb-textarea is-mono';
    input.spellcheck = false;
    input.value = String(initial);
  }
  if (parameter.name === 'path' || parameter.name.endsWith('_path')) {
    input.placeholder = 'D:\\samples\\target.exe';
    input.className = 'hb-input is-mono';
  }
  return { node: input, read: () => input.value, focus: () => input.focus() };
}

function bytesEditor(parameter, context, initial) {
  const stack = element('div', 'hb-stack');
  const area = document.createElement('textarea');
  area.className = 'hb-textarea is-mono';
  area.spellcheck = false;
  area.value = String(initial ?? '');
  let canonicalHex;
  try {
    canonicalHex = normaliseHex(area.value, parameter.name);
  } catch {
    canonicalHex = '';
  }

  const controls = element('div', 'hb-field-row');
  const mode = selectInput([{ value: 'hex', label: 'hexadecimal' }, { value: 'ascii', label: 'text (utf-8)' }], 'hex');
  const count = element('span', 'hb-dim hb-mono hb-nowrap');

  const refresh = () => {
    try {
      const length = mode.value === 'hex' ? normaliseHex(area.value, parameter.name).length / 2 : new TextEncoder().encode(area.value).length;
      count.textContent = `${length} byte${length === 1 ? '' : 's'}`;
    } catch (error) {
      count.textContent = error instanceof FormError ? 'invalid' : '—';
    }
  };
  area.addEventListener('input', () => {
    try {
      canonicalHex = mode.value === 'hex' ? normaliseHex(area.value, parameter.name) : asciiToHex(area.value);
    } catch {
      /* keep the last valid canonical value until the field parses again */
    }
    refresh();
  });

  mode.addEventListener('change', () => {
    area.value = mode.value === 'ascii' ? hexToAscii(canonicalHex) : canonicalHex;
    refresh();
  });
  controls.append(mode, count);

  if (context.handle) {
    controls.appendChild(button('from selection', 'Read the selected bytes out of the active document', () => {
      const length = context.selection ?? 0;
      if (length <= 0) {
        count.textContent = 'nothing selected';
        return;
      }
      const start = context.selectionStart !== null && context.selectionStart !== undefined ? context.selectionStart : (context.caret ?? 0);
      readWindow(context.handle, start, Math.min(length, IMPORT_CAP))
        .then((window) => {
          mode.value = 'hex';
          canonicalHex = toHex(window.bytes).toLowerCase();
          area.value = canonicalHex;
          refresh();
        })
        .catch((error) => {
          count.textContent = error.message;
        });
    }));
  }

  const sources = (context.documents ?? []).filter((info) => info.length > 0);
  if (sources.length > 0) {
    const picker = selectInput(
      sources.map((info) => ({ value: info.handle, label: `${info.label} (${humanSize(info.length)})` })),
      context.handle ?? sources[0].handle,
    );
    controls.append(picker, button('load document', 'Read this document\u2019s bytes into the field', () => {
      const info = sources.find((entry) => entry.handle === picker.value);
      if (!info) {
        return;
      }
      const span = Math.min(info.length, IMPORT_CAP);
      readWindow(info.handle, 0, span)
        .then((window) => {
          mode.value = 'hex';
          canonicalHex = toHex(window.bytes).toLowerCase();
          area.value = canonicalHex;
          refresh();
          count.textContent = span < info.length
            ? `${span} of ${info.length} bytes — capped at ${humanSize(IMPORT_CAP)}`
            : `${span} byte${span === 1 ? '' : 's'}`;
        })
        .catch((error) => {
          count.textContent = error.message;
        });
    }));
  }

  refresh();
  stack.append(area, controls);
  return {
    node: stack,
    read: () => (mode.value === 'hex' ? normaliseHex(area.value, parameter.name) : canonicalHex),
    focus: () => area.focus(),
  };
}

function intPairEditor(parameter, context, initial) {
  const row = element('div', 'hb-field-row');
  const first = textInput(String(initial[0]));
  const second = textInput(String(initial[1]));
  row.append(first, element('span', 'hb-dim', '…'), second);
  if (parameter.name === 'byte_range') {
    row.appendChild(button('selection', 'Use the selected range', () => {
      if (context.selectionStart !== null && context.selectionStart !== undefined) {
        first.value = String(context.selectionStart);
        second.value = String(context.selectionEnd);
        return;
      }
      const start = context.caret ?? 0;
      first.value = String(start);
      second.value = String(start + (context.selection ?? 0));
    }));
  }
  return {
    node: row,
    read: () => [parseInteger(first.value, `${parameter.name}[0]`), parseInteger(second.value, `${parameter.name}[1]`)],
    focus: () => first.focus(),
  };
}

function boolPairEditor(parameter, initial) {
  const row = element('div', 'hb-field-row');
  const input = checkbox('input', Boolean(initial[0]));
  const output = checkbox('output', Boolean(initial[1]));
  row.append(input.wrapper, output.wrapper);
  return { node: row, read: () => [input.box.checked, output.box.checked], focus: () => input.box.focus() };
}

function bookmarkEditor(parameter, context, initial) {
  const grid = element('div', 'hb-stack');
  const offset = textInput(String(initial.offset ?? context.caret ?? 0));
  const length = textInput(String(initial.length ?? (context.selection > 0 ? context.selection : 1)));
  const label = textInput(String(initial.label ?? ''), false);
  const colour = document.createElement('input');
  colour.type = 'color';
  colour.className = 'hb-input';
  colour.value = initial.color ?? DEFAULT_COLOR;

  const line = (name, control, extra) => {
    const row = element('div', 'hb-field-row');
    row.appendChild(element('span', 'hb-arg-name hb-nowrap', name));
    row.appendChild(control);
    if (extra) {
      row.appendChild(extra);
    }
    return row;
  };

  grid.append(
    line('offset', offset, button('caret', 'Use the caret offset', () => {
      offset.value = String(context.caret ?? 0);
    })),
    line('length', length, button('selection', 'Use the selection length', () => {
      length.value = String(context.selection > 0 ? context.selection : 1);
    })),
    line('label', label),
    line('color', colour),
  );

  return {
    node: grid,
    read: () => ({
      offset: parseInteger(offset.value, `${parameter.name}.offset`),
      length: parseInteger(length.value, `${parameter.name}.length`),
      label: label.value,
      color: colour.value,
    }),
    focus: () => label.focus(),
  };
}

/* ----------------------------------------------------------- bytes as map */

function transformParameterRow(spec) {
  const row = element('div', 'hb-map-row');
  row.appendChild(element('span', 'hb-arg-name hb-truncate', spec.key));

  let control;
  let read;
  if (spec.choices.length > 0) {
    const select = selectInput(spec.choices.map((choice) => ({ value: choice, label: choice })), spec.choices[0]);
    control = select;
    read = () => asciiToHex(select.value);
  } else {
    const initial = spec.default_hex ?? '';
    const input = textInput(initial);
    input.placeholder = spec.byte_widths.length > 0 ? `${spec.byte_widths.join(' or ')} bytes, hexadecimal` : 'hexadecimal';
    control = input;
    read = () => {
      const value = normaliseHex(input.value, spec.key);
      if (value === '' && spec.required) {
        throw new FormError(`params.${spec.key} is required`, spec.key);
      }
      if (spec.byte_widths.length > 0 && value !== '' && !spec.byte_widths.includes(value.length / 2)) {
        throw new FormError(`params.${spec.key}: expected ${spec.byte_widths.join(' or ')} bytes, got ${value.length / 2}`, spec.key);
      }
      return value;
    };
  }
  row.appendChild(control);

  const include = document.createElement('input');
  include.type = 'checkbox';
  include.className = 'hb-check-box';
  include.checked = spec.required;
  include.disabled = spec.required;
  include.title = spec.required
    ? 'This entry is required'
    : 'Send this optional entry rather than letting the engine apply its own default';
  row.appendChild(include);

  if (!spec.required) {
    const arm = () => {
      include.checked = true;
    };
    control.addEventListener('change', arm);
    control.addEventListener('input', arm);
  }

  return { row, read, include, spec };
}

function bytesMapEditor(operation, parameter, context) {
  const host = element('div', 'hb-map-editor');
  const note = element('div', 'hb-arg-hint');
  let rows = [];
  let custom = [];

  const addCustomRow = (key = '', value = '') => {
    const row = element('div', 'hb-map-row');
    const keyInput = textInput(key, false);
    keyInput.placeholder = 'entry name';
    const valueInput = textInput(value);
    valueInput.placeholder = 'hexadecimal';
    const remove = element('button', 'hb-map-remove', '✕');
    remove.type = 'button';
    const entry = { row, keyInput, valueInput };
    remove.addEventListener('click', () => {
      custom = custom.filter((item) => item !== entry);
      row.remove();
    });
    row.append(keyInput, valueInput, remove);
    custom.push(entry);
    host.insertBefore(row, host.lastElementChild);
  };

  const add = element('button', 'hb-map-add', '+ entry');
  add.type = 'button';
  add.addEventListener('click', () => addCustomRow());

  const rebuild = (transformName) => {
    for (const entry of rows) {
      entry.row.remove();
    }
    rows = [];
    const table = context.reference?.transforms ?? {};
    const specs = table[transformName];
    if (specs === undefined) {
      note.textContent = `${transformName || 'this transform'} has no published parameter table; add entries by hand.`;
    } else if (specs.length === 0) {
      note.textContent = `${transformName} takes no parameters.`;
    } else {
      note.textContent = specs.map((spec) => `${spec.key}: ${spec.note}`).join(' ');
      for (const spec of specs) {
        const entry = transformParameterRow(spec);
        rows.push(entry);
        host.insertBefore(entry.row, add);
      }
    }
  };

  host.appendChild(add);
  if (operation.name !== TRANSFORM_OPERATION) {
    note.textContent = 'Every value is raw bytes, written as hexadecimal.';
  }

  const container = element('div', 'hb-stack');
  container.append(host, note);

  return {
    node: container,
    rebuild,
    read: () => {
      const values = {};
      for (const entry of rows) {
        if (!entry.include.checked) {
          continue;
        }
        const value = entry.read();
        if (value !== '' || entry.spec.required) {
          values[entry.spec.key] = value;
        }
      }
      for (const entry of custom) {
        const key = entry.keyInput.value.trim();
        if (key === '') {
          continue;
        }
        values[key] = normaliseHex(entry.valueInput.value, key);
      }
      return values;
    },
    focus: () => {
      const first = rows[0];
      if (first) {
        first.row.querySelector('input, select')?.focus();
      }
    },
  };
}

/* ------------------------------------------------------------------- form */

function editorFor(operation, parameter, context) {
  const initial = defaultFor(operation, parameter, context);
  switch (parameter.kind) {
    case 'int':
      return intEditor(operation, parameter, context, initial);
    case 'float':
      return floatEditor(parameter, initial);
    case 'bool':
      return boolEditor(parameter, initial);
    case 'text':
      return textEditor(operation, parameter, context, initial);
    case 'bytes':
      return bytesEditor(parameter, context, initial);
    case 'int_pair':
      return intPairEditor(parameter, context, initial);
    case 'bool_pair':
      return boolPairEditor(parameter, initial);
    case 'bytes_map':
      return bytesMapEditor(operation, parameter, context);
    case 'bookmark':
      return bookmarkEditor(parameter, context, initial ?? {});
    default:
      throw new FormError(`${parameter.name} has the unknown kind ${parameter.kind}`, parameter.name);
  }
}

/**
 * Build the argument form for one catalogued operation.
 *
 * The returned `read` throws a {@link FormError} carrying the offending
 * parameter name, and the form marks that field so the message and the control
 * cannot end up describing different things.
 *
 * @param {object} operation Catalogue entry, with its parameter list.
 * @param {object} reference The engine reference tables, or null.
 * @param {object} context Handle, caret offset, selection length and open documents.
 * @returns {{element: HTMLElement, read: () => object, focus: () => void, operation: object}}
 */
export function buildForm(operation, reference, context) {
  const scope = { ...context, reference };
  const root = element('div', 'hb-stack');
  const editors = new Map();
  const wrappers = new Map();

  if (operation.parameters.length === 0) {
    root.appendChild(element('div', 'hb-op-hint', `${operation.name} takes no arguments.`));
  }

  for (const parameter of operation.parameters) {
    const wrapper = element('div', 'hb-arg');
    const label = element('label', 'hb-arg-label');
    label.append(element('span', 'hb-arg-name', parameter.name), element('span', 'hb-arg-type', parameter.annotation));
    const control = element('div', 'hb-arg-control');
    const editor = editorFor(operation, parameter, scope);
    control.appendChild(editor.node);
    wrapper.append(label, control);
    root.appendChild(wrapper);
    editors.set(parameter.name, editor);
    wrappers.set(parameter.name, wrapper);
  }

  if (operation.name === TRANSFORM_OPERATION) {
    const nameEditor = editors.get('name');
    const paramsEditor = editors.get(TRANSFORM_PARAMS);
    if (nameEditor && paramsEditor && typeof nameEditor.watch === 'function') {
      nameEditor.watch((value) => paramsEditor.rebuild(value));
      paramsEditor.rebuild(nameEditor.current());
    }
  }

  const clearErrors = () => {
    for (const wrapper of wrappers.values()) {
      wrapper.classList.remove('is-invalid');
      wrapper.querySelector('.hb-arg-error')?.remove();
    }
  };

  return {
    element: root,
    operation,
    read: () => {
      clearErrors();
      const values = {};
      for (const [name, editor] of editors) {
        try {
          values[name] = editor.read();
        } catch (error) {
          const wrapper = wrappers.get(name);
          if (wrapper) {
            wrapper.classList.add('is-invalid');
            wrapper.appendChild(element('div', 'hb-arg-error', error.message));
          }
          throw error;
        }
      }
      return values;
    },
    focus: () => {
      const first = editors.values().next().value;
      first?.focus();
    },
  };
}

/* ----------------------------------------------------------------- dialog */

/**
 * Show one operation's form in a modal and resolve with its arguments.
 *
 * @param {object} operation Catalogue entry.
 * @param {object} reference The engine reference tables, or null.
 * @param {object} context Handle, caret offset, selection length and open documents.
 * @returns {Promise<object|null>} The argument object, or null when dismissed.
 */
export async function openArgumentDialog(operation, reference, context) {
  await primeSuggestions(operation, context).catch(() => undefined);
  return new Promise((resolve) => {
    const overlay = element('div', 'hbx-overlay');
    const scrim = element('div', 'hb-scrim');
    const dialog = element('div', 'hb-dialog hbx-dialog-wide');

    const header = element('div', 'hb-dialog-header');
    header.appendChild(element('span', 'hb-dialog-title', operation.name));
    if (operation.mutating) {
      header.appendChild(element('span', 'hb-badge is-warning', 'mutates'));
    }
    const close = element('button', 'hb-dialog-close', '✕');
    close.type = 'button';
    header.appendChild(close);

    const body = element('div', 'hb-dialog-body');
    body.appendChild(element('div', 'hb-op-sig', `${operation.receiver} · ${operation.group} · returns ${operation.returns}`));
    const form = buildForm(operation, reference, context);
    body.appendChild(form.element);

    const footer = element('div', 'hb-dialog-footer');
    const cancel = element('button', 'hb-btn is-ghost', 'Cancel');
    cancel.type = 'button';
    const confirm = element('button', 'hb-btn is-primary', operation.mutating ? 'Run (mutates)' : 'Run');
    confirm.type = 'button';
    const problem = element('div', 'hb-arg-error');
    footer.append(problem, element('span', 'hb-grow'), cancel, confirm);

    dialog.append(header, body, footer);
    overlay.append(scrim, dialog);
    document.getElementById('overlays')?.appendChild(overlay);

    const finish = (values) => {
      overlay.remove();
      resolve(values);
    };
    const submit = () => {
      try {
        finish(form.read());
      } catch (error) {
        problem.textContent = error.message;
      }
    };

    scrim.addEventListener('mousedown', () => finish(null));
    cancel.addEventListener('click', () => finish(null));
    close.addEventListener('click', () => finish(null));
    confirm.addEventListener('click', submit);
    overlay.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        finish(null);
      } else if (event.key === 'Enter' && event.ctrlKey) {
        event.preventDefault();
        submit();
      }
    });
    form.focus();
  });
}
