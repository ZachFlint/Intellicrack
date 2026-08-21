/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Zachary Flint
   This file is part of Intellicrack. See LICENSE for details.

   The docked panels, and the wiring that gives every one of them the same
   picture of the session.

   A panel here never talks to the shell's internals; it is handed a context
   object built in one place, so the caret a panel reads, the handle it runs
   against and the document its result is attributed to cannot disagree. The
   shell's own Inspector and Activity panels are replaced rather than duplicated
   by re-registering their identifiers, which is what registerPanel already does
   for a repeated id. */

import { callOp, getReference, isTaggedBytes, listJobs, readWindow, taggedBytes, toHex } from './api.js';
import { byteTypeChart, classificationChart, DIFF_HIGHLIGHT_TOKENS, diffTrackChart, digramChart, entropyStripChart, tokenHex } from './charts.js';
import { createOperationConsole } from './console.js';
import { decorativeGlyph, iconButton, nextId, trapFocus } from './dom.js';
import { clearSuggestionCache, element, hexOf, humanSize, openArgumentDialog } from './forms.js';
import { actionButton, banner, cell, emptyState, errorKindLabel, fetchRaw, renderError, renderResult, table } from './renderers.js';


const INSPECT_DEBOUNCE_MS = 90;
const OFFSET_DIGITS = 8;
const DIFF_CAP = 1048576;
const DEFAULT_MIN_STRING = 5;
const DEFAULT_STRING_LIMIT = 2048;
const RESULTS_LIMIT = 200;
const SUMMARY_LIMIT = 56;
const ENTROPY_STRIP_BLOCK = 256;
const CLASSIFICATION_STRIP_BLOCK = 4096;
const DIFF_BYTE_SNIPPET_CAP = 8;
const DIFF_KIND_LABEL = new Map([
  ['inserted_b', 'added'],
  ['inserted_a', 'removed'],
  ['modified', 'modified'],
]);
const DIFF_KIND_TONE = new Map([
  ['inserted_b', 'is-success'],
  ['inserted_a', 'is-error'],
  ['modified', 'is-warning'],
]);
const DIFF_KIND_CLASS = new Map([
  ['inserted_b', 'is-diff-added'],
  ['inserted_a', 'is-diff-removed'],
  ['modified', 'is-diff-modified'],
]);

/**
 * The byte-grid overlay class `grid.highlight(ranges, className)` paints a
 * diff region's kind with.
 *
 * @param {string} kind One of `diff_bytes`' `diff_type` values.
 * @returns {string} `is-diff-added`, `is-diff-removed` or `is-diff-modified`.
 */
export function diffHighlightClass(kind) {
  return DIFF_KIND_CLASS.get(kind) ?? 'is-diff-modified';
}
const SEARCH_OPERATIONS = new Set([
  'search_bytes',
  'search_hex',
  'search_numeric',
  'search_numeric_float',
  'search_numeric_range',
  'search_regex',
  'search_text',
  'search_text_encoded',
]);
const MUTATING_REFRESH = new Set([
  'import_patches_ips',
  'import_patches_bps',
  'import_patches_ups',
  'register_json_template',
  'remove_template',
]);
const EXPORT_FORMATS = [
  ['export_patches_ips', 'IPS'],
  ['export_patches_ips32', 'IPS32'],
  ['export_patches_cod', 'COD'],
  ['export_patches_bps', 'BPS'],
  ['export_patches_ups', 'UPS'],
  ['export_patches_json', 'JSON'],
];

function offsetText(value) {
  return `0x${hexOf(value, OFFSET_DIGITS)}`;
}

/**
 * A short hexadecimal preview of a diff region's bytes, for the Diff panel's
 * table.
 *
 * @param {Uint8Array|null} bytes The side's full read window, or null when
 * that side was never fetched.
 * @param {number} offset Byte offset the region starts at, in `bytes`.
 * @param {number} length Number of bytes the region covers.
 * @returns {string} Up to {@link DIFF_BYTE_SNIPPET_CAP} space-separated hex
 * pairs, trailed with an ellipsis when the region runs longer.
 */
function shortDiffHex(bytes, offset, length) {
  if (bytes === null || bytes === undefined) {
    return '';
  }
  const start = Math.max(0, offset);
  const shown = Math.min(length, DIFF_BYTE_SNIPPET_CAP);
  const slice = bytes.subarray(start, start + shown);
  const text = [...slice].map((value) => hexOf(value, 2)).join(' ');
  return length > DIFF_BYTE_SNIPPET_CAP ? `${text} …` : text;
}

function panelHeader(title, subtitleText) {
  const header = element('div', 'hb-panel-header');
  header.appendChild(element('span', 'hb-panel-title', title));
  const subtitle = element('span', 'hb-panel-subtitle', subtitleText);
  header.appendChild(subtitle);
  const actions = element('div', 'hb-panel-actions');
  header.appendChild(actions);
  return { header, subtitle, actions };
}

function panelAction(glyph, title, onClick) {
  return iconButton(glyph, title, onClick, 'hb-panel-action');
}

function busy(host, message) {
  host.replaceChildren(element('div', 'hb-op-hint', message));
}

/**
 * The key a document-scoped panel compares against to notice it changed.
 *
 * Handle alone is not enough - reopening the same handle after an edit (or an
 * undo) leaves the handle unchanged while the generation moves, so a panel
 * keyed on handle alone would keep showing a pre-edit reading.
 *
 * @param {{handle?: string, generation?: number}|null|undefined} document The
 * active document, as `formContext().document`.
 * @returns {string} A key equal only when both handle and generation match.
 */
export function documentKey(document) {
  return `${document?.handle ?? ''}:${document?.generation ?? ''}`;
}

/**
 * A "does this response still matter" gate for out-of-order async replies.
 *
 * `ThreadingHTTPServer` lets two in-flight requests from the same panel
 * complete out of order, so a `.then()` callback cannot assume it is the most
 * recent one issued. Each call site takes a token from `begin()` before
 * starting its request and checks `isCurrent()` before acting on the reply;
 * a later `begin()` call - from a newer keystroke, a debounce firing again, or
 * a manual refresh - invalidates every token handed out before it.
 *
 * @returns {{begin: () => number, isCurrent: (token: number) => boolean}} The gate.
 */
export function createRequestGate() {
  let token = 0;
  return {
    begin: () => {
      token += 1;
      return token;
    },
    isCurrent: (candidate) => candidate === token,
  };
}

/* -------------------------------------------------------------- the world */

function createEnvironment(bench) {
  let reference = null;

  const formContext = () => {
    const active = bench.activeDocument();
    const caret = bench.grid.caret;
    const selection = bench.grid.selection;
    return {
      handle: active?.handle ?? null,
      document: active,
      documents: bench.documents(),
      caret: caret.offset,
      selection: selection === null ? 0 : selection.length,
      selectionStart: selection === null ? null : selection.start,
      selectionEnd: selection === null ? null : selection.end,
      length: active?.length ?? 0,
      reference,
    };
  };

  /* Both events carry the arguments the run was made with, which the result
     itself does not: a panel recording what the session has done needs to be
     able to offer the run again, and re-deriving the arguments from a form that
     has since been rebuilt is not the same thing. The failed event is separate
     rather than an `operation` with an error on it, because `operation` already
     has subscribers that read `result` unconditionally. */
  const run = async (name, args, handle) => {
    const started = performance.now();
    let result;
    try {
      result = await callOp(name, { handle, arguments: args });
      if (result.created_handle) {
        await bench.reload(result.created_handle);
      } else if (result.document && (MUTATING_REFRESH.has(name) || result.document.generation !== bench.activeDocument()?.generation)) {
        await bench.reload(result.document.handle);
      }
    } catch (error) {
      bench.emit('operation-failed', { name, arguments: args, handle, error, duration_ms: performance.now() - started });
      throw error;
    }
    if (MUTATING_REFRESH.has(name)) {
      clearSuggestionCache();
      bench.grid.invalidate();
    }
    bench.emit('operation', { name, result, arguments: args, handle });
    return result;
  };

  const resultContext = (args, handle) => {
    const base = formContext();
    return {
      ...base,
      handle: handle ?? base.handle,
      args,
      reference,
      seek: (offset) => bench.seek(offset),
      select: (offset, length) => bench.select(offset, length),
      highlight: (ranges, className) => bench.highlight(ranges, className),
      setHits: (pairs) => bench.setHits(pairs),
      toast: (kind, title, detail) => bench.toast(kind, title, detail),
      run,
      raw: (name, rawArgs, rawHandle) => fetchRaw(name, rawArgs, rawHandle ?? base.handle),
      openOperation: (name, initial) => bench.openOperation(name, initial),
      refresh: () => bench.refresh(),
    };
  };

  return {
    bench,
    catalog: () => bench.catalog,
    reference: () => reference,
    setReference: (value) => {
      reference = value;
    },
    formContext,
    resultContext,
    run,
    toast: (kind, title, detail) => bench.toast(kind, title, detail),
  };
}

function showResultModal(env, name, result, args, handle) {
  const titleId = nextId('hb-dialog-title');
  const overlay = element('div', 'hbx-overlay', undefined, { role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleId });
  const scrim = element('div', 'hb-scrim');
  const dialog = element('div', 'hb-dialog hbx-dialog-wide');

  const header = element('div', 'hb-dialog-header');
  const title = element('span', 'hb-dialog-title', name);
  title.id = titleId;
  header.appendChild(title);
  header.appendChild(element('span', 'hb-badge is-mono', `${result.duration_ms.toFixed(2)} ms`));
  const close = iconButton('✕', 'Close', null, 'hb-dialog-close');
  header.appendChild(close);

  const body = element('div', 'hb-dialog-body');
  body.appendChild(renderResult(name, result, env.resultContext(args, handle)));

  const footer = element('div', 'hb-dialog-footer');
  const again = element('button', 'hb-btn is-ghost', 'Run again…');
  again.type = 'button';
  const done = element('button', 'hb-btn is-primary', 'Close');
  done.type = 'button';
  footer.append(again, done);

  dialog.append(header, body, footer);
  overlay.append(scrim, dialog);
  document.getElementById('overlays')?.appendChild(overlay);
  const trap = trapFocus(overlay);

  const dismiss = () => {
    trap.release();
    overlay.remove();
  };
  scrim.addEventListener('mousedown', dismiss);
  close.addEventListener('click', dismiss);
  done.addEventListener('click', dismiss);
  again.addEventListener('click', () => {
    dismiss();
    env.bench.openOperation(name, args);
  });
  overlay.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      dismiss();
    }
  });
  done.focus();
}

async function promptAndRun(env, name, initial) {
  const operation = env.bench.operation(name);
  if (operation === null) {
    env.bench.palette.open(name);
    return null;
  }
  const context = { ...env.formContext(), initial };
  const args = await openArgumentDialog(operation, env.reference(), context);
  if (args === null) {
    return null;
  }
  const handle = operation.receiver === 'document' ? context.handle : null;
  if (operation.receiver === 'document' && handle === null) {
    env.toast('warning', 'No document', `${name} acts on an open document.`);
    return null;
  }
  try {
    const result = await env.run(name, args, handle);
    showResultModal(env, name, result, args, handle);
    return result;
  } catch (error) {
    env.toast('error', error.kind ?? 'failed', error.message);
    return null;
  }
}

/* ---------------------------------------------------------- panel: inspector */

function inspectorPanel(env) {
  let body = null;
  let subtitle = null;
  let timer = 0;
  let lastKey = '';
  const gate = createRequestGate();

  const paint = (offset) => {
    const context = env.formContext();
    if (!context.handle) {
      gate.begin();
      body.replaceChildren(emptyState('No document', 'Open a file to read the bytes under the caret as every type that still fits.', '⌷'));
      return;
    }
    const token = gate.begin();
    callOp('inspect_at', { handle: context.handle, arguments: { offset } })
      .then((result) => {
        if (gate.isCurrent(token)) {
          body.replaceChildren(renderResult('inspect_at', result, env.resultContext({ offset }, context.handle)));
        }
      })
      .catch((error) => {
        if (gate.isCurrent(token)) {
          body.replaceChildren(renderError(error));
        }
      });
  };

  return {
    id: 'shell.inspector',
    title: 'Inspector',
    dock: 'right',
    side: 'right',
    order: 10,
    mount: (host) => {
      const built = panelHeader('inspector', 'no caret');
      subtitle = built.subtitle;
      built.actions.appendChild(panelAction('⟳', 'Re-read the caret', () => {
        lastKey = '';
        paint(env.formContext().caret);
      }));
      body = element('div', 'hb-panel-body is-padded');
      host.append(built.header, body);
      paint(env.formContext().caret);
    },
    update: (context) => {
      if (body === null) {
        return;
      }
      const offset = context.caret.offset;
      const key = `${context.document?.handle ?? ''}:${context.document?.generation ?? ''}:${offset}`;
      if (key === lastKey) {
        return;
      }
      lastKey = key;
      subtitle.textContent = context.document ? `at ${offsetText(offset)}` : 'no document';
      window.clearTimeout(timer);
      timer = window.setTimeout(() => paint(offset), INSPECT_DEBOUNCE_MS);
    },
  };
}

/* --------------------------------------------------------- panel: bookmarks */

function bookmarksPanel(env) {
  let body = null;
  let subtitle = null;
  let count = 0;
  let lastKey = '';

  const reload = () => {
    const context = env.formContext();
    if (!context.handle) {
      count = 0;
      body.replaceChildren(emptyState('No document', 'Bookmarks belong to an open document.', '⚑'));
      return;
    }
    callOp('get_bookmarks', { handle: context.handle, arguments: {} })
      .then((result) => {
        const bookmarks = Array.isArray(result.value) ? result.value : [];
        count = bookmarks.length;
        subtitle.textContent = `${count} bookmark${count === 1 ? '' : 's'}`;
        if (count === 0) {
          body.replaceChildren(emptyState('No bookmarks', 'Select a range and add one to keep a named position in this document.', '⚑'));
          return;
        }
        const list = element('div', 'hb-stack');
        bookmarks.forEach((bookmark, index) => {
          const row = element('div', 'hb-row-flex');
          const swatch = element('span', 'hb-swatch is-lg');
          swatch.style.background = bookmark.color;
          swatch.title = bookmark.color;
          const label = element('button', 'hb-grow hb-truncate', bookmark.label || '(unlabelled)');
          label.type = 'button';
          label.style.textAlign = 'left';
          label.title = `${offsetText(bookmark.offset)} · ${bookmark.length} bytes`;
          label.addEventListener('click', () => env.bench.select(bookmark.offset, Math.max(1, bookmark.length)));
          const position = element('span', 'hb-dim hb-mono hb-nowrap', `${offsetText(bookmark.offset)} +${bookmark.length}`);
          row.append(swatch, label, position);
          row.appendChild(actionButton('edit', 'Replace this bookmark through update_bookmark', () => {
            promptAndRun(env, 'update_bookmark', { index, bookmark }).then(reload);
          }));
          row.appendChild(actionButton('remove', 'Drop this bookmark', () => {
            env.run('remove_bookmark', { index }, context.handle)
              .then(() => {
                env.toast('success', 'Removed', `bookmark ${index}`);
                reload();
              })
              .catch((error) => env.toast('error', 'Remove failed', error.message));
          }));
          list.appendChild(row);
        });
        body.replaceChildren(list);
      })
      .catch((error) => body.replaceChildren(renderError(error)));
  };

  return {
    id: 'panels.bookmarks',
    title: 'Bookmarks',
    dock: 'right',
    side: 'right',
    order: 20,
    count: () => (count === 0 ? null : count),
    mount: (host) => {
      const built = panelHeader('bookmarks', 'no document');
      subtitle = built.subtitle;
      built.actions.appendChild(panelAction('+', 'Bookmark the selection', () => {
        const context = env.formContext();
        if (!context.handle) {
          return;
        }
        promptAndRun(env, 'add_bookmark', {
          offset: context.caret,
          length: Math.max(1, context.selection),
          label: `mark at ${offsetText(context.caret)}`,
          color: tokenHex('--hb-bookmark'),
        }).then(reload);
      }));
      built.actions.appendChild(panelAction('⊞', 'Add through the Bookmark object', () => {
        promptAndRun(env, 'add_bookmark_object', {}).then(reload);
      }));
      built.actions.appendChild(panelAction('⟳', 'Re-read the bookmark list', reload));
      body = element('div', 'hb-panel-body is-padded');
      host.append(built.header, body);
      reload();
    },
    update: (context) => {
      const key = `${context.document?.handle ?? ''}:${context.document?.generation ?? ''}`;
      if (key === lastKey || body === null) {
        return;
      }
      lastKey = key;
      reload();
    },
  };
}

/* --------------------------------------------------------- panel: templates */

function templatesPanel(env) {
  let body = null;
  let subtitle = null;
  let footerText = null;
  let filter = null;
  let templates = [];
  let resultHost = null;
  let lastHandle = '';
  let appliedName = null;
  let appliedCount = 0;

  const updateSubtitle = () => {
    subtitle.textContent = appliedName !== null
      ? `${appliedName} · ${appliedCount} field${appliedCount === 1 ? '' : 's'}`
      : `${templates.length} template${templates.length === 1 ? '' : 's'}`;
  };

  const paint = () => {
    const needle = (filter?.value ?? '').trim().toLowerCase();
    const list = element('div', 'hb-stack');
    const groups = new Map();
    for (const [name, description, category, fields] of templates) {
      if (needle !== '' && !`${name} ${category} ${description}`.toLowerCase().includes(needle)) {
        continue;
      }
      const bucket = groups.get(category) ?? [];
      bucket.push({ name, description, fields });
      groups.set(category, bucket);
    }
    if (groups.size === 0) {
      list.appendChild(emptyState('Nothing matches', 'No builtin or registered template matches that filter.', '⊞'));
    }
    for (const [category, entries] of [...groups].sort(([left], [right]) => left.localeCompare(right))) {
      const heading = element('div', 'hb-op-group');
      heading.append(element('span', undefined, category), element('span', 'hb-badge', String(entries.length)));
      list.appendChild(heading);
      for (const entry of entries) {
        const row = element('div', 'hb-row-flex');
        const name = element('button', 'hb-grow hb-truncate hb-mono', entry.name);
        name.type = 'button';
        name.style.textAlign = 'left';
        name.title = entry.description;
        name.addEventListener('click', () => apply(entry.name));
        row.append(name, element('span', 'hb-dim hb-nowrap', `${entry.fields} fields`));
        row.appendChild(actionButton('export', 'Export this template definition as JSON', () => {
          promptAndRun(env, 'export_template_json', { name: entry.name });
        }));
        list.appendChild(row);
      }
    }
    body.replaceChildren(list, resultHost);
  };

  const apply = (name) => {
    const context = env.formContext();
    if (!context.handle) {
      env.toast('warning', 'No document', 'apply_template acts on an open document.');
      return;
    }
    const args = { name, offset: context.caret };
    busy(resultHost, `applying ${name} at ${offsetText(context.caret)}…`);
    env.run('apply_template', args, context.handle)
      .then((result) => {
        const fields = Array.isArray(result.value) ? result.value : [];
        appliedName = name;
        appliedCount = fields.length;
        updateSubtitle();
        resultHost.replaceChildren(renderResult('apply_template', result, env.resultContext(args, context.handle)));
      })
      .catch((error) => resultHost.replaceChildren(renderError(error)));
  };

  const reload = () => {
    const context = env.formContext();
    if (!context.handle) {
      templates = [];
      body.replaceChildren(emptyState('No document', 'The template registry is read through an open document.', '⊞'));
      return;
    }
    callOp('list_templates_detailed', { handle: context.handle, arguments: {} })
      .then((result) => {
        templates = Array.isArray(result.value) ? result.value : [];
        updateSubtitle();
        paint();
      })
      .catch((error) => body.replaceChildren(renderError(error)));
  };

  /** Drop whatever template result and byte marking belonged to the document being left. */
  const resetApplied = () => {
    appliedName = null;
    appliedCount = 0;
    env.bench.highlight([], 'is-field');
  };

  return {
    id: 'panels.templates',
    title: 'Templates',
    dock: 'right',
    side: 'right',
    order: 30,
    count: () => (templates.length === 0 ? null : templates.length),
    mount: (host) => {
      const built = panelHeader('templates', 'no document');
      subtitle = built.subtitle;
      filter = document.createElement('input');
      filter.type = 'text';
      filter.className = 'hb-input is-narrow';
      filter.placeholder = 'filter';
      filter.spellcheck = false;
      filter.addEventListener('input', paint);
      built.actions.append(filter);
      built.actions.appendChild(panelAction('{}', 'Register a template from JSON', () => {
        promptAndRun(env, 'register_json_template', {}).then(reload);
      }));
      built.actions.appendChild(panelAction('−', 'Remove a registered template', () => {
        promptAndRun(env, 'remove_template', {}).then(reload);
      }));
      built.actions.appendChild(panelAction('⟳', 'Re-read the registry', reload));
      body = element('div', 'hb-panel-body is-padded');
      resultHost = element('div', 'hb-stack');
      const footer = element('div', 'hb-panel-footer');
      footerText = element('span', 'hb-mono hb-dim', 'selecting a field marks its bytes with is-field');
      footer.appendChild(footerText);
      host.append(built.header, body, footer);
      reload();
    },
    update: (context) => {
      const handle = context.document?.handle ?? '';
      if (handle === lastHandle || body === null) {
        return;
      }
      lastHandle = handle;
      resetApplied();
      reload();
    },
  };
}

/* ------------------------------------------------------ panel: va mappings */

function vaMappingsPanel(env) {
  let body = null;
  let subtitle = null;
  let tableHost = null;
  let selectedIndex = -1;
  let count = 0;
  let lastKey = '';

  const converter = () => {
    const stack = element('div', 'hb-stack');
    stack.appendChild(element('div', 'hb-panel-title', 'converter'));

    const build = (label, operation, argument, hint) => {
      const row = element('div', 'hb-field-row');
      row.appendChild(element('span', 'hb-arg-name hb-nowrap', label));
      const input = document.createElement('input');
      input.type = 'text';
      input.className = 'hb-input is-mono';
      input.placeholder = '0x1000';
      input.spellcheck = false;
      const output = element('span', 'hb-mono hb-nowrap hb-dim', '—');
      row.append(input, output);
      let timer = 0;
      const gate = createRequestGate();
      input.addEventListener('input', () => {
        window.clearTimeout(timer);
        const raw = input.value.trim();
        if (raw === '') {
          gate.begin();
          output.className = 'hb-mono hb-nowrap hb-dim';
          output.textContent = '—';
          return;
        }
        timer = window.setTimeout(() => {
          const context = env.formContext();
          if (!context.handle) {
            gate.begin();
            output.textContent = 'no document';
            return;
          }
          const token = gate.begin();
          callOp(operation, { handle: context.handle, arguments: { [argument]: raw } })
            .then((result) => {
              if (!gate.isCurrent(token)) {
                return;
              }
              if (result.value === null) {
                output.className = 'hb-mono hb-nowrap hb-badge is-warning';
                output.textContent = 'null — no mapping covers it';
              } else {
                output.className = 'hb-mono hb-nowrap hb-badge is-success';
                output.textContent = `${offsetText(Number(result.value))} · ${result.value}`;
              }
            })
            .catch((error) => {
              if (!gate.isCurrent(token)) {
                return;
              }
              output.className = 'hb-mono hb-nowrap hb-badge is-error';
              output.textContent = error.message;
            });
        }, INSPECT_DEBOUNCE_MS);
      });
      const wrapper = element('div', 'hb-stack');
      wrapper.append(row, element('div', 'hb-arg-hint', hint));
      return wrapper;
    };

    stack.append(
      build('file offset →', 'file_offset_to_va', 'offset', 'A null answer means no mapping covers the offset, which is not the same answer as the address 0.'),
      build('virtual address →', 'va_to_file_offset', 'va', 'Both directions are live; each keystroke asks the engine.'),
    );
    return stack;
  };

  /**
   * The panel's own table, built directly against `hb-table` rather than
   * through `renderResult` - the spec's columns (File / VA / Size) drop the
   * generic renderer's leading index and add a per-row remove control, and
   * its body carries no padding, both of which the shared `list_va_mappings`
   * view is not free to assume for every caller.
   *
   * @param {Array<[number, number, number]>} rows `(file_offset, virtual_address, length)` triples.
   * @param {string} handle The document the mappings belong to.
   * @returns {void}
   */
  const paintTable = (rows, handle) => {
    if (rows.length === 0) {
      tableHost.replaceChildren(emptyState('No mappings', 'Add one to translate between file offsets and virtual addresses.', '⇄'));
      return;
    }
    const built = table([
      { label: 'file', className: 'is-mono' },
      { label: 'va', className: 'is-mono' },
      { label: 'size', className: 'is-numeric' },
      { label: '', className: '' },
    ]);
    rows.forEach(([offset, va, length], index) => {
      const row = document.createElement('tr');
      row.classList.toggle('is-selected', index === selectedIndex);
      row.append(
        cell(offsetText(offset), 'is-mono is-primary'),
        cell(offsetText(va), 'is-mono'),
        cell(humanSize(length), 'is-numeric'),
      );
      const actionCell = document.createElement('td');
      actionCell.appendChild(actionButton('remove', `Remove mapping ${index}`, () => {
        env.run('remove_va_mapping', { index }, handle)
          .then(() => reload())
          .catch((error) => env.toast('error', 'Remove failed', error.message));
      }));
      row.appendChild(actionCell);
      row.addEventListener('click', () => {
        selectedIndex = index;
        for (const selected of built.body.querySelectorAll('tr.is-selected')) {
          selected.classList.remove('is-selected');
        }
        row.classList.add('is-selected');
        env.bench.select(offset, Math.max(1, length));
      });
      built.body.appendChild(row);
    });
    tableHost.replaceChildren(built.node);
  };

  const reload = () => {
    const context = env.formContext();
    if (!context.handle) {
      count = 0;
      selectedIndex = -1;
      tableHost.replaceChildren(emptyState('No document', 'Mappings belong to an open document.', '⇄'));
      return;
    }
    callOp('list_va_mappings', { handle: context.handle, arguments: {} })
      .then((result) => {
        const rows = Array.isArray(result.value) ? result.value : [];
        count = rows.length;
        if (selectedIndex >= rows.length) {
          selectedIndex = -1;
        }
        subtitle.textContent = `${count} mapping${count === 1 ? '' : 's'}`;
        paintTable(rows, context.handle);
      })
      .catch((error) => tableHost.replaceChildren(renderError(error)));
  };

  return {
    id: 'panels.va',
    title: 'VA mappings',
    dock: 'right',
    side: 'right',
    order: 40,
    count: () => (count === 0 ? null : count),
    mount: (host) => {
      const built = panelHeader('addressing', 'no document');
      subtitle = built.subtitle;
      built.actions.appendChild(panelAction('+', 'Add a mapping', () => {
        promptAndRun(env, 'add_va_mapping', { file_offset: env.formContext().caret }).then(reload);
      }));
      built.actions.appendChild(panelAction('⟳', 'Re-read the mapping list', reload));
      body = element('div', 'hb-panel-body');
      tableHost = element('div');
      body.appendChild(tableHost);
      const toolsBody = element('div', 'hb-panel-body is-padded');
      toolsBody.appendChild(converter());
      host.append(built.header, body, toolsBody);
      reload();
    },
    update: (context) => {
      const key = `${context.document?.handle ?? ''}:${context.document?.generation ?? ''}`;
      if (key === lastKey || body === null) {
        return;
      }
      lastKey = key;
      reload();
    },
  };
}

/* ----------------------------------------------------------- panel: patches */

function patchesPanel(env) {
  let body = null;
  let subtitle = null;
  let listHost = null;
  let count = 0;
  let lastKey = '';

  const reload = () => {
    const context = env.formContext();
    if (!context.handle) {
      count = 0;
      listHost.replaceChildren(emptyState('No document', 'Patches are recorded per document.', '◫'));
      return;
    }
    callOp('get_patches', { handle: context.handle, arguments: {} })
      .then((result) => {
        count = Array.isArray(result.value) ? result.value.length : 0;
        subtitle.textContent = `${count} raw entr${count === 1 ? 'y' : 'ies'}`;
        listHost.replaceChildren(renderResult('get_patches', result, env.resultContext({}, context.handle)));
      })
      .catch((error) => listHost.replaceChildren(renderError(error)));
  };

  return {
    id: 'panels.patches',
    title: 'Patches',
    dock: 'right',
    side: 'right',
    order: 50,
    count: () => (count === 0 ? null : count),
    mount: (host) => {
      const built = panelHeader('patches', 'no document');
      subtitle = built.subtitle;
      built.actions.appendChild(panelAction('⟳', 'Re-read the patch list', reload));
      body = element('div', 'hb-panel-body is-padded hb-stack');
      listHost = element('div', 'hb-stack');

      const exports = element('div', 'hb-stack');
      exports.appendChild(element('div', 'hb-panel-title', 'export'));
      const row = element('div', 'hb-legend');
      for (const [operation, label] of EXPORT_FORMATS) {
        row.appendChild(actionButton(label, `Run ${operation}`, () => promptAndRun(env, operation, {})));
      }
      exports.append(row, element('div', 'hb-arg-hint', 'A binary export is fetched through the raw sidecar; the JSON route would truncate it at 4096 bytes and produce a corrupt patch.'));

      const imports = element('div', 'hb-stack');
      imports.appendChild(element('div', 'hb-panel-title', 'import'));
      const importRow = element('div', 'hb-legend');
      for (const operation of ['import_patches_ips', 'import_patches_bps', 'import_patches_ups']) {
        importRow.appendChild(actionButton(operation.replace('import_patches_', '').toUpperCase(), `Run ${operation}`, () => {
          promptAndRun(env, operation, {}).then(reload);
        }));
      }
      imports.append(importRow, element('div', 'hb-arg-hint', 'Importing replaces the whole document and resets the undo stack; file_path() becomes null, so saving afterwards needs an explicit path.'));

      body.append(listHost, exports, imports);
      host.append(built.header, body);
      reload();
    },
    update: (context) => {
      const key = `${context.document?.handle ?? ''}:${context.document?.generation ?? ''}`;
      if (key === lastKey || body === null) {
        return;
      }
      lastKey = key;
      reload();
    },
  };
}

/* ----------------------------------------------------- panel: search results */

function searchPanel(env) {
  let body = null;
  let subtitle = null;
  let hits = [];
  let lastName = 'search';

  const paint = () => {
    if (body === null) {
      return;
    }
    subtitle.textContent = hits.length === 0 ? 'no results' : `${hits.length} from ${lastName}`;
    if (hits.length === 0) {
      const empty = emptyState('No search results', 'Run a search from the toolbar, the Search menu, or any of the eight search operations in the console.', '⌕');
      const row = element('div', 'hb-row-flex');
      row.appendChild(actionButton('Find…', 'Open the shell search dialog', () => env.bench.run('search.find')));
      for (const name of ['search_hex', 'search_regex', 'search_numeric']) {
        row.appendChild(actionButton(name, `Open ${name}`, () => env.bench.openOperation(name)));
      }
      empty.appendChild(row);
      body.replaceChildren(empty);
      return;
    }
    const context = env.formContext();
    const silent = { ...env.resultContext({}, context.handle), setHits: () => undefined };
    body.replaceChildren(renderResult(lastName, { value: hits.map((hit) => [hit.offset, hit.length]) }, silent));
  };

  env.bench.on('hits', (pairs) => {
    hits = pairs;
    paint();
  });
  env.bench.on('operation', ({ name, result }) => {
    if (!SEARCH_OPERATIONS.has(name)) {
      return;
    }
    lastName = name;
    const pairs = Array.isArray(result.value) ? result.value : [];
    window.setTimeout(() => {
      const already = hits.length === pairs.length && hits.every((hit, index) => hit.offset === pairs[index][0] && hit.length === pairs[index][1]);
      if (!already) {
        env.bench.setHits(pairs);
      } else {
        paint();
      }
    }, 0);
  });

  return {
    id: 'panels.search',
    title: 'Search',
    dock: 'bottom',
    side: 'bottom',
    order: 10,
    count: () => (hits.length === 0 ? null : hits.length),
    mount: (host) => {
      const built = panelHeader('search results', 'no results');
      subtitle = built.subtitle;
      built.actions.appendChild(panelAction('⌕', 'Open the search dialog', () => env.bench.run('search.find')));
      built.actions.appendChild(panelAction('✕', 'Clear the results', () => env.bench.setHits([])));
      body = element('div', 'hb-panel-body is-padded');
      host.append(built.header, body);
      paint();
    },
    update: () => undefined,
  };
}

/* ---------------------------------------------------------- panel: strings */

function stringsPanel(env) {
  let body = null;
  let subtitle = null;
  let minLength = null;
  let ascii = null;
  let utf16 = null;
  let count = 0;
  let lastKey = '';

  const clear = () => {
    count = 0;
    subtitle.textContent = 'not extracted';
    body.replaceChildren(emptyState('Nothing extracted yet', 'Choose a minimum length and the encodings, then run the extraction.', '≡'));
  };

  const extract = () => {
    const context = env.formContext();
    if (!context.handle) {
      body.replaceChildren(emptyState('No document', 'Open a file to extract its strings.', '≡'));
      return;
    }
    const args = {
      min_length: Math.max(1, Number.parseInt(minLength.value, 10) || DEFAULT_MIN_STRING),
      include_ascii: ascii.checked,
      include_utf16: utf16.checked,
      max_results: DEFAULT_STRING_LIMIT,
    };
    busy(body, 'extracting…');
    env.run('extract_strings', args, context.handle)
      .then((result) => {
        count = Array.isArray(result.value) ? result.value.length : 0;
        subtitle.textContent = `${count} strings, minimum ${args.min_length}`;
        body.replaceChildren(renderResult('extract_strings', result, env.resultContext(args, context.handle)));
      })
      .catch((error) => body.replaceChildren(renderError(error)));
  };

  return {
    id: 'panels.strings',
    title: 'Strings',
    dock: 'bottom',
    side: 'bottom',
    order: 20,
    count: () => (count === 0 ? null : count),
    mount: (host) => {
      const built = panelHeader('strings', 'not extracted');
      subtitle = built.subtitle;

      minLength = document.createElement('input');
      minLength.type = 'text';
      minLength.className = 'hb-input is-narrow is-mono';
      minLength.value = String(DEFAULT_MIN_STRING);
      minLength.title = 'Minimum length';

      const asciiCheck = element('label', 'hb-check is-checked');
      ascii = document.createElement('input');
      ascii.type = 'checkbox';
      ascii.className = 'hb-check-box';
      ascii.checked = true;
      ascii.addEventListener('change', () => asciiCheck.classList.toggle('is-checked', ascii.checked));
      asciiCheck.append(ascii, element('span', undefined, 'ascii'));

      const utf16Check = element('label', 'hb-check is-checked');
      utf16 = document.createElement('input');
      utf16.type = 'checkbox';
      utf16.className = 'hb-check-box';
      utf16.checked = true;
      utf16.addEventListener('change', () => utf16Check.classList.toggle('is-checked', utf16.checked));
      utf16Check.append(utf16, element('span', undefined, 'utf-16'));

      built.actions.append(minLength, asciiCheck, utf16Check, panelAction('▶', 'Extract strings now', extract));
      body = element('div', 'hb-panel-body is-padded');
      host.append(built.header, body);
      lastKey = documentKey(env.formContext().document);
      clear();
    },
    update: (context) => {
      const key = documentKey(context.document);
      if (key === lastKey || body === null) {
        return;
      }
      lastKey = key;
      clear();
    },
  };
}

/* ------------------------------------------------------------- panel: diff */

function diffPanel(env) {
  let body = null;
  let subtitle = null;
  let mapHost = null;
  let tableHost = null;
  let footerText = null;
  let lastDocuments = '';
  let lastActiveHandle = '';
  let state = null;
  let minimap = null;

  const documentOptions = () => env.bench.documents().map((info) => ({ value: info.handle, label: `${info.label} (${humanSize(info.length)})` }));

  const teardownMinimap = () => {
    if (minimap !== null) {
      minimap.chart.destroy();
      minimap = null;
    }
  };

  const clearHighlights = () => {
    for (const kind of DIFF_HIGHLIGHT_TOKENS.keys()) {
      env.bench.highlight([], diffHighlightClass(kind));
    }
  };

  const applyHighlights = () => {
    const active = env.formContext().handle;
    const key = state === null ? null : active === state.left.handle ? 'offset_a' : active === state.right.handle ? 'offset_b' : null;
    for (const kind of DIFF_HIGHLIGHT_TOKENS.keys()) {
      const className = diffHighlightClass(kind);
      if (key === null) {
        env.bench.highlight([], className);
        continue;
      }
      const ranges = state.changed
        .filter((region) => String(region.diff_type) === kind)
        .map((region) => ({ offset: Number(region[key] ?? 0), length: Number(region.length ?? 0) }));
      env.bench.highlight(ranges, className);
    }
  };

  const regionOffset = (region) => {
    const active = env.formContext().handle;
    const key = active === state?.right.handle ? 'offset_b' : 'offset_a';
    return { offset: Number(region[key] ?? 0), length: Math.max(1, Number(region.length ?? 0)) };
  };

  const navigateTo = (region) => {
    if (state === null) {
      return;
    }
    state.cursor = state.changed.indexOf(region);
    const { offset, length } = regionOffset(region);
    env.bench.select(offset, length);
  };

  const stepNext = () => {
    if (state === null || state.changed.length === 0) {
      env.toast('info', 'Nothing to step through', 'Compare two documents first.');
      return;
    }
    state.cursor = (state.cursor + 1) % state.changed.length;
    navigateTo(state.changed[state.cursor]);
  };

  const bytesCell = (region) => {
    const kind = String(region.diff_type);
    if (kind === 'modified') {
      return `${shortDiffHex(state.leftBytes, region.offset_a, region.length)} → ${shortDiffHex(state.rightBytes, region.offset_b, region.length)}`;
    }
    if (kind === 'inserted_b') {
      return shortDiffHex(state.rightBytes, region.offset_b, region.length);
    }
    if (kind === 'inserted_a') {
      return shortDiffHex(state.leftBytes, region.offset_a, region.length);
    }
    return '';
  };

  const emptyDiff = () => {
    const empty = emptyState('Nothing compared yet', 'Pick two open documents to see where they differ.', '⇔');
    const row = element('div', 'hb-row-flex');
    row.appendChild(actionButton('choose documents…', 'Pick two open documents to compare', chooseTarget));
    empty.appendChild(row);
    return empty;
  };

  const paintTable = () => {
    const built = table([
      { label: 'offset', className: 'is-mono' },
      { label: 'len', className: 'is-numeric' },
      { label: 'kind', className: '' },
      { label: 'bytes', className: 'is-mono' },
    ]);
    for (const region of state.changed) {
      const kind = String(region.diff_type);
      const row = document.createElement('tr');
      row.append(cell(offsetText(Number(region.offset_a ?? 0)), 'is-mono'), cell(String(region.length ?? 0), 'is-numeric'));
      const kindCell = document.createElement('td');
      kindCell.appendChild(element('span', `hb-badge ${DIFF_KIND_TONE.get(kind) ?? ''}`.trim(), DIFF_KIND_LABEL.get(kind) ?? kind));
      row.appendChild(kindCell);
      row.appendChild(cell(bytesCell(region), 'is-mono'));
      row.addEventListener('click', () => navigateTo(region));
      built.body.appendChild(row);
    }
    if (state.changed.length === 0) {
      tableHost.replaceChildren(
        banner('success', 'The two inputs are identical', `${state.regions.length} region${state.regions.length === 1 ? '' : 's'} in the alignment, all matching.`),
        built.node,
      );
    } else {
      tableHost.replaceChildren(built.node);
    }
  };

  const syncCaret = (context) => {
    if (minimap === null) {
      return;
    }
    const activeHandle = context.document?.handle ?? null;
    minimap.setCaret(state !== null && activeHandle === state.left.handle ? context.caret.offset : null);
  };

  const paintMinimap = () => {
    teardownMinimap();
    minimap = diffTrackChart(state.changed, { span: Math.max(state.left.length, state.right.length), onPick: navigateTo });
    mapHost.replaceChildren(minimap.element);
    syncCaret(env.bench.context());
  };

  const paintResult = () => {
    subtitle.textContent = `${state.left.label} ↔ ${state.right.label}`;
    footerText.textContent = `diff_bytes · ${humanSize(state.comparedBytes)} compared in ${state.durationMs.toFixed(2)} ms`;
    paintMinimap();
    paintTable();
    applyHighlights();
  };

  const resetState = () => {
    state = null;
    teardownMinimap();
    mapHost.replaceChildren();
    clearHighlights();
    subtitle.textContent = 'nothing compared';
    footerText.textContent = '';
    tableHost.replaceChildren(emptyDiff());
  };

  const compare = (leftHandle, rightHandle) => {
    const left = env.bench.documents().find((info) => info.handle === leftHandle);
    const right = env.bench.documents().find((info) => info.handle === rightHandle);
    if (!left || !right) {
      env.toast('warning', 'Pick two documents', 'diff_bytes needs two open documents.');
      return;
    }
    teardownMinimap();
    mapHost.replaceChildren();
    busy(tableHost, 'reading both documents…');
    Promise.all([
      readWindow(left.handle, 0, Math.min(left.length, DIFF_CAP)),
      readWindow(right.handle, 0, Math.min(right.length, DIFF_CAP)),
    ])
      .then(([a, b]) => {
        const args = { data_a: toHex(a.bytes).toLowerCase(), data_b: toHex(b.bytes).toLowerCase() };
        const capped = left.length > DIFF_CAP || right.length > DIFF_CAP;
        return env.run('diff_bytes', args, null).then((result) => {
          const regions = Array.isArray(result.value?.regions) ? result.value.regions : [];
          state = {
            left,
            right,
            leftBytes: a.bytes,
            rightBytes: b.bytes,
            regions,
            changed: regions.filter((region) => DIFF_HIGHLIGHT_TOKENS.has(String(region.diff_type))),
            comparedBytes: Math.max(a.bytes.length, b.bytes.length),
            durationMs: result.duration_ms,
            cursor: -1,
          };
          paintResult();
          if (capped) {
            tableHost.prepend(banner('warning', `Compared the first ${humanSize(DIFF_CAP)} of each`, 'A longer document is read through the window endpoint, which caps a single read at one mebibyte.'));
          }
        });
      })
      .catch((error) => tableHost.replaceChildren(renderError(error)));
  };

  async function chooseTarget() {
    const options = documentOptions();
    if (options.length < 2) {
      env.toast('warning', 'Need two documents', 'Open a second document to compare against.');
      return;
    }
    const values = await env.bench.dialog({
      title: 'Compare documents',
      confirmLabel: 'Compare',
      fields: [
        { name: 'left', label: 'first', type: 'select', value: state?.left.handle ?? options[0].value, options },
        { name: 'right', label: 'second', type: 'select', value: state?.right.handle ?? options[Math.min(1, options.length - 1)].value, options },
      ],
    });
    if (values === null) {
      return;
    }
    if (values.left === values.right) {
      env.toast('warning', 'Pick two different documents', 'Comparing a document against itself is always a match.');
      return;
    }
    compare(values.left, values.right);
  }

  return {
    id: 'panels.diff',
    title: 'Diff',
    dock: 'bottom',
    side: 'bottom',
    order: 30,
    mount: (host) => {
      const built = panelHeader('difference', 'nothing compared');
      subtitle = built.subtitle;
      built.actions.appendChild(panelAction('⇄', 'Choose two documents to compare', chooseTarget));
      built.actions.appendChild(panelAction('→', 'Jump to the next changed region', stepNext));
      body = element('div', 'hb-panel-body is-padded hb-stack');
      mapHost = element('div');
      tableHost = element('div', 'hb-stack');
      tableHost.appendChild(emptyDiff());
      body.append(mapHost, tableHost);
      const footer = element('div', 'hb-panel-footer');
      footerText = element('span', 'hb-mono hb-dim');
      footer.appendChild(footerText);
      lastDocuments = env.bench.documents().map((info) => info.handle).join(',');
      host.append(built.header, body, footer);
    },
    update: (context) => {
      if (body === null) {
        return;
      }
      const handles = context.documents.map((info) => info.handle).join(',');
      if (handles !== lastDocuments) {
        lastDocuments = handles;
        if (state !== null && (!context.documents.some((info) => info.handle === state.left.handle) || !context.documents.some((info) => info.handle === state.right.handle))) {
          resetState();
        }
      }
      const activeHandle = context.document?.handle ?? '';
      if (activeHandle !== lastActiveHandle) {
        lastActiveHandle = activeHandle;
        if (state !== null) {
          applyHighlights();
        }
      }
      syncCaret(context);
    },
  };
}

/* ---------------------------------------------------------- panel: entropy */

/**
 * The Shannon-entropy dock panel: a live strip that marks the caret's
 * position, rather than the one-shot modal `analyze.entropy` used to open.
 *
 * Pinning freezes the panel on whichever document was active when it was
 * pinned - a document switch neither recomputes nor moves the caret marker
 * until it is unpinned - so a reading stays put while the grid is used to
 * look at something else.
 *
 * @param {object} env The panel environment built by {@link createEnvironment}.
 * @returns {object} The panel descriptor.
 */
function entropyPanel(env) {
  let body = null;
  let chartHandle = null;
  let pinned = false;
  let pinGlyph = null;
  let pinButton = null;
  let trackedKey = '';

  const teardown = () => {
    if (chartHandle !== null) {
      chartHandle.chart.destroy();
      chartHandle = null;
    }
  };

  const paintEmpty = (title, hint) => {
    teardown();
    body.replaceChildren(emptyState(title, hint, '≈'));
  };

  const load = (targetDocument) => {
    if (!targetDocument?.handle) {
      trackedKey = '';
      paintEmpty('No document', 'Open a file to see its entropy plotted in 256-byte blocks.');
      return;
    }
    trackedKey = documentKey(targetDocument);
    busy(body, 'reading entropy…');
    callOp('entropy_map', { handle: targetDocument.handle, arguments: { block_size: ENTROPY_STRIP_BLOCK } })
      .then((result) => {
        if (trackedKey !== documentKey(targetDocument)) {
          return;
        }
        const values = Array.isArray(result.value) ? result.value.map(Number) : [];
        if (values.length === 0) {
          paintEmpty('No blocks to map', 'The document is shorter than one block.');
          return;
        }
        teardown();
        chartHandle = entropyStripChart(values, {
          blockSize: ENTROPY_STRIP_BLOCK,
          documentLength: targetDocument.length,
          onSeek: (offset) => env.bench.seek(offset),
        });
        body.replaceChildren(chartHandle.element);
      })
      .catch((error) => {
        if (trackedKey !== documentKey(targetDocument)) {
          return;
        }
        teardown();
        body.replaceChildren(renderError(error));
      });
  };

  return {
    id: 'panels.entropy',
    title: 'Entropy',
    dock: 'bottom',
    side: 'bottom',
    order: 40,
    mount: (host) => {
      const built = panelHeader('entropy', 'block 256 B · follows caret');
      built.actions.appendChild(panelAction('⟳', 'Recompute the entropy map', () => load(env.formContext().document)));
      pinButton = panelAction('○', 'Pin to this document', () => {
        pinned = !pinned;
        pinGlyph.textContent = pinned ? '●' : '○';
        const label = pinned ? 'Unpin — follow the active document' : 'Pin to this document';
        pinButton.title = label;
        pinButton.setAttribute('aria-label', label);
      });
      pinGlyph = pinButton.firstChild;
      built.actions.appendChild(pinButton);
      body = element('div', 'hb-panel-body is-padded');
      host.append(built.header, body);
      load(env.formContext().document);
    },
    update: (context) => {
      if (body === null) {
        return;
      }
      const activeKey = documentKey(context.document);
      if (!pinned && trackedKey !== activeKey) {
        load(context.document);
        return;
      }
      if (chartHandle !== null) {
        chartHandle.setCaret(trackedKey === activeKey ? context.caret.offset : null);
      }
    },
  };
}

/* -------------------------------------------------------- panel: byte types */

/**
 * The byte-type distribution dock panel: null, printable, control and high
 * bytes as one segmented bar, recomputed whenever the active document changes.
 *
 * @param {object} env The panel environment built by {@link createEnvironment}.
 * @returns {object} The panel descriptor.
 */
function byteTypesPanel(env) {
  let body = null;
  let subtitle = null;
  let lastKey = '';

  const reload = (context) => {
    lastKey = documentKey(context.document);
    const handle = context.document?.handle ?? null;
    if (handle === null) {
      body.replaceChildren(emptyState('No document', 'Open a file to see its byte-type split.', '▥'));
      return;
    }
    busy(body, 'reading…');
    callOp('byte_type_distribution', { handle, arguments: {} })
      .then((result) => {
        if (lastKey !== documentKey(context.document)) {
          return;
        }
        const counts = Array.isArray(result.value) ? result.value.map(Number) : [0, 0, 0, 0];
        subtitle.textContent = 'whole document';
        body.replaceChildren(byteTypeChart(counts).element);
      })
      .catch((error) => {
        if (lastKey === documentKey(context.document)) {
          body.replaceChildren(renderError(error));
        }
      });
  };

  return {
    id: 'panels.byteTypes',
    title: 'Byte types',
    dock: 'bottom',
    side: 'bottom',
    order: 41,
    mount: (host) => {
      const built = panelHeader('byte types', 'no document');
      subtitle = built.subtitle;
      built.actions.appendChild(panelAction('⟳', 'Recompute the byte-type split', () => reload(env.bench.context())));
      body = element('div', 'hb-panel-body is-padded');
      host.append(built.header, body);
      reload(env.bench.context());
    },
    update: (context) => {
      if (body === null || documentKey(context.document) === lastKey) {
        return;
      }
      reload(context);
    },
  };
}

/* ----------------------------------------------------- panel: classification */

/**
 * The content-classification dock panel: one colour-coded column per block,
 * recomputed whenever the active document changes.
 *
 * @param {object} env The panel environment built by {@link createEnvironment}.
 * @returns {object} The panel descriptor.
 */
function classificationPanel(env) {
  let body = null;
  let subtitle = null;
  let lastKey = '';

  const reload = (context) => {
    lastKey = documentKey(context.document);
    const handle = context.document?.handle ?? null;
    if (handle === null) {
      body.replaceChildren(emptyState('No document', 'Open a file to see its content classification.', '▤'));
      return;
    }
    subtitle.textContent = `${humanSize(CLASSIFICATION_STRIP_BLOCK)} blocks`;
    busy(body, 'reading…');
    fetchRaw('content_classification', { block_size: CLASSIFICATION_STRIP_BLOCK }, handle)
      .then((buffer) => {
        if (lastKey !== documentKey(context.document)) {
          return;
        }
        const codes = new Uint8Array(buffer);
        body.replaceChildren(classificationChart(codes, { blockSize: CLASSIFICATION_STRIP_BLOCK, onSeek: (offset) => env.bench.seek(offset) }).element);
      })
      .catch((error) => {
        if (lastKey === documentKey(context.document)) {
          body.replaceChildren(renderError(error));
        }
      });
  };

  return {
    id: 'panels.classification',
    title: 'Classification',
    dock: 'bottom',
    side: 'bottom',
    order: 42,
    mount: (host) => {
      const built = panelHeader('content classification', 'no document');
      subtitle = built.subtitle;
      built.actions.appendChild(panelAction('⟳', 'Recompute the classification map', () => reload(env.bench.context())));
      body = element('div', 'hb-panel-body is-padded');
      host.append(built.header, body);
      reload(env.bench.context());
    },
    update: (context) => {
      if (body === null || documentKey(context.document) === lastKey) {
        return;
      }
      reload(context);
    },
  };
}

/* ------------------------------------------------------------ panel: digram */

/**
 * The digram-matrix dock panel: the 256 by 256 byte-pair plane, recomputed
 * whenever the active document changes.
 *
 * @param {object} env The panel environment built by {@link createEnvironment}.
 * @returns {object} The panel descriptor.
 */
function digramPanel(env) {
  let body = null;
  let subtitle = null;
  let lastKey = '';

  const reload = (context) => {
    lastKey = documentKey(context.document);
    const handle = context.document?.handle ?? null;
    if (handle === null) {
      body.replaceChildren(emptyState('No document', 'Open a file to see its digram matrix.', '▦'));
      return;
    }
    busy(body, 'reading…');
    callOp('digram_matrix', { handle, arguments: {} })
      .then((result) => {
        if (lastKey !== documentKey(context.document)) {
          return;
        }
        const counts = Array.isArray(result.value) ? result.value : [];
        if (counts.length === 0) {
          subtitle.textContent = 'no digrams';
          body.replaceChildren(emptyState('No digrams', 'The document has fewer than two bytes.', '▦'));
          return;
        }
        subtitle.textContent = `${counts.length} pairs`;
        body.replaceChildren(digramChart(counts).element);
      })
      .catch((error) => {
        if (lastKey === documentKey(context.document)) {
          body.replaceChildren(renderError(error));
        }
      });
  };

  return {
    id: 'panels.digram',
    title: 'Digram',
    dock: 'bottom',
    side: 'bottom',
    order: 43,
    mount: (host) => {
      const built = panelHeader('digram matrix', 'no document');
      subtitle = built.subtitle;
      built.actions.appendChild(panelAction('⟳', 'Recompute the digram matrix', () => reload(env.bench.context())));
      body = element('div', 'hb-panel-body is-padded');
      host.append(built.header, body);
      reload(env.bench.context());
    },
    update: (context) => {
      if (body === null || documentKey(context.document) === lastKey) {
        return;
      }
      reload(context);
    },
  };
}

/* ---------------------------------------------------------- panel: results */

/**
 * A one-line rendering of whatever an operation returned.
 *
 * @param {unknown} value The JSON-safe value from an invocation result.
 * @returns {string} A summary short enough for a tree row.
 */
function valueSummary(value) {
  if (value === null || value === undefined) {
    return 'null';
  }
  if (isTaggedBytes(value)) {
    return humanSize(taggedBytes(value).length);
  }
  if (Array.isArray(value)) {
    return `${value.length} ${value.length === 1 ? 'entry' : 'entries'}`;
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value);
    return `${keys.length} ${keys.length === 1 ? 'entry' : 'entries'}`;
  }
  const text = String(value).replace(/\s+/g, ' ').trim();
  return text.length > SUMMARY_LIMIT ? `${text.slice(0, SUMMARY_LIMIT)}…` : text;
}

/**
 * The type name shown against an argument.
 *
 * @param {unknown} value The argument as it was sent.
 * @returns {string} A short type name.
 */
function argumentType(value) {
  if (value === null || value === undefined) {
    return 'null';
  }
  if (isTaggedBytes(value)) {
    return 'bytes';
  }
  if (Array.isArray(value)) {
    return 'list';
  }
  return typeof value;
}

/**
 * The twisty's classes for a run, given whether it has arguments to show.
 *
 * @param {number} count Number of arguments the run was made with.
 * @param {boolean} expanded Whether the run starts with its arguments showing.
 * @returns {string} The class list for the twisty glyph.
 */
function twistyClass(count, expanded) {
  if (count === 0) {
    return 'hb-tree-twisty is-leaf';
  }
  return expanded ? 'hb-tree-twisty is-open' : 'hb-tree-twisty';
}

function resultsPanel(env) {
  let body = null;
  let footerText = null;
  const runs = [];

  const runNode = (entry, expanded) => {
    const fragment = document.createDocumentFragment();
    const args = entry.args === null ? [] : Object.entries(entry.args);

    const node = element('div', 'hb-tree-node');
    node.style.setProperty('--hb-tree-depth', '0');
    node.appendChild(decorativeGlyph('', 'hb-tree-indent'));
    const twisty = decorativeGlyph('', twistyClass(args.length, expanded));
    node.appendChild(twisty);

    const label = element('span', 'hb-tree-label', entry.name);
    if (entry.error !== null) {
      label.style.color = 'var(--hb-error)';
    }
    node.appendChild(label);
    node.appendChild(element('span', 'hb-tree-type', entry.error === null ? entry.returns : 'error'));
    const value = entry.error === null
      ? valueSummary(entry.value)
      : `${errorKindLabel(entry.error.kind ?? 'internal')} · ${entry.error.message}`;
    node.appendChild(element('span', 'hb-tree-value', value));
    node.appendChild(element('span', 'hb-tree-offset', `${entry.duration.toFixed(2)} ms`));
    node.title = `${entry.name} · ${entry.at.toLocaleTimeString()}`;
    node.addEventListener('click', () => {
      for (const selected of body?.querySelectorAll('.hb-tree-node.is-selected') ?? []) {
        selected.classList.remove('is-selected');
      }
      node.classList.add('is-selected');
      env.bench.openOperation(entry.name, entry.args ?? undefined);
    });
    fragment.appendChild(node);

    if (args.length === 0) {
      return fragment;
    }
    const holder = element('div');
    holder.hidden = !expanded;
    for (const [name, argument] of args) {
      const child = element('div', 'hb-tree-node');
      child.style.setProperty('--hb-tree-depth', '1');
      child.appendChild(decorativeGlyph('', 'hb-tree-indent'));
      child.appendChild(decorativeGlyph('', 'hb-tree-twisty is-leaf'));
      child.append(
        element('span', 'hb-tree-label', name),
        element('span', 'hb-tree-type', argumentType(argument)),
        element('span', 'hb-tree-value', valueSummary(argument)),
      );
      holder.appendChild(child);
    }
    fragment.appendChild(holder);
    twisty.addEventListener('click', (event) => {
      event.stopPropagation();
      holder.hidden = !twisty.classList.toggle('is-open');
    });
    return fragment;
  };

  const paint = () => {
    if (body === null) {
      return;
    }
    if (footerText !== null) {
      footerText.textContent = `${runs.length} ${runs.length === 1 ? 'run' : 'runs'} · newest first`;
    }
    if (runs.length === 0) {
      body.replaceChildren(emptyState('Nothing run yet', 'Every operation this session runs is kept here with its arguments, so two results can be read without running either again.', '▶'));
      return;
    }
    const tree = element('div', 'hb-tree');
    runs.forEach((entry, index) => tree.appendChild(runNode(entry, index === 0)));
    body.replaceChildren(tree);
  };

  const record = (entry) => {
    runs.unshift(entry);
    runs.length = Math.min(runs.length, RESULTS_LIMIT);
    paint();
  };

  env.bench.on('operation', ({ name, result, arguments: args }) => {
    record({
      name,
      args: args ?? null,
      at: new Date(),
      duration: result.duration_ms,
      returns: env.bench.operation(name)?.returns ?? typeof result.value,
      value: result.value,
      error: null,
    });
  });

  env.bench.on('operation-failed', ({ name, arguments: args, error, duration_ms: duration }) => {
    record({ name, args: args ?? null, at: new Date(), duration, returns: 'error', value: null, error });
  });

  return {
    id: 'panels.results',
    title: 'Results',
    dock: 'bottom',
    side: 'bottom',
    order: 50,
    count: () => (runs.length === 0 ? null : runs.length),
    mount: (host) => {
      const built = panelHeader('Results', 'this session');
      built.actions.appendChild(panelAction('⌫', 'Clear the recorded runs', () => {
        runs.length = 0;
        paint();
      }));
      body = element('div', 'hb-panel-body');
      const footer = element('div', 'hb-panel-footer');
      footerText = element('span', 'hb-mono hb-dim');
      footer.appendChild(footerText);
      host.append(built.header, body, footer);
      paint();
    },
  };
}

/* ---------------------------------------------------------- panel: run log */

function runLogPanel(env) {
  let body = null;
  let subtitle = null;
  let jobCount = 0;
  let lastRefresh = 0;
  const history = [];

  env.bench.on('operation', ({ name, result }) => {
    history.unshift({ name, at: new Date(), duration: result.duration_ms, handle: result.document?.handle ?? null });
    history.length = Math.min(history.length, 200);
  });

  const paint = (jobs) => {
    const stack = element('div', 'hb-stack');

    if (jobs.length > 0) {
      stack.appendChild(element('div', 'hb-panel-title', 'background jobs'));
      const node = element('table', 'hb-table');
      const head = document.createElement('thead');
      const headRow = document.createElement('tr');
      for (const heading of ['operation', 'state', 'handle', 'submitted']) {
        headRow.appendChild(element('th', heading === 'operation' ? 'is-mono' : '', heading, { scope: 'col' }));
      }
      head.appendChild(headRow);
      const tbody = document.createElement('tbody');
      for (const job of [...jobs].reverse()) {
        const row = document.createElement('tr');
        row.appendChild(element('td', 'is-primary is-mono', job.operation));
        const stateCell = document.createElement('td');
        const tone = job.state === 'failed' ? 'is-error' : job.state === 'done' ? 'is-success' : 'is-info';
        stateCell.appendChild(element('span', `hb-badge ${tone}`, job.state));
        row.appendChild(stateCell);
        row.append(element('td', 'is-mono', job.handle ?? '—'), element('td', '', new Date(job.submitted_at * 1000).toLocaleTimeString()));
        tbody.appendChild(row);
      }
      node.append(head, tbody);
      stack.appendChild(node);
    }

    stack.appendChild(element('div', 'hb-panel-title', 'this session'));
    if (history.length === 0) {
      stack.appendChild(emptyState('Nothing run yet', 'Every operation this session runs is listed here with the time it took.', '▶'));
    } else {
      const node = element('table', 'hb-table');
      const head = document.createElement('thead');
      const headRow = document.createElement('tr');
      for (const heading of ['operation', 'duration', 'document', 'at']) {
        headRow.appendChild(element('th', heading === 'operation' ? 'is-mono' : '', heading, { scope: 'col' }));
      }
      head.appendChild(headRow);
      const tbody = document.createElement('tbody');
      for (const entry of history.slice(0, 80)) {
        const row = document.createElement('tr');
        row.append(
          element('td', 'is-mono is-primary', entry.name),
          element('td', 'is-numeric', `${entry.duration.toFixed(2)} ms`),
          element('td', 'is-mono', entry.handle ?? '—'),
          element('td', '', entry.at.toLocaleTimeString()),
        );
        row.addEventListener('click', () => env.bench.openOperation(entry.name));
        tbody.appendChild(row);
      }
      node.append(head, tbody);
      stack.appendChild(node);
    }
    body.replaceChildren(stack);
  };

  const reload = () => {
    lastRefresh = performance.now();
    listJobs()
      .then((payload) => {
        jobCount = payload.jobs.length + history.length;
        subtitle.textContent = `${payload.exercised.length} of ${payload.operation_count} operations exercised`;
        paint(payload.jobs);
      })
      .catch((error) => body.replaceChildren(renderError(error)));
  };

  return {
    id: 'shell.activity',
    title: 'Run log',
    dock: 'bottom',
    side: 'bottom',
    order: 90,
    count: () => (jobCount === 0 ? null : jobCount),
    mount: (host) => {
      const built = panelHeader('run log', 'no runs yet');
      subtitle = built.subtitle;
      built.actions.appendChild(panelAction('⟳', 'Re-read the job list', reload));
      body = element('div', 'hb-panel-body is-padded');
      host.append(built.header, body);
      reload();
    },
    update: () => {
      if (body !== null && performance.now() - lastRefresh > 2000) {
        reload();
      }
    },
  };
}

/* ---------------------------------------------------------------- install */

/**
 * Panels the shell builds for itself that this module supersedes.
 *
 * Registering the same identifier is not enough on its own: the dock keeps the
 * host element it already mounted and never calls the replacement's mount, so
 * the old body would stay on screen driven by a panel object that is no longer
 * in the list. Removing the identifier first drops that host.
 */
const REPLACED_IDS = ['shell.inspector', 'shell.activity'];

/** Identifiers of every panel this module registers. */
export const PANEL_IDS = [
  'shell.inspector',
  'panels.bookmarks',
  'panels.templates',
  'panels.va',
  'panels.patches',
  'panels.search',
  'panels.strings',
  'panels.diff',
  'panels.entropy',
  'panels.byteTypes',
  'panels.classification',
  'panels.digram',
  'panels.console',
  'panels.results',
  'shell.activity',
];

/**
 * Register every panel and take over the argument-form hook.
 *
 * @param {object} bench The integration surface published on `window.hexbench`.
 * @returns {Promise<object>} The environment the panels share.
 */
export async function installPanels(bench) {
  const env = createEnvironment(bench);
  try {
    env.setReference(await getReference());
  } catch (error) {
    bench.toast('warning', 'Reference unavailable', `Argument hints will be sparse: ${error.message}`);
  }

  bench.openOperation = (name, initial) => {
    promptAndRun(env, name, initial).catch((error) => bench.toast('error', 'Operation failed', error.message));
  };

  for (const id of REPLACED_IDS) {
    bench.unregisterPanel(id);
  }

  const panels = [
    inspectorPanel(env),
    bookmarksPanel(env),
    templatesPanel(env),
    vaMappingsPanel(env),
    patchesPanel(env),
    searchPanel(env),
    stringsPanel(env),
    diffPanel(env),
    entropyPanel(env),
    byteTypesPanel(env),
    classificationPanel(env),
    digramPanel(env),
    createOperationConsole(env),
    resultsPanel(env),
    runLogPanel(env),
  ];
  for (const panel of panels) {
    bench.registerPanel(panel);
  }
  return env;
}

function whenPublished() {
  return new Promise((resolve) => {
    const poll = () => {
      if (window.hexbench) {
        resolve(window.hexbench);
        return;
      }
      window.setTimeout(poll, 10);
    };
    poll();
  });
}

whenPublished()
  .then((bench) => bench.ready.then(() => installPanels(bench)))
  .catch((error) => {
    const host = document.getElementById('dock-right');
    if (host !== null) {
      host.appendChild(banner('error', 'The panels could not start', String(error && error.message ? error.message : error)));
    }
  });
