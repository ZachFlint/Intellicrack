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

import { callOp, getReference, listJobs, readWindow, toHex } from './api.js';
import { tokenHex } from './charts.js';
import { createOperationConsole } from './console.js';
import { iconButton, nextId, trapFocus } from './dom.js';
import { clearSuggestionCache, element, hexOf, humanSize, openArgumentDialog } from './forms.js';
import { actionButton, banner, emptyState, fetchRaw, renderError, renderResult } from './renderers.js';


const INSPECT_DEBOUNCE_MS = 90;
const OFFSET_DIGITS = 8;
const DIFF_CAP = 1048576;
const DEFAULT_MIN_STRING = 5;
const DEFAULT_STRING_LIMIT = 2048;
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

  const run = async (name, args, handle) => {
    const result = await callOp(name, { handle, arguments: args });
    if (result.created_handle) {
      await bench.reload(result.created_handle);
    } else if (result.document && (MUTATING_REFRESH.has(name) || result.document.generation !== bench.activeDocument()?.generation)) {
      await bench.reload(result.document.handle);
    }
    if (MUTATING_REFRESH.has(name)) {
      clearSuggestionCache();
      bench.grid.invalidate();
    }
    bench.emit('operation', { name, result });
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
  let filter = null;
  let templates = [];
  let resultHost = null;
  let lastHandle = '';

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
      .then((result) => resultHost.replaceChildren(renderResult('apply_template', result, env.resultContext(args, context.handle))))
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
        subtitle.textContent = `${templates.length} templates`;
        paint();
      })
      .catch((error) => body.replaceChildren(renderError(error)));
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
      host.append(built.header, body);
      reload();
    },
    update: (context) => {
      const handle = context.document?.handle ?? '';
      if (handle === lastHandle || body === null) {
        return;
      }
      lastHandle = handle;
      reload();
    },
  };
}

/* ------------------------------------------------------ panel: va mappings */

function vaMappingsPanel(env) {
  let body = null;
  let subtitle = null;
  let tableHost = null;
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

  const reload = () => {
    const context = env.formContext();
    if (!context.handle) {
      count = 0;
      body.replaceChildren(emptyState('No document', 'Mappings belong to an open document.', '⇄'));
      return;
    }
    callOp('list_va_mappings', { handle: context.handle, arguments: {} })
      .then((result) => {
        const rows = Array.isArray(result.value) ? result.value : [];
        count = rows.length;
        subtitle.textContent = `${count} mapping${count === 1 ? '' : 's'}`;
        tableHost.replaceChildren(renderResult('list_va_mappings', result, env.resultContext({}, context.handle)));
        if (rows.length > 0) {
          const remove = element('div', 'hb-row-flex');
          remove.appendChild(element('span', 'hb-dim', 'remove'));
          rows.forEach((_row, index) => {
            remove.appendChild(actionButton(String(index), `Remove mapping ${index}`, () => {
              env.run('remove_va_mapping', { index }, context.handle)
                .then(() => reload())
                .catch((error) => env.toast('error', 'Remove failed', error.message));
            }));
          });
          tableHost.appendChild(remove);
        }
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
      body = element('div', 'hb-panel-body is-padded hb-stack');
      tableHost = element('div', 'hb-stack');
      body.append(tableHost, converter());
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
  let resultHost = null;
  let controlHost = null;
  let lastDocuments = '';

  const documentOptions = () => env.bench.documents().map((info) => ({ value: info.handle, label: `${info.label} (${humanSize(info.length)})` }));

  const select = (options) => {
    const node = document.createElement('select');
    node.className = 'hb-select';
    for (const option of options) {
      node.appendChild(new Option(option.label, option.value));
    }
    return node;
  };

  const buildControls = () => {
    const stack = element('div', 'hb-stack');

    const documents = element('div', 'hb-stack');
    documents.appendChild(element('div', 'hb-panel-title', 'diff_bytes — two open documents'));
    const options = documentOptions();
    const first = select(options);
    const second = select(options);
    if (options.length > 1) {
      second.value = options[1].value;
    }
    const documentsRow = element('div', 'hb-field-row');
    documentsRow.append(first, element('span', 'hb-dim', 'vs'), second);
    documentsRow.appendChild(actionButton('compare', 'Read both documents and compare their bytes', () => {
      const left = env.bench.documents().find((info) => info.handle === first.value);
      const right = env.bench.documents().find((info) => info.handle === second.value);
      if (!left || !right) {
        env.toast('warning', 'Pick two documents', 'diff_bytes needs two open documents.');
        return;
      }
      busy(resultHost, 'reading both documents…');
      Promise.all([
        readWindow(left.handle, 0, Math.min(left.length, DIFF_CAP)),
        readWindow(right.handle, 0, Math.min(right.length, DIFF_CAP)),
      ])
        .then(([a, b]) => {
          const args = { data_a: toHex(a.bytes).toLowerCase(), data_b: toHex(b.bytes).toLowerCase() };
          const capped = left.length > DIFF_CAP || right.length > DIFF_CAP;
          return env.run('diff_bytes', args, null).then((result) => {
            subtitle.textContent = `${left.label} vs ${right.label}`;
            resultHost.replaceChildren(renderResult('diff_bytes', result, env.resultContext(args, null)));
            if (capped) {
              resultHost.prepend(banner('warning', `Compared the first ${humanSize(DIFF_CAP)} of each`, 'A longer document is read through the window endpoint, which caps a single read at one mebibyte.'));
            }
          });
        })
        .catch((error) => resultHost.replaceChildren(renderError(error)));
    }, 'hb-btn is-sm is-primary'));
    documents.append(documentsRow, element('div', 'hb-arg-hint', 'Bytes are read out of the open documents, so an unsaved edit is compared as it stands.'));

    const files = element('div', 'hb-stack');
    files.appendChild(element('div', 'hb-panel-title', 'diff_files — two paths on this machine'));
    const filesRow = element('div', 'hb-field-row');
    filesRow.appendChild(actionButton('choose paths…', 'Open the diff_files form', () => promptAndRun(env, 'diff_files', {})));
    files.append(filesRow, element('div', 'hb-arg-hint', 'The paths are resolved by the server process; a missing file is an OSError rather than an empty diff.'));

    stack.append(documents, files);
    return stack;
  };

  return {
    id: 'panels.diff',
    title: 'Diff',
    dock: 'bottom',
    side: 'bottom',
    order: 30,
    mount: (host) => {
      const built = panelHeader('difference', 'nothing compared');
      subtitle = built.subtitle;
      body = element('div', 'hb-panel-body is-padded hb-stack');
      resultHost = element('div', 'hb-stack');
      controlHost = element('div');
      controlHost.appendChild(buildControls());
      lastDocuments = env.bench.documents().map((info) => info.handle).join(',');
      body.append(controlHost, resultHost);
      host.append(built.header, body);
      resultHost.replaceChildren(emptyState('Nothing compared yet', 'Pick two open documents, or two paths on this machine.', '⇔'));
    },
    update: (context) => {
      if (controlHost === null) {
        return;
      }
      const handles = context.documents.map((info) => info.handle).join(',');
      if (handles === lastDocuments) {
        return;
      }
      lastDocuments = handles;
      controlHost.replaceChildren(buildControls());
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
  'panels.console',
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
    createOperationConsole(env),
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
