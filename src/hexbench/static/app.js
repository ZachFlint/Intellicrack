/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Zachary Flint
   This file is part of Intellicrack. See LICENSE for details.

   Start-up. Collects the shell's elements, builds the grid, the chrome and the
   palette, publishes the integration surface on window.hexbench, and then does
   nothing else; every behaviour lives in the module that owns it. */

import * as api from './api.js';
import { CommandPalette } from './palette.js';
import { Shell } from './shell.js';


function byId(id) {
  const node = document.getElementById(id);
  if (node === null) {
    throw new Error(`the application document is missing #${id}`);
  }
  return node;
}

function collectNodes() {
  return {
    menubar: byId('menubar'),
    toolbar: byId('toolbar'),
    tabstrip: byId('tabstrip'),
    workspace: byId('workspace'),
    editorHost: byId('editor-host'),
    dockRight: byId('dock-right'),
    dockBottom: byId('dock-bottom'),
    splitterV: byId('splitter-v'),
    splitterH: byId('splitter-h'),
    overlays: byId('overlays'),
    toasts: byId('toasts'),
    status: {
      dot: byId('status-dot'),
      state: byId('status-state'),
      offset: byId('status-offset'),
      pane: byId('status-pane'),
      selection: byId('status-selection'),
      hits: byId('status-hits'),
      size: byId('status-size'),
      entropy: byId('status-entropy'),
      scale: byId('status-scale'),
      scaleItem: byId('status-scale-item'),
      modified: byId('status-modified'),
      modifiedItem: byId('status-modified-item'),
      mode: byId('status-mode'),
    },
  };
}

function fatal(host, error) {
  const banner = document.createElement('div');
  banner.className = 'hb-banner is-error';
  const glyph = document.createElement('span');
  glyph.className = 'hb-banner-glyph';
  glyph.textContent = '!';
  const body = document.createElement('div');
  body.className = 'hb-banner-body';
  const title = document.createElement('div');
  title.className = 'hb-banner-title';
  title.textContent = 'Hexbench could not start';
  const detail = document.createElement('div');
  detail.className = 'hb-banner-detail';
  detail.textContent = error instanceof api.DispatchError
    ? `${error.kind}: ${error.message}`
    : String(error && error.message ? error.message : error);
  body.append(title, detail);
  if (error instanceof api.DispatchError && error.kind === 'transport') {
    const hint = document.createElement('div');
    hint.className = 'hb-banner-detail';
    hint.textContent = 'The session ended with the window that opened it. Start Hexbench again to get a new one.';
    body.appendChild(hint);
  }
  banner.append(glyph, body);
  host.replaceChildren(banner);
}

/**
 * The surface other modules integrate against.
 *
 * `openOperation` is deliberately a writable property rather than a method: a
 * panel module that builds a proper argument form replaces it, and everything
 * that wants a form — the palette, the menus, the shell — goes through this one
 * name. The default assigned here is the shell's own JSON-argument form, so the
 * application is complete on its own.
 */
function publish(shell, palette, ready) {
  const hexbench = {
    api,
    shell,
    palette,
    ready,
    catalog: null,
    get grid() {
      return shell.grid;
    },
    openOperation(name) {
      shell.promptOperation(name).catch((error) => shell.reportError(error));
    },
    registerPanel: (panel) => shell.registerPanel(panel),
    unregisterPanel: (id) => shell.unregisterPanel(id),
    context: () => shell.context(),
    documents: () => shell.documents,
    activeDocument: () => shell.activeDocument,
    operation: (name) => shell.operation(name),
    run: (command) => shell.run(command),
    reload: (handle) => shell.reload(handle),
    refresh: () => shell.refresh(),
    seek: (offset) => shell.grid.seek(offset),
    select: (offset, length) => shell.grid.select(offset, length),
    highlight: (ranges, className) => shell.grid.highlight(ranges, className),
    setHits: (pairs) => shell.setHits(pairs),
    toast: (kind, title, detail) => shell.toasts.show(kind, title, detail),
    dialog: (spec) => shell.dialogs.form(spec),
    showResult: (title, meta, value) => shell.dialogs.result(title, meta, value),
    on: (name, handler) => shell.on(name, handler),
    off: (name, handler) => shell.off(name, handler),
    emit: (name, detail) => shell.emit(name, detail),
  };
  window.hexbench = hexbench;
  return hexbench;
}

async function boot() {
  const nodes = collectNodes();
  const shell = new Shell(nodes);
  const palette = new CommandPalette(nodes.overlays, {
    onRun: (operation) => shell.invoke(operation, {}).catch((error) => shell.reportError(error)),
    onOpen: (name) => shell.openOperation(name),
  });
  shell.attachPalette(palette);

  let settle = () => undefined;
  const ready = new Promise((resolve) => {
    settle = resolve;
  });
  const hexbench = publish(shell, palette, ready);

  api.startHeartbeat();

  const catalog = await api.getCatalog();
  shell.setCatalog(catalog);
  palette.setCatalog(catalog);
  hexbench.catalog = catalog;
  shell.emit('catalog', catalog);

  await shell.reload();
  shell.grid.focus();
  settle(hexbench);
  shell.emit('ready', hexbench);
}

boot().catch((error) => {
  const host = document.getElementById('editor-host');
  if (host !== null) {
    fatal(host, error);
  }
});
