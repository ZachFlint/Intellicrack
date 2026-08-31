/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Gates A-4 and A-5: the dock strips and the document strip are two visually
 * identical systems, so they must answer to one keyboard and one set of roles,
 * and neither may cost a tab stop per tab.
 *
 * The shared contract lives in dom.js, which touches no DOM at module scope and
 * so is driven here for real against a small node model: roles are applied to
 * strips built the way the shell builds them, keys are dispatched, and the calls
 * the strips make back into their owners are recorded. The strips the model
 * builds are pinned to the two real builders by the source checks at the end --
 * `Dock.renderTabs` needs a whole dock and `#renderTabs` a whole Shell, so what
 * cannot be constructed here is instead held to the shape that can.
 *
 * Run by gate.ps1 (or directly with node). Exits non-zero on failure.
 */

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const failures = [];

function check(label, condition, detail) {
  if (!condition) {
    failures.push(`${label}: ${detail}`);
  }
}

/* ============================================================ the node model */

class FakeNode {
  constructor(tag) {
    this.localName = tag;
    this.tagName = tag.toUpperCase();
    this.attributes = new Map();
    this.children = [];
    this.parent = null;
    this.listeners = new Map();
    this.className = '';
    this.textContent = '';
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  removeAttribute(name) {
    this.attributes.delete(name);
  }

  hasAttribute(name) {
    return this.attributes.has(name);
  }

  appendChild(node) {
    node.parent = this;
    this.children.push(node);
    return node;
  }

  append(...nodes) {
    for (const node of nodes) {
      this.appendChild(node);
    }
  }

  addEventListener(type, handler) {
    const bucket = this.listeners.get(type) ?? [];
    bucket.push(handler);
    this.listeners.set(type, bucket);
  }

  dispatch(type, event) {
    for (const handler of this.listeners.get(type) ?? []) {
      handler(event);
    }
  }

  contains(node) {
    for (let cursor = node; cursor !== null && cursor !== undefined; cursor = cursor.parent) {
      if (cursor === this) {
        return true;
      }
    }
    return false;
  }

  /** The nearest ancestor-or-self matching a class or attribute selector, which is all the module asks for. */
  closest(selector) {
    for (let cursor = this; cursor !== null && cursor !== undefined; cursor = cursor.parent) {
      if (selector.startsWith('.')) {
        if (cursor.className.split(/\s+/).includes(selector.slice(1))) {
          return cursor;
        }
      } else if (cursor.hasAttribute(selector.slice(1, -1))) {
        return cursor;
      }
    }
    return null;
  }

  focus() {
    globalThis.document.activeElement = this;
  }
}

globalThis.document = {
  activeElement: null,
  createElement(tag) {
    return new FakeNode(tag);
  },
  querySelector() {
    return null;
  },
  getElementById() {
    return null;
  },
  addEventListener() {},
  removeEventListener() {},
};
globalThis.window = { location: { search: '' } };
globalThis.HTMLElement = FakeNode;

const staticDir = fileURLToPath(new URL('../static/', import.meta.url));
const shellSource = (await readFile(`${staticDir}shell.js`, 'utf8')).replace(/\r\n/g, '\n');

const { applyTabStripRoles, element, iconButton, wireTabStrip } = await import('../static/dom.js');

/* ======================================================== the two real strips */

/** A dock strip: one button per panel, keyed by data-panel, with an optional count pill. */
function buildDockStrip(panels, activeId) {
  const strip = element('div', 'hb-dock-tabs');
  const body = element('div', 'hb-dock-body');
  for (const panel of panels) {
    const tab = element('button', panel.id === activeId ? 'hb-dock-tab is-active' : 'hb-dock-tab');
    tab.setAttribute('data-panel', panel.id);
    tab.textContent = panel.title;
    if (panel.count !== undefined) {
      tab.appendChild(element('span', 'hb-dock-tab-count', String(panel.count), {
        'aria-label': `${panel.count} ${panel.title.toLowerCase()}`,
      }));
    }
    strip.appendChild(tab);
  }
  return { strip, body };
}

/** A document strip: one div per document, keyed by data-handle, each carrying a close button keyed the same way. */
function buildDocumentStrip(documents, activeHandle) {
  const strip = element('div', 'hb-tabstrip');
  const host = element('div', 'hb-main');
  for (const info of documents) {
    const tab = element('div', info.handle === activeHandle ? 'hb-tab is-active' : 'hb-tab', undefined, { 'aria-label': info.label });
    tab.setAttribute('data-handle', info.handle);
    tab.appendChild(element('span', 'hb-tab-title', info.label));
    const close = iconButton('✕', `Close ${info.label}`, undefined, 'hb-tab-close');
    close.setAttribute('data-handle', info.handle);
    close.setAttribute('tabindex', '-1');
    tab.appendChild(close);
    strip.appendChild(tab);
  }
  return { strip, host };
}

function tabsOf(strip) {
  return strip.children.filter((child) => child.getAttribute('role') === 'tab');
}

/** The one test both strips have to pass, run against each of them. */
function assertTablist(name, strip, panel, keyAttribute, activeKey, label) {
  check(`${name}: the strip declares itself a tablist`, strip.getAttribute('role') === 'tablist', `expected role=tablist, got ${JSON.stringify(strip.getAttribute('role'))}`);
  check(`${name}: the strip carries a name`, strip.getAttribute('aria-label') === label, `expected aria-label ${JSON.stringify(label)}, got ${JSON.stringify(strip.getAttribute('aria-label'))}`);

  const tabs = tabsOf(strip);
  check(`${name}: every tab in the strip took the tab role`, tabs.length === strip.children.length, `${strip.children.length} children but only ${tabs.length} tabs`);

  const selected = tabs.filter((tab) => tab.getAttribute('aria-selected') === 'true');
  check(`${name}: exactly one tab reports itself selected`, selected.length === 1, `${selected.length} tabs claim aria-selected=true`);
  check(
    `${name}: the selected tab is the active one`,
    selected[0]?.getAttribute(`data-${keyAttribute}`) === activeKey,
    `expected ${JSON.stringify(activeKey)} selected, got ${JSON.stringify(selected[0]?.getAttribute(`data-${keyAttribute}`))}`,
  );

  const tabbable = tabs.filter((tab) => tab.getAttribute('tabindex') === '0');
  check(`${name}: the whole strip is one tab stop`, tabbable.length === 1, `${tabbable.length} tabs are in the tab order; a strip of a dozen documents would cost a dozen Tab presses`);
  check(`${name}: the one tab stop is the selected tab`, tabbable[0] === selected[0], 'the roving tab stop is not on the selected tab');

  check(`${name}: the body it controls is a tabpanel`, panel.getAttribute('role') === 'tabpanel', `expected role=tabpanel, got ${JSON.stringify(panel.getAttribute('role'))}`);
  check(
    `${name}: every tab points at that panel`,
    tabs.every((tab) => tab.getAttribute('aria-controls') === panel.getAttribute('id')) && panel.getAttribute('id') !== null,
    'aria-controls does not name the panel the strip drives',
  );
  check(
    `${name}: the panel is named by its selected tab`,
    panel.getAttribute('aria-labelledby') === selected[0]?.getAttribute('id') && selected[0]?.getAttribute('id') !== null,
    `expected aria-labelledby ${JSON.stringify(selected[0]?.getAttribute('id'))}, got ${JSON.stringify(panel.getAttribute('aria-labelledby'))}`,
  );
}

function press(strip, target, key) {
  let prevented = false;
  strip.dispatch('keydown', {
    key,
    target,
    preventDefault() {
      prevented = true;
    },
  });
  return prevented;
}

/* ------------------------------------------------------------ the dock strip */

const PANELS = [
  { id: 'shell.inspector', title: 'Inspector' },
  { id: 'panels.strings', title: 'Strings', count: 212 },
  { id: 'shell.activity', title: 'Activity' },
];

let dockActive = 'panels.strings';
const dock = buildDockStrip(PANELS, dockActive);
const dockActivations = [];
wireTabStrip(dock.strip, {
  keyAttribute: 'panel',
  onActivate: (id) => {
    dockActive = id;
    dockActivations.push(id);
  },
});
applyTabStripRoles(dock.strip, { keyAttribute: 'panel', activeKey: dockActive, panel: dock.body, label: 'Bottom dock panels' });

assertTablist('dock strip', dock.strip, dock.body, 'panel', 'panels.strings', 'Bottom dock panels');

const stringsTab = tabsOf(dock.strip)[1];
check(
  'the count pill is read as a measurement rather than as part of the tab name',
  stringsTab.children[0]?.getAttribute('aria-label') === '212 strings',
  `expected the pill to name its unit ("212 strings"), got ${JSON.stringify(stringsTab.children[0]?.getAttribute('aria-label'))}`,
);
check(
  'the count pill is not itself a tab',
  stringsTab.children[0]?.getAttribute('role') !== 'tab',
  'a child of a tab took the tab role, so the strip would report more tabs than it has',
);

check('ArrowRight moves to the next dock panel', press(dock.strip, stringsTab, 'ArrowRight') && dockActivations.at(-1) === 'shell.activity', `expected shell.activity, got ${JSON.stringify(dockActivations.at(-1))}`);
check('ArrowRight wraps round the dock strip', press(dock.strip, tabsOf(dock.strip)[2], 'ArrowRight') && dockActivations.at(-1) === 'shell.inspector', `expected shell.inspector, got ${JSON.stringify(dockActivations.at(-1))}`);
check('ArrowLeft moves back', press(dock.strip, tabsOf(dock.strip)[1], 'ArrowLeft') && dockActivations.at(-1) === 'shell.inspector', `expected shell.inspector, got ${JSON.stringify(dockActivations.at(-1))}`);
check('End reaches the last panel', press(dock.strip, tabsOf(dock.strip)[0], 'End') && dockActivations.at(-1) === 'shell.activity', `expected shell.activity, got ${JSON.stringify(dockActivations.at(-1))}`);
check('Home reaches the first panel', press(dock.strip, tabsOf(dock.strip)[2], 'Home') && dockActivations.at(-1) === 'shell.inspector', `expected shell.inspector, got ${JSON.stringify(dockActivations.at(-1))}`);

const beforeStray = dockActivations.length;
press(dock.strip, dock.strip, 'ArrowRight');
check('a key pressed on the strip itself activates nothing', dockActivations.length === beforeStray, 'the strip reacted to a key that was not pressed on a tab');

/* -------------------------------------------------------- the document strip */

const DOCUMENTS = [
  { handle: 'doc-a', label: 'kernel32.dll' },
  { handle: 'doc-b', label: 'firmware.bin' },
  { handle: 'doc-c', label: 'scratch' },
];

let documentActive = 'doc-a';
const docs = buildDocumentStrip(DOCUMENTS, documentActive);
const documentActivations = [];
const documentCloses = [];
wireTabStrip(docs.strip, {
  keyAttribute: 'handle',
  onActivate: (handle) => {
    documentActive = handle;
    documentActivations.push(handle);
  },
  onClose: (handle) => documentCloses.push(handle),
  ignoreSelector: '.hb-tab-close',
});
applyTabStripRoles(docs.strip, { keyAttribute: 'handle', activeKey: documentActive, panel: docs.host, label: 'Open documents' });

assertTablist('document strip', docs.strip, docs.host, 'handle', 'doc-a', 'Open documents');

const firstTab = tabsOf(docs.strip)[0];
const firstClose = firstTab.children.find((child) => child.className === 'hb-tab-close');
check(
  'the close button inside a tab is not read as a tab of its own',
  firstClose !== undefined && firstClose.getAttribute('role') !== 'tab',
  'the close button carries the same data-handle as its tab, and it has been treated as a second tab',
);
check(
  'the close button is out of the tab order',
  firstClose?.getAttribute('tabindex') === '-1',
  'a close button per document puts the strip back to one tab stop per tab',
);

check('ArrowRight moves to the next document', press(docs.strip, firstTab, 'ArrowRight') && documentActivations.at(-1) === 'doc-b', `expected doc-b, got ${JSON.stringify(documentActivations.at(-1))}`);
check('ArrowLeft wraps to the last document', press(docs.strip, firstTab, 'ArrowLeft') && documentActivations.at(-1) === 'doc-c', `expected doc-c, got ${JSON.stringify(documentActivations.at(-1))}`);
check('Delete closes the focused document', press(docs.strip, tabsOf(docs.strip)[1], 'Delete') && documentCloses.at(-1) === 'doc-b', `expected doc-b closed, got ${JSON.stringify(documentCloses.at(-1))}`);

const activationsBeforeClose = documentActivations.length;
press(docs.strip, firstClose, 'Enter');
check(
  'Enter on a close button is left to the close button',
  documentActivations.length === activationsBeforeClose,
  'Enter on the close button activated the tab instead of letting the button close it',
);
check('Enter on a tab activates it', press(docs.strip, tabsOf(docs.strip)[2], 'Enter') && documentActivations.at(-1) === 'doc-c', `expected doc-c, got ${JSON.stringify(documentActivations.at(-1))}`);

/* ----------------------------------------- the strips the shell actually builds */

check(
  'the dock binds the shared strip keyboard once, at construction',
  /wireTabStrip\(this\.#tabs, \{ keyAttribute: 'panel', onActivate: \(id\) => this\.activate\(id\) \}\);/.test(shellSource),
  'the dock no longer wires wireTabStrip, so Arrow keys cannot move between dock panels',
);
check(
  'the dock re-applies the roles after every render',
  /applyTabStripRoles\(this\.#tabs, \{\s*\n\s*keyAttribute: 'panel',\s*\n\s*activeKey: this\.#active === '' \? null : this\.#active,\s*\n\s*panel: this\.#body,\s*\n\s*label: this\.#label,\s*\n\s*\}\);/.test(shellSource),
  'Dock.renderTabs no longer re-applies the tablist roles; the strip rebuilds its children wholesale, so the roles would be lost on the first re-render',
);
check(
  'each dock strip is given a name of its own',
  /new Dock\(nodes\.dockRight, 'Right dock panels'\)/.test(shellSource) && /new Dock\(nodes\.dockBottom, 'Bottom dock panels'\)/.test(shellSource),
  'the two dock strips are no longer named, so a screen reader announces two unnamed tablists',
);
check(
  'the dock count pill names its unit',
  /'aria-label': `\$\{count\} \$\{panel\.title\.toLowerCase\(\)\}`/.test(shellSource),
  'the dock tab count no longer carries an aria-label, so "Strings 212" is read as the tab name with a unitless number in it',
);

check(
  'the document strip binds the same shared keyboard',
  /wireTabStrip\(this\.#nodes\.tabstrip, \{\s*\n\s*keyAttribute: 'handle',\s*\n\s*onActivate: \(handle\) => this\.activate\(handle\),\s*\n\s*onClose: \(handle\) => this\.close\(handle\),\s*\n\s*ignoreSelector: '\.hb-tab-close',\s*\n\s*\}\);/.test(shellSource),
  '#bindTabs no longer wires wireTabStrip with a close route and the close-button exception, so Delete cannot close a tab (or Enter on the close button activates instead of closing)',
);
check(
  'the document strip re-applies the roles after every render',
  /applyTabStripRoles\(this\.#nodes\.tabstrip, \{\s*\n\s*keyAttribute: 'handle',\s*\n\s*activeKey: this\.#active\?\.handle \?\? null,\s*\n\s*panel: this\.#nodes\.editorHost,\s*\n\s*label: 'Open documents',\s*\n\s*\}\);/.test(shellSource),
  '#renderTabs no longer re-applies the tablist roles, so a rebuilt strip loses its roving tabindex and its aria-selected',
);
check(
  '#renderTabs no longer stamps the tab roles by hand',
  !/role: 'tab',\s*\n\s*tabindex: '0',/.test(shellSource),
  '#renderTabs is stamping role and tabindex itself again, so every tab is a tab stop and the shared helper is being fought rather than used',
);
check(
  'the close button is built out of the tab order',
  /close\.tabIndex = -1;/.test(shellSource),
  '#renderTabs no longer takes the close buttons out of the tab order, so a dozen documents cost two dozen Tab presses',
);
check(
  'the strip keeps its own click and middle-click routes',
  /const close = target\.closest\('\.hb-tab-close'\);/.test(shellSource) && /if \(event\.button !== 1\)/.test(shellSource),
  'the pointer routes into the tab strip were dropped along with the old keydown handler',
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} tab strip expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('dock and document tab strips (A-4, A-5): all expectations held\n');
