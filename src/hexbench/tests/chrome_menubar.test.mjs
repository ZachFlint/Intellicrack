/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Gates A-3: the menu bar has to implement the keyboard its `menubar` role has
 * been announcing (WCAG 2.1.1).
 *
 * `bindMenubarKeys` is a module-level function of a bar element and a small
 * controller, so it is bound to a real (small) node model here and driven with
 * real keydown events: focus really moves, `open`/`close` are really called, and
 * every assertion below reads the state those calls left behind. Only the two
 * things the browser owns -- creating a node and delivering an event to the
 * listeners on the way up -- are modelled.
 *
 * The menu entries the model builds are the shape `#toggleMenu` builds them in,
 * so the last section reads shell.js as text and pins that shape: the role, the
 * disabled marking, the label element and the tab stop. Change the markup
 * without changing the double and those checks go red rather than leaving this
 * suite passing against a menu that no longer exists.
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
    this.ownText = '';
  }

  get textContent() {
    return this.children.length === 0 ? this.ownText : this.children.map((child) => child.textContent).join('');
  }

  set textContent(value) {
    this.ownText = String(value);
    this.children = [];
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
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

  replaceChildren() {
    this.children = [];
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

  focus() {
    globalThis.document.activeElement = this;
  }

  descendants() {
    const found = [];
    for (const child of this.children) {
      found.push(child, ...child.descendants());
    }
    return found;
  }

  /** Class selectors only, which is all the module under test asks of a node. */
  querySelector(selector) {
    if (!selector.startsWith('.')) {
      throw new Error(`the node model cannot evaluate the selector ${selector}`);
    }
    const wanted = selector.slice(1);
    return this.descendants().find((node) => node.className.split(/\s+/).includes(wanted)) ?? null;
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

const { element } = await import('../static/dom.js');
const { bindMenubarKeys } = await import('../static/shell.js');

/* =========================================================== the bar and its menus */

/* One entry per line: label, and whether the command behind it is enabled. */
const FILE_ENTRIES = [
  ['New document', true],
  ['-', false],
  ['Save', true],
  ['Save as…', true],
];

const EDIT_ENTRIES = [
  ['Undo', false],
  ['Redo', true],
  ['Select all', true],
];

const VIEW_ENTRIES = [
  ['Go to offset…', true],
  ['Toggle theme', true],
];

/**
 * Build the menu bar the way `#buildMenus` and `#toggleMenu` build it.
 *
 * @param {Array<Array<Array<string|boolean>>>} specs One entry list per menu.
 * @returns {Object} The bar, its buttons, and the controller `bindMenubarKeys` was given.
 */
function buildBar(specs) {
  const menubar = new FakeNode('div');
  menubar.setAttribute('role', 'menubar');
  const buttons = [];
  const popups = [];
  const closes = [];
  let openIndex = -1;

  for (const [index] of specs.entries()) {
    const holder = element('div', 'hb-menu');
    const button = element('button', 'hb-menu-item', `Menu ${index}`, { type: 'button', role: 'menuitem' });
    button.setAttribute('tabindex', index === 0 ? '0' : '-1');
    const popup = element('div', 'hb-menu-popup', undefined, { role: 'menu' });
    holder.append(button, popup);
    menubar.appendChild(holder);
    buttons.push(button);
    popups.push(popup);
  }

  const fill = (index) => {
    const popup = popups[index];
    popup.replaceChildren();
    for (const [label, enabled] of specs[index]) {
      if (label === '-') {
        popup.appendChild(element('div', 'hb-menu-sep', undefined, { role: 'separator' }));
        continue;
      }
      const item = element('button', enabled ? 'hb-menu-entry' : 'hb-menu-entry is-disabled', undefined, {
        type: 'button',
        role: 'menuitem',
        tabindex: '-1',
      });
      item.appendChild(element('span', 'hb-menu-entry-label', label));
      item.appendChild(element('span', 'hb-menu-shortcut', ''));
      if (!enabled) {
        item.setAttribute('aria-disabled', 'true');
      }
      popup.appendChild(item);
    }
  };

  const controller = {
    buttons: () => buttons,
    openIndex: () => openIndex,
    popup: () => (openIndex === -1 ? null : popups[openIndex]),
    open: (index) => {
      openIndex = index;
      fill(index);
    },
    close: (returnFocus) => {
      closes.push(returnFocus);
      const wasOpen = openIndex;
      openIndex = -1;
      if (returnFocus && wasOpen !== -1) {
        buttons[wasOpen].focus();
      }
    },
  };

  bindMenubarKeys(menubar, controller);
  return { menubar, buttons, popups, closes, controller };
}

function press(bar, key, extras = {}) {
  let prevented = false;
  bar.menubar.dispatch('keydown', {
    key,
    ctrlKey: false,
    altKey: false,
    metaKey: false,
    shiftKey: false,
    ...extras,
    target: globalThis.document.activeElement,
    preventDefault() {
      prevented = true;
    },
  });
  return prevented;
}

/** The label of whatever holds focus, so an assertion reads as the entry a user would see. */
function focusedLabel() {
  const node = globalThis.document.activeElement;
  if (node === null) {
    return null;
  }
  const label = node.querySelector('.hb-menu-entry-label');
  return label === null ? node.textContent : label.textContent;
}

/* ------------------------------------------------- opening a menu from its button */

const bar = buildBar([FILE_ENTRIES, EDIT_ENTRIES, VIEW_ENTRIES]);
bar.buttons[0].focus();

const openedByDown = press(bar, 'ArrowDown');
check('ArrowDown on a menu button opens that menu', bar.controller.openIndex() === 0, `expected the File menu open, got index ${bar.controller.openIndex()}`);
check('ArrowDown claims the key rather than scrolling the window', openedByDown, 'the handler did not preventDefault, so the page scrolls out from under the menu it just opened');
check(
  'opening puts focus on the first enabled entry',
  focusedLabel() === 'New document',
  `expected focus on "New document", got ${JSON.stringify(focusedLabel())}`,
);

check(
  'first-letter typeahead reaches an entry further down the menu',
  press(bar, 's') && focusedLabel() === 'Save',
  `expected typeahead "s" to focus "Save", got ${JSON.stringify(focusedLabel())}`,
);
check(
  'typeahead is a movement, not an activation',
  bar.controller.openIndex() === 0 && bar.closes.length === 0,
  'typing a letter closed the menu; it must only move focus inside it',
);

const enterOnEntry = press(bar, 'Enter');
check(
  'Enter on an entry is left to the browser, which clicks the button',
  enterOnEntry === false,
  'the handler claimed Enter on a menu entry; the entry is a real button with its own click listener, so claiming the key here either runs the command twice or (with no handler of its own) never at all',
);

press(bar, 'Escape');
check('Escape closes the open menu', bar.controller.openIndex() === -1, 'Escape left the menu open');
check('Escape asks for focus to be restored', bar.closes.at(-1) === true, `close() was called with ${JSON.stringify(bar.closes.at(-1))}; the opening button must get focus back`);
check(
  'Escape lands focus back on the button that opened the menu',
  globalThis.document.activeElement === bar.buttons[0],
  'focus was left on the entry of a menu that is no longer there',
);

/* ------------------------------------------- moving inside a menu skips the disabled */

const skips = buildBar([[['New document', true], ['-', false], ['Save', false], ['Save as…', true]]]);
skips.buttons[0].focus();
press(skips, 'ArrowDown');
check('the disabled fixture opens on its first enabled entry', focusedLabel() === 'New document', `got ${JSON.stringify(focusedLabel())}`);

press(skips, 'ArrowDown');
check(
  'ArrowDown steps over a disabled entry rather than focusing it',
  focusedLabel() === 'Save as…',
  `expected "Save as…", got ${JSON.stringify(focusedLabel())}; a disabled entry must be skipped, not focused`,
);
press(skips, 'ArrowDown');
check('ArrowDown wraps from the last entry to the first', focusedLabel() === 'New document', `expected "New document", got ${JSON.stringify(focusedLabel())}`);
press(skips, 'ArrowUp');
check('ArrowUp wraps backwards past the disabled entry', focusedLabel() === 'Save as…', `expected "Save as…", got ${JSON.stringify(focusedLabel())}`);
press(skips, 'Home');
check('Home goes to the first enabled entry', focusedLabel() === 'New document', `expected "New document", got ${JSON.stringify(focusedLabel())}`);
press(skips, 'End');
check('End goes to the last enabled entry', focusedLabel() === 'Save as…', `expected "Save as…", got ${JSON.stringify(focusedLabel())}`);
press(skips, 'Home');
check(
  'typeahead skips a disabled entry with the same first letter',
  press(skips, 's') && focusedLabel() === 'Save as…',
  `expected typeahead "s" to pass over the disabled "Save" and land on "Save as…", got ${JSON.stringify(focusedLabel())}`,
);
check(
  'a separator is never focused',
  globalThis.document.activeElement.getAttribute('role') === 'menuitem',
  `focus landed on a ${JSON.stringify(globalThis.document.activeElement.getAttribute('role'))}`,
);

/* --------------------------------------------------- moving across the bar itself */

const across = buildBar([FILE_ENTRIES, EDIT_ENTRIES, VIEW_ENTRIES]);
across.buttons[0].focus();

press(across, 'ArrowRight');
check('ArrowRight moves along the bar', globalThis.document.activeElement === across.buttons[1], 'ArrowRight did not move focus to the next menu button');
check('ArrowRight with nothing open does not open anything', across.controller.openIndex() === -1, 'walking the bar opened a menu the user did not ask for');
check(
  'the bar is one tab stop: only the focused button is tabbable',
  across.buttons[1].getAttribute('tabindex') === '0'
    && across.buttons.filter((button) => button.getAttribute('tabindex') === '0').length === 1,
  `expected exactly one tabbable button, got tabindexes ${JSON.stringify(across.buttons.map((button) => button.getAttribute('tabindex')))}`,
);

press(across, 'ArrowLeft');
press(across, 'ArrowLeft');
check('ArrowLeft wraps round to the last menu', globalThis.document.activeElement === across.buttons[2], 'ArrowLeft did not wrap to the end of the bar');

press(across, 'Home');
check('Home goes to the first menu', globalThis.document.activeElement === across.buttons[0], 'Home did not reach the first menu button');
press(across, 'End');
check('End goes to the last menu', globalThis.document.activeElement === across.buttons[2], 'End did not reach the last menu button');

across.buttons[0].focus();
const enterOnButton = press(across, 'Enter');
check('Enter on a menu button opens its menu', across.controller.openIndex() === 0, 'Enter did not open the menu');
check(
  'Enter on a menu button is claimed, so the browser cannot click the button shut again',
  enterOnButton,
  'the handler let Enter through to the button; the native click then toggles the menu closed the instant it opened',
);
check('Enter on a menu button focuses the first entry', focusedLabel() === 'New document', `got ${JSON.stringify(focusedLabel())}`);

press(across, 'ArrowRight');
check('ArrowRight from inside a menu moves to the next menu', across.controller.openIndex() === 1, `expected the second menu open, got ${across.controller.openIndex()}`);
check(
  'the next menu opens with focus on its first enabled entry',
  focusedLabel() === 'Redo',
  `expected "Redo" (the disabled "Undo" is skipped), got ${JSON.stringify(focusedLabel())}`,
);
check(
  'walking sideways moves the roving tab stop with the open menu',
  across.buttons[1].getAttribute('tabindex') === '0' && across.buttons[0].getAttribute('tabindex') === '-1',
  'the tab stop was left on the menu that is no longer open',
);

across.buttons[1].focus();
press(across, 'ArrowUp');
check(
  'ArrowUp on a menu button opens it from the bottom',
  focusedLabel() === 'Select all',
  `expected the last enabled entry "Select all", got ${JSON.stringify(focusedLabel())}`,
);

across.buttons[1].focus();
press(across, 'Escape');
check('Escape on the bar closes the open menu', across.controller.openIndex() === -1, 'Escape from the button left the menu open');

const closesBefore = across.closes.length;
press(across, 'Escape');
check('Escape with nothing open is not claimed', across.closes.length === closesBefore, 'Escape closed a menu that was not open; the key belongs to whatever else is listening');

/* ------------------------------------------------- the bar the shell actually builds */

check(
  '#buildMenus binds the keyboard contract to the menu bar',
  /bindMenubarKeys\(this\.#nodes\.menubar, \{/.test(shellSource),
  '#buildMenus no longer calls bindMenubarKeys, so everything exercised above is dead code and the menubar is eight dead tab stops again',
);
for (const member of ['buttons: \\(\\) =>', 'openIndex: \\(\\) =>', 'popup: \\(\\) =>', 'open: \\(index\\) =>', 'close: \\(returnFocus\\) =>']) {
  check(
    `the menubar controller supplies ${member.split(':')[0]}`,
    new RegExp(member).test(shellSource),
    `the controller handed to bindMenubarKeys no longer supplies ${member.split(':')[0]}, so that half of the contract cannot work`,
  );
}
check(
  'the keyboard route into a menu opens it through the shell\'s own toggle',
  /#openMenuAt\(index\) \{[\s\S]*?this\.#toggleMenu\(menu\.id, menu\.holder, menu\.button, menu\.popup, true\);/.test(shellSource),
  '#openMenuAt no longer forces #toggleMenu open, so a keyboard open could toggle the menu shut instead',
);
check(
  'Escape from a menu restores focus through #closeMenu(true)',
  /close: \(returnFocus\) => this\.#closeMenu\(returnFocus\)/.test(shellSource),
  'the controller no longer forwards returnFocus to #closeMenu, so Escape would abandon focus in a popup that is gone',
);
check(
  'the menu buttons start with a roving tab stop rather than eight of them',
  /button\.setAttribute\('tabindex', this\.#menus\.length === 0 \? '0' : '-1'\);/.test(shellSource),
  '#buildMenus no longer gives the menu buttons a roving tabindex, so every menu is its own tab stop again',
);

/* The entry markup the model above is built from, pinned to the source it doubles. */
check(
  'a menu entry is a button carrying the menuitem role and no tab stop of its own',
  /element\('button', enabled \? 'hb-menu-entry' : 'hb-menu-entry is-disabled', undefined, \{ type: 'button', role: 'menuitem', tabindex: '-1' \}\)/.test(shellSource),
  'the menu entry markup changed; the node model in this suite is built from it, so the two have to move together',
);
check(
  'a disabled entry is marked with aria-disabled, which is what movement skips',
  /item\.setAttribute\('aria-disabled', 'true'\);/.test(shellSource),
  'disabled entries are no longer marked with aria-disabled, so arrow movement can no longer tell which entries to skip',
);
check(
  'an entry carries its label in its own element, which is what typeahead reads',
  /element\('span', 'hb-menu-entry-label', command\.label\)/.test(shellSource),
  'the entry label element changed name or shape; typeahead reads .hb-menu-entry-label and would fall back to the label plus its shortcut',
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} menubar keyboard expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('menu bar keyboard (A-3): all expectations held\n');
