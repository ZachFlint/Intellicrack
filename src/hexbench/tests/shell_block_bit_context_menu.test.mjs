/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Gates BE-3: the Edit menu's block operations (`fill_block` already had a
 * menu entry; `copy_block`, `move_block` and `swap_blocks` did not) and the
 * grid's context menu, which did not exist at all - carrying that same
 * selection-scoped subset plus the three bit toggles (`get_bit`, `set_bit`,
 * `toggle_bit`), none of which had any surface either.
 *
 * Every parameter name below is taken verbatim from the Rust signatures in
 * intellicrack-hexcore/src/lib.rs (fill_block, copy_block, move_block,
 * swap_blocks, get_bit, set_bit, toggle_bit) - a renamed argument on either
 * side would silently turn a block or bit edit into a dispatch error the user
 * has no way to read as "the JS and the engine disagree about a parameter
 * name", the same technique shell_templates_transforms_numeric_search.test.mjs
 * uses for the numeric search calls.
 *
 * The context menu's keyboard contract is A-3's own `bindMenubarKeys`, reused
 * rather than reimplemented, given a controller with an empty button list.
 * That controller shape is exercised for real here, against the same real
 * `bindMenubarKeys` chrome_menubar.test.mjs drives with a full button set,
 * because an empty-buttons controller is a materially different configuration
 * of that contract and nothing else proves it does not fall through a branch
 * that assumed at least one button existed.
 *
 * shell.js transitively imports api.js, which reads `document`/`window` at
 * module scope, so both are stubbed with the bare minimum before it loads.
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
  querySelector: () => null,
  getElementById: () => null,
  addEventListener() {},
  removeEventListener() {},
};
globalThis.window = { location: { search: '' }, innerWidth: 1200, innerHeight: 800 };
globalThis.HTMLElement = FakeNode;

const staticDir = fileURLToPath(new URL('../static/', import.meta.url));
const rustSource = await readFile(fileURLToPath(new URL('../../intellicrack-hexcore/src/lib.rs', import.meta.url)), 'utf8');
const shellSource = (await readFile(`${staticDir}shell.js`, 'utf8')).replace(/\r\n/g, '\n');

const { element } = await import('../static/dom.js');
const { bindMenubarKeys } = await import('../static/shell.js');

/* -------------------------------------------------------- the engine truth */

function rustSignature(name) {
  const match = new RegExp(`fn ${name}\\(([\\s\\S]*?)\\)\\s*(?:->|\\{)`).exec(rustSource);
  if (match === null) {
    return null;
  }
  return [...match[1].matchAll(/(\w+):/g)].map((entry) => entry[1]).filter((param) => param !== 'self');
}

const EXPECTED_SIGNATURES = {
  fill_block: ['offset', 'length', 'pattern'],
  copy_block: ['src_offset', 'length', 'dst_offset'],
  move_block: ['src_offset', 'length', 'dst_offset'],
  swap_blocks: ['offset_a', 'len_a', 'offset_b', 'len_b'],
  get_bit: ['offset', 'bit_index'],
  set_bit: ['offset', 'bit_index', 'value'],
  toggle_bit: ['offset', 'bit_index'],
};

for (const [name, expected] of Object.entries(EXPECTED_SIGNATURES)) {
  check(
    `${name} could be located in lib.rs`,
    rustSignature(name) !== null,
    `fn ${name}(...) was not found in intellicrack-hexcore/src/lib.rs; this suite's ground truth has moved`,
  );
  check(
    `this suite's own record of ${name}'s parameters matches lib.rs`,
    JSON.stringify(rustSignature(name)) === JSON.stringify(expected),
    `lib.rs declares ${name}(${JSON.stringify(rustSignature(name))}), this suite expected ${JSON.stringify(expected)}`,
  );
}

/* --------------------------------------------------------- the Edit menu */

const editMenu = /id: 'edit',\s*\n\s*items: \[([\s\S]*?)\],\s*\n\s*\},/.exec(shellSource);
check('the edit menu could be located in MENUS', editMenu !== null, 'MENUS no longer declares an "edit" entry');
const editItems = editMenu ? editMenu[1] : '';
for (const command of ['edit.fill', 'edit.copyBlock', 'edit.moveBlock', 'edit.swapBlocks']) {
  check(`the Edit menu lists ${command}`, editItems.includes(`'${command}'`), `${command} is missing from the Edit menu, so the block operations have no menu entry point`);
}

/* --------------------------------------------------- the grid context menu */

const contextItems = /const GRID_CONTEXT_MENU_ITEMS = \[([\s\S]*?)\];/.exec(shellSource);
check('GRID_CONTEXT_MENU_ITEMS could be located in shell.js', contextItems !== null, 'the grid context menu item list was not found');
const contextItemsBody = contextItems ? contextItems[1] : '';
for (const command of ['edit.fill', 'edit.copyBlock', 'edit.moveBlock', 'edit.swapBlocks', 'edit.getBit', 'edit.setBit', 'edit.toggleBit']) {
  check(
    `the grid context menu carries ${command}`,
    contextItemsBody.includes(`'${command}'`),
    `${command} is missing from GRID_CONTEXT_MENU_ITEMS, so it has no context-menu entry point (there was no grid context menu at all before BE-3)`,
  );
}

check(
  'the grid gets a contextmenu listener, which is how the ContextMenu key and Shift+F10 reach it as well as a right-click',
  /#editorFrame\?\.addEventListener\('contextmenu', \(event\) => \{/.test(shellSource),
  'no listener answers the contextmenu event fired by a right-click, the ContextMenu key or Shift+F10',
);
check(
  'the context menu is built through the same entry loop the menubar popups use, not a second implementation',
  /this\.#populateMenuEntries\(popup, GRID_CONTEXT_MENU_ITEMS, \(\) => this\.#closeContextMenu\(\)\);/.test(shellSource),
  '#openGridContextMenu no longer routes through #populateMenuEntries, so its entries could disagree with the menubar\'s in role, disabled marking or shortcut text',
);
check(
  'the menubar popups are built through the same shared loop',
  /this\.#populateMenuEntries\(popup, spec\.items, \(\) => this\.#closeMenu\(\)\);/.test(shellSource),
  '#toggleMenu no longer routes through #populateMenuEntries; the entry-building loop has drifted into two copies',
);
check(
  'the context menu reuses A-3\'s keyboard contract rather than reimplementing it',
  /bindMenubarKeys\(popup, \{\s*\n\s*buttons: \(\) => \[\],\s*\n\s*openIndex: \(\) => -1,\s*\n\s*popup: \(\) => popup,/.test(shellSource),
  '#openGridContextMenu no longer calls bindMenubarKeys with an empty-button controller; a context menu needs Arrow/Home/End/typeahead/Escape and this is where A-3 already implements them',
);

/* --------------------------------------------- what each new command does */

function commandDefinition(id) {
  const escaped = id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = new RegExp(`this\\.#define\\('${escaped}', '[^']*', '[^']*', \\(\\) => (.*)\\);$`, 'm').exec(shellSource);
  if (match === null) {
    return null;
  }
  const gated = match[1].endsWith(', hasSelection') || match[1].endsWith(', hasDocument');
  const action = gated ? match[1].slice(0, match[1].lastIndexOf(',')) : match[1];
  const gate = match[1].endsWith(', hasSelection') ? 'hasSelection' : match[1].endsWith(', hasDocument') ? 'hasDocument' : null;
  return { action, gated, gate };
}

const EXPECTED_COMMANDS = [
  ['edit.copyBlock', 'this.copyBlock()', 'hasSelection'],
  ['edit.moveBlock', 'this.moveBlock()', 'hasSelection'],
  ['edit.swapBlocks', 'this.swapBlocks()', 'hasSelection'],
  ['edit.getBit', 'this.getBitAt()', 'hasDocument'],
  ['edit.setBit', 'this.setBitAt()', 'hasDocument'],
  ['edit.toggleBit', 'this.toggleBitAt()', 'hasDocument'],
];

for (const [id, expectedAction, expectedGate] of EXPECTED_COMMANDS) {
  const definition = commandDefinition(id);
  check(`${id} could be located as a #define(...) call`, definition !== null, `this.#define('${id}', ...) was not found in shell.js`);
  if (definition === null) {
    continue;
  }
  check(`${id} runs ${expectedAction}`, definition.action === expectedAction, `${id} runs "${definition.action}", expected "${expectedAction}"`);
  check(
    `${id} is gated on ${expectedGate}`,
    definition.gate === expectedGate,
    `${id} is gated on ${JSON.stringify(definition.gate)}, expected ${expectedGate} - a block op needs a selection, a bit op only needs an open document`,
  );
}

/* -------------------------------------------- the methods dispatch by name */

function methodSource(name) {
  const match = new RegExp(`  async ${name}\\(\\) \\{[\\s\\S]*?\\n  \\}\\n`).exec(shellSource);
  return match === null ? null : match[0];
}

const copyBlockSource = methodSource('copyBlock');
check('copyBlock() could be located in shell.js', copyBlockSource !== null, 'async copyBlock() { ... } was not found as a single top-level method');
check(
  'copyBlock() calls copy_block with src_offset/length/dst_offset, matching lib.rs exactly',
  /runOnDocument\('copy_block', \{ src_offset: selection\.start, length: selection\.length, dst_offset: dstOffset \}\)/.test(copyBlockSource ?? ''),
  'the copy_block call no longer matches its Rust signature (src_offset, length, dst_offset)',
);

const moveBlockSource = methodSource('moveBlock');
check('moveBlock() could be located in shell.js', moveBlockSource !== null, 'async moveBlock() { ... } was not found as a single top-level method');
check(
  'moveBlock() calls move_block with src_offset/length/dst_offset, matching lib.rs exactly',
  /runOnDocument\('move_block', \{ src_offset: selection\.start, length: selection\.length, dst_offset: dstOffset \}\)/.test(moveBlockSource ?? ''),
  'the move_block call no longer matches its Rust signature (src_offset, length, dst_offset)',
);

const swapBlocksSource = methodSource('swapBlocks');
check('swapBlocks() could be located in shell.js', swapBlocksSource !== null, 'async swapBlocks() { ... } was not found as a single top-level method');
check(
  'swapBlocks() calls swap_blocks with offset_a/len_a/offset_b/len_b, matching lib.rs exactly',
  /runOnDocument\('swap_blocks', \{ offset_a: selection\.start, len_a: selection\.length, offset_b: offsetB, len_b: selection\.length \}\)/.test(swapBlocksSource ?? ''),
  'the swap_blocks call no longer matches its Rust signature (offset_a, len_a, offset_b, len_b)',
);
check(
  'swapBlocks() sends len_b equal to len_a rather than asking for it (swap_blocks in lib.rs rejects unequal lengths)',
  !/name: 'lenB'/.test(swapBlocksSource ?? ''),
  'swapBlocks() asks the user to type a second length that must equal the first or the engine refuses the call; it should be derived, not typed',
);

const getBitSource = methodSource('getBitAt');
check('getBitAt() could be located in shell.js', getBitSource !== null, 'async getBitAt() { ... } was not found as a single top-level method');
check(
  'getBitAt() calls get_bit with offset/bit_index, matching lib.rs exactly',
  /showResult\('get_bit', \{ offset: target\.offset, bit_index: target\.bitIndex \}\)/.test(getBitSource ?? ''),
  'the get_bit call no longer matches its Rust signature (offset, bit_index)',
);

const setBitSource = methodSource('setBitAt');
check('setBitAt() could be located in shell.js', setBitSource !== null, 'async setBitAt() { ... } was not found as a single top-level method');
check(
  'setBitAt() calls set_bit with offset/bit_index/value, matching lib.rs exactly',
  /runOnDocument\('set_bit', \{ offset: target\.offset, bit_index: target\.bitIndex, value: values\.value \}\)/.test(setBitSource ?? ''),
  'the set_bit call no longer matches its Rust signature (offset, bit_index, value)',
);

const toggleBitSource = methodSource('toggleBitAt');
check('toggleBitAt() could be located in shell.js', toggleBitSource !== null, 'async toggleBitAt() { ... } was not found as a single top-level method');
check(
  'toggleBitAt() calls toggle_bit with offset/bit_index, matching lib.rs exactly',
  /showResult\('toggle_bit', \{ offset: target\.offset, bit_index: target\.bitIndex \}\)/.test(toggleBitSource ?? ''),
  'the toggle_bit call no longer matches its Rust signature (offset, bit_index)',
);

/* ------------------------------ the bit index is validated at the boundary */

check(
  '#readBitTarget rejects a bit index outside 0-7, which is what get_bit/set_bit/toggle_bit enforce in lib.rs',
  /bitIndex < 0 \|\| bitIndex > MAX_BIT_INDEX/.test(shellSource) && /const MAX_BIT_INDEX = 7;/.test(shellSource),
  'nothing in shell.js stops an out-of-range bit index from reaching the engine as a validation error the user cannot read as their own mistake',
);

/* ------------------------------------- the context menu's keyboard contract */

/**
 * Build a single popup with three entries (two enabled, one disabled) and
 * drive it through `bindMenubarKeys` with the exact controller shape
 * `#openGridContextMenu` uses: an empty button list, so every key routes
 * straight to the entry-navigation half of the contract.
 *
 * @returns {Object} The popup, its entries and the `close()` calls recorded.
 */
function buildContextMenu() {
  const popup = element('div', 'hb-menu-popup', undefined, { role: 'menu', 'aria-label': 'Selection actions', tabindex: '-1' });
  const labels = ['Fill selection…', 'Copy block…', 'Get bit…'];
  const disabled = [false, true, false];
  const entries = labels.map((label, index) => {
    const item = element('button', disabled[index] ? 'hb-menu-entry is-disabled' : 'hb-menu-entry', undefined, { type: 'button', role: 'menuitem', tabindex: '-1' });
    item.appendChild(element('span', 'hb-menu-entry-label', label));
    if (disabled[index]) {
      item.setAttribute('aria-disabled', 'true');
    }
    popup.appendChild(item);
    return item;
  });
  const closes = [];
  bindMenubarKeys(popup, {
    buttons: () => [],
    openIndex: () => -1,
    popup: () => popup,
    open: () => {},
    close: (returnFocus) => closes.push(returnFocus),
  });
  entries[0].focus();
  return { popup, entries, closes };
}

function press(popup, key, extras = {}) {
  let prevented = false;
  popup.dispatch('keydown', {
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

function focusedLabel() {
  const node = globalThis.document.activeElement;
  return node === null ? null : node.textContent;
}

const menu = buildContextMenu();
check('the popup opens with focus on its first entry', focusedLabel() === 'Fill selection…', `expected "Fill selection…", got ${JSON.stringify(focusedLabel())}`);

const downPrevented = press(menu.popup, 'ArrowDown');
check('ArrowDown claims the key', downPrevented, 'ArrowDown inside the context menu did not preventDefault, so the page could scroll under it');
check(
  'ArrowDown skips the disabled entry',
  focusedLabel() === 'Get bit…',
  `expected ArrowDown to skip the disabled "Copy block…" and land on "Get bit…", got ${JSON.stringify(focusedLabel())}`,
);

press(menu.popup, 'ArrowDown');
check('ArrowDown wraps back to the first entry', focusedLabel() === 'Fill selection…', `expected wrap to "Fill selection…", got ${JSON.stringify(focusedLabel())}`);

check(
  'typeahead reaches an entry by its first letter',
  press(menu.popup, 'g') && focusedLabel() === 'Get bit…',
  `expected typeahead "g" to reach "Get bit…" (skipping the disabled "Copy block…"), got ${JSON.stringify(focusedLabel())}`,
);

check('nothing has closed the menu yet', menu.closes.length === 0, 'movement inside the context menu closed it, which would make every arrow key a dismissal');

const escapePrevented = press(menu.popup, 'Escape');
check('Escape claims the key and closes the menu', escapePrevented && menu.closes.length === 1, 'Escape inside the context menu did not close it through close()');
check('Escape asks for focus to be restored', menu.closes.at(-1) === true, `close() was called with ${JSON.stringify(menu.closes.at(-1))}; focus must return to the grid`);

/* ArrowLeft/ArrowRight have no sibling menu to switch to; they must not throw
 * or move focus off the popup, since the controller reports zero buttons. */
const sideways = buildContextMenu();
const beforeSideways = focusedLabel();
press(sideways.popup, 'ArrowRight');
check(
  'ArrowRight with no sibling menus leaves focus where it was, rather than throwing',
  focusedLabel() === beforeSideways,
  `ArrowRight moved focus from ${JSON.stringify(beforeSideways)} to ${JSON.stringify(focusedLabel())} with no button list to move across`,
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} block/bit editing and context-menu expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('block/bit editing and the grid context menu (BE-3): all expectations held\n');
