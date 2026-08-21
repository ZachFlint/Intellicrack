/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Gates UX-2: a shortcut printed beside a menu entry is a promise, and the menu
 * printed three keys that no binding reached. Every command that advertises a
 * key must therefore either be bound window-wide in SHORTCUTS or be declared as
 * one the hex view owns -- and be advertised as such.
 *
 * The command table is built inside the Shell constructor, which needs a whole
 * document tree, so the three tables are read out of shell.js as text and
 * compared against each other. The comparison is the point: it cannot be
 * satisfied by writing a shortcut string into a #define and stopping there.
 * `shortcutText` and `shouldRunShortcut` are pure and exported, so those two are
 * executed for real.
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

globalThis.document = { querySelector: () => null };
globalThis.window = { location: { search: '' } };

const staticDir = fileURLToPath(new URL('../static/', import.meta.url));
const shellSource = (await readFile(`${staticDir}shell.js`, 'utf8')).replace(/\r\n/g, '\n');

const { shortcutText, shouldRunShortcut } = await import('../static/shell.js');

/* ------------------------------------------------------------- the three tables */

const commands = new Map();
for (const define of shellSource.matchAll(/this\.#define\('([\w.]+)', '([^']*)', '([^']*)'/g)) {
  commands.set(define[1], { id: define[1], label: define[2], shortcut: define[3] });
}

const shortcutsBlock = /const SHORTCUTS = \[[\s\S]*?\n\];/.exec(shellSource);
const bound = new Map();
for (const entry of (shortcutsBlock ? shortcutsBlock[0] : '').matchAll(/\{ combo: '([^']+)', command: '([\w.]+)' \}/g)) {
  bound.set(entry[2], entry[1]);
}

const scopedBlock = /const EDITOR_SCOPED_SHORTCUTS = new Set\(\[([^\]]*)\]\);/.exec(shellSource);
const editorScoped = new Set([...(scopedBlock ? scopedBlock[1] : '').matchAll(/'([\w.]+)'/g)].map((entry) => entry[1]));

check('the command table could be read out of shell.js', commands.size >= 30, `the #define scan found only ${commands.size} commands, too few to be reading the real table`);
check('the SHORTCUTS table could be read out of shell.js', bound.size >= 10, `the SHORTCUTS scan found only ${bound.size} bindings, too few to be reading the real table`);
check('the editor-scoped set could be read out of shell.js', editorScoped.size > 0, 'EDITOR_SCOPED_SHORTCUTS was not found, so a grid-only key has nowhere to be declared');

/* --------------------------------------- every advertised key is bound or scoped */

/** The combo `comboOf` would build for a shortcut as the menus print it. */
function comboFor(shortcut) {
  return shortcut
    .toLowerCase()
    .split('+')
    .map((part) => (part === 'del' ? 'delete' : part === 'ins' ? 'insert' : part))
    .join('+');
}

for (const command of commands.values()) {
  if (command.shortcut === '') {
    continue;
  }
  check(
    `${command.id} advertises ${command.shortcut} and something answers for it`,
    bound.has(command.id) || editorScoped.has(command.id),
    `"${command.label}" prints ${command.shortcut} in the menu, but the key is in no SHORTCUTS entry and the command is not declared editor-scoped, so pressing it does nothing`,
  );
  if (bound.has(command.id)) {
    check(
      `${command.id} is bound to the key it advertises`,
      bound.get(command.id) === comboFor(command.shortcut),
      `the menu prints ${command.shortcut} but the binding listens for ${bound.get(command.id)}`,
    );
  }
}

for (const [id, combo] of bound) {
  check(`the ${combo} binding names a command that exists`, commands.has(id), `SHORTCUTS binds ${combo} to ${id}, which is never passed to #define`);
  check(`the ${combo} binding runs a command that advertises a key`, commands.get(id)?.shortcut !== '', `${id} is bound to ${combo} but prints no shortcut, so the key is undiscoverable`);
}

for (const id of editorScoped) {
  check(`the editor-scoped ${id} exists`, commands.has(id), `EDITOR_SCOPED_SHORTCUTS names ${id}, which is never passed to #define`);
  check(`the editor-scoped ${id} advertises a key worth scoping`, commands.get(id)?.shortcut !== '', `${id} is declared editor-scoped but prints no shortcut at all`);
  check(`the editor-scoped ${id} is not also bound window-wide`, !bound.has(id), `${id} is both editor-scoped and in SHORTCUTS; the grid and the window would both handle the key and the edit would happen twice`);
}

check(
  'the three keys the Edit menu used to promise are accounted for',
  ['edit.selectAll', 'edit.delete', 'edit.toggleInsert'].every((id) => bound.has(id) || editorScoped.has(id)),
  'Ctrl+A, Del and Ins are printed in the Edit menu; each must be bound or declared editor-scoped',
);
check('edit.paste finally has a key', commands.get('edit.paste')?.shortcut === 'Ctrl+V', `expected Ctrl+V on edit.paste, got ${JSON.stringify(commands.get('edit.paste')?.shortcut)}`);
check('Ctrl+V reaches edit.paste', bound.get('edit.paste') === 'ctrl+v', `expected the ctrl+v binding to run edit.paste, got ${JSON.stringify(bound.get('edit.paste'))}`);
check(
  'the dead ctrl+x branch is gone',
  !/ctrl\+x/.test(shellSource),
  'shouldRunShortcut still carries a ctrl+x case that no binding can reach',
);

/* --------------------------------------------- how a scoped key is advertised */

check(
  'an editor-scoped key is printed with its scope',
  shortcutText({ id: 'edit.selectAll', shortcut: 'Ctrl+A' }) === 'Ctrl+A · editor',
  `expected "Ctrl+A · editor", got ${JSON.stringify(shortcutText({ id: 'edit.selectAll', shortcut: 'Ctrl+A' }))}`,
);
check(
  'a window-wide key is printed plainly',
  shortcutText({ id: 'file.save', shortcut: 'Ctrl+S' }) === 'Ctrl+S',
  `a bound key must not be marked as scoped; got ${JSON.stringify(shortcutText({ id: 'file.save', shortcut: 'Ctrl+S' }))}`,
);
check(
  'a command with no key prints nothing',
  shortcutText({ id: 'edit.fill', shortcut: '' }) === '',
  `expected an empty string, got ${JSON.stringify(shortcutText({ id: 'edit.fill', shortcut: '' }))}`,
);
check(
  'the menu prints the scoped form rather than the raw shortcut',
  /element\('span', 'hb-menu-shortcut', shortcutText\(command\)\)/.test(shellSource),
  '#toggleMenu no longer renders shortcutText, so an editor-only key is advertised as a window-wide one again',
);
check(
  'Help lists the editor-scoped keys with their scope',
  /for \(const id of EDITOR_SCOPED_SHORTCUTS\) \{[\s\S]*?\(editor\)/.test(shellSource),
  'showShortcuts no longer lists the editor-scoped keys, so Help promises them as window-wide or omits them entirely',
);
check(
  'Help documents the key that releases the editor (A-1)',
  /'f6 \/ ctrl\+tab', 'Move between the hex and ASCII panes'/.test(shellSource),
  'Help still names Tab as the pane switch; Tab now leaves the editor and F6 / Ctrl+Tab switch panes',
);
check(
  'Help says how to get out of the editor',
  /'tab \/ shift\+tab'/.test(shellSource),
  'Help does not say that Tab and Shift+Tab leave the editor, which is the whole point of the A-1 fix',
);

/* ----------------------------------------------- what runs while a field has focus */

check(
  'Ctrl+V in a field is left to the field, selection or not',
  shouldRunShortcut('ctrl+v', { typing: true, hasTextSelection: false, gridSelection: null }) === false
    && shouldRunShortcut('ctrl+v', { typing: true, hasTextSelection: true, gridSelection: null }) === false,
  'pasting into the offset field would open the paste-bytes dialog instead of pasting the text',
);
check(
  'Ctrl+V outside a field opens the paste dialog',
  shouldRunShortcut('ctrl+v', { typing: false, hasTextSelection: false, gridSelection: null }) === true,
  'the new Ctrl+V binding never runs, which is the dead branch again in the other direction',
);
check(
  'Ctrl+C in a field with a selection still defers to the field',
  shouldRunShortcut('ctrl+c', { typing: true, hasTextSelection: true, gridSelection: { start: 0, length: 4 } }) === false,
  'the copy rule regressed while the paste rule was added',
);
check(
  'Ctrl+C in a field with nothing selected still copies the grid selection',
  shouldRunShortcut('ctrl+c', { typing: true, hasTextSelection: false, gridSelection: { start: 0, length: 4 } }) === true,
  'the copy rule regressed while the paste rule was added',
);
check(
  'Ctrl+S still works from inside a field',
  shouldRunShortcut('ctrl+s', { typing: true, hasTextSelection: true, gridSelection: null }) === true,
  'a non-clipboard ctrl combo must keep working while a field has focus',
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} shortcut expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('advertised shortcuts (UX-2): all expectations held\n');
