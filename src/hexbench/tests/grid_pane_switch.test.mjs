/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Gates A-1: the hex view must not be a keyboard trap (WCAG 2.1.2).
 *
 * grid.js imports api.js, which resolves its session token from `document` and
 * `window` at module load, so the module cannot be imported under plain node.
 * `switchesPane` is written as a module-level function of the event alone for
 * exactly that reason: it carries the whole pane-switch decision, depends on no
 * `this`, no private field and no import, and so is extracted here and really
 * executed rather than pattern-matched.
 *
 * Execution alone does not prove the handler lets Tab through, so the four
 * links that carry a Tab keydown out of `#onKeyDown` untouched are each
 * asserted: the pane-switch guard declines it, the modifier branch does not
 * claim it, the switch has no `Tab` case left, and the trailing
 * printable-character path cannot match a four-character key name. Break any
 * one of them and a keyboard-only user is stranded in the editor again.
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

/** Slice out a `{ ... }` block starting at the first match of `headerPattern`, brace-balanced. */
function extractBlock(source, headerPattern) {
  const match = source.match(headerPattern);
  if (!match) {
    throw new Error(`pattern not found in grid.js: ${headerPattern}`);
  }
  const braceStart = source.indexOf('{', match.index);
  let depth = 1;
  let index = braceStart + 1;
  while (depth > 0 && index < source.length) {
    if (source[index] === '{') {
      depth += 1;
    } else if (source[index] === '}') {
      depth -= 1;
    }
    index += 1;
  }
  return { full: source.slice(match.index, index), inner: source.slice(braceStart + 1, index - 1) };
}

const staticDir = fileURLToPath(new URL('../static/', import.meta.url));
const gridSource = await readFile(`${staticDir}grid.js`, 'utf8');

check(
  'the grid.js source is actually being read',
  gridSource.length > 20000,
  `grid.js read as only ${gridSource.length} characters`,
);

/* ------------------------------------------- the decision, actually executed */

const switchesPaneBlock = extractBlock(gridSource, /function switchesPane\(event\) \{/);
const switchesPane = new Function('event', switchesPaneBlock.inner);

function keyEvent(key, modifiers) {
  return { key, shiftKey: false, ctrlKey: false, altKey: false, metaKey: false, ...modifiers };
}

check(
  'Shift+Tab is not a pane switch',
  switchesPane(keyEvent('Tab', { shiftKey: true })) === false,
  'Shift+Tab is claimed by the pane switch again, so the editor swallows the one key that walks focus backwards out of it',
);
check(
  'plain Tab is not a pane switch',
  switchesPane(keyEvent('Tab')) === false,
  'Tab is claimed by the pane switch again, so focus can never leave the editor forwards',
);
check(
  'F6 is a pane switch',
  switchesPane(keyEvent('F6')) === true,
  'F6 no longer switches panes, so the behaviour Tab gave up has no replacement',
);
check(
  'Ctrl+Tab is a pane switch',
  switchesPane(keyEvent('Tab', { ctrlKey: true })) === true,
  'Ctrl+Tab no longer switches panes',
);
check(
  'Ctrl+Shift+Tab still switches panes',
  switchesPane(keyEvent('Tab', { ctrlKey: true, shiftKey: true })) === true,
  'the shifted form of the pane-switch chord was dropped, so it reaches the browser as a tab-cycling key instead',
);
check(
  'Alt+F6 is left to the window manager',
  switchesPane(keyEvent('F6', { altKey: true })) === false,
  'a modified F6 is being claimed by the grid',
);
check(
  'a bare character key is not a pane switch',
  switchesPane(keyEvent('a')) === false && switchesPane(keyEvent('Escape')) === false,
  'switchesPane claims keys that have nothing to do with the panes',
);

/* ------------------------------- the four links a Tab keydown has to survive */

const onKeyDown = extractBlock(gridSource, /#onKeyDown\(event\) \{/).full;

check(
  'the pane switch is consulted before the modifier branch',
  onKeyDown.indexOf('switchesPane(event)') !== -1
    && onKeyDown.indexOf('switchesPane(event)') < onKeyDown.indexOf('#onModifiedKey(event)'),
  'Ctrl+Tab reaches #onModifiedKey before the pane-switch guard sees it, so the chord is lost',
);
check(
  'the keydown switch no longer has a Tab case',
  !/case 'Tab':/.test(onKeyDown),
  "case 'Tab' is back in the keydown switch: Tab and Shift+Tab are swallowed and the editor is a keyboard trap again (WCAG 2.1.2)",
);
check(
  'togglePane is reached only through the pane-switch guard',
  (onKeyDown.match(/this\.togglePane\(\)/g) ?? []).length === 1,
  'a second call site toggles the panes from inside the keydown switch, where the pane-switch guard cannot vet the key',
);
check(
  'the trailing printable path is still length-gated',
  /if \(event\.key\.length === 1\) \{\s*this\.#typeCharacter\(event\);/.test(onKeyDown),
  'the fall-through path no longer requires a single-character key name, so a Tab keydown would be typed into the document as text',
);

const modifiedKey = extractBlock(gridSource, /#onModifiedKey\(event\) \{/).full;
check(
  'the modifier branch does not claim Tab either',
  !modifiedKey.includes("'Tab'"),
  'Ctrl+Tab is handled in two places, so which one wins depends on ordering rather than on a single rule',
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} grid pane-switch expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('grid pane switch (A-1): all expectations held\n');
