/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Gates UX-8: the toolbar's Go to field states its base, and the field and the
 * Ctrl+G dialog are one answer to one question rather than two.
 *
 * Both halves are markup and wiring -- the affordance is a literal prefix in
 * index.html, and the coupling is which value the dialog opens on and where the
 * jump writes back -- so both are read as text. #bindToolbar and gotoOffset need
 * a whole Shell to run.
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

const staticDir = fileURLToPath(new URL('../static/', import.meta.url));
const shellSource = (await readFile(`${staticDir}shell.js`, 'utf8')).replace(/\r\n/g, '\n');
const indexSource = (await readFile(`${staticDir}index.html`, 'utf8')).replace(/\r\n/g, '\n');

/* --------------------------------------------------------------- the affordance */

const field = /<label class="hb-tool-field">[\s\S]*?<\/label>/.exec(indexSource);
check('the Go to field could be located in index.html', field !== null, 'the .hb-tool-field block was not found');
const fieldSource = field ? field[0] : '';

check(
  'the field carries a literal 0x prefix',
  /<span aria-hidden="true">0x<\/span>/.test(fieldSource),
  'the field renders the input alone again, so nothing on screen states that the offset is hexadecimal',
);
check(
  'the prefix comes before the input, where it reads as part of the value',
  fieldSource.indexOf('0x</span>') < fieldSource.indexOf('<input'),
  'the 0x prefix is rendered after the input, where it reads as a unit rather than as a base',
);
check(
  'the prefix is hidden from assistive technology',
  /<span aria-hidden="true">0x<\/span>/.test(fieldSource),
  'the prefix is not aria-hidden, so it joins the field\'s accessible name and the field is announced as "Go to offset 0x"',
);
check(
  'the field keeps its accessible name',
  /<span class="hb-sr-only">Go to offset<\/span>/.test(fieldSource),
  'the field lost the label that names it, leaving a bare input in the toolbar',
);
check('the field is still the input the shell binds', fieldSource.includes('id="toolbar-goto"'), '#toolbar-goto is gone; #bindToolbar queries for it and would fail at boot');

/* ------------------------------------------------------- one answer, one question */

check(
  'the shell keeps hold of the field',
  /this\.#gotoField = this\.#nodes\.toolbar\.querySelector\('#toolbar-goto'\);/.test(shellSource),
  '#bindToolbar no longer keeps the field, so the dialog has nothing to read from or write back to',
);
check(
  'the dialog opens on whatever the field says',
  /const typed = this\.#gotoField === null \? null : parseOffset\(this\.#gotoField\.value\);/.test(shellSource),
  'gotoOffset no longer reads the toolbar field, so typing an offset into the field and pressing Ctrl+G offers a different one',
);
check(
  'the dialog falls back to the caret when the field says nothing usable',
  /value: hex\(typed \?\? this\.#grid\.caret\.offset, 8\)/.test(shellSource),
  'the dialog no longer falls back to the caret, so an empty field would seed it with nothing',
);
check(
  'both routes jump through the same place',
  (shellSource.match(/this\.#jumpTo\(offset\);/g) ?? []).length === 2,
  'the field and the dialog no longer share #jumpTo, so only one of them can keep the two in step',
);
check(
  'a jump leaves the field showing where the view went',
  /#jumpTo\(offset\) \{[\s\S]*?this\.#gotoField\.value = hex\(offset, 8\);[\s\S]*?this\.#grid\.seek\(offset\);/.test(shellSource),
  '#jumpTo no longer writes the offset back into the field before seeking, so the field keeps showing the last thing typed into it',
);
check(
  'a jump still moves the caret and hands focus to the grid',
  /#jumpTo\(offset\) \{[\s\S]*?this\.#grid\.seek\(offset\);\s*\n\s*this\.#grid\.focus\(\);/.test(shellSource),
  '#jumpTo no longer seeks and focuses the grid, so Go to would update a text field and nothing else',
);
/*
 * 'Not an offset' is also the toast BE-3's block-editing dialogs raise for
 * their own destination-offset fields (copyBlock, moveBlock, swapBlocks), so
 * counting the literal across the whole file no longer isolates the two Go to
 * routes. Each route's own method body is checked instead.
 */
const toolbarBody = /#bindToolbar\(\) \{[\s\S]*?\n  \}\n/.exec(shellSource);
check('#bindToolbar() could be located in shell.js', toolbarBody !== null, '#bindToolbar() { ... } was not found as a single top-level method');
check(
  'the toolbar field reports a malformed offset rather than swallowing it',
  (toolbarBody?.[0].match(/'Not an offset'/g) ?? []).length === 1,
  'the toolbar Go to field no longer reports an unparseable offset',
);

const gotoOffsetBody = /async gotoOffset\(\) \{[\s\S]*?\n  \}\n/.exec(shellSource);
check('gotoOffset() could be located in shell.js', gotoOffsetBody !== null, 'async gotoOffset() { ... } was not found as a single top-level method');
check(
  'the Go to dialog reports a malformed offset rather than swallowing it',
  (gotoOffsetBody?.[0].match(/'Not an offset'/g) ?? []).length === 1,
  'the Go to dialog no longer reports an unparseable offset',
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} Go to field expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('Go to field and dialog (UX-8): all expectations held\n');
