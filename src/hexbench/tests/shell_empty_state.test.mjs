/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Holds the "nothing open" screen to what it promises. The blank screen is the
 * first thing the application shows and the only thing offering a way out of
 * it, so three separate failures all read as "the window is broken": the screen
 * not appearing (or not going away again), an action button wired to a command
 * that was never defined, and a command defined but reachable from nowhere else
 * once a document is open.
 *
 * The wiring is asserted by reading shell.js and renderers.js as text, because
 * the Shell constructor needs a whole real document tree and none is available
 * here. The two rules that are pure functions -- what the drop handlers accept
 * and what the paste dialog converts -- are exercised for real against the
 * exported implementations. shell.js transitively imports api.js, whose
 * module-level token resolution touches `document`/`window`, so both globals
 * are stubbed with the bare minimum before the module is loaded; the stub is
 * never touched by an assertion.
 *
 * Run by gate.ps1. Exits non-zero on the first failed expectation.
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
/* Read with line endings normalised to LF. The repository stores its sources
 * with CRLF terminators, and every structural pattern below is written against
 * "\n"; matching them against the raw bytes would fail on the line endings
 * rather than on the code the checks are actually about. */
const shellSource = (await readFile(`${staticDir}shell.js`, 'utf8')).replace(/\r\n/g, '\n');
const renderersSource = (await readFile(`${staticDir}renderers.js`, 'utf8')).replace(/\r\n/g, '\n');
const indexSource = (await readFile(`${staticDir}index.html`, 'utf8')).replace(/\r\n/g, '\n');

const { carriesFiles, hexFromPastedText } = await import('../static/shell.js');

/* Slice out one brace-delimited body by counting braces from its signature, so
 * a check about what `attachProcess` calls cannot be satisfied by an identical
 * call somewhere else in the file. */
function bracedBlock(source, signature) {
  const start = source.indexOf(signature);
  if (start === -1) {
    return '';
  }
  let depth = 0;
  for (let index = start + signature.length - 1; index < source.length; index += 1) {
    if (source[index] === '{') {
      depth += 1;
    } else if (source[index] === '}') {
      depth -= 1;
      if (depth === 0) {
        return source.slice(start, index + 1);
      }
    }
  }
  return '';
}

const BLANK_LEDE_TEXT = 'Open a file, attach to a running process, or drop bytes straight in. '
  + 'Everything else in the window stays disabled until one of those happens.';

/* ------------------------------------------------- the screen comes and goes */

check(
  '#setActive decides the blank screen from whether a document is active',
  /#setActive\(info\) \{[\s\S]*?this\.#showBlank\(!info\);/.test(shellSource),
  '#setActive no longer calls #showBlank(!info), so the blank screen cannot track the active document',
);
check(
  '#setActive hands the same document on to the grid',
  /#setActive\(info\) \{[\s\S]*?this\.#showBlank\(!info\);\s*\n\s*this\.#grid\.setDocument\(info\);/.test(shellSource),
  '#setActive no longer sets the grid document right after deciding the blank screen, so the two can disagree about what is open',
);
check(
  '#showBlank hides the editor frame while blank and restores it afterwards',
  /this\.#editorFrame\.style\.display = visible \? 'none' : '';/.test(shellSource),
  "#showBlank no longer toggles the editor frame's inline display, so the grid would stay visible behind the blank screen (or stay hidden once a document opens)",
);
check(
  '#showBlank takes the blank screen back down when a document becomes active',
  /if \(!visible\) \{\s*\n\s*this\.#blank\?\.remove\(\);\s*\n\s*return;/.test(shellSource),
  '#showBlank no longer removes the blank element when a document is active, so an opened document would render underneath it',
);
check(
  '#showBlank mounts the blank screen into the editor host',
  /this\.#nodes\.editorHost\.appendChild\(this\.#blank\);/.test(shellSource),
  '#showBlank no longer appends the blank element to the editor host, so nothing would be shown in place of the grid',
);
check(
  'the shell starts on the blank screen',
  /this\.#showBlank\(true\);/.test(shellSource),
  'the constructor no longer puts the blank screen up, so a freshly loaded window would show an empty grid instead',
);

/* ------------------------------------------------------------------- the copy */

check(
  'the blank screen title is the exact agreed copy',
  shellSource.includes("const BLANK_TITLE = 'Nothing open.';"),
  'BLANK_TITLE is no longer exactly "Nothing open."',
);
check(
  'the blank screen lede is the exact agreed copy',
  shellSource.includes(`const BLANK_LEDE = '${BLANK_LEDE_TEXT}';`),
  `BLANK_LEDE is no longer exactly: ${BLANK_LEDE_TEXT}`,
);
check(
  '#buildBlank renders the title and the lede rather than merely declaring them',
  /element\('h1', 'hb-blank-title', BLANK_TITLE\), element\('p', 'hb-blank-lede', BLANK_LEDE\)/.test(shellSource),
  '#buildBlank no longer renders BLANK_TITLE and BLANK_LEDE, so the constants could be dead text',
);

/* ---------------------------------------------------------- the three actions */

const blankActionsBlock = /const BLANK_ACTIONS = \[[\s\S]*?\n\];/.exec(shellSource);
check(
  'the BLANK_ACTIONS table could be located for inspection',
  blankActionsBlock !== null,
  'const BLANK_ACTIONS = [ ... ]; was not found as a single top-level block in shell.js',
);
const blankActionsSource = blankActionsBlock ? blankActionsBlock[0] : '';
const blankCommands = [...blankActionsSource.matchAll(/command: '([\w.]+)'/g)].map((entry) => entry[1]);

check(
  'the blank screen offers exactly the three documented ways in',
  JSON.stringify(blankCommands) === JSON.stringify(['file.open', 'file.attach', 'edit.paste']),
  `expected ["file.open","file.attach","edit.paste"], got ${JSON.stringify(blankCommands)}`,
);
check(
  'every blank action carries a title the button can show',
  (blankActionsSource.match(/title: '/g) ?? []).length === blankCommands.length,
  `${blankCommands.length} actions but ${(blankActionsSource.match(/title: '/g) ?? []).length} titles; an action with no title would render as a blank card`,
);
check(
  '#buildBlank builds one button per BLANK_ACTIONS entry',
  /for \(const action of BLANK_ACTIONS\) \{/.test(shellSource),
  '#buildBlank no longer iterates BLANK_ACTIONS, so the table and the rendered buttons could drift apart',
);
check(
  'each blank action button runs its own command',
  /button\.addEventListener\('click', \(\) => this\.run\(action\.command\)\);/.test(shellSource),
  'the blank action buttons are no longer wired to this.run(action.command), so the only way out of the blank screen would be inert',
);

/* --------------------------------- the same commands are reachable from a menu */

const menusBlock = /const MENUS = \[[\s\S]*?\n\];/.exec(shellSource);
check('the MENUS table could be located for inspection', menusBlock !== null, 'const MENUS = [ ... ]; was not found as a single top-level block in shell.js');
const menuCommands = new Set([...(menusBlock ? menusBlock[0] : '').matchAll(/'([a-z]+\.[A-Za-z]+)'/g)].map((entry) => entry[1]));

check(
  'the MENUS scan actually read a menu table',
  menuCommands.size >= 20,
  `the menu scan found only ${menuCommands.size} commands, too few to be reading the real MENUS table`,
);
for (const command of ['file.open', 'file.attach', 'edit.paste']) {
  check(
    `${command} is defined as a command`,
    shellSource.includes(`this.#define('${command}',`),
    `${command} is wired to a blank-screen button but never passed to #define, so pressing that button does nothing`,
  );
  check(
    `${command} is reachable from the menu bar as well as the blank screen`,
    menuCommands.has(command),
    `${command} is missing from the MENUS table, so once a document is open there is no way to reach it`,
  );
}

/* ------------------------------------------- what the attach and paste paths call */

const attachBody = bracedBlock(shellSource, 'async attachProcess() {');
const pasteBody = bracedBlock(shellSource, 'async pasteBytes() {');
const regionsBody = bracedBlock(renderersSource, 'function renderRegions(name, result, ctx) {');

check('attachProcess() could be sliced out of shell.js', attachBody.length > 0 && attachBody.length < shellSource.length, 'async attachProcess() { ... } was not found as a balanced block');
check('pasteBytes() could be sliced out of shell.js', pasteBody.length > 0 && pasteBody.length < shellSource.length, 'async pasteBytes() { ... } was not found as a balanced block');
check(
  'renderRegions() could be sliced out of renderers.js',
  regionsBody.length > 0 && regionsBody.length < renderersSource.length,
  'function renderRegions(name, result, ctx) { ... } was not found as a balanced block; the attach path no longer has a region renderer',
);

const invoked = new Set();
for (const body of [attachBody, pasteBody, regionsBody]) {
  for (const call of body.matchAll(/(?:callOp|ctx\.run)\('([a-z0-9_]+)'/g)) {
    invoked.add(call[1]);
  }
}
check(
  'the attach and paste paths reach exactly the three catalogued operations they document',
  JSON.stringify([...invoked].sort()) === JSON.stringify(['from_process_memory', 'list_process_memory_regions', 'open_bytes']),
  `expected ["from_process_memory","list_process_memory_regions","open_bytes"], got ${JSON.stringify([...invoked].sort())}`,
);

/* ------------------------------------------------- no recent-documents list crept in */

check('the shell keeps no localStorage', !/localStorage/.test(shellSource), 'shell.js now touches localStorage; the recent-documents list was deliberately cut and nothing on the blank screen may persist across sessions');
check('the shell keeps no sessionStorage', !/sessionStorage/.test(shellSource), 'shell.js now touches sessionStorage; the recent-documents list was deliberately cut');
check('the shell shows no "Recent" heading', !/\bRecent\b/.test(shellSource), 'shell.js now names a "Recent" heading; the recent-documents list was deliberately cut');
check('the served page declares no "Recent" heading', !/\bRecent\b/.test(indexSource), 'index.html now names a "Recent" heading; the recent-documents list was deliberately cut');

/* ------------------------------------------------------------------- splitters */

check(
  'a splitter is put in the tab order when its keys are bound',
  /#splitterKeys\(handle, side\) \{\s*\n\s*handle\.tabIndex = 0;/.test(shellSource),
  '#splitterKeys no longer sets handle.tabIndex, so neither splitter could be reached from the keyboard',
);
check(
  'the vertical splitter gets its keys and its tab stop',
  /this\.#splitterKeys\(this\.#nodes\.splitterV, 'right'\);/.test(shellSource),
  '#bindSplitters no longer runs #splitterKeys for the vertical splitter',
);
check(
  'the horizontal splitter gets its keys and its tab stop',
  /this\.#splitterKeys\(this\.#nodes\.splitterH, 'bottom'\);/.test(shellSource),
  '#bindSplitters no longer runs #splitterKeys for the horizontal splitter',
);
check(
  'a splitter publishes its current position',
  /handle\.setAttribute\('aria-valuenow', String\(Math\.round\(value\)\)\);/.test(shellSource),
  '#describeSplitter no longer writes aria-valuenow, so assistive technology cannot read where a splitter now sits',
);
check(
  'the vertical splitter is re-described whenever the docks are re-clamped',
  /this\.#describeSplitter\(this\.#nodes\.splitterV, right, rect\.width\);/.test(shellSource),
  '#clampDocks no longer re-describes the vertical splitter, so aria-valuenow would go stale the moment the window is resized',
);
check(
  'the horizontal splitter is re-described whenever the docks are re-clamped',
  /this\.#describeSplitter\(this\.#nodes\.splitterH, bottom, rect\.height\);/.test(shellSource),
  '#clampDocks no longer re-describes the horizontal splitter, so aria-valuenow would go stale the moment the window is resized',
);
check(
  'a resize actually re-clamps the docks',
  /this\.#workspaceObserver = new ResizeObserver\(\(\) => this\.#clampDocks\(\)\);/.test(shellSource),
  'the workspace is no longer observed for resizes, so #clampDocks (and with it aria-valuenow) would only run on a drag',
);

/* --------------------------------------------------------- window-wide file drop */

check(
  'the shell binds its file-drop handlers at construction',
  /this\.#bindFileDrop\(\);/.test(shellSource),
  'the constructor no longer calls #bindFileDrop, so the blank screen would promise a drop target that does not exist',
);
check(
  'dragover is bound on the window, not on the editor',
  /window\.addEventListener\('dragover', \(event\) => \{/.test(shellSource),
  'the dragover handler is no longer bound on window; without it the drop event never fires at all',
);
check(
  'drop is bound on the window, not on the editor',
  /window\.addEventListener\('drop', \(event\) => \{/.test(shellSource),
  'the drop handler is no longer bound on window; without it the browser navigates away from the application to the dropped file',
);
check(
  'the drop handler opens the dropped file through the same path the picker uses',
  /this\.openFile\(file\)\.catch\(\(error\) => this\.reportError\(error\)\);/.test(shellSource),
  'the drop handler no longer routes through openFile(), so a dropped file and a chosen one could behave differently',
);

check('a drag carrying a file is accepted', carriesFiles({ types: ['Files'] }) === true, 'a DataTransfer advertising Files must be treated as a file drop');
check(
  'a drag carrying only text is ignored',
  carriesFiles({ types: ['text/plain'] }) === false,
  'dragging selected text inside an input must not be cancelled, or text dragging would break everywhere in the window',
);
check('a drag with no payload description is ignored', carriesFiles(null) === false, 'a missing DataTransfer must not read as a file drop');
check('a drag advertising nothing is ignored', carriesFiles({ types: [] }) === false, 'an empty type list must not read as a file drop');

/* ------------------------------------------------------ what edit.paste converts */

const pastedHex = hexFromPastedText('4d 5a 90 00', 'hex');
check('a spaced hex paste converts to compact upper-case hex', pastedHex.ok === true && pastedHex.hex === '4D5A9000', `expected 4D5A9000, got ${JSON.stringify(pastedHex)}`);

const pastedBase64 = hexFromPastedText('TVqQAA==', 'base64');
check('a base64 paste converts to the same bytes', pastedBase64.ok === true && pastedBase64.hex.toUpperCase() === '4D5A9000', `expected 4D5A9000, got ${JSON.stringify(pastedBase64)}`);

const pastedRaw = hexFromPastedText('MZ', 'raw');
check('a raw paste is encoded as UTF-8 bytes', pastedRaw.ok === true && pastedRaw.hex.toUpperCase() === '4D5A', `expected 4D5A, got ${JSON.stringify(pastedRaw)}`);

const halfByte = hexFromPastedText('4d5a9', 'hex');
check('an odd number of hex digits is refused rather than silently trimmed', halfByte.ok === false, `a truncated paste must be reported, not opened as ${JSON.stringify(halfByte)}`);

const notHex = hexFromPastedText('4d5ax0', 'hex');
check('a non-hex digit is refused', notHex.ok === false, `expected a refusal, got ${JSON.stringify(notHex)}`);

const notBase64 = hexFromPastedText('****', 'base64');
check('text outside the base64 alphabet is refused', notBase64.ok === false, `expected a refusal, got ${JSON.stringify(notBase64)}`);

check(
  'pasteBytes converts through hexFromPastedText rather than converting inline',
  /const converted = hexFromPastedText\(values\.text, values\.format\);/.test(pasteBody),
  'pasteBytes no longer routes the pasted text through hexFromPastedText, so the rules exercised above could be dead code',
);
check(
  'pasteBytes refuses to open a paste that carries no bytes',
  /if \(converted\.hex === ''\) \{/.test(pasteBody),
  'pasteBytes no longer rejects an empty conversion, so it would open a zero-length document the user did not ask for',
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} blank-screen expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('blank screen, command reachability and window-wide drop: all expectations held\n');
