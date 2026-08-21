/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Gates UX-3: the status bar reads in three tiers, and an item with nothing to
 * say is absent rather than printed as an em dash. Ten items of equal weight,
 * three of them dashes most of the time, is a bar nobody reads.
 *
 * `statusReadout` is the whole decision and is pure and exported, so every state
 * below is a real call: null means "hide this item", and the caret-only session
 * is counted rather than described. The markup half is read out of index.html,
 * because the placeholders this task removes were written there.
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
const indexSource = (await readFile(`${staticDir}index.html`, 'utf8')).replace(/\r\n/g, '\n');

const { statusReadout } = await import('../static/shell.js');

const CARET = { offset: 0x4a, pane: 'hex', nibble: 0 };
const DOCUMENT = { handle: 'doc-a', generation: 1, length: 640, modified: false };
const UNSCALED = { scaled: false, bytesPerPixel: 1 };

/** The state of a session where a document is open and nothing else has happened yet. */
function caretOnly(overrides = {}) {
  return {
    document: DOCUMENT,
    caret: CARET,
    selection: null,
    entropy: null,
    hits: 0,
    hitIndex: -1,
    insertMode: false,
    busy: false,
    metrics: UNSCALED,
    ...overrides,
  };
}

function shown(readout) {
  return Object.entries(readout).filter(([, value]) => value !== null).map(([name]) => name);
}

/* ------------------------------------------------------- the caret-only session */

const quiet = statusReadout(caretOnly());
const quietItems = shown(quiet);

check(
  'a caret-only session shows at most five items',
  quietItems.length <= 5,
  `${quietItems.length} items would render for a session that has measured nothing: ${quietItems.join(', ')}`,
);
check(
  'the five are where you are, how big it is, and the engine',
  JSON.stringify(quietItems.sort()) === JSON.stringify(['mode', 'offset', 'pane', 'size', 'state']),
  `expected offset, pane, size, mode and state, got ${JSON.stringify(quietItems)}`,
);
check(
  'nothing that has not been measured renders at all',
  quiet.selection === null && quiet.entropy === null && quiet.hits === null && quiet.scale === null && quiet.modified === null,
  `an unmeasured value rendered a placeholder: ${JSON.stringify(quiet)}`,
);

for (const state of [
  caretOnly(),
  caretOnly({ document: null }),
  caretOnly({ selection: { start: 0x40, length: 14 }, entropy: 3.37, hits: 9, hitIndex: 1, busy: true, insertMode: true }),
  caretOnly({ document: { ...DOCUMENT, modified: true }, metrics: { scaled: true, bytesPerPixel: 1400 } }),
]) {
  const readout = statusReadout(state);
  const printed = Object.values(readout).filter((value) => value !== null);
  check(
    'no item ever renders a placeholder dash',
    printed.every((value) => !value.includes('—')),
    `an em dash reached the bar: ${JSON.stringify(readout)}`,
  );
  check(
    'no item ever renders the word none',
    printed.every((value) => value !== 'none'),
    `"none" reached the bar: ${JSON.stringify(readout)}`,
  );
  check('every rendered value carries something to read', printed.every((value) => value.trim() !== ''), `an empty string reached the bar: ${JSON.stringify(readout)}`);
}

/* ------------------------------------------------------- with nothing open at all */

const blank = statusReadout(caretOnly({ document: null }));
check(
  'a window with no document shows only the engine state',
  JSON.stringify(shown(blank)) === JSON.stringify(['state']),
  `expected just the engine state, got ${JSON.stringify(shown(blank))}`,
);
check('the engine state is never hidden', blank.state === 'ready', `expected "ready", got ${JSON.stringify(blank.state)}`);

/* ------------------------------------------------ the values, once they are real */

const busy = statusReadout(caretOnly({
  selection: { start: 0x40, length: 14 },
  entropy: 3.37,
  hits: 9,
  hitIndex: 1,
  insertMode: true,
  busy: true,
  document: { ...DOCUMENT, modified: true },
}));

check('the caret prints as a hexadecimal offset', busy.offset.startsWith('0x0000004A'), `got ${JSON.stringify(busy.offset)}`);
check('the pane names the nibble in the hex pane', busy.pane === 'hex hi', `got ${JSON.stringify(busy.pane)}`);
check('a selection appears once there is one', busy.selection === '14 B @ 0x00000040', `got ${JSON.stringify(busy.selection)}`);
check('entropy appears once it has been measured', busy.entropy === '3.370', `got ${JSON.stringify(busy.entropy)}`);
check('hits read as position of total', busy.hits === '2/9', `got ${JSON.stringify(busy.hits)}`);
check('a modified document says so', busy.modified === 'modified', `got ${JSON.stringify(busy.modified)}`);
check('a clean document says nothing at all', statusReadout(caretOnly()).modified === null, 'a clean document still prints "clean", which is a word for the absence of news');
check('the mode follows the grid', busy.mode === 'INS' && statusReadout(caretOnly()).mode === 'OVR', `got ${JSON.stringify(busy.mode)}`);
check('the engine says when it is working', busy.state === 'working', `got ${JSON.stringify(busy.state)}`);

const scaled = statusReadout(caretOnly({ metrics: { scaled: true, bytesPerPixel: 1400 } }));
check('the scale appears only when the scroller is scaled', scaled.scale !== null && statusReadout(caretOnly()).scale === null, `got ${JSON.stringify(scaled.scale)}`);

const firstHit = statusReadout(caretOnly({ hits: 1, hitIndex: 0 }));
check('a single hit reads as 1/1 rather than 0/1', firstHit.hits === '1/1', `got ${JSON.stringify(firstHit.hits)}`);

/* ----------------------------------------------------------- how it is applied */

check(
  '#renderStatus decides through statusReadout',
  /const readout = statusReadout\(\{/.test(shellSource),
  '#renderStatus no longer routes through statusReadout, so every rule exercised above could be dead code',
);
check(
  '#renderStatus hides an item rather than printing a placeholder',
  /hideStatusNode\(node\.closest\('\.hb-status-item'\), value === null\);/.test(shellSource),
  '#renderStatus no longer hides the item whose value is null, so a missing value would render as an empty or dashed item',
);
check(
  'hiding an item really removes it from the row',
  /function hideStatusNode\(node, hidden\) \{\s*\n\s*node\.hidden = hidden;\s*\n\s*node\.style\.display = hidden \? 'none' : '';/.test(shellSource),
  'hideStatusNode no longer sets the inline display; .hb-status-item declares a display of its own, which outranks the hidden attribute, so the item would keep its place in the bar',
);
check(
  'the separators are trimmed with the items',
  /this\.#trimStatusSeparators\(\);/.test(shellSource),
  '#renderStatus no longer trims the separators, so a hidden tier leaves bare hairlines behind it',
);
check(
  'a separator needs an item on both sides of it',
  /hideStatusNode\(child, !\(itemBeside\(index - 1, -1\) && itemBeside\(index \+ 1, 1\)\)\);/.test(shellSource),
  'the separator rule changed; a separator with an empty side prints as a stray hairline',
);
check(
  'the accent is reserved for something to act on',
  /nodes\.modifiedItem\.classList\.toggle\('is-warning', readout\.modified !== null\);/.test(shellSource),
  'the modified item no longer takes is-warning from the readout, so the only conditional colour in the bar is decoration',
);

/* -------------------------------------------------------------- the markup */

const statusbar = /<div class="hb-statusbar"[\s\S]*?\n  <\/div>/.exec(indexSource);
check('the status bar could be located in index.html', statusbar !== null, 'the .hb-statusbar block was not found in index.html');
const bar = statusbar ? statusbar[0] : '';

check('the served status bar carries no em dashes', !bar.includes('—'), 'index.html still ships placeholder dashes, which show until the first render and read as broken readouts');
check('the served status bar carries no "none"', !/>none</.test(bar), 'index.html still ships the word "none" as a selection placeholder');
check('the served status bar carries no "clean"', !/>clean</.test(bar), 'index.html still ships "clean" as the modified placeholder');
check(
  'entropy is no longer accented',
  !/is-accent/.test(bar),
  'the accent is still on entropy, which pulls the eye to a number that rarely changes and is not something to act on',
);
check(
  'the caret item is keyed "off", since its value is already 0x-prefixed',
  /<span class="hb-status-key">off<\/span>/.test(bar),
  'the caret item is not keyed "off"',
);
check(
  'the engine dot sits with its own label at the far right',
  /<span class="hb-status-item"><span class="hb-status-dot is-ready" id="status-dot"><\/span><span class="hb-status-value" id="status-state">ready<\/span><\/span>\s*\n\s*<\/div>/.test(bar),
  'the engine dot is not the last item beside its state label, so a colour change has nothing to read it against',
);
const barLines = bar.split('\n');
for (const id of ['status-offset', 'status-pane', 'status-selection', 'status-size', 'status-entropy', 'status-hits', 'status-scale', 'status-modified', 'status-mode', 'status-state']) {
  check(`the bar still declares #${id}`, bar.includes(`id="${id}"`), `#${id} is gone from index.html; the shell writes every readout key by that id and would fail at boot`);
  check(
    `#${id} sits inside an item that can be hidden`,
    barLines.some((line) => line.includes(`id="${id}"`) && line.includes('class="hb-status-item"')),
    `#${id} has no .hb-status-item around it; #renderStatus hides a value by hiding that wrapper and would throw on a value with none`,
  );
}

if (failures.length > 0) {
  process.stdout.write(`${failures.length} status bar expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('status bar tiers (UX-3): all expectations held\n');
