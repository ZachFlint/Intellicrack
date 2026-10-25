/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Gates how the browser treats a comparison the engine cut short. diff_bytes
 * and diff_files list at most `max_regions` regions and count the rest, so a
 * view that draws the list as if it were the whole answer, or reports "identical"
 * because the list holds no change, is wrong in a way no other check notices.
 *
 * `regionAccounting` and `readLimit` are pure and are exercised for real. The
 * panel and renderer bodies are closures that need a live bench and DOM, so
 * their wiring is read as text, the same technique
 * panels_diff_entropy_dock_wiring.test.mjs uses. Both modules transitively
 * import api.js, which reads `document`/`window` at module scope, so both
 * globals are stubbed with the bare minimum before they load.
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
globalThis.window = { location: { search: '' }, setTimeout: () => 0, clearTimeout: () => undefined };

const staticDir = fileURLToPath(new URL('../static/', import.meta.url));
/* Read with line endings normalized to LF, matching the repository's CRLF
 * checkout against patterns written for "\n". */
const panelsSource = (await readFile(`${staticDir}panels.js`, 'utf8')).replace(/\r\n/g, '\n');
const renderersSource = (await readFile(`${staticDir}renderers.js`, 'utf8')).replace(/\r\n/g, '\n');

const { regionAccounting } = await import('../static/renderers.js');
const { readLimit } = await import('../static/panels.js');

/* ------------------------------------------------------- regionAccounting */

const cut = regionAccounting({ regions: [{}, {}, {}], region_count: 1000 });
check(
  'a result with more regions counted than listed reports the difference',
  cut.listed === 3 && cut.counted === 1000 && cut.unlisted === 997,
  `expected 3 listed, 1000 counted, 997 unlisted, got ${JSON.stringify(cut)}`,
);

const whole = regionAccounting({ regions: [{}, {}], region_count: 2 });
check('a complete result has nothing unlisted', whole.unlisted === 0 && whole.counted === 2, `got ${JSON.stringify(whole)}`);

const legacy = regionAccounting({ regions: [{}, {}, {}] });
check(
  'a result from an engine that reports no region_count is taken to be complete',
  legacy.unlisted === 0 && legacy.counted === 3,
  `got ${JSON.stringify(legacy)}`,
);

const bogus = regionAccounting({ regions: [{}, {}, {}], region_count: 1 });
check(
  'a count smaller than the list is never reported as a negative number of unlisted regions',
  bogus.unlisted === 0 && bogus.counted === 3,
  `got ${JSON.stringify(bogus)}`,
);

const empty = regionAccounting(null);
check('no result at all is an empty, complete listing', empty.listed === 0 && empty.counted === 0 && empty.unlisted === 0, `got ${JSON.stringify(empty)}`);

check(
  'renderDiff words its banner from regionAccounting, not from the list length',
  /const \{ counted, unlisted \} = regionAccounting\(value\);/.test(renderersSource),
  'renderDiff no longer asks regionAccounting how many regions the engine counted, so a cut-short result reads as complete',
);
check(
  'renderDiff shows a truncation banner exactly when regions are unlisted',
  /if \(unlisted > 0\) \{[\s\S]{0,200}banner\(\s*'truncated'/.test(renderersSource),
  'renderDiff no longer appends a truncated banner when regions were counted but not listed',
);
check(
  'the truncated banner has its own glyph, matching the design card',
  /truncated: '⋮'/.test(renderersSource),
  'banner() has no glyph for the truncated kind, so it would fall back to the info glyph',
);

/* --------------------------------------------------------------- readLimit */

check('a blank limit keeps the engine default', readLimit('').ok === true && readLimit('').value === undefined, `got ${JSON.stringify(readLimit(''))}`);
check('whitespace is a blank limit', readLimit('   ').ok === true && readLimit('   ').value === undefined, `got ${JSON.stringify(readLimit('   '))}`);
check('a whole number is read as that number', readLimit('250').ok === true && readLimit('250').value === 250, `got ${JSON.stringify(readLimit('250'))}`);
check('zero is a valid limit (list nothing, count everything)', readLimit('0').ok === true && readLimit('0').value === 0, `got ${JSON.stringify(readLimit('0'))}`);
for (const text of ['-1', '1.5', '1e3', 'abc', '0x10', '12 34']) {
  check(`"${text}" is refused rather than guessed at`, readLimit(text).ok === false, `got ${JSON.stringify(readLimit(text))}`);
}
check(
  'a number too large to hold exactly is refused rather than rounded',
  readLimit('9007199254740993').ok === false,
  `got ${JSON.stringify(readLimit('9007199254740993'))}`,
);

/* ---------------------------------------------------------- the Diff panel */

const diffPanelMatch = /function diffPanel\(env\) \{[\s\S]*?\n\}\n/.exec(panelsSource);
check('diffPanel could be located in panels.js for inspection', diffPanelMatch !== null, 'function diffPanel(env) { ... } was not found as a single top-level block');
const diffPanelSource = diffPanelMatch ? diffPanelMatch[0] : '';

check(
  'a limit the user left blank is not sent, so the dispatcher supplies the engine default',
  /if \(limits\.minMatch !== undefined\) \{\s*\n\s*args\.min_match = limits\.minMatch;/.test(diffPanelSource)
    && /if \(limits\.maxRegions !== undefined\) \{\s*\n\s*args\.max_regions = limits\.maxRegions;/.test(diffPanelSource),
  'the compare call no longer sends min_match/max_regions conditionally, so it either ignores the dialog or hard-codes a default',
);
check(
  'the compare dialog asks for both limits',
  /name: 'minMatch'/.test(diffPanelSource) && /name: 'maxRegions'/.test(diffPanelSource),
  'the compare dialog lost its minimum match or most regions field',
);
check(
  'a limit that is not a whole number is refused before anything is compared',
  /const minMatch = readLimit\(values\.minMatch\);[\s\S]{0,300}if \(!minMatch\.ok \|\| !maxRegions\.ok\) \{[\s\S]{0,200}return;/.test(diffPanelSource),
  'chooseTarget no longer validates the limits through readLimit before calling compare',
);
check(
  '"identical" comes from the engine, not from the list holding no change',
  /if \(state\.filesIdentical\) \{/.test(diffPanelSource) && !/state\.changed\.length === 0\) \{\s*\n\s*tableHost\.replaceChildren\(\s*\n\s*banner\('success'/.test(diffPanelSource),
  'paintTable still decides a comparison is identical from an empty change list, so a cap of zero would report different files as identical',
);
check(
  'the panel shows a truncation banner when differing regions are unlisted',
  /unlisted > 0\) \{[\s\S]{0,200}banner\(\s*\n\s*'truncated'/.test(diffPanelSource),
  'paintTable no longer warns when the engine counted differing regions it did not list',
);
check(
  'the panel takes the differing-region count from the engine',
  /changeCount: Number\.isSafeInteger\(result\.value\?\.change_count\)/.test(diffPanelSource),
  'the panel no longer reads change_count, so it cannot say how many differing regions were left out',
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} diff region limit expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('diff region limits (min_match, max_regions, truncation): all expectations held\n');
