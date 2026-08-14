/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Exercises panels.js's pure request-sequencing and document-scoping rules
 * for real, and reads panels.js as text to confirm the panels those rules
 * were extracted from actually call them. panels.js transitively imports
 * api.js, whose module-level token resolution touches `document`/`window`,
 * and panels.js itself starts a self-installing poll loop
 * (`whenPublished()`) the moment it is imported, so both globals are stubbed
 * with the bare minimum before the module is loaded: `window.setTimeout` is
 * a no-op so that poll never reschedules itself and the process can exit.
 * The stub is never touched by any assertion below, every check runs
 * against the real exported functions.
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
/* Read with line endings normalised to LF. The repository stores its sources
 * with CRLF terminators, and every structural pattern below is written against
 * "\n"; matching them against the raw bytes would fail on the line endings
 * rather than on the code the checks are actually about. */
const panelsSource = (await readFile(`${staticDir}panels.js`, 'utf8')).replace(/\r\n/g, '\n');

const { createRequestGate, documentKey } = await import('../static/panels.js');

/* ------------------------------------------------------ #38/#66: request gate */

const gate = createRequestGate();
const firstToken = gate.begin();
check('a freshly begun token reads as current', gate.isCurrent(firstToken), 'the token just handed out should be the current one');

const secondToken = gate.begin();
check(
  'beginning a newer request invalidates the older token (the defect)',
  !gate.isCurrent(firstToken),
  'an older in-flight request must stop being "current" once a newer one starts, or an out-of-order reply can overwrite a newer one',
);
check('the newest token still reads as current', gate.isCurrent(secondToken), 'the most recently begun token must remain current until superseded');

const independentGate = createRequestGate();
check(
  'two gate instances track independent sequences',
  independentGate.isCurrent(firstToken) === false,
  'a token from one gate must never be mistaken for current on an unrelated gate',
);

check(
  'inspectorPanel guards its paint() reply with a request gate',
  /const gate = createRequestGate\(\);[\s\S]{0,600}const token = gate\.begin\(\);[\s\S]{0,300}if \(gate\.isCurrent\(token\)\)/.test(panelsSource),
  'inspectorPanel no longer tokenises its inspect_at request, so a stale reply can again overwrite a fresher one',
);
check(
  'the VA mapping converter guards its reply with its own request gate',
  /const gate = createRequestGate\(\);[\s\S]{0,900}if \(!gate\.isCurrent\(token\)\)/.test(panelsSource),
  'the file-offset/VA converter no longer tokenises its request, so a stale conversion can again overwrite a fresher one',
);
check(
  'inspectorPanel and vaMappingsPanel each construct their own gate (two call sites)',
  (panelsSource.match(/const gate = createRequestGate\(\);/g) ?? []).length >= 2,
  'expected at least two independent createRequestGate() call sites (inspector and the VA converter)',
);

/* ------------------------------------------------------------- documentKey */

check(
  'documentKey distinguishes two different handles',
  documentKey({ handle: 'doc-a', generation: 1 }) !== documentKey({ handle: 'doc-b', generation: 1 }),
  'two different open documents must not share a key',
);
check(
  'documentKey distinguishes generations of the same handle',
  documentKey({ handle: 'doc-a', generation: 1 }) !== documentKey({ handle: 'doc-a', generation: 2 }),
  'an edit that bumps the generation must change the key, or a stale panel would not know to refresh',
);
check(
  'documentKey treats a missing document consistently',
  documentKey(null) === documentKey(undefined) && documentKey(null) === documentKey({}),
  'no active document should always produce the same key regardless of how "no document" is spelled',
);
check(
  'documentKey reuses the same key for the same document',
  documentKey({ handle: 'doc-a', generation: 4 }) === documentKey({ handle: 'doc-a', generation: 4 }),
  'an unrelated re-render of the same document must not look like a document switch',
);

/* --------------------------------------------------------------- #37: strings panel */

const stringsPanelMatch = /function stringsPanel\(env\) \{[\s\S]*?\n\}\n/.exec(panelsSource);
check('the strings panel function could be located in panels.js for inspection', stringsPanelMatch !== null, 'function stringsPanel(env) { ... } was not found as a single top-level block');
const stringsPanelSource = stringsPanelMatch ? stringsPanelMatch[0] : '';

check(
  'stringsPanel.update is no longer a no-op (the defect)',
  stringsPanelSource.length > 0 && !/update:\s*\(\)\s*=>\s*undefined,/.test(stringsPanelSource),
  'stringsPanel still declares update: () => undefined, so switching documents leaves a stale string list on screen',
);
check(
  'stringsPanel.update compares the active document through documentKey',
  /update: \(context\) => \{\s*const key = documentKey\(context\.document\);/.test(stringsPanelSource),
  'stringsPanel.update no longer keys off documentKey(context.document), so it cannot notice a document switch',
);
check(
  'stringsPanel clears its stale results when the document changes',
  /lastKey = key;\s*\n\s*clear\(\);/.test(stringsPanelSource),
  'stringsPanel.update no longer calls clear() when the tracked document changes, so results from a previous document would persist',
);
check(
  'stringsPanel starts from the same clear() the mount hook uses',
  /clear\(\);\s*\n\s*\},\s*\n\s*update:/.test(stringsPanelSource),
  'stringsPanel.mount no longer initialises through the same clear() helper update() uses, so the two code paths could drift apart',
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} panels expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('panels request-sequencing and document-scope rules: all expectations held\n');
