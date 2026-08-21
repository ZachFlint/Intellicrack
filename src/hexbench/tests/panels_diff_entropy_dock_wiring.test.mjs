/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Gates the wiring halves of BE-1 (the Diff panel's grid marking, region
 * table and footer) and UX-1 (the four spatial analyses living in the bottom
 * dock instead of a modal, and the modal staying for one-shot text answers).
 *
 * `diffHighlightClass` is exercised for real, against the real
 * `DIFF_HIGHLIGHT_TOKENS` map `charts.js` exports for the mini-map, so the two
 * modules cannot silently disagree about which kind gets which class. The
 * panel bodies themselves are closures panels.js does not export - mounting
 * one for real would mean reconstructing `bench`, `callOp`'s HTTP layer and a
 * live document, so this reads panels.js and shell.js as text to confirm the
 * calls those pure pieces feed into are the ones actually made, the same
 * technique panels_document_scope.test.mjs uses for stringsPanel. panels.js
 * transitively imports api.js, which reads `document`/`window` at module
 * scope, and starts a self-installing poll loop the moment it is imported, so
 * both globals are stubbed with the bare minimum before the module loads.
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
/* Read with line endings normalised to LF, matching the repository's CRLF
 * checkout against patterns written for "\n". */
const panelsSource = (await readFile(`${staticDir}panels.js`, 'utf8')).replace(/\r\n/g, '\n');
const shellSource = (await readFile(`${staticDir}shell.js`, 'utf8')).replace(/\r\n/g, '\n');

const { diffHighlightClass } = await import('../static/panels.js');
const { DIFF_HIGHLIGHT_TOKENS } = await import('../static/charts.js');

/* --------------------------------------------------------- BE-1: the mapping */

check(
  'DIFF_HIGHLIGHT_TOKENS names exactly the three diff_bytes kinds the grid and the mini-map both mark',
  [...DIFF_HIGHLIGHT_TOKENS.keys()].sort().join(',') === 'inserted_a,inserted_b,modified',
  `got ${[...DIFF_HIGHLIGHT_TOKENS.keys()].sort().join(',')}`,
);

check(
  'diffHighlightClass maps an addition to is-diff-added',
  diffHighlightClass('inserted_b') === 'is-diff-added',
  `got ${diffHighlightClass('inserted_b')}`,
);
check(
  'diffHighlightClass maps a removal to is-diff-removed',
  diffHighlightClass('inserted_a') === 'is-diff-removed',
  `got ${diffHighlightClass('inserted_a')}`,
);
check(
  'diffHighlightClass maps a modification to is-diff-modified',
  diffHighlightClass('modified') === 'is-diff-modified',
  `got ${diffHighlightClass('modified')}`,
);

const mappedClasses = new Set([...DIFF_HIGHLIGHT_TOKENS.keys()].map(diffHighlightClass));
check(
  'every diff_bytes kind the mini-map marks gets its own distinct grid class (no two kinds collapse onto one mark)',
  mappedClasses.size === 3,
  `${[...DIFF_HIGHLIGHT_TOKENS.keys()].map((kind) => `${kind}->${diffHighlightClass(kind)}`).join(', ')} produced only ${mappedClasses.size} distinct class(es)`,
);
for (const className of mappedClasses) {
  check(
    `the app.css shape-channel rule for ${className} exists (A-8 pairs with BE-1)`,
    (await readFile(`${staticDir}app.css`, 'utf8')).includes(`.hb-byte.${className}`),
    `app.css has no [data-marks="on"] .hb-byte.${className} rule for a class the diff panel actually paints`,
  );
}

/* ---------------------------------------------------- BE-1: the panel wiring */

const diffPanelMatch = /function diffPanel\(env\) \{[\s\S]*?\n\}\n/.exec(panelsSource);
check('diffPanel could be located in panels.js for inspection', diffPanelMatch !== null, 'function diffPanel(env) { ... } was not found as a single top-level block');
const diffPanelSource = diffPanelMatch ? diffPanelMatch[0] : '';

check(
  'diffPanel pushes ranges into grid.highlight through env.bench.highlight, not a one-off overlay',
  /for \(const kind of DIFF_HIGHLIGHT_TOKENS\.keys\(\)\) \{[\s\S]{0,400}env\.bench\.highlight\(/.test(diffPanelSource),
  'applyHighlights (or its equivalent) no longer iterates DIFF_HIGHLIGHT_TOKENS and calls env.bench.highlight, so a diff_bytes result would never reach the byte grid',
);
check(
  'diffPanel clears all three diff layers, not just one, when the comparison is reset',
  /for \(const kind of DIFF_HIGHLIGHT_TOKENS\.keys\(\)\) \{[\s\S]{0,200}env\.bench\.highlight\(\[\], diffHighlightClass\(kind\)\)/.test(diffPanelSource),
  'clearHighlights (or its equivalent) no longer clears every is-diff-* layer, so a stale mark could survive a reset comparison',
);
check(
  'the mini-map is built through diffTrackChart, the canvas geometry charts.js exports for it',
  /diffTrackChart\(/.test(diffPanelSource),
  'diffPanel no longer calls diffTrackChart, so BE-1\'s mini-map spec has no renderer wired to it',
);
check(
  'the footer reports the operation, the size and the timing, per the design handoff\'s Diff spec',
  /footerText\.textContent = `diff_bytes · \$\{humanSize\(state\.comparedBytes\)\} compared in \$\{state\.durationMs\.toFixed\(2\)\} ms`/.test(diffPanelSource),
  'the footer no longer reads "diff_bytes · <size> compared in <n> ms", so hb-panel-footer stays as dead as DS-1 found it',
);
check(
  'the table renders kind as an hb-badge toned by the diff kind (added/removed/modified are not colour-only)',
  /hb-badge \$\{DIFF_KIND_TONE\.get\(kind\) \?\? ''\}/.test(diffPanelSource),
  'the Kind column no longer paints an hb-badge tone, so success/warning/error state is lost from the table',
);
check(
  'clicking a table row navigates the grid to that region',
  /row\.addEventListener\('click', \(\) => navigateTo\(region\)\)/.test(diffPanelSource),
  'a table row no longer calls navigateTo on click, so BE-1\'s "clicking a region navigates the grid to it" is not wired',
);
check(
  'the "next region" action steps the cursor through the changed regions and wraps around',
  /state\.cursor = \(state\.cursor \+ 1\) % state\.changed\.length/.test(diffPanelSource),
  'stepNext (or its equivalent) no longer advances state.cursor modulo the region count, so "next region" cannot step through the whole list',
);
check(
  'the diff panel lives in the bottom dock, not a modal',
  /id: 'panels\.diff',\s*\n\s*title: 'Diff',\s*\n\s*dock: 'bottom'/.test(diffPanelSource),
  'panels.diff no longer declares dock: \'bottom\'',
);

/* --------------------------------------------------- UX-1: the four analyses */

for (const [name, chartCall] of [['entropyPanel', 'entropyStripChart('], ['byteTypesPanel', 'byteTypeChart('], ['classificationPanel', 'classificationChart('], ['digramPanel', 'digramChart(']]) {
  const match = new RegExp(`function ${name}\\(env\\) \\{[\\s\\S]*?\\n\\}\\n`).exec(panelsSource);
  check(`${name} could be located in panels.js for inspection`, match !== null, `function ${name}(env) { ... } was not found as a single top-level block`);
  const body = match ? match[0] : '';
  check(
    `${name} declares dock: 'bottom' (a live panel, not a one-shot modal)`,
    /dock: 'bottom'/.test(body),
    `${name} no longer declares dock: 'bottom'`,
  );
  check(
    `${name} is built through ${chartCall.slice(0, -1)}, not routed through showResultModal`,
    body.includes(chartCall),
    `${name} no longer calls ${chartCall}`,
  );
  check(
    `${name} is instantiated in installPanels' panel list, so bench.registerPanel actually mounts it`,
    panelsSource.includes(`${name}(env),`),
    `${name}(env) is no longer passed to bench.registerPanel`,
  );
}

check(
  'entropyPanel follows the caret through the chart handle\'s setCaret, not a static snapshot',
  /chartHandle\.setCaret\(trackedKey === activeKey \? context\.caret\.offset : null\)/.test(panelsSource),
  'entropyPanel.update no longer calls chartHandle.setCaret with the live caret offset, so UX-1\'s "marks the caret\'s position on the strip" is not wired',
);
check(
  'entropyPanel stays open across an edit: it recomputes only when the tracked document key changes, not on every update',
  /if \(!pinned && trackedKey !== activeKey\) \{\s*\n\s*load\(context\.document\);/.test(panelsSource),
  'entropyPanel.update no longer gates reloading on trackedKey !== activeKey, so the panel would either never update or tear itself down every keystroke',
);
check(
  'entropyPanel offers a pin action, so a reading can stay put while another document is viewed',
  /'Pin to this document'/.test(panelsSource) && /pinned = !pinned/.test(panelsSource),
  'entropyPanel no longer offers a pin toggle',
);
check(
  'entropyPanel offers a recompute action',
  /'Recompute the entropy map'/.test(panelsSource),
  'entropyPanel no longer offers a recompute action',
);

/* ------------------------------------------------- UX-1: shell command routing */

const focusBottomCalls = new Map([...shellSource.matchAll(/this\.#define\('(analyze\.\w+)', '[^']*', '[^']*', \(\) => this\.#focusBottomPanel\('([\w.]+)'\)/g)].map(([, command, panelId]) => [command, panelId]));

for (const [command, panelId] of [['analyze.entropy', 'panels.entropy'], ['analyze.byteTypes', 'panels.byteTypes'], ['analyze.classification', 'panels.classification'], ['analyze.digram', 'panels.digram']]) {
  check(
    `${command} focuses the ${panelId} dock panel instead of opening a modal`,
    focusBottomCalls.get(command) === panelId,
    `${command} routes to ${focusBottomCalls.get(command) ?? '(no #focusBottomPanel call found)'}, expected ${panelId} - UX-1 requires the spatial analyses to live in the bottom dock`,
  );
}

check(
  'analyze.hash stays a one-shot modal (the design handoff\'s own example of what to keep in the modal)',
  /this\.#define\('analyze\.hash', 'Compute hash…', '', \(\) => this\.computeHash\(\)/.test(shellSource),
  'analyze.hash no longer opens through computeHash(), so it may have been (wrongly) converted into a dock panel',
);
check(
  'analyze.pe stays a one-shot modal (the design handoff\'s other example)',
  /this\.#define\('analyze\.pe', 'Verify PE checksum', '', \(\) => this\.showResult\('verify_pe_checksum', \{\}\)/.test(shellSource),
  'analyze.pe no longer opens through showResult(), so it may have been (wrongly) converted into a dock panel',
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} diff/entropy dock-wiring expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('diff and entropy dock wiring (BE-1, UX-1): all expectations held\n');
