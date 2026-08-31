/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Gates BE-2: wiring add_va_mapping and remove_va_mapping into the VA panel,
 * and showing the virtual address beside the caret's file offset in the
 * status bar when a mapping covers it.
 *
 * `nextVaState` and `statusReadout` are exercised for real, against their
 * actual exported behaviour: a stale reply (the document moved on, or the
 * caret moved before the reply arrived) must never overwrite a fresher
 * reading, and "no mapping covers this offset" - which the engine reports as
 * `null`, not an error - must hide the item rather than print a placeholder,
 * per UX-3's rule that an unmeasured value is absent, never a dash. The panel
 * and markup wiring these pure functions feed cannot be exercised the same
 * way without reconstructing api.js's HTTP layer and a live document, so
 * those parts are read as text, the same technique panels_document_scope and
 * panels_diff_entropy_dock_wiring already use for their own panels.
 * shell.js and panels.js transitively import api.js, which reads
 * `document`/`window` at module scope, and panels.js starts a
 * self-installing poll loop the moment it is imported, so both globals are
 * stubbed with the bare minimum before either module loads.
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
globalThis.window = { location: { search: '' }, setTimeout: () => 0, clearTimeout: () => undefined };

const staticDir = fileURLToPath(new URL('../static/', import.meta.url));
const shellSource = (await readFile(`${staticDir}shell.js`, 'utf8')).replace(/\r\n/g, '\n');
const panelsSource = (await readFile(`${staticDir}panels.js`, 'utf8')).replace(/\r\n/g, '\n');
const indexSource = (await readFile(`${staticDir}index.html`, 'utf8')).replace(/\r\n/g, '\n');
const appSource = (await readFile(`${staticDir}app.js`, 'utf8')).replace(/\r\n/g, '\n');

const { nextVaState, statusReadout } = await import('../static/shell.js');

/* ------------------------------------------------------------ nextVaState */

const DOC_A = { handle: 'doc-a', generation: 3 };
const REQUEST = { handle: 'doc-a', generation: 3, offset: 0x600 };

const hit = nextVaState({ ok: true, value: 0x140001000 }, REQUEST, DOC_A, 0x600);
check(
  'a mapping that covers the offset produces its virtual address',
  hit.changed === true && hit.value === 0x140001000,
  `expected {changed: true, value: 0x140001000}, got ${JSON.stringify(hit)}`,
);

const noCoverage = nextVaState({ ok: true, value: null }, REQUEST, DOC_A, 0x600);
check(
  'no mapping covering the offset resets to null rather than an error state (the engine reports this as null, not a failure)',
  noCoverage.changed === true && noCoverage.value === null,
  `expected {changed: true, value: null}, got ${JSON.stringify(noCoverage)}`,
);

const failed = nextVaState({ ok: false }, REQUEST, DOC_A, 0x600);
check(
  'a failed lookup resets to null rather than leaving a stale reading on screen',
  failed.changed === true && failed.value === null,
  `expected {changed: true, value: null}, got ${JSON.stringify(failed)}`,
);

const staleHandle = nextVaState({ ok: true, value: 0x1000 }, REQUEST, { handle: 'doc-b', generation: 3 }, 0x600);
check(
  'a reply for a document that is no longer active is dropped (stale by handle)',
  staleHandle.changed === false,
  `a stale-by-handle reply must not overwrite the current reading, got ${JSON.stringify(staleHandle)}`,
);

const staleGeneration = nextVaState({ ok: true, value: 0x1000 }, REQUEST, { handle: 'doc-a', generation: 4 }, 0x600);
check(
  'a reply for a superseded generation of the same document is dropped (an edit landed first)',
  staleGeneration.changed === false,
  `a stale-by-generation reply must not overwrite the current reading, got ${JSON.stringify(staleGeneration)}`,
);

const staleCaret = nextVaState({ ok: true, value: 0x1000 }, REQUEST, DOC_A, 0x700);
check(
  'a reply for an offset the caret has already left is dropped (the defect this gate exists for)',
  staleCaret.changed === false,
  `the caret moved from 0x600 to 0x700 before this reply arrived; it must not land, got ${JSON.stringify(staleCaret)}`,
);

const noDocument = nextVaState({ ok: true, value: 0x1000 }, REQUEST, null, 0x600);
check(
  'a reply that arrives after the document closed is dropped',
  noDocument.changed === false,
  `got ${JSON.stringify(noDocument)}`,
);

/* -------------------------------------------------------- statusReadout va */

const CARET = { offset: 0x4a, pane: 'hex', nibble: 0 };
const DOCUMENT = { handle: 'doc-a', generation: 1, length: 640, modified: false };
const METRICS = { scaled: false, bytesPerPixel: 1 };

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
    metrics: METRICS,
    va: null,
    ...overrides,
  };
}

check(
  'no mapping over the caret hides the va item, per UX-3\'s rule for an unmeasured value',
  statusReadout(caretOnly()).va === null,
  `expected va to be hidden (null) with no mapping, got ${JSON.stringify(statusReadout(caretOnly()).va)}`,
);

const covered = statusReadout(caretOnly({ va: 0x140001000 }));
check(
  'a covered offset prints the virtual address as hexadecimal and decimal, matching the file offset\'s own format',
  covered.va === '0x140001000 · 5368713216',
  `got ${JSON.stringify(covered.va)}`,
);
check(
  'the va reading pads to the same eight hex digits the offset uses',
  /^0x[0-9A-F]{8,}/.test(covered.va),
  `got ${JSON.stringify(covered.va)}`,
);

check(
  'statusReadout defaults va to null when a caller omits it, so callers that predate VA mapping still work',
  statusReadout({ document: DOCUMENT, caret: CARET, selection: null, entropy: null, hits: 0, hitIndex: -1, insertMode: false, busy: false, metrics: METRICS }).va === null,
  'omitting va from the state object must not throw and must hide the item',
);

/* --------------------------------------------------------- how it is wired */

check(
  '#onCaret schedules a VA lookup on every caret move',
  /#onCaret\(caret\) \{[\s\S]{0,200}this\.#scheduleVa\(\);/.test(shellSource),
  '#onCaret no longer calls #scheduleVa, so moving the caret would never refresh the status-bar VA reading',
);
check(
  '#scheduleVa debounces through file_offset_to_va, keyed on the caret\'s own offset',
  /callOp\('file_offset_to_va', \{ handle: request\.handle, arguments: \{ offset: request\.offset \} \}\)/.test(shellSource),
  '#scheduleVa no longer calls file_offset_to_va with the caret offset',
);
check(
  '#scheduleVa routes its outcome through nextVaState, the function this gate proved above',
  /const next = nextVaState\(outcome, request, active, this\.#grid\.caret\.offset\);/.test(shellSource),
  '#scheduleVa no longer routes through nextVaState, so every rule proved above could be dead code',
);
check(
  '#renderStatus feeds va into statusReadout',
  /va: this\.#va,/.test(shellSource),
  '#renderStatus no longer passes #va into statusReadout, so a resolved mapping would never reach the bar',
);
check(
  'a closed document clears #va immediately rather than waiting on a stale timer',
  /if \(!this\.#active\) \{\s*\n\s*if \(this\.#va !== null\) \{\s*\n\s*this\.#va = null;/.test(shellSource),
  '#scheduleVa no longer resets #va to null when there is no active document',
);

/* -------------------------------------------------------------- the markup */

const statusbar = /<div class="hb-statusbar" id="statusbar">([\s\S]*?)<\/div>/.exec(indexSource);
check('the status bar could be located in index.html', statusbar !== null, 'the .hb-statusbar block was not found in index.html');
const barMarkup = statusbar ? statusbar[1] : '';

check('index.html declares a status-va slot', barMarkup.includes('id="status-va"'), '#status-va is missing from index.html; the shell writes the VA readout by that id and would fail at boot');
check(
  'status-va starts hidden, like every value UX-3 has not measured yet',
  new RegExp('<span class="hb-status-item" hidden><span class="hb-status-key">va</span><span class="hb-status-value" id="status-va"></span></span>').test(barMarkup),
  'the status-va item is not declared hidden with a "va" key, so it would render an empty item before the first caret move',
);

const barItemIds = [...barMarkup.matchAll(/id="(status-[a-z]+)"/g)].map((match) => match[1]);
const offsetIndex = barItemIds.indexOf('status-offset');
const vaIndex = barItemIds.indexOf('status-va');
const paneIndex = barItemIds.indexOf('status-pane');
check(
  'va sits in the same tier as offset - "where the caret is" - immediately after it and before pane',
  offsetIndex !== -1 && vaIndex === offsetIndex + 1 && paneIndex === vaIndex + 1,
  `expected the order …offset, va, pane…, got ${JSON.stringify(barItemIds)}`,
);

check(
  'app.js wires #status-va into the status node map the shell reads',
  /va: byId\('status-va'\),/.test(appSource),
  'collectNodes() no longer resolves #status-va, so Shell would throw reading nodes.status.va',
);

/* ------------------------------------------------------------- the panel */

const vaPanelMatch = /function vaMappingsPanel\(env\) \{[\s\S]*?\n\}\n/.exec(panelsSource);
check('vaMappingsPanel could be located in panels.js for inspection', vaPanelMatch !== null, 'function vaMappingsPanel(env) { ... } was not found as a single top-level block');
const vaPanelSource = vaPanelMatch ? vaPanelMatch[0] : '';

check(
  'the header offers a "+" action that adds a mapping through add_va_mapping',
  /panelAction\('\+', 'Add a mapping', \(\) => \{\s*\n\s*promptAndRun\(env, 'add_va_mapping', \{ file_offset: env\.formContext\(\)\.caret \}\)\.then\(reload\);/.test(vaPanelSource),
  'the "+" header action no longer opens add_va_mapping, so BE-2\'s add entry point is missing',
);
check(
  'every mapping row can be removed through remove_va_mapping',
  /actionButton\('remove', `Remove mapping \$\{index\}`, \(\) => \{\s*\n\s*env\.run\('remove_va_mapping', \{ index \}, handle\)/.test(vaPanelSource),
  'a mapping row no longer offers remove_va_mapping, so BE-2\'s per-row remove is missing',
);
check(
  'removing a mapping reloads the table rather than leaving a stale row on screen',
  /env\.run\('remove_va_mapping', \{ index \}, handle\)\s*\n\s*\.then\(\(\) => reload\(\)\)/.test(vaPanelSource),
  'remove_va_mapping no longer reloads the table on success',
);

check(
  'the table body carries no padding, per the panel spec',
  /body = element\('div', 'hb-panel-body'\);/.test(vaPanelSource) && !/body = element\('div', 'hb-panel-body is-padded'\);/.test(vaPanelSource),
  'the VA table\'s hb-panel-body gained an is-padded class, or lost its own declaration',
);
check(
  'the table columns are file, va and size, values monospace (file and va) or numeric (size)',
  /\{ label: 'file', className: 'is-mono' \},\s*\n\s*\{ label: 'va', className: 'is-mono' \},\s*\n\s*\{ label: 'size', className: 'is-numeric' \},/.test(vaPanelSource),
  'the VA table no longer declares file/va/size columns in that order with those classes',
);
check(
  'a selected row carries is-selected',
  /row\.classList\.toggle\('is-selected', index === selectedIndex\);/.test(vaPanelSource) && /row\.classList\.add\('is-selected'\);/.test(vaPanelSource),
  'the VA table no longer marks the selected row with is-selected',
);
check(
  'clicking a row moves the caret to that mapping\'s file offset - which is how its VA reaches the status bar, through the same caret pipeline every other seek uses',
  /row\.addEventListener\('click', \(\) => \{\s*\n\s*selectedIndex = index;[\s\S]{0,200}env\.bench\.select\(offset, Math\.max\(1, length\)\);/.test(vaPanelSource),
  'a table row no longer calls env.bench.select on click, so selecting a mapping would not move the caret (and so would not update the status-bar VA)',
);

check(
  'vaMappingsPanel is registered so bench.registerPanel actually mounts it',
  /vaMappingsPanel\(env\),/.test(panelsSource) && panelsSource.includes("id: 'panels.va',"),
  'vaMappingsPanel(env) is no longer passed to bench.registerPanel, or its id changed',
);

/* Per the correction recorded for this stage: list_va_mappings returns plain
 * (file_offset, virtual_address, length) triples - intellicrack-hexcore/src/lib.rs
 * carries no per-mapping section, protection or backing-module field, and the
 * catalogue exposes no operation that could derive one. A "Section" column
 * would have nothing real to show, so this gate holds the table to the three
 * columns the engine actually returns rather than asserting a fourth column
 * this codebase has no data for. */
check(
  'the table has no fabricated Section column (no engine call in this codebase supplies per-mapping section data)',
  !/label: 'section'/i.test(vaPanelSource),
  'a Section column appeared with no backing operation to populate it - this would be a placeholder, which the project forbids',
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} VA mapping expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('VA mapping panel and status-bar wiring (BE-2): all expectations held\n');
