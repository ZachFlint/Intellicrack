/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Gates BE-5: entry points for real engine features that had none before -
 * the template registry under the Analyze menu, transforms and encodings
 * under Tools, and numeric search as a mode of the Find dialog - plus the
 * Template panel's own spec: selecting a field actually marks its bytes.
 *
 * `parseSearchInt` is exercised for real, against its actual exported
 * behaviour. The menu wiring, the dispatch argument shapes and the template
 * tree's click behaviour cannot be exercised the same way without
 * reconstructing api.js's HTTP layer, a live document and a real DOM, so
 * those are read as text and matched against the engine's own parameter
 * names (intellicrack-hexcore/src/lib.rs), the same technique
 * panels_diff_entropy_dock_wiring.test.mjs uses for BE-1's wiring. shell.js,
 * panels.js and renderers.js transitively import api.js, which reads
 * `document`/`window` at module scope, and panels.js starts a
 * self-installing poll loop the moment it is imported, so both globals are
 * stubbed with the bare minimum before any of them load.
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
const renderersSource = (await readFile(`${staticDir}renderers.js`, 'utf8')).replace(/\r\n/g, '\n');

const { parseSearchInt } = await import('../static/shell.js');

/* --------------------------------------------------------- parseSearchInt */

check('a hex literal parses', parseSearchInt('0x1A') === 26, `got ${parseSearchInt('0x1A')}`);
check('a binary literal parses', parseSearchInt('0b101') === 5, `got ${parseSearchInt('0b101')}`);
check('a decimal literal parses', parseSearchInt('42') === 42, `got ${parseSearchInt('42')}`);
check('a negative decimal parses, for a signed numeric search', parseSearchInt('-7') === -7, `got ${parseSearchInt('-7')}`);
check('a negative hex value parses', parseSearchInt('-0x10') === -16, `got ${parseSearchInt('-0x10')}`);
check('separators inside the literal are tolerated', parseSearchInt('1_000') === 1000, `got ${parseSearchInt('1_000')}`);
check('surrounding whitespace is tolerated', parseSearchInt('  0x2A  ') === 42, `got ${parseSearchInt('  0x2A  ')}`);
check('free text is rejected rather than coerced to 0', parseSearchInt('not a number') === null, `got ${parseSearchInt('not a number')}`);
check('a bare 0x prefix with no digits is rejected', parseSearchInt('0x') === null, `got ${parseSearchInt('0x')}`);
check('an empty field is rejected', parseSearchInt('') === null, `got ${parseSearchInt('')}`);

/* ------------------------------------------------------- the Analyze menu */

const analyzeMenu = /id: 'analyze',\s*\n\s*items: \[([\s\S]*?)\],\s*\n\s*\},/.exec(shellSource);
check('the analyze menu could be located in MENUS', analyzeMenu !== null, 'MENUS no longer declares an "analyze" entry');
const analyzeItems = analyzeMenu ? analyzeMenu[1] : '';
for (const command of ['analyze.templates', 'analyze.applyTemplate', 'analyze.registerTemplate', 'analyze.removeTemplate', 'analyze.exportTemplate']) {
  check(`the Analyze menu lists ${command}`, analyzeItems.includes(`'${command}'`), `${command} is missing from the Analyze menu, so the template registry has no menu entry point`);
}

/* --------------------------------------------------------- the Tools menu */

const toolsMenu = /id: 'tools',\s*\n\s*items: \[([\s\S]*?)\],\s*\n\s*\},/.exec(shellSource);
check('the tools menu could be located in MENUS', toolsMenu !== null, 'MENUS no longer declares a "tools" entry');
const toolsItems = toolsMenu ? toolsMenu[1] : '';
for (const command of ['tools.transforms', 'tools.applyTransform', 'tools.encodings', 'tools.decodeText']) {
  check(`the Tools menu lists ${command}`, toolsItems.includes(`'${command}'`), `${command} is missing from the Tools menu`);
}

/* --------------------------------------------------- what each command does */

/**
 * Find one `this.#define(id, label, shortcut, run, enabled)` call and report
 * what its run thunk does and whether it was given an enabled predicate.
 *
 * @param {string} id Command identifier, e.g. `'analyze.templates'`.
 * @returns {{action: string, gated: boolean}|null} The run thunk's body text
 * and whether a fifth (enabled) argument was passed, or null if not found.
 */
function commandDefinition(id) {
  const escaped = id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = new RegExp(`this\\.#define\\('${escaped}', '[^']*', '[^']*', \\(\\) => (.*)\\);$`, 'm').exec(shellSource);
  if (match === null) {
    return null;
  }
  const gated = match[1].endsWith(', hasDocument');
  const action = gated ? match[1].slice(0, -', hasDocument'.length) : match[1];
  return { action, gated };
}

const EXPECTED = [
  ['analyze.templates', "this.#focusRightPanel('panels.templates')", true],
  ['analyze.applyTemplate', "this.openOperation('apply_template')", true],
  ['analyze.registerTemplate', "this.openOperation('register_json_template')", true],
  ['analyze.removeTemplate', "this.openOperation('remove_template')", true],
  ['analyze.exportTemplate', "this.openOperation('export_template_json')", true],
  ['tools.transforms', "this.openOperation('list_transforms')", false],
  ['tools.applyTransform', "this.openOperation('transform_data')", true],
  ['tools.encodings', "this.openOperation('list_encodings')", false],
  ['tools.decodeText', "this.openOperation('decode_text')", true],
];

for (const [id, expectedAction, expectGated] of EXPECTED) {
  const definition = commandDefinition(id);
  check(`${id} could be located as a #define(...) call`, definition !== null, `this.#define('${id}', ...) was not found in shell.js`);
  if (definition === null) {
    continue;
  }
  check(`${id} runs ${expectedAction}`, definition.action === expectedAction, `${id} runs "${definition.action}", expected "${expectedAction}"`);
  check(
    `${id} is ${expectGated ? '' : 'not '}gated on an open document`,
    definition.gated === expectGated,
    `${id} is ${definition.gated ? '' : 'not '}gated on hasDocument, expected ${expectGated ? '' : 'not '}gated - ${expectGated ? 'the underlying operation is document-scoped in intellicrack-hexcore/src/lib.rs' : 'the underlying operation is a static/module call with no document argument'}`,
  );
}

/* -------------------------------------------------------- the Find dialog */

const findBody = /async find\(\) \{[\s\S]*?\n  \}\n/.exec(shellSource);
check('find() could be located in shell.js', findBody !== null, 'async find() { ... } was not found as a single top-level method');
const findSource = findBody ? findBody[0] : '';

for (const [value, label] of [['numeric', 'Numeric integer'], ['numeric_float', 'Numeric float'], ['numeric_range', 'Numeric range']]) {
  check(
    `the Find dialog offers "${label}" as a search kind`,
    findSource.includes(`{ value: '${value}', label: '${label}' }`),
    `the mode select no longer offers { value: '${value}', label: '${label}' }, so BE-5's numeric search has no way in`,
  );
}

/* Every parameter name below is taken verbatim from the Rust signatures in
 * intellicrack-hexcore/src/lib.rs (search_numeric, search_numeric_float,
 * search_numeric_range) - a renamed argument on either side would silently
 * turn a numeric search into a dispatch error the user has no way to read as
 * "the JS and the engine disagree about a parameter name". */
check(
  'search_numeric is called with value/size/signed/big_endian/alignment/max_results, matching lib.rs exactly',
  /runOnDocument\('search_numeric', \{ value: low, size, signed: values\.signed, big_endian: values\.bigEndian, alignment, max_results: limit \}\)/.test(findSource),
  'the search_numeric call no longer matches its Rust signature (value, size, signed, big_endian, alignment, max_results)',
);
check(
  'search_numeric_range is called with value_range as a two-element array, matching the (i64, i64) tuple lib.rs expects',
  /runOnDocument\('search_numeric_range', \{ value_range: \[low, high\], size, signed: values\.signed, big_endian: values\.bigEndian, alignment, max_results: limit \}\)/.test(findSource),
  'the search_numeric_range call no longer sends value_range as [low, high]',
);
check(
  'search_numeric_float is called with value/size/big_endian/tolerance/alignment/max_results, matching lib.rs exactly (no signed field - float search has none)',
  /runOnDocument\('search_numeric_float', \{\s*\n\s*value,\s*\n\s*size,\s*\n\s*big_endian: values\.bigEndian,\s*\n\s*tolerance: Number\.isFinite\(tolerance\) \? tolerance : 0,\s*\n\s*alignment,\s*\n\s*max_results: limit,\s*\n\s*\}\)/.test(findSource),
  'the search_numeric_float call no longer matches its Rust signature (value, size, big_endian, tolerance, alignment, max_results)',
);
check(
  'a non-numeric needle for a numeric search is rejected before it ever reaches the engine',
  /const low = parseSearchInt\(values\.needle\);\s*\n\s*if \(low === null\) \{/.test(findSource),
  'find() no longer validates the numeric needle through parseSearchInt before dispatching',
);
check(
  'a non-numeric range end is rejected the same way',
  /const high = parseSearchInt\(values\.rangeEnd\);\s*\n\s*if \(high === null\) \{/.test(findSource),
  'find() no longer validates the range end through parseSearchInt before dispatching',
);

/* ------------------------------------------------------------ the panel */

const templatesPanelMatch = /function templatesPanel\(env\) \{[\s\S]*?\n\}\n/.exec(panelsSource);
check('templatesPanel could be located in panels.js for inspection', templatesPanelMatch !== null, 'function templatesPanel(env) { ... } was not found as a single top-level block');
const templatesPanelSource = templatesPanelMatch ? templatesPanelMatch[0] : '';

check(
  'the header offers a "register from JSON" action through register_json_template',
  /panelAction\('\{\}', 'Register a template from JSON', \(\) => \{\s*\n\s*promptAndRun\(env, 'register_json_template', \{\}\)\.then\(reload\);/.test(templatesPanelSource),
  'the templates panel no longer offers register_json_template from its header',
);
check(
  'the header offers a "remove" action through remove_template',
  /panelAction\('−', 'Remove a registered template', \(\) => \{\s*\n\s*promptAndRun\(env, 'remove_template', \{\}\)\.then\(reload\);/.test(templatesPanelSource),
  'the templates panel no longer offers remove_template from its header',
);
check(
  'every listed template can be exported through export_template_json',
  /actionButton\('export', 'Export this template definition as JSON', \(\) => \{\s*\n\s*promptAndRun\(env, 'export_template_json', \{ name: entry\.name \}\);/.test(templatesPanelSource),
  'a template row no longer offers export_template_json',
);
check(
  'the footer states the field-marking contract the spec requires verbatim',
  templatesPanelSource.includes("'selecting a field marks its bytes with is-field'"),
  'the templates panel footer no longer states the is-field contract',
);

/* -------------------------------------- the template tree really marks bytes */

const templateNodeMatch = /function templateNode\(field, depth, ctx, budget\) \{[\s\S]*?\n\}\n/.exec(renderersSource);
check('templateNode could be located in renderers.js for inspection', templateNodeMatch !== null, 'function templateNode(field, depth, ctx, budget) { ... } was not found as a single top-level block');
const templateNodeSource = templateNodeMatch ? templateNodeMatch[0] : '';

check(
  'clicking a field row selects its bytes and marks them is-field, not merely highlights something generic',
  /ctx\.select\(offset, size\);\s*\n\s*ctx\.highlight\(\[\{ offset, length: size \}\], 'is-field'\);/.test(templateNodeSource),
  'a template field row no longer calls ctx.highlight([...], \'is-field\') on click, so BE-5\'s "selecting a field marks its bytes with is-field" is not wired',
);
check(
  'a validated field is told apart from a failed one by more than colour (an explicit pass/fail badge, not colour alone)',
  /hb-badge is-success', 'pass'/.test(templateNodeSource) && /hb-badge is-error', 'fail'/.test(templateNodeSource),
  'templateNode no longer renders distinct pass/fail badges for validation_passed, so a failed field is marked by colour alone',
);
check(
  'the struct/field mark is driven by the field\'s own color, per apply_template\'s per-field colour',
  /mark\.style\.background = field\.color;/.test(templateNodeSource),
  'templateNode no longer paints hb-tree-mark from field.color',
);
check(
  'a struct with children opens with a twisty that can collapse it, a leaf field has none',
  /children\.length > 0 \? 'hb-tree-twisty is-open' : 'hb-tree-twisty is-leaf'/.test(templateNodeSource),
  'templateNode no longer distinguishes an open struct twisty from a leaf field',
);

check(
  'renderTemplate is the renderer wired for apply_template results',
  /\['apply_template', renderTemplate\]/.test(renderersSource),
  'apply_template results no longer render through renderTemplate',
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} template/transform/numeric-search expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('templates, transforms, encodings and numeric search entry points (BE-5): all expectations held\n');
