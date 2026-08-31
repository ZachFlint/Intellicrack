/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Gates BE-4: the Patch menu used to offer a hardcoded pair (IPS export, JSON
 * export, IPS import) while the engine already published eight export
 * formats and three import formats (ips, ips32, cod, json, bps, bps_from_path,
 * ups, ups_from_path / ips, bps, ups). The fix replaces that pair with one
 * `patch.export` and one `patch.import` command, each opening a format picker
 * built from `this.#catalog.operations` at runtime rather than a list typed
 * into shell.js.
 *
 * The expected format list is not typed out here either: it comes from
 * actually running `hexbench.catalog.build_catalog()` in the same Python
 * interpreter the running application uses (the pixi env's own python.exe),
 * which is the live introspection of the compiled `intellicrack_hexcore`
 * extension - the same source catalog.py itself reads and the same source
 * `#transferPatches` filters at runtime. A new export or import format
 * (an "export patches" or "import patches" operation) added to the engine
 * changes what this subprocess call reports, and the assertions below would
 * catch shell.js falling out of step with it.
 *
 * shell.js transitively imports api.js, which reads `document`/`window` at
 * module scope, so both are stubbed with the bare minimum before it loads.
 *
 * Run by gate.ps1 (or directly with node). Exits non-zero on failure.
 */

import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
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
const repoRoot = fileURLToPath(new URL('../../../', import.meta.url));
const shellSource = (await readFile(`${staticDir}shell.js`, 'utf8')).replace(/\r\n/g, '\n');

const { patchFormatLabel } = await import('../static/shell.js');

/* ============================================================ the ground truth */

/**
 * Ask the real Python interpreter the running application uses to build the
 * catalogue for real, and report the full operation-name list plus the
 * export/import patch-format subsets it derives from live introspection of
 * `intellicrack_hexcore`.
 *
 * @returns {{all: string[], export: string[], import: string[]}} What the engine actually publishes right now.
 */
function realCatalogPatchOperations() {
  const pixiPython = fileURLToPath(new URL('../../../.pixi/envs/default/python.exe', import.meta.url));
  const pythonExe = existsSync(pixiPython) ? pixiPython : 'python';
  const script = [
    'import json, sys',
    `sys.path.insert(0, ${JSON.stringify(`${repoRoot.replace(/\\/g, '/')}src`)})`,
    'from hexbench.catalog import build_catalog',
    'names = sorted(op.name for op in build_catalog())',
    "print(json.dumps({'all': names}))",
  ].join('\n');
  const proc = spawnSync(pythonExe, ['-c', script], { cwd: repoRoot, encoding: 'utf8' });
  if (proc.error || proc.status !== 0) {
    throw new Error(
      `could not build the real engine catalogue via ${pythonExe}: `
      + `${proc.error ?? ''} status=${proc.status} stderr=${proc.stderr ?? ''}`,
    );
  }
  const { all } = JSON.parse(proc.stdout);
  return {
    all,
    export: all.filter((name) => name.startsWith('export_patches_')),
    import: all.filter((name) => name.startsWith('import_patches_')),
  };
}

const real = realCatalogPatchOperations();

check('the engine publishes at least one export_patches_* operation', real.export.length > 0, 'no export_patches_* operation came back from build_catalog(); this suite has nothing to check reachability against');
check('the engine publishes at least one import_patches_* operation', real.import.length > 0, 'no import_patches_* operation came back from build_catalog(); this suite has nothing to check reachability against');
check(
  'the real export formats include every one BE-4 was scoped against',
  ['export_patches_ips', 'export_patches_ips32', 'export_patches_cod', 'export_patches_json', 'export_patches_bps', 'export_patches_bps_from_path', 'export_patches_ups', 'export_patches_ups_from_path'].every((name) => real.export.includes(name)),
  `build_catalog() reported export formats ${JSON.stringify(real.export)}; expected it to be a superset of the eight BE-4 names it - the engine's own surface has narrowed`,
);
check(
  'the real import formats include every one BE-4 was scoped against',
  ['import_patches_ips', 'import_patches_bps', 'import_patches_ups'].every((name) => real.import.includes(name)),
  `build_catalog() reported import formats ${JSON.stringify(real.import)}; expected it to be a superset of the three BE-4 names - the engine's own surface has narrowed`,
);

/* --------------------------------------------------------- the Patch menu */

const patchMenu = /id: 'patch',\s*\n\s*items: \[([\s\S]*?)\],\s*\n\s*\},/.exec(shellSource);
check('the patch menu could be located in MENUS', patchMenu !== null, 'MENUS no longer declares a "patch" entry');
const patchMenuBody = patchMenu ? patchMenu[1] : '';

check('the Patch menu carries exactly one export command (patch.export)', patchMenuBody.includes("'patch.export'"), 'patch.export is missing from the Patch menu');
check('the Patch menu carries exactly one import command (patch.import)', patchMenuBody.includes("'patch.import'"), 'patch.import is missing from the Patch menu');
check(
  'the old hardcoded per-format export entries are gone from the Patch menu',
  !patchMenuBody.includes("'patch.exportJson'") && !patchMenuBody.includes("'patch.exportIps'"),
  'the Patch menu still lists patch.exportJson or patch.exportIps: the hardcoded pair was supposed to be replaced, not kept alongside the new picker',
);
check(
  'patch.exportJson is no longer defined as a command anywhere in shell.js',
  !/#define\('patch\.exportJson'/.test(shellSource),
  'this.#define(\'patch.exportJson\', ...) still exists; BE-4 asked for one export command, not a hardcoded pair plus a new one',
);
check(
  'patch.exportIps is no longer defined as a command anywhere in shell.js',
  !/#define\('patch\.exportIps'/.test(shellSource),
  'this.#define(\'patch.exportIps\', ...) still exists; BE-4 asked for one export command, not a hardcoded pair plus a new one',
);

/* ------------------------------------------------ the patch.export/import commands */

function commandDefinition(id) {
  const escaped = id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = new RegExp(`this\\.#define\\('${escaped}', '[^']*', '[^']*', \\(\\) => (.*)\\);$`, 'm').exec(shellSource);
  if (match === null) {
    return null;
  }
  const gated = match[1].endsWith(', hasDocument');
  const action = gated ? match[1].slice(0, match[1].lastIndexOf(',')) : match[1];
  return { action, gated };
}

for (const [id, expectedAction] of [
  ['patch.export', "this.#transferPatches('export')"],
  ['patch.import', "this.#transferPatches('import')"],
]) {
  const definition = commandDefinition(id);
  check(`${id} could be located as a #define(...) call`, definition !== null, `this.#define('${id}', ...) was not found in shell.js`);
  if (definition === null) {
    continue;
  }
  check(`${id} runs ${expectedAction}`, definition.action === expectedAction, `${id} runs "${definition.action}", expected "${expectedAction}"`);
  check(`${id} is gated on hasDocument`, definition.gated, `${id} is not gated on hasDocument; the Patch menu should not offer it with nothing open`);
}

/* -------------------------------------------------------- #transferPatches */

const transferMatch = /async #transferPatches\(direction\) \{[\s\S]*?\n  \}\n/.exec(shellSource);
check('#transferPatches(direction) could be located in shell.js', transferMatch !== null, 'async #transferPatches(direction) { ... } was not found as a single top-level method');
const transferBody = transferMatch ? transferMatch[0] : '';

const prefixMatch = /const prefix = direction === 'export' \? '([^']+)' : '([^']+)';/.exec(transferBody);
check(
  '#transferPatches derives its prefix from the direction rather than a fixed string',
  prefixMatch !== null,
  '#transferPatches no longer computes an export/import prefix from `direction`; the format list would stop tracking which half of the menu asked',
);
const [, exportPrefix, importPrefix] = prefixMatch ?? [null, null, null];
check('the export prefix is export_patches_', exportPrefix === 'export_patches_', `the export branch's prefix is ${JSON.stringify(exportPrefix)}, expected "export_patches_"`);
check('the import prefix is import_patches_', importPrefix === 'import_patches_', `the import branch's prefix is ${JSON.stringify(importPrefix)}, expected "import_patches_"`);

check(
  'the format list is filtered from the live catalogue, not a written-out array',
  /\(this\.#catalog\?\.operations \?\? \[\]\)\.filter\(\(operation\) => operation\.name\.startsWith\(prefix\)\)/.test(transferBody),
  '#transferPatches no longer filters this.#catalog?.operations by the computed prefix; a hardcoded format list would not notice a new export_patches_*/import_patches_* operation',
);

const formPart = /this\.#dialogs\.form\(\{[\s\S]*?\}\);/.exec(transferBody);
check('#transferPatches opens a picker dialog', formPart !== null, 'no this.#dialogs.form({ ... }) call was found inside #transferPatches');
const formBody = formPart ? formPart[0] : '';
const fieldNameCount = (formBody.match(/name: '/g) ?? []).length;
check(
  'the picker asks for exactly one field: the format',
  fieldNameCount === 1 && /name: 'format'/.test(formBody),
  `the picker dialog declares ${fieldNameCount} named field(s); expected exactly one ("format") - collecting a source argument here as well would duplicate what the generic per-operation dialog already builds from that operation's own parameters`,
);

check(
  'the chosen format is handed to the generic operation dialog, not a per-format handler',
  /this\.openOperation\(values\.format\);/.test(transferBody),
  '#transferPatches no longer calls this.openOperation(values.format); reachability depends on the generic dialog building its fields from the chosen operation\'s own parameter list - which is what makes a source-file argument appear only for the formats that declare one',
);

/* ------------------------------------- the real formats are actually reachable */

/**
 * What `#transferPatches` would compute for `direction`, given the live prefix
 * literals actually found in shell.js and the real engine's full operation
 * list - i.e. `(catalog.operations).filter(op => op.name.startsWith(prefix))`,
 * run for real against real data instead of merely pattern-matched as text.
 *
 * @param {string} prefix The prefix literal extracted from shell.js's own source.
 * @returns {string[]} Operation names #transferPatches would offer.
 */
function reachableFormats(prefix) {
  return real.all.filter((name) => name.startsWith(prefix));
}

if (exportPrefix !== null) {
  const reachableExport = [...reachableFormats(exportPrefix)].sort();
  const expectedExport = [...real.export].sort();
  check(
    'every export_patches_* operation the engine publishes is reachable through patch.export',
    JSON.stringify(reachableExport) === JSON.stringify(expectedExport),
    `shell.js's export prefix reaches ${JSON.stringify(reachableExport)}, the engine actually publishes ${JSON.stringify(expectedExport)}`,
  );
}
if (importPrefix !== null) {
  const reachableImport = [...reachableFormats(importPrefix)].sort();
  const expectedImport = [...real.import].sort();
  check(
    'every import_patches_* operation the engine publishes is reachable through patch.import',
    JSON.stringify(reachableImport) === JSON.stringify(expectedImport),
    `shell.js's import prefix reaches ${JSON.stringify(reachableImport)}, the engine actually publishes ${JSON.stringify(expectedImport)}`,
  );
}

/* ------------------------------------------------------- patchFormatLabel() */

/**
 * An oracle for `patchFormatLabel`, computed independently (regex rather than
 * `endsWith`/`slice`) so a broken implementation of the real function is
 * caught rather than the two copies agreeing by construction.
 *
 * @param {string} name Operation name, e.g. `export_patches_bps_from_path`.
 * @param {string} prefix Prefix to strip.
 * @returns {string} The expected label.
 */
function expectedPatchFormatLabel(name, prefix) {
  const suffix = name.slice(prefix.length);
  const fromPath = /^(.+)_from_path$/.exec(suffix);
  if (fromPath !== null) {
    return `${fromPath[1].toUpperCase()} (from a source path)`;
  }
  return suffix.toUpperCase();
}

for (const name of real.export) {
  const got = patchFormatLabel(name, 'export_patches_');
  const want = expectedPatchFormatLabel(name, 'export_patches_');
  check(`patchFormatLabel labels ${name} as "${want}"`, got === want, `patchFormatLabel(${JSON.stringify(name)}, 'export_patches_') returned ${JSON.stringify(got)}, expected ${JSON.stringify(want)}`);
}
for (const name of real.import) {
  const got = patchFormatLabel(name, 'import_patches_');
  const want = expectedPatchFormatLabel(name, 'import_patches_');
  check(`patchFormatLabel labels ${name} as "${want}"`, got === want, `patchFormatLabel(${JSON.stringify(name)}, 'import_patches_') returned ${JSON.stringify(got)}, expected ${JSON.stringify(want)}`);
}

if (failures.length > 0) {
  process.stdout.write(`${failures.length} patch-format menu expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write(`patch export/import formats (BE-4): all expectations held (${real.export.length} export, ${real.import.length} import formats reachable)\n`);
