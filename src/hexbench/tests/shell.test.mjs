/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Exercises the shell's pure decision rules for real, and reads shell.js as
 * text to confirm the class methods those rules were extracted from actually
 * call them. shell.js transitively imports api.js, whose module-level token
 * resolution touches `document`/`window`, so those two globals are stubbed
 * with the bare minimum before the module is loaded -- the stub is never
 * touched by any assertion below, every check runs against the real
 * exported functions.
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
const shellSource = await readFile(`${staticDir}shell.js`, 'utf8');

const {
  isValidHexPattern,
  isValidHexSearchPattern,
  inspectorCacheKey,
  copyResultToast,
  nextEntropyState,
  shouldRunShortcut,
} = await import('../static/shell.js');

/* -------------------------------------------------------------- F41: hex search wildcard */

check('search pattern accepts a byte wildcard', isValidHexSearchPattern('4D ?? 90') === true, 'the documented ?? wildcard was rejected');
check('search pattern accepts a nibble wildcard', isValidHexSearchPattern('A?') === true, 'a single ? nibble wildcard was rejected');
check('search pattern still rejects non-hex letters', isValidHexSearchPattern('zz') === false, 'zz should never be a valid hex-ish pattern');
check('search pattern accepts plain hex', isValidHexSearchPattern('4D5A9000') === true, 'a plain literal pattern regressed');

check(
  'literal (replace/fill) pattern still rejects the wildcard',
  isValidHexPattern('4D ?? 90') === false,
  'replace_bytes takes raw bytes, not a wildcard pattern, so ?? must stay invalid here',
);
check('literal pattern accepts plain hex', isValidHexPattern('4D5A9000') === true, 'a plain literal pattern regressed');

check(
  'find() routes its hex-mode check through the wildcard-permissive rule',
  /isValidHexSearchPattern\(values\.needle\)/.test(shellSource),
  'find() no longer calls isValidHexSearchPattern on the hex-mode needle',
);
check(
  'replace() keeps the strict rule for both of its fields',
  /isValidHexPattern\(values\.find\)\s*\|\|\s*!isValidHexPattern\(values\.replace\)/.test(shellSource),
  'replace() no longer validates both fields with the strict (non-wildcard) rule',
);

/* -------------------------------------------------------------------- F14: inspector cache */

check('inspectorCacheKey is null with no document', inspectorCacheKey(null, 0) === null, 'a null document must not produce a cache key');
const keyDocA = inspectorCacheKey({ handle: 'doc-a', generation: 1 }, 0);
const keyDocB = inspectorCacheKey({ handle: 'doc-b', generation: 1 }, 0);
check(
  'switching documents at the same offset changes the cache key',
  keyDocA !== keyDocB,
  `expected different keys for different documents at offset 0, got the same key ${keyDocA} for both`,
);
check(
  'a new generation of the same document changes the cache key',
  inspectorCacheKey({ handle: 'doc-a', generation: 1 }, 0) !== inspectorCacheKey({ handle: 'doc-a', generation: 2 }, 0),
  'an edit to the active document (bumping its generation) must invalidate the inspector cache',
);
check(
  'the same document and offset reuse the same key',
  inspectorCacheKey({ handle: 'doc-a', generation: 1 }, 4) === inspectorCacheKey({ handle: 'doc-a', generation: 1 }, 4),
  'an unrelated re-render at the same caret position should not force a re-fetch',
);

check(
  'the inspector panel keys its cache through inspectorCacheKey',
  /const key = inspectorCacheKey\(context\.document, offset\)/.test(shellSource),
  'the inspector panel update() no longer compares a document-aware cache key',
);

/* -------------------------------------------------------------------------- F40: copy cap */

const complete = copyResultToast(200, 200);
check('a complete copy reports success', complete.kind === 'success', `expected success, got ${complete.kind}`);
check('a complete copy names no limit', !complete.detail.includes('exceeds'), 'a complete copy should not warn about a cap');

const truncated = copyResultToast(4096, 100000);
check('a truncated copy reports a warning, not success', truncated.kind === 'warning', `expected warning, got ${truncated.kind}`);
check('a truncated copy states both counts', truncated.detail.includes('4096') && truncated.detail.includes('100000'), `truncated detail did not name both counts: ${truncated.detail}`);

check(
  'copySelection reports the toast through copyResultToast',
  /copyResultToast\(bytes\.length, selection\.length\)/.test(shellSource),
  'copySelection no longer routes its result through copyResultToast, so a truncated copy could again read as complete success',
);

/* --------------------------------------------------------------------- F42: entropy reset */

const request = { handle: 'doc-a', generation: 3 };
const sameActive = { handle: 'doc-a', generation: 3 };
const movedOnActive = { handle: 'doc-a', generation: 4 };

const successResult = nextEntropyState({ ok: true, value: 5.5 }, request, sameActive);
check('a successful, current refresh updates the value', successResult.changed === true && successResult.value === 5.5, `expected changed value 5.5, got ${JSON.stringify(successResult)}`);

const failureResult = nextEntropyState({ ok: false }, request, sameActive);
check(
  'a failed, current refresh resets the value rather than leaving it stale (the defect)',
  failureResult.changed === true && failureResult.value === null,
  `a failed refresh must reset entropy to null so the status bar shows "-"; got ${JSON.stringify(failureResult)}`,
);

const staleFailure = nextEntropyState({ ok: false }, request, movedOnActive);
check(
  'a failed refresh for a document the user has already moved past is dropped',
  staleFailure.changed === false,
  `a stale reply must not touch the newer document's entropy; got ${JSON.stringify(staleFailure)}`,
);

const noActive = nextEntropyState({ ok: false }, request, null);
check('a reply with no active document at all is dropped', noActive.changed === false, `expected dropped, got ${JSON.stringify(noActive)}`);

check(
  '#scheduleEntropy applies a successful reply through applyOutcome/nextEntropyState',
  /\.then\(\(result\) => applyOutcome\(\{ ok: true, value: result\.value \}\)\)/.test(shellSource),
  'the success branch of the debounced entropy call no longer routes through applyOutcome',
);
check(
  '#scheduleEntropy applies a failed reply through applyOutcome/nextEntropyState instead of swallowing it',
  /\.catch\(\(\) => applyOutcome\(\{ ok: false \}\)\)/.test(shellSource),
  'the failure branch of the debounced entropy call no longer routes through applyOutcome, so a failed refresh could again leave a stale reading on screen',
);

/* -------------------------------------------------------------------- F43: clear hits docks */

check(
  'clearHits() refreshes the docks like setHits() does',
  /clearHits\(\) \{[\s\S]*?#updateDocks\(\);[\s\S]*?\}/.test(shellSource),
  'clearHits() still omits the #updateDocks() call that setHits() ends with, so a dock panel showing hits goes stale on Clear results',
);

/* ----------------------------------------------------------------------------- F44: exit */

check('file.exit no longer wires directly to window.close()', !/'file\.exit'.*window\.close\(\)/.test(shellSource), 'file.exit still calls window.close() directly with no server-side shutdown');
check('file.exit runs the shell\'s own exit() command', /this\.#define\('file\.exit', 'Exit', '', \(\) => this\.exit\(\)\)/.test(shellSource), 'file.exit is not wired to Shell#exit()');
check('exit() calls the server shutdown route', /async exit\(\) \{\s*await shutdown\(\);/.test(shellSource), 'Shell#exit() no longer awaits the api.js shutdown() call');
check('shutdown is imported from api.js', /import \{[^}]*\bshutdown\b[^}]*\} from '\.\/api\.js';/.test(shellSource), 'shell.js no longer imports shutdown from api.js');

/* ---------------------------------------------------------------- F68: ctrl+c input hijack */

check(
  'ctrl+c in a field with its own selection defers to native copy (the defect)',
  shouldRunShortcut('ctrl+c', { typing: true, hasTextSelection: true, gridSelection: { start: 0, length: 4 } }) === false,
  'a user copying text they selected in the toolbar offset field must not have it replaced by the hex-grid copy',
);
check(
  'ctrl+c in a field with no selection still runs the grid copy',
  shouldRunShortcut('ctrl+c', { typing: true, hasTextSelection: false, gridSelection: { start: 0, length: 4 } }) === true,
  'focusing an empty field should not disable Ctrl+C for the grid selection',
);
check(
  'ctrl+c outside any field still requires a grid selection',
  shouldRunShortcut('ctrl+c', { typing: false, hasTextSelection: false, gridSelection: null }) === false,
  'Ctrl+C with nothing selected anywhere should still be a no-op',
);
check(
  'ctrl+c outside any field runs normally when the grid has a selection',
  shouldRunShortcut('ctrl+c', { typing: false, hasTextSelection: false, gridSelection: { start: 0, length: 1 } }) === true,
  'the ordinary Ctrl+C copy path regressed',
);
check(
  'a non-ctrl key while typing defers to native handling',
  shouldRunShortcut('a', { typing: true, hasTextSelection: false, gridSelection: null }) === false,
  'plain character keys must still fall through to native input handling while typing',
);
check(
  'a non-clipboard ctrl combo still runs while typing',
  shouldRunShortcut('ctrl+s', { typing: true, hasTextSelection: true, gridSelection: null }) === true,
  'Ctrl+S must keep working from inside a field even when that field has a selection',
);

check(
  '#bindKeyboard decides through shouldRunShortcut',
  /if \(!shouldRunShortcut\(combo, context\)\) \{/.test(shellSource),
  '#bindKeyboard no longer gates on shouldRunShortcut, so the extracted rule could be dead code',
);
check(
  '#bindKeyboard reads the focused element\'s own text selection',
  /hasTextSelection: Boolean\(nativeSelection && !nativeSelection\.isCollapsed\)/.test(shellSource),
  '#bindKeyboard no longer inspects the focused element\'s native selection',
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} shell expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('shell rendering rules: all expectations held\n');
