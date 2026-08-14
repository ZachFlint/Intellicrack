/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Exercises renderers.js's pure truncation-aware decision rules for real, and
 * reads renderers.js as text to confirm the DOM code those rules were
 * extracted from actually calls them. renderers.js transitively imports
 * api.js, whose module-level token resolution touches `document`/`window`, so
 * those two globals are stubbed with the bare minimum before the module is
 * loaded -- the stub is never touched by any assertion below, every check
 * runs against the real exported functions.
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
const renderersSource = await readFile(`${staticDir}renderers.js`, 'utf8');

const { mergePatches, sliceCodePoints, writeBackPlan } = await import('../static/renderers.js');

/* ---------------------------------------------------------- #39: mergePatches */

const wholeEntryA = { __bytes__: '0102', length: 2, truncated: false };
const wholeEntryB = { __bytes__: '0304', length: 2, truncated: false };
const whole = mergePatches([[0, wholeEntryA], [2, wholeEntryB]]);
check(
  'adjacent untruncated entries coalesce into one run',
  whole.merged.length === 1 && whole.merged[0].offset === 0 && whole.merged[0].values.length === 4,
  `expected a single 4-byte run at offset 0, got ${JSON.stringify(whole.merged)}`,
);
check('an untruncated merge reports untruncated', whole.truncated === false, `expected false, got ${whole.truncated}`);

const cappedHex = 'ab'.repeat(4096);
const cappedEntry = { __bytes__: cappedHex, length: 8192, truncated: true };
const capped = mergePatches([[0, cappedEntry]]);
check(
  'mergePatches surfaces the truncated flag (the defect)',
  capped.truncated === true,
  'a patch entry the transport capped at 4096 bytes was merged without any indication the view understates it',
);
check(
  'the merged run only carries the bytes that actually arrived inline',
  capped.merged[0].values.length === 4096,
  `expected the inline-capped 4096 bytes, got ${capped.merged[0]?.values.length}`,
);

const skipped = mergePatches([[0, null]]);
check('an entry with no decodable bytes is skipped rather than crashing', skipped.merged.length === 0, `expected no runs, got ${JSON.stringify(skipped.merged)}`);

check(
  'renderPatches reads the truncated flag mergePatches now returns',
  /const \{ merged, truncated \} = mergePatches\(entries\)/.test(renderersSource),
  'renderPatches no longer destructures truncated off mergePatches, so a truncated merge cannot be reported',
);
check(
  'renderPatches warns when the merged view understates an entry',
  /if \(truncated\) \{[\s\S]{0,200}banner\(/.test(renderersSource),
  'renderPatches no longer appends a banner when mergePatches reports a truncated contribution',
);

/* ------------------------------------------------------ #67: sliceCodePoints */

check('short text passes through unchanged', sliceCodePoints('hello', 240) === 'hello', 'a string under the limit must not be altered');
check('empty text passes through unchanged', sliceCodePoints('', 240) === '', 'an empty string must not be altered');

const SURROGATE_TEXT = 'AB😀CD';
const naiveSlice = SURROGATE_TEXT.slice(0, 3);
check(
  'sanity: a raw code-unit slice actually breaks this pair',
  /[\uD800-\uDBFF]$/.test(naiveSlice),
  `the fixture no longer demonstrates the defect: naive slice produced ${JSON.stringify(naiveSlice)}`,
);

const safeSlice = sliceCodePoints(SURROGATE_TEXT, 3);
check(
  'sliceCodePoints never ends on a lone leading surrogate (the defect)',
  !/[\uD800-\uDBFF]$/.test(safeSlice),
  `expected no dangling high surrogate, got ${JSON.stringify(safeSlice)}`,
);
check(
  'sliceCodePoints keeps exactly the requested number of code points',
  [...safeSlice].length === 3,
  `expected 3 code points, got ${[...safeSlice].length}: ${JSON.stringify(safeSlice)}`,
);
check(
  'sliceCodePoints keeps the supplementary-plane character whole',
  safeSlice === 'AB😀',
  `expected "AB\\uD83D\\uDE00", got ${JSON.stringify(safeSlice)}`,
);

check(
  'the strings preview cell truncates through sliceCodePoints',
  /sliceCodePoints\(content, STRING_PREVIEW\)/.test(renderersSource),
  'renderStrings no longer truncates the preview cell through sliceCodePoints',
);
check(
  'the strings row title truncates through sliceCodePoints',
  /row\.title = sliceCodePoints\(content, TITLE_PREVIEW\)/.test(renderersSource),
  'renderStrings no longer truncates the row title through sliceCodePoints',
);

/* ------------------------------------------------------- #13: writeBackPlan */

const exactWrite = writeBackPlan({ length: 16, truncated: false }, 16);
check(
  'a matching, untruncated result needs no note',
  exactWrite.trueLength === 16 && exactWrite.truncated === false && exactWrite.note === null,
  `expected a clean plan, got ${JSON.stringify(exactWrite)}`,
);

const resizingWrite = writeBackPlan({ length: 8, truncated: false }, 16);
check(
  'a genuine length-changing transform is still flagged as a resize',
  resizingWrite.truncated === false && resizingWrite.note !== null && resizingWrite.note.includes('source range'),
  `expected a resize note, got ${JSON.stringify(resizingWrite)}`,
);

/* The finding's exact motivating case: a length-preserving transform (the
   true output length equals the source range) whose result was capped by
   the 4096-byte inline transport cap. */
const truncatedWrite = writeBackPlan({ length: 8192, truncated: true }, 8192);
check(
  'writeBackPlan reports the true (untruncated) length, not the inline-capped one (the defect)',
  truncatedWrite.trueLength === 8192,
  `expected the true output length 8192, got ${truncatedWrite.trueLength}`,
);
check(
  'writeBackPlan flags a truncated result so the caller fetches the raw payload before writing',
  truncatedWrite.truncated === true,
  'a truncated transform result was not flagged for a raw re-fetch before write-back',
);
check(
  'a truncated but length-preserving write still gets a note warning it will be re-fetched',
  truncatedWrite.note !== null && /inline|fetch/i.test(truncatedWrite.note),
  `expected a note naming the inline cap, got ${JSON.stringify(truncatedWrite.note)}`,
);
check(
  'the truncation note reads differently from an ordinary resize note',
  truncatedWrite.note !== resizingWrite.note,
  'a truncated result produced the exact same note text as an unrelated genuine resize, which would misattribute the cause',
);

const truncatedAndResizedWrite = writeBackPlan({ length: 9000, truncated: true }, 8192);
check(
  'a truncated result that also genuinely resizes reports both the true length and a note',
  truncatedAndResizedWrite.trueLength === 9000 && truncatedAndResizedWrite.truncated === true && truncatedAndResizedWrite.note !== null,
  `expected a combined truncation+resize plan, got ${JSON.stringify(truncatedAndResizedWrite)}`,
);

check(
  'the write-back button labels itself with the plan\'s true length',
  /write \$\{plan\.trueLength\} bytes back/.test(renderersSource),
  'renderTransform no longer labels the write-back button from writeBackPlan().trueLength',
);
check(
  'the write-back button fetches the untruncated payload before writing when truncated (the defect)',
  /if \(plan\.truncated\) \{\s*ctx\.raw\(name, args, ctx\.handle\)/.test(renderersSource),
  'renderTransform no longer fetches the raw payload through ctx.raw() before writing a truncated transform result back',
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} renderers truncation expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('renderers truncation rules: all expectations held\n');
