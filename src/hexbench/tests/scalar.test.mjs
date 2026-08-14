/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Executes the inspector's scalar re-spelling rule for real, rather than
 * scanning its source. node is already a declared environment dependency, so
 * this costs the gate nothing new.
 *
 * Run by gate.ps1. Exits non-zero on the first failed expectation.
 */

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { compactScalar } from '../static/scalar.js';

const failures = [];

function check(label, condition, detail) {
  if (!condition) {
    failures.push(`${label}: ${detail}`);
  }
}

const DENORMAL = `0.${'0'.repeat(313)}63706613826`;
const HUGE = '4370871509808368000000000000000000000000000000000000000000000000';
const U64_MAX = '18446744073709551615';
const GUID = '00905a4d-0003-0000-0400-0000ffff0000';
const HEXDUMP = '4d5a90000300000004000000ffff0000';

let compactedCount = 0;

function expectCompacted(label, input) {
  const { text, full } = compactScalar(input);
  check(label, text.length < input.length, `expected a shorter rendering, got ${text.length} characters`);
  check(label, full === input, 'the exact original must be retained for the title attribute');
  check(label, Number(text) === Number(input), `re-spelling changed the value: ${Number(text)} vs ${Number(input)}`);
  if (text.length < input.length) {
    compactedCount += 1;
  }
}

function expectUntouched(label, input) {
  const { text, full } = compactScalar(input);
  check(label, text === input, `expected the value to pass through unchanged, got ${text}`);
  check(label, full === null, 'an untouched value must not claim to have been compacted');
}

expectCompacted('denormal float64 (the defect)', DENORMAL);
expectCompacted('very large float64', HUGE);

expectUntouched('u64 max must keep every digit', U64_MAX);
expectUntouched('i64 min must keep every digit', '-9223372036854775808');
expectUntouched('a guid is not a number', GUID);
expectUntouched('a hex dump is not a number', HEXDUMP);
expectUntouched('a short float', '21.40625');
expectUntouched('a date', '2025-02-13');
expectUntouched('a single character', 'M');
expectUntouched('empty text', '');
expectUntouched('a long non-numeric string', 'this program cannot be run in DOS mode');

const denormal = compactScalar(DENORMAL);
check(
  'denormal renders in exponential form',
  /e[+-]\d+$/.test(denormal.text),
  `expected exponential notation, got ${denormal.text}`,
);
check('denormal stays a denormal', Number(denormal.text) > 0, 'the value collapsed to zero');

check(
  'the suite proves compaction happens at all',
  compactedCount >= 2,
  `only ${compactedCount} values were compacted; a rule that never fires would pass every untouched case`,
);

const staticDir = fileURLToPath(new URL('../static/', import.meta.url));
const renderers = await readFile(`${staticDir}renderers.js`, 'utf8');
const stylesheet = await readFile(`${staticDir}app.css`, 'utf8');

check(
  'the renderer source is actually being read',
  renderers.length > 20000,
  `renderers.js read as only ${renderers.length} characters`,
);
check(
  'the inspector imports the rule rather than reimplementing it',
  renderers.includes("from './scalar.js'"),
  'renderers.js no longer imports compactScalar from scalar.js',
);
check(
  'the inspector no longer renders the engine string verbatim',
  !renderers.includes('String(value[key])'),
  'renderInspect stringifies the engine value directly again; a denormal will bury the rows below it',
);
check(
  'the inspector builds its value cells through the compacting helper',
  renderers.includes('scalarCell(value[key])'),
  'renderInspect no longer routes its values through scalarCell',
);
check(
  'a compacted cell keeps the exact value in its title',
  /function scalarCell[\s\S]{0,400}\.title\s*=/.test(renderers),
  'scalarCell no longer sets the title attribute, so the exact value is unreachable',
);
check(
  'a compacted reading is visually distinguishable',
  stylesheet.includes('.hb-kv-value.is-compacted'),
  'app.css does not style .hb-kv-value.is-compacted, so an abbreviated number looks exact',
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} scalar expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('scalar rendering: all expectations held\n');
