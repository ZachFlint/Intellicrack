/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * forms.js imports api.js, which resolves its session token from `document`
 * and `window` at module load time, so it cannot be imported under plain
 * node the way scalar.js can (see scalar.test.mjs). This suite therefore
 * reads the real source and checks the exact expressions the caret/selection
 * defaults and the bytes editor's canonical value depend on, the same
 * technique scalar.test.mjs already uses against renderers.js and app.css.
 *
 * Run by gate.ps1 (or directly with node). Exits non-zero on the first
 * failed expectation.
 */

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const failures = [];

function check(label, condition, detail) {
  if (!condition) {
    failures.push(`${label}: ${detail}`);
  }
}

/** Slice out a `{ ... }` block starting at the first match of `headerPattern`, brace-balanced. */
function extractBlock(source, headerPattern) {
  const match = source.match(headerPattern);
  if (!match) {
    throw new Error(`pattern not found: ${headerPattern}`);
  }
  const braceStart = source.indexOf('{', match.index);
  let depth = 1;
  let index = braceStart + 1;
  while (depth > 0 && index < source.length) {
    if (source[index] === '{') {
      depth += 1;
    } else if (source[index] === '}') {
      depth -= 1;
    }
    index += 1;
  }
  return { full: source.slice(match.index, index), inner: source.slice(braceStart + 1, index - 1) };
}

const staticDir = fileURLToPath(new URL('../static/', import.meta.url));
const formsSource = await readFile(`${staticDir}forms.js`, 'utf8');

check(
  'the forms.js source is actually being read',
  formsSource.length > 20000,
  `forms.js read as only ${formsSource.length} characters`,
);

/* --------------------------------------------------------------- finding #2 */

const defaultForBody = extractBlock(formsSource, /function defaultFor\(operation, parameter, context\) \{/).full;
const caretParamBlock = extractBlock(defaultForBody, /if \(CARET_PARAMETERS\.has\(parameter\.name\) && parameter\.kind === 'int'\) \{/).full;

check(
  'defaultFor (finding #2): CARET_PARAMETERS prefer the selection start over the caret',
  caretParamBlock.includes('context.selectionStart'),
  'offset-like parameters (offset, start, address, ...) still default straight from context.caret, which is the trailing '
    + '(focus) edge of a forward drag selection rather than its start',
);
check(
  'defaultFor (finding #2): still falls back to the caret when nothing is selected',
  caretParamBlock.includes('context.caret ?? 0'),
  'the no-selection fallback to context.caret is gone from the CARET_PARAMETERS default',
);

/* -------------------------------------------------------------- finding #11 */

const intPairBody = extractBlock(formsSource, /function intPairEditor\(parameter, context, initial\) \{/).full;
const byteRangeBlock = extractBlock(intPairBody, /if \(parameter\.name === 'byte_range'\) \{/).full;

check(
  'intPairEditor (finding #11): "Use the selected range" reads selectionStart/selectionEnd',
  byteRangeBlock.includes('context.selectionStart') && byteRangeBlock.includes('context.selectionEnd'),
  'the byte_range "Use the selected range" button still recomputes [start, start + selection] from context.caret, '
    + 'which is the selection\'s trailing edge for a forward drag, not its start',
);
check(
  'intPairEditor (finding #11): still falls back to the caret when nothing is selected',
  byteRangeBlock.includes('context.caret ?? 0') && byteRangeBlock.includes('context.selection ?? 0'),
  'the no-selection fallback (caret + selection length) is gone from the byte_range button',
);

/* -------------------------------------------------------- findings #1 and #2 */

const bytesEditorBody = extractBlock(formsSource, /function bytesEditor\(parameter, context, initial\) \{/).full;

check(
  'bytesEditor (finding #1): keeps a canonical hex value independent of the display mode',
  /let canonicalHex/.test(bytesEditorBody),
  'bytesEditor no longer tracks a canonical hex string separate from whatever text the textarea currently displays',
);
check(
  'bytesEditor (finding #1): editing the textarea keeps the canonical value in sync',
  /area\.addEventListener\('input', \(\) => \{\s*try \{\s*canonicalHex = mode\.value === 'hex' \? normaliseHex\(area\.value, parameter\.name\) : asciiToHex\(area\.value\);/.test(bytesEditorBody),
  'a genuine user edit to the textarea no longer updates canonicalHex, so an edit made while viewing ascii would be '
    + 'lost the next time the mode is toggled',
);
check(
  'bytesEditor (finding #1): switching the mode only changes the display, not the canonical value',
  /mode\.addEventListener\('change', \(\) => \{\s*area\.value = mode\.value === 'ascii' \? hexToAscii\(canonicalHex\) : canonicalHex;/.test(bytesEditorBody),
  'toggling hex/ascii still re-derives the shown text from whatever is currently in the box instead of the stored '
    + 'canonical hex, so hex -> ascii -> hex can no longer round-trip a non-printable byte without loss',
);
check(
  'bytesEditor (finding #1): read() returns the canonical hex in ascii mode',
  /read: \(\) => \(mode\.value === 'hex' \? normaliseHex\(area\.value, parameter\.name\) : canonicalHex\)/.test(bytesEditorBody),
  "read() still evaluates asciiToHex(area.value) in ascii mode, re-encoding hexToAscii's lossy '.' placeholders as "
    + 'the literal byte 0x2e in place of every original non-printable byte',
);

const fromSelectionBlock = extractBlock(
  bytesEditorBody,
  /button\('from selection', 'Read the selected bytes out of the active document', \(\) => \{/,
).full;

check(
  'bytesEditor "from selection" (finding #2): reads from the selection start, not the trailing caret',
  fromSelectionBlock.includes('context.selectionStart'),
  'the "from selection" button still calls readWindow with context.caret as the offset, which is the trailing '
    + '(focus) edge of a forward drag selection rather than its start',
);
check(
  'bytesEditor "from selection" (finding #1): updates the canonical hex, not just the display',
  /canonicalHex = toHex\(window\.bytes\)\.toLowerCase\(\);\s*area\.value = canonicalHex;/.test(fromSelectionBlock),
  'the "from selection" button writes straight to area.value without updating canonicalHex, so a later mode toggle '
    + 'can still lose the bytes it just imported',
);

const loadDocumentBlock = extractBlock(
  bytesEditorBody,
  /button\('load document', 'Read this document\\u2019s bytes into the field', \(\) => \{/,
).full;

check(
  'bytesEditor "load document" (finding #1): updates the canonical hex, not just the display',
  /canonicalHex = toHex\(window\.bytes\)\.toLowerCase\(\);\s*area\.value = canonicalHex;/.test(loadDocumentBlock),
  'the "load document" button writes straight to area.value without updating canonicalHex, so a later mode toggle '
    + 'can still lose the bytes it just loaded',
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} forms selection/bytes expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('forms caret/selection/bytes fixes: all expectations held\n');
