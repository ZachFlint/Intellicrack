/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * grid.js pulls in api.js, which resolves its session token from `document`
 * and `window` at module load time, so it cannot be imported under plain
 * node the way scalar.js can (see scalar.test.mjs). This suite therefore
 * reads the real source and checks the exact expressions the caret and
 * selection arithmetic depends on, the same technique scalar.test.mjs
 * already uses against renderers.js and app.css. `clamp` itself has no such
 * dependency, so it is extracted and actually executed rather than merely
 * pattern-matched.
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
    throw new Error(`pattern not found in grid.js: ${headerPattern}`);
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
const gridSource = await readFile(`${staticDir}grid.js`, 'utf8');

check(
  'the grid.js source is actually being read',
  gridSource.length > 20000,
  `grid.js read as only ${gridSource.length} characters`,
);

/* clamp() has no dependency on `this`, private fields or any import, so it
   can be pulled out and genuinely executed instead of just pattern-matched. */
const clampBlock = extractBlock(gridSource, /function clamp\(value, low, high\) \{/);
const clamp = new Function('value', 'low', 'high', clampBlock.inner);

check('clamp: below the floor', clamp(-5, 0, 10) === 0, `expected 0, got ${clamp(-5, 0, 10)}`);
check('clamp: above the ceiling', clamp(15, 0, 10) === 10, `expected 10, got ${clamp(15, 0, 10)}`);
check('clamp: inside the range is untouched', clamp(4, 0, 10) === 4, `expected 4, got ${clamp(4, 0, 10)}`);
check('clamp: reaching the ceiling exactly is allowed', clamp(10, 0, 10) === 10, `expected 10, got ${clamp(10, 0, 10)}`);

/* --------------------------------------------------------- findings #3, #12 */

const typeByte = extractBlock(gridSource, /#typeByte\(value\) \{/).full;
check(
  'typeByte (finding #3): clamps the caret to the post-write length',
  /const newTotal = insertingNew \? total \+ 1 : total;/.test(typeByte) && /clamp\(offset \+ 1, 0, newTotal\)/.test(typeByte),
  'typing a byte at the end of the document must be able to advance the caret to total + 1 once the write extends the document; '
    + 'reverting to the old bound (which used the pre-write `total`) makes the caret clamp back onto the byte just written',
);
check(
  'typeByte (finding #3): the pre-write clamp bound is gone',
  !typeByte.includes('Math.max(0, insertingNew ? total : total - 1)'),
  'the old pre-write clamp expression is back in typeByte',
);

const typeNibble = extractBlock(gridSource, /#typeNibble\(digit\) \{/).full;
check(
  'typeNibble (finding #12): the else branch advances to the freshly grown length',
  /this\.#caretNibble = NIBBLE_HIGH;\s*\n\s*this\.#caretOffset = clamp\(offset \+ 1, 0, total\);/.test(typeNibble),
  'completing the low nibble of the byte at the end of the document must land the caret on the append position (offset === total), '
    + 'not one short of it',
);
check(
  'typeNibble (finding #12): the total - 1 clamp bound is gone',
  !typeNibble.includes('Math.max(0, total - 1)'),
  'the old total - 1 clamp bound is back in typeNibble, so the caret would stay pinned on the byte it just completed',
);

check(
  'the total - 1 clamp bound is gone from the whole file',
  !gridSource.includes('Math.max(0, total - 1)'),
  'a caller still clamps a post-edit caret to one byte short of where the write actually reached',
);

/* -------------------------------------------------------------- finding #36 */

const selectMethod = extractBlock(gridSource, /select\(offset, length\) \{/).full;
check(
  'select() (finding #36): refuses to select on an empty document',
  /if \(length <= 0 \|\| this\.#documentLength <= 0\)/.test(selectMethod),
  'select() must bail out (clear the selection and seek instead) when the document has zero bytes, the same way it already does for a non-positive length',
);
check(
  'select() (finding #36): no longer inflates an empty document into a 1-byte bound',
  !selectMethod.includes('Math.max(0, this.#documentLength)') && !selectMethod.includes('Math.max(0, total - 1)'),
  'select() still derives start/end from Math.max(0, total - 1), which collapses to 0 on an empty document and manufactures a phantom selection',
);

/* -------------------------------------------------------------- finding #64 */

const hexClass = extractBlock(gridSource, /#hexClass\(column, offset, value, beyond, shared\) \{/).full;
const asciiClass = extractBlock(gridSource, /#asciiClass\(offset, value, beyond, shared\) \{/).full;
const appendPositionGuard = /offset === this\.#caretOffset && \(!beyond \|\| offset === this\.#documentLength\)/;

check(
  '#hexClass (finding #64): renders the caret at the append position',
  appendPositionGuard.test(hexClass),
  'the append-position cell (offset === caretOffset === documentLength) is still excluded from every caret/nibble class by the bare !beyond guard',
);
check(
  '#asciiClass (finding #64): renders the caret at the append position',
  appendPositionGuard.test(asciiClass),
  'the append-position cell (offset === caretOffset === documentLength) is still excluded from every caret class by the bare !beyond guard',
);

/* -------------------------------------------------------------- finding #65 */

const stepLeft = extractBlock(gridSource, /#stepLeft\(\) \{/).full;
const stepRight = extractBlock(gridSource, /#stepRight\(\) \{/).full;
const moveCaret = extractBlock(gridSource, /#moveCaret\(target, extend, nibble\) \{/).full;
const onKeyDown = extractBlock(gridSource, /#onKeyDown\(event\) \{/).full;

check(
  'stepLeft (finding #65): asks to land on the low nibble when it crosses a byte boundary',
  /return \{ offset: this\.#caretOffset - 1, nibble: NIBBLE_LOW \};/.test(stepLeft),
  'stepLeft no longer communicates the low-nibble landing to its caller, so the request is lost again',
);
check(
  'stepRight (finding #65): still asks to land on the high nibble when it crosses a byte boundary',
  /return \{ offset: this\.#caretOffset \+ 1, nibble: NIBBLE_HIGH \};/.test(stepRight),
  'stepRight no longer communicates the high-nibble landing to its caller',
);
check(
  'moveCaret (finding #65): honours a nibble a caller explicitly requested',
  /if \(nibble !== undefined\) \{\s*this\.#caretNibble = nibble;\s*\}/.test(moveCaret),
  'moveCaret no longer distinguishes an explicit nibble request from its own default reset-to-high behaviour, so a cross-boundary step is overridden again',
);
check(
  'moveCaret (finding #65): still resets to the high nibble for callers that pass no nibble',
  /\} else if \(next !== this\.#caretOffset\) \{\s*this\.#caretNibble = NIBBLE_HIGH;/.test(moveCaret),
  'ArrowUp/ArrowDown/PageUp/PageDown/Home/End no longer reset the nibble when they land on a new offset',
);
check(
  'onKeyDown (finding #65): ArrowLeft/ArrowRight thread the step nibble through to moveCaret',
  (onKeyDown.match(/this\.#moveCaret\(step\.offset, extend, step\.nibble\)/g) ?? []).length === 2,
  'ArrowLeft and/or ArrowRight no longer pass stepLeft/stepRight\'s chosen nibble into moveCaret',
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} grid caret expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('grid caret/selection fixes: all expectations held\n');
