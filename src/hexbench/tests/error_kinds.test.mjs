/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Every failure kind the application can produce must arrive at the user as a
 * styled banner carrying a readable tag.
 *
 * The kind is a slug composed into a class name (`err-${kind}`) and printed into
 * a chip, which means a kind nothing has styled renders as an unstyled box and a
 * kind nothing has named renders as `unknown_operation`, overflowing the chip it
 * sits in. Neither failure is visible from any one file, so this suite reads
 * three: the producers (`dispatch.py`, `api.js`), the map that names them
 * (`renderers.js`) and the stylesheet that styles them (`app.css`). The kinds
 * are enumerated from the producers rather than listed here, so a kind added to
 * the dispatch layer arrives in this suite by itself.
 *
 * renderers.js cannot be imported under node - it reaches api.js, which reads
 * `document` at module scope - so the three pieces under test are lifted out of
 * its source and executed, which is what the sibling suites do for the same
 * reason.
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

const staticDir = fileURLToPath(new URL('../static/', import.meta.url));
const packageDir = fileURLToPath(new URL('../', import.meta.url));
const dispatchSource = await readFile(`${packageDir}dispatch.py`, 'utf8');
const apiSource = await readFile(`${staticDir}api.js`, 'utf8');
const renderersSource = await readFile(`${staticDir}renderers.js`, 'utf8');
const cssSource = await readFile(`${staticDir}app.css`, 'utf8');

/* ------------------------------------------------------- what can be produced */

/* dispatch.py produces a kind two ways: `_EXCEPTION_RULES` maps an exception
   type onto one, and a handful of sites raise DispatchError with the kind
   spelled at the raise. */
const dispatchKinds = new Set();
const rulesBlock = /_EXCEPTION_RULES[^=]*=\s*\(([\s\S]*?)\n\)/.exec(dispatchSource);
for (const [, kind] of (rulesBlock?.[1] ?? '').matchAll(/,\s*"([a-z_]+)",/g)) {
  dispatchKinds.add(kind);
}
const ruleCount = dispatchKinds.size;
for (const [, kind] of dispatchSource.matchAll(/kind="([a-z_]+)"/g)) {
  dispatchKinds.add(kind);
}

/* api.js manufactures its own when the server's answer carries no envelope, or
   an envelope with no kind. */
const apiKinds = new Set();
for (const [, args] of apiSource.matchAll(/new DispatchError\((.*?)\);/gs)) {
  const match = /,\s*(?:\w+\s*\?\?\s*)?'([a-z_]+)'/.exec(args);
  if (match !== null) {
    apiKinds.add(match[1]);
  }
}

check(
  'the exception rules were located in dispatch.py',
  ruleCount >= 8,
  `parsed ${ruleCount} kinds out of _EXCEPTION_RULES, which means the block moved and this suite is enumerating almost nothing`,
);
check(
  'the raise sites were located in dispatch.py',
  dispatchKinds.has('unknown_operation') && dispatchKinds.has('missing_document'),
  `expected the directly raised kinds among ${JSON.stringify([...dispatchKinds])}`,
);
check(
  'the client-side kinds were located in api.js',
  apiKinds.has('transport') && apiKinds.size >= 2,
  `expected transport and the envelope default among ${JSON.stringify([...apiKinds])}`,
);

const kinds = [...new Set([...dispatchKinds, ...apiKinds])].sort();

/* --------------------------------------------------- the map, lifted and run */

function lift(pattern, what) {
  const match = pattern.exec(renderersSource);
  if (match === null) {
    throw new Error(`${what} could not be located in renderers.js`);
  }
  return match[0].replace('export ', '');
}

const mapSource = lift(/export const ERROR_KIND_LABELS = new Map\(\[[\s\S]*?\n\]\);/, 'ERROR_KIND_LABELS');
const labelSource = lift(/export function errorKindLabel\(kind\) \{[\s\S]*?\n\}/, 'errorKindLabel');
const bannerSource = lift(/export function renderError\(error\) \{[\s\S]*?\n\}/, 'renderError');

function fakeElement(tag, className, text) {
  return { tag, className: className ?? '', textContent: text ?? '', children: [], appendChild(child) { this.children.push(child); return child; } };
}

const built = new Function('element', `${mapSource}\n${labelSource}\n${bannerSource}\nreturn { ERROR_KIND_LABELS, errorKindLabel, renderError };`)(fakeElement);

/* ------------------------------------------- every kind has a label and a rule */

check(
  'the kind enumeration is not empty',
  kinds.length >= 10,
  `only ${kinds.length} kinds were enumerated, so the expectations below would pass vacuously`,
);

for (const kind of kinds) {
  check(
    `${kind} has a display label`,
    built.ERROR_KIND_LABELS.has(kind),
    `this kind reaches renderError and would print its raw slug into the chip; add it to ERROR_KIND_LABELS in renderers.js`,
  );
  check(
    `${kind} has a stylesheet rule`,
    cssSource.includes(`.hb-error-banner.err-${kind}`),
    `this kind reaches the banner and lands on it unstyled; app.css needs a .hb-error-banner.err-${kind} rule in its error-banner section`,
  );
}

for (const [kind, label] of built.ERROR_KIND_LABELS) {
  check(
    `the label for ${kind} fits a chip`,
    label.length <= 12 && label === label.toUpperCase(),
    `the design specifies a short uppercase tag; ${JSON.stringify(label)} is neither`,
  );
  check(
    `${kind} is a kind something actually produces`,
    kinds.includes(kind),
    'nothing in dispatch.py or api.js produces this kind any more, so the map has drifted from the producers',
  );
}

/* ------------------------------------------------------- what renderError does */

const io = built.renderError({ kind: 'io', message: 'the file is locked' });
check(
  'the banner keeps the slug in its class name',
  io.className === 'hb-error-banner err-io',
  `the stylesheet selects on err-<kind>, so the slug has to stay on the element; got ${JSON.stringify(io.className)}`,
);
const chip = io.children.find((child) => child.className === 'hb-error-kind');
check(
  'the chip prints the label rather than the slug (the defect)',
  chip !== undefined && chip.textContent === 'I/O',
  `expected the display tag I/O in the chip, got ${JSON.stringify(chip?.textContent)}`,
);

const longSlug = built.renderError({ kind: 'unknown_operation', message: 'unknown operation "nope"' });
const longChip = longSlug.children.find((child) => child.className === 'hb-error-kind');
check(
  'the longest slug is shortened for the chip',
  longChip !== undefined && longChip.textContent === 'UNKNOWN OP',
  `unknown_operation overflows the chip and must print as UNKNOWN OP, got ${JSON.stringify(longChip?.textContent)}`,
);

const withDetail = built.renderError({ kind: 'missing_document', message: 'no handle', detail: 'GET /api/documents lists the handles this session holds' });
const detailLine = withDetail.children.find((child) => child.className === 'hb-error-detail');
check(
  'a failure carrying a detail renders it as the second line (the defect)',
  detailLine !== undefined && detailLine.textContent === 'GET /api/documents lists the handles this session holds',
  `renderError never emitted hb-error-detail, so the actionable second line is missing; children were ${JSON.stringify(withDetail.children.map((child) => child.className))}`,
);

const withoutDetail = built.renderError({ kind: 'value', message: 'offset is negative' });
check(
  'a failure with no detail renders no empty second line',
  withoutDetail.children.every((child) => child.className !== 'hb-error-detail'),
  'an empty hb-error-detail leaves a blank line under every message that has nothing more to say',
);

const unknown = built.errorKindLabel('a_kind_from_the_future');
check(
  'an unrecognised kind still reads as a tag',
  unknown === 'A KIND FROM THE FUTURE',
  `a slug from a newer server must still be uppercased rather than printed raw, got ${JSON.stringify(unknown)}`,
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} error-kind expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write(`error kinds: all ${kinds.length} producible kinds have a label and a rule\n`);
