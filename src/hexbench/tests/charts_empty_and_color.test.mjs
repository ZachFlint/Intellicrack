/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Exercises charts.js's pure per-pixel and colour-parsing rules for real, and
 * reads charts.js as text to confirm the pointer handlers those rules were
 * extracted from actually call them. charts.js has no module-level DOM
 * access, so it loads under plain node without any stubbing.
 *
 * The tokenHex section at the end needs a `getComputedStyle`, because that is
 * how a design-system token reaches the function. It is installed there rather
 * than here, well after the import above has already happened, so the bare-node
 * load this suite exists to protect stays exactly as it is.
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
const chartsSource = await readFile(`${staticDir}charts.js`, 'utf8');

const { hoverIndex, histogramPeak, parseColor, tokenHex } = await import('../static/charts.js');

/* -------------------------------------------------------- #62/#63: hoverIndex */

check('hoverIndex is null for an empty series (the defect)', hoverIndex(0, 10, 100) === null, 'an empty series must not resolve to index 0, which reads out of bounds');
check('hoverIndex clamps the left edge', hoverIndex(256, 0, 100) === 0, 'the leftmost pointer position should map to the first bucket');
check('hoverIndex clamps the right edge', hoverIndex(256, 99, 100) === Math.floor((99 / 100) * 256), 'the rightmost pointer position produced an unexpected bucket');
check('hoverIndex never returns an out-of-range index', hoverIndex(256, 1000, 100) === 255, `a pointer past the canvas must clamp to the last bucket, got ${hoverIndex(256, 1000, 100)}`);
check('hoverIndex maps the midpoint proportionally', hoverIndex(256, 50, 100) === 128, `expected bucket 128 at the midpoint, got ${hoverIndex(256, 50, 100)}`);

check(
  'entropyMapChart guards its hover index against an empty series (the defect)',
  /const index = hoverIndex\(values\.length, point\.x, point\.width\);\s*\n\s*hover\.textContent = index === null/.test(chartsSource),
  'entropyMapChart no longer guards its onHover handler with hoverIndex, so an empty entropy map would throw calling .toFixed on undefined',
);
check(
  'classificationChart guards its hover index against an empty series (the defect)',
  /const index = hoverIndex\(codes\.length, point\.x, point\.width\);\s*\n\s*if \(index === null\)/.test(chartsSource),
  'classificationChart no longer guards its onHover handler with hoverIndex, so an empty code map would read undefined and print "undefined unknown code"',
);
check(
  'entropyMapChart also guards its onClick handler',
  /onClick: onSeek === null \? undefined : \(point\) => \{\s*const index = hoverIndex\(values\.length/.test(chartsSource),
  'entropyMapChart onClick no longer routes through hoverIndex',
);
check(
  'classificationChart also guards its onClick handler',
  /onClick: onSeek === null \? undefined : \(point\) => \{\s*const index = hoverIndex\(codes\.length/.test(chartsSource),
  'classificationChart onClick no longer routes through hoverIndex',
);

/* -------------------------------------------------------------- #35: histogramPeak */

check('histogramPeak is null for an all-zero histogram (the defect)', histogramPeak(new Array(256).fill(0)) === null, 'an empty document must report no peak rather than a fabricated one');

const withOnePeak = new Array(256).fill(0);
withOnePeak[0x41] = 5;
withOnePeak[0x20] = 3;
const peakResult = histogramPeak(withOnePeak);
check(
  'histogramPeak finds the tallest bucket and its byte value',
  peakResult !== null && peakResult.peak === 5 && peakResult.index === 0x41,
  `expected {peak: 5, index: 65}, got ${JSON.stringify(peakResult)}`,
);

check(
  'the histogram caption reports "no peak" rather than "peak 1 at 0x-1" for an empty document (the defect)',
  /peakInfo === null\s*\n\s*\? 'no peak/.test(chartsSource),
  'histogramChart no longer special-cases an empty (all-zero) histogram in its caption',
);
check(
  'the histogram caption is built from histogramPeak',
  /const peakInfo = histogramPeak\(counts\)/.test(chartsSource),
  'histogramChart no longer computes its caption through histogramPeak',
);

/* ---------------------------------------------------------------- #77: parseColor */

check(
  '6-digit hex parses correctly (baseline)',
  JSON.stringify(parseColor('#ff0000')) === JSON.stringify({ r: 255, g: 0, b: 0 }),
  `expected pure red, got ${JSON.stringify(parseColor('#ff0000'))}`,
);
check(
  '3-digit shorthand hex still parses correctly (no regression)',
  JSON.stringify(parseColor('#f00')) === JSON.stringify({ r: 255, g: 0, b: 0 }),
  `expected pure red, got ${JSON.stringify(parseColor('#f00'))}`,
);
check(
  '4-digit #rgba shorthand parses its colour channels, not garbage (the defect)',
  JSON.stringify(parseColor('#f00a')) === JSON.stringify({ r: 255, g: 0, b: 0 }),
  `expected the alpha digit to be dropped and the colour read as pure red, got ${JSON.stringify(parseColor('#f00a'))}`,
);
check(
  'functional rgb() notation is unaffected',
  JSON.stringify(parseColor('rgb(1, 2, 3)')) === JSON.stringify({ r: 1, g: 2, b: 3 }),
  `expected {r:1,g:2,b:3}, got ${JSON.stringify(parseColor('rgb(1, 2, 3)'))}`,
);

/* ------------------------------------------------------------------ tokenHex */

/* A colour input and a canvas gradient stop both take `#rrggbb` and nothing
 * else, so tokenHex's job is to turn whatever notation the stylesheet happened
 * to write into that one form. The token text has to arrive through a computed
 * style, so a node here *is* its own computed style and getComputedStyle hands
 * the node it was given straight back. Nothing below asserts on that text: every
 * expectation is on the normalisation tokenHex performed on it. */
globalThis.getComputedStyle = (node) => node;

function styleNode(properties) {
  return { getPropertyValue: (name) => properties[name] ?? '' };
}

const themed = styleNode({
  '--hb-accent': '#AB12CD',
  '--hb-warning': 'rgb(1, 2, 3)',
  '--hb-info': 'rgb(255 128 0 / 0.5)',
  '--hb-error': '  #F00  ',
});

check(
  'tokenHex passes a six-digit hex token straight through, lower cased',
  tokenHex('--hb-accent', '#808080', themed) === '#ab12cd',
  `a token the stylesheet wrote as #AB12CD must reach a colour input as #ab12cd, got ${tokenHex('--hb-accent', '#808080', themed)}`,
);
check(
  'tokenHex normalises a comma-separated rgb() token to #rrggbb',
  tokenHex('--hb-warning', '#808080', themed) === '#010203',
  `rgb(1, 2, 3) must become #010203 or the control silently rejects it, got ${tokenHex('--hb-warning', '#808080', themed)}`,
);
check(
  'tokenHex normalises the space-separated rgb() notation with an alpha too',
  tokenHex('--hb-info', '#808080', themed) === '#ff8000',
  `rgb(255 128 0 / 0.5) must become #ff8000, got ${tokenHex('--hb-info', '#808080', themed)}`,
);
check(
  'tokenHex expands a shorthand hex token and trims its whitespace',
  tokenHex('--hb-error', '#808080', themed) === '#ff0000',
  `a token resolving to "  #F00  " must become #ff0000, got ${tokenHex('--hb-error', '#808080', themed)}`,
);
check(
  'tokenHex falls back when the token resolves to nothing',
  tokenHex('--hb-not-a-token', '#123456', themed) === '#123456',
  `an undeclared token must yield the caller's fallback, got ${tokenHex('--hb-not-a-token', '#123456', themed)}`,
);
check(
  'tokenHex normalises the fallback the same way it normalises a token',
  tokenHex('--hb-not-a-token', 'rgb(9, 9, 9)', themed) === '#090909',
  `a fallback is a colour like any other and must also reach the control as #rrggbb, got ${tokenHex('--hb-not-a-token', 'rgb(9, 9, 9)', themed)}`,
);
check(
  'tokenHex has a fallback of its own',
  tokenHex('--hb-not-a-token', undefined, themed) === '#808080',
  `with no fallback given, an undeclared token must still produce a usable colour, got ${tokenHex('--hb-not-a-token', undefined, themed)}`,
);
check(
  'tokenHex prefers a declared token over the fallback',
  tokenHex('--hb-accent', '#123456', themed) !== '#123456',
  'a declared token was ignored in favour of the fallback',
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} charts expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('charts empty-series, colour and token rules: all expectations held\n');
