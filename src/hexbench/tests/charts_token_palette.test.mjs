/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Ties charts.js's palette table to the stylesheet it claims to copy.
 *
 * A canvas cannot read a custom property, so every chart colour is resolved
 * through getComputedStyle, and an undeclared property resolves to an empty
 * string rather than to an error. That makes a renamed token completely silent:
 * the charts keep drawing, in whatever the fallback happened to be. This suite
 * is the thing that is not silent. It reads app.css as text - the whole point is
 * to compare against the stylesheet rather than against another copy of the
 * values - and asserts three separate ways for the table to be wrong: a token
 * the stylesheet no longer declares, a fallback that has drifted from the light
 * theme's value, and a token read somewhere in the app that the table does not
 * carry at all.
 *
 * charts.js has no module-level DOM access, so it loads here under plain node
 * with no stubbing whatsoever.
 *
 * Run by gate.ps1. Exits non-zero on the first failed expectation.
 */

import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const failures = [];

function check(label, condition, detail) {
  if (!condition) {
    failures.push(`${label}: ${detail}`);
  }
}

const staticDir = fileURLToPath(new URL('../static/', import.meta.url));
const chartsSource = await readFile(`${staticDir}charts.js`, 'utf8');
const cssSource = await readFile(`${staticDir}app.css`, 'utf8');

const { CHART_TOKEN_FALLBACKS } = await import('../static/charts.js');

/* ------------------------------------------------- the light palette, as CSS */

/* The light theme is the bare `:root` block; the dark theme is declared twice
   after it, once under a media query and once under an attribute selector, and
   a light-palette fallback must not be read out of either. */
const rootStart = cssSource.indexOf('\n:root {');
const rootEnd = cssSource.indexOf('\n}', rootStart);
const rootBlock = rootStart === -1 ? '' : cssSource.slice(rootStart, rootEnd);
const declared = new Map();
for (const [, token, value] of rootBlock.matchAll(/(--hb-[a-z0-9-]+)\s*:\s*([^;]+);/g)) {
  declared.set(token, value.trim());
}

check(
  'the light palette was located in app.css',
  declared.size > 50,
  `parsed ${declared.size} tokens out of the :root block, which means the block was not found and every expectation below would pass vacuously`,
);

/* ------------------------------------------------------ the table is honest */

for (const [token, fallback] of CHART_TOKEN_FALLBACKS) {
  check(
    `${token} is still a declared token`,
    declared.has(token),
    'charts.js resolves this token but app.css no longer declares it in :root, so every chart reading it now draws from a fallback',
  );
  check(
    `${token}'s fallback matches the light theme`,
    declared.get(token) === fallback,
    `the table says ${fallback} and the light theme says ${declared.get(token)}, so a fallback that does reach a pixel is off-palette`,
  );
}

/* ------------------------------------------ nothing reads an untabled token */

/* Two kinds of custom property appear in charts.js: the ones it reads off a
   computed style, which must all be in the table, and the ones it writes onto
   an element for the stylesheet to consume (--hb-bar, --hb-seg). Only the
   written ones are excluded, and they are excluded by finding the setProperty
   calls rather than by listing them here. */
const written = new Set([...chartsSource.matchAll(/setProperty\('(--hb-[a-z0-9-]+)'/g)].map(([, token]) => token));
const mentioned = new Set([...chartsSource.matchAll(/'(--hb-[a-z0-9-]+)'/g)].map(([, token]) => token));
const read = [...mentioned].filter((token) => !written.has(token));

check(
  'charts.js does read design tokens at all',
  read.length > 10,
  `only ${read.length} tokens were found in charts.js, so the expectations below would pass vacuously`,
);
for (const token of read) {
  check(
    `${token} has a palette entry`,
    CHART_TOKEN_FALLBACKS.has(token),
    'charts.js names this token but CHART_TOKEN_FALLBACKS carries no light-palette value for it, so resolving it throws',
  );
}

/* Other modules reach the same resolver through tokenHex, and a token they pass
   that the table does not carry fails at the call rather than at review. */
const moduleNames = (await readdir(staticDir)).filter((name) => name.endsWith('.js') && name !== 'charts.js');
const outside = new Map();
for (const name of moduleNames) {
  const source = await readFile(`${staticDir}${name}`, 'utf8');
  for (const [, token] of source.matchAll(/tokenHex\('(--hb-[a-z0-9-]+)'/g)) {
    outside.set(token, name);
  }
  for (const [, constant] of source.matchAll(/COLOR_TOKEN\s*=\s*'(--hb-[a-z0-9-]+)'/g)) {
    outside.set(constant, name);
  }
}
check(
  'the modules outside charts.js do resolve tokens through tokenHex',
  outside.size > 0,
  'no tokenHex call site was found anywhere, so the expectations below would pass vacuously',
);
for (const [token, name] of outside) {
  check(
    `${token}, passed to tokenHex by ${name}, has a palette entry`,
    CHART_TOKEN_FALLBACKS.has(token),
    `${name} resolves this token through charts.js, which throws for a token with no light-palette value`,
  );
}

/* ------------------------------------------------ no off-palette literals left */

/* The values DS-4 found hardcoded at the call sites. None belongs to either
   theme, and a fallback is exactly where such a colour survives unnoticed. */
const OFF_PALETTE = ['#808080', '#4c9df0', '#ef5f8c', '#101010', '#202020', 'rgba(128,128,128,0.2)', 'rgba(76,157,240,0.24)'];
for (const literal of OFF_PALETTE) {
  check(
    `charts.js no longer carries the literal ${literal}`,
    !chartsSource.includes(literal),
    'this colour is in no palette in either theme, so a chart that falls back to it looks like a chart that worked',
  );
}

if (failures.length > 0) {
  process.stdout.write(`${failures.length} chart palette expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('chart colour tokens: table, stylesheet and call sites agree\n');
