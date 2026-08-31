/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Gates the stylesheet's token layer: A-7 (control borders at 3:1), A-6 (the
 * command palette's focus indicator), DS-2 (the dark palette declared twice),
 * DS-3/A-9 (the control-size scale) and A-8 (the shape channel).
 *
 * A-7 is a measured ratio rather than a colour anyone chose, so this suite
 * measures it: the palette blocks are parsed out of app.css and the contrast of
 * --hb-border-strong against --hb-surface-2 is computed with the WCAG relative
 * luminance formula in both themes. The pre-A-7 value is measured too, and has
 * to come out below 3:1 - a formula that cannot fail the old colour would pass
 * every colour.
 *
 * The rule checks parse app.css rather than a browser, which is what a node
 * suite can do honestly: they assert that the declarations the audit names are
 * present with the token the audit names, so reverting any of them turns this
 * red. What they cannot see is layout, which is why A-9's own done-when is a
 * measurement in the running app.
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

const staticDir = fileURLToPath(new URL('../static/', import.meta.url));

/* The repository is CRLF throughout, so the line endings come off before any
   selector is matched: a multi-line selector list is the normal spelling here
   and every pattern below would otherwise have to carry \r of its own. */
const css = (await readFile(`${staticDir}app.css`, 'utf8')).replace(/\r\n/g, '\n');

check(
  'the stylesheet is actually being read',
  css.length > 60000,
  `app.css read as only ${css.length} characters`,
);

/* --------------------------------------------------------------- parsing */

/** The `{ ... }` body of the rule whose selector text is exactly `selector`, brace-balanced. */
function body(selector) {
  const anchor = new RegExp(`(^|\\n)\\s*${selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\{`);
  const match = css.match(anchor);
  if (!match) {
    throw new Error(`selector not found in app.css: ${selector}`);
  }
  const open = css.indexOf('{', match.index);
  let depth = 1;
  let index = open + 1;
  while (depth > 0 && index < css.length) {
    if (css[index] === '{') {
      depth += 1;
    } else if (css[index] === '}') {
      depth -= 1;
    }
    index += 1;
  }
  return css.slice(open + 1, index - 1);
}

/** Every `--hb-*` declaration in a block, as a Map of name to trimmed value. */
function tokens(block) {
  const found = new Map();
  for (const match of block.matchAll(/(--hb-[a-z0-9-]+)\s*:\s*([^;]+);/g)) {
    found.set(match[1], match[2].trim().replace(/\s+/g, ' '));
  }
  return found;
}

/** The `{ ... }` body of a rule inside the marks block, found by its first selector. */
function markBody(selector) {
  const at = css.indexOf(`[data-marks="on"] ${selector}`);
  if (at === -1) {
    throw new Error(`the shape-channel rule for ${selector} is not in app.css at all`);
  }
  const open = css.indexOf('{', at);
  let depth = 1;
  let index = open + 1;
  while (depth > 0 && index < css.length) {
    if (css[index] === '{') {
      depth += 1;
    } else if (css[index] === '}') {
      depth -= 1;
    }
    index += 1;
  }
  return css.slice(open + 1, index - 1);
}

const lightRoot = tokens(body(':root'));
const darkMedia = tokens(body(':root:not([data-theme="light"])'));
const darkAttr = tokens(body(':root[data-theme="dark"],\n[data-theme="dark"]'));
const lightAttr = tokens(body(':root[data-theme="light"],\n[data-theme="light"]'));

check(
  'the light palette parsed',
  lightRoot.size > 120,
  `only ${lightRoot.size} tokens were read from :root`,
);
check(
  'both dark palettes parsed',
  darkMedia.size >= 88 && darkAttr.size >= 88,
  `media block ${darkMedia.size} tokens, attribute block ${darkAttr.size}`,
);

/* ------------------------------------------------- DS-2: one dark palette */

const onlyInMedia = [...darkMedia.keys()].filter((name) => !darkAttr.has(name));
const onlyInAttr = [...darkAttr.keys()].filter((name) => !darkMedia.has(name));
const disagreeing = [...darkMedia.entries()]
  .filter(([name, value]) => darkAttr.has(name) && darkAttr.get(name) !== value)
  .map(([name, value]) => `${name}: ${value} vs ${darkAttr.get(name)}`);

check(
  'the two dark blocks declare the same tokens',
  onlyInMedia.length === 0 && onlyInAttr.length === 0,
  `media-only: [${onlyInMedia.join(', ')}] attribute-only: [${onlyInAttr.join(', ')}]`,
);
check(
  'the two dark blocks agree on every value',
  disagreeing.length === 0,
  `the theme a reader sees would depend on how it was chosen: ${disagreeing.join(' | ')}`,
);

const lightDisagreeing = [...lightAttr.entries()]
  .filter(([name, value]) => lightRoot.get(name) !== value)
  .map(([name, value]) => `${name}: ${value} vs ${lightRoot.get(name) ?? 'undeclared'}`);

check(
  'the light attribute block agrees with :root',
  lightDisagreeing.length === 0,
  `forcing the light theme would not give the default theme: ${lightDisagreeing.join(' | ')}`,
);

/* ------------------------------------------- A-7 and A-6: measured ratios */

function channel(value) {
  const srgb = value / 255;
  return srgb <= 0.04045 ? srgb / 12.92 : ((srgb + 0.055) / 1.055) ** 2.4;
}

/** WCAG 2.x relative luminance of an opaque `#rrggbb` colour. */
function luminance(hex) {
  const match = /^#([0-9a-f]{6})$/i.exec(hex.trim());
  if (!match) {
    throw new Error(`not an opaque hex colour: ${hex}`);
  }
  const value = Number.parseInt(match[1], 16);
  return (
    0.2126 * channel((value >> 16) & 0xff)
    + 0.7152 * channel((value >> 8) & 0xff)
    + 0.0722 * channel(value & 0xff)
  );
}

/** WCAG 2.x contrast ratio between two opaque colours, 1 to 21. */
function contrast(a, b) {
  const first = luminance(a);
  const second = luminance(b);
  return (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05);
}

const themes = [
  ['light', lightRoot],
  ['dark', darkAttr],
];

for (const [name, palette] of themes) {
  for (const surface of ['--hb-surface-2', '--hb-surface-1']) {
    const ratio = contrast(palette.get('--hb-border-strong'), palette.get(surface));
    check(
      `A-7: border-strong reaches 3:1 on ${surface.replace('--hb-', '')} (${name})`,
      ratio >= 3,
      `measured ${ratio.toFixed(2)}:1 for ${palette.get('--hb-border-strong')} on ${palette.get(surface)}, `
        + 'so a control whose border is its only affordance fails WCAG 1.4.11',
    );
  }

  const focus = contrast(palette.get('--hb-focus-ring'), palette.get('--hb-surface-3'));
  check(
    `A-6: the focus ring reaches 3:1 on the palette surface (${name})`,
    focus >= 3,
    `measured ${focus.toFixed(2)}:1 for ${palette.get('--hb-focus-ring')} on ${palette.get('--hb-surface-3')}`,
  );
}

/* The measurement has to be able to fail, or the four checks above are theatre:
   the token A-7 replaced is put through the same formula and must come out
   short. */
const supersededLight = contrast('#b7c0cd', lightRoot.get('--hb-surface-2'));
const supersededDark = contrast('#3a4453', darkAttr.get('--hb-surface-2'));

check(
  'the contrast formula fails the colour A-7 replaced',
  supersededLight < 3 && supersededDark < 3,
  `the pre-A-7 border-strong measured ${supersededLight.toFixed(2)}:1 light and `
    + `${supersededDark.toFixed(2)}:1 dark, which is above the threshold this suite claims to enforce`,
);

/* ------------------------------------------- A-7: applied where it belongs */

const controls = [
  ['.hb-input,\n.hb-select,\n.hb-textarea', 'border: 1px solid var(--hb-border-strong)'],
  ['.hb-tool-btn', 'border: 1px solid var(--hb-border-strong)'],
  ['.hb-tool-field', 'border: 1px solid var(--hb-border-strong)'],
  ['.hb-btn', 'border: 1px solid var(--hb-border-strong)'],
  ['.hb-check-box', 'border: 1px solid var(--hb-border-strong)'],
];

for (const [selector, declaration] of controls) {
  check(
    `A-7: ${selector.split('\n')[0]} draws its boundary with the strong token`,
    body(selector).includes(declaration),
    `expected "${declaration}"`,
  );
}

check(
  'A-7: the tool button keeps the strong border on hover',
  !/\.hb-tool-btn:hover:not\(:disabled\) \{[^}]*border-color: var\(--hb-border\);/.test(css),
  'hovering a tool button drops its border back to --hb-border, which measures 1.27:1 on the toolbar',
);
check(
  'A-7: panel edges stay on the weak token',
  !body('.hb-panel').includes('--hb-border-strong'),
  'the stronger border was applied to a surface edge, not just to controls, so the chrome gets louder overall',
);

/* ------------------------------------ A-9 and DS-3: the control-size scale */

const sized = [
  ['.hb-tab-close', 'width: var(--hb-hit-min)'],
  ['.hb-tab-close', 'height: var(--hb-hit-min)'],
  ['.hb-panel-action', 'min-width: var(--hb-hit-min)'],
  ['.hb-panel-action', 'height: var(--hb-hit-min)'],
  ['.hb-tree-twisty', 'width: var(--hb-hit-min)'],
  ['.hb-tree-twisty', 'height: var(--hb-hit-min)'],
  ['.hb-menu-entry', 'height: var(--hb-control-h)'],
  ['.hb-tool-btn', 'height: var(--hb-control-h)'],
  ['.hb-tool-field', 'height: var(--hb-control-h)'],
  ['.hb-input,\n.hb-select,\n.hb-textarea', 'height: var(--hb-control-h)'],
  ['.hb-check', 'height: var(--hb-control-h)'],
  ['.hb-panel-footer', 'min-height: var(--hb-control-h)'],
  ['.hb-badge', 'height: var(--hb-control-h-sm)'],
];

for (const [selector, declaration] of sized) {
  check(
    `DS-3: ${selector.split('\n')[0]} takes its height from the scale`,
    body(selector).includes(declaration),
    `expected "${declaration}"`,
  );
}

check(
  'A-9: the hit floor is 24px and the scale is intact',
  lightRoot.get('--hb-hit-min') === '24px'
    && lightRoot.get('--hb-control-h') === '26px'
    && lightRoot.get('--hb-control-h-sm') === '20px',
  `hit-min ${lightRoot.get('--hb-hit-min')}, control-h ${lightRoot.get('--hb-control-h')}, `
    + `control-h-sm ${lightRoot.get('--hb-control-h-sm')}`,
);
check(
  'A-9: an interactive badge is floored at the hit minimum',
  /\.hb-badge:is\([^)]*\) \{\s*min-height: var\(--hb-hit-min\);/.test(css),
  'a badge that can be operated is back under 24px tall',
);
check(
  'A-9: the tree indent still steps 14px per depth',
  body('.hb-tree-indent').includes('var(--hb-tree-depth, 0) * 14px'),
  'the twisty box was allowed to change the indentation it overlaps',
);

/* ------------------------------------------------- A-8: the shape channel */

const cellSlots = body('.hb-byte,\n.hb-ascii');
for (const slot of ['--hb-cell-dash: 0', '--hb-cell-double: 0', '--hb-cell-strike: transparent']) {
  check(
    `A-8: the cell declares ${slot.split(':')[0]}`,
    cellSlots.includes(slot),
    'the shape slots have to default to off on every cell, or a mark leaks into the cells that have no class',
  );
}

const beforeLayer = body('.hb-byte::before,\n.hb-ascii::before');
for (const slot of ['--hb-cell-dash', '--hb-cell-double', '--hb-cell-strike']) {
  check(
    `A-8: ${slot} is composited in ::before`,
    beforeLayer.includes(`var(${slot})`),
    'the slot is declared but nothing paints it, so the rule that sets it does nothing',
  );
}
for (const slot of [
  '--hb-cell-corner',
  '--hb-cell-underline',
  '--hb-cell-state',
  '--hb-cell-hit',
  '--hb-cell-diff',
  '--hb-cell-field',
  '--hb-cell-tint',
]) {
  check(
    `A-8: the original ${slot} layer survived`,
    beforeLayer.includes(`var(${slot})`),
    'a layer that was already painted was dropped while adding the new ones',
  );
}

const marks = [
  ['.hb-byte.bc-print', '--hb-cell-underline: currentColor'],
  ['.hb-byte.bc-ctrl', '--hb-cell-dash: 1'],
  ['.hb-byte.bc-high', '--hb-cell-corner: currentColor'],
  ['.hb-byte.is-diff-added', '--hb-cell-ring: inset 3px 0 0 0 var(--hb-success)'],
  ['.hb-byte.is-diff-removed', '--hb-cell-strike: var(--hb-error)'],
  ['.hb-byte.is-diff-modified', '--hb-cell-double: 1'],
  ['.hb-byte.is-selected', '--hb-cell-ring: inset 0 0 0 1px var(--hb-sel-border)'],
];

for (const [selector, declaration] of marks) {
  check(
    `A-8: ${selector} carries a shape when marks are on`,
    markBody(selector).includes(declaration),
    `expected "${declaration}" so the class is told apart without colour (WCAG 1.4.1)`,
  );
}

check(
  'DS-5: --hb-sel-border is drawn by something',
  css.includes('var(--hb-sel-border)'),
  'the selection border is declared in both themes and painted by nothing',
);

/* ------------------------------------------------ A-10: forced colours */

const forced = body('@media (forced-colors: active)');
for (const fragment of [
  'color: CanvasText',
  'background: Highlight',
  '--hb-cell-dash: 1',
  '--hb-cell-corner: currentColor',
  'outline: 2px solid LinkText',
  'forced-color-adjust: none',
]) {
  check(
    `A-10: the forced-colors block still maps ${fragment}`,
    forced.includes(fragment),
    'High Contrast drops the palette and box-shadow together, so this is the only channel left',
  );
}

/* ------------------------------------------------------- UX-7 and DS-7 */

const dockTabActive = body('.hb-dock-tab.is-active');
check(
  'UX-7: the active panel tab is filled rather than underlined',
  dockTabActive.includes('background: var(--hb-surface-1)')
    && body('.hb-dock-tab.is-active::after').includes('content: none'),
  'the dock strip is drawing a document tab again, so the two strips are indistinguishable in greyscale',
);
check(
  'UX-7: the document tab keeps its accent underline',
  body('.hb-tab.is-active::after').includes('background: var(--hb-accent)'),
  'both strips changed, so they still match each other',
);

check(
  'DS-7: the swatch ring is a token in both themes',
  lightRoot.has('--hb-swatch-ring') && darkAttr.has('--hb-swatch-ring')
    && darkMedia.has('--hb-swatch-ring') && lightAttr.has('--hb-swatch-ring'),
  'a theme is missing --hb-swatch-ring, so the swatch edge falls back to nothing',
);
check(
  'DS-7: no colour literal is left in the swatch rules',
  body('.hb-swatch').includes('var(--hb-swatch-ring)')
    && body('.hb-swatch').includes('var(--hb-swatch-sheen)')
    && body('.hb-legend-swatch').includes('var(--hb-swatch-ring)'),
  'the swatches are back on hardcoded rgb() values, which no palette can follow',
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} stylesheet token expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('stylesheet tokens (A-6, A-7, A-8, A-9, A-10, DS-2, DS-3, DS-5, DS-7, UX-7): all expectations held\n');
