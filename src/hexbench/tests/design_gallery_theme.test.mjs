/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Gates the one switch on the design gallery (DS-8).
 *
 * `design/index.html` is generated, links the live stylesheet, and carries the
 * only piece of behaviour in the whole design directory: two inline scripts
 * that resolve a theme before the body parses and then wire the switch to it.
 * Python can check the page's structure but not what those scripts do, and a
 * broken switch on a page that still renders perfectly is exactly the kind of
 * defect nothing else here would notice.
 *
 * So the scripts are lifted out of the generated page and really executed
 * against a small node model: attributes are stored verbatim, the click
 * listener the page registers is the one dispatched, and `localStorage` is a
 * real map that can also be made to throw the way a file:// page in a privacy
 * mode does. Nothing is pattern-matched, and nothing restates what the scripts
 * are supposed to say -- every expectation reads the attributes and the label a
 * browser would end up with.
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

const INDEX_PATH = fileURLToPath(new URL('../design/index.html', import.meta.url));
const SWITCH_ID = 'ds-theme';
const THEME_ATTRIBUTE = 'data-theme';
const DARK_QUERY = '(prefers-color-scheme: dark)';

const page = await readFile(INDEX_PATH, 'utf8');

const scripts = [...page.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((match) => match[1]);
if (scripts.length !== 2) {
  process.stdout.write(`design/index.html carries ${scripts.length} inline scripts, expected the head and body pair\n`);
  process.exit(1);
}
const [headScript, bodyScript] = scripts;

if (!page.includes(`id="${SWITCH_ID}"`)) {
  process.stdout.write(`design/index.html has no #${SWITCH_ID} control for the scripts to wire\n`);
  process.exit(1);
}

/* ============================================================ the node model */

function makeElement() {
  return {
    attributes: new Map(),
    textContent: '',
    listeners: [],
    setAttribute(name, value) {
      this.attributes.set(name, String(value));
    },
    getAttribute(name) {
      return this.attributes.has(name) ? this.attributes.get(name) : null;
    },
    addEventListener(type, handler) {
      this.listeners.push({ type, handler });
    },
    dispatch(type) {
      for (const listener of this.listeners) {
        if (listener.type === type) {
          listener.handler({ type });
        }
      }
    },
  };
}

function makeStorage({ stored = null, readThrows = false, writeThrows = false } = {}) {
  const values = new Map(stored === null ? [] : [[stored.key, stored.value]]);
  return {
    values,
    getItem(key) {
      if (readThrows) {
        throw new Error('access to storage is denied for this document');
      }
      return values.has(key) ? values.get(key) : null;
    },
    setItem(key, value) {
      if (writeThrows) {
        throw new Error('access to storage is denied for this document');
      }
      values.set(key, value);
    },
  };
}

function makeSession({ prefersDark, storage }) {
  const root = makeElement();
  const button = makeElement();
  const queried = [];
  const document = {
    documentElement: root,
    getElementById: (id) => (id === SWITCH_ID ? button : null),
  };
  const window = {
    localStorage: storage,
    matchMedia(query) {
      queried.push(query);
      return { matches: prefersDark && query === DARK_QUERY };
    },
  };
  return {
    root,
    button,
    queried,
    storage,
    runHead: () => new Function('document', 'window', headScript)(document, window),
    runBody: () => new Function('document', 'window', bodyScript)(document, window),
  };
}

function themeOf(session) {
  return session.root.getAttribute(THEME_ATTRIBUTE);
}

/* ============================================================ the OS default */

const followsSystem = makeSession({ prefersDark: true, storage: makeStorage() });
followsSystem.runHead();

check(
  'an unvisited gallery follows the operating system',
  themeOf(followsSystem) === 'dark',
  `nothing was stored and the system asked for dark, but the page stamped ${themeOf(followsSystem)}`,
);
check(
  'the system preference is read from the colour-scheme query',
  followsSystem.queried.includes(DARK_QUERY),
  `the head script asked for ${JSON.stringify(followsSystem.queried)} instead of ${DARK_QUERY}`,
);

followsSystem.runBody();

check(
  'the switch names the theme it is showing',
  followsSystem.button.textContent === 'Dark theme' && followsSystem.button.getAttribute('aria-pressed') === 'true',
  `the switch reads ${JSON.stringify(followsSystem.button.textContent)} with aria-pressed ` +
    `${followsSystem.button.getAttribute('aria-pressed')} while the page is dark`,
);
check(
  'loading the page persists nothing',
  followsSystem.storage.values.size === 0,
  'the resolved theme was written to storage on load, which pins the gallery to whatever the system said the first time',
);

/* ============================================================ the switch */

followsSystem.button.dispatch('click');

check(
  'clicking the switch swaps the palette',
  themeOf(followsSystem) === 'light',
  `one click from dark left the page at ${themeOf(followsSystem)}`,
);
check(
  'the switch relabels itself',
  followsSystem.button.textContent === 'Light theme' && followsSystem.button.getAttribute('aria-pressed') === 'false',
  `after the click the switch reads ${JSON.stringify(followsSystem.button.textContent)} with aria-pressed ` +
    `${followsSystem.button.getAttribute('aria-pressed')}`,
);
check(
  'an explicit choice is remembered',
  [...followsSystem.storage.values.values()].includes('light'),
  `storage holds ${JSON.stringify([...followsSystem.storage.values.entries()])} after the theme was chosen by hand`,
);

followsSystem.button.dispatch('click');

check(
  'the switch swaps back',
  themeOf(followsSystem) === 'dark' && followsSystem.button.textContent === 'Dark theme',
  `a second click left the page at ${themeOf(followsSystem)} labelled ${JSON.stringify(followsSystem.button.textContent)}`,
);

/* ============================================================ the reload */

const [rememberedKey] = [...followsSystem.storage.values.keys()];
const revisited = makeSession({
  prefersDark: true,
  storage: makeStorage({ stored: { key: rememberedKey, value: 'light' } }),
});
revisited.runHead();
revisited.runBody();

check(
  'a remembered choice outranks the operating system',
  themeOf(revisited) === 'light',
  `the stored choice was light and the system asked for dark, and the page came back ${themeOf(revisited)}`,
);
check(
  'the switch comes back labelled for what it is showing',
  revisited.button.textContent === 'Light theme' && revisited.button.getAttribute('aria-pressed') === 'false',
  `the reloaded switch reads ${JSON.stringify(revisited.button.textContent)} over a ${themeOf(revisited)} page`,
);

const corrupted = makeSession({
  prefersDark: false,
  storage: makeStorage({ stored: { key: rememberedKey, value: 'sepia' } }),
});
corrupted.runHead();

check(
  'a value that is not a theme is ignored rather than stamped',
  themeOf(corrupted) === 'light',
  `storage held "sepia" and the system asked for light, and the page stamped ${themeOf(corrupted)}`,
);

/* ============================================================ no storage */

const denied = makeSession({ prefersDark: true, storage: makeStorage({ readThrows: true, writeThrows: true }) });
denied.runHead();
denied.runBody();
denied.button.dispatch('click');

check(
  'a page with no storage still resolves and still switches',
  themeOf(denied) === 'light' && denied.button.textContent === 'Light theme',
  `with storage throwing, the page ended at ${themeOf(denied)} labelled ${JSON.stringify(denied.button.textContent)}`,
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} design gallery theme expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('design gallery theme switch (DS-8): all expectations held\n');
