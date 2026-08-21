/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * One badge, one writer.
 *
 * The dock asks every panel for a `count()` and rebuilds its tab strip from the
 * answers. The operation console used to also reach into the document for its
 * own tab and append a pill to it, which made two writers for one badge: the
 * next re-render from the panel list dropped the console's number without a
 * word. This suite holds both halves of the fix - that nothing outside the dock
 * addresses a dock tab any more, and that the console's coverage really does
 * arrive through count().
 *
 * The count is not a constant, it is what the session has exercised, so the
 * behavioural half drives the real panel: a stubbed `/api/jobs` answer goes in
 * through the real api.js request path and the expectation is on what count()
 * reports afterwards.
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

/* ------------------------------------------------- nobody else writes the tab */

const moduleNames = (await readdir(staticDir)).filter((name) => name.endsWith('.js'));
check(
  'the static modules were found',
  moduleNames.length > 5,
  `only ${moduleNames.length} modules were read, so the expectations below would pass vacuously`,
);
for (const name of moduleNames) {
  const source = await readFile(`${staticDir}${name}`, 'utf8');
  const mentions = (source.match(/hb-dock-tab/g) ?? []).length;
  check(
    `${name} does not address a dock tab`,
    name === 'shell.js' || mentions === 0,
    `${name} names hb-dock-tab ${mentions} time(s); the dock's own render is the only writer of a tab, and a second one is silently overwritten by the next render`,
  );
}

const consoleSource = await readFile(`${staticDir}console.js`, 'utf8');
check(
  'the console panel still reports a count at all',
  /count: /.test(consoleSource),
  'the console panel descriptor has no count member, so the dock has nothing to paint and the number is simply gone',
);

/* ------------------------------------------------------------- the document */

class FakeElement {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase();
    this.className = '';
    this.textContent = '';
    this.hidden = false;
    this.children = [];
    this.style = { setProperty: () => undefined };
    this.classList = { add: () => undefined, remove: () => undefined, contains: () => false, toggle: () => false };
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  append(...nodes) {
    for (const node of nodes) {
      this.appendChild(node);
    }
  }

  replaceChildren(...nodes) {
    this.children = [];
    this.append(...nodes);
  }

  setAttribute() {
    return undefined;
  }

  addEventListener() {
    return undefined;
  }

  querySelectorAll() {
    return [];
  }

  querySelector() {
    return null;
  }

  scrollIntoView() {
    return undefined;
  }
}

globalThis.document = {
  createElement: (tag) => new FakeElement(tag),
  createDocumentFragment: () => new FakeElement('#fragment'),
  querySelector: () => null,
  getElementById: () => null,
  documentElement: new FakeElement('html'),
};
globalThis.window = { location: { search: '' }, setTimeout: () => 0, clearTimeout: () => undefined };

/* The one server answer the panel needs. Anything else must not be quietly
   answered with an empty object: a request this suite did not intend is a
   change in behaviour, not a fixture detail. */
const requested = [];
globalThis.fetch = (path) => {
  requested.push(String(path));
  if (String(path).startsWith('/api/jobs')) {
    return Promise.resolve({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ jobs: [], exercised: ['read_bytes', 'compute_hash', 'entropy'], operation_count: 12 }),
    });
  }
  return Promise.reject(new Error(`unexpected request to ${path}`));
};

const { createOperationConsole } = await import('../static/console.js');

const panel = createOperationConsole({
  catalog: () => null,
  reference: () => null,
  formContext: () => ({ handle: null }),
  resultContext: () => ({}),
  run: () => Promise.reject(new Error('not run here')),
  toast: () => undefined,
});

check(
  'the console panel exposes count() to the dock',
  typeof panel.count === 'function',
  'the dock reads a panel count through count(); without one the console has no way to report a number at all',
);
check(
  'an unread session reports no count rather than 0/0',
  panel.count() === null,
  `before any coverage is known the tab must carry no pill, got ${JSON.stringify(panel.count())}`,
);

panel.mount(new FakeElement('div'));
await new Promise((resolve) => setTimeout(resolve, 0));

check(
  'the panel did read the job list',
  requested.some((path) => path.startsWith('/api/jobs')),
  `nothing asked the server for the coverage, so the expectation below would pass vacuously; requests: ${JSON.stringify(requested)}`,
);
check(
  'the coverage reaches the dock through count()',
  panel.count() === '3/12',
  `the session exercised 3 of 12 operations and that is what the tab pill must read; count() said ${JSON.stringify(panel.count())}`,
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} dock-count expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('dock tab counts: one writer, and the console reports through count()\n');
