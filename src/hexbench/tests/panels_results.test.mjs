/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Gates the Results panel: two operations run one after the other must both
 * still be readable, with their arguments, without either being run again.
 *
 * The panel is not reached through an export. It is reached the way the
 * application reaches it - `installPanels` builds every panel and hands each to
 * `registerPanel` - so this suite is also what proves the panel is registered at
 * all, and it fails rather than skips if the identifier ever stops arriving.
 * That costs a document: panels.js transitively imports api.js, whose token
 * resolution touches `document` and `window` at module scope, and the panel
 * builds a real element tree. The stub below is therefore a small but genuine
 * node model - parent/child links, class lists, custom properties, listeners -
 * and every expectation reads the tree the panel actually built.
 *
 * Run by gate.ps1. Exits non-zero on the first failed expectation.
 */

const failures = [];

function check(label, condition, detail) {
  if (!condition) {
    failures.push(`${label}: ${detail}`);
  }
}

/* ------------------------------------------------------------- the document */

class FakeStyle {
  constructor() {
    this.properties = new Map();
  }

  setProperty(name, value) {
    this.properties.set(name, String(value));
  }

  getPropertyValue(name) {
    return this.properties.get(name) ?? '';
  }
}

class FakeClassList {
  constructor(node) {
    this.node = node;
  }

  get tokens() {
    return this.node.className === '' ? [] : this.node.className.split(/\s+/);
  }

  add(name) {
    if (!this.contains(name)) {
      this.node.className = [...this.tokens, name].join(' ');
    }
  }

  remove(name) {
    this.node.className = this.tokens.filter((token) => token !== name).join(' ');
  }

  contains(name) {
    return this.tokens.includes(name);
  }

  toggle(name) {
    if (this.contains(name)) {
      this.remove(name);
      return false;
    }
    this.add(name);
    return true;
  }
}

class FakeElement {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase();
    this.className = '';
    this.textContent = '';
    this.title = '';
    this.hidden = false;
    this.children = [];
    this.attributes = new Map();
    this.listeners = new Map();
    this.style = new FakeStyle();
    this.classList = new FakeClassList(this);
  }

  appendChild(child) {
    /* A fragment is spliced into the parent rather than nested, exactly as the
       DOM does it; the panel builds one fragment per run. */
    if (child instanceof FakeFragment) {
      for (const grandchild of child.children) {
        this.children.push(grandchild);
      }
      child.children.length = 0;
      return child;
    }
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

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }

  addEventListener(type, handler) {
    const bucket = this.listeners.get(type) ?? [];
    bucket.push(handler);
    this.listeners.set(type, bucket);
  }

  dispatch(type, event = {}) {
    for (const handler of this.listeners.get(type) ?? []) {
      handler({ stopPropagation: () => undefined, preventDefault: () => undefined, ...event });
    }
  }

  querySelectorAll(selector) {
    const wanted = selector.split('.').filter((part) => part !== '');
    const found = [];
    walk(this, (node) => {
      if (node !== this && wanted.every((name) => node.classList.contains(name))) {
        found.push(node);
      }
    });
    return found;
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] ?? null;
  }
}

class FakeFragment extends FakeElement {
  constructor() {
    super('#fragment');
  }
}

function walk(node, visit) {
  visit(node);
  for (const child of node.children ?? []) {
    walk(child, visit);
  }
}

function find(root, className) {
  const found = [];
  walk(root, (node) => {
    if (node.classList !== undefined && node.classList.contains(className)) {
      found.push(node);
    }
  });
  return found;
}

globalThis.document = {
  createElement: (tag) => new FakeElement(tag),
  createDocumentFragment: () => new FakeFragment(),
  querySelector: () => null,
  getElementById: () => null,
  documentElement: new FakeElement('html'),
};
globalThis.window = { location: { search: '' }, setTimeout: () => 0, clearTimeout: () => undefined };

/* ---------------------------------------------------------------- the bench */

const listeners = new Map();
const registered = new Map();
const reopened = [];

const bench = {
  catalog: null,
  grid: { caret: { offset: 0 }, selection: null, invalidate: () => undefined },
  documents: () => [],
  activeDocument: () => null,
  operation: (name) => (name === 'compute_hash' ? { name, returns: 'str', receiver: 'document', parameters: [] } : null),
  openOperation: (name, initial) => reopened.push({ name, initial }),
  reload: () => Promise.resolve(),
  toast: () => undefined,
  registerPanel: (panel) => registered.set(panel.id, panel),
  unregisterPanel: (id) => registered.delete(id),
  on: (name, handler) => {
    const bucket = listeners.get(name) ?? [];
    bucket.push(handler);
    listeners.set(name, bucket);
  },
  emit: (name, detail) => {
    for (const handler of listeners.get(name) ?? []) {
      handler(detail);
    }
  },
};

/* The runs below go through the real api.js request path, so what the panel
   records is what an operation returning through the shell records. Only the
   two operation routes are answered: an unexpected request is a change in
   behaviour and says so rather than resolving to something empty. */
const OPERATION_REPLIES = new Map([
  ['compute_hash', { ok: true, body: { operation: 'compute_hash', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', duration_ms: 1.42, created_handle: null, document: null } }],
  ['byte_type_distribution', { ok: true, body: { operation: 'byte_type_distribution', value: [12, 34, 56, 78], duration_ms: 0.36, created_handle: null, document: null } }],
  ['apply_template', { ok: false, status: 400, body: { error: { kind: 'index', status: 400, message: 'offset past end' } } }],
]);

globalThis.fetch = (path) => {
  const name = /\/api\/op\/([a-z_]+)/.exec(String(path))?.[1] ?? '';
  const reply = OPERATION_REPLIES.get(name);
  if (reply === undefined) {
    return Promise.reject(new Error(`unexpected request to ${path}`));
  }
  return Promise.resolve({ ok: reply.ok, status: reply.status ?? 200, statusText: 'Bad Request', json: () => Promise.resolve(reply.body) });
};

const { installPanels } = await import('../static/panels.js');
const env = await installPanels(bench);

/* installPanels takes over bench.openOperation - that hook is how a panel asks
   for an argument dialog, and the dialog is a modal this fixture has no business
   opening. The recorder goes back on afterwards, so what the click expectation
   below reads is the call the panel made, at the same seam the shell uses. */
bench.openOperation = (name, initial) => reopened.push({ name, initial });

const panel = registered.get('panels.results');
check(
  'installPanels registers the Results panel',
  panel !== undefined,
  `no panel with the id panels.results was registered; ids seen: ${JSON.stringify([...registered.keys()])}`,
);
if (panel === undefined) {
  report();
}

check('the Results panel lives in the bottom dock', panel.dock === 'bottom', `expected the bottom dock, got ${panel.dock}`);
check('the Results panel reports no count while empty', panel.count() === null, `an empty panel must not paint a count pill, got ${JSON.stringify(panel.count())}`);

const host = new FakeElement('div');
panel.mount(host);

/* ------------------------------------------------------- two consecutive runs */

await env.run('compute_hash', { algorithm: 'sha256', offset: 0 }, 'doc-a');
await env.run('byte_type_distribution', {}, 'doc-a');

const nodes = find(host, 'hb-tree-node').filter((node) => node.style.getPropertyValue('--hb-tree-depth') === '0');
check(
  'both runs are on screen at once (the point of the panel)',
  nodes.length === 2,
  `expected two run rows after two runs, got ${nodes.length}`,
);

function rowFields(node) {
  const part = (className) => find(node, className).map((child) => child.textContent).join('');
  return {
    label: part('hb-tree-label'),
    type: part('hb-tree-type'),
    value: part('hb-tree-value'),
    offset: part('hb-tree-offset'),
  };
}

const newest = nodes.length > 0 ? rowFields(nodes[0]) : null;
const older = nodes.length > 1 ? rowFields(nodes[1]) : null;

check(
  'the newest run is first',
  newest !== null && newest.label === 'byte_type_distribution',
  `newest first is the whole ordering promise; the first row was ${JSON.stringify(newest)}`,
);
check(
  'the earlier run is still readable, unaltered, below it',
  older !== null && older.label === 'compute_hash' && older.value.startsWith('e3b0c44298fc1c14'),
  `the first run must survive the second without being re-run; the second row was ${JSON.stringify(older)}`,
);
check(
  'a run carries the duration the engine reported',
  older !== null && older.offset === '1.42 ms',
  `expected the reported 1.42 ms against compute_hash, got ${JSON.stringify(older?.offset)}`,
);
check(
  'a run carries the catalogued return type',
  older !== null && older.type === 'str',
  `compute_hash returns str per the catalogue, the row said ${JSON.stringify(older?.type)}`,
);
check(
  'a list result is summarised rather than dumped',
  newest !== null && newest.value === '4 entries',
  `expected "4 entries" for a four-element return, got ${JSON.stringify(newest?.value)}`,
);
check(
  'a long string result is truncated',
  older !== null && older.value.endsWith('…') && older.value.length < 64,
  `a 64-character hash must not be printed whole into a tree row, got ${JSON.stringify(older?.value)}`,
);

const argumentRows = find(host, 'hb-tree-node').filter((node) => node.style.getPropertyValue('--hb-tree-depth') === '1');
check(
  'the arguments of a run are its children',
  argumentRows.length === 2,
  `compute_hash was run with two arguments and they are what expands under it, got ${argumentRows.length} child rows`,
);
const argumentText = argumentRows.map((row) => rowFields(row));
check(
  'an argument row names the argument and shows its value',
  argumentText.some((row) => row.label === 'algorithm' && row.value === 'sha256'),
  `expected an algorithm/sha256 row, got ${JSON.stringify(argumentText)}`,
);

/* -------------------------------------------------------------- a failed run */

let rethrown = null;
try {
  await env.run('apply_template', { name: 'pe', offset: 4096 }, 'doc-a');
} catch (error) {
  rethrown = error;
}
check(
  'a failing run still reaches its caller',
  rethrown !== null && rethrown.kind === 'index',
  'recording a failure must not swallow it: the caller still has to be able to report the failure itself',
);

const failedRow = find(host, 'hb-tree-node')
  .filter((node) => node.style.getPropertyValue('--hb-tree-depth') === '0')
  .map((node) => ({ node, fields: rowFields(node) }))
  .find((entry) => entry.fields.label === 'apply_template');

check(
  'a failure is recorded beside the successes rather than lost with a dialog',
  failedRow !== undefined,
  'a run that failed left no row at all, so the panel only records what already worked',
);
check(
  'a failed run reads as an error',
  failedRow !== undefined && failedRow.fields.type === 'error',
  `expected the type column to read "error", got ${JSON.stringify(failedRow?.fields.type)}`,
);
check(
  'a failed run shows the kind label and the message',
  failedRow !== undefined && failedRow.fields.value === 'INDEX · offset past end',
  `expected "INDEX · offset past end", got ${JSON.stringify(failedRow?.fields.value)}`,
);
const failedLabel = failedRow === undefined ? null : find(failedRow.node, 'hb-tree-label')[0] ?? null;
check(
  'a failed run marks its label with the error colour',
  failedLabel !== null && failedLabel.style.color === 'var(--hb-error)',
  `the operation name on a failed run must carry --hb-error, got ${JSON.stringify(failedLabel?.style?.color)}`,
);

check(
  'a failed run is timed even though no engine timing came back',
  failedRow !== undefined && /^\d+\.\d\d ms$/.test(failedRow.fields.offset),
  `a failure has a duration too - how long the attempt took - and the row should carry it; got ${JSON.stringify(failedRow?.fields.offset)}`,
);

/* ------------------------------------------------- a run the shell made itself */

/* The shell runs a few operations without going through the panels' env.run and
   emits the same event with no arguments attached. Such a run is still a run and
   still belongs in the list; it simply has nothing to expand. */
bench.emit('operation', { name: 'list_process_memory_regions', result: { duration_ms: 5.5, value: [1, 2], document: null } });

const shellRow = find(host, 'hb-tree-node')
  .filter((node) => node.style.getPropertyValue('--hb-tree-depth') === '0')
  .map((node) => rowFields(node))
  .find((fields) => fields.label === 'list_process_memory_regions');
check(
  'a run the shell reports without arguments is still recorded',
  shellRow !== undefined && shellRow.offset === '5.50 ms',
  `an operation the shell ran itself must still be listed; got ${JSON.stringify(shellRow)}`,
);

/* ------------------------------------------------------- footer, count, reuse */

const footer = find(host, 'hb-panel-footer')[0];
check(
  'the footer counts the runs and states the ordering',
  footer !== undefined && find(footer, 'hb-dim')[0]?.textContent === '4 runs · newest first',
  `expected "4 runs · newest first", got ${JSON.stringify(footer === undefined ? null : find(footer, 'hb-dim')[0]?.textContent)}`,
);
check(
  'the dock tab count follows the recorded runs',
  panel.count() === 4,
  `the panel must report its own count through count(), got ${JSON.stringify(panel.count())}`,
);

const compute = find(host, 'hb-tree-node').find((node) => rowFields(node).label === 'compute_hash');
check(
  'the first run is still on screen to be re-opened',
  compute !== undefined,
  'the earliest run has gone from the tree, so the re-open expectations below cannot be made at all',
);
if (compute !== undefined) {
  compute.dispatch('click');
  check(
    'clicking a run re-opens it with the arguments it was run with',
    reopened.length === 1 && reopened[0].name === 'compute_hash' && reopened[0].initial?.algorithm === 'sha256',
    `expected compute_hash to be re-opened prefilled, got ${JSON.stringify(reopened)}`,
  );
  check(
    'the clicked run is marked as selected',
    compute.classList.contains('is-selected'),
    'clicking a row leaves nothing showing which row is being talked about',
  );
}

const clear = find(host, 'hb-panel-action')[0];
check('the panel offers a clear action', clear !== undefined, 'no hb-panel-action was built, so the header lost its clear button');
if (clear !== undefined) {
  clear.dispatch('click');
  check(
    'the clear action empties the panel',
    find(host, 'hb-tree-node').length === 0 && panel.count() === null,
    `clearing must remove every row and stop the count pill, ${find(host, 'hb-tree-node').length} rows remained`,
  );
}

report();

function report() {
  if (failures.length > 0) {
    process.stdout.write(`${failures.length} results-panel expectation(s) failed:\n`);
    for (const failure of failures) {
      process.stdout.write(`  - ${failure}\n`);
    }
    process.exit(1);
  }
  process.stdout.write('results panel: two consecutive runs, their arguments and a failure all stay readable\n');
}
