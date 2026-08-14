/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Exercises api.js's pure failure-classification rule for real, and reads
 * api.js as text to confirm readFailure() actually routes through it rather
 * than reimplementing a second, stale server-error shape. api.js's
 * module-level token resolution touches `document`/`window`, so both are
 * stubbed with the bare minimum before the module is loaded -- the stub is
 * never touched by any assertion below, every check runs against the real
 * exported function.
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

globalThis.document = { querySelector: () => null };
globalThis.window = { location: { search: '' } };

const staticDir = fileURLToPath(new URL('../static/', import.meta.url));
const apiSource = await readFile(`${staticDir}api.js`, 'utf8');

const { classifyFailure, DispatchError, isBusy } = await import('../static/api.js');

/* --------------------------------------------------------------- #61: classifyFailure */

const busyFailure = classifyFailure({ error: { message: 'compute_hash is busy', kind: 'busy', status: 503 } }, 503, 'Service Unavailable');
check('a real server busy envelope classifies as busy', isBusy(busyFailure), `expected a busy DispatchError, got kind=${busyFailure.kind}`);
check('a real server busy envelope keeps the server message', busyFailure.message === 'compute_hash is busy', `expected the server message, got ${busyFailure.message}`);
check('a real server busy envelope keeps the server status', busyFailure.status === 503, `expected 503, got ${busyFailure.status}`);

const internalFailure = classifyFailure({ error: { message: 'boom', kind: 'internal', status: 500 } }, 500, 'Internal Server Error');
check('a non-busy classified error keeps its own kind', internalFailure.kind === 'internal', `expected internal, got ${internalFailure.kind}`);
check('a classified error is never mistaken for busy', !isBusy(internalFailure), 'an internal error must not be reported as busy');

const missingKind = classifyFailure({ error: { message: 'boom' } }, 500, 'Internal Server Error');
check('a classified error missing a kind falls back to internal', missingKind.kind === 'internal', `expected the internal fallback, got ${missingKind.kind}`);

/* The server never emits a bare {"busy": true} envelope (BusyError is always
   routed through dispatch.py's _EXCEPTION_RULES into the same {"error": {...}}
   shape as every other classified failure) - this was dead code claiming a
   second server contract that does not exist (the defect). */
const bareBusyShape = classifyFailure({ busy: true, operation: 'compute_hash' }, 503, 'Service Unavailable');
check(
  'a bare {busy: true} payload (a shape the server never sends) is not treated as busy (the defect)',
  !isBusy(bareBusyShape),
  `a payload with no "error" envelope classified as busy anyway (kind=${bareBusyShape.kind}), reviving a server contract that does not exist`,
);
check('a bare {busy: true} payload falls back to the generic transport failure', bareBusyShape.kind === 'transport', `expected transport, got ${bareBusyShape.kind}`);

const noBody = classifyFailure(null, 502, 'Bad Gateway');
check('an unparsable body falls back to a transport failure', noBody.kind === 'transport' && noBody.status === 502, `expected a 502 transport failure, got ${JSON.stringify({ kind: noBody.kind, status: noBody.status })}`);
check('an unparsable body with no status text still carries the numeric status', classifyFailure(null, 502, '').message.includes('502'), 'the fallback message must name the HTTP status when statusText is empty');

check('classifyFailure produces a real DispatchError', busyFailure instanceof DispatchError, 'classifyFailure must return a DispatchError, not a plain object');

check(
  'readFailure routes through classifyFailure rather than reimplementing the shape',
  /return classifyFailure\(payload, response\.status, response\.statusText\);/.test(apiSource),
  'readFailure() no longer delegates to classifyFailure(), so the two could drift apart',
);
check(
  'the stale bare payload.busy branch is gone from api.js (the defect)',
  !/payload\.busy\b/.test(apiSource),
  'api.js still checks a bare payload.busy flag the server never sends',
);

if (failures.length > 0) {
  process.stdout.write(`${failures.length} api failure-classification expectation(s) failed:\n`);
  for (const failure of failures) {
    process.stdout.write(`  - ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write('api failure classification rules: all expectations held\n');
