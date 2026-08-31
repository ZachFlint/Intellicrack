/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Zachary Flint
   This file is part of Intellicrack. See LICENSE for details.

   The one place that talks to the server. Every other module goes through
   these functions, so the session token, the error shape and the tagged-bytes
   encoding are each dealt with exactly once. */

const TOKEN_HEADER = 'X-Hexbench-Token';
const JSON_TYPE = 'application/json';
const HEARTBEAT_MS = 2000;
const BYTES_TAG = '__bytes__';
const HEX_RADIX = 16;
const HEX_DIGITS = '0123456789ABCDEF';

const HEX_TABLE = (() => {
  const table = new Array(256);
  for (let value = 0; value < 256; value += 1) {
    table[value] = HEX_DIGITS[value >> 4] + HEX_DIGITS[value & 0x0f];
  }
  return table;
})();

function resolveToken() {
  const meta = document.querySelector('meta[name="hexbench-token"]');
  const embedded = meta ? meta.content.trim() : '';
  if (embedded && !embedded.startsWith('__')) {
    return embedded;
  }
  return new URLSearchParams(window.location.search).get('token') ?? '';
}

const TOKEN = resolveToken();

/** A failure the server classified, or a transport failure dressed in the same shape. */
export class DispatchError extends Error {
  constructor(message, kind, status) {
    super(message);
    this.name = 'DispatchError';
    this.kind = kind;
    this.status = status;
  }
}

/** True when the failure means the document was held by another operation. */
export function isBusy(error) {
  return error instanceof DispatchError && error.kind === 'busy';
}

/** True when the caller aborted the request itself. */
export function isAborted(error) {
  return error instanceof DOMException && error.name === 'AbortError';
}

function headers(hasBody) {
  const built = { [TOKEN_HEADER]: TOKEN };
  if (hasBody) {
    built['Content-Type'] = JSON_TYPE;
  }
  return built;
}

/**
 * Build the failure a parsed response body describes.
 *
 * The server's `_error_response` -> `_failure()` path (`api.py`, `dispatch.py`)
 * nests every classified failure - including a busy document, raised as
 * `registry.BusyError` and mapped through `_EXCEPTION_RULES` - under a single
 * `{"error": {"kind": ..., "status": ..., "message": ...}}` envelope. There is
 * no second, bare `{"busy": true}` shape for the server to ever send.
 *
 * @param {object|null} payload The parsed JSON body, or null when it wasn't JSON.
 * @param {number} status HTTP status code of the response.
 * @param {string} statusText HTTP status text of the response.
 * @returns {DispatchError} The failure the payload describes.
 */
export function classifyFailure(payload, status, statusText) {
  if (payload && typeof payload === 'object' && payload.error) {
    const { message, kind, status: payloadStatus } = payload.error;
    return new DispatchError(message ?? statusText, kind ?? 'internal', payloadStatus ?? status);
  }
  return new DispatchError(statusText || `HTTP ${status}`, 'transport', status);
}

async function readFailure(response) {
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  return classifyFailure(payload, response.status, response.statusText);
}

async function request(method, path, options = {}) {
  const { body = null, signal = null } = options;
  let response;
  try {
    response = await fetch(path, {
      method,
      headers: headers(body !== null),
      body: body === null ? null : JSON.stringify(body),
      cache: 'no-store',
      signal,
    });
  } catch (error) {
    if (isAborted(error)) {
      throw error;
    }
    throw new DispatchError(String(error && error.message ? error.message : error), 'transport', 0);
  }
  if (!response.ok) {
    throw await readFailure(response);
  }
  return response;
}

async function requestJson(method, path, options = {}) {
  const response = await request(method, path, options);
  return response.json();
}

/** Hexadecimal for a byte sequence, uppercase, no separators. */
export function toHex(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = '';
  for (let index = 0; index < view.length; index += 1) {
    out += HEX_TABLE[view[index]];
  }
  return out;
}

/** Bytes for a hexadecimal string; whitespace and 0x prefixes are ignored. */
export function fromHex(text) {
  const cleaned = String(text).replace(/0x/gi, '').replace(/[\s_,:-]/g, '');
  const usable = cleaned.length % 2 === 0 ? cleaned : cleaned.slice(0, -1);
  const bytes = new Uint8Array(usable.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(usable.slice(index * 2, index * 2 + 2), HEX_RADIX);
  }
  return bytes;
}

/** True when a JSON value is the server's tagged-bytes shape. */
export function isTaggedBytes(value) {
  return Boolean(value) && typeof value === 'object' && typeof value[BYTES_TAG] === 'string';
}

/** Bytes carried by a tagged-bytes value, or null when the value is something else. */
export function taggedBytes(value) {
  return isTaggedBytes(value) ? fromHex(value[BYTES_TAG]) : null;
}

/** The catalogue, fetched once per session. */
let catalogPromise = null;
export function getCatalog() {
  catalogPromise ??= requestJson('GET', '/api/catalog');
  return catalogPromise;
}

/** The engine facts the catalogue's signatures do not carry, fetched once per session. */
let referencePromise = null;
export function getReference() {
  referencePromise ??= requestJson('GET', '/api/reference');
  return referencePromise;
}

/** Run one catalogued operation. */
export function callOp(name, options = {}) {
  const { handle = null, mode = null } = options;
  const args = options.arguments ?? options.args ?? {};
  const query = mode ? `?mode=${encodeURIComponent(mode)}` : '';
  const body = { arguments: args };
  if (handle) {
    body.handle = handle;
  }
  if (mode) {
    body.mode = mode;
  }
  return requestJson('POST', `/api/op/${encodeURIComponent(name)}${query}`, { body });
}

/** Run one operation and take its untruncated binary return value. */
export async function callOpRaw(name, args = {}, options = {}) {
  const { handle = null } = options;
  const body = { arguments: args };
  if (handle) {
    body.handle = handle;
  }
  const response = await request('POST', `/api/op/${encodeURIComponent(name)}?raw=1`, { body });
  return response.arrayBuffer();
}

/** Read the byte window the grid is showing, already decoded. */
export async function readWindow(handle, offset, length, options = {}) {
  const { signal = null } = options;
  const query = `offset=${offset}&length=${length}`;
  const payload = await requestJson('GET', `/api/documents/${encodeURIComponent(handle)}/window?${query}`, { signal });
  return {
    offset: payload.offset,
    length: payload.length,
    generation: payload.generation,
    documentLength: payload.document_length,
    bytes: fromHex(payload.data),
  };
}

/** Every document this session holds open. */
export function listDocuments() {
  return requestJson('GET', '/api/documents');
}

/** State of one open document. */
export function getDocument(handle) {
  return requestJson('GET', `/api/documents/${encodeURIComponent(handle)}`);
}

/** Open a new, empty document. */
export function createDocument() {
  return requestJson('POST', '/api/documents');
}

/** Drop a document from the session. */
export function closeDocument(handle) {
  return requestJson('DELETE', `/api/documents/${encodeURIComponent(handle)}`);
}

/** The run log and the coverage the session has reached. */
export function listJobs(limit = 100) {
  return requestJson('GET', `/api/jobs?limit=${limit}`);
}

/** State of one background job. */
export function pollJob(jobId) {
  return requestJson('GET', `/api/jobs/${encodeURIComponent(jobId)}`);
}

/** The untruncated binary payload a background job produced. */
export async function jobRaw(jobId) {
  const response = await request('GET', `/api/jobs/${encodeURIComponent(jobId)}/raw`);
  return response.arrayBuffer();
}

/** Tell the server the window is still open. */
export function heartbeat() {
  return requestJson('POST', '/api/heartbeat');
}

/** Ask the server to stop. */
export function shutdown() {
  return requestJson('POST', '/api/shutdown');
}

let heartbeatTimer = null;
let suppressed = false;

/**
 * Let the page go away once without taking the server with it.
 *
 * A reload fires `pagehide` exactly as a close does, and shutting down on a
 * reload would leave the reloaded page pointing at a dead port. Anything that
 * knows the page is coming back says so here first.
 */
export function suppressNextShutdown() {
  suppressed = true;
}

function beaconShutdown() {
  if (suppressed) {
    return;
  }
  const url = '/api/shutdown';
  if (typeof fetch === 'function') {
    fetch(url, { method: 'POST', headers: headers(false), keepalive: true }).catch(() => undefined);
    return;
  }
  navigator.sendBeacon(url, new Blob([''], { type: JSON_TYPE }));
}

function noticeReloadKey(event) {
  if (event.key === 'F5' || ((event.ctrlKey || event.metaKey) && (event.key === 'r' || event.key === 'R'))) {
    suppressNextShutdown();
  }
}

/**
 * Keep the session alive while the window is, and end it when the window goes.
 *
 * The server treats silence as the client having closed, so the page must beat.
 * The shutdown on `pagehide` is what makes closing the window stop the process
 * promptly rather than after the idle timeout; it goes out with `keepalive`
 * rather than `sendBeacon` because a beacon cannot carry the session token and
 * would be refused.
 */
export function startHeartbeat() {
  if (heartbeatTimer !== null) {
    return;
  }
  heartbeatTimer = window.setInterval(() => {
    heartbeat().catch(() => undefined);
  }, HEARTBEAT_MS);
  window.addEventListener('keydown', noticeReloadKey, true);
  window.addEventListener('pagehide', beaconShutdown);
}

/** Stop beating and stop asking the server to stay. */
export function stopHeartbeat() {
  if (heartbeatTimer !== null) {
    window.clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }
  window.removeEventListener('keydown', noticeReloadKey, true);
  window.removeEventListener('pagehide', beaconShutdown);
}
