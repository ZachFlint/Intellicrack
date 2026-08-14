/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Zachary Flint
   This file is part of Intellicrack. See LICENSE for details.

   list_process_memory_regions hands back the protection and the state exactly as
   the kernel reported them: two raw bit fields. Decoding them is the difference
   between a table of 64s and 4096s and a table that says PAGE_EXECUTE_READWRITE
   in a committed region, so the decoding lives here rather than being open coded
   wherever a region is displayed. */

const PAGE_GUARD = 0x100;
const PAGE_NOCACHE = 0x200;
const PAGE_WRITECOMBINE = 0x400;
const ACCESS_MASK = 0xff;

const PAGE_ACCESS = new Map([
  [0x01, 'PAGE_NOACCESS'],
  [0x02, 'PAGE_READONLY'],
  [0x04, 'PAGE_READWRITE'],
  [0x08, 'PAGE_WRITECOPY'],
  [0x10, 'PAGE_EXECUTE'],
  [0x20, 'PAGE_EXECUTE_READ'],
  [0x40, 'PAGE_EXECUTE_READWRITE'],
  [0x80, 'PAGE_EXECUTE_WRITECOPY'],
]);

const PAGE_MODIFIERS = new Map([
  [PAGE_GUARD, 'PAGE_GUARD'],
  [PAGE_NOCACHE, 'PAGE_NOCACHE'],
  [PAGE_WRITECOMBINE, 'PAGE_WRITECOMBINE'],
]);

const MEMORY_STATES = new Map([
  [0x1000, 'MEM_COMMIT'],
  [0x2000, 'MEM_RESERVE'],
  [0x10000, 'MEM_FREE'],
]);

const EXECUTABLE_ACCESS = new Set([0x10, 0x20, 0x40, 0x80]);
const WRITABLE_ACCESS = new Set([0x04, 0x08, 0x40, 0x80]);
const READABLE_ACCESS = new Set([0x02, 0x04, 0x08, 0x20, 0x40, 0x80]);

/** Every named page protection constant, access bits and modifier bits alike. */
export const PROTECTION_NAMES = new Map([...PAGE_ACCESS, ...PAGE_MODIFIERS]);

/** Every named memory state constant. */
export const STATE_NAMES = new Map(MEMORY_STATES);

/**
 * Split a raw protection value into its one access constant and its modifiers.
 *
 * A protection is never a single lookup: exactly one access constant occupies
 * the low byte and any number of modifier bits sit above it, so a region that is
 * both executable and guarded reports 0x120 and appears in no table of names.
 *
 * @param {number} value Raw protection value as the kernel reported it.
 * @returns {{access: string, modifiers: string[], text: string, readable: boolean,
 *   writable: boolean, executable: boolean, guarded: boolean, unknown: boolean}}
 */
export function describeProtection(value) {
  const numeric = Number(value) | 0;
  const accessBits = numeric & ACCESS_MASK;
  const access = PAGE_ACCESS.get(accessBits) ?? null;
  const modifiers = [];
  for (const [bit, name] of PAGE_MODIFIERS) {
    if ((numeric & bit) !== 0) {
      modifiers.push(name);
    }
  }
  const label = access ?? `0x${numeric.toString(16).toUpperCase()}`;
  return {
    access: label,
    modifiers,
    text: [label, ...modifiers].join(' | '),
    readable: READABLE_ACCESS.has(accessBits),
    writable: WRITABLE_ACCESS.has(accessBits),
    executable: EXECUTABLE_ACCESS.has(accessBits),
    guarded: (numeric & PAGE_GUARD) !== 0,
    unknown: access === null,
  };
}

/**
 * Name a raw memory state value.
 *
 * @param {number} value Raw state value as the kernel reported it.
 * @returns {{name: string, committed: boolean, free: boolean, unknown: boolean}}
 */
export function describeState(value) {
  const numeric = Number(value) | 0;
  const name = MEMORY_STATES.get(numeric) ?? null;
  return {
    name: name ?? `0x${numeric.toString(16).toUpperCase()}`,
    committed: numeric === 0x1000,
    free: numeric === 0x10000,
    unknown: name === null,
  };
}

/**
 * Pick the badge modifier that matches how dangerous a protection is.
 *
 * @param {number} value Raw protection value.
 * @returns {string} One of the design system's badge modifier class names.
 */
export function protectionTone(value) {
  const decoded = describeProtection(value);
  if (decoded.executable && decoded.writable) {
    return 'is-error';
  }
  if (decoded.executable) {
    return 'is-warning';
  }
  if (decoded.guarded) {
    return 'is-accent';
  }
  if (decoded.writable) {
    return 'is-info';
  }
  return '';
}

/**
 * Pick the badge modifier that matches a memory state.
 *
 * @param {number} value Raw state value.
 * @returns {string} One of the design system's badge modifier class names.
 */
export function stateTone(value) {
  const decoded = describeState(value);
  if (decoded.committed) {
    return 'is-success';
  }
  if (decoded.free) {
    return '';
  }
  return 'is-info';
}

/**
 * Whether a region can be snapshotted into a document at all.
 *
 * Reading an uncommitted or no-access region fails inside the engine, so the UI
 * disables the action rather than offering a call that cannot succeed.
 *
 * @param {number} protection Raw protection value.
 * @param {number} state Raw state value.
 * @returns {boolean} True when a snapshot of the region is worth attempting.
 */
export function isSnapshotable(protection, state) {
  return describeState(state).committed && describeProtection(protection).readable && !describeProtection(protection).guarded;
}
