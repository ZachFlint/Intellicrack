/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Zachary Flint
 *
 * This file is part of Intellicrack. See LICENSE for details.
 *
 * Rust's Display for a float never switches to scientific notation, so a
 * denormal reaching the inspector as text arrives spelled out in full: a
 * float64 can run past three hundred characters of leading zeros. Rendered
 * verbatim, one such row grows taller than the panel holding it and pushes
 * every reading below it out of view.
 *
 * This module holds nothing but the re-spelling rule, free of any DOM access,
 * so it can be exercised directly by the test suite rather than only inside a
 * browser.
 */

const SCALAR_TEXT_LIMIT = 24;
const NUMERIC_TEXT = /^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/;

export function compactScalar(raw) {
  const text = String(raw);
  if (text.length <= SCALAR_TEXT_LIMIT || !NUMERIC_TEXT.test(text)) {
    return { text, full: null };
  }
  const parsed = Number(text);
  if (!Number.isFinite(parsed) || Number(parsed.toExponential()) !== parsed) {
    return { text, full: null };
  }
  const compact = parsed.toExponential();
  return compact.length < text.length ? { text: compact, full: text } : { text, full: null };
}
