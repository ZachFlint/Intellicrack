// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Zachary Flint
//
// This file is part of Intellicrack. See LICENSE for details.

//! Searching a buffer: exact bytes, hex patterns with nibble wildcards, text
//! in any encoding, byte regular expressions and integers or floats of a given
//! width, plus replacing every non-overlapping occurrence of a byte pattern.
//! Large buffers are searched in parallel chunks that overlap by the pattern
//! length, so a match across a seam is found once.

use rayon::prelude::*;
use thiserror::Error;

use crate::encodings::EncodingError;

/// One match: the byte range `offset..offset + length`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResult {
    /// Offset of the first matched byte.
    pub offset: usize,
    /// Number of matched bytes.
    pub length: usize,
}

/// Errors raised for search input that cannot be evaluated.
#[derive(Error, Debug)]
pub enum SearchError {
    /// The hex pattern contains an invalid character or an odd digit count.
    #[error("invalid hex pattern: {0}")]
    InvalidHexPattern(String),
    /// The regular expression does not compile.
    #[error("invalid regex: {0}")]
    InvalidRegex(#[from] regex::Error),
    /// The text encoding is not recognized.
    #[error(transparent)]
    Encoding(#[from] EncodingError),
    /// A numeric search was given an unsupported width or a non-finite value.
    #[error("invalid numeric search: {0}")]
    InvalidNumeric(String),
}

const CHUNK_SIZE: usize = 4 * 1024 * 1024;

fn build_bad_char_table(pattern: &[u8]) -> [usize; 256] {
    let plen = pattern.len();
    let mut table = [plen; 256];
    for i in 0..plen.saturating_sub(1) {
        table[pattern[i] as usize] = plen - 1 - i;
    }
    table
}

fn build_good_suffix_table(pattern: &[u8]) -> Vec<usize> {
    let m = pattern.len();
    if m == 0 {
        return Vec::new();
    }
    let mut table = vec![m; m];
    let mut suffix = vec![0usize; m];

    suffix[m - 1] = m;
    let mut g: isize = m.cast_signed() - 1;
    let mut f: usize = 0;

    for i in (0..m - 1).rev() {
        let i_signed = i.cast_signed();
        if i_signed > g && suffix[i + m - 1 - f] < (i_signed - g).cast_unsigned() {
            suffix[i] = suffix[i + m - 1 - f];
        } else {
            if i_signed < g {
                g = i_signed;
            }
            f = i;
            while g >= 0 && pattern[g.cast_unsigned()] == pattern[g.cast_unsigned() + m - 1 - f] {
                g -= 1;
            }
            suffix[i] = (f.cast_signed() - g).cast_unsigned();
        }
    }

    let mut j = 0usize;
    for i in (0..m).rev() {
        if suffix[i] == i + 1 {
            while j < m - 1 - i {
                if table[j] == m {
                    table[j] = m - 1 - i;
                }
                j += 1;
            }
        }
    }

    for i in 0..m - 1 {
        table[m - 1 - suffix[i]] = m - 1 - i;
    }

    table
}

/// Finds every (overlapping) occurrence of `pattern`, in ascending offset order.
///
/// Inputs above 4 MiB are split into overlapping chunks searched in parallel;
/// the merged result is identical to a serial scan.
#[must_use]
pub fn search_bytes(data: &[u8], pattern: &[u8], max_results: usize) -> Vec<SearchResult> {
    if pattern.is_empty() || data.len() < pattern.len() {
        return Vec::new();
    }

    if data.len() <= CHUNK_SIZE {
        return search_bytes_single(data, pattern, max_results, 0);
    }

    let overlap = pattern.len().saturating_sub(1);
    let mut chunks: Vec<(usize, &[u8])> = Vec::new();
    let mut start: usize = 0;
    while start < data.len() {
        let end = (start + CHUNK_SIZE + overlap).min(data.len());
        chunks.push((start, &data[start..end]));
        start += CHUNK_SIZE;
    }

    let mut all_results: Vec<SearchResult> = chunks
        .par_iter()
        .flat_map(|(chunk_offset, chunk)| {
            search_bytes_single(chunk, pattern, max_results, *chunk_offset)
        })
        .collect();

    all_results.sort_by_key(|r| r.offset);
    all_results.dedup_by_key(|r| r.offset);
    all_results.truncate(max_results);
    all_results
}

fn search_bytes_single(
    data: &[u8],
    pattern: &[u8],
    max_results: usize,
    base_offset: usize,
) -> Vec<SearchResult> {
    let plen = pattern.len();
    if data.len() < plen {
        return Vec::new();
    }

    let bad_char = build_bad_char_table(pattern);
    let good_suffix = build_good_suffix_table(pattern);
    let mut results = Vec::new();
    let mut i: usize = 0;

    while i <= data.len() - plen && results.len() < max_results {
        let mut j = plen;
        while j > 0 && pattern[j - 1] == data[i + j - 1] {
            j -= 1;
        }

        if j == 0 {
            results.push(SearchResult {
                offset: base_offset + i,
                length: plen,
            });
            i += good_suffix[0];
        } else {
            let bad = bad_char[usize::from(data[i + j - 1])];
            let bc_shift = if bad > plen - j { bad - (plen - j) } else { 1 };
            let gs_shift = good_suffix[j - 1];
            i += bc_shift.max(gs_shift);
        }
    }

    results
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HexNibble {
    Value(u8),
    Wildcard,
}

/// Parses a hex pattern into `(value, mask)` byte pairs.
///
/// Accepts hex digits and `?` nibble wildcards, separated by any mix of
/// whitespace and the `_ , : -` separators the editor's hex fields allow.
/// Every other character is rejected rather than silently dropped, because
/// dropping it (e.g. the `x` of a `0x` prefix) re-pairs the nibbles and
/// searches for different bytes.
fn parse_hex_pattern(pattern_str: &str) -> Result<Vec<(u8, u8)>, SearchError> {
    let mut nibbles: Vec<HexNibble> = Vec::new();
    for (position, ch) in pattern_str.chars().enumerate() {
        if let Some(digit) = ch.to_digit(16) {
            let value = u8::try_from(digit).map_err(|_| {
                SearchError::InvalidHexPattern(format!("digit '{ch}' out of range"))
            })?;
            nibbles.push(HexNibble::Value(value));
        } else if ch == '?' {
            nibbles.push(HexNibble::Wildcard);
        } else if !(ch.is_whitespace() || matches!(ch, '_' | ',' | ':' | '-')) {
            return Err(SearchError::InvalidHexPattern(format!(
                "unexpected character {ch:?} at position {position}"
            )));
        }
    }

    if !nibbles.len().is_multiple_of(2) {
        return Err(SearchError::InvalidHexPattern(format!(
            "odd number of hex digits ({})",
            nibbles.len()
        )));
    }

    Ok(nibbles
        .chunks(2)
        .map(|pair| match (pair[0], pair[1]) {
            (HexNibble::Value(hi), HexNibble::Value(lo)) => ((hi << 4) | lo, 0xFF),
            (HexNibble::Value(hi), HexNibble::Wildcard) => (hi << 4, 0xF0),
            (HexNibble::Wildcard, HexNibble::Value(lo)) => (lo, 0x0F),
            (HexNibble::Wildcard, HexNibble::Wildcard) => (0x00, 0x00),
        })
        .collect())
}

/// Finds every occurrence of a hex pattern with optional `?` nibble wildcards.
///
/// # Errors
///
/// Returns `SearchError::InvalidHexPattern` for a character that is neither a
/// hex digit, a wildcard nor a separator, or for an odd number of digits.
pub fn search_hex_with_wildcards(
    data: &[u8],
    pattern_str: &str,
    max_results: usize,
) -> Result<Vec<SearchResult>, SearchError> {
    let pattern = parse_hex_pattern(pattern_str)?;

    if pattern.is_empty() || data.len() < pattern.len() {
        return Ok(Vec::new());
    }

    let plen = pattern.len();
    let has_wildcards = pattern.iter().any(|(_, mask)| *mask != 0xFF);

    if !has_wildcards {
        let exact: Vec<u8> = pattern.iter().map(|(v, _)| *v).collect();
        return Ok(search_bytes(data, &exact, max_results));
    }

    if data.len() <= CHUNK_SIZE {
        return Ok(search_masked_single(data, &pattern, max_results, 0));
    }

    let overlap = plen.saturating_sub(1);
    let mut chunks: Vec<(usize, &[u8])> = Vec::new();
    let mut start: usize = 0;
    while start < data.len() {
        let end = (start + CHUNK_SIZE + overlap).min(data.len());
        chunks.push((start, &data[start..end]));
        start += CHUNK_SIZE;
    }

    let mut all_results: Vec<SearchResult> = chunks
        .par_iter()
        .flat_map(|(chunk_offset, chunk)| {
            search_masked_single(chunk, &pattern, max_results, *chunk_offset)
        })
        .collect();

    all_results.sort_by_key(|r| r.offset);
    all_results.dedup_by_key(|r| r.offset);
    all_results.truncate(max_results);
    Ok(all_results)
}

fn search_masked_single(
    data: &[u8],
    pattern: &[(u8, u8)],
    max_results: usize,
    base_offset: usize,
) -> Vec<SearchResult> {
    let plen = pattern.len();
    if data.len() < plen {
        return Vec::new();
    }
    let mut results = Vec::new();

    for i in 0..=data.len() - plen {
        if results.len() >= max_results {
            break;
        }
        let matched = pattern
            .iter()
            .zip(&data[i..i + plen])
            .all(|((value, mask), byte)| byte & mask == value & mask);
        if matched {
            results.push(SearchResult {
                offset: base_offset + i,
                length: plen,
            });
        }
    }

    results
}

/// Finds every (overlapping) occurrence of `text` encoded as `encoding`.
///
/// This is [`crate::encodings::search_text_encoded`] returned as
/// [`SearchResult`]s, so the two entry points always report the same
/// matches. Case-insensitive matching decodes each candidate window and
/// compares it lowercased, at every byte offset (so UTF-16 text at an odd
/// offset is found in both modes). Text that cannot be represented in the
/// encoding matches nothing.
///
/// # Errors
///
/// Returns `SearchError::Encoding` if the encoding name is not recognized.
pub fn search_text(
    data: &[u8],
    text: &str,
    encoding: &str,
    case_sensitive: bool,
    max_results: usize,
) -> Result<Vec<SearchResult>, SearchError> {
    Ok(
        crate::encodings::search_text_encoded(data, text, encoding, case_sensitive, max_results)?
            .into_iter()
            .map(|(offset, length)| SearchResult { offset, length })
            .collect(),
    )
}

/// Finds non-overlapping matches of a byte-oriented regular expression.
///
/// The expression runs in byte mode (Unicode mode off), so `\xFF` matches the
/// raw byte `0xFF` and `.` matches any byte except `\n`, as a hex editor's
/// regex search must; `(?u)` re-enables Unicode classes inline. An empty
/// pattern matches nothing, like every other search mode, and zero-length
/// matches are skipped since they select no bytes.
///
/// # Errors
///
/// Returns `SearchError::InvalidRegex` if the pattern does not compile.
pub fn search_regex(
    data: &[u8],
    pattern: &str,
    max_results: usize,
) -> Result<Vec<SearchResult>, SearchError> {
    let re = regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .build()?;
    if pattern.is_empty() {
        return Ok(Vec::new());
    }
    Ok(re
        .find_iter(data)
        .filter(|m| !m.is_empty())
        .take(max_results)
        .map(|m| SearchResult {
            offset: m.start(),
            length: m.len(),
        })
        .collect())
}

/// Replaces every non-overlapping occurrence of `pattern`, left to right.
///
/// Returns the rewritten buffer and the number of replacements; an empty
/// pattern replaces nothing.
#[must_use]
pub fn replace_all(data: &[u8], pattern: &[u8], replacement: &[u8]) -> (Vec<u8>, usize) {
    if pattern.is_empty() {
        return (data.to_vec(), 0);
    }

    // Stream the non-overlapping leftmost matches rather than materializing a
    // record per match first: on a document full of one-byte patterns the match
    // list alone would dwarf the output and could exhaust memory before the
    // rewrite even begins. `find_iter` advances past each match by the needle
    // length, which is the same non-overlapping rule the match loop applied.
    let mut result = Vec::with_capacity(data.len());
    let mut last_end: usize = 0;
    let mut count: usize = 0;

    for offset in memchr::memmem::find_iter(data, pattern) {
        result.extend_from_slice(&data[last_end..offset]);
        result.extend_from_slice(replacement);
        last_end = offset + pattern.len();
        count += 1;
    }
    result.extend_from_slice(&data[last_end..]);

    (result, count)
}

/// The start of every non-overlapping occurrence of `pattern`, left to right,
/// as [`replace_all`] finds them, or `None` once there are more than `limit`.
///
/// The bound lets a caller decide that a list of offsets would cost more than
/// the alternative before the list has grown that large. An empty pattern has
/// no occurrences.
#[must_use]
pub fn match_offsets_within(data: &[u8], pattern: &[u8], limit: usize) -> Option<Vec<usize>> {
    if pattern.is_empty() {
        return Some(Vec::new());
    }
    let mut offsets = Vec::new();
    for offset in memchr::memmem::find_iter(data, pattern) {
        if offsets.len() == limit {
            return None;
        }
        offsets.push(offset);
    }
    Some(offsets)
}

fn decode_uint(bytes: &[u8], size: usize, big_endian: bool) -> u64 {
    let fold = |acc: u64, &b: &u8| (acc << 8) | u64::from(b);
    if big_endian {
        bytes[..size].iter().fold(0, fold)
    } else {
        bytes[..size].iter().rev().fold(0, fold)
    }
}

fn sign_extend(raw: u64, size: usize) -> i64 {
    let shift = 64 - 8 * u32::try_from(size).unwrap_or(8);
    (raw << shift).cast_signed() >> shift
}

/// Encodes `value` as a `size`-byte integer, or `None` when it is out of range
/// for that width and signedness (no such bytes can exist in the data).
fn encode_int_target(value: i64, size: usize, signed: bool, big_endian: bool) -> Option<Vec<u8>> {
    let bits = 8 * u32::try_from(size).ok()?;
    let raw = if signed {
        let min = i64::MIN >> (64 - bits);
        let max = i64::MAX >> (64 - bits);
        if !(min..=max).contains(&value) {
            return None;
        }
        value.cast_unsigned()
    } else {
        let uval = u64::try_from(value).ok()?;
        if bits < 64 && uval >> bits != 0 {
            return None;
        }
        uval
    };
    Some(if big_endian {
        raw.to_be_bytes()[8 - size..].to_vec()
    } else {
        raw.to_le_bytes()[..size].to_vec()
    })
}

fn validate_int_width(size: usize) -> Result<(), SearchError> {
    if (1..=8).contains(&size) {
        Ok(())
    } else {
        Err(SearchError::InvalidNumeric(format!(
            "integer width must be 1..=8 bytes, got {size}"
        )))
    }
}

/// Scans every `step`-aligned `size`-byte window and keeps those `pred`
/// accepts, in ascending offset order.
///
/// Positions are enumerated by index (`offset = index * step` with
/// `index < positions`), so no offset arithmetic can overflow even for an
/// alignment near `usize::MAX`. Inputs above 4 MiB are split by position
/// range and scanned in parallel, with the same result as the serial path.
fn scan_aligned(
    data: &[u8],
    size: usize,
    alignment: usize,
    max_results: usize,
    pred: impl Fn(&[u8]) -> bool + Sync,
) -> Vec<SearchResult> {
    if size == 0 || data.len() < size || max_results == 0 {
        return Vec::new();
    }
    let step = alignment.max(1);
    let positions = (data.len() - size) / step + 1;
    let hit = |index: usize| {
        let offset = index * step;
        pred(&data[offset..offset + size]).then_some(SearchResult {
            offset,
            length: size,
        })
    };

    if data.len() <= CHUNK_SIZE {
        return (0..positions).filter_map(hit).take(max_results).collect();
    }

    let per_chunk = (CHUNK_SIZE / step).max(1);
    let ranges: Vec<(usize, usize)> = (0..positions)
        .step_by(per_chunk)
        .map(|start| (start, (start + per_chunk).min(positions)))
        .collect();
    let mut results: Vec<SearchResult> = ranges
        .par_iter()
        .flat_map(|&(start, end)| {
            (start..end)
                .filter_map(hit)
                .take(max_results)
                .collect::<Vec<_>>()
        })
        .collect();
    results.sort_by_key(|r| r.offset);
    results.truncate(max_results);
    results
}

/// Finds `size`-byte integers equal to `value`.
///
/// `size` may be any width from 1 to 8 bytes. A `value` that does not fit the
/// width and signedness matches nothing.
///
/// # Errors
///
/// Returns `SearchError::InvalidNumeric` if `size` is outside `1..=8`.
pub fn search_numeric_int(
    data: &[u8],
    value: i64,
    size: usize,
    signed: bool,
    big_endian: bool,
    alignment: usize,
    max_results: usize,
) -> Result<Vec<SearchResult>, SearchError> {
    validate_int_width(size)?;
    let Some(target) = encode_int_target(value, size, signed, big_endian) else {
        return Ok(Vec::new());
    };
    Ok(scan_aligned(data, size, alignment, max_results, |window| {
        window == target.as_slice()
    }))
}

/// Finds 4- or 8-byte IEEE floats within `tolerance` of `value`.
///
/// Windows holding NaN or an infinity never match.
///
/// # Errors
///
/// Returns `SearchError::InvalidNumeric` if `size` is not 4 or 8, if `value`
/// is not finite, or if `tolerance` is negative or not finite (an infinite
/// tolerance would match every finite window).
pub fn search_numeric_float(
    data: &[u8],
    value: f64,
    size: usize,
    big_endian: bool,
    tolerance: f64,
    alignment: usize,
    max_results: usize,
) -> Result<Vec<SearchResult>, SearchError> {
    if size != 4 && size != 8 {
        return Err(SearchError::InvalidNumeric(format!(
            "float width must be 4 or 8 bytes, got {size}"
        )));
    }
    if !value.is_finite() {
        return Err(SearchError::InvalidNumeric(format!(
            "float value must be finite, got {value}"
        )));
    }
    if !tolerance.is_finite() || tolerance < 0.0 {
        return Err(SearchError::InvalidNumeric(format!(
            "tolerance must be finite and non-negative, got {tolerance}"
        )));
    }

    Ok(scan_aligned(data, size, alignment, max_results, |bytes| {
        let decoded = if size == 4 {
            let arr = [bytes[0], bytes[1], bytes[2], bytes[3]];
            f64::from(if big_endian {
                f32::from_be_bytes(arr)
            } else {
                f32::from_le_bytes(arr)
            })
        } else {
            let arr = [
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ];
            if big_endian {
                f64::from_be_bytes(arr)
            } else {
                f64::from_le_bytes(arr)
            }
        };
        decoded.is_finite() && (decoded - value).abs() <= tolerance
    }))
}

/// Finds `size`-byte integers in the inclusive range `min_val..=max_val`.
///
/// For an unsigned search the bounds are clamped to the non-negative values
/// they admit, so a range lying entirely below zero matches nothing.
///
/// # Errors
///
/// Returns `SearchError::InvalidNumeric` if `size` is outside `1..=8`.
pub fn search_numeric_range(
    data: &[u8],
    min_val: i64,
    max_val: i64,
    size: usize,
    signed: bool,
    big_endian: bool,
    alignment: usize,
    max_results: usize,
) -> Result<Vec<SearchResult>, SearchError> {
    validate_int_width(size)?;
    if min_val > max_val || (!signed && max_val < 0) {
        return Ok(Vec::new());
    }
    let min_u = u64::try_from(min_val).unwrap_or(0);
    let max_u = max_val.cast_unsigned();
    Ok(scan_aligned(data, size, alignment, max_results, |bytes| {
        let raw = decode_uint(bytes, size, big_endian);
        if signed {
            (min_val..=max_val).contains(&sign_extend(raw, size))
        } else {
            (min_u..=max_u).contains(&raw)
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encodings::Codec;

    #[test]
    fn test_search_bytes_exact() {
        let data = b"Hello World Hello";
        let results = search_bytes(data, b"Hello", 10);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].offset, 0);
        assert_eq!(results[1].offset, 12);
    }

    #[test]
    fn test_search_hex_wildcards_short_trailing_chunk() {
        let mut data = vec![0u8; CHUNK_SIZE + 2];
        data[100..105].copy_from_slice(&[0xAA, 0x11, 0xBB, 0xCC, 0xDD]);
        data[CHUNK_SIZE] = 0xAA;
        data[CHUNK_SIZE + 1] = 0x11;

        let results = search_hex_with_wildcards(&data, "AA ?? BB CC DD", 16).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 100);
    }

    #[test]
    fn test_search_bytes_no_match() {
        let data = b"Hello World";
        let results = search_bytes(data, b"xyz", 10);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_search_bytes_max_results() {
        let data = b"AAAA";
        let results = search_bytes(data, b"A", 2);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_search_hex_exact() {
        let data = vec![0x4D, 0x5A, 0x90, 0x00, 0x03];
        let results = search_hex_with_wildcards(&data, "4D 5A", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 0);
    }

    #[test]
    fn test_search_hex_wildcard() {
        let data = vec![0x4D, 0x5A, 0x90, 0x00, 0x4D, 0xFF, 0x90];
        let results = search_hex_with_wildcards(&data, "4D ?? 90", 10).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].offset, 0);
        assert_eq!(results[1].offset, 4);
    }

    #[test]
    fn test_search_hex_nibble_wildcard() {
        let data = vec![0xA0, 0xA1, 0xA2, 0xB0];
        let results = search_hex_with_wildcards(&data, "A?", 10).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_search_text_case_sensitive() {
        let data = b"Hello hello HELLO";
        let results = search_text(data, "Hello", "utf-8", true, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 0);
    }

    #[test]
    fn test_search_text_case_insensitive() {
        let data = b"Hello hello HELLO";
        let results = search_text(data, "hello", "utf-8", false, 10).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_search_text_case_insensitive_overlapping_matches() {
        // Case-insensitive overlap semantics must match the case-sensitive engine:
        // search_bytes(b"aaaa", b"aa", ..) legitimately returns [0, 1, 2].
        let results = search_text(b"aaaa", "aa", "utf-8", false, 10).unwrap();
        let found: Vec<usize> = results.iter().map(|r| r.offset).collect();
        assert_eq!(found, vec![0, 1, 2]);
    }

    #[test]
    fn test_search_text_mixed_case_needle() {
        let data = b"say hello world hello";
        let results = search_text(data, "HeLLo", "utf-8", false, 10).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].offset, 4);
        assert_eq!(results[1].offset, 16);
    }

    #[test]
    fn test_search_text_mixed_case_cyrillic_utf16le() {
        let target = "привет";
        let haystack: Vec<u8> = target.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let results = search_text(&haystack, "ПрИвЕт", "utf-16le", false, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 0);
        assert_eq!(results[0].length, haystack.len());
    }

    #[test]
    fn test_search_text_utf16le() {
        let text = "AB";
        let encoded: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut data = vec![0x00; 10];
        data.extend_from_slice(&encoded);
        data.extend_from_slice(&[0x00; 10]);

        let results = search_text(&data, "AB", "utf-16le", true, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 10);
    }

    #[test]
    fn test_search_regex_basic() {
        let data = b"test123 test456";
        let results = search_regex(data, r"test\d+", 10).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_search_regex_no_match() {
        let data = b"hello world";
        let results = search_regex(data, r"\d+", 10).unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_replace_all() {
        let data = b"AABAA";
        let (result, count) = replace_all(data, b"AA", b"X");
        assert_eq!(count, 2);
        assert_eq!(result, b"XBX".to_vec());
    }

    /// Every occurrence of a one-byte pattern in a dense buffer is replaced and
    /// counted exactly; the streaming rewrite must not skip adjacent matches.
    #[test]
    fn test_replace_all_rewrites_every_dense_occurrence() {
        let (result, count) = replace_all(&vec![0u8; 4096], &[0], &[0x90]);
        assert_eq!(count, 4096);
        assert_eq!(result, vec![0x90u8; 4096]);
    }

    #[test]
    fn test_replace_all_no_match() {
        let data = b"ABC";
        let (result, count) = replace_all(data, b"XY", b"Z");
        assert_eq!(count, 0);
        assert_eq!(result, data.to_vec());
    }

    #[test]
    fn test_replace_all_overlapping_matches_no_panic_or_abort() {
        // search_bytes(b"aaaa", b"aa", ..) legitimately returns overlapping matches
        // [0, 1, 2]; replace_all must only apply the non-overlapping ones ([0, 2])
        // rather than panicking on a reversed slice range.
        let (result, count) = replace_all(b"aaaa", b"aa", b"X");
        assert_eq!(count, 2);
        assert_eq!(result, b"XX".to_vec());
    }

    #[test]
    fn test_replace_all_overlapping_matches_shrinking_replacement_no_abort() {
        // A shrinking replacement on overlapping matches must not integer-underflow
        // a capacity computation (which would abort the whole process).
        let (result, count) = replace_all(b"aaaa", b"aa", b"");
        assert_eq!(count, 2);
        assert_eq!(result, b"".to_vec());
    }

    #[test]
    fn test_search_empty_pattern() {
        let data = b"Hello";
        let results = search_bytes(data, b"", 10);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_search_pattern_longer_than_data() {
        let data = b"Hi";
        let results = search_bytes(data, b"Hello World", 10);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_parse_hex_pattern_valid() {
        let result = parse_hex_pattern("4D 5A ?? 00").unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], (0x4D, 0xFF));
        assert_eq!(result[1], (0x5A, 0xFF));
        assert_eq!(result[2], (0x00, 0x00));
        assert_eq!(result[3], (0x00, 0xFF));
    }

    #[test]
    fn test_search_numeric_int_le() {
        let val: u32 = 0x1234_5678;
        let mut data = vec![0u8; 100];
        data[20..24].copy_from_slice(&val.to_le_bytes());
        data[50..54].copy_from_slice(&val.to_le_bytes());
        let results = search_numeric_int(&data, 0x1234_5678, 4, false, false, 1, 100).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].offset, 20);
        assert_eq!(results[1].offset, 50);
    }

    #[test]
    fn test_search_numeric_int_be() {
        let val: u32 = 0x1234_5678;
        let mut data = vec![0u8; 100];
        data[20..24].copy_from_slice(&val.to_be_bytes());
        let results = search_numeric_int(&data, 0x1234_5678, 4, false, true, 1, 100).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 20);
    }

    #[test]
    fn test_search_numeric_float() {
        let val: f32 = 1.234;
        let mut data = vec![0u8; 100];
        data[40..44].copy_from_slice(&val.to_le_bytes());
        let results = search_numeric_float(&data, 1.234, 4, false, 0.001, 1, 100).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 40);
    }

    #[test]
    fn test_search_numeric_range() {
        let mut data = vec![0u8; 100];
        data[0..4].copy_from_slice(&10u32.to_le_bytes());
        data[4..8].copy_from_slice(&20u32.to_le_bytes());
        data[8..12].copy_from_slice(&30u32.to_le_bytes());
        let results = search_numeric_range(&data, 15, 25, 4, false, false, 4, 100).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 4);
    }

    #[test]
    fn test_search_numeric_alignment() {
        let val: u16 = 0x1234;
        let mut data = vec![0u8; 100];
        data[3..5].copy_from_slice(&val.to_le_bytes());
        data[4..6].copy_from_slice(&val.to_le_bytes());
        let results = search_numeric_int(&data, 0x1234, 2, false, false, 2, 100).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 4);
    }

    #[test]
    fn test_search_numeric_signed() {
        let val: i32 = -1;
        let mut data = vec![0u8; 100];
        data[10..14].copy_from_slice(&val.to_le_bytes());
        let results = search_numeric_int(&data, -1, 4, true, false, 1, 100).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 10);
    }

    #[test]
    fn test_search_bytes_good_suffix() {
        let data = b"AAAABAAAABAAAAAB";
        let results = search_bytes(data, b"AAAAAB", 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 10);

        let data2 = b"ABCABCABCABC";
        let results2 = search_bytes(data2, b"ABCABC", 10);
        assert_eq!(results2.len(), 3);
        assert_eq!(results2[0].offset, 0);
        assert_eq!(results2[1].offset, 3);
        assert_eq!(results2[2].offset, 6);
    }

    fn buf_with(total: usize, fill: u8, pat: &[u8], offsets: &[usize]) -> Vec<u8> {
        let mut d = vec![fill; total];
        for &off in offsets {
            d[off..off + pat.len()].copy_from_slice(pat);
        }
        d
    }

    #[test]
    fn test_search_bytes_parallel_over_chunk_boundary() {
        // >4 MiB forces the rayon chunked path; one match straddles the CHUNK_SIZE seam.
        let pat = [0xDEu8, 0xAD, 0xBE, 0xEF, 0xCA];
        let total = CHUNK_SIZE + 300_000;
        let offsets = [100usize, CHUNK_SIZE - 2, CHUNK_SIZE + 50_000];
        let data = buf_with(total, 0x00, &pat, &offsets);
        let results = search_bytes(&data, &pat, 100);
        let found: Vec<usize> = results.iter().map(|r| r.offset).collect();
        assert_eq!(found, vec![100, CHUNK_SIZE - 2, CHUNK_SIZE + 50_000]);
        // dedup_by_key must collapse any boundary double-report to a single hit.
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_search_hex_wildcards_parallel_over_chunk() {
        // Wildcards keep it on the masked parallel path (not delegated to search_bytes).
        let total = CHUNK_SIZE + 200_000;
        let mut data = vec![0x11u8; total];
        // Matches for "DE AD ?? EF": 0xDE 0xAD <any> 0xEF
        for &off in &[500usize, CHUNK_SIZE + 1000] {
            data[off] = 0xDE;
            data[off + 1] = 0xAD;
            data[off + 2] = 0x77;
            data[off + 3] = 0xEF;
        }
        let results = search_hex_with_wildcards(&data, "DE AD ?? EF", 100).unwrap();
        let found: Vec<usize> = results.iter().map(|r| r.offset).collect();
        assert_eq!(found, vec![500, CHUNK_SIZE + 1000]);
    }

    /// The offsets of `results`, in order.
    fn offsets_of(results: &[SearchResult]) -> Vec<usize> {
        results.iter().map(|r| r.offset).collect()
    }

    /// Each parallel chunk keeps up to `max_results` matches, so the merged
    /// list is cut to the first `max_results` overall: three matches in the
    /// first chunk and one in the second return exactly the first two, for
    /// byte, wildcard and numeric searches alike.
    #[test]
    fn test_parallel_searches_truncate_to_max_results_in_offset_order() {
        let mut data = vec![0x11u8; CHUNK_SIZE + 100_000];
        for offset in [64, 1000, 2000, CHUNK_SIZE + 40] {
            data[offset..offset + 4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        }
        assert_eq!(
            offsets_of(&search_bytes(&data, &0xDEAD_BEEFu32.to_le_bytes(), 2)),
            vec![64, 1000]
        );
        assert_eq!(
            offsets_of(&search_hex_with_wildcards(&data, "EF ?? AD", 2).unwrap()),
            vec![64, 1000]
        );
        assert_eq!(
            offsets_of(&search_numeric_int(&data, 0xDEAD_BEEF, 4, false, false, 1, 2).unwrap()),
            vec![64, 1000]
        );
    }

    /// A match whose last byte is the last byte of a chunk's overlap is found
    /// once, at its exact offset, on both the exact and the masked path: the
    /// overlap must reach `pattern length - 1` bytes past the chunk.
    #[test]
    fn test_match_ending_on_the_last_overlap_byte_is_found() {
        let mut data = vec![0x11u8; CHUNK_SIZE + 100];
        data[CHUNK_SIZE - 1..CHUNK_SIZE + 4].copy_from_slice(&[0xDE, 0xAD, 0x77, 0xEF, 0xCA]);
        let exact = search_bytes(&data, &[0xDE, 0xAD, 0x77, 0xEF, 0xCA], 100);
        let masked = search_hex_with_wildcards(&data, "DE AD ?? EF", 100).unwrap();
        assert_eq!(
            exact
                .iter()
                .map(|r| (r.offset, r.length))
                .collect::<Vec<_>>(),
            vec![(CHUNK_SIZE - 1, 5)]
        );
        assert_eq!(
            masked
                .iter()
                .map(|r| (r.offset, r.length))
                .collect::<Vec<_>>(),
            vec![(CHUNK_SIZE - 1, 4)]
        );
    }

    /// Range bounds are inclusive at both ends, signed and unsigned: of the
    /// values 100, 1000, 99 and 1001 only the bounds match `100..=1000`, and of
    /// -5, 5, 6 and -6 only the bounds match `-5..=5`.
    #[test]
    fn test_search_numeric_range_bounds_are_inclusive() {
        let unsigned: Vec<u8> = [100u32, 1000, 99, 1001]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let signed: Vec<u8> = [-5i32, 5, 6, -6]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        assert_eq!(
            offsets_of(
                &search_numeric_range(&unsigned, 100, 1000, 4, false, false, 4, 10).unwrap()
            ),
            vec![0, 4]
        );
        assert_eq!(
            offsets_of(&search_numeric_range(&signed, -5, 5, 4, true, false, 4, 10).unwrap()),
            vec![0, 4]
        );
    }

    /// A float exactly `tolerance` away from the target matches: 1.5 against
    /// 1.0 with tolerance 0.5, all exact in binary.
    #[test]
    fn test_search_numeric_float_tolerance_bound_is_inclusive() {
        let mut data = vec![0x11u8; 16];
        data[4..8].copy_from_slice(&1.5f32.to_le_bytes());
        assert_eq!(
            offsets_of(&search_numeric_float(&data, 1.0, 4, false, 0.5, 4, 10).unwrap()),
            vec![4]
        );
    }

    #[test]
    fn test_search_numeric_int_parallel_over_chunk() {
        let total = CHUNK_SIZE + 100_000;
        let mut data = vec![0x11u8; total];
        let val: u32 = 0xDEAD_BEEF;
        data[64..68].copy_from_slice(&val.to_le_bytes());
        data[CHUNK_SIZE + 40..CHUNK_SIZE + 44].copy_from_slice(&val.to_le_bytes());
        let results = search_numeric_int(&data, 0xDEAD_BEEF, 4, false, false, 1, 100).unwrap();
        let found: Vec<usize> = results.iter().map(|r| r.offset).collect();
        assert_eq!(found, vec![64, CHUNK_SIZE + 40]);
    }

    #[test]
    fn test_search_numeric_float_parallel_over_chunk_f64_be() {
        let total = CHUNK_SIZE + 80_000;
        let mut data = vec![0x11u8; total];
        let val: f64 = 12_345.678_9;
        data[32..40].copy_from_slice(&val.to_be_bytes());
        data[CHUNK_SIZE + 8..CHUNK_SIZE + 16].copy_from_slice(&val.to_be_bytes());
        let results = search_numeric_float(&data, 12_345.678_9, 8, true, 1e-9, 8, 100).unwrap();
        let found: Vec<usize> = results.iter().map(|r| r.offset).collect();
        assert_eq!(found, vec![32, CHUNK_SIZE + 8]);
    }

    #[test]
    fn test_search_numeric_range_parallel_over_chunk() {
        let total = CHUNK_SIZE + 60_000;
        let mut data = vec![0x00u8; total];
        // value 500 (LE) is inside [100, 1000]; place at two positions.
        data[16..20].copy_from_slice(&500u32.to_le_bytes());
        data[CHUNK_SIZE + 4..CHUNK_SIZE + 8].copy_from_slice(&500u32.to_le_bytes());
        // A zero window (fill) decodes to 0, outside [100,1000]; must not match.
        let results = search_numeric_range(&data, 100, 1000, 4, false, false, 4, 100).unwrap();
        let found: Vec<usize> = results.iter().map(|r| r.offset).collect();
        assert_eq!(found, vec![16, CHUNK_SIZE + 4]);
    }

    #[test]
    fn test_parse_hex_pattern_odd_nibble_count_returns_none() {
        assert!(parse_hex_pattern("4D 5").is_err());
    }

    #[test]
    fn test_parse_hex_pattern_high_nibble_wildcard() {
        // "?A" -> low nibble 0xA known, high nibble wildcard -> (value 0x0A, mask 0x0F)
        let result = parse_hex_pattern("?A").unwrap();
        assert_eq!(result, vec![(0x0A, 0x0F)]);
    }

    #[test]
    fn test_parse_hex_pattern_empty_returns_empty_vec() {
        // Empty (and all-non-hex) input yields zero nibbles: 0 is even -> Some(empty).
        assert_eq!(parse_hex_pattern("").unwrap(), Vec::<(u8, u8)>::new());
        assert!(matches!(
            parse_hex_pattern("GG!!"),
            Err(SearchError::InvalidHexPattern(ref m)) if m == "unexpected character 'G' at position 0"
        ));
    }

    #[test]
    fn test_search_hex_empty_pattern_returns_empty() {
        // parse succeeds with an empty pattern -> guard returns no results.
        let results = search_hex_with_wildcards(b"anything", "", 10).unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_search_text_empty_text_returns_empty() {
        assert_eq!(
            search_text(b"data", "", "utf-8", true, 10).unwrap().len(),
            0
        );
    }

    #[test]
    fn test_search_text_utf16be_case_sensitive() {
        let encoded: Vec<u8> = "OK".encode_utf16().flat_map(u16::to_be_bytes).collect();
        let mut data = vec![0x00u8; 6];
        data.extend_from_slice(&encoded);
        let results = search_text(&data, "OK", "utf-16be", true, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 6);
    }

    #[test]
    fn test_search_text_windows1252_encoding_matches_real_bytes() {
        // "café" in windows-1252 is the 4 bytes 63 61 66 E9 (single-byte 'é' = 0xE9),
        // not the 5-byte UTF-8 encoding of the query text.
        let mut data = vec![0u8; 4];
        data.extend_from_slice(&[0x63, 0x61, 0x66, 0xE9]);
        data.extend_from_slice(&[0u8; 4]);
        let results = search_text(&data, "café", "windows-1252", true, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 4);
        assert_eq!(results[0].length, 4);
    }

    #[test]
    fn test_search_text_ci_data_shorter_than_needle_returns_empty() {
        // Case-insensitive branch: data.len() < encoded.len() -> early empty.
        let results = search_text(b"ab", "abcdef", "utf-8", false, 10).unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_window_matches_ignore_case_utf16be() {
        let window: Vec<u8> = "AB".encode_utf16().flat_map(u16::to_be_bytes).collect();
        assert!(Codec::resolve("utf-16be")
            .unwrap()
            .window_matches_ignore_case(&window, "ab"));
    }

    #[test]
    fn test_window_matches_ignore_case_odd_length_utf16_rejected() {
        assert!(!Codec::resolve("utf-16le")
            .unwrap()
            .window_matches_ignore_case(&[0x41], "a"));
        assert!(!Codec::resolve("utf-16be")
            .unwrap()
            .window_matches_ignore_case(&[0x41], "a"));
    }

    #[test]
    fn test_window_matches_ignore_case_invalid_utf16_rejected() {
        // Lone high surrogate D800 (LE bytes 0x00,0xD8) is invalid UTF-16.
        assert!(!Codec::resolve("utf-16le")
            .unwrap()
            .window_matches_ignore_case(&[0x00, 0xD8], "x"));
        assert!(!Codec::resolve("utf-16be")
            .unwrap()
            .window_matches_ignore_case(&[0xD8, 0x00], "x"));
    }

    #[test]
    fn test_window_matches_ignore_case_invalid_utf8_rejected() {
        assert!(!Codec::resolve("utf-8")
            .unwrap()
            .window_matches_ignore_case(&[0xFF, 0xFE], "x"));
    }

    #[test]
    fn test_window_matches_ignore_case_ascii_high_bit_rejected_and_valid_accepted() {
        assert!(!Codec::resolve("ascii")
            .unwrap()
            .window_matches_ignore_case(&[0x80], "x"));
        assert!(Codec::resolve("ascii")
            .unwrap()
            .window_matches_ignore_case(b"AB", "ab"));
    }

    #[test]
    fn test_window_matches_ignore_case_encoding_rs_fallback_windows1252_and_latin1() {
        // 0xC9 is 'É' in windows-1252/latin1; lowercased 'é'.
        assert!(Codec::resolve("windows-1252")
            .unwrap()
            .window_matches_ignore_case(&[0xC9], "é"));
        assert!(Codec::resolve("latin1")
            .unwrap()
            .window_matches_ignore_case(&[0xC9], "é"));
    }

    #[test]
    fn test_window_matches_ignore_case_encoding_rs_had_errors_rejected() {
        // Lone Shift_JIS lead byte 0x81 cannot decode -> had_errors -> reject.
        assert!(!Codec::resolve("shift_jis")
            .unwrap()
            .window_matches_ignore_case(&[0x81], "x"));
    }

    #[test]
    fn test_window_matches_ignore_case_unknown_label_rejected() {
        assert!(Codec::resolve("no-such-encoding-xyz").is_err());
    }

    /// An invalid regex must return an error rather than no matches, so a typo
    /// is not shown to the user as "0 matches" with the compile error discarded.
    #[test]
    fn test_search_regex_invalid_pattern_is_typed_error() {
        assert!(matches!(
            search_regex(b"data", "[unclosed", 10),
            Err(SearchError::InvalidRegex(_))
        ));
    }

    /// The regex must run in byte mode: in Unicode mode `\xFF` means U+00FF
    /// (bytes C3 BF) and `.` never matches a byte >= 0x80, but a hex editor's
    /// regex must address raw bytes.
    #[test]
    fn test_search_regex_is_byte_oriented() {
        let offsets = |pattern: &str| -> Vec<usize> {
            search_regex(&[0xFF, 0x41, 0xC3, 0xBF], pattern, 10)
                .unwrap()
                .iter()
                .map(|r| r.offset)
                .collect()
        };
        assert_eq!(offsets(r"\xFF"), vec![0]);
        assert_eq!(offsets("."), vec![0, 1, 2, 3]);
        assert_eq!(offsets("(?u)\u{FF}"), vec![2]);
    }

    /// An empty regex must not match the empty string at every offset, which
    /// would flood the results with zero-length hits.
    #[test]
    fn test_search_regex_empty_and_zero_length_matches_suppressed() {
        assert_eq!(search_regex(b"abc", "", 10).unwrap().len(), 0);
        let starred: Vec<(usize, usize)> = search_regex(b"xaax", "a*", 10)
            .unwrap()
            .iter()
            .map(|r| (r.offset, r.length))
            .collect();
        assert_eq!(starred, vec![(1, 2)]);
    }

    /// The hex parser must reject characters that are not hex digits, `?` or
    /// separators instead of dropping them. Dropping them made `"0x4D 0x5A"`
    /// search for `04 D0 5A` and report hits on the wrong bytes.
    #[test]
    fn test_search_hex_rejects_garbage_instead_of_searching_wrong_bytes() {
        assert!(matches!(
            search_hex_with_wildcards(&[0x04, 0xD0, 0x5A], "0x4D 0x5A", 10),
            Err(SearchError::InvalidHexPattern(ref m)) if m == "unexpected character 'x' at position 1"
        ));
        assert_eq!(
            search_hex_with_wildcards(&[0x4D, 0x5A, 0x90], "4d_5a:9?", 10)
                .unwrap()
                .iter()
                .map(|r| (r.offset, r.length))
                .collect::<Vec<_>>(),
            vec![(0, 3)]
        );
    }

    /// The serial numeric scan must advance with a checked addition. An unchecked
    /// `offset += step` overflows for an alignment near `usize::MAX` (a
    /// `PanicException` from Python), while the parallel path does not.
    #[test]
    fn test_search_numeric_huge_alignment_does_not_overflow() {
        let hits = |r: Vec<SearchResult>| -> Vec<(usize, usize)> {
            r.iter().map(|m| (m.offset, m.length)).collect()
        };
        assert_eq!(
            hits(search_numeric_int(&[0u8; 16], 0, 4, false, false, usize::MAX, 10).unwrap()),
            vec![(0, 4)]
        );
        assert_eq!(
            hits(search_numeric_float(&[0u8; 16], 0.0, 4, false, 0.0, usize::MAX, 10).unwrap()),
            vec![(0, 4)]
        );
        assert_eq!(
            hits(search_numeric_range(&[0u8; 16], 0, 0, 4, false, false, usize::MAX, 10).unwrap()),
            vec![(0, 4)]
        );
    }

    /// An unsigned range whose bounds are both negative matches nothing, since
    /// no unsigned value is negative.
    #[test]
    fn test_search_numeric_range_unsigned_all_negative_is_empty() {
        assert_eq!(
            search_numeric_range(&[0u8; 4], -10, -1, 1, false, false, 1, 10)
                .unwrap()
                .len(),
            0
        );
        let signed: Vec<usize> =
            search_numeric_range(&[0xFF, 0x00], -10, -1, 1, true, false, 1, 10)
                .unwrap()
                .iter()
                .map(|r| r.offset)
                .collect();
        assert_eq!(signed, vec![0]);
    }

    /// Integer search must match widths 5-7, which `search_numeric_range` decodes,
    /// so the same bytes are found by both entry points.
    #[test]
    fn test_search_numeric_int_odd_widths_match() {
        let found = |size: usize, be: bool, data: &[u8]| -> Vec<usize> {
            search_numeric_int(data, 1, size, false, be, 1, 10)
                .unwrap()
                .iter()
                .map(|r| r.offset)
                .collect()
        };
        assert_eq!(found(5, false, &[1, 0, 0, 0, 0]), vec![0]);
        assert_eq!(found(6, true, &[0, 0, 0, 0, 0, 1]), vec![0]);
        assert_eq!(found(7, false, &[9, 1, 0, 0, 0, 0, 0, 0]), vec![1]);
    }

    /// `"utf-16"` must not fall through to `encoding_rs`, whose UTF-16 encoder
    /// emits UTF-8, so the needle `AB` would search for `41 42`.
    #[test]
    fn test_search_text_utf16_alias_searches_utf16_bytes() {
        let data = [0x41, 0x00, 0x42, 0x00];
        assert_eq!(
            search_text(&data, "AB", "utf-16", true, 10)
                .unwrap()
                .iter()
                .map(|r| (r.offset, r.length))
                .collect::<Vec<_>>(),
            vec![(0, 4)]
        );
    }

    /// Case-insensitive UTF-16 search must not step two bytes at a time, which
    /// would miss text at odd offsets that case-sensitive search finds.
    #[test]
    fn test_search_text_utf16_case_insensitive_odd_offset() {
        let data = [0x00, 0x41, 0x00, 0x42, 0x00];
        assert_eq!(
            search_text(&data, "ab", "utf-16le", false, 10)
                .unwrap()
                .iter()
                .map(|r| (r.offset, r.length))
                .collect::<Vec<_>>(),
            vec![(1, 4)]
        );
    }

    /// An unknown encoding must return an error instead of no matches, as
    /// `decode_text`/`encode_text` do for the same name.
    #[test]
    fn test_search_text_unknown_encoding_is_typed_error() {
        assert!(matches!(
            search_text(b"x", "x", "no-such-encoding", true, 10),
            Err(SearchError::Encoding(EncodingError::UnsupportedEncoding(_)))
        ));
    }

    #[test]
    fn test_search_regex_max_results_break() {
        let data = b"a a a a a";
        let results = search_regex(data, "a", 2).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_replace_all_empty_pattern_returns_copy_and_zero() {
        let (out, count) = replace_all(b"abc", b"", b"z");
        assert_eq!(out, b"abc".to_vec());
        assert_eq!(count, 0);
    }

    #[test]
    fn test_decode_uint_all_sizes_and_endianness() {
        assert_eq!(decode_uint(&[0xAB], 1, false), 0xAB);
        assert_eq!(decode_uint(&[0x12, 0x34], 2, false), 0x3412);
        assert_eq!(decode_uint(&[0x12, 0x34], 2, true), 0x1234);
        assert_eq!(decode_uint(&[0x12, 0x34, 0x56], 3, false), 0x0056_3412);
        assert_eq!(decode_uint(&[0x12, 0x34, 0x56], 3, true), 0x0012_3456);
        assert_eq!(decode_uint(&[1, 2, 3, 4], 4, false), 0x0403_0201);
        assert_eq!(decode_uint(&[1, 2, 3, 4], 4, true), 0x0102_0304);
        let eight = [1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(decode_uint(&eight, 8, true), 0x0102_0304_0506_0708);
        assert_eq!(decode_uint(&eight, 8, false), 0x0807_0605_0403_0201);
        // Widths 5/6/7 are genuinely decoded (not silently zeroed).
        assert_eq!(decode_uint(&[1, 2, 3, 4, 5], 5, false), 0x05_0403_0201);
        assert_eq!(decode_uint(&[1, 2, 3, 4, 5], 5, true), 0x01_0203_0405);
        assert_eq!(decode_uint(&[1, 2, 3, 4, 5, 6], 6, false), 0x0605_0403_0201);
        assert_eq!(decode_uint(&[1, 2, 3, 4, 5, 6], 6, true), 0x0102_0304_0506);
        assert_eq!(
            decode_uint(&[1, 2, 3, 4, 5, 6, 7], 7, false),
            0x0007_0605_0403_0201
        );
        assert_eq!(
            decode_uint(&[1, 2, 3, 4, 5, 6, 7], 7, true),
            0x0001_0203_0405_0607
        );
    }

    #[test]
    fn test_sign_extend_all_sizes() {
        assert_eq!(sign_extend(0xFF, 1), -1);
        assert_eq!(sign_extend(0x7F, 1), 127);
        assert_eq!(sign_extend(0xFFFF, 2), -1);
        assert_eq!(sign_extend(0xFF_FFFF, 3), -1);
        assert_eq!(sign_extend(0x80_0000, 3), -8_388_608);
        assert_eq!(sign_extend(0xFFFF_FFFF, 4), -1);
        assert_eq!(sign_extend(u64::MAX, 8), -1);
        // Widths 5/6/7 are genuinely sign-extended from their own top bit.
        assert_eq!(sign_extend(0xFF_FFFF_FFFF, 5), -1);
        assert_eq!(sign_extend(0x80_0000_0000, 5), -549_755_813_888);
        assert_eq!(sign_extend(0x7F_FFFF_FFFF, 5), 549_755_813_887);
        assert_eq!(sign_extend(0xFFFF_FFFF_FFFF, 6), -1);
        assert_eq!(sign_extend(0x8000_0000_0000, 6), -140_737_488_355_328);
        assert_eq!(sign_extend(0xFF_FFFF_FFFF_FFFF, 7), -1);
        assert_eq!(sign_extend(0x80_0000_0000_0000, 7), -36_028_797_018_963_968);
    }

    #[test]
    fn test_encode_int_target_unsigned_widths_and_overflow() {
        assert_eq!(encode_int_target(200, 1, false, false), Some(vec![200]));
        assert_eq!(encode_int_target(256, 1, false, false), None);
        assert_eq!(encode_int_target(-1, 1, false, false), None);
        assert_eq!(
            encode_int_target(0x1234, 2, false, true),
            Some(vec![0x12, 0x34])
        );
        assert_eq!(
            encode_int_target(0x1234, 2, false, false),
            Some(vec![0x34, 0x12])
        );
        assert_eq!(encode_int_target(0x1_0000, 2, false, false), None);
        assert_eq!(
            encode_int_target(0x0012_3456, 3, false, true),
            Some(vec![0x12, 0x34, 0x56])
        );
        assert_eq!(
            encode_int_target(0x0012_3456, 3, false, false),
            Some(vec![0x56, 0x34, 0x12])
        );
        assert_eq!(encode_int_target(0x0100_0000, 3, false, false), None);
        assert_eq!(encode_int_target(0x1_0000_0000, 4, false, false), None);
        assert_eq!(
            encode_int_target(0xABCD, 4, false, true),
            Some(vec![0x00, 0x00, 0xAB, 0xCD])
        );
        assert_eq!(
            encode_int_target(1, 8, false, true),
            Some(vec![0, 0, 0, 0, 0, 0, 0, 1])
        );
        // Unsupported width -> None.
        assert_eq!(
            encode_int_target(1, 5, false, false),
            Some(vec![1, 0, 0, 0, 0])
        );
    }

    #[test]
    fn test_encode_int_target_signed_widths_and_overflow() {
        assert_eq!(encode_int_target(-1, 1, true, false), Some(vec![0xFF]));
        assert_eq!(encode_int_target(200, 1, true, false), None);
        assert_eq!(encode_int_target(-1, 2, true, true), Some(vec![0xFF, 0xFF]));
        assert_eq!(
            encode_int_target(8_388_607, 3, true, false).unwrap().len(),
            3
        );
        assert_eq!(encode_int_target(8_388_608, 3, true, false), None);
        assert_eq!(
            encode_int_target(-8_388_608, 3, true, false).unwrap().len(),
            3
        );
        assert_eq!(encode_int_target(-8_388_609, 3, true, false), None);
        assert_eq!(
            encode_int_target(-1, 4, true, false),
            Some(vec![0xFF, 0xFF, 0xFF, 0xFF])
        );
        assert_eq!(encode_int_target(-1, 8, true, true), Some(vec![0xFF; 8]));
        assert_eq!(
            encode_int_target(-2, 7, true, false),
            Some(vec![0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        );
        assert_eq!(encode_int_target(1 << 55, 7, true, false), None);
    }

    #[test]
    fn test_search_numeric_int_size_guards_and_encode_none() {
        assert!(matches!(
            search_numeric_int(b"abcd", 1, 0, false, false, 1, 10),
            Err(SearchError::InvalidNumeric(_))
        ));
        assert!(matches!(
            search_numeric_int(b"abcd", 1, 9, false, false, 1, 10),
            Err(SearchError::InvalidNumeric(_))
        ));
        assert_eq!(
            search_numeric_int(b"a", 1, 4, false, false, 1, 10)
                .unwrap()
                .len(),
            0
        );
        // value 256 does not fit in 1 unsigned byte -> encode returns None -> empty.
        assert_eq!(
            search_numeric_int(b"abcd", 256, 1, false, false, 1, 10)
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn test_search_numeric_int_size3_and_size8_small_path() {
        let mut data = vec![0x00u8; 32];
        // 24-bit value 0x0056_3412 little-endian == bytes 12 34 56
        data[4..7].copy_from_slice(&[0x12, 0x34, 0x56]);
        let r3 = search_numeric_int(&data, 0x0056_3412, 3, false, false, 1, 10).unwrap();
        assert_eq!(r3.iter().map(|r| r.offset).collect::<Vec<_>>(), vec![4]);
        let v: u64 = 0x0102_0304_0506_0708;
        data[8..16].copy_from_slice(&v.to_le_bytes());
        let r8 = search_numeric_int(&data, v.cast_signed(), 8, false, false, 1, 10).unwrap();
        assert_eq!(r8.iter().map(|r| r.offset).collect::<Vec<_>>(), vec![8]);
    }

    #[test]
    fn test_search_numeric_float_size_guard_and_non_finite_skip() {
        // size 2 is invalid for float search, as are non-finite values and tolerances.
        assert!(matches!(
            search_numeric_float(b"abcdef", 1.0, 2, false, 0.0, 1, 10),
            Err(SearchError::InvalidNumeric(_))
        ));
        assert!(matches!(
            search_numeric_float(b"abcdef", 1.0, 4, false, f64::INFINITY, 1, 10),
            Err(SearchError::InvalidNumeric(ref m)) if m == "tolerance must be finite and non-negative, got inf"
        ));
        assert!(matches!(
            search_numeric_float(b"abcdef", f64::NAN, 4, false, 0.0, 1, 10),
            Err(SearchError::InvalidNumeric(_))
        ));
        // An f32 +inf window must be skipped (non-finite guard); a real 5.0 must match.
        let mut data = vec![0x11u8; 64];
        data[8..12].copy_from_slice(&[0x00, 0x00, 0x80, 0x7F]); // f32 +inf LE
        data[20..24].copy_from_slice(&5.0f32.to_le_bytes());
        let results = search_numeric_float(&data, 5.0, 4, false, 0.001, 1, 10).unwrap();
        let found: Vec<usize> = results.iter().map(|r| r.offset).collect();
        assert_eq!(found, vec![20]);
    }

    #[test]
    fn test_search_numeric_range_signed_negative_small_path() {
        let mut data = vec![0x00u8; 32];
        data[4..8].copy_from_slice(&(-50i32).to_le_bytes());
        data[8..12].copy_from_slice(&25i32.to_le_bytes());
        // range [-100, -1] signed matches only the -50 window (zero-fill windows decode to 0).
        let results = search_numeric_range(&data, -100, -1, 4, true, false, 4, 10).unwrap();
        let found: Vec<usize> = results.iter().map(|r| r.offset).collect();
        assert_eq!(found, vec![4]);
    }

    #[test]
    fn test_search_numeric_range_five_byte_width_no_spurious_matches() {
        // All-0xFF filler: a buggy 5-byte decode that silently falls back to 0 would
        // report a match at EVERY offset since 0 is inside [0, 100]. Real decoding
        // must reject the filler and find only the planted 5-byte LE value 50.
        let mut data = vec![0xFFu8; 64];
        data[10..15].copy_from_slice(&[50, 0, 0, 0, 0]);
        let results = search_numeric_range(&data, 0, 100, 5, false, false, 1, 1000).unwrap();
        let found: Vec<usize> = results.iter().map(|r| r.offset).collect();
        assert_eq!(found, vec![10]);
    }

    #[test]
    fn test_search_numeric_range_unsigned_u64_large_values_not_falsely_matched() {
        // A true u64 value above i64::MAX must not be lossily clamped into matching
        // a range capped at i64::MAX; only the genuinely in-range value matches.
        let mut data = vec![0u8; 32];
        data[0..8].copy_from_slice(&5000u64.to_le_bytes());
        data[8..16].copy_from_slice(&0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes());
        let results = search_numeric_range(&data, 1000, i64::MAX, 8, false, false, 8, 100).unwrap();
        let found: Vec<usize> = results.iter().map(|r| r.offset).collect();
        assert_eq!(found, vec![0]);
    }
}
