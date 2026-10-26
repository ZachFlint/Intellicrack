// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Zachary Flint
//
// This file is part of Intellicrack. See LICENSE for details.

//! Byte statistics: Shannon entropy over the whole buffer or per block, byte
//! and byte-pair distributions, byte classes and per-block content
//! classification. Large inputs are counted in parallel.

use rayon::prelude::*;

/// Inputs at least this long are split across the rayon pool.
const PARALLEL_THRESHOLD: usize = 1024 * 1024;

/// Shannon entropy of `data` in bits per byte, in `0.0..=8.0`.
///
/// Empty input yields `0.0`; a buffer of one repeated byte yields exactly
/// `0.0` and a buffer holding every byte value equally often exactly `8.0`.
#[must_use]
pub fn compute_entropy(data: &[u8]) -> f64 {
    entropy_from_counts(&byte_distribution(data), data.len())
}

/// Shannon entropy of a byte histogram over `len` bytes.
fn entropy_from_counts(counts: &[u64; 256], len: usize) -> f64 {
    if len == 0 {
        return 0.0;
    }
    let len_u64: u64 = len.try_into().unwrap_or(u64::MAX);
    let total = u64_to_f64(len_u64);
    let mut entropy = 0.0;
    for &count in counts {
        if count > 0 {
            let p = u64_to_f64(count) / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn u64_to_f64(val: u64) -> f64 {
    let bytes = val.to_le_bytes();
    let lower = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let upper = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    f64::from(upper) * 4_294_967_296.0 + f64::from(lower)
}

/// Entropy of each consecutive `block_size`-byte block, the last block
/// possibly shorter. Empty input or a zero `block_size` yields no blocks.
#[must_use]
pub fn entropy_map(data: &[u8], block_size: usize) -> Vec<f64> {
    if data.is_empty() || block_size == 0 {
        return Vec::new();
    }
    data.par_chunks(block_size).map(compute_entropy).collect()
}

/// Occurrences of each byte value, indexed by value.
#[must_use]
pub fn byte_distribution(data: &[u8]) -> [u64; 256] {
    if data.len() < PARALLEL_THRESHOLD {
        let mut counts = [0u64; 256];
        for &b in data {
            counts[usize::from(b)] += 1;
        }
        counts
    } else {
        byte_distribution_chunked(data, parallel_chunk_size(data.len()))
    }
}

/// The chunk size the parallel counters split `len` bytes into: one chunk per
/// rayon thread, but never under 64 KiB.
fn parallel_chunk_size(len: usize) -> usize {
    (len / rayon::current_num_threads()).max(65536)
}

/// [`byte_distribution`] counted over `chunk_size`-byte chunks in parallel and
/// merged.
fn byte_distribution_chunked(data: &[u8], chunk_size: usize) -> [u64; 256] {
    let chunk_counts: Vec<[u64; 256]> = data
        .par_chunks(chunk_size)
        .map(|chunk| {
            let mut local = [0u64; 256];
            for &b in chunk {
                local[usize::from(b)] += 1;
            }
            local
        })
        .collect();

    let mut merged = [0u64; 256];
    for counts in chunk_counts {
        for (total, count) in merged.iter_mut().zip(counts) {
            *total += count;
        }
    }
    merged
}

/// Counts of `(null, printable, control, high)` bytes, in [`byte_class`]
/// tag order.
#[must_use]
pub fn byte_type_distribution(data: &[u8]) -> (u64, u64, u64, u64) {
    let mut counts = [0u64; BYTE_CLASS_COUNT];
    for &b in data {
        counts[usize::from(byte_class(b))] += 1;
    }
    (counts[0], counts[1], counts[2], counts[3])
}

/// A byte that is exactly zero.
pub const BYTE_CLASS_NULL: u8 = 0;
/// A byte in the printable ASCII range.
pub const BYTE_CLASS_PRINTABLE: u8 = 1;
/// A C0 control byte, or delete.
pub const BYTE_CLASS_CONTROL: u8 = 2;
/// A byte with the high bit set.
pub const BYTE_CLASS_HIGH: u8 = 3;
/// How many classes [`byte_class`] can return.
pub const BYTE_CLASS_COUNT: usize = 4;

/// Classify one byte.
///
/// The returned tag is the index of that class within
/// [`byte_type_distribution`]'s tuple, which is the single definition of these
/// four ranges; a caller tinting bytes and a caller counting them therefore
/// cannot disagree.
#[must_use]
pub fn byte_class(byte: u8) -> u8 {
    match byte {
        0x00 => BYTE_CLASS_NULL,
        0x20..=0x7E => BYTE_CLASS_PRINTABLE,
        0x01..=0x1F | 0x7F => BYTE_CLASS_CONTROL,
        0x80..=0xFF => BYTE_CLASS_HIGH,
    }
}

/// Classify every byte in `data`, one tag per byte.
#[must_use]
pub fn classify_bytes(data: &[u8]) -> Vec<u8> {
    data.iter().copied().map(byte_class).collect()
}

/// Counts of every adjacent byte pair, as a 256x256 row-major grid.
///
/// Entry `a * 256 + b` counts positions `i` with `data[i] == a` and
/// `data[i + 1] == b`. Large inputs are split into chunks that overlap by one
/// byte, so each pair spanning a chunk seam is counted exactly once.
#[must_use]
pub fn digram_matrix(data: &[u8]) -> Vec<u64> {
    if data.len() < PARALLEL_THRESHOLD {
        return count_pairs(data);
    }
    digram_matrix_chunked(data, parallel_chunk_size(data.len()))
}

/// The digram grid of one slice; see [`digram_matrix`].
fn count_pairs(chunk: &[u8]) -> Vec<u64> {
    let mut matrix = vec![0u64; 65536];
    for window in chunk.windows(2) {
        matrix[usize::from(window[0]) * 256 + usize::from(window[1])] += 1;
    }
    matrix
}

/// [`digram_matrix`] counted over `chunk_size`-byte chunks in parallel, each
/// extended one byte into the next so the pair across every seam is counted
/// by exactly one chunk.
fn digram_matrix_chunked(data: &[u8], chunk_size: usize) -> Vec<u64> {
    let chunks: Vec<&[u8]> = (0..data.len())
        .step_by(chunk_size)
        .map(|start| &data[start..(start + chunk_size + 1).min(data.len())])
        .collect();

    let mut merged = vec![0u64; 65536];
    for matrix in chunks
        .par_iter()
        .map(|chunk| count_pairs(chunk))
        .collect::<Vec<_>>()
    {
        for (total, count) in merged.iter_mut().zip(matrix) {
            *total += count;
        }
    }
    merged
}

/// Coarse content category of each `block_size`-byte block.
///
/// The codes are:
///
/// * `0` — null-heavy: entropy below 0.5 and more than 90% zero bytes;
/// * `1` — text: entropy below 4.5 and more than 70% printable ASCII;
/// * `2` — structured/other: anything not matched by another rule;
/// * `3` — high entropy: above 7.0 bits per byte (compressed or encrypted);
/// * `4` — mixed entropy: 4.5 to 7.0 bits per byte inclusive.
///
/// A block of `n` bytes can reach at most `log2(min(n, 256))` bits, so blocks
/// of 128 bytes or fewer never classify as `3`, and blocks shorter than 23
/// bytes never as `4`; use blocks of at least 256 bytes for entropy work.
#[must_use]
pub fn content_classification(data: &[u8], block_size: usize) -> Vec<u8> {
    if data.is_empty() || block_size == 0 {
        return Vec::new();
    }
    data.par_chunks(block_size).map(classify_block).collect()
}

fn classify_block(block: &[u8]) -> u8 {
    if block.is_empty() {
        return 0;
    }

    let counts = byte_distribution(block);
    let null_count = counts[0];
    let printable_count: u64 = counts[0x20..=0x7E].iter().sum();
    let block_len_u64: u64 = block.len().try_into().unwrap_or(u64::MAX);
    let total = u64_to_f64(block_len_u64);
    let null_ratio = u64_to_f64(null_count) / total;
    let printable_ratio = u64_to_f64(printable_count) / total;

    let entropy = entropy_from_counts(&counts, block.len());

    if entropy < 0.5 && null_ratio > 0.9 {
        return 0;
    }
    if entropy < 4.5 && printable_ratio > 0.7 {
        return 1;
    }
    if entropy > 7.0 {
        return 3;
    }
    if (4.5..=7.0).contains(&entropy) {
        return 4;
    }
    2
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact bits of `value`, so a float result is compared exactly.
    fn bits(value: f64) -> u64 {
        value.to_bits()
    }

    #[test]
    fn test_entropy_of_a_constant_buffer_is_exactly_zero() {
        let data = vec![0x42u8; 1000];
        assert_eq!(bits(compute_entropy(&data)), bits(0.0));
    }

    /// Each of the 256 values has p = 1/256 exactly, so the sum is exactly 8.
    #[test]
    fn test_entropy_of_a_byte_ramp_is_exactly_eight() {
        let mut data = vec![0u8; 256 * 100];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i.to_le_bytes()[0];
        }
        assert_eq!(bits(compute_entropy(&data)), bits(8.0));
    }

    #[test]
    fn test_entropy_empty() {
        assert_eq!(bits(compute_entropy(&[])), bits(0.0));
    }

    #[test]
    fn test_entropy_map_blocks() {
        let mut data = vec![0u8; 2048];
        for b in &mut data[1024..] {
            *b = 0xFF;
        }
        let map = entropy_map(&data, 1024);
        assert_eq!(
            map.iter().copied().map(bits).collect::<Vec<_>>(),
            vec![bits(0.0); 2]
        );
    }

    #[test]
    fn test_entropy_map_last_partial_block_exact() {
        let mut data = vec![0u8; 2048];
        data.extend_from_slice(&[0x41, 0x42]);
        let map = entropy_map(&data, 1024);
        assert_eq!(map.len(), 3);
        assert_eq!(bits(map[0]), bits(0.0));
        assert_eq!(bits(map[2]), bits(1.0), "tail entropy {}", map[2]);
        assert_eq!(content_classification(&data, 1024), vec![0, 0, 1]);
    }

    #[test]
    fn test_classify_block_band_edges_are_exact() {
        // 128 symbols x 32 each: entropy exactly 7.0, which is in band 4, not 3.
        let seven: Vec<u8> = (0..128u8).cycle().take(4096).collect();
        assert_eq!(classify_block(&seven), 4);
        // 64 symbols at p = 1/128 plus two at p = 1/4: entropy exactly 4.5,
        // printable ratio 1.0, so arm 1 (`< 4.5`) must not claim it.
        let mut four_and_half: Vec<u8> = (0x20..=0x5Fu8).cycle().take(256).collect();
        four_and_half.extend(std::iter::repeat_n(b'a', 128));
        four_and_half.extend(std::iter::repeat_n(b'b', 128));
        assert_eq!(classify_block(&four_and_half), 4);
    }

    /// The null arm needs strictly more than 90% zeros: 900 zeros and 100
    /// `A`s (ratio exactly 0.9, entropy 0.469) fall through to class 2, and
    /// one more zero makes the block class 0.
    #[test]
    fn test_classify_block_null_arm_is_strict_above_ninety_percent() {
        let mut at_threshold = vec![0u8; 900];
        at_threshold.extend([b'A'; 100]);
        let mut above = vec![0u8; 901];
        above.extend([b'A'; 99]);
        assert_eq!(classify_block(&at_threshold), 2);
        assert_eq!(classify_block(&above), 0);
    }

    /// The printable arm needs strictly more than 70% printable bytes: 700
    /// `A`s and 300 `0x80`s (ratio exactly 0.7, entropy 0.881) fall through to
    /// class 2, and one more `A` makes the block class 1.
    #[test]
    fn test_classify_block_printable_arm_is_strict_above_seventy_percent() {
        let mut at_threshold = vec![b'A'; 700];
        at_threshold.extend([0x80u8; 300]);
        let mut above = vec![b'A'; 701];
        above.extend([0x80u8; 299]);
        assert_eq!(classify_block(&at_threshold), 2);
        assert_eq!(classify_block(&above), 1);
    }

    /// Each chunk extends one byte into the next, so every pair is counted by
    /// exactly one chunk whatever the chunk size: 9 bytes alternating 1, 2
    /// hold four `(1, 2)` and four `(2, 1)` pairs, and 10 000 zeros hold 9 999
    /// `(0, 0)` pairs.
    #[test]
    fn test_digram_matrix_chunked_counts_each_seam_pair_once() {
        let alternating = [1u8, 2, 1, 2, 1, 2, 1, 2, 1];
        for chunk_size in 1..=4 {
            let matrix = digram_matrix_chunked(&alternating, chunk_size);
            assert_eq!(matrix[256 + 2], 4, "chunk size {chunk_size}");
            assert_eq!(matrix[2 * 256 + 1], 4, "chunk size {chunk_size}");
            assert_eq!(matrix.iter().sum::<u64>(), 8, "chunk size {chunk_size}");
        }
        let zeros = digram_matrix_chunked(&[0u8; 10_000], 1_000);
        assert_eq!(zeros[0], 9_999);
        assert_eq!(zeros.iter().sum::<u64>(), 9_999);
    }

    /// The parallel byte counts merge every chunk, including a short last one.
    #[test]
    fn test_byte_distribution_chunked_merges_every_chunk() {
        let mut data = vec![7u8; 10_000];
        data[9_999] = 9;
        let counts = byte_distribution_chunked(&data, 999);
        assert_eq!(counts[7], 9_999);
        assert_eq!(counts[9], 1);
        assert_eq!(counts.iter().sum::<u64>(), 10_000);
    }

    #[test]
    fn test_digram_matrix_parallel_alternating_pairs_exact() {
        let data: Vec<u8> = (0..2 * 1024 * 1024)
            .map(|i| if i % 2 == 0 { 1 } else { 2 })
            .collect();
        let matrix = digram_matrix(&data);
        assert_eq!(matrix[256 + 2], 1_048_576);
        assert_eq!(matrix[2 * 256 + 1], 1_048_575);
    }

    #[test]
    fn test_entropy_map_empty() {
        assert_eq!(entropy_map(&[], 256).len(), 0);
    }

    #[test]
    fn test_byte_distribution_sums() {
        let data = b"Hello World!";
        let dist = byte_distribution(data);
        let total: u64 = dist.iter().sum();
        assert_eq!(total, data.len() as u64);
    }

    #[test]
    fn test_byte_type_distribution_sums() {
        let data: Vec<u8> = (0..=255).collect();
        let (null, printable, control, high) = byte_type_distribution(&data);
        assert_eq!(null + printable + control + high, 256);
    }

    #[test]
    fn test_byte_type_distribution_categories() {
        let data = [0x00, 0x41, 0x01, 0x80];
        let (null, printable, control, high) = byte_type_distribution(&data);
        assert_eq!(null, 1);
        assert_eq!(printable, 1);
        assert_eq!(control, 1);
        assert_eq!(high, 1);
    }

    #[test]
    fn test_digram_matrix_size() {
        let data = b"ABC";
        let matrix = digram_matrix(data);
        assert_eq!(matrix.len(), 65536);
    }

    #[test]
    fn test_digram_matrix_counts() {
        let data = b"AABB";
        let matrix = digram_matrix(data);
        let pair_double_a = 0x41 * 256 + 0x41;
        let pair_a_then_b = 0x41 * 256 + 0x42;
        let pair_double_b = 0x42 * 256 + 0x42;
        assert_eq!(matrix[pair_double_a], 1);
        assert_eq!(matrix[pair_a_then_b], 1);
        assert_eq!(matrix[pair_double_b], 1);
    }

    #[test]
    fn test_digram_matrix_empty() {
        let matrix = digram_matrix(&[]);
        assert_eq!(matrix.len(), 65536);
        assert!(matrix.iter().all(|&v| v == 0));
    }

    #[test]
    fn test_classification_null_block() {
        let data = vec![0u8; 1024];
        let classes = content_classification(&data, 1024);
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0], 0);
    }

    #[test]
    fn test_classification_plaintext() {
        let data = b"The quick brown fox jumps over the lazy dog. ".repeat(20);
        let classes = content_classification(&data, data.len());
        assert_eq!(classes[0], 1);
    }

    #[test]
    fn test_classification_high_entropy() {
        let mut data = vec![0u8; 4096];
        let mut state: u32 = 12345;
        for b in &mut data {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
            *b = (state >> 16).to_le_bytes()[0];
        }
        let classes = content_classification(&data, data.len());
        // Single 4096-byte LCG stream has Shannon entropy 7.953 (> 7.0) -> category 3 exactly.
        assert_eq!(classes[0], 3);
    }

    #[test]
    fn test_classification_empty() {
        assert_eq!(content_classification(&[], 256).len(), 0);
    }

    #[test]
    fn test_byte_distribution_parallel_merge_counts_all_chunks() {
        // 2 MiB (>= PARALLEL_THRESHOLD) drives the par_chunks + merge path.
        // Byte value == index % 256 so every value appears exactly len/256 times.
        let total: usize = 2 * 1024 * 1024;
        let data: Vec<u8> = (0..total).map(|i| u8::try_from(i % 256).unwrap()).collect();
        let dist = byte_distribution(&data);
        let expected = (total / 256) as u64;
        assert!(dist.iter().all(|&c| c == expected), "merge dropped counts");
        assert_eq!(dist.iter().sum::<u64>(), total as u64);
    }

    #[test]
    fn test_digram_matrix_parallel_merge_boundary_exact() {
        // 2 MiB of constant 0x00 -> every 2-byte window is (0,0); N-1 total.
        // The per-chunk +1 overlap must count each boundary digram exactly once.
        let total: usize = 2 * 1024 * 1024;
        let data = vec![0u8; total];
        let matrix = digram_matrix(&data);
        assert_eq!(matrix[0], (total - 1) as u64);
        assert_eq!(matrix.iter().sum::<u64>(), (total - 1) as u64);
    }

    #[test]
    fn test_classify_block_category_2_moderate_low_printable() {
        // Four distinct high bytes -> entropy 2.0, printable 0, null 0.
        // Fails every earlier arm and every entropy band -> falls through to 2.
        let block: Vec<u8> = [0x80u8, 0x81, 0x82, 0x83]
            .iter()
            .copied()
            .cycle()
            .take(256)
            .collect();
        assert_eq!(classify_block(&block), 2);
    }

    #[test]
    fn test_classify_block_full_byte_range_is_category_3() {
        // All 256 byte values equiprobable -> entropy 8.0 (> 7.0) -> category 3.
        let block: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert_eq!(classify_block(&block), 3);
    }

    #[test]
    fn test_classify_block_moderate_entropy_is_category_4() {
        // 64 equiprobable symbols -> entropy 6.0, printable 0.5 -> band (4.5,7.0] -> 4.
        let block: Vec<u8> = (0..64u8).cycle().take(4096).collect();
        assert_eq!(classify_block(&block), 4);
    }

    #[test]
    fn test_entropy_map_block_size_zero_guard() {
        // Non-empty data isolates the block_size == 0 sub-condition.
        assert_eq!(entropy_map(b"abc", 0).len(), 0);
    }

    #[test]
    fn test_content_classification_block_size_zero_guard() {
        assert_eq!(content_classification(b"abc", 0).len(), 0);
    }

    #[test]
    fn test_byte_class_agrees_with_byte_type_distribution() {
        // Counting every byte value once must put exactly one tally in each
        // class per byte, so the tuple and the tags cannot disagree about any
        // of the 256 values. Widen or narrow either range alone and this fails.
        let all: Vec<u8> = (0..=255u8).collect();
        let (nulls, printable, control, high) = byte_type_distribution(&all);
        let tags = classify_bytes(&all);

        let tally = |wanted: u8| -> u64 {
            tags.iter()
                .fold(0u64, |total, &tag| total + u64::from(tag == wanted))
        };

        assert_eq!(tally(BYTE_CLASS_NULL), nulls);
        assert_eq!(tally(BYTE_CLASS_PRINTABLE), printable);
        assert_eq!(tally(BYTE_CLASS_CONTROL), control);
        assert_eq!(tally(BYTE_CLASS_HIGH), high);
        assert_eq!(nulls + printable + control + high, 256);
    }

    #[test]
    fn test_byte_class_boundaries() {
        assert_eq!(byte_class(0x00), BYTE_CLASS_NULL);
        assert_eq!(byte_class(0x01), BYTE_CLASS_CONTROL);
        assert_eq!(byte_class(0x1F), BYTE_CLASS_CONTROL);
        assert_eq!(byte_class(0x20), BYTE_CLASS_PRINTABLE);
        assert_eq!(byte_class(0x7E), BYTE_CLASS_PRINTABLE);
        assert_eq!(byte_class(0x7F), BYTE_CLASS_CONTROL);
        assert_eq!(byte_class(0x80), BYTE_CLASS_HIGH);
        assert_eq!(byte_class(0xFF), BYTE_CLASS_HIGH);
    }

    #[test]
    fn test_classify_bytes_is_one_tag_per_byte_in_order() {
        let data = b"\x00A\x1F\xFF";
        assert_eq!(
            classify_bytes(data),
            vec![
                BYTE_CLASS_NULL,
                BYTE_CLASS_PRINTABLE,
                BYTE_CLASS_CONTROL,
                BYTE_CLASS_HIGH
            ]
        );
    }
}
