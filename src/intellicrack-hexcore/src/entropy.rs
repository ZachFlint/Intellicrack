use rayon::prelude::*;

#[must_use]
pub fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let counts = byte_distribution(data);
    let len_u64: u64 = data.len().try_into().unwrap_or(u64::MAX);
    let total = u64_to_f64(len_u64);
    let mut entropy = 0.0;
    for &count in &counts {
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

#[must_use]
pub fn entropy_map(data: &[u8], block_size: usize) -> Vec<f64> {
    if data.is_empty() || block_size == 0 {
        return Vec::new();
    }

    let blocks: Vec<&[u8]> = data.chunks(block_size).collect();
    blocks
        .par_iter()
        .map(|block| compute_entropy(block))
        .collect()
}

#[must_use]
pub fn byte_distribution(data: &[u8]) -> [u64; 256] {
    const PARALLEL_THRESHOLD: usize = 1024 * 1024;

    if data.len() < PARALLEL_THRESHOLD {
        let mut counts = [0u64; 256];
        for &b in data {
            counts[usize::from(b)] += 1;
        }
        counts
    } else {
        let chunk_size = (data.len() / rayon::current_num_threads()).max(65536);
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
            for i in 0..256 {
                merged[i] += counts[i];
            }
        }
        merged
    }
}

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

#[must_use]
pub fn digram_matrix(data: &[u8]) -> Vec<u64> {
    const PARALLEL_THRESHOLD: usize = 1024 * 1024;

    if data.len() < 2 {
        return vec![0u64; 65536];
    }

    if data.len() < PARALLEL_THRESHOLD {
        let mut matrix = vec![0u64; 65536];
        for window in data.windows(2) {
            let idx = usize::from(window[0]) * 256 + usize::from(window[1]);
            matrix[idx] += 1;
        }
        matrix
    } else {
        let chunk_size = (data.len() / rayon::current_num_threads()).max(65536);
        let chunks: Vec<(usize, &[u8])> = {
            let mut result = Vec::new();
            let mut start = 0;
            while start < data.len() {
                let end = (start + chunk_size + 1).min(data.len());
                result.push((start, &data[start..end]));
                start += chunk_size;
            }
            result
        };

        let chunk_matrices: Vec<Vec<u64>> = chunks
            .par_iter()
            .map(|(_, chunk)| {
                let mut local = vec![0u64; 65536];
                for window in chunk.windows(2) {
                    let idx = usize::from(window[0]) * 256 + usize::from(window[1]);
                    local[idx] += 1;
                }
                local
            })
            .collect();

        let mut merged = vec![0u64; 65536];
        for matrix in chunk_matrices {
            for i in 0..65536 {
                merged[i] += matrix[i];
            }
        }
        merged
    }
}

#[must_use]
pub fn content_classification(data: &[u8], block_size: usize) -> Vec<u8> {
    if data.is_empty() || block_size == 0 {
        return Vec::new();
    }

    let blocks: Vec<&[u8]> = data.chunks(block_size).collect();
    blocks
        .par_iter()
        .map(|block| classify_block(block))
        .collect()
}

fn classify_block(block: &[u8]) -> u8 {
    if block.is_empty() {
        return 0;
    }

    let (null_count, printable_count, _control_count, _high_count) = byte_type_distribution(block);
    let block_len_u64: u64 = block.len().try_into().unwrap_or(u64::MAX);
    let total = u64_to_f64(block_len_u64);
    let null_ratio = u64_to_f64(null_count) / total;
    let printable_ratio = u64_to_f64(printable_count) / total;

    let entropy = compute_entropy(block);

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

    #[test]
    fn test_entropy_uniform() {
        let data = vec![0x42u8; 1000];
        let ent = compute_entropy(&data);
        assert!(
            ent < 0.01,
            "uniform data should have near-zero entropy, got {ent}"
        );
    }

    #[test]
    fn test_entropy_random() {
        let mut data = vec![0u8; 256 * 100];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i.to_le_bytes()[0];
        }
        let ent = compute_entropy(&data);
        assert!(
            ent > 7.99,
            "uniform distribution should have entropy ~8.0, got {ent}"
        );
    }

    #[test]
    fn test_entropy_empty() {
        assert!(compute_entropy(&[]).abs() < f64::EPSILON);
    }

    #[test]
    fn test_entropy_map_blocks() {
        let mut data = vec![0u8; 2048];
        for b in &mut data[1024..] {
            *b = 0xFF;
        }
        let map = entropy_map(&data, 1024);
        assert_eq!(map.len(), 2);
        assert!(map[0] < 0.01);
        assert!(map[1] < 0.01);
    }

    #[test]
    fn test_entropy_map_empty() {
        assert!(entropy_map(&[], 256).is_empty());
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
        assert!(content_classification(&[], 256).is_empty());
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
        assert!(entropy_map(b"abc", 0).is_empty());
    }

    #[test]
    fn test_content_classification_block_size_zero_guard() {
        assert!(content_classification(b"abc", 0).is_empty());
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
