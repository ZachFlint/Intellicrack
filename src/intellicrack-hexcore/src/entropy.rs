use rayon::prelude::*;

pub fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let counts = byte_distribution(data);
    let total = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

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

pub fn byte_distribution(data: &[u8]) -> [u64; 256] {
    const PARALLEL_THRESHOLD: usize = 1024 * 1024;

    if data.len() < PARALLEL_THRESHOLD {
        let mut counts = [0u64; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        counts
    } else {
        let chunk_size = (data.len() / rayon::current_num_threads()).max(65536);
        let chunk_counts: Vec<[u64; 256]> = data
            .par_chunks(chunk_size)
            .map(|chunk| {
                let mut local = [0u64; 256];
                for &b in chunk {
                    local[b as usize] += 1;
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

pub fn byte_type_distribution(data: &[u8]) -> (u64, u64, u64, u64) {
    let mut null_count: u64 = 0;
    let mut printable_count: u64 = 0;
    let mut control_count: u64 = 0;
    let mut high_count: u64 = 0;

    for &b in data {
        match b {
            0x00 => null_count += 1,
            0x20..=0x7E => printable_count += 1,
            0x01..=0x1F | 0x7F => control_count += 1,
            0x80..=0xFF => high_count += 1,
        }
    }

    (null_count, printable_count, control_count, high_count)
}

pub fn digram_matrix(data: &[u8]) -> Vec<u64> {
    const PARALLEL_THRESHOLD: usize = 1024 * 1024;

    if data.len() < 2 {
        return vec![0u64; 65536];
    }

    if data.len() < PARALLEL_THRESHOLD {
        let mut matrix = vec![0u64; 65536];
        for window in data.windows(2) {
            let idx = (window[0] as usize) * 256 + (window[1] as usize);
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
                    let idx = (window[0] as usize) * 256 + (window[1] as usize);
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

    let (null_count, printable_count, _control_count, _high_count) =
        byte_type_distribution(block);
    let total = block.len() as f64;
    let null_ratio = null_count as f64 / total;
    let printable_ratio = printable_count as f64 / total;

    let entropy = compute_entropy(block);

    if entropy < 0.5 && null_ratio > 0.9 {
        return 0; // null/empty
    }
    if entropy < 4.5 && printable_ratio > 0.7 {
        return 1; // plaintext
    }
    if entropy > 7.0 {
        return 3; // encrypted/compressed
    }
    if entropy >= 4.5 && entropy <= 7.0 {
        return 4; // code
    }
    2 // structured
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_uniform() {
        let data = vec![0x42u8; 1000];
        let ent = compute_entropy(&data);
        assert!(ent < 0.01, "uniform data should have near-zero entropy, got {}", ent);
    }

    #[test]
    fn test_entropy_random() {
        let mut data = vec![0u8; 256 * 100];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        let ent = compute_entropy(&data);
        assert!(ent > 7.99, "uniform distribution should have entropy ~8.0, got {}", ent);
    }

    #[test]
    fn test_entropy_empty() {
        assert_eq!(compute_entropy(&[]), 0.0);
    }

    #[test]
    fn test_entropy_map_blocks() {
        let mut data = vec![0u8; 2048];
        for b in data[1024..].iter_mut() {
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
        let aa_idx = 0x41 * 256 + 0x41;
        let ab_idx = 0x41 * 256 + 0x42;
        let bb_idx = 0x42 * 256 + 0x42;
        assert_eq!(matrix[aa_idx], 1);
        assert_eq!(matrix[ab_idx], 1);
        assert_eq!(matrix[bb_idx], 1);
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
        for b in data.iter_mut() {
            state = state.wrapping_mul(1103515245).wrapping_add(12345);
            *b = (state >> 16) as u8;
        }
        let classes = content_classification(&data, data.len());
        assert!(classes[0] == 3 || classes[0] == 4);
    }

    #[test]
    fn test_classification_empty() {
        assert!(content_classification(&[], 256).is_empty());
    }
}
