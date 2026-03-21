#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffType {
    Match,
    Modified,
    InsertedA,
    InsertedB,
}

#[derive(Debug, Clone)]
pub struct DiffRegion {
    pub offset_a: usize,
    pub offset_b: usize,
    pub length: usize,
    pub diff_type: DiffType,
}

#[derive(Debug)]
pub struct DiffResult {
    pub regions: Vec<DiffRegion>,
    pub total_differences: usize,
    pub files_identical: bool,
}

const BLOCK_SIZE: usize = 16;

pub fn diff_data(data_a: &[u8], data_b: &[u8]) -> DiffResult {
    if data_a == data_b {
        return DiffResult {
            regions: vec![DiffRegion {
                offset_a: 0,
                offset_b: 0,
                length: data_a.len(),
                diff_type: DiffType::Match,
            }],
            total_differences: 0,
            files_identical: true,
        };
    }

    let min_len = data_a.len().min(data_b.len());
    let max_len = data_a.len().max(data_b.len());
    let num_blocks = (min_len + BLOCK_SIZE - 1) / BLOCK_SIZE;

    let mut regions: Vec<DiffRegion> = Vec::new();
    let mut total_diffs: usize = 0;
    let mut current_type: Option<DiffType> = None;
    let mut region_start_a: usize = 0;
    let mut region_start_b: usize = 0;
    let mut region_len: usize = 0;

    for block_idx in 0..num_blocks {
        let start = block_idx * BLOCK_SIZE;
        let end = (start + BLOCK_SIZE).min(min_len);
        let block_a = &data_a[start..end];
        let block_b = &data_b[start..end];

        let block_type = if block_a == block_b {
            DiffType::Match
        } else {
            total_diffs += block_a
                .iter()
                .zip(block_b.iter())
                .filter(|(a, b)| a != b)
                .count();
            DiffType::Modified
        };

        match current_type {
            Some(ct) if ct == block_type => {
                region_len += end - start;
            }
            _ => {
                if region_len > 0 {
                    regions.push(DiffRegion {
                        offset_a: region_start_a,
                        offset_b: region_start_b,
                        length: region_len,
                        diff_type: current_type.unwrap(),
                    });
                }
                current_type = Some(block_type);
                region_start_a = start;
                region_start_b = start;
                region_len = end - start;
            }
        }
    }

    if region_len > 0 {
        if let Some(ct) = current_type {
            regions.push(DiffRegion {
                offset_a: region_start_a,
                offset_b: region_start_b,
                length: region_len,
                diff_type: ct,
            });
        }
    }

    if data_a.len() > min_len {
        let extra = data_a.len() - min_len;
        total_diffs += extra;
        regions.push(DiffRegion {
            offset_a: min_len,
            offset_b: min_len,
            length: extra,
            diff_type: DiffType::InsertedA,
        });
    } else if data_b.len() > min_len {
        let extra = data_b.len() - min_len;
        total_diffs += extra;
        regions.push(DiffRegion {
            offset_a: min_len,
            offset_b: min_len,
            length: extra,
            diff_type: DiffType::InsertedB,
        });
    }

    let _ = max_len;

    DiffResult {
        regions,
        total_differences: total_diffs,
        files_identical: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_files() {
        let data = b"Hello World";
        let result = diff_data(data, data);
        assert!(result.files_identical);
        assert_eq!(result.total_differences, 0);
        assert_eq!(result.regions.len(), 1);
        assert_eq!(result.regions[0].diff_type, DiffType::Match);
    }

    #[test]
    fn test_single_byte_diff() {
        let a = b"Hello World";
        let mut b = a.to_vec();
        b[0] = b'J';
        let result = diff_data(a, &b);
        assert!(!result.files_identical);
        assert_eq!(result.total_differences, 1);
    }

    #[test]
    fn test_completely_different() {
        let a = vec![0x00u8; 32];
        let b = vec![0xFFu8; 32];
        let result = diff_data(&a, &b);
        assert!(!result.files_identical);
        assert_eq!(result.total_differences, 32);
    }

    #[test]
    fn test_different_lengths_a_longer() {
        let a = b"Hello World Extra";
        let b = b"Hello World";
        let result = diff_data(a, b);
        assert!(!result.files_identical);
        let has_inserted_a = result
            .regions
            .iter()
            .any(|r| r.diff_type == DiffType::InsertedA);
        assert!(has_inserted_a);
    }

    #[test]
    fn test_different_lengths_b_longer() {
        let a = b"Hello";
        let b = b"Hello World";
        let result = diff_data(a, b);
        assert!(!result.files_identical);
        let has_inserted_b = result
            .regions
            .iter()
            .any(|r| r.diff_type == DiffType::InsertedB);
        assert!(has_inserted_b);
    }

    #[test]
    fn test_empty_files() {
        let result = diff_data(b"", b"");
        assert!(result.files_identical);
    }

    #[test]
    fn test_one_empty() {
        let result = diff_data(b"ABC", b"");
        assert!(!result.files_identical);
        assert_eq!(result.total_differences, 3);
    }

    #[test]
    fn test_block_aligned_diff() {
        let a = vec![0x00u8; 64];
        let mut b = vec![0x00u8; 64];
        b[32] = 0xFF;
        let result = diff_data(&a, &b);
        assert!(!result.files_identical);
        assert_eq!(result.total_differences, 1);

        let match_regions: Vec<_> = result
            .regions
            .iter()
            .filter(|r| r.diff_type == DiffType::Match)
            .collect();
        assert!(!match_regions.is_empty());
    }
}
