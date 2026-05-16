use adler2::Adler32;
use similar::{capture_diff_slices, Algorithm, DiffOp};

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

const BYTE_LEVEL_THRESHOLD: usize = 1_048_576;
const ANCHOR_WINDOW: usize = 1024;
const ANCHOR_MASK: u32 = (1 << 10) - 1;
const ADLER_MOD: u32 = 65_521;

#[must_use]
pub fn diff_data(data_a: &[u8], data_b: &[u8]) -> DiffResult {
    if data_a.len() <= BYTE_LEVEL_THRESHOLD && data_b.len() <= BYTE_LEVEL_THRESHOLD {
        diff_data_byte_level(data_a, data_b)
    } else {
        diff_data_anchored(data_a, data_b)
    }
}

fn identical_result(len: usize) -> DiffResult {
    DiffResult {
        regions: vec![DiffRegion {
            offset_a: 0,
            offset_b: 0,
            length: len,
            diff_type: DiffType::Match,
        }],
        total_differences: 0,
        files_identical: true,
    }
}

fn empty_result() -> DiffResult {
    DiffResult {
        regions: Vec::new(),
        total_differences: 0,
        files_identical: true,
    }
}

fn op_to_region(op: &DiffOp, base_a: usize, base_b: usize) -> (DiffRegion, usize) {
    match *op {
        DiffOp::Equal {
            old_index,
            new_index,
            len,
        } => (
            DiffRegion {
                offset_a: base_a + old_index,
                offset_b: base_b + new_index,
                length: len,
                diff_type: DiffType::Match,
            },
            0,
        ),
        DiffOp::Delete {
            old_index,
            old_len,
            new_index,
        } => (
            DiffRegion {
                offset_a: base_a + old_index,
                offset_b: base_b + new_index,
                length: old_len,
                diff_type: DiffType::InsertedA,
            },
            old_len,
        ),
        DiffOp::Insert {
            old_index,
            new_index,
            new_len,
        } => (
            DiffRegion {
                offset_a: base_a + old_index,
                offset_b: base_b + new_index,
                length: new_len,
                diff_type: DiffType::InsertedB,
            },
            new_len,
        ),
        DiffOp::Replace {
            old_index,
            old_len,
            new_index,
            new_len,
        } => {
            let length = old_len.max(new_len);
            (
                DiffRegion {
                    offset_a: base_a + old_index,
                    offset_b: base_b + new_index,
                    length,
                    diff_type: DiffType::Modified,
                },
                length,
            )
        }
    }
}

fn diff_slice_with_base(
    data_a: &[u8],
    data_b: &[u8],
    base_a: usize,
    base_b: usize,
    regions: &mut Vec<DiffRegion>,
    total_diffs: &mut usize,
) {
    if data_a.is_empty() && data_b.is_empty() {
        return;
    }
    if data_a.is_empty() {
        regions.push(DiffRegion {
            offset_a: base_a,
            offset_b: base_b,
            length: data_b.len(),
            diff_type: DiffType::InsertedB,
        });
        *total_diffs += data_b.len();
        return;
    }
    if data_b.is_empty() {
        regions.push(DiffRegion {
            offset_a: base_a,
            offset_b: base_b,
            length: data_a.len(),
            diff_type: DiffType::InsertedA,
        });
        *total_diffs += data_a.len();
        return;
    }
    if data_a == data_b {
        regions.push(DiffRegion {
            offset_a: base_a,
            offset_b: base_b,
            length: data_a.len(),
            diff_type: DiffType::Match,
        });
        return;
    }
    let ops = capture_diff_slices(Algorithm::Myers, data_a, data_b);
    for op in &ops {
        let (region, diff_count) = op_to_region(op, base_a, base_b);
        *total_diffs += diff_count;
        regions.push(region);
    }
}

fn diff_data_byte_level(data_a: &[u8], data_b: &[u8]) -> DiffResult {
    if data_a.is_empty() && data_b.is_empty() {
        return empty_result();
    }
    if data_a == data_b {
        return identical_result(data_a.len());
    }

    let mut regions: Vec<DiffRegion> = Vec::new();
    let mut total_diffs: usize = 0;
    diff_slice_with_base(data_a, data_b, 0, 0, &mut regions, &mut total_diffs);

    DiffResult {
        regions,
        total_differences: total_diffs,
        files_identical: false,
    }
}

fn initial_adler32(window: &[u8]) -> (u32, u32) {
    let mut hasher = Adler32::new();
    hasher.write_slice(window);
    let checksum = hasher.checksum();
    (checksum & 0xFFFF, checksum >> 16)
}

fn roll_adler32(a: u32, b: u32, out_byte: u8, in_byte: u8, window: u32) -> (u32, u32) {
    let out = u32::from(out_byte);
    let inv = u32::from(in_byte);
    let new_a = (a + inv + ADLER_MOD - out) % ADLER_MOD;
    let window_mod = window % ADLER_MOD;
    let decrement = (window_mod * out) % ADLER_MOD;
    let new_b = (b + new_a + 2 * ADLER_MOD - decrement - a) % ADLER_MOD;
    (new_a, new_b)
}

fn compute_anchors(data: &[u8]) -> Vec<(u32, usize)> {
    if data.len() < ANCHOR_WINDOW {
        return Vec::new();
    }

    let window = ANCHOR_WINDOW;
    let window_u32 = u32::try_from(window).expect("ANCHOR_WINDOW constant must fit in u32");
    let mut anchors: Vec<(u32, usize)> = Vec::new();

    let mut idx: usize = 0;
    let (mut a, mut b) = initial_adler32(&data[0..window]);
    loop {
        let hash = (b << 16) | a;
        if (hash & ANCHOR_MASK) == 0 {
            anchors.push((hash, idx + window));
            let next_idx = idx + window;
            if next_idx + window > data.len() {
                break;
            }
            idx = next_idx;
            let (na, nb) = initial_adler32(&data[idx..idx + window]);
            a = na;
            b = nb;
        } else {
            let next_idx = idx + 1;
            if next_idx + window > data.len() {
                break;
            }
            let out_byte = data[idx];
            let in_byte = data[idx + window];
            let (na, nb) = roll_adler32(a, b, out_byte, in_byte, window_u32);
            a = na;
            b = nb;
            idx = next_idx;
        }
    }

    anchors
}

fn find_sync_points(anchors_a: &[(u32, usize)], anchors_b: &[(u32, usize)]) -> Vec<(usize, usize)> {
    if anchors_a.is_empty() || anchors_b.is_empty() {
        return Vec::new();
    }

    let mut sync: Vec<(usize, usize)> = Vec::new();
    let mut i: usize = 0;
    let mut j: usize = 0;
    let mut last_a: usize = 0;
    let mut last_b: usize = 0;

    while i < anchors_a.len() && j < anchors_b.len() {
        let (hash_a, pos_a) = anchors_a[i];
        let (hash_b, pos_b) = anchors_b[j];
        if hash_a == hash_b {
            if pos_a >= last_a && pos_b >= last_b {
                sync.push((pos_a, pos_b));
                last_a = pos_a;
                last_b = pos_b;
            }
            i += 1;
            j += 1;
        } else {
            let mut advanced = false;
            for look in 1..=8 {
                if j + look < anchors_b.len() && anchors_b[j + look].0 == hash_a {
                    j += look;
                    advanced = true;
                    break;
                }
                if i + look < anchors_a.len() && anchors_a[i + look].0 == hash_b {
                    i += look;
                    advanced = true;
                    break;
                }
            }
            if !advanced {
                i += 1;
                j += 1;
            }
        }
    }

    sync
}

fn diff_data_anchored(data_a: &[u8], data_b: &[u8]) -> DiffResult {
    if data_a == data_b {
        return identical_result(data_a.len());
    }

    let anchors_a = compute_anchors(data_a);
    let anchors_b = compute_anchors(data_b);
    let sync_points = find_sync_points(&anchors_a, &anchors_b);

    let mut regions: Vec<DiffRegion> = Vec::new();
    let mut total_diffs: usize = 0;
    let mut prev_a: usize = 0;
    let mut prev_b: usize = 0;

    for (sync_a, sync_b) in &sync_points {
        let seg_a = &data_a[prev_a..*sync_a];
        let seg_b = &data_b[prev_b..*sync_b];
        diff_slice_with_base(seg_a, seg_b, prev_a, prev_b, &mut regions, &mut total_diffs);
        prev_a = *sync_a;
        prev_b = *sync_b;
    }

    let tail_a = &data_a[prev_a..];
    let tail_b = &data_b[prev_b..];
    diff_slice_with_base(
        tail_a,
        tail_b,
        prev_a,
        prev_b,
        &mut regions,
        &mut total_diffs,
    );

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
        assert!(result.total_differences >= 1);
    }

    #[test]
    fn test_completely_different() {
        let a = vec![0x00u8; 32];
        let b = vec![0xFFu8; 32];
        let result = diff_data(&a, &b);
        assert!(!result.files_identical);
        assert!(result.total_differences >= 32);
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
        assert!(result.total_differences >= 1);

        let match_regions: Vec<_> = result
            .regions
            .iter()
            .filter(|r| r.diff_type == DiffType::Match)
            .collect();
        assert!(!match_regions.is_empty());
    }

    #[test]
    fn test_single_byte_insertion() {
        let a = b"ABCDEF";
        let mut b = Vec::from(&a[..]);
        b.insert(3, b'X');
        let result = diff_data(a, &b);
        assert!(!result.files_identical);
        let has_insert = result
            .regions
            .iter()
            .any(|r| r.diff_type == DiffType::InsertedB);
        assert!(
            has_insert,
            "Expected InsertedB region for single byte insertion, got: {:?}",
            result.regions
        );
        let match_count = result
            .regions
            .iter()
            .filter(|r| r.diff_type == DiffType::Match)
            .count();
        assert!(match_count >= 1, "Expected at least one Match region");
    }

    #[test]
    fn test_insertion_at_offset_zero() {
        let a = b"ABCDEFGHIJ";
        let mut b: Vec<u8> = Vec::new();
        b.push(b'X');
        b.extend_from_slice(a);
        let result = diff_data(a, &b);
        assert!(!result.files_identical);

        let first_non_empty = result
            .regions
            .iter()
            .find(|r| r.length > 0)
            .expect("Expected at least one region with length > 0");
        assert_eq!(first_non_empty.diff_type, DiffType::InsertedB);
        assert_eq!(first_non_empty.offset_a, 0);
        assert_eq!(first_non_empty.offset_b, 0);
        assert_eq!(first_non_empty.length, 1);

        let match_region = result
            .regions
            .iter()
            .find(|r| r.diff_type == DiffType::Match)
            .expect("Expected a Match region for the shared suffix");
        assert_eq!(match_region.length, a.len());
        assert_eq!(match_region.offset_a, 0);
        assert_eq!(match_region.offset_b, 1);
    }

    #[test]
    fn test_deletion_in_middle() {
        let a = b"ABCDEFGHIJ";
        let mut b: Vec<u8> = Vec::new();
        b.extend_from_slice(&a[..4]);
        b.extend_from_slice(&a[6..]);
        let result = diff_data(a, &b);
        assert!(!result.files_identical);

        let types: Vec<DiffType> = result
            .regions
            .iter()
            .filter(|r| r.length > 0)
            .map(|r| r.diff_type)
            .collect();
        assert!(types.contains(&DiffType::Match));
        assert!(types.contains(&DiffType::InsertedA));

        let deleted = result
            .regions
            .iter()
            .find(|r| r.diff_type == DiffType::InsertedA)
            .expect("Expected InsertedA for middle deletion");
        assert_eq!(deleted.length, 2);
        assert_eq!(deleted.offset_a, 4);
    }

    #[test]
    fn test_replace_middle_bytes() {
        let a = b"ABCDEFGHIJ";
        let mut b = a.to_vec();
        b[4] = b'!';
        b[5] = b'?';
        let result = diff_data(a, &b);
        assert!(!result.files_identical);

        let has_modification = result.regions.iter().any(|r| {
            r.diff_type == DiffType::Modified
                || r.diff_type == DiffType::InsertedA
                || r.diff_type == DiffType::InsertedB
        });
        assert!(
            has_modification,
            "Expected a non-match region for replaced bytes, got {:?}",
            result.regions
        );

        let match_count = result
            .regions
            .iter()
            .filter(|r| r.diff_type == DiffType::Match)
            .count();
        assert!(match_count >= 2, "Expected surrounding Match regions");
    }

    #[test]
    fn test_large_identical_files() {
        let size = BYTE_LEVEL_THRESHOLD + 256;
        let data_a = vec![0xAAu8; size];
        let data_b = data_a.clone();
        let result = diff_data(&data_a, &data_b);
        assert!(result.files_identical);
        assert_eq!(result.total_differences, 0);
        assert_eq!(result.regions.len(), 1);
        assert_eq!(result.regions[0].diff_type, DiffType::Match);
        assert_eq!(result.regions[0].length, size);
    }

    #[test]
    fn test_large_files_small_middle_change() {
        let size = BYTE_LEVEL_THRESHOLD + 4096;
        let mut data_a = vec![0u8; size];
        for (idx, byte) in data_a.iter_mut().enumerate() {
            *byte = u8::try_from((idx * 31 + 7) & 0xFF)
                .expect("mask with 0xFF guarantees value fits in u8");
        }
        let mut data_b = data_a.clone();
        let change_offset = size / 2;
        data_b[change_offset] ^= 0xFF;
        data_b[change_offset + 1] ^= 0xFF;
        data_b[change_offset + 2] ^= 0xFF;

        let result = diff_data(&data_a, &data_b);
        assert!(!result.files_identical);

        let match_bytes: usize = result
            .regions
            .iter()
            .filter(|r| r.diff_type == DiffType::Match)
            .map(|r| r.length)
            .sum();
        assert!(
            match_bytes > size - 4096,
            "Expected anchored diff to keep most of the file as Match, got {match_bytes} match bytes out of {size}"
        );

        let non_match_bytes: usize = result
            .regions
            .iter()
            .filter(|r| r.diff_type != DiffType::Match)
            .map(|r| r.length)
            .sum();
        assert!(
            non_match_bytes < 4096,
            "Expected localized diff, got {non_match_bytes} non-match bytes"
        );
    }

    #[test]
    fn test_byte_level_edit_script_not_giant_replace() {
        let mut a: Vec<u8> = Vec::new();
        for i in 0..200u32 {
            a.push((i & 0xFF) as u8);
        }
        let mut b: Vec<u8> = Vec::new();
        b.push(0xFF);
        b.extend_from_slice(&a);
        let result = diff_data(&a, &b);
        assert!(!result.files_identical);

        let match_bytes: usize = result
            .regions
            .iter()
            .filter(|r| r.diff_type == DiffType::Match)
            .map(|r| r.length)
            .sum();
        assert!(
            match_bytes >= a.len(),
            "Expected a proper edit script with the original body as Match (got {match_bytes} match bytes, body is {})",
            a.len()
        );
        assert_eq!(result.total_differences, 1);
    }

    /// Audit-1 F-0003 regression: large-file diff dispatch must take the
    /// anchored path directly rather than the deleted block-level Myers
    /// fallback. Confirms that for buffers above `BYTE_LEVEL_THRESHOLD`
    /// the anchored algorithm produces region offsets at byte granularity
    /// (not block-aligned multiples of 64) and emits a real edit script.
    #[test]
    fn test_large_file_dispatch_uses_anchored_byte_offsets() {
        let size = BYTE_LEVEL_THRESHOLD + 1024;
        let mut data_a = vec![0u8; size];
        for (idx, byte) in data_a.iter_mut().enumerate() {
            *byte = u8::try_from((idx * 17 + 3) & 0xFF)
                .expect("mask with 0xFF guarantees value fits in u8");
        }
        let mut data_b = data_a.clone();
        let change_offset = size / 3 + 5;
        data_b[change_offset] ^= 0xFF;

        let result = diff_data(&data_a, &data_b);
        assert!(!result.files_identical);

        let mismatch_region = result
            .regions
            .iter()
            .find(|r| r.diff_type != DiffType::Match && r.length > 0)
            .expect("anchored diff must surface the modified region");
        assert!(
            mismatch_region.offset_a % 64 != 0 || mismatch_region.length % 64 != 0,
            "anchored diff should yield byte-precise offsets, not 64-byte block-aligned ones; got offset_a={} length={}",
            mismatch_region.offset_a,
            mismatch_region.length,
        );
        assert!(
            mismatch_region.length < 64,
            "single-byte change should not be reported as a 64-byte block (got length={})",
            mismatch_region.length,
        );
    }
}
