//! BPS and UPS patch format encoding and decoding.
//!
//! Implements the BPS1 (Beat Patching System) and UPS1 (Universal Patching System)
//! binary diff patch formats with CRC32 validation.

use crc32fast::Hasher;
use std::io;

fn crc32_compute(data: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

fn encode_var_int(mut val: u64) -> Vec<u8> {
    let mut result = Vec::new();
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val == 0 {
            byte |= 0x80;
            result.push(byte);
            break;
        }
        result.push(byte);
        val -= 1;
    }
    result
}

fn decode_var_int(data: &[u8], pos: &mut usize) -> io::Result<u64> {
    let overflow = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "variable-length integer overflow",
        )
    };
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected end of data in variable-length integer",
            ));
        }
        let byte = data[*pos];
        *pos += 1;
        let addend = u64::from(byte & 0x7F)
            .checked_shl(shift)
            .ok_or_else(overflow)?;
        result = result.checked_add(addend).ok_or_else(overflow)?;
        if byte & 0x80 != 0 {
            return Ok(result);
        }
        shift += 7;
        if shift > 63 {
            return Err(overflow());
        }
        result = result.checked_add(1u64 << shift).ok_or_else(overflow)?;
    }
}

const BPS_MATCH_WINDOW: usize = 4;
const BPS_MIN_COPY_LEN: usize = 4;

#[derive(Clone, Copy)]
enum ChoiceKind {
    SourceRead,
    SourceCopy,
    TargetCopy,
}

fn usize_to_i64(value: usize) -> io::Result<i64> {
    i64::try_from(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "buffer offset exceeds signed 64-bit range",
        )
    })
}

fn build_hash_index(data: &[u8]) -> std::collections::HashMap<[u8; BPS_MATCH_WINDOW], Vec<usize>> {
    let mut index: std::collections::HashMap<[u8; BPS_MATCH_WINDOW], Vec<usize>> =
        std::collections::HashMap::new();
    if data.len() < BPS_MATCH_WINDOW {
        return index;
    }
    for i in 0..=data.len() - BPS_MATCH_WINDOW {
        index_target_window(&mut index, data, i);
    }
    index
}

fn extend_match(a: &[u8], a_start: usize, b: &[u8], b_start: usize, max_len: usize) -> usize {
    let mut len = 0usize;
    while len < max_len
        && a_start + len < a.len()
        && b_start + len < b.len()
        && a[a_start + len] == b[b_start + len]
    {
        len += 1;
    }
    len
}

fn encode_rel_offset(rel_offset: i64) -> u64 {
    let negative = rel_offset < 0;
    let abs_val = rel_offset.unsigned_abs();
    (abs_val << 1) | u64::from(negative)
}

fn var_int_len(val: u64) -> usize {
    let mut v = val;
    let mut len = 0usize;
    loop {
        len += 1;
        v >>= 7;
        if v == 0 {
            break;
        }
        v -= 1;
    }
    len
}

fn find_best_match(
    haystack: &[u8],
    needle: &[u8],
    needle_pos: usize,
    index: &std::collections::HashMap<[u8; BPS_MATCH_WINDOW], Vec<usize>>,
    haystack_limit: usize,
) -> Option<(usize, usize)> {
    if needle_pos + BPS_MATCH_WINDOW > needle.len() {
        return None;
    }
    let key: [u8; BPS_MATCH_WINDOW] = [
        needle[needle_pos],
        needle[needle_pos + 1],
        needle[needle_pos + 2],
        needle[needle_pos + 3],
    ];
    let candidates = index.get(&key)?;
    let mut best_len = 0usize;
    let mut best_off = 0usize;
    let max_len = needle.len() - needle_pos;
    for &cand in candidates.iter().rev() {
        if cand >= haystack_limit {
            continue;
        }
        let cand_max = haystack_limit.saturating_sub(cand);
        let cap = max_len.min(cand_max);
        if cap <= best_len {
            continue;
        }
        let m = extend_match(haystack, cand, needle, needle_pos, cap);
        if m > best_len {
            best_len = m;
            best_off = cand;
            if best_len == max_len {
                break;
            }
        }
    }
    if best_len >= BPS_MIN_COPY_LEN {
        Some((best_off, best_len))
    } else {
        None
    }
}

fn flush_target_read(patch: &mut Vec<u8>, buf: &mut Vec<u8>) {
    if buf.is_empty() {
        return;
    }
    let diff_len = buf.len() as u64;
    patch.extend_from_slice(&encode_var_int(((diff_len - 1) << 2) | 1));
    patch.extend_from_slice(buf);
    buf.clear();
}

fn index_target_window(
    index: &mut std::collections::HashMap<[u8; BPS_MATCH_WINDOW], Vec<usize>>,
    data: &[u8],
    pos: usize,
) {
    if pos + BPS_MATCH_WINDOW > data.len() {
        return;
    }
    let key: [u8; BPS_MATCH_WINDOW] = [data[pos], data[pos + 1], data[pos + 2], data[pos + 3]];
    index.entry(key).or_default().push(pos);
}

/// Generate a BPS patch from source and target byte arrays.
///
/// Emits `SourceRead`, `TargetRead`, `SourceCopy`, and `TargetCopy` actions to
/// produce a compact patch. Uses a 4-byte rolling hash index over both the
/// source buffer and the already-written target buffer to discover matches.
/// Footer contains source CRC32, target CRC32, and patch CRC32.
///
/// # Errors
///
/// Returns `io::Error` for API consistency. This function does not
/// currently produce errors for valid inputs.
pub fn export_bps(source: &[u8], target: &[u8]) -> io::Result<Vec<u8>> {
    let mut patch = Vec::new();

    patch.extend_from_slice(b"BPS1");
    patch.extend_from_slice(&encode_var_int(source.len() as u64));
    patch.extend_from_slice(&encode_var_int(target.len() as u64));
    patch.extend_from_slice(&encode_var_int(0));

    let source_index = build_hash_index(source);
    let mut target_index: std::collections::HashMap<[u8; BPS_MATCH_WINDOW], Vec<usize>> =
        std::collections::HashMap::new();

    let mut tgt_pos: usize = 0;
    let mut source_rel_offset: i64 = 0;
    let mut target_rel_offset: i64 = 0;
    let mut pending_target_read: Vec<u8> = Vec::new();

    while tgt_pos < target.len() {
        let mut source_read_len = 0usize;
        if tgt_pos < source.len() {
            source_read_len =
                extend_match(source, tgt_pos, target, tgt_pos, target.len() - tgt_pos);
        }

        let source_copy_candidate =
            find_best_match(source, target, tgt_pos, &source_index, source.len());
        let target_copy_candidate =
            find_best_match(target, target, tgt_pos, &target_index, tgt_pos);

        let mut choices: Vec<(i64, ChoiceKind, usize, usize)> = Vec::new();

        if source_read_len >= BPS_MIN_COPY_LEN {
            let cmd_cost = var_int_len(((source_read_len as u64) - 1) << 2);
            let score = usize_to_i64(source_read_len)? - usize_to_i64(cmd_cost)?;
            choices.push((score, ChoiceKind::SourceRead, source_read_len, 0));
        }

        if let Some((offset, len)) = source_copy_candidate {
            let delta = usize_to_i64(offset)? - source_rel_offset;
            let enc = encode_rel_offset(delta);
            let cmd_cost = var_int_len((((len as u64) - 1) << 2) | 2) + var_int_len(enc);
            let score = usize_to_i64(len)? - usize_to_i64(cmd_cost)?;
            choices.push((score, ChoiceKind::SourceCopy, len, offset));
        }

        if let Some((offset, len)) = target_copy_candidate {
            let delta = usize_to_i64(offset)? - target_rel_offset;
            let enc = encode_rel_offset(delta);
            let cmd_cost = var_int_len((((len as u64) - 1) << 2) | 3) + var_int_len(enc);
            let score = usize_to_i64(len)? - usize_to_i64(cmd_cost)?;
            choices.push((score, ChoiceKind::TargetCopy, len, offset));
        }

        let (best_kind, best_len, best_offset) = choices
            .into_iter()
            .max_by_key(|&(score, _, _, _)| score)
            .map_or(
                (ChoiceKind::SourceRead, 0usize, 0usize),
                |(_, kind, len, off)| (kind, len, off),
            );

        if best_len == 0 {
            pending_target_read.push(target[tgt_pos]);
            index_target_window(&mut target_index, target, tgt_pos);
            tgt_pos += 1;
            continue;
        }

        flush_target_read(&mut patch, &mut pending_target_read);

        match best_kind {
            ChoiceKind::SourceRead => {
                patch.extend_from_slice(&encode_var_int(((best_len as u64) - 1) << 2));
            }
            ChoiceKind::SourceCopy => {
                let new_rel = usize_to_i64(best_offset)?;
                let delta = new_rel - source_rel_offset;
                source_rel_offset = new_rel + usize_to_i64(best_len)?;
                patch.extend_from_slice(&encode_var_int((((best_len as u64) - 1) << 2) | 2));
                patch.extend_from_slice(&encode_var_int(encode_rel_offset(delta)));
            }
            ChoiceKind::TargetCopy => {
                let new_rel = usize_to_i64(best_offset)?;
                let delta = new_rel - target_rel_offset;
                target_rel_offset = new_rel + usize_to_i64(best_len)?;
                patch.extend_from_slice(&encode_var_int((((best_len as u64) - 1) << 2) | 3));
                patch.extend_from_slice(&encode_var_int(encode_rel_offset(delta)));
            }
        }

        for i in 0..best_len {
            index_target_window(&mut target_index, target, tgt_pos + i);
        }

        tgt_pos += best_len;
    }

    flush_target_read(&mut patch, &mut pending_target_read);

    let source_crc = crc32_compute(source);
    let target_crc = crc32_compute(target);
    patch.extend_from_slice(&source_crc.to_le_bytes());
    patch.extend_from_slice(&target_crc.to_le_bytes());

    let patch_crc = crc32_compute(&patch);
    patch.extend_from_slice(&patch_crc.to_le_bytes());

    Ok(patch)
}

struct BpsValidation {
    footer_start: usize,
    stored_target_crc: u32,
}

fn validate_bps_patch(patch: &[u8], source: &[u8]) -> io::Result<BpsValidation> {
    // Minimum well-formed size: 4-byte magic + at least 1 byte each for the
    // source-size, target-size, and metadata-size varints + 12-byte footer.
    if patch.len() < 19 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "BPS patch too short",
        ));
    }
    if &patch[..4] != b"BPS1" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a BPS1 patch",
        ));
    }

    let patch_body = &patch[..patch.len() - 4];
    let stored_patch_crc = u32::from_le_bytes([
        patch[patch.len() - 4],
        patch[patch.len() - 3],
        patch[patch.len() - 2],
        patch[patch.len() - 1],
    ]);
    if crc32_compute(patch_body) != stored_patch_crc {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "patch CRC32 mismatch",
        ));
    }

    let footer_start = patch.len() - 12;
    let stored_source_crc = u32::from_le_bytes([
        patch[footer_start],
        patch[footer_start + 1],
        patch[footer_start + 2],
        patch[footer_start + 3],
    ]);
    let stored_target_crc = u32::from_le_bytes([
        patch[footer_start + 4],
        patch[footer_start + 5],
        patch[footer_start + 6],
        patch[footer_start + 7],
    ]);

    if crc32_compute(source) != stored_source_crc {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "source CRC32 mismatch",
        ));
    }

    Ok(BpsValidation {
        footer_start,
        stored_target_crc,
    })
}

fn apply_source_read(
    target: &mut [u8],
    source: &[u8],
    output_offset: &mut usize,
    length: usize,
    pos: usize,
) -> io::Result<()> {
    let end = output_offset.saturating_add(length);
    if end > target.len() || end > source.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "BPS SourceRead OOB at patch offset {pos}: source/target read of {length} bytes would exceed bounds"
            ),
        ));
    }
    for _ in 0..length {
        target[*output_offset] = source[*output_offset];
        *output_offset += 1;
    }
    Ok(())
}

fn apply_target_read(
    target: &mut [u8],
    patch: &[u8],
    output_offset: &mut usize,
    pos: &mut usize,
    length: usize,
    footer_start: usize,
) -> io::Result<()> {
    if *pos >= footer_start
        || pos.saturating_add(length) > footer_start
        || output_offset.saturating_add(length) > target.len()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "BPS TargetRead OOB at patch offset {pos}: source/target read of {length} bytes would exceed bounds"
            ),
        ));
    }
    for _ in 0..length {
        target[*output_offset] = patch[*pos];
        *pos += 1;
        *output_offset += 1;
    }
    Ok(())
}

fn apply_source_copy(
    target: &mut [u8],
    source: &[u8],
    patch: &[u8],
    output_offset: &mut usize,
    pos: &mut usize,
    source_rel_offset: &mut i64,
    length: usize,
) -> io::Result<()> {
    let offset_data = decode_var_int(patch, pos)?;
    let negative = offset_data & 1 != 0;
    let offset_val = i64::try_from(offset_data >> 1)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "source copy offset overflow"))?;
    let delta = if negative { -offset_val } else { offset_val };
    *source_rel_offset = source_rel_offset
        .checked_add(delta)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source copy offset overflow"))?;
    let length_i64 = i64::try_from(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "source copy length overflow"))?;
    let end_src = source_rel_offset
        .checked_add(length_i64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source copy end overflow"))?;
    let src_start = usize::try_from(*source_rel_offset).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "BPS SourceCopy OOB at patch offset {pos}: source/target read of {length} bytes would exceed bounds"
            ),
        )
    })?;
    let src_end = usize::try_from(end_src).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "BPS SourceCopy OOB at patch offset {pos}: source/target read of {length} bytes would exceed bounds"
            ),
        )
    })?;
    if src_end > source.len() || output_offset.saturating_add(length) > target.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "BPS SourceCopy OOB at patch offset {pos}: source/target read of {length} bytes would exceed bounds"
            ),
        ));
    }
    for &src_byte in &source[src_start..src_end] {
        target[*output_offset] = src_byte;
        *output_offset += 1;
    }
    *source_rel_offset = end_src;
    Ok(())
}

fn apply_target_copy(
    target: &mut [u8],
    patch: &[u8],
    output_offset: &mut usize,
    pos: &mut usize,
    target_rel_offset: &mut i64,
    length: usize,
) -> io::Result<()> {
    let offset_data = decode_var_int(patch, pos)?;
    let negative = offset_data & 1 != 0;
    let offset_val = i64::try_from(offset_data >> 1)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "target copy offset overflow"))?;
    let delta = if negative { -offset_val } else { offset_val };
    *target_rel_offset = target_rel_offset
        .checked_add(delta)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "target copy offset overflow"))?;
    let tgt_start = usize::try_from(*target_rel_offset).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "BPS TargetCopy OOB at patch offset {pos}: source/target read of {length} bytes would exceed bounds"
            ),
        )
    })?;
    if tgt_start >= *output_offset || output_offset.saturating_add(length) > target.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "BPS TargetCopy OOB at patch offset {pos}: source/target read of {length} bytes would exceed bounds"
            ),
        ));
    }
    for _ in 0..length {
        let tgt_idx = usize::try_from(*target_rel_offset).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "BPS TargetCopy OOB at patch offset {pos}: source/target read of {length} bytes would exceed bounds"
                ),
            )
        })?;
        target[*output_offset] = target[tgt_idx];
        *target_rel_offset += 1;
        *output_offset += 1;
    }
    Ok(())
}

/// Apply a BPS patch to the source data, producing the target.
///
/// Validates the BPS1 header, source CRC32, target CRC32, and patch CRC32.
///
/// # Errors
///
/// Returns `io::Error` if the patch is malformed, CRC32 validation fails,
/// or the source data does not match the expected checksum.
pub fn import_bps(patch: &[u8], source: &[u8]) -> io::Result<Vec<u8>> {
    let validation = validate_bps_patch(patch, source)?;
    let footer_start = validation.footer_start;

    let mut pos: usize = 4;
    let _source_size = decode_var_int(patch, &mut pos)?;
    let target_size = decode_var_int(patch, &mut pos)?;
    let metadata_size = decode_var_int(patch, &mut pos)?;
    pos += usize::try_from(metadata_size)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "metadata size overflow"))?;

    let target_len = usize::try_from(target_size)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "target size overflow"))?;
    let mut target = Vec::new();
    target.try_reserve_exact(target_len).map_err(|e| {
        io::Error::new(
            io::ErrorKind::OutOfMemory,
            format!("failed to reserve target buffer of {target_len} bytes: {e}"),
        )
    })?;
    target.resize(target_len, 0);
    let mut output_offset: usize = 0;
    let mut source_rel_offset: i64 = 0;
    let mut target_rel_offset: i64 = 0;

    while pos < footer_start {
        let action = decode_var_int(patch, &mut pos)?;
        let command = action & 3;
        let length = usize::try_from(action >> 2)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "action length overflow"))?
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "action length overflow"))?;

        match command {
            0 => apply_source_read(&mut target, source, &mut output_offset, length, pos)?,
            1 => apply_target_read(
                &mut target,
                patch,
                &mut output_offset,
                &mut pos,
                length,
                footer_start,
            )?,
            2 => apply_source_copy(
                &mut target,
                source,
                patch,
                &mut output_offset,
                &mut pos,
                &mut source_rel_offset,
                length,
            )?,
            3 => apply_target_copy(
                &mut target,
                patch,
                &mut output_offset,
                &mut pos,
                &mut target_rel_offset,
                length,
            )?,
            _ => unreachable!(),
        }
    }

    if crc32_compute(&target) != validation.stored_target_crc {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "target CRC32 mismatch",
        ));
    }

    Ok(target)
}

/// Generate a UPS patch from source and target byte arrays.
///
/// Uses XOR-based difference records terminated by zero bytes.
///
/// # Errors
///
/// Returns `io::Error` for API consistency. This function does not
/// currently produce errors for valid inputs.
pub fn export_ups(source: &[u8], target: &[u8]) -> io::Result<Vec<u8>> {
    let mut patch = Vec::new();
    patch.extend_from_slice(b"UPS1");
    patch.extend_from_slice(&encode_var_int(source.len() as u64));
    patch.extend_from_slice(&encode_var_int(target.len() as u64));

    let max_len = source.len().max(target.len());
    let mut write_pos: usize = 0;
    let mut offset: usize = 0;

    while offset < max_len {
        let src_byte = if offset < source.len() {
            source[offset]
        } else {
            0
        };
        let tgt_byte = if offset < target.len() {
            target[offset]
        } else {
            0
        };
        let xor = src_byte ^ tgt_byte;

        if xor != 0 {
            let rel_offset = offset - write_pos;
            patch.extend_from_slice(&encode_var_int(rel_offset as u64));

            while offset < max_len {
                let s = if offset < source.len() {
                    source[offset]
                } else {
                    0
                };
                let t = if offset < target.len() {
                    target[offset]
                } else {
                    0
                };
                let x = s ^ t;
                patch.push(x);
                offset += 1;
                if x == 0 {
                    break;
                }
            }
            write_pos = offset;
        } else {
            offset += 1;
        }
    }

    let source_crc = crc32_compute(source);
    let target_crc = crc32_compute(target);
    patch.extend_from_slice(&source_crc.to_le_bytes());
    patch.extend_from_slice(&target_crc.to_le_bytes());

    let patch_crc = crc32_compute(&patch);
    patch.extend_from_slice(&patch_crc.to_le_bytes());

    Ok(patch)
}

/// Apply a UPS patch to the source data, producing the target.
///
/// Validates UPS1 header and all three CRC32 checksums.
///
/// # Errors
///
/// Returns `io::Error` if the patch is malformed, CRC32 validation fails,
/// or the source data does not match the expected checksum.
pub fn import_ups(patch: &[u8], source: &[u8]) -> io::Result<Vec<u8>> {
    // Minimum well-formed size: 4-byte magic + at least 1 byte each for the
    // source-size and target-size varints + 12-byte footer.
    if patch.len() < 18 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "UPS patch too short",
        ));
    }
    if &patch[..4] != b"UPS1" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a UPS1 patch",
        ));
    }

    let patch_body = &patch[..patch.len() - 4];
    let stored_patch_crc = u32::from_le_bytes([
        patch[patch.len() - 4],
        patch[patch.len() - 3],
        patch[patch.len() - 2],
        patch[patch.len() - 1],
    ]);
    if crc32_compute(patch_body) != stored_patch_crc {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "patch CRC32 mismatch",
        ));
    }

    let footer_start = patch.len() - 12;
    let stored_source_crc = u32::from_le_bytes([
        patch[footer_start],
        patch[footer_start + 1],
        patch[footer_start + 2],
        patch[footer_start + 3],
    ]);
    let stored_target_crc = u32::from_le_bytes([
        patch[footer_start + 4],
        patch[footer_start + 5],
        patch[footer_start + 6],
        patch[footer_start + 7],
    ]);

    if crc32_compute(source) != stored_source_crc {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "source CRC32 mismatch",
        ));
    }

    let mut pos: usize = 4;
    let _source_size = decode_var_int(patch, &mut pos)?;
    let target_size = decode_var_int(patch, &mut pos)?;

    let target_len = usize::try_from(target_size)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "target size overflow"))?;
    let mut target = source.to_vec();
    let needed_extra = target_len.saturating_sub(target.len());
    if needed_extra > 0 {
        target.try_reserve_exact(needed_extra).map_err(|e| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!(
                    "failed to reserve additional target capacity of {needed_extra} bytes: {e}"
                ),
            )
        })?;
    }
    target.resize(target_len, 0);

    let mut offset: usize = 0;

    while pos < footer_start {
        let rel_offset = decode_var_int(patch, &mut pos)?;
        let rel_offset_usize = usize::try_from(rel_offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "offset overflow"))?;
        offset = offset
            .checked_add(rel_offset_usize)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "offset overflow"))?;

        while pos < footer_start {
            let xor_byte = patch[pos];
            pos += 1;
            if xor_byte == 0 {
                offset += 1;
                break;
            }
            if offset < target.len() {
                target[offset] ^= xor_byte;
            }
            offset += 1;
        }
    }

    if crc32_compute(&target) != stored_target_crc {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "target CRC32 mismatch",
        ));
    }

    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_var_int_roundtrip() {
        for val in [0u64, 1, 127, 128, 255, 1000, 65535, 1_000_000] {
            let encoded = encode_var_int(val);
            let mut pos = 0;
            let decoded = decode_var_int(&encoded, &mut pos).unwrap();
            assert_eq!(val, decoded);
            assert_eq!(pos, encoded.len());
        }
    }

    /// F-0076 regression: `decode_var_int` shifted `1u64 << shift` *before*
    /// its `shift > 63` guard, so a malformed varint made of continuation
    /// bytes (high bit clear) drove `shift` to 70 and panicked with "attempt
    /// to shift left with overflow" — a panic across the FFI boundary aborts
    /// the host. Every byte < 0x80 is a continuation byte, so twelve `0x00`
    /// bytes never terminate and must surface a typed `InvalidData` error.
    ///
    /// Mutation caught: reverting to `result += 1u64 << shift;` before the
    /// guard makes this input panic instead of returning `Err`, so the
    /// `is_err()` assertion is never reached.
    #[test]
    fn test_decode_var_int_malformed_overlong_is_error_not_panic() {
        let malformed = [0x00u8; 12];
        let mut pos = 0;
        let result = decode_var_int(&malformed, &mut pos);
        assert!(
            result.is_err(),
            "an over-long varint must return an error, never panic"
        );
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "over-long varint must map to InvalidData"
        );
    }

    /// F-0076 companion: the fix must not reject a legitimate maximal varint.
    /// `u64::MAX` encodes to a terminated 10-byte sequence and must still
    /// round-trip exactly.
    #[test]
    fn test_decode_var_int_max_u64_still_roundtrips() {
        let encoded = encode_var_int(u64::MAX);
        let mut pos = 0;
        assert_eq!(decode_var_int(&encoded, &mut pos).unwrap(), u64::MAX);
        assert_eq!(pos, encoded.len());
    }

    #[test]
    fn test_bps_roundtrip() {
        let source = b"Hello, World!";
        let target = b"Hello, Rust!!";
        let patch = export_bps(source, target).unwrap();
        let result = import_bps(&patch, source).unwrap();
        assert_eq!(&result, target);
    }

    #[test]
    fn test_ups_roundtrip() {
        let source = b"ABCDEFGH";
        let target = b"AbCdEfGh";
        let patch = export_ups(source, target).unwrap();
        let result = import_ups(&patch, source).unwrap();
        assert_eq!(&result, target);
    }

    fn patch_contains_command(patch: &[u8], cmd_nibble: u64) -> bool {
        let footer_start = patch.len() - 12;
        let mut pos: usize = 4;
        let _src = decode_var_int(patch, &mut pos).unwrap();
        let _tgt = decode_var_int(patch, &mut pos).unwrap();
        let metadata_size = decode_var_int(patch, &mut pos).unwrap();
        pos += usize::try_from(metadata_size).expect("test patch metadata fits in usize");

        while pos < footer_start {
            let action = decode_var_int(patch, &mut pos).unwrap();
            let command = action & 3;
            let length = ((action >> 2) as usize) + 1;
            if command == cmd_nibble {
                return true;
            }
            match command {
                0 => {}
                1 => pos += length,
                2 | 3 => {
                    let _off = decode_var_int(patch, &mut pos).unwrap();
                }
                _ => unreachable!(),
            }
        }
        false
    }

    #[test]
    fn test_bps_source_copy_roundtrip() {
        let pattern: Vec<u8> = (0u8..64).collect();
        let mut source: Vec<u8> = vec![0xAAu8; 128];
        source.extend_from_slice(&pattern);
        source.extend(vec![0xBBu8; 128]);

        let mut target: Vec<u8> = vec![0xCCu8; 64];
        target.extend_from_slice(&pattern);
        target.extend(vec![0xDDu8; 64]);

        let patch = export_bps(&source, &target).unwrap();
        assert!(
            patch_contains_command(&patch, 2),
            "patch must emit at least one SourceCopy command"
        );
        let decoded = import_bps(&patch, &source).unwrap();
        assert_eq!(decoded, target);
    }

    #[test]
    fn test_bps_target_copy_roundtrip() {
        let pattern: Vec<u8> = (0u8..64).collect();
        let source: Vec<u8> = vec![0u8; 256];

        let mut target: Vec<u8> = Vec::new();
        target.extend_from_slice(&pattern);
        target.extend(vec![0xEEu8; 64]);
        target.extend_from_slice(&pattern);
        target.extend(vec![0xFFu8; 64]);

        let patch = export_bps(&source, &target).unwrap();
        assert!(
            patch_contains_command(&patch, 3),
            "patch must emit at least one TargetCopy command"
        );
        let decoded = import_bps(&patch, &source).unwrap();
        assert_eq!(decoded, target);
    }

    #[test]
    fn test_bps_import_source_read_oob_fails_loud() {
        let source = b"abcd".to_vec();
        let mut body = Vec::new();
        body.extend_from_slice(b"BPS1");
        body.extend_from_slice(&encode_var_int(source.len() as u64));
        body.extend_from_slice(&encode_var_int(32));
        body.extend_from_slice(&encode_var_int(0));

        let length: u64 = 32;
        let action: u64 = (length - 1) << 2;
        body.extend_from_slice(&encode_var_int(action));

        let target_expected = vec![0u8; 32];
        let source_crc = crc32_compute(&source);
        let target_crc = crc32_compute(&target_expected);
        body.extend_from_slice(&source_crc.to_le_bytes());
        body.extend_from_slice(&target_crc.to_le_bytes());

        let patch_crc = crc32_compute(&body);
        body.extend_from_slice(&patch_crc.to_le_bytes());

        let err = import_bps(&body, &source).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let msg = err.to_string();
        assert!(
            msg.contains("SourceRead") && msg.contains("OOB"),
            "expected SourceRead OOB error, got: {msg}"
        );
    }

    #[test]
    fn test_bps_import_source_copy_oob_fails_loud() {
        let source = b"abcd".to_vec();
        let mut body = Vec::new();
        body.extend_from_slice(b"BPS1");
        body.extend_from_slice(&encode_var_int(source.len() as u64));
        body.extend_from_slice(&encode_var_int(16));
        body.extend_from_slice(&encode_var_int(0));

        let length: u64 = 16;
        let action: u64 = ((length - 1) << 2) | 2;
        body.extend_from_slice(&encode_var_int(action));
        body.extend_from_slice(&encode_var_int(encode_rel_offset(0)));

        let target_expected = vec![0u8; 16];
        let source_crc = crc32_compute(&source);
        let target_crc = crc32_compute(&target_expected);
        body.extend_from_slice(&source_crc.to_le_bytes());
        body.extend_from_slice(&target_crc.to_le_bytes());

        let patch_crc = crc32_compute(&body);
        body.extend_from_slice(&patch_crc.to_le_bytes());

        let err = import_bps(&body, &source).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let msg = err.to_string();
        assert!(
            msg.contains("SourceCopy") && msg.contains("OOB"),
            "expected SourceCopy OOB error, got: {msg}"
        );
    }

    #[test]
    fn test_bps_import_target_copy_oob_fails_loud() {
        let source = vec![0u8; 16];
        let mut body = Vec::new();
        body.extend_from_slice(b"BPS1");
        body.extend_from_slice(&encode_var_int(source.len() as u64));
        body.extend_from_slice(&encode_var_int(16));
        body.extend_from_slice(&encode_var_int(0));

        let length: u64 = 8;
        let action: u64 = ((length - 1) << 2) | 3;
        body.extend_from_slice(&encode_var_int(action));
        body.extend_from_slice(&encode_var_int(encode_rel_offset(0)));

        let target_expected = vec![0u8; 16];
        let source_crc = crc32_compute(&source);
        let target_crc = crc32_compute(&target_expected);
        body.extend_from_slice(&source_crc.to_le_bytes());
        body.extend_from_slice(&target_crc.to_le_bytes());

        let patch_crc = crc32_compute(&body);
        body.extend_from_slice(&patch_crc.to_le_bytes());

        let err = import_bps(&body, &source).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let msg = err.to_string();
        assert!(
            msg.contains("TargetCopy") && msg.contains("OOB"),
            "expected TargetCopy OOB error, got: {msg}"
        );
    }

    /// Encodes a BPS action header the same way the writer does: the low two
    /// bits carry the command and the remaining bits carry `length - 1`.
    const fn action_header(command: u64, length: u64) -> u64 {
        ((length - 1) << 2) | command
    }

    fn assemble_bps(source: &[u8], target: &[u8], metadata: &[u8], actions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(b"BPS1");
        body.extend_from_slice(&encode_var_int(source.len() as u64));
        body.extend_from_slice(&encode_var_int(target.len() as u64));
        body.extend_from_slice(&encode_var_int(metadata.len() as u64));
        body.extend_from_slice(metadata);
        body.extend_from_slice(actions);
        body.extend_from_slice(&crc32_compute(source).to_le_bytes());
        body.extend_from_slice(&crc32_compute(target).to_le_bytes());
        let pc = crc32_compute(&body);
        body.extend_from_slice(&pc.to_le_bytes());
        body
    }

    #[test]
    fn test_decode_var_int_unexpected_eof() {
        // Empty input.
        let err = decode_var_int(&[], &mut 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        // A continuation byte (no 0x80) at the end of the buffer.
        let err2 = decode_var_int(&[0x00], &mut 0).unwrap_err();
        assert_eq!(err2.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_validate_bps_too_short() {
        let err = import_bps(&[0u8; 8], b"src").unwrap_err();
        assert!(err.to_string().contains("too short"), "got {err}");
    }

    #[test]
    fn test_validate_bps_min_length_rejects_undersized_header() {
        // 15 bytes clears the old `< 12` gate but is shorter than the mandatory
        // magic(4) + 3 minimum-size varints(3) + footer(12) = 19 bytes a
        // well-formed BPS patch requires. Under the old bound, footer_start
        // (len-12=3) would undercut the 4-byte magic, letting header bytes
        // double as footer bytes instead of being rejected outright.
        let p = vec![0u8; 15];
        let err = import_bps(&p, b"").unwrap_err();
        assert!(err.to_string().contains("too short"), "got {err}");
    }

    #[test]
    fn test_validate_bps_bad_magic() {
        let mut p = vec![0u8; 19];
        p[..4].copy_from_slice(b"XPS1");
        let err = import_bps(&p, b"src").unwrap_err();
        assert!(err.to_string().contains("not a BPS1 patch"), "got {err}");
    }

    #[test]
    fn test_validate_bps_patch_crc_mismatch() {
        let mut p = export_bps(b"source", b"target").unwrap();
        p[6] ^= 0xFF; // corrupt a body byte, leave the trailing patch CRC intact
        let err = import_bps(&p, b"source").unwrap_err();
        assert!(
            err.to_string().contains("patch CRC32 mismatch"),
            "got {err}"
        );
    }

    #[test]
    fn test_validate_bps_source_crc_mismatch() {
        let p = export_bps(b"source", b"target").unwrap();
        let err = import_bps(&p, b"a completely different source").unwrap_err();
        assert!(
            err.to_string().contains("source CRC32 mismatch"),
            "got {err}"
        );
    }

    #[test]
    fn test_import_bps_target_crc_mismatch() {
        let mut p = export_bps(b"source", b"target").unwrap();
        let fs = p.len() - 12;
        p[fs + 4] ^= 0xFF; // corrupt the stored target CRC
        let body_len = p.len() - 4;
        let new_crc = crc32_compute(&p[..body_len]);
        p[body_len..].copy_from_slice(&new_crc.to_le_bytes());
        let err = import_bps(&p, b"source").unwrap_err();
        assert!(
            err.to_string().contains("target CRC32 mismatch"),
            "got {err}"
        );
    }

    #[test]
    fn test_import_bps_skips_nonzero_metadata() {
        // TargetRead of the whole 5-byte target, behind 2 metadata bytes.
        let target = b"HELLO";
        let mut actions = Vec::new();
        let action: u64 = ((5 - 1) << 2) | 1; // command 1 (TargetRead), length 5
        actions.extend_from_slice(&encode_var_int(action));
        actions.extend_from_slice(target);
        let patch = assemble_bps(b"", target, &[0xAA, 0xBB], &actions);
        let decoded = import_bps(&patch, b"").unwrap();
        assert_eq!(decoded, target);
    }

    #[test]
    fn test_apply_target_copy_self_referential_rle() {
        // TargetRead one byte, then TargetCopy from offset 0 length 3 -> RLE fill.
        let target = [0xABu8, 0xAB, 0xAB, 0xAB];
        let mut actions = Vec::new();
        actions.extend_from_slice(&encode_var_int(1)); // TargetRead len 1 -> action 1
        actions.push(0xAB);
        actions.extend_from_slice(&encode_var_int(((3 - 1) << 2) | 3)); // TargetCopy len 3
        actions.extend_from_slice(&encode_var_int(encode_rel_offset(0))); // delta 0 -> tgt_start 0
        let patch = assemble_bps(b"", &target, &[], &actions);
        let decoded = import_bps(&patch, b"").unwrap();
        assert_eq!(decoded, target);
    }

    #[test]
    fn test_apply_source_copy_backward_negative_offset() {
        // Two source copies: forward to offset 4, then a backward delta to offset 0.
        let source = b"ABCDEFGH";
        let target = b"EFGHABCD";
        let mut actions = Vec::new();
        actions.extend_from_slice(&encode_var_int(((4 - 1) << 2) | 2)); // SourceCopy len 4
        actions.extend_from_slice(&encode_var_int(encode_rel_offset(4))); // +4
        actions.extend_from_slice(&encode_var_int(((4 - 1) << 2) | 2)); // SourceCopy len 4
        actions.extend_from_slice(&encode_var_int(encode_rel_offset(-8))); // -8 (backward)
        let patch = assemble_bps(source, target, &[], &actions);
        let decoded = import_bps(&patch, source).unwrap();
        assert_eq!(&decoded, target);
    }

    #[test]
    fn test_export_ups_unequal_lengths_roundtrip() {
        // Source longer than target: target zero-fill branch.
        let s1 = b"ABCDEFGH";
        let t1 = b"XY";
        let p1 = export_ups(s1, t1).unwrap();
        assert_eq!(&import_ups(&p1, s1).unwrap(), t1);
        // Target longer than source: source zero-fill branch.
        let s2 = b"XY";
        let t2 = b"ABCDEFGH";
        let p2 = export_ups(s2, t2).unwrap();
        assert_eq!(&import_ups(&p2, s2).unwrap(), t2);
    }

    #[test]
    fn test_validate_ups_too_short() {
        let err = import_ups(&[0u8; 10], b"src").unwrap_err();
        assert!(err.to_string().contains("too short"), "got {err}");
    }

    fn assemble_ups(source: &[u8], target_len: usize, records: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(b"UPS1");
        body.extend_from_slice(&encode_var_int(source.len() as u64));
        body.extend_from_slice(&encode_var_int(target_len as u64));
        body.extend_from_slice(records);
        body.extend_from_slice(&crc32_compute(source).to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        let pc = crc32_compute(&body);
        body.extend_from_slice(&pc.to_le_bytes());
        body
    }

    #[test]
    fn test_import_ups_offset_accumulation_overflow_rejected() {
        // First record's immediate terminator advances offset to 1; the
        // second record's rel_offset is u64::MAX, so accumulating it onto
        // the running usize offset overflows. Without checked_add this
        // panics in a debug build instead of returning a clean io::Error.
        let source: &[u8] = b"";
        let mut records = Vec::new();
        records.extend_from_slice(&encode_var_int(0)); // rel_offset 0
        records.push(0x00); // immediate terminator -> offset becomes 1
        records.extend_from_slice(&encode_var_int(u64::MAX)); // overflowing rel_offset
        let patch = assemble_ups(source, 4, &records);
        let err = import_ups(&patch, source).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("offset overflow"),
            "expected the offset-accumulation overflow guard to fire, got: {err}"
        );
    }

    #[test]
    fn test_validate_ups_min_length_rejects_undersized_header() {
        // 15 bytes clears the old `< 16` gate but is shorter than the mandatory
        // magic(4) + 2 minimum-size varints(2) + footer(12) = 18 bytes a
        // well-formed UPS patch requires.
        let p = vec![0u8; 15];
        let err = import_ups(&p, b"").unwrap_err();
        assert!(err.to_string().contains("too short"), "got {err}");
    }

    #[test]
    fn test_validate_ups_bad_magic() {
        let mut p = vec![0u8; 20];
        p[..4].copy_from_slice(b"XPS1");
        let err = import_ups(&p, b"src").unwrap_err();
        assert!(err.to_string().contains("not a UPS1 patch"), "got {err}");
    }

    #[test]
    fn test_validate_ups_patch_crc_mismatch() {
        let mut p = export_ups(b"ABCDEFGH", b"AbCdEfGh").unwrap();
        p[6] ^= 0xFF;
        let err = import_ups(&p, b"ABCDEFGH").unwrap_err();
        assert!(
            err.to_string().contains("patch CRC32 mismatch"),
            "got {err}"
        );
    }

    #[test]
    fn test_validate_ups_source_crc_mismatch() {
        let p = export_ups(b"ABCDEFGH", b"AbCdEfGh").unwrap();
        let err = import_ups(&p, b"different source data here").unwrap_err();
        assert!(
            err.to_string().contains("source CRC32 mismatch"),
            "got {err}"
        );
    }

    #[test]
    fn test_import_ups_target_crc_mismatch() {
        let mut p = export_ups(b"ABCDEFGH", b"AbCdEfGh").unwrap();
        let fs = p.len() - 12;
        p[fs + 4] ^= 0xFF; // corrupt stored target CRC
        let body_len = p.len() - 4;
        let new_crc = crc32_compute(&p[..body_len]);
        p[body_len..].copy_from_slice(&new_crc.to_le_bytes());
        let err = import_ups(&p, b"ABCDEFGH").unwrap_err();
        assert!(
            err.to_string().contains("target CRC32 mismatch"),
            "got {err}"
        );
    }

    #[test]
    fn test_apply_target_read_oob() {
        // TargetRead length 5 but the reconstructed target is only 2 bytes.
        let mut actions = Vec::new();
        actions.extend_from_slice(&encode_var_int(((5 - 1) << 2) | 1)); // TargetRead len 5
        actions.extend_from_slice(&[0x41; 5]);
        let patch = assemble_bps(b"", b"AB", &[], &actions);
        let err = import_bps(&patch, b"").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("TargetRead") && msg.contains("OOB"),
            "got {msg}"
        );
    }

    #[test]
    fn test_export_bps_source_shorter_than_match_window() {
        // Source shorter than the 4-byte hash window -> build_hash_index returns empty early.
        let patch = export_bps(b"ab", b"abcd").unwrap();
        assert_eq!(import_bps(&patch, b"ab").unwrap(), b"abcd");
    }

    #[test]
    fn test_export_ups_trailing_zero_matches_outer_loop() {
        // Longer buffer's trailing bytes are zero and match the shorter one, so the outer
        // loop (not the inner diff loop) reads past the shorter length via the zero-fill.
        let src = [0x41u8, 0x42, 0x00, 0x00];
        let tgt = [0x41u8, 0x42];
        let p = export_ups(&src, &tgt).unwrap();
        assert_eq!(import_ups(&p, &src).unwrap(), tgt.to_vec());

        let src2 = [0x41u8, 0x42];
        let tgt2 = [0x41u8, 0x42, 0x00, 0x00];
        let p2 = export_ups(&src2, &tgt2).unwrap();
        assert_eq!(import_ups(&p2, &src2).unwrap(), tgt2.to_vec());
    }

    #[test]
    fn test_apply_source_copy_negative_rel_offset_underflow() {
        // A backward delta drives source_rel_offset below zero, so usize::try_from fails.
        let source = b"ABCDEFGH";
        let mut actions = Vec::new();
        actions.extend_from_slice(&encode_var_int(((4 - 1) << 2) | 2)); // SourceCopy len 4
        actions.extend_from_slice(&encode_var_int(encode_rel_offset(-1)));
        let patch = assemble_bps(source, &[0u8; 4], &[], &actions);
        let err = import_bps(&patch, source).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("SourceCopy") && msg.contains("OOB"),
            "got {msg}"
        );
    }

    #[test]
    fn test_apply_target_copy_negative_rel_offset_underflow() {
        // A backward delta drives target_rel_offset below zero, so usize::try_from fails.
        let mut actions = Vec::new();
        actions.extend_from_slice(&encode_var_int(((4 - 1) << 2) | 3)); // TargetCopy len 4
        actions.extend_from_slice(&encode_var_int(encode_rel_offset(-1)));
        let patch = assemble_bps(b"", &[0u8; 4], &[], &actions);
        let err = import_bps(&patch, b"").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("TargetCopy") && msg.contains("OOB"),
            "got {msg}"
        );
    }

    #[test]
    fn test_apply_source_copy_offset_accumulation_overflow_rejected() {
        // First SourceCopy leaves source_rel_offset at a small value (4); the
        // second SourceCopy's delta is i64::MAX, so accumulating it onto the
        // running offset overflows i64::MAX. Without checked_add this panics
        // in a debug build (Rust's default overflow-checks) instead of
        // returning a clean io::Error -- unwrap_err() below would itself
        // panic on a raw `+=` regression, failing the test either way.
        let source = vec![0u8; 8];
        let mut actions = Vec::new();
        actions.extend_from_slice(&encode_var_int(((4 - 1) << 2) | 2)); // SourceCopy len 4
        actions.extend_from_slice(&encode_var_int(encode_rel_offset(4))); // delta +4
        actions.extend_from_slice(&encode_var_int(((4 - 1) << 2) | 2)); // SourceCopy len 4
        actions.extend_from_slice(&encode_var_int(encode_rel_offset(i64::MAX))); // overflowing delta
        let patch = assemble_bps(&source, &[0u8; 8], &[], &actions);
        let err = import_bps(&patch, &source).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("source copy offset overflow"),
            "expected the offset-accumulation overflow guard to fire, got: {err}"
        );
    }

    #[test]
    fn test_apply_target_copy_offset_accumulation_overflow_rejected() {
        // TargetRead establishes output_offset=1, a TargetCopy with delta 0
        // leaves target_rel_offset at 1, then a second TargetCopy with delta
        // i64::MAX overflows the accumulating add.
        let target = [0u8; 8];
        let mut actions = Vec::new();
        actions.extend_from_slice(&encode_var_int(1)); // TargetRead len 1 -> action 1
        actions.push(0xAB);
        actions.extend_from_slice(&encode_var_int(action_header(3, 1))); // TargetCopy len 1
        actions.extend_from_slice(&encode_var_int(encode_rel_offset(0))); // delta 0
        actions.extend_from_slice(&encode_var_int(action_header(3, 1))); // TargetCopy len 1
        actions.extend_from_slice(&encode_var_int(encode_rel_offset(i64::MAX))); // overflowing delta
        let patch = assemble_bps(b"", &target, &[], &actions);
        let err = import_bps(&patch, b"").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("target copy offset overflow"),
            "expected the offset-accumulation overflow guard to fire, got: {err}"
        );
    }

    #[test]
    fn test_export_bps_partial_key_match_diverges() {
        // "WXYZ" is indexed at two source positions; both diverge on the next byte, so
        // find_best_match evaluates the first candidate (improve, no break -> fall through
        // line 157), then loops to the second candidate.
        let mut source = b"WXYZ".to_vec();
        source.extend(vec![0x11u8; 4]);
        source.extend_from_slice(b"WXYZ");
        source.extend(vec![0x33u8; 12]);
        let mut target = b"WXYZ".to_vec();
        target.extend(vec![0x22u8; 20]);
        let patch = export_bps(&source, &target).unwrap();
        assert_eq!(import_bps(&patch, &source).unwrap(), target);
    }

    #[test]
    fn test_patch_contains_command_full_scan_source_read() {
        // A near-identical file yields SourceRead/TargetRead commands; searching for an
        // absent TargetCopy forces the helper to scan every record and return false.
        let source = b"HELLO WORLD THIS IS A LONGER TEST BUFFER FOR BPS";
        let mut target = source.to_vec();
        target[10] = b'!';
        let patch = export_bps(source, &target).unwrap();
        assert!(!patch_contains_command(&patch, 3));
        // Sanity: the patch still round-trips.
        assert_eq!(import_bps(&patch, source).unwrap(), target);
    }

    const HUGE_TARGET_SIZE: u64 = 1 << 40;

    /// Rewrites the target-size field of a real BPS or UPS patch to
    /// `HUGE_TARGET_SIZE` and repairs the trailing patch CRC32.
    ///
    /// Both formats place the target-size varint directly after the 4-byte
    /// magic and the source-size varint, and both end with a CRC32 over
    /// everything preceding it, so the same surgery applies to each. The
    /// existing field's extent is located with the production `decode_var_int`
    /// rather than assumed, so this follows any change to the encoding.
    fn splice_huge_target_size(patch: &[u8], source_len: usize) -> Vec<u8> {
        let field_start = 4 + encode_var_int(source_len as u64).len();
        let mut field_end = field_start;
        decode_var_int(patch, &mut field_end).expect("patch must carry a target-size varint");

        let mut spliced = Vec::with_capacity(patch.len());
        spliced.extend_from_slice(&patch[..field_start]);
        spliced.extend_from_slice(&encode_var_int(HUGE_TARGET_SIZE));
        spliced.extend_from_slice(&patch[field_end..]);

        let body_len = spliced.len() - 4;
        let repaired_crc = crc32_compute(&spliced[..body_len]);
        spliced[body_len..].copy_from_slice(&repaired_crc.to_le_bytes());
        spliced
    }

    #[test]
    fn test_import_bps_oom_returns_err() {
        let source = b"test_source";
        let target = b"test_target";
        let patch = export_bps(source, target).unwrap();

        // Precondition: the unmutated patch applies cleanly, so an error below
        // cannot be a malformed-patch rejection masquerading as the OOM guard.
        assert_eq!(import_bps(&patch, source).unwrap(), target);

        let oversized = splice_huge_target_size(&patch, source.len());
        let err = import_bps(&oversized, source).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::OutOfMemory);
    }

    #[test]
    fn test_import_ups_oom_returns_err() {
        let source = b"test_source";
        let target = b"test_target";
        let patch = export_ups(source, target).unwrap();

        assert_eq!(import_ups(&patch, source).unwrap(), target);

        let oversized = splice_huge_target_size(&patch, source.len());
        let err = import_ups(&oversized, source).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::OutOfMemory);
    }
}
