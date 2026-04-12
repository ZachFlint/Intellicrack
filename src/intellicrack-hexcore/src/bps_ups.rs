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
        result += ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 != 0 {
            return Ok(result);
        }
        shift += 7;
        result += 1u64 << shift;
        if shift > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "variable-length integer overflow",
            ));
        }
    }
}

/// Generate a BPS patch from source and target byte arrays.
///
/// Uses SourceRead and TargetRead actions for a simple but correct patch.
/// Footer contains source CRC32, target CRC32, and patch CRC32.
pub fn export_bps(source: &[u8], target: &[u8]) -> io::Result<Vec<u8>> {
    let mut patch = Vec::new();

    patch.extend_from_slice(b"BPS1");
    patch.extend_from_slice(&encode_var_int(source.len() as u64));
    patch.extend_from_slice(&encode_var_int(target.len() as u64));
    patch.extend_from_slice(&encode_var_int(0)); // metadata size

    let mut src_pos: usize = 0;
    let mut tgt_pos: usize = 0;

    while tgt_pos < target.len() {
        let mut match_len: usize = 0;
        while src_pos + match_len < source.len()
            && tgt_pos + match_len < target.len()
            && source[src_pos + match_len] == target[tgt_pos + match_len]
        {
            match_len += 1;
        }

        if match_len > 0 {
            // SourceRead: action = ((length-1) << 2) | 0
            patch.extend_from_slice(&encode_var_int(((match_len as u64) - 1) << 2));
            src_pos += match_len;
            tgt_pos += match_len;
        }

        if tgt_pos >= target.len() {
            break;
        }

        // Find how many bytes differ
        let mut diff_len: usize = 0;
        while tgt_pos + diff_len < target.len() {
            if src_pos + diff_len < source.len()
                && source[src_pos + diff_len] == target[tgt_pos + diff_len]
            {
                // Check if we have a long enough match ahead to break
                let mut ahead_match = 0;
                while src_pos + diff_len + ahead_match < source.len()
                    && tgt_pos + diff_len + ahead_match < target.len()
                    && source[src_pos + diff_len + ahead_match]
                        == target[tgt_pos + diff_len + ahead_match]
                {
                    ahead_match += 1;
                }
                if ahead_match >= 4 {
                    break;
                }
            }
            diff_len += 1;
            if diff_len >= 256 {
                break;
            }
        }

        if diff_len > 0 {
            // TargetRead: action = ((length-1) << 2) | 1
            patch.extend_from_slice(&encode_var_int((((diff_len as u64) - 1) << 2) | 1));
            patch.extend_from_slice(&target[tgt_pos..tgt_pos + diff_len]);
            src_pos += diff_len;
            tgt_pos += diff_len;
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

/// Apply a BPS patch to the source data, producing the target.
///
/// Validates the BPS1 header, source CRC32, target CRC32, and patch CRC32.
pub fn import_bps(patch: &[u8], source: &[u8]) -> io::Result<Vec<u8>> {
    if patch.len() < 12 {
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

    // Verify patch CRC32 (last 4 bytes cover everything before them)
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
    let metadata_size = decode_var_int(patch, &mut pos)?;
    pos += metadata_size as usize;

    let mut target = vec![0u8; target_size as usize];
    let mut output_offset: usize = 0;
    let mut source_rel_offset: i64 = 0;
    let mut target_rel_offset: i64 = 0;

    while pos < footer_start {
        let action = decode_var_int(patch, &mut pos)?;
        let command = action & 3;
        let length = (action >> 2) as usize + 1;

        match command {
            0 => {
                // SourceRead
                for _ in 0..length {
                    if output_offset < target.len() && output_offset < source.len() {
                        target[output_offset] = source[output_offset];
                    }
                    output_offset += 1;
                }
            }
            1 => {
                // TargetRead
                for _ in 0..length {
                    if pos < footer_start && output_offset < target.len() {
                        target[output_offset] = patch[pos];
                        pos += 1;
                        output_offset += 1;
                    }
                }
            }
            2 => {
                // SourceCopy
                let offset_data = decode_var_int(patch, &mut pos)?;
                let negative = offset_data & 1 != 0;
                let offset_val = (offset_data >> 1) as i64;
                source_rel_offset += if negative { -offset_val } else { offset_val };
                for _ in 0..length {
                    let src_idx = source_rel_offset as usize;
                    if src_idx < source.len() && output_offset < target.len() {
                        target[output_offset] = source[src_idx];
                    }
                    source_rel_offset += 1;
                    output_offset += 1;
                }
            }
            3 => {
                // TargetCopy
                let offset_data = decode_var_int(patch, &mut pos)?;
                let negative = offset_data & 1 != 0;
                let offset_val = (offset_data >> 1) as i64;
                target_rel_offset += if negative { -offset_val } else { offset_val };
                for _ in 0..length {
                    let tgt_idx = target_rel_offset as usize;
                    if tgt_idx < target.len() && output_offset < target.len() {
                        target[output_offset] = target[tgt_idx];
                    }
                    target_rel_offset += 1;
                    output_offset += 1;
                }
            }
            _ => unreachable!(),
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

/// Generate a UPS patch from source and target byte arrays.
///
/// Uses XOR-based difference records terminated by zero bytes.
pub fn export_ups(source: &[u8], target: &[u8]) -> io::Result<Vec<u8>> {
    let mut patch = Vec::new();
    patch.extend_from_slice(b"UPS1");
    patch.extend_from_slice(&encode_var_int(source.len() as u64));
    patch.extend_from_slice(&encode_var_int(target.len() as u64));

    let max_len = source.len().max(target.len());
    let mut write_pos: usize = 0;
    let mut offset: usize = 0;

    while offset < max_len {
        let src_byte = if offset < source.len() { source[offset] } else { 0 };
        let tgt_byte = if offset < target.len() { target[offset] } else { 0 };
        let xor = src_byte ^ tgt_byte;

        if xor != 0 {
            let rel_offset = offset - write_pos;
            patch.extend_from_slice(&encode_var_int(rel_offset as u64));

            while offset < max_len {
                let s = if offset < source.len() { source[offset] } else { 0 };
                let t = if offset < target.len() { target[offset] } else { 0 };
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
pub fn import_ups(patch: &[u8], source: &[u8]) -> io::Result<Vec<u8>> {
    if patch.len() < 16 {
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

    // Verify patch CRC32
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

    let mut target = source.to_vec();
    target.resize(target_size as usize, 0);

    let mut offset: usize = 0;

    while pos < footer_start {
        let rel_offset = decode_var_int(patch, &mut pos)?;
        offset += rel_offset as usize;

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
}
