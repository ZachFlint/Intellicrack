use serde::{Deserialize, Serialize};
use thiserror::Error;

const IPS_TERMINATOR_OFFSET: usize = 0x0045_4F46;
const IPS32_TERMINATOR_OFFSET: usize = 0x4545_4F46;

#[derive(Error, Debug)]
pub enum PatchError {
    #[error("invalid IPS data: {0}")]
    InvalidIps(String),
    #[error("patch too large for IPS format (offset > 0xFFFFFF)")]
    PatchTooLarge,
}

#[derive(Debug, Clone)]
pub struct PatchRecord {
    pub offset: usize,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonPatchEntry {
    offset: u64,
    data: String,
}

/// Exports patch records in IPS format (24-bit offsets).
///
/// # Errors
///
/// Returns `PatchError::PatchTooLarge` if any patch offset exceeds `0x00FF_FFFF`.
pub fn export_ips(patches: &[PatchRecord]) -> Result<Vec<u8>, PatchError> {
    let mut output = Vec::new();
    output.extend_from_slice(b"PATCH");

    for patch in patches {
        if patch.offset > 0x00FF_FFFF {
            return Err(PatchError::PatchTooLarge);
        }
        let mut remaining = patch.data.as_slice();
        let mut current_offset = patch.offset;

        while !remaining.is_empty() {
            if current_offset > 0x00FF_FFFF {
                return Err(PatchError::PatchTooLarge);
            }
            let mut chunk_size = remaining.len().min(0xFFFF);

            if current_offset == IPS_TERMINATOR_OFFSET {
                let prev_offset = IPS_TERMINATOR_OFFSET - 1;
                let merged_len = (chunk_size + 1).min(0xFFFF);
                let offset_bytes = prev_offset.to_be_bytes();
                let offset_start = offset_bytes.len() - 3;
                output.extend_from_slice(&offset_bytes[offset_start..]);
                let size_bytes = merged_len.to_be_bytes();
                let size_start = size_bytes.len() - 2;
                output.extend_from_slice(&size_bytes[size_start..]);
                output.push(0x00);
                let consumed = merged_len - 1;
                output.extend_from_slice(&remaining[..consumed]);
                remaining = &remaining[consumed..];
                current_offset += consumed;
                continue;
            }

            if current_offset < IPS_TERMINATOR_OFFSET
                && current_offset + chunk_size > IPS_TERMINATOR_OFFSET
            {
                let span_through = IPS_TERMINATOR_OFFSET + 1 - current_offset;
                if span_through <= 0xFFFF && span_through <= remaining.len() {
                    chunk_size = span_through;
                } else {
                    chunk_size = IPS_TERMINATOR_OFFSET - current_offset;
                }
            }

            let offset_bytes = current_offset.to_be_bytes();
            let offset_start = offset_bytes.len() - 3;
            output.extend_from_slice(&offset_bytes[offset_start..]);
            let size_bytes = chunk_size.to_be_bytes();
            let size_start = size_bytes.len() - 2;
            output.extend_from_slice(&size_bytes[size_start..]);
            output.extend_from_slice(&remaining[..chunk_size]);
            remaining = &remaining[chunk_size..];
            current_offset += chunk_size;
        }
    }

    output.extend_from_slice(b"EOF");
    Ok(output)
}

/// Exports patch records in IPS32 format (32-bit offsets).
///
/// # Errors
///
/// Returns `PatchError` if the export fails.
pub fn export_ips32(patches: &[PatchRecord]) -> Result<Vec<u8>, PatchError> {
    let mut output = Vec::new();
    output.extend_from_slice(b"IPS32");

    for patch in patches {
        let mut remaining = patch.data.as_slice();
        let mut current_offset = patch.offset;

        while !remaining.is_empty() {
            let mut chunk_size = remaining.len().min(0xFFFF);

            if current_offset == IPS32_TERMINATOR_OFFSET {
                let prev_offset = IPS32_TERMINATOR_OFFSET - 1;
                let merged_len = (chunk_size + 1).min(0xFFFF);
                let offset_bytes = prev_offset.to_be_bytes();
                let offset_start = offset_bytes.len() - 4;
                output.extend_from_slice(&offset_bytes[offset_start..]);
                let size_bytes = merged_len.to_be_bytes();
                let size_start = size_bytes.len() - 2;
                output.extend_from_slice(&size_bytes[size_start..]);
                output.push(0x00);
                let consumed = merged_len - 1;
                output.extend_from_slice(&remaining[..consumed]);
                remaining = &remaining[consumed..];
                current_offset += consumed;
                continue;
            }

            if current_offset < IPS32_TERMINATOR_OFFSET
                && current_offset + chunk_size > IPS32_TERMINATOR_OFFSET
            {
                let span_through = IPS32_TERMINATOR_OFFSET + 1 - current_offset;
                if span_through <= 0xFFFF && span_through <= remaining.len() {
                    chunk_size = span_through;
                } else {
                    chunk_size = IPS32_TERMINATOR_OFFSET - current_offset;
                }
            }

            let offset_bytes = current_offset.to_be_bytes();
            let offset_start = offset_bytes.len() - 4;
            output.extend_from_slice(&offset_bytes[offset_start..]);
            let size_bytes = chunk_size.to_be_bytes();
            let size_start = size_bytes.len() - 2;
            output.extend_from_slice(&size_bytes[size_start..]);
            output.extend_from_slice(&remaining[..chunk_size]);
            remaining = &remaining[chunk_size..];
            current_offset += chunk_size;
        }
    }

    output.extend_from_slice(b"EEOF");
    Ok(output)
}

/// Exports patch records in COD format.
///
/// Each record is serialized as a 4-byte big-endian offset followed by a
/// 4-byte big-endian length and then the raw patch bytes. No header or
/// terminator is emitted. Offsets greater than `u32::MAX` are truncated to
/// the low 32 bits; callers should prefer IPS32 for offsets beyond that
/// range.
#[must_use]
pub fn export_cod(records: &[PatchRecord]) -> Vec<u8> {
    let mut output = Vec::new();
    for record in records {
        let offset_u32 = u32::try_from(record.offset).unwrap_or(u32::MAX);
        let length_u32 = u32::try_from(record.data.len()).unwrap_or(u32::MAX);
        output.extend_from_slice(&offset_u32.to_be_bytes());
        output.extend_from_slice(&length_u32.to_be_bytes());
        output.extend_from_slice(&record.data);
    }
    output
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

/// Exports patch records as pretty-printed JSON.
///
/// Each record is represented as an object with a `u64` `offset` field and a
/// lowercase hex-encoded `data` string. The resulting JSON is stable and
/// suitable for external tooling or diffing.
///
/// # Errors
///
/// Returns a `serde_json::Error` if serialization fails. Serialization of the
/// owned `Vec<JsonPatchEntry>` does not fail in practice, but the error is
/// surfaced to keep the API forward-compatible.
pub fn export_patches_json(records: &[PatchRecord]) -> Result<String, serde_json::Error> {
    let entries: Vec<JsonPatchEntry> = records
        .iter()
        .map(|r| JsonPatchEntry {
            offset: r.offset as u64,
            data: encode_hex(&r.data),
        })
        .collect();
    serde_json::to_string_pretty(&entries)
}

/// Imports patch records from IPS or IPS32 format data.
///
/// # Errors
///
/// Returns `PatchError::InvalidIps` if the data has an invalid header, is truncated,
/// or is otherwise malformed.
pub fn import_ips(data: &[u8]) -> Result<Vec<PatchRecord>, PatchError> {
    if data.len() < 5 {
        return Err(PatchError::InvalidIps("data too short".to_string()));
    }

    if &data[..5] == b"IPS32" {
        return import_ips32_inner(data);
    }

    if &data[..5] != b"PATCH" {
        return Err(PatchError::InvalidIps(
            "invalid header (expected PATCH or IPS32)".to_string(),
        ));
    }

    let mut records = Vec::new();
    let mut pos = 5;

    loop {
        if pos + 3 > data.len() {
            return Err(PatchError::InvalidIps("unexpected end of data".to_string()));
        }

        if &data[pos..pos + 3] == b"EOF" {
            break;
        }

        if pos + 5 > data.len() {
            return Err(PatchError::InvalidIps(
                "truncated record header".to_string(),
            ));
        }

        let offset = ((data[pos] as usize) << 16)
            | ((data[pos + 1] as usize) << 8)
            | (data[pos + 2] as usize);
        let size = ((data[pos + 3] as usize) << 8) | (data[pos + 4] as usize);
        pos += 5;

        if size == 0 {
            if pos + 3 > data.len() {
                return Err(PatchError::InvalidIps("truncated RLE record".to_string()));
            }
            let rle_count = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
            let rle_value = data[pos + 2];
            pos += 3;
            records.push(PatchRecord {
                offset,
                data: vec![rle_value; rle_count],
            });
        } else {
            if pos + size > data.len() {
                return Err(PatchError::InvalidIps("truncated record data".to_string()));
            }
            records.push(PatchRecord {
                offset,
                data: data[pos..pos + size].to_vec(),
            });
            pos += size;
        }
    }

    Ok(records)
}

fn import_ips32_inner(data: &[u8]) -> Result<Vec<PatchRecord>, PatchError> {
    let mut records = Vec::new();
    let mut pos = 5;

    loop {
        if pos + 4 > data.len() {
            return Err(PatchError::InvalidIps(
                "unexpected end of IPS32 data".to_string(),
            ));
        }

        if &data[pos..pos + 4] == b"EEOF" {
            break;
        }

        if pos + 6 > data.len() {
            return Err(PatchError::InvalidIps(
                "truncated IPS32 record header".to_string(),
            ));
        }

        let offset = ((data[pos] as usize) << 24)
            | ((data[pos + 1] as usize) << 16)
            | ((data[pos + 2] as usize) << 8)
            | (data[pos + 3] as usize);
        let size = ((data[pos + 4] as usize) << 8) | (data[pos + 5] as usize);
        pos += 6;

        if size == 0 {
            if pos + 3 > data.len() {
                return Err(PatchError::InvalidIps(
                    "truncated IPS32 RLE record".to_string(),
                ));
            }
            let rle_count = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
            let rle_value = data[pos + 2];
            pos += 3;
            records.push(PatchRecord {
                offset,
                data: vec![rle_value; rle_count],
            });
        } else {
            if pos + size > data.len() {
                return Err(PatchError::InvalidIps(
                    "truncated IPS32 record data".to_string(),
                ));
            }
            records.push(PatchRecord {
                offset,
                data: data[pos..pos + size].to_vec(),
            });
            pos += size;
        }
    }

    Ok(records)
}

#[must_use]
pub fn extract_patches_from_overwrites(operations: &[(usize, Vec<u8>)]) -> Vec<PatchRecord> {
    if operations.is_empty() {
        return Vec::new();
    }

    let mut sorted: Vec<(usize, &[u8])> =
        operations.iter().map(|(o, d)| (*o, d.as_slice())).collect();
    sorted.sort_by_key(|(offset, _)| *offset);

    let mut merged: Vec<PatchRecord> = Vec::new();

    for (offset, data) in sorted {
        if let Some(last) = merged.last_mut() {
            let last_end = last.offset + last.data.len();
            if offset <= last_end {
                let overlap_start = offset.saturating_sub(last.offset);
                if offset >= last.offset {
                    if offset + data.len() > last.offset + last.data.len() {
                        let extend_start = last.data.len().saturating_sub(overlap_start);
                        if extend_start < data.len() {
                            last.data.extend_from_slice(&data[extend_start..]);
                        }
                    }
                    let copy_len = data.len().min(last.data.len() - overlap_start);
                    last.data[overlap_start..overlap_start + copy_len]
                        .copy_from_slice(&data[..copy_len]);
                }
                continue;
            }
        }
        merged.push(PatchRecord {
            offset,
            data: data.to_vec(),
        });
    }

    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ips_roundtrip() {
        let patches = vec![
            PatchRecord {
                offset: 0x100,
                data: vec![0x41, 0x42, 0x43],
            },
            PatchRecord {
                offset: 0x200,
                data: vec![0x90, 0x90],
            },
        ];
        let exported = export_ips(&patches).unwrap();
        assert!(exported.starts_with(b"PATCH"));
        assert!(exported.ends_with(b"EOF"));

        let imported = import_ips(&exported).unwrap();
        assert_eq!(imported.len(), 2);
        assert_eq!(imported[0].offset, 0x100);
        assert_eq!(imported[0].data, vec![0x41, 0x42, 0x43]);
        assert_eq!(imported[1].offset, 0x200);
        assert_eq!(imported[1].data, vec![0x90, 0x90]);
    }

    #[test]
    fn test_ips32_roundtrip() {
        let patches = vec![PatchRecord {
            offset: 0x0100_0000,
            data: vec![0xDE, 0xAD],
        }];
        let exported = export_ips32(&patches).unwrap();
        assert!(exported.starts_with(b"IPS32"));
        assert!(exported.ends_with(b"EEOF"));

        let imported = import_ips(&exported).unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].offset, 0x0100_0000);
        assert_eq!(imported[0].data, vec![0xDE, 0xAD]);
    }

    #[test]
    fn test_ips_offset_too_large() {
        let patches = vec![PatchRecord {
            offset: 0x0100_0000,
            data: vec![0x00],
        }];
        assert!(export_ips(&patches).is_err());
    }

    #[test]
    fn test_empty_patches() {
        let exported = export_ips(&[]).unwrap();
        assert_eq!(exported, b"PATCHEOF");
        let imported = import_ips(&exported).unwrap();
        assert!(imported.is_empty());
    }

    #[test]
    fn test_invalid_header() {
        assert!(import_ips(b"NOTIP").is_err());
    }

    #[test]
    fn test_extract_patches_merging() {
        let ops = vec![(10, vec![0x41, 0x42]), (12, vec![0x43, 0x44])];
        let merged = extract_patches_from_overwrites(&ops);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].offset, 10);
        assert_eq!(merged[0].data, vec![0x41, 0x42, 0x43, 0x44]);
    }

    #[test]
    fn test_extract_patches_no_overlap() {
        let ops = vec![(10, vec![0x41]), (20, vec![0x42])];
        let merged = extract_patches_from_overwrites(&ops);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn test_extract_patches_empty() {
        let merged = extract_patches_from_overwrites(&[]);
        assert!(merged.is_empty());
    }

    #[test]
    fn test_export_cod_single_record() {
        let patches = vec![PatchRecord {
            offset: 0x1234_5678,
            data: vec![0xAA, 0xBB, 0xCC],
        }];
        let out = export_cod(&patches);
        assert_eq!(
            out,
            vec![0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC]
        );
    }

    #[test]
    fn test_export_cod_multiple_records() {
        let patches = vec![
            PatchRecord {
                offset: 0x0000_0001,
                data: vec![0x11],
            },
            PatchRecord {
                offset: 0x0000_FF00,
                data: vec![0x22, 0x33],
            },
        ];
        let out = export_cod(&patches);
        assert_eq!(
            out,
            vec![
                0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x11, 0x00, 0x00, 0xFF, 0x00, 0x00,
                0x00, 0x00, 0x02, 0x22, 0x33,
            ]
        );
    }

    #[test]
    fn test_export_cod_empty() {
        assert!(export_cod(&[]).is_empty());
    }

    #[test]
    fn test_export_patches_json_single_record() {
        let patches = vec![PatchRecord {
            offset: 0x100,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        }];
        let json = export_patches_json(&patches).unwrap();
        let parsed: Vec<JsonPatchEntry> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].offset, 0x100);
        assert_eq!(parsed[0].data, "deadbeef");
    }

    #[test]
    fn test_export_patches_json_empty() {
        let json = export_patches_json(&[]).unwrap();
        assert_eq!(json.trim(), "[]");
    }

    #[test]
    fn test_export_patches_json_is_pretty() {
        let patches = vec![PatchRecord {
            offset: 1,
            data: vec![0x01],
        }];
        let json = export_patches_json(&patches).unwrap();
        assert!(json.contains('\n'));
    }

    #[test]
    fn test_ips_collision_no_record_at_terminator_offset() {
        let patches = vec![PatchRecord {
            offset: IPS_TERMINATOR_OFFSET,
            data: vec![0x11, 0x22, 0x33],
        }];
        let exported = export_ips(&patches).unwrap();

        let header_end = exported.len() - 3;
        let body = &exported[5..header_end];
        assert!(!contains_header_with_offset_3(body, IPS_TERMINATOR_OFFSET));
    }

    #[test]
    fn test_ips_collision_spanning_terminator_offset() {
        let patches = vec![PatchRecord {
            offset: IPS_TERMINATOR_OFFSET - 2,
            data: vec![0xAA, 0xBB, 0xCC, 0xDD],
        }];
        let exported = export_ips(&patches).unwrap();
        let header_end = exported.len() - 3;
        let body = &exported[5..header_end];
        assert!(!contains_header_with_offset_3(body, IPS_TERMINATOR_OFFSET));

        let imported = import_ips(&exported).unwrap();
        let mut reconstructed = vec![0u8; IPS_TERMINATOR_OFFSET + 4];
        for rec in &imported {
            reconstructed[rec.offset..rec.offset + rec.data.len()].copy_from_slice(&rec.data);
        }
        assert_eq!(
            &reconstructed[IPS_TERMINATOR_OFFSET - 2..IPS_TERMINATOR_OFFSET + 2],
            &[0xAA, 0xBB, 0xCC, 0xDD]
        );
    }

    #[test]
    fn test_ips32_collision_no_record_at_terminator_offset() {
        let patches = vec![PatchRecord {
            offset: IPS32_TERMINATOR_OFFSET,
            data: vec![0x11, 0x22, 0x33],
        }];
        let exported = export_ips32(&patches).unwrap();
        let header_end = exported.len() - 4;
        let body = &exported[5..header_end];
        assert!(!contains_header_with_offset_4(
            body,
            IPS32_TERMINATOR_OFFSET
        ));
    }

    #[test]
    fn test_ips32_collision_roundtrip() {
        let patches = vec![PatchRecord {
            offset: IPS32_TERMINATOR_OFFSET,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        }];
        let exported = export_ips32(&patches).unwrap();
        let header_end = exported.len() - 4;
        let body = &exported[5..header_end];
        assert!(!contains_header_with_offset_4(
            body,
            IPS32_TERMINATOR_OFFSET
        ));

        let imported = import_ips(&exported).unwrap();

        let mut reconstructed = vec![0u8; IPS32_TERMINATOR_OFFSET + 5];
        for rec in &imported {
            reconstructed[rec.offset..rec.offset + rec.data.len()].copy_from_slice(&rec.data);
        }
        assert_eq!(
            &reconstructed[IPS32_TERMINATOR_OFFSET..IPS32_TERMINATOR_OFFSET + 4],
            &[0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    fn contains_header_with_offset_3(body: &[u8], offset: usize) -> bool {
        let target = [
            ((offset >> 16) & 0xFF) as u8,
            ((offset >> 8) & 0xFF) as u8,
            (offset & 0xFF) as u8,
        ];
        let mut pos = 0;
        while pos + 5 <= body.len() {
            if body[pos..pos + 3] == target {
                return true;
            }
            let size = ((body[pos + 3] as usize) << 8) | (body[pos + 4] as usize);
            let step = if size == 0 { 5 + 3 } else { 5 + size };
            pos += step;
        }
        false
    }

    fn contains_header_with_offset_4(body: &[u8], offset: usize) -> bool {
        let target = [
            ((offset >> 24) & 0xFF) as u8,
            ((offset >> 16) & 0xFF) as u8,
            ((offset >> 8) & 0xFF) as u8,
            (offset & 0xFF) as u8,
        ];
        let mut pos = 0;
        while pos + 6 <= body.len() {
            if body[pos..pos + 4] == target {
                return true;
            }
            let size = ((body[pos + 4] as usize) << 8) | (body[pos + 5] as usize);
            let step = if size == 0 { 6 + 3 } else { 6 + size };
            pos += step;
        }
        false
    }
}
