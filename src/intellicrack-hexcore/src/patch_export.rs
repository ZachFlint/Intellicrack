use thiserror::Error;

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

pub fn export_ips(patches: &[PatchRecord]) -> Result<Vec<u8>, PatchError> {
    let mut output = Vec::new();
    output.extend_from_slice(b"PATCH");

    for patch in patches {
        if patch.offset > 0xFFFFFF {
            return Err(PatchError::PatchTooLarge);
        }
        let mut remaining = patch.data.as_slice();
        let mut current_offset = patch.offset;

        while !remaining.is_empty() {
            if current_offset > 0xFFFFFF {
                return Err(PatchError::PatchTooLarge);
            }
            let chunk_size = remaining.len().min(0xFFFF);
            output.push(((current_offset >> 16) & 0xFF) as u8);
            output.push(((current_offset >> 8) & 0xFF) as u8);
            output.push((current_offset & 0xFF) as u8);
            output.push(((chunk_size >> 8) & 0xFF) as u8);
            output.push((chunk_size & 0xFF) as u8);
            output.extend_from_slice(&remaining[..chunk_size]);
            remaining = &remaining[chunk_size..];
            current_offset += chunk_size;
        }
    }

    output.extend_from_slice(b"EOF");
    Ok(output)
}

pub fn export_ips32(patches: &[PatchRecord]) -> Result<Vec<u8>, PatchError> {
    let mut output = Vec::new();
    output.extend_from_slice(b"IPS32");

    for patch in patches {
        let mut remaining = patch.data.as_slice();
        let mut current_offset = patch.offset;

        while !remaining.is_empty() {
            let chunk_size = remaining.len().min(0xFFFF);
            output.push(((current_offset >> 24) & 0xFF) as u8);
            output.push(((current_offset >> 16) & 0xFF) as u8);
            output.push(((current_offset >> 8) & 0xFF) as u8);
            output.push((current_offset & 0xFF) as u8);
            output.push(((chunk_size >> 8) & 0xFF) as u8);
            output.push((chunk_size & 0xFF) as u8);
            output.extend_from_slice(&remaining[..chunk_size]);
            remaining = &remaining[chunk_size..];
            current_offset += chunk_size;
        }
    }

    output.extend_from_slice(b"EEOF");
    Ok(output)
}

pub fn import_ips(data: &[u8]) -> Result<Vec<PatchRecord>, PatchError> {
    if data.len() < 5 {
        return Err(PatchError::InvalidIps("data too short".to_string()));
    }

    if &data[..5] == b"IPS32" {
        return import_ips32_inner(data);
    }

    if &data[..5] != b"PATCH" {
        return Err(PatchError::InvalidIps("invalid header (expected PATCH or IPS32)".to_string()));
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
            return Err(PatchError::InvalidIps("truncated record header".to_string()));
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
            return Err(PatchError::InvalidIps("unexpected end of IPS32 data".to_string()));
        }

        if &data[pos..pos + 4] == b"EEOF" {
            break;
        }

        if pos + 6 > data.len() {
            return Err(PatchError::InvalidIps("truncated IPS32 record header".to_string()));
        }

        let offset = ((data[pos] as usize) << 24)
            | ((data[pos + 1] as usize) << 16)
            | ((data[pos + 2] as usize) << 8)
            | (data[pos + 3] as usize);
        let size = ((data[pos + 4] as usize) << 8) | (data[pos + 5] as usize);
        pos += 6;

        if size == 0 {
            if pos + 3 > data.len() {
                return Err(PatchError::InvalidIps("truncated IPS32 RLE record".to_string()));
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
                return Err(PatchError::InvalidIps("truncated IPS32 record data".to_string()));
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

pub fn extract_patches_from_overwrites(operations: &[(usize, Vec<u8>)]) -> Vec<PatchRecord> {
    if operations.is_empty() {
        return Vec::new();
    }

    let mut sorted: Vec<(usize, &[u8])> = operations.iter().map(|(o, d)| (*o, d.as_slice())).collect();
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
            PatchRecord { offset: 0x100, data: vec![0x41, 0x42, 0x43] },
            PatchRecord { offset: 0x200, data: vec![0x90, 0x90] },
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
        let patches = vec![
            PatchRecord { offset: 0x1000000, data: vec![0xDE, 0xAD] },
        ];
        let exported = export_ips32(&patches).unwrap();
        assert!(exported.starts_with(b"IPS32"));
        assert!(exported.ends_with(b"EEOF"));

        let imported = import_ips(&exported).unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].offset, 0x1000000);
        assert_eq!(imported[0].data, vec![0xDE, 0xAD]);
    }

    #[test]
    fn test_ips_offset_too_large() {
        let patches = vec![PatchRecord { offset: 0x1000000, data: vec![0x00] }];
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
        let ops = vec![
            (10, vec![0x41, 0x42]),
            (12, vec![0x43, 0x44]),
        ];
        let merged = extract_patches_from_overwrites(&ops);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].offset, 10);
        assert_eq!(merged[0].data, vec![0x41, 0x42, 0x43, 0x44]);
    }

    #[test]
    fn test_extract_patches_no_overlap() {
        let ops = vec![
            (10, vec![0x41]),
            (20, vec![0x42]),
        ];
        let merged = extract_patches_from_overwrites(&ops);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn test_extract_patches_empty() {
        let merged = extract_patches_from_overwrites(&[]);
        assert!(merged.is_empty());
    }
}
