// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Zachary Flint
//
// This file is part of Intellicrack. See LICENSE for details.

//! Overwrite patch formats: IPS and IPS32 export and import, COD export and a
//! JSON patch listing, all built from the overwrites in a document's history.

use serde::{Deserialize, Serialize};
use thiserror::Error;

const IPS_TERMINATOR_OFFSET: usize = 0x0045_4F46;
const IPS32_TERMINATOR_OFFSET: usize = 0x4545_4F46;

/// Errors raised while encoding or decoding patch files.
#[derive(Error, Debug)]
pub enum PatchError {
    /// The IPS/IPS32 input is malformed or truncated.
    #[error("invalid IPS data: {0}")]
    InvalidIps(String),
    /// A record writes past the 24-bit address space IPS can express.
    #[error("patch too large for IPS format (offset > 0xFFFFFF)")]
    PatchTooLarge,
    /// A record or its length exceeds the 32-bit range of IPS32 or COD.
    #[error("patch offset or length exceeds the 32-bit range of the {0} format")]
    Exceeds32Bit(&'static str),
    /// A record starts on the terminator offset and the byte before it is unknown.
    #[error("cannot resolve IPS terminator collision at offset {0:#x}: original byte unavailable")]
    UnresolvedTerminatorCollision(usize),
}

/// One contiguous run of patched bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchRecord {
    /// File offset of the first byte.
    pub offset: usize,
    /// Bytes written starting at `offset`.
    pub data: Vec<u8>,
}

/// The result of parsing an IPS/IPS32 patch against a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpsImport {
    /// Non-overlapping, offset-ordered runs to write; where records overlap,
    /// the later record's bytes win, exactly as sequential application would.
    pub runs: Vec<PatchRecord>,
    /// Number of non-empty records that start inside the document.
    pub applied_records: usize,
    /// Truncation length from the optional extension after the terminator,
    /// when it is shorter than the document.
    pub truncate_to: Option<usize>,
}

/// Offset of the last byte a record writes, or `None` for an empty record.
fn record_last_byte(record: &PatchRecord) -> Option<usize> {
    record
        .data
        .len()
        .checked_sub(1)
        .map(|tail| record.offset.saturating_add(tail))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonPatchEntry {
    offset: u64,
    data: String,
}

/// Exports patch records in IPS format (24-bit offsets).
///
/// The records are applied in order, so where two overlap the later one's
/// bytes win, and they are coalesced into disjoint runs before encoding. A run
/// written at the reserved terminator value (`IPS_TERMINATOR_OFFSET`) would
/// emit a header a parser misreads as the `EOF` marker, so that record is
/// shifted back to start one byte earlier. The byte it then carries comes from
/// the run itself when the run covers it, and otherwise from
/// `original_byte_at`, which is consulted only for a byte no record writes.
///
/// # Errors
///
/// Returns `PatchError::PatchTooLarge` if any record writes a byte past
/// `0x00FF_FFFF`.
/// Returns `PatchError::UnresolvedTerminatorCollision` if a run starts exactly
/// at the terminator offset and `original_byte_at` cannot supply the byte
/// immediately before it.
pub fn export_ips(
    patches: &[PatchRecord],
    original_byte_at: &dyn Fn(usize) -> Option<u8>,
) -> Result<Vec<u8>, PatchError> {
    export_records(&IPS_FORMAT, patches, original_byte_at)
}

/// Exports patch records in IPS32 format (32-bit offsets).
///
/// Records are coalesced and a run at `IPS32_TERMINATOR_OFFSET` is shifted
/// back one byte, exactly as [`export_ips`] does for its `EOF` marker, so the
/// `EEOF` marker is never emitted as a header.
///
/// # Errors
///
/// Returns `PatchError::Exceeds32Bit` if any record writes a byte past
/// `0xFFFF_FFFF`, which the 4-byte offset field would otherwise silently
/// truncate onto a low address.
/// Returns `PatchError::UnresolvedTerminatorCollision` if a run starts exactly
/// at the terminator offset and `original_byte_at` cannot supply the byte
/// immediately before it.
pub fn export_ips32(
    patches: &[PatchRecord],
    original_byte_at: &dyn Fn(usize) -> Option<u8>,
) -> Result<Vec<u8>, PatchError> {
    export_records(&IPS32_FORMAT, patches, original_byte_at)
}

/// The largest record payload an IPS or IPS32 size field can describe.
const MAX_IPS_RECORD: usize = 0xFFFF;

/// Encodes `patches` as records of `format`; see [`export_ips`].
fn export_records(
    format: &IpsFormat,
    patches: &[PatchRecord],
    original_byte_at: &dyn Fn(usize) -> Option<u8>,
) -> Result<Vec<u8>, PatchError> {
    let terminator = format.terminator_offset;
    let mut output = format.header.to_vec();

    for run in &coalesce(patches.iter().map(|p| (p.offset, p.data.as_slice()))) {
        if run.offset > format.max_offset
            || record_last_byte(run).is_some_and(|last| last > format.max_offset)
        {
            return Err((format.out_of_range)());
        }
        let mut remaining = run.data.as_slice();
        let mut current_offset = run.offset;

        while !remaining.is_empty() {
            if current_offset == terminator {
                let prev_offset = terminator - 1;
                let prev_byte = if current_offset > run.offset {
                    run.data[prev_offset - run.offset]
                } else {
                    original_byte_at(prev_offset)
                        .ok_or(PatchError::UnresolvedTerminatorCollision(terminator))?
                };
                let consumed = remaining.len().min(MAX_IPS_RECORD - 1);
                push_record_header(&mut output, format, prev_offset, consumed + 1);
                output.push(prev_byte);
                output.extend_from_slice(&remaining[..consumed]);
                remaining = &remaining[consumed..];
                current_offset += consumed;
                continue;
            }

            let mut chunk_size = remaining.len().min(MAX_IPS_RECORD);
            if current_offset < terminator && current_offset + chunk_size > terminator {
                chunk_size = terminator + 1 - current_offset;
            }
            push_record_header(&mut output, format, current_offset, chunk_size);
            output.extend_from_slice(&remaining[..chunk_size]);
            remaining = &remaining[chunk_size..];
            current_offset += chunk_size;
        }
    }

    output.extend_from_slice(format.terminator);
    Ok(output)
}

/// Appends a record header: `offset` in the format's offset width, then the
/// 16-bit `size`, both big-endian.
fn push_record_header(output: &mut Vec<u8>, format: &IpsFormat, offset: usize, size: usize) {
    let offset_bytes = offset.to_be_bytes();
    output.extend_from_slice(&offset_bytes[offset_bytes.len() - format.offset_width..]);
    let size_bytes = size.to_be_bytes();
    output.extend_from_slice(&size_bytes[size_bytes.len() - 2..]);
}

/// Exports patch records in COD format.
///
/// Each record is serialized as a 4-byte big-endian offset followed by a
/// 4-byte big-endian length and then the raw patch bytes. No header or
/// terminator is emitted.
///
/// # Errors
///
/// Returns `PatchError::Exceeds32Bit` if a record's offset or length does not
/// fit the 32-bit fields, since saturating either would write the bytes at the
/// wrong address or misalign every following record.
pub fn export_cod(records: &[PatchRecord]) -> Result<Vec<u8>, PatchError> {
    let mut output = Vec::new();
    for record in records {
        let offset_u32 =
            u32::try_from(record.offset).map_err(|_| PatchError::Exceeds32Bit("COD"))?;
        let length_u32 =
            u32::try_from(record.data.len()).map_err(|_| PatchError::Exceeds32Bit("COD"))?;
        output.extend_from_slice(&offset_u32.to_be_bytes());
        output.extend_from_slice(&length_u32.to_be_bytes());
        output.extend_from_slice(&record.data);
    }
    Ok(output)
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

/// Field layout of one IPS dialect.
struct IpsFormat {
    header: &'static [u8],
    terminator: &'static [u8],
    offset_width: usize,
    /// The offset whose big-endian encoding spells `terminator`, so no record
    /// header may carry it.
    terminator_offset: usize,
    /// The last offset a record may write.
    max_offset: usize,
    /// The error for a record that writes past `max_offset`.
    out_of_range: fn() -> PatchError,
    end_of_data: &'static str,
    truncated_header: &'static str,
    truncated_rle: &'static str,
    truncated_data: &'static str,
}

const IPS_FORMAT: IpsFormat = IpsFormat {
    header: b"PATCH",
    terminator: b"EOF",
    offset_width: 3,
    terminator_offset: IPS_TERMINATOR_OFFSET,
    max_offset: 0x00FF_FFFF,
    out_of_range: || PatchError::PatchTooLarge,
    end_of_data: "unexpected end of data",
    truncated_header: "truncated record header",
    truncated_rle: "truncated RLE record",
    truncated_data: "truncated record data",
};

const IPS32_FORMAT: IpsFormat = IpsFormat {
    header: b"IPS32",
    terminator: b"EEOF",
    offset_width: 4,
    terminator_offset: IPS32_TERMINATOR_OFFSET,
    max_offset: 0xFFFF_FFFF,
    out_of_range: || PatchError::Exceeds32Bit("IPS32"),
    end_of_data: "unexpected end of IPS32 data",
    truncated_header: "truncated IPS32 record header",
    truncated_rle: "truncated IPS32 RLE record",
    truncated_data: "truncated IPS32 record data",
};

/// The payload of one parsed IPS record.
enum IpsBody<'a> {
    /// Bytes copied verbatim from the patch.
    Literal(&'a [u8]),
    /// `count` copies of `value` (an RLE record).
    Run { count: usize, value: u8 },
}

fn read_be(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .fold(0usize, |acc, &byte| (acc << 8) | usize::from(byte))
}

/// Walks every record of an IPS or IPS32 patch, handing each to `visit`.
///
/// Returns the truncation length carried by the optional extension that
/// follows the terminator (3 bytes for IPS, 4 for IPS32). Any other trailing
/// data after the terminator is ignored, as common IPS appliers do.
fn parse_ips<'a>(
    data: &'a [u8],
    mut visit: impl FnMut(usize, IpsBody<'a>),
) -> Result<Option<usize>, PatchError> {
    if data.len() < 5 {
        return Err(PatchError::InvalidIps("data too short".to_string()));
    }
    let format = if data.starts_with(IPS32_FORMAT.header) {
        &IPS32_FORMAT
    } else if data.starts_with(IPS_FORMAT.header) {
        &IPS_FORMAT
    } else {
        return Err(PatchError::InvalidIps(
            "invalid header (expected PATCH or IPS32)".to_string(),
        ));
    };

    let width = format.offset_width;
    let term_len = format.terminator.len();
    let mut pos = format.header.len();
    loop {
        if pos + term_len > data.len() {
            return Err(PatchError::InvalidIps(format.end_of_data.to_string()));
        }
        if &data[pos..pos + term_len] == format.terminator {
            pos += term_len;
            break;
        }
        if pos + width + 2 > data.len() {
            return Err(PatchError::InvalidIps(format.truncated_header.to_string()));
        }
        let offset = read_be(&data[pos..pos + width]);
        let size = read_be(&data[pos + width..pos + width + 2]);
        pos += width + 2;

        if size == 0 {
            if pos + 3 > data.len() {
                return Err(PatchError::InvalidIps(format.truncated_rle.to_string()));
            }
            let count = read_be(&data[pos..pos + 2]);
            let value = data[pos + 2];
            pos += 3;
            if count > 0 {
                visit(offset, IpsBody::Run { count, value });
            }
        } else {
            if pos + size > data.len() {
                return Err(PatchError::InvalidIps(format.truncated_data.to_string()));
            }
            visit(offset, IpsBody::Literal(&data[pos..pos + size]));
            pos += size;
        }
    }

    let trailer = &data[pos..];
    Ok((trailer.len() == width).then(|| read_be(trailer)))
}

/// Parses an IPS or IPS32 patch for application to a `document_len`-byte
/// document.
///
/// Each record is clamped to the document (a record starting at or past the
/// end is skipped, one running past the end is cut at it, matching the
/// overwrite-never-grows policy of the editor) and merged into
/// non-overlapping runs in record order, so a later record overrides an
/// earlier one exactly as sequential application would. Because the runs
/// never extend past the document, the memory used is bounded by
/// `document_len` no matter how many RLE records a hostile patch contains.
///
/// # Errors
///
/// Returns `PatchError::InvalidIps` if the data has an invalid header, is
/// truncated, or is otherwise malformed.
pub fn import_ips_patch(data: &[u8], document_len: usize) -> Result<IpsImport, PatchError> {
    let mut runs: Vec<PatchRecord> = Vec::new();
    let mut applied_records = 0usize;
    let truncation = parse_ips(data, |offset, body| {
        if offset >= document_len {
            return;
        }
        applied_records += 1;
        let room = document_len - offset;
        match body {
            IpsBody::Literal(bytes) => {
                splice_run(&mut runs, offset, &bytes[..bytes.len().min(room)]);
            }
            IpsBody::Run { count, value } => {
                splice_run(&mut runs, offset, &vec![value; count.min(room)]);
            }
        }
    })?;
    Ok(IpsImport {
        runs,
        applied_records,
        truncate_to: truncation.filter(|&len| len < document_len),
    })
}

/// Writes `data` at `start` into `runs`, keeping them sorted, disjoint and
/// coalesced, with `data` overriding any bytes it overlaps.
fn splice_run(runs: &mut Vec<PatchRecord>, start: usize, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let end = start.saturating_add(data.len());
    let lo = runs.partition_point(|r| r.offset + r.data.len() < start);
    let hi = runs.partition_point(|r| r.offset <= end);
    if lo >= hi {
        runs.insert(
            lo,
            PatchRecord {
                offset: start,
                data: data.to_vec(),
            },
        );
        return;
    }
    if hi - lo == 1 && runs[lo].offset <= start {
        let run = &mut runs[lo];
        let rel = start - run.offset;
        if rel + data.len() > run.data.len() {
            run.data.resize(rel + data.len(), 0);
        }
        run.data[rel..rel + data.len()].copy_from_slice(data);
        return;
    }
    let new_start = start.min(runs[lo].offset);
    let last = &runs[hi - 1];
    let new_end = end.max(last.offset + last.data.len());
    let mut merged = vec![0u8; new_end - new_start];
    for run in &runs[lo..hi] {
        let rel = run.offset - new_start;
        merged[rel..rel + run.data.len()].copy_from_slice(&run.data);
    }
    merged[start - new_start..end - new_start].copy_from_slice(data);
    runs.splice(
        lo..hi,
        std::iter::once(PatchRecord {
            offset: new_start,
            data: merged,
        }),
    );
}

/// Collapses a chronological list of overwrites into disjoint patch records.
///
/// `operations` must be in the order the writes happened (the undo-stack
/// order). Where writes overlap the newest one wins, and touching or
/// overlapping writes coalesce into one record, so the result reproduces the
/// final bytes of every written position.
#[must_use]
pub fn extract_patches_from_overwrites(operations: &[(usize, Vec<u8>)]) -> Vec<PatchRecord> {
    coalesce(
        operations
            .iter()
            .map(|(offset, data)| (*offset, data.as_slice())),
    )
}

/// Folds `writes`, in the order they apply, into sorted, disjoint,
/// non-touching runs, the later write winning wherever two overlap.
fn coalesce<'a>(writes: impl IntoIterator<Item = (usize, &'a [u8])>) -> Vec<PatchRecord> {
    let mut runs: Vec<PatchRecord> = Vec::new();
    for (offset, data) in writes {
        splice_run(&mut runs, offset, data);
    }
    runs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_original(_offset: usize) -> Option<u8> {
        None
    }

    /// Decodes every non-empty record of an IPS or IPS32 patch in file order,
    /// RLE records expanded, so the exporters' record layout can be checked
    /// exactly. The expansion is unbounded, which is why only the bounded
    /// [`import_ips_patch`] is part of the engine.
    fn import_ips(data: &[u8]) -> Result<Vec<PatchRecord>, PatchError> {
        let mut records = Vec::new();
        parse_ips(data, |offset, body| {
            let bytes = match body {
                IpsBody::Literal(bytes) => bytes.to_vec(),
                IpsBody::Run { count, value } => vec![value; count],
            };
            records.push(PatchRecord {
                offset,
                data: bytes,
            });
        })?;
        Ok(records)
    }

    /// The byte `records` leave at `offset` when applied in order, or `None`
    /// when no record writes it. Records are looked up rather than replayed
    /// into a dense buffer, which near the IPS32 terminator offset would be
    /// over a gigabyte.
    fn written_byte(records: &[PatchRecord], offset: usize) -> Option<u8> {
        records.iter().rev().find_map(|rec| {
            offset
                .checked_sub(rec.offset)
                .and_then(|rel| rec.data.get(rel).copied())
        })
    }

    fn written_bytes(records: &[PatchRecord], start: usize, len: usize) -> Vec<Option<u8>> {
        (start..start + len)
            .map(|offset| written_byte(records, offset))
            .collect()
    }

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
        let exported = export_ips(&patches, &no_original).unwrap();
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
        let exported = export_ips32(&patches, &no_original).unwrap();
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
        assert!(matches!(
            export_ips(&patches, &no_original),
            Err(PatchError::PatchTooLarge)
        ));
    }

    #[test]
    fn test_empty_patches() {
        let exported = export_ips(&[], &no_original).unwrap();
        assert_eq!(exported, b"PATCHEOF");
        let imported = import_ips(&exported).unwrap();
        assert_eq!(imported.len(), 0);
    }

    #[test]
    fn test_invalid_header() {
        let err = import_ips(b"NOTIP").unwrap_err();
        assert!(matches!(&err, PatchError::InvalidIps(m) if m.contains("invalid header")));
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
        assert_eq!(merged[0].offset, 10);
        assert_eq!(merged[0].data, vec![0x41]);
        assert_eq!(merged[1].offset, 20);
        assert_eq!(merged[1].data, vec![0x42]);
    }

    #[test]
    fn test_extract_patches_empty() {
        let merged = extract_patches_from_overwrites(&[]);
        assert_eq!(merged.len(), 0);
    }

    #[test]
    fn test_export_cod_single_record() {
        let patches = vec![PatchRecord {
            offset: 0x1234_5678,
            data: vec![0xAA, 0xBB, 0xCC],
        }];
        let out = export_cod(&patches).unwrap();
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
        let out = export_cod(&patches).unwrap();
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
        assert_eq!(export_cod(&[]).unwrap().len(), 0);
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
        let parsed: Vec<JsonPatchEntry> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].offset, 1);
        assert_eq!(parsed[0].data, "01");
    }

    #[test]
    fn test_ips_collision_no_record_at_terminator_offset() {
        // The byte immediately before the terminator offset is not part of this
        // record's data, so the exporter obtains it from `original_byte_at`; the
        // reconstructed byte at PREV_BYTE_OFFSET must equal that original byte.
        const PREV_BYTE: u8 = 0x77;
        let patches = vec![PatchRecord {
            offset: IPS_TERMINATOR_OFFSET,
            data: vec![0x11, 0x22, 0x33],
        }];
        let original_at =
            |offset: usize| (offset == IPS_TERMINATOR_OFFSET - 1).then_some(PREV_BYTE);
        let exported = export_ips(&patches, &original_at).unwrap();

        let header_end = exported.len() - 3;
        let body = &exported[5..header_end];
        assert!(!contains_header_with_offset_3(body, IPS_TERMINATOR_OFFSET));

        let imported = import_ips(&exported).unwrap();
        assert_eq!(
            written_byte(&imported, IPS_TERMINATOR_OFFSET - 1),
            Some(PREV_BYTE)
        );
        assert_eq!(
            written_bytes(&imported, IPS_TERMINATOR_OFFSET, 3),
            [Some(0x11), Some(0x22), Some(0x33)]
        );
    }

    #[test]
    fn test_ips_collision_unresolved_returns_error() {
        // Record starts exactly at the terminator offset and no original
        // byte is available -- must fail loudly instead of fabricating 0x00.
        let patches = vec![PatchRecord {
            offset: IPS_TERMINATOR_OFFSET,
            data: vec![0x11, 0x22, 0x33],
        }];
        let err = export_ips(&patches, &no_original).unwrap_err();
        assert!(
            matches!(err, PatchError::UnresolvedTerminatorCollision(offset) if offset == IPS_TERMINATOR_OFFSET),
            "got {err:?}"
        );
    }

    #[test]
    fn test_ips_collision_spanning_terminator_offset() {
        let patches = vec![PatchRecord {
            offset: IPS_TERMINATOR_OFFSET - 2,
            data: vec![0xAA, 0xBB, 0xCC, 0xDD],
        }];
        let exported = export_ips(&patches, &no_original).unwrap();
        let header_end = exported.len() - 3;
        let body = &exported[5..header_end];
        assert!(!contains_header_with_offset_3(body, IPS_TERMINATOR_OFFSET));

        let imported = import_ips(&exported).unwrap();
        assert_eq!(
            written_bytes(&imported, IPS_TERMINATOR_OFFSET - 2, 4),
            [Some(0xAA), Some(0xBB), Some(0xCC), Some(0xDD)]
        );
    }

    #[test]
    fn test_ips32_collision_no_record_at_terminator_offset() {
        const PREV_BYTE: u8 = 0x99;
        let patches = vec![PatchRecord {
            offset: IPS32_TERMINATOR_OFFSET,
            data: vec![0x11, 0x22, 0x33],
        }];
        let original_at =
            |offset: usize| (offset == IPS32_TERMINATOR_OFFSET - 1).then_some(PREV_BYTE);
        let exported = export_ips32(&patches, &original_at).unwrap();
        let header_end = exported.len() - 4;
        let body = &exported[5..header_end];
        assert!(!contains_header_with_offset_4(
            body,
            IPS32_TERMINATOR_OFFSET
        ));

        let imported = import_ips(&exported).unwrap();
        assert_eq!(
            written_byte(&imported, IPS32_TERMINATOR_OFFSET - 1),
            Some(PREV_BYTE)
        );
        assert_eq!(
            written_bytes(&imported, IPS32_TERMINATOR_OFFSET, 3),
            [Some(0x11), Some(0x22), Some(0x33)]
        );
    }

    #[test]
    fn test_ips32_collision_roundtrip() {
        // Unwritten offsets read as `None`, so only a byte the patch really
        // writes can match PREV_BYTE.
        const PREV_BYTE: u8 = 0x5A;
        let patches = vec![PatchRecord {
            offset: IPS32_TERMINATOR_OFFSET,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        }];
        let original_at =
            |offset: usize| (offset == IPS32_TERMINATOR_OFFSET - 1).then_some(PREV_BYTE);
        let exported = export_ips32(&patches, &original_at).unwrap();
        let header_end = exported.len() - 4;
        let body = &exported[5..header_end];
        assert!(!contains_header_with_offset_4(
            body,
            IPS32_TERMINATOR_OFFSET
        ));

        let imported = import_ips(&exported).unwrap();
        assert_eq!(
            written_byte(&imported, IPS32_TERMINATOR_OFFSET - 1),
            Some(PREV_BYTE)
        );
        assert_eq!(
            written_bytes(&imported, IPS32_TERMINATOR_OFFSET, 4),
            [Some(0xDE), Some(0xAD), Some(0xBE), Some(0xEF)]
        );
    }

    /// A record at the terminator whose preceding byte another record writes
    /// takes that byte from the other record: `original_byte_at` supplies only
    /// bytes no record covers, so its 0x00 here never reaches the patch. Both
    /// orders of the two records give the same bytes, in both dialects.
    #[test]
    fn test_collision_takes_the_prev_byte_from_another_record() {
        type Export =
            fn(&[PatchRecord], &dyn Fn(usize) -> Option<u8>) -> Result<Vec<u8>, PatchError>;
        for (terminator, export) in [
            (IPS_TERMINATOR_OFFSET, export_ips as Export),
            (IPS32_TERMINATOR_OFFSET, export_ips32 as Export),
        ] {
            let before = PatchRecord {
                offset: terminator - 1,
                data: vec![0xAA],
            };
            let at = PatchRecord {
                offset: terminator,
                data: vec![0xBB],
            };
            let original_at = |offset: usize| (offset == terminator - 1).then_some(0x00);
            for patches in [vec![before.clone(), at.clone()], vec![at, before]] {
                let imported = import_ips(&export(&patches, &original_at).unwrap()).unwrap();
                assert_eq!(
                    imported,
                    vec![PatchRecord {
                        offset: terminator - 1,
                        data: vec![0xAA, 0xBB],
                    }],
                    "terminator {terminator:#x}"
                );
            }
        }
    }

    /// A run whose first full-size chunk ends just before the terminator
    /// continues with a chunk that would start on it, so that chunk is shifted
    /// back one byte and carries the run's own byte there, with no call to
    /// `original_byte_at`.
    #[test]
    fn test_collision_after_a_full_chunk_uses_the_run_s_own_byte() {
        let mut data = vec![0u8; 0x1_0000];
        data[0xFFFE] = 0x5A;
        data[0xFFFF] = 0x6B;
        let start = IPS_TERMINATOR_OFFSET - 0xFFFF;
        let exported = export_ips(
            &[PatchRecord {
                offset: start,
                data: data.clone(),
            }],
            &no_original,
        )
        .unwrap();

        let imported = import_ips(&exported).unwrap();
        let offsets: Vec<usize> = imported.iter().map(|record| record.offset).collect();
        assert_eq!(offsets, vec![start, IPS_TERMINATOR_OFFSET - 1]);
        assert_eq!(imported[1].data, vec![0x5A, 0x6B]);
        assert_eq!(
            written_bytes(&imported, start, data.len()),
            data.iter().copied().map(Some).collect::<Vec<_>>()
        );
    }

    /// Overlapping records apply in order, so the export holds one run with
    /// the later record's byte where they overlap.
    #[test]
    fn test_export_coalesces_overlapping_records_later_wins() {
        let patches = vec![
            PatchRecord {
                offset: 10,
                data: vec![1, 2, 3],
            },
            PatchRecord {
                offset: 11,
                data: vec![9],
            },
        ];
        let exported = export_ips(&patches, &no_original).unwrap();
        assert_eq!(
            exported,
            b"PATCH\x00\x00\x0a\x00\x03\x01\x09\x03EOF".to_vec()
        );
    }

    #[test]
    fn test_import_ips_rle_record() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"PATCH");
        buf.extend_from_slice(&[0x00, 0x00, 0x10]); // offset 0x10
        buf.extend_from_slice(&[0x00, 0x00]); // size 0 -> RLE
        buf.extend_from_slice(&[0x00, 0x04, 0xAB]); // count 4, value 0xAB
        buf.extend_from_slice(b"EOF");
        let records = import_ips(&buf).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].offset, 0x10);
        assert_eq!(records[0].data, vec![0xAB; 4]);
    }

    #[test]
    fn test_import_ips32_rle_record() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"IPS32");
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x10]); // offset 0x10
        buf.extend_from_slice(&[0x00, 0x00]); // size 0 -> RLE
        buf.extend_from_slice(&[0x00, 0x03, 0xCC]); // count 3, value 0xCC
        buf.extend_from_slice(b"EEOF");
        let records = import_ips(&buf).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].offset, 0x10);
        assert_eq!(records[0].data, vec![0xCC; 3]);
    }

    #[test]
    fn test_import_ips_truncation_errors() {
        assert!(import_ips(b"AB")
            .unwrap_err()
            .to_string()
            .contains("data too short"));
        assert!(import_ips(b"PATCH\x00\x00")
            .unwrap_err()
            .to_string()
            .contains("unexpected end of data"));
        assert!(import_ips(b"PATCH\x00\x00\x10")
            .unwrap_err()
            .to_string()
            .contains("truncated record header"));
        // size 0 RLE with fewer than 3 trailing bytes
        let rle = [
            b'P', b'A', b'T', b'C', b'H', 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(import_ips(&rle)
            .unwrap_err()
            .to_string()
            .contains("truncated RLE record"));
        // size 3 with only 1 data byte
        let dat = [
            b'P', b'A', b'T', b'C', b'H', 0x00, 0x00, 0x10, 0x00, 0x03, 0xAA,
        ];
        assert!(import_ips(&dat)
            .unwrap_err()
            .to_string()
            .contains("truncated record data"));
    }

    #[test]
    fn test_import_ips32_truncation_errors() {
        assert!(import_ips(b"IPS32\x00\x00")
            .unwrap_err()
            .to_string()
            .contains("unexpected end of IPS32 data"));
        let hdr = [b'I', b'P', b'S', b'3', b'2', 0x00, 0x00, 0x00, 0x10];
        assert!(import_ips(&hdr)
            .unwrap_err()
            .to_string()
            .contains("truncated IPS32 record header"));
        let rle = [
            b'I', b'P', b'S', b'3', b'2', 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(import_ips(&rle)
            .unwrap_err()
            .to_string()
            .contains("truncated IPS32 RLE record"));
        let dat = [
            b'I', b'P', b'S', b'3', b'2', 0x00, 0x00, 0x00, 0x10, 0x00, 0x03, 0xAA,
        ];
        assert!(import_ips(&dat)
            .unwrap_err()
            .to_string()
            .contains("truncated IPS32 record data"));
    }

    #[test]
    fn test_export_ips_midloop_offset_overflow() {
        // offset itself is <= 0xFFFFFF, but the data pushes current_offset past it mid-loop.
        let patches = vec![PatchRecord {
            offset: 0x00FF_FFFE,
            data: vec![0xAB; 0x10000],
        }];
        let err = export_ips(&patches, &no_original).unwrap_err();
        assert!(matches!(err, PatchError::PatchTooLarge), "got {err:?}");
    }

    #[test]
    fn test_export_ips_multi_chunk_single_patch_roundtrip() {
        // data > 0xFFFF forces the chunk loop to iterate more than once.
        let original = vec![0xABu8; 0x10000];
        let patches = vec![PatchRecord {
            offset: 0x100,
            data: original.clone(),
        }];
        let exported = export_ips(&patches, &no_original).unwrap();
        let imported = import_ips(&exported).unwrap();
        assert!(imported.len() >= 2, "expected multiple chunk records");
        let mut recon = vec![0u8; 0x100 + original.len()];
        for r in &imported {
            recon[r.offset..r.offset + r.data.len()].copy_from_slice(&r.data);
        }
        assert_eq!(&recon[0x100..0x100 + original.len()], original.as_slice());
    }

    /// `export_cod` must reject an offset above `u32::MAX` rather than saturate
    /// it to `0xFFFF_FFFF` and write the bytes to the wrong address.
    #[test]
    fn test_export_cod_rejects_offset_above_u32_max() {
        let records = vec![PatchRecord {
            offset: 0x1_0000_0000,
            data: vec![0xAA],
        }];
        assert!(matches!(
            export_cod(&records),
            Err(PatchError::Exceeds32Bit("COD"))
        ));
    }

    /// `export_ips32` must reject offsets above 32 bits, so a patch near the
    /// 4 GiB boundary is never truncated into its low 32 bits or collided with
    /// the `EEOF` terminator.
    #[test]
    fn test_export_ips32_rejects_offset_above_u32_max() {
        let high = [PatchRecord {
            offset: 0x1_0000_0010,
            data: vec![0x41],
        }];
        assert!(matches!(
            export_ips32(&high, &no_original),
            Err(PatchError::Exceeds32Bit("IPS32"))
        ));
        let crossing = [PatchRecord {
            offset: 0xFFFF_FFFF,
            data: vec![0x41, 0x42],
        }];
        assert!(matches!(
            export_ips32(&crossing, &no_original),
            Err(PatchError::Exceeds32Bit("IPS32"))
        ));
    }

    /// The 24-bit ceiling is checked for every byte of a record, not only at its
    /// start, so a record that begins at `0xFFFFFE` but runs past `0xFFFFFF` is
    /// rejected while one that ends exactly at the ceiling is accepted.
    #[test]
    fn test_export_ips_rejects_record_crossing_24bit_ceiling() {
        let crossing = [PatchRecord {
            offset: 0x00FF_FFFE,
            data: vec![1, 2, 3],
        }];
        assert!(matches!(
            export_ips(&crossing, &no_original),
            Err(PatchError::PatchTooLarge)
        ));
        let edge = [PatchRecord {
            offset: 0x00FF_FFFE,
            data: vec![1, 2],
        }];
        assert_eq!(
            export_ips(&edge, &no_original).unwrap(),
            [
                b"PATCH".as_slice(),
                &[0xFF, 0xFF, 0xFE, 0x00, 0x02, 1, 2],
                b"EOF"
            ]
            .concat()
        );
    }

    /// The merge keeps overwrites in chronological order: a later write to a
    /// lower offset wins over an earlier write to an overlapping higher one, so
    /// the exported bytes match the final document.
    #[test]
    fn test_extract_patches_later_lower_offset_write_wins() {
        let ops = vec![
            (10, vec![0xAA, 0xBB, 0xCC, 0xDD]),
            (8, vec![0x11, 0x22, 0x33, 0x44]),
        ];
        assert_eq!(
            extract_patches_from_overwrites(&ops),
            vec![PatchRecord {
                offset: 8,
                data: vec![0x11, 0x22, 0x33, 0x44, 0xCC, 0xDD],
            }]
        );
        let bridged = vec![(0, vec![1]), (4, vec![5]), (1, vec![2, 3, 4])];
        assert_eq!(
            extract_patches_from_overwrites(&bridged),
            vec![PatchRecord {
                offset: 0,
                data: vec![1, 2, 3, 4, 5],
            }]
        );
    }

    /// RLE records are expanded lazily and bounded by the document size, so a
    /// small IPS file of many 65535-count records cannot force gigabytes of
    /// allocation.
    #[test]
    fn test_import_ips_patch_bounds_rle_expansion_by_document() {
        let mut buf = b"PATCH".to_vec();
        for _ in 0..2000 {
            buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xAB]);
        }
        buf.extend_from_slice(b"EOF");
        let parsed = import_ips_patch(&buf, 16).unwrap();
        assert_eq!(
            parsed.runs,
            vec![PatchRecord {
                offset: 0,
                data: vec![0xAB; 16],
            }]
        );
        assert_eq!(parsed.applied_records, 2000);
        assert_eq!(parsed.truncate_to, None);
    }

    /// A zero-count RLE record must not import as an empty record, which the
    /// document would then count as an applied patch.
    #[test]
    fn test_import_ips_skips_zero_count_rle() {
        let buf = b"PATCH\x00\x00\x10\x00\x00\x00\x00\xABEOF";
        assert_eq!(import_ips(buf).unwrap().len(), 0);
        assert_eq!(import_ips_patch(buf, 64).unwrap().applied_records, 0);
    }

    /// The 3-byte truncation extension after `EOF` must be read. Ignoring it makes
    /// a patch that shrinks its target import as plain writes and leave the original
    /// tail in place.
    #[test]
    fn test_import_ips_patch_reads_truncation_extension() {
        let buf = b"PATCH\x00\x00\x00\x00\x01\x58EOF\x00\x00\x03";
        let parsed = import_ips_patch(buf, 6).unwrap();
        assert_eq!(parsed.truncate_to, Some(3));
        assert_eq!(
            parsed.runs,
            vec![PatchRecord {
                offset: 0,
                data: vec![0x58],
            }]
        );
        assert_eq!(import_ips_patch(buf, 2).unwrap().truncate_to, None);
        let ips32 = b"IPS32EEOF\x00\x00\x00\x02";
        assert_eq!(import_ips_patch(ips32, 9).unwrap().truncate_to, Some(2));
    }

    #[test]
    fn test_extract_patches_within_existing_no_extend() {
        // Second op is fully inside the first record: overwrite in place, no extension.
        let ops = vec![(10, vec![0x41, 0x42, 0x43, 0x44]), (11, vec![0xFF])];
        let merged = extract_patches_from_overwrites(&ops);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].offset, 10);
        assert_eq!(merged[0].data, vec![0x41, 0xFF, 0x43, 0x44]);
    }

    fn contains_header_with_offset_3(body: &[u8], offset: usize) -> bool {
        let target = [
            u8::try_from((offset >> 16) & 0xFF).expect("mask with 0xFF fits in u8"),
            u8::try_from((offset >> 8) & 0xFF).expect("mask with 0xFF fits in u8"),
            u8::try_from(offset & 0xFF).expect("mask with 0xFF fits in u8"),
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
            u8::try_from((offset >> 24) & 0xFF).expect("mask with 0xFF fits in u8"),
            u8::try_from((offset >> 16) & 0xFF).expect("mask with 0xFF fits in u8"),
            u8::try_from((offset >> 8) & 0xFF).expect("mask with 0xFF fits in u8"),
            u8::try_from(offset & 0xFF).expect("mask with 0xFF fits in u8"),
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
