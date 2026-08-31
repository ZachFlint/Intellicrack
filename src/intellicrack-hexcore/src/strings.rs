//! Full-document string extraction (ASCII and UTF-16LE).
//!
//! Scans binary data for printable ASCII and UTF-16LE string sequences,
//! with optional rayon parallelism for large files.

use rayon::prelude::*;
use serde::Serialize;

const PARALLEL_THRESHOLD: usize = 1_048_576; // 1 MB
const PARALLEL_CHUNK_SIZE: usize = 65536;

/// A matched string found in the binary data.
#[derive(Serialize, Clone, Debug)]
pub struct StringMatch {
    /// Byte offset of the string in the source data.
    pub offset: usize,
    /// Length of the string in bytes (not characters for UTF-16).
    pub length: usize,
    /// Encoding of the matched string ("ascii" or "utf16le").
    pub encoding: String,
    /// Decoded string content.
    pub content: String,
}

fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7E).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r'
}

struct RawAsciiRun {
    offset: usize,
    content: String,
}

fn extract_ascii_runs_unfiltered(data: &[u8]) -> Vec<RawAsciiRun> {
    let mut runs = Vec::new();
    let mut start: Option<usize> = None;

    for (i, &byte) in data.iter().enumerate() {
        if is_printable_ascii(byte) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start {
            runs.push(RawAsciiRun {
                offset: s,
                content: String::from_utf8_lossy(&data[s..i]).to_string(),
            });
            start = None;
        }
    }

    if let Some(s) = start {
        runs.push(RawAsciiRun {
            offset: s,
            content: String::from_utf8_lossy(&data[s..]).to_string(),
        });
    }

    runs
}

fn extract_ascii_strings(data: &[u8], min_length: usize) -> Vec<StringMatch> {
    extract_ascii_runs_unfiltered(data)
        .into_iter()
        .filter(|r| r.content.len() >= min_length)
        .map(|r| StringMatch {
            offset: r.offset,
            length: r.content.len(),
            encoding: "ascii".to_string(),
            content: r.content,
        })
        .collect()
}

fn extract_ascii_strings_parallel(data: &[u8], min_length: usize) -> Vec<StringMatch> {
    let chunks: Vec<(usize, &[u8])> = data
        .chunks(PARALLEL_CHUNK_SIZE)
        .enumerate()
        .map(|(i, chunk)| (i * PARALLEL_CHUNK_SIZE, chunk))
        .collect();

    let mut chunk_runs: Vec<Vec<RawAsciiRun>> = chunks
        .par_iter()
        .map(|(base_offset, chunk)| {
            let mut runs = extract_ascii_runs_unfiltered(chunk);
            for r in &mut runs {
                r.offset += base_offset;
            }
            runs
        })
        .collect();

    // Stitch runs that abut a chunk seam back into a single continuous run before
    // the min_length filter is applied, so a string split across the 64 KiB chunk
    // boundary is neither fragmented nor dropped.
    let mut stitched: Vec<RawAsciiRun> = Vec::new();
    for (chunk_idx, (base_offset, _)) in chunks.iter().enumerate() {
        for run in std::mem::take(&mut chunk_runs[chunk_idx]) {
            let touches_left_edge = run.offset == *base_offset;
            if touches_left_edge {
                if let Some(prev) = stitched.last_mut() {
                    if prev.offset + prev.content.len() == *base_offset {
                        prev.content.push_str(&run.content);
                        continue;
                    }
                }
            }
            stitched.push(run);
        }
    }

    let mut all_results: Vec<StringMatch> = stitched
        .into_iter()
        .filter(|r| r.content.len() >= min_length)
        .map(|r| StringMatch {
            offset: r.offset,
            length: r.content.len(),
            encoding: "ascii".to_string(),
            content: r.content,
        })
        .collect();

    all_results.sort_by_key(|r| r.offset);
    all_results
}

fn is_printable_char(c: char) -> bool {
    !c.is_control() || c == '\t' || c == '\n' || c == '\r'
}

enum DecodeStep {
    Scalar { value: u32, bytes: usize },
    Invalid { bytes: usize },
    Eof,
}

fn decode_utf16le_step(data: &[u8], i: usize) -> DecodeStep {
    let unit = u16::from_le_bytes([data[i], data[i + 1]]);

    if (0xDC00..=0xDFFF).contains(&unit) {
        return DecodeStep::Invalid { bytes: 2 };
    }

    if !(0xD800..=0xDBFF).contains(&unit) {
        return DecodeStep::Scalar {
            value: u32::from(unit),
            bytes: 2,
        };
    }

    if i + 3 >= data.len() {
        return DecodeStep::Eof;
    }

    let low = u16::from_le_bytes([data[i + 2], data[i + 3]]);
    if !(0xDC00..=0xDFFF).contains(&low) {
        return DecodeStep::Invalid { bytes: 2 };
    }

    let cp = ((u32::from(unit) - 0xD800) << 10) + (u32::from(low) - 0xDC00) + 0x10000;
    DecodeStep::Scalar {
        value: cp,
        bytes: 4,
    }
}

fn extract_utf16le_strings(data: &[u8], min_length: usize) -> Vec<StringMatch> {
    let mut results = Vec::new();
    if data.len() < 2 {
        return results;
    }

    let mut current = String::new();
    let mut char_count: usize = 0;
    let mut start_offset: usize = 0;

    let flush = |current: &mut String,
                 char_count: &mut usize,
                 start: usize,
                 end: usize,
                 results: &mut Vec<StringMatch>| {
        if *char_count > 0 && *char_count >= min_length {
            results.push(StringMatch {
                offset: start,
                length: end - start,
                encoding: "utf16le".to_string(),
                content: std::mem::take(current),
            });
        }
        current.clear();
        *char_count = 0;
    };

    let mut i = 0;
    while i + 1 < data.len() {
        let unit_start = i;
        match decode_utf16le_step(data, i) {
            DecodeStep::Scalar { value, bytes } => {
                match char::from_u32(value).filter(|c| is_printable_char(*c)) {
                    Some(c) => {
                        if char_count == 0 {
                            start_offset = unit_start;
                        }
                        current.push(c);
                        char_count += 1;
                    }
                    None => {
                        flush(
                            &mut current,
                            &mut char_count,
                            start_offset,
                            unit_start,
                            &mut results,
                        );
                    }
                }
                i += bytes;
            }
            DecodeStep::Invalid { bytes } => {
                flush(
                    &mut current,
                    &mut char_count,
                    start_offset,
                    unit_start,
                    &mut results,
                );
                i += bytes;
            }
            DecodeStep::Eof => {
                flush(
                    &mut current,
                    &mut char_count,
                    start_offset,
                    unit_start,
                    &mut results,
                );
                break;
            }
        }
    }

    flush(&mut current, &mut char_count, start_offset, i, &mut results);

    results
}

/// Extract printable strings from binary data.
///
/// Supports ASCII and UTF-16LE encodings. Uses rayon parallelism for
/// ASCII scanning on files larger than 1 MB.
///
/// # Arguments
///
/// * `data` - Source binary data to scan
/// * `min_length` - Minimum character length for a string to be included
/// * `include_ascii` - Whether to scan for ASCII strings
/// * `include_utf16` - Whether to scan for UTF-16LE strings
/// * `max_results` - Maximum number of results to return
#[must_use]
pub fn extract_strings(
    data: &[u8],
    min_length: usize,
    include_ascii: bool,
    include_utf16: bool,
    max_results: usize,
) -> Vec<StringMatch> {
    let mut all_results: Vec<StringMatch> = Vec::new();

    if include_ascii {
        let ascii_results = if data.len() > PARALLEL_THRESHOLD {
            extract_ascii_strings_parallel(data, min_length)
        } else {
            extract_ascii_strings(data, min_length)
        };
        all_results.extend(ascii_results);
    }

    if include_utf16 {
        let utf16_results = extract_utf16le_strings(data, min_length);
        all_results.extend(utf16_results);
    }

    all_results.sort_by_key(|r| r.offset);

    if all_results.len() > max_results {
        all_results.truncate(max_results);
    }

    all_results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ascii_extraction() {
        let data = b"\x00\x00Hello World\x00\x00Hi\x00\x00ABCDEF\x00";
        let results = extract_strings(data, 4, true, false, 100);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].content, "Hello World");
        assert_eq!(results[0].encoding, "ascii");
        assert_eq!(results[1].content, "ABCDEF");
    }

    #[test]
    fn test_utf16le_extraction() {
        let text = "Hello";
        let mut data: Vec<u8> = vec![0, 0];
        for &b in text.as_bytes() {
            data.push(b);
            data.push(0);
        }
        data.extend_from_slice(&[0, 0]);
        let results = extract_strings(&data, 4, false, true, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "Hello");
        assert_eq!(results[0].encoding, "utf16le");
    }

    #[test]
    fn test_max_results() {
        let mut data = Vec::new();
        for _ in 0..100 {
            data.extend_from_slice(b"\x00ABCDEFGH\x00");
        }
        let results = extract_strings(&data, 4, true, false, 10);
        assert_eq!(results.len(), 10);
    }

    fn encode_utf16le(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for unit in text.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out
    }

    #[test]
    fn test_utf16le_cyrillic() {
        let text = "Привет";
        let mut data: Vec<u8> = vec![0, 0];
        data.extend_from_slice(&encode_utf16le(text));
        data.extend_from_slice(&[0, 0]);
        let results = extract_strings(&data, 4, false, true, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, text);
        assert_eq!(results[0].encoding, "utf16le");
        assert_eq!(results[0].offset, 2);
        assert_eq!(results[0].length, text.encode_utf16().count() * 2);
    }

    #[test]
    fn test_utf16le_emoji_supplementary_plane() {
        let text = "Hi\u{1F600}!";
        let mut data: Vec<u8> = vec![0, 0];
        data.extend_from_slice(&encode_utf16le(text));
        data.extend_from_slice(&[0, 0]);
        let results = extract_strings(&data, 4, false, true, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, text);
        assert_eq!(results[0].encoding, "utf16le");
        assert_eq!(results[0].offset, 2);
        assert_eq!(results[0].length, text.encode_utf16().count() * 2);
    }

    #[test]
    fn test_utf16le_dangling_high_surrogate_terminates() {
        let mut data: Vec<u8> = vec![0, 0];
        data.extend_from_slice(&encode_utf16le("Hello"));
        data.extend_from_slice(&[0x00, 0xD8]);
        data.extend_from_slice(&encode_utf16le("World"));
        data.extend_from_slice(&[0, 0]);
        let results = extract_strings(&data, 4, false, true, 100);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].content, "Hello");
        assert_eq!(results[1].content, "World");
    }

    #[test]
    fn test_utf16le_dangling_high_surrogate_at_eof() {
        let mut data: Vec<u8> = vec![0, 0];
        data.extend_from_slice(&encode_utf16le("Hello"));
        data.extend_from_slice(&[0x00, 0xD8]);
        let results = extract_strings(&data, 4, false, true, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "Hello");
    }

    #[test]
    fn test_utf16le_lone_low_surrogate_terminates() {
        let mut data: Vec<u8> = vec![0, 0];
        data.extend_from_slice(&encode_utf16le("Hello"));
        data.extend_from_slice(&[0x00, 0xDC]);
        data.extend_from_slice(&encode_utf16le("World"));
        data.extend_from_slice(&[0, 0]);
        let results = extract_strings(&data, 4, false, true, 100);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].content, "Hello");
        assert_eq!(results[1].content, "World");
    }

    #[test]
    fn test_ascii_parallel_large_buffer_offset_stitching_and_sort() {
        // > 1 MiB drives the rayon path; a 20-byte run straddling the 65536 chunk seam
        // must be stitched back into a single match with correct absolute offset.
        let total = 2 * 1024 * 1024;
        let mut data = vec![0u8; total];
        data[100..111].copy_from_slice(b"FIRSTSTRING");
        for b in &mut data[65530..65550] {
            *b = b'A';
        }
        data[200_000..200_010].copy_from_slice(b"LASTSTRING");
        let results = extract_strings(&data, 4, true, false, 100);
        let got: Vec<(usize, String)> = results
            .iter()
            .map(|r| (r.offset, r.content.clone()))
            .collect();
        assert_eq!(
            got,
            vec![
                (100, "FIRSTSTRING".to_string()),
                (65530, "A".repeat(20)),
                (200_000, "LASTSTRING".to_string()),
            ]
        );
    }

    #[test]
    fn test_ascii_parallel_boundary_stitch_recovers_run_below_per_chunk_min_length() {
        // A 6-byte run split 3/3 across the chunk seam: each half is below
        // min_length=4 in isolation but the stitched whole must be reported.
        let total = 2 * 1024 * 1024;
        let mut data = vec![0u8; total];
        for b in &mut data[PARALLEL_CHUNK_SIZE - 3..PARALLEL_CHUNK_SIZE + 3] {
            *b = b'B';
        }
        let results = extract_strings(&data, 4, true, false, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, PARALLEL_CHUNK_SIZE - 3);
        assert_eq!(results[0].content, "BBBBBB");
    }

    #[test]
    fn test_ascii_run_to_eof_no_trailing_terminator() {
        let data = b"\x00GOODBYE";
        let results = extract_strings(data, 4, true, false, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "GOODBYE");
        assert_eq!(results[0].offset, 1);
    }

    #[test]
    fn test_ascii_whitespace_bytes_are_printable() {
        // \t \n \r are printable per is_printable_ascii.
        let data = b"\x00A\tB\nC\rD\x00";
        let results = extract_strings(data, 4, true, false, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "A\tB\nC\rD");
    }

    #[test]
    fn test_utf16le_shorter_than_two_bytes_is_empty() {
        let results = extract_strings(&[0x41], 4, false, true, 100);
        assert!(results.is_empty());
    }

    #[test]
    fn test_utf16le_min_length_zero_no_spurious_empty_matches() {
        // A run of NUL-terminated control units flushes with nothing accumulated;
        // min_length=0 must not fabricate empty-content matches at every terminator.
        let data = vec![0u8; 40];
        let results = extract_strings(&data, 0, false, true, 100);
        assert!(results.is_empty());
    }

    #[test]
    fn test_utf16le_min_length_zero_still_reports_real_strings() {
        let mut data: Vec<u8> = vec![0, 0];
        data.extend_from_slice(&encode_utf16le("Hi"));
        data.extend_from_slice(&[0, 0]);
        let results = extract_strings(&data, 0, false, true, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "Hi");
    }

    #[test]
    fn test_utf16le_mid_string_control_char_flushes() {
        // "ABCD" then U+0001 (control, flush) then "EFGH".
        let mut data: Vec<u8> = vec![0, 0];
        data.extend_from_slice(&encode_utf16le("ABCD"));
        data.extend_from_slice(&[0x01, 0x00]); // U+0001 control -> flush
        data.extend_from_slice(&encode_utf16le("EFGH"));
        data.extend_from_slice(&[0, 0]);
        let results = extract_strings(&data, 2, false, true, 100);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].content, "ABCD");
        assert_eq!(results[1].content, "EFGH");
    }

    #[test]
    fn test_combined_ascii_and_utf16_merge() {
        // ASCII string at offset 0 (even length), a 0x00,0x00 pair flushes the UTF-16
        // scanner, then "UNICODE" begins at an even offset so it decodes cleanly.
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(b"ASCIISTR"); // ascii at offset 0
        data.extend_from_slice(&[0x00, 0x00]);
        data.extend_from_slice(&encode_utf16le("UNICODE"));
        data.extend_from_slice(&[0, 0]);

        let results = extract_strings(&data, 4, true, true, 100);
        assert!(results
            .iter()
            .any(|r| r.encoding == "ascii" && r.content == "ASCIISTR"));
        assert!(results
            .iter()
            .any(|r| r.encoding == "utf16le" && r.content == "UNICODE"));
        // offsets must be globally sorted after the merge
        assert!(results.windows(2).all(|w| w[0].offset <= w[1].offset));

        // max_results truncation applies after the merge
        let truncated = extract_strings(&data, 4, true, true, 1);
        assert_eq!(truncated.len(), 1);
    }
}
