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

fn extract_ascii_strings(data: &[u8], min_length: usize) -> Vec<StringMatch> {
    let mut results = Vec::new();
    let mut start: Option<usize> = None;

    for (i, &byte) in data.iter().enumerate() {
        if is_printable_ascii(byte) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start {
            let len = i - s;
            if len >= min_length {
                let content = String::from_utf8_lossy(&data[s..i]).to_string();
                results.push(StringMatch {
                    offset: s,
                    length: len,
                    encoding: "ascii".to_string(),
                    content,
                });
            }
            start = None;
        }
    }

    if let Some(s) = start {
        let len = data.len() - s;
        if len >= min_length {
            let content = String::from_utf8_lossy(&data[s..]).to_string();
            results.push(StringMatch {
                offset: s,
                length: len,
                encoding: "ascii".to_string(),
                content,
            });
        }
    }

    results
}

fn extract_ascii_strings_parallel(data: &[u8], min_length: usize) -> Vec<StringMatch> {
    let chunks: Vec<(usize, &[u8])> = data
        .chunks(PARALLEL_CHUNK_SIZE)
        .enumerate()
        .map(|(i, chunk)| (i * PARALLEL_CHUNK_SIZE, chunk))
        .collect();

    let mut all_results: Vec<StringMatch> = chunks
        .par_iter()
        .flat_map(|(base_offset, chunk)| {
            let mut chunk_results = extract_ascii_strings(chunk, min_length);
            for r in &mut chunk_results {
                r.offset += base_offset;
            }
            chunk_results
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
        if *char_count >= min_length {
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
}
