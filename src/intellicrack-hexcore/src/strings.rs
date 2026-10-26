// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Zachary Flint
//
// This file is part of Intellicrack. See LICENSE for details.

//! Full-document string extraction (ASCII, UTF-16LE and UTF-16BE).
//!
//! Scans binary data for printable ASCII and UTF-16 string sequences in
//! either byte order, with optional rayon parallelism for large files. Every
//! encoding accepts the same character set: printable ASCII plus tab, CR and
//! LF. For UTF-16 that means a code unit counts only when its high byte is
//! zero, which is what dedicated hex editors and `strings`-style tools report;
//! accepting any non-control scalar instead turns random or compressed bytes
//! into a flood of spurious "wide strings".

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
    /// Encoding of the matched string ("ascii", "utf16le" or "utf16be").
    pub encoding: &'static str,
    /// Decoded string content.
    pub content: String,
}

/// Which encodings a string scan reports.
///
/// UTF-16LE and UTF-16BE are scanned independently, as `strings -e l` and
/// `strings -e b` are. A run such as `00 41 00 42 00 43 00 44 00` is a valid
/// reading in both byte orders, one byte apart, so asking for both reports
/// each reading instead of guessing which one the file meant.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StringEncodings {
    /// Printable ASCII runs.
    pub ascii: bool,
    /// UTF-16 little-endian runs, the Windows wide-string layout.
    pub utf16le: bool,
    /// UTF-16 big-endian runs, as in Java class files, network byte order and
    /// classic Mac resources.
    pub utf16be: bool,
}

/// Byte order of a UTF-16 code unit.
#[derive(Clone, Copy)]
enum Utf16Order {
    Little,
    Big,
}

impl Utf16Order {
    /// The printable ASCII byte a two-byte code unit encodes in this byte
    /// order, or `None` when its high byte is not zero or its low byte is not
    /// printable.
    fn printable_unit(self, first: u8, second: u8) -> Option<u8> {
        let (low, high) = match self {
            Self::Little => (first, second),
            Self::Big => (second, first),
        };
        (high == 0 && is_printable_ascii(low)).then_some(low)
    }

    fn label(self) -> &'static str {
        match self {
            Self::Little => "utf16le",
            Self::Big => "utf16be",
        }
    }
}

fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7E).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r'
}

/// A run of printable ASCII bytes, `offset..offset + len`.
#[derive(Clone, Copy)]
struct Span {
    offset: usize,
    len: usize,
}

/// Collects the printable-ASCII runs of `data` (offsets relative to `data`).
///
/// A run is kept when it is at least `min_length` long or touches either end
/// of `data` (it may continue into a neighboring chunk); at most
/// `max_results` qualifying interior runs are kept, which is exact because
/// later runs in the same slice can never precede earlier ones.
fn ascii_spans(data: &[u8], min_length: usize, max_results: usize) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut kept_interior = 0usize;
    let mut start: Option<usize> = None;
    for i in 0..=data.len() {
        let printable = i < data.len() && is_printable_ascii(data[i]);
        match (printable, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                start = None;
                let span = Span {
                    offset: s,
                    len: i - s,
                };
                let at_edge = s == 0 || i == data.len();
                if at_edge {
                    spans.push(span);
                } else if span.len >= min_length && kept_interior < max_results {
                    kept_interior += 1;
                    spans.push(span);
                }
            }
            _ => {}
        }
    }
    spans
}

fn ascii_match(data: &[u8], span: Span) -> StringMatch {
    StringMatch {
        offset: span.offset,
        length: span.len,
        encoding: "ascii",
        content: data[span.offset..span.offset + span.len]
            .iter()
            .map(|&b| char::from(b))
            .collect(),
    }
}

fn extract_ascii_strings(data: &[u8], min_length: usize, max_results: usize) -> Vec<StringMatch> {
    ascii_spans(data, min_length, max_results)
        .into_iter()
        .filter(|span| span.len >= min_length)
        .take(max_results)
        .map(|span| ascii_match(data, span))
        .collect()
}

fn extract_ascii_strings_parallel(
    data: &[u8],
    min_length: usize,
    max_results: usize,
) -> Vec<StringMatch> {
    let batch_len = PARALLEL_CHUNK_SIZE * rayon::current_num_threads().max(1) * CHUNKS_PER_THREAD;
    ascii_spans_batched(data, min_length, max_results, batch_len)
        .into_iter()
        .map(|span| ascii_match(data, span))
        .collect()
}

/// Chunks each rayon thread scans per batch of [`ascii_spans_batched`], enough
/// to keep the pool busy while bounding how much a batch holds.
const CHUNKS_PER_THREAD: usize = 4;

/// The first `max_results` printable-ASCII runs of `data` at least
/// `min_length` long, found by scanning `batch_len` bytes at a time with the
/// batch's chunks in parallel.
///
/// Runs that abut a chunk seam are stitched back into one continuous run
/// before the `min_length` filter, so a string split across a chunk or batch
/// boundary is neither fragmented nor dropped. The last run of a batch stays
/// open until the next batch shows where it ends. Scanning stops as soon as
/// `max_results` runs are final, and each chunk keeps only as many interior
/// runs as are still needed, so the candidates held at once are bounded by one
/// batch rather than by the size of `data`. `batch_len` must be a multiple of
/// the chunk size, so chunk boundaries fall at the same offsets in every
/// batch.
fn ascii_spans_batched(
    data: &[u8],
    min_length: usize,
    max_results: usize,
    batch_len: usize,
) -> Vec<Span> {
    let mut kept: Vec<Span> = Vec::new();
    if max_results == 0 {
        return kept;
    }
    let mut open: Option<Span> = None;
    for (batch_index, batch) in data.chunks(batch_len).enumerate() {
        let needed = max_results - kept.len();
        let batch_base = batch_index * batch_len;
        let chunk_spans: Vec<Vec<Span>> = batch
            .par_chunks(PARALLEL_CHUNK_SIZE)
            .enumerate()
            .map(|(index, chunk)| {
                let base = batch_base + index * PARALLEL_CHUNK_SIZE;
                ascii_spans(chunk, min_length, needed)
                    .into_iter()
                    .map(|span| Span {
                        offset: span.offset + base,
                        len: span.len,
                    })
                    .collect()
            })
            .collect();
        for span in chunk_spans.into_iter().flatten() {
            match open.as_mut() {
                Some(prev) if prev.offset + prev.len == span.offset => prev.len += span.len,
                _ => {
                    if let Some(done) = open.replace(span) {
                        if done.len >= min_length {
                            kept.push(done);
                            if kept.len() == max_results {
                                return kept;
                            }
                        }
                    }
                }
            }
        }
    }
    if let Some(done) = open {
        if done.len >= min_length && kept.len() < max_results {
            kept.push(done);
        }
    }
    kept
}

/// Extracts UTF-16 strings in byte order `order` whose code units start at
/// offsets of the given `parity` (0 for even, 1 for odd).
fn extract_utf16_strings(
    data: &[u8],
    min_length: usize,
    parity: usize,
    max_results: usize,
    order: Utf16Order,
) -> Vec<StringMatch> {
    let mut results = Vec::new();
    let mut current = String::new();
    let mut start_offset = parity;
    let mut i = parity;
    loop {
        let unit = (i + 1 < data.len()).then(|| (data[i], data[i + 1]));
        if let Some(byte) = unit.and_then(|(first, second)| order.printable_unit(first, second)) {
            if current.is_empty() {
                start_offset = i;
            }
            current.push(char::from(byte));
        } else {
            if !current.is_empty() && current.len() >= min_length {
                results.push(StringMatch {
                    offset: start_offset,
                    length: i - start_offset,
                    encoding: order.label(),
                    content: std::mem::take(&mut current),
                });
                if results.len() >= max_results {
                    break;
                }
            }
            current.clear();
            if unit.is_none() {
                break;
            }
        }
        i += 2;
    }
    results
}

/// Extract printable strings from binary data.
///
/// Scans for each encoding `encodings` enables; UTF-16 strings in either byte
/// order are found at both even and odd byte offsets. Uses rayon parallelism
/// for ASCII scanning on files larger than 1 MB. Each encoding stops after
/// `max_results` matches, which is exact because results are returned in
/// offset order; the merged list is sorted by offset (ties keep ASCII, then
/// UTF-16LE, then UTF-16BE) and truncated to `max_results`.
///
/// # Arguments
///
/// * `data` - Source binary data to scan
/// * `min_length` - Minimum character length for a string to be included
/// * `encodings` - Which encodings to scan for
/// * `max_results` - Maximum number of results to return
#[must_use]
pub fn extract_strings(
    data: &[u8],
    min_length: usize,
    encodings: StringEncodings,
    max_results: usize,
) -> Vec<StringMatch> {
    if max_results == 0 {
        return Vec::new();
    }
    let mut all_results: Vec<StringMatch> = Vec::new();

    if encodings.ascii {
        let ascii_results = if data.len() > PARALLEL_THRESHOLD {
            extract_ascii_strings_parallel(data, min_length, max_results)
        } else {
            extract_ascii_strings(data, min_length, max_results)
        };
        all_results.extend(ascii_results);
    }

    for (enabled, order) in [
        (encodings.utf16le, Utf16Order::Little),
        (encodings.utf16be, Utf16Order::Big),
    ] {
        if enabled {
            for parity in [0, 1] {
                all_results.extend(extract_utf16_strings(
                    data,
                    min_length,
                    parity,
                    max_results,
                    order,
                ));
            }
        }
    }

    all_results.sort_by_key(|r| r.offset);
    all_results.truncate(max_results);
    all_results
}

#[cfg(test)]
mod tests {
    use super::*;

    const ASCII: StringEncodings = StringEncodings {
        ascii: true,
        utf16le: false,
        utf16be: false,
    };
    const UTF16LE: StringEncodings = StringEncodings {
        ascii: false,
        utf16le: true,
        utf16be: false,
    };
    const UTF16BE: StringEncodings = StringEncodings {
        ascii: false,
        utf16le: false,
        utf16be: true,
    };
    const ASCII_AND_UTF16LE: StringEncodings = StringEncodings {
        ascii: true,
        utf16le: true,
        utf16be: false,
    };

    fn encode_utf16be(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_be_bytes).collect()
    }

    fn found(results: &[StringMatch]) -> Vec<(usize, usize, &'static str, &str)> {
        results
            .iter()
            .map(|r| (r.offset, r.length, r.encoding, r.content.as_str()))
            .collect()
    }

    /// Big-endian UTF-16 text is reported under its own label at its exact
    /// even offset, and the scan only runs when it is asked for: the
    /// little-endian scan reads the same bytes as a one-byte-shifted shadow
    /// labeled `utf16le`, never as `utf16be`.
    #[test]
    fn test_utf16be_extraction_reports_big_endian_strings() {
        let mut data = vec![0xFF, 0xFF];
        data.extend_from_slice(&encode_utf16be("Hello"));
        data.extend_from_slice(&[0xFF, 0xFF]);

        assert_eq!(
            found(&extract_strings(&data, 4, UTF16BE, 100)),
            vec![(2, 10, "utf16be", "Hello")]
        );
        assert!(extract_strings(&data, 4, UTF16LE, 100)
            .iter()
            .all(|r| r.encoding == "utf16le"));
        assert!(extract_strings(&data, 4, StringEncodings::default(), 100).is_empty());
    }

    /// Big-endian text starting at an odd offset is found by the odd-parity
    /// scan, with the even-parity reading of the same bytes contributing
    /// nothing.
    #[test]
    fn test_utf16be_odd_aligned_string_found() {
        let mut data = vec![0xFF];
        data.extend_from_slice(&encode_utf16be("World"));
        data.extend_from_slice(&[0xFF, 0xFF]);
        assert_eq!(
            found(&extract_strings(&data, 4, UTF16BE, 100)),
            vec![(1, 10, "utf16be", "World")]
        );
    }

    #[test]
    fn test_ascii_extraction() {
        let data = b"\x00\x00Hello World\x00\x00Hi\x00\x00ABCDEF\x00";
        let results = extract_strings(data, 4, ASCII, 100);
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
        let results = extract_strings(&data, 4, UTF16LE, 100);
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
        let results = extract_strings(&data, 4, ASCII, 10);
        assert_eq!(results.len(), 10);
    }

    fn encode_utf16le(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for unit in text.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out
    }

    /// The UTF-16LE scanner must accept only printable ASCII code units. Accepting
    /// any non-control scalar lets non-ASCII units (and, on random bytes, almost every
    /// unit) form "wide strings", which disagrees with the strict printable-ASCII
    /// rule of the Python fallback and of dedicated hex editors.
    #[test]
    fn test_utf16le_rejects_non_ascii_code_units() {
        let mut data = vec![0u8; 32];
        data.extend_from_slice(&encode_utf16le(&"\u{2070}".repeat(16)));
        data.extend_from_slice(&[0u8; 32]);
        assert!(extract_strings(&data, 4, UTF16LE, 100).is_empty());

        let mut cyrillic: Vec<u8> = vec![0, 0];
        cyrillic.extend_from_slice(&encode_utf16le("Привет"));
        cyrillic.extend_from_slice(&[0, 0]);
        assert!(extract_strings(&cyrillic, 4, UTF16LE, 100).is_empty());
    }

    #[test]
    fn test_utf16le_supplementary_plane_splits_ascii_runs() {
        let mut data: Vec<u8> = vec![0, 0];
        data.extend_from_slice(&encode_utf16le("Hi\u{1F600}!"));
        data.extend_from_slice(&[0, 0]);
        let results = extract_strings(&data, 2, UTF16LE, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "Hi");
        assert_eq!(results[0].offset, 2);
        assert_eq!(results[0].length, 4);
    }

    /// UTF-16LE text at an odd offset must be reported. Scanning only even offsets
    /// misses it, and the even-parity reading of the same bytes produces garbage
    /// units instead.
    #[test]
    fn test_utf16le_odd_aligned_string_found() {
        let mut data = vec![0xFFu8];
        data.extend_from_slice(&encode_utf16le("Hello"));
        data.extend_from_slice(&[0u8; 32]);
        let results = extract_strings(&data, 4, UTF16LE, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 1);
        assert_eq!(results[0].length, 10);
        assert_eq!(results[0].content, "Hello");
    }

    /// Runs below `min_length` must be dropped before they are materialized as heap
    /// `String`s. Materializing every run first costs several times the buffer size
    /// in allocations for a buffer of short runs.
    #[test]
    fn test_ascii_spans_keep_only_qualifying_and_edge_runs() {
        let mut data = vec![0u8];
        for _ in 0..1000 {
            data.extend_from_slice(b"A\x00");
        }
        assert_eq!(ascii_spans(&data, 4, usize::MAX).len(), 0);
        let edges = ascii_spans(b"AB\x00ABCDEF\x00CD", 4, usize::MAX);
        let got: Vec<(usize, usize)> = edges.iter().map(|s| (s.offset, s.len)).collect();
        assert_eq!(got, vec![(0, 2), (3, 6), (10, 2)]);
        assert_eq!(ascii_spans(b"\x00ABCD\x00EFGH\x00", 4, 1).len(), 1);
    }

    #[test]
    fn test_ascii_min_length_boundary_exact_included_one_below_excluded() {
        let results = extract_strings(b"\x00ABCD\x00EFG\x00", 4, ASCII, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 1);
        assert_eq!(results[0].length, 4);
        assert_eq!(results[0].content, "ABCD");
    }

    #[test]
    fn test_utf16le_min_length_boundary_exact_included_one_below_excluded() {
        let mut data: Vec<u8> = vec![0, 0];
        data.extend_from_slice(&encode_utf16le("ABCD"));
        data.extend_from_slice(&[0, 0]);
        data.extend_from_slice(&encode_utf16le("EFG"));
        data.extend_from_slice(&[0, 0]);
        let results = extract_strings(&data, 4, UTF16LE, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 2);
        assert_eq!(results[0].length, 8);
        assert_eq!(results[0].content, "ABCD");
    }

    #[test]
    fn test_parallel_cap_returns_first_matches_in_offset_order() {
        let mut data = vec![0u8; 2 * 1024 * 1024];
        for k in 0..200 {
            let at = 16 + k * 10_000;
            data[at..at + 5].copy_from_slice(b"QWERT");
        }
        let results = extract_strings(&data, 4, ASCII, 3);
        let offsets: Vec<usize> = results.iter().map(|r| r.offset).collect();
        assert_eq!(offsets, vec![16, 10_016, 20_016]);
    }

    #[test]
    fn test_utf16le_dangling_high_surrogate_terminates() {
        let mut data: Vec<u8> = vec![0, 0];
        data.extend_from_slice(&encode_utf16le("Hello"));
        data.extend_from_slice(&[0x00, 0xD8]);
        data.extend_from_slice(&encode_utf16le("World"));
        data.extend_from_slice(&[0, 0]);
        let results = extract_strings(&data, 4, UTF16LE, 100);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].content, "Hello");
        assert_eq!(results[1].content, "World");
    }

    #[test]
    fn test_utf16le_dangling_high_surrogate_at_eof() {
        let mut data: Vec<u8> = vec![0, 0];
        data.extend_from_slice(&encode_utf16le("Hello"));
        data.extend_from_slice(&[0x00, 0xD8]);
        let results = extract_strings(&data, 4, UTF16LE, 100);
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
        let results = extract_strings(&data, 4, UTF16LE, 100);
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
        let results = extract_strings(&data, 4, ASCII, 100);
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
        let results = extract_strings(&data, 4, ASCII, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, PARALLEL_CHUNK_SIZE - 3);
        assert_eq!(results[0].content, "BBBBBB");
    }

    /// The batched scan holds no more runs than it reports: on 2 MiB of dense
    /// five-byte runs it returns exactly the first ten, at offsets 0, 5, … 45,
    /// rather than ten per chunk across all 32 chunks.
    #[test]
    fn test_ascii_batched_scan_stops_at_max_results() {
        let data = b"ABCD\0".repeat((2 << 20) / 5);
        let spans = ascii_spans_batched(&data, 4, 10, 2 * PARALLEL_CHUNK_SIZE);
        let offsets: Vec<usize> = spans.iter().map(|span| span.offset).collect();
        assert_eq!(offsets, (0..10).map(|i| i * 5).collect::<Vec<_>>());
        assert!(spans.iter().all(|span| span.len == 4));
        assert_eq!(
            ascii_spans_batched(&data, 4, 0, 2 * PARALLEL_CHUNK_SIZE).len(),
            0
        );
    }

    /// Runs that cross a chunk seam or a batch seam come out whole and in
    /// order, the same runs a single sequential scan finds, including one
    /// that spans an entire batch.
    #[test]
    fn test_ascii_batched_scan_matches_a_sequential_scan_across_batch_seams() {
        let chunk = PARALLEL_CHUNK_SIZE;
        let batch = 2 * chunk;
        let mut data = vec![0u8; 7 * chunk + 123];
        for (start, len) in [
            (chunk - 3, 6),
            (batch - 2, 5),
            (2 * batch + 10, batch + 20),
            (5 * chunk + 7, 3),
            (7 * chunk + 100, 23),
        ] {
            data[start..start + len].fill(b'Z');
        }
        let sequential: Vec<(usize, usize)> = ascii_spans(&data, 4, usize::MAX)
            .into_iter()
            .filter(|span| span.len >= 4)
            .map(|span| (span.offset, span.len))
            .collect();
        let batched: Vec<(usize, usize)> = ascii_spans_batched(&data, 4, usize::MAX, batch)
            .into_iter()
            .map(|span| (span.offset, span.len))
            .collect();
        assert_eq!(
            batched,
            vec![
                (chunk - 3, 6),
                (batch - 2, 5),
                (2 * batch + 10, batch + 20),
                (7 * chunk + 100, 23)
            ]
        );
        assert_eq!(batched, sequential);
    }

    #[test]
    fn test_ascii_run_to_eof_no_trailing_terminator() {
        let data = b"\x00GOODBYE";
        let results = extract_strings(data, 4, ASCII, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "GOODBYE");
        assert_eq!(results[0].offset, 1);
    }

    #[test]
    fn test_ascii_whitespace_bytes_are_printable() {
        // \t \n \r are printable per is_printable_ascii.
        let data = b"\x00A\tB\nC\rD\x00";
        let results = extract_strings(data, 4, ASCII, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "A\tB\nC\rD");
    }

    #[test]
    fn test_utf16le_shorter_than_two_bytes_is_empty() {
        let results = extract_strings(&[0x41], 4, UTF16LE, 100);
        assert!(results.is_empty());
    }

    #[test]
    fn test_utf16le_min_length_zero_no_spurious_empty_matches() {
        // A run of NUL-terminated control units flushes with nothing accumulated;
        // min_length=0 must not fabricate empty-content matches at every terminator.
        let data = vec![0u8; 40];
        let results = extract_strings(&data, 0, UTF16LE, 100);
        assert!(results.is_empty());
    }

    #[test]
    fn test_utf16le_min_length_zero_still_reports_real_strings() {
        let mut data: Vec<u8> = vec![0, 0];
        data.extend_from_slice(&encode_utf16le("Hi"));
        data.extend_from_slice(&[0, 0]);
        let results = extract_strings(&data, 0, UTF16LE, 100);
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
        let results = extract_strings(&data, 2, UTF16LE, 100);
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

        let results = extract_strings(&data, 4, ASCII_AND_UTF16LE, 100);
        assert!(results
            .iter()
            .any(|r| r.encoding == "ascii" && r.content == "ASCIISTR"));
        assert!(results
            .iter()
            .any(|r| r.encoding == "utf16le" && r.content == "UNICODE"));
        // offsets must be globally sorted after the merge
        assert!(results.windows(2).all(|w| w[0].offset <= w[1].offset));

        // max_results truncation applies after the merge
        let truncated = extract_strings(&data, 4, ASCII_AND_UTF16LE, 1);
        assert_eq!(truncated.len(), 1);
    }
}
