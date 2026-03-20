use rayon::prelude::*;

#[derive(Debug, Clone)]
pub struct SearchResult {
    pub offset: usize,
    pub length: usize,
    pub matched_bytes: Vec<u8>,
}

const CHUNK_SIZE: usize = 4 * 1024 * 1024;

fn build_bad_char_table(pattern: &[u8]) -> [usize; 256] {
    let plen = pattern.len();
    let mut table = [plen; 256];
    for i in 0..plen.saturating_sub(1) {
        table[pattern[i] as usize] = plen - 1 - i;
    }
    table
}

pub fn search_bytes(data: &[u8], pattern: &[u8], max_results: usize) -> Vec<SearchResult> {
    if pattern.is_empty() || data.len() < pattern.len() {
        return Vec::new();
    }

    let plen = pattern.len();
    let overlap = plen.saturating_sub(1);

    if data.len() <= CHUNK_SIZE {
        return search_bytes_single(data, pattern, max_results, 0);
    }

    let mut chunks: Vec<(usize, &[u8])> = Vec::new();
    let mut start: usize = 0;
    while start < data.len() {
        let end = (start + CHUNK_SIZE + overlap).min(data.len());
        chunks.push((start, &data[start..end]));
        start += CHUNK_SIZE;
    }

    let mut all_results: Vec<SearchResult> = chunks
        .par_iter()
        .flat_map(|(chunk_offset, chunk)| {
            search_bytes_single(chunk, pattern, max_results, *chunk_offset)
        })
        .collect();

    all_results.sort_by_key(|r| r.offset);
    all_results.dedup_by_key(|r| r.offset);
    all_results.truncate(max_results);
    all_results
}

fn search_bytes_single(
    data: &[u8],
    pattern: &[u8],
    max_results: usize,
    base_offset: usize,
) -> Vec<SearchResult> {
    let plen = pattern.len();
    if data.len() < plen {
        return Vec::new();
    }

    let bad_char = build_bad_char_table(pattern);
    let mut results = Vec::new();
    let mut i: usize = plen - 1;

    while i < data.len() && results.len() < max_results {
        let mut j = plen - 1;
        let mut k = i;

        loop {
            if data[k] != pattern[j] {
                break;
            }
            if j == 0 {
                let match_start = k;
                results.push(SearchResult {
                    offset: base_offset + match_start,
                    length: plen,
                    matched_bytes: data[match_start..match_start + plen].to_vec(),
                });
                break;
            }
            j -= 1;
            k -= 1;
        }

        let shift = bad_char[data[i] as usize];
        i += shift.max(1);
    }

    results
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HexNibble {
    Value(u8),
    Wildcard,
}

fn parse_hex_pattern(pattern_str: &str) -> Option<Vec<(u8, u8)>> {
    let cleaned: String = pattern_str
        .chars()
        .filter(|c| c.is_ascii_hexdigit() || *c == '?' || *c == ' ')
        .collect();

    let mut nibbles: Vec<HexNibble> = Vec::new();
    let mut chars = cleaned.chars().peekable();

    while let Some(&ch) = chars.peek() {
        if ch == ' ' {
            chars.next();
            continue;
        }
        if ch == '?' {
            nibbles.push(HexNibble::Wildcard);
            chars.next();
            continue;
        }
        if ch.is_ascii_hexdigit() {
            let val = ch.to_digit(16).unwrap() as u8;
            nibbles.push(HexNibble::Value(val));
            chars.next();
            continue;
        }
        chars.next();
    }

    if nibbles.len() % 2 != 0 {
        return None;
    }

    let mut bytes = Vec::new();
    for pair in nibbles.chunks(2) {
        let (value, mask) = match (pair[0], pair[1]) {
            (HexNibble::Value(hi), HexNibble::Value(lo)) => ((hi << 4) | lo, 0xFF),
            (HexNibble::Value(hi), HexNibble::Wildcard) => (hi << 4, 0xF0),
            (HexNibble::Wildcard, HexNibble::Value(lo)) => (lo, 0x0F),
            (HexNibble::Wildcard, HexNibble::Wildcard) => (0x00, 0x00),
        };
        bytes.push((value, mask));
    }

    Some(bytes)
}

pub fn search_hex_with_wildcards(
    data: &[u8],
    pattern_str: &str,
    max_results: usize,
) -> Vec<SearchResult> {
    let pattern = match parse_hex_pattern(pattern_str) {
        Some(p) => p,
        None => return Vec::new(),
    };

    if pattern.is_empty() || data.len() < pattern.len() {
        return Vec::new();
    }

    let plen = pattern.len();
    let has_wildcards = pattern.iter().any(|(_, mask)| *mask != 0xFF);

    if !has_wildcards {
        let exact: Vec<u8> = pattern.iter().map(|(v, _)| *v).collect();
        return search_bytes(data, &exact, max_results);
    }

    let overlap = plen.saturating_sub(1);

    if data.len() <= CHUNK_SIZE {
        return search_masked_single(data, &pattern, max_results, 0);
    }

    let mut chunks: Vec<(usize, &[u8])> = Vec::new();
    let mut start: usize = 0;
    while start < data.len() {
        let end = (start + CHUNK_SIZE + overlap).min(data.len());
        chunks.push((start, &data[start..end]));
        start += CHUNK_SIZE;
    }

    let mut all_results: Vec<SearchResult> = chunks
        .par_iter()
        .flat_map(|(chunk_offset, chunk)| {
            search_masked_single(chunk, &pattern, max_results, *chunk_offset)
        })
        .collect();

    all_results.sort_by_key(|r| r.offset);
    all_results.dedup_by_key(|r| r.offset);
    all_results.truncate(max_results);
    all_results
}

fn search_masked_single(
    data: &[u8],
    pattern: &[(u8, u8)],
    max_results: usize,
    base_offset: usize,
) -> Vec<SearchResult> {
    let plen = pattern.len();
    let mut results = Vec::new();

    for i in 0..=data.len().saturating_sub(plen) {
        if results.len() >= max_results {
            break;
        }

        let mut matched = true;
        for (j, (value, mask)) in pattern.iter().enumerate() {
            if (data[i + j] & mask) != (*value & mask) {
                matched = false;
                break;
            }
        }

        if matched {
            results.push(SearchResult {
                offset: base_offset + i,
                length: plen,
                matched_bytes: data[i..i + plen].to_vec(),
            });
        }
    }

    results
}

pub fn search_text(
    data: &[u8],
    text: &str,
    encoding: &str,
    case_sensitive: bool,
    max_results: usize,
) -> Vec<SearchResult> {
    let search_text = if case_sensitive {
        text.to_string()
    } else {
        text.to_lowercase()
    };

    let encoded: Vec<u8> = match encoding.to_lowercase().as_str() {
        "ascii" | "utf-8" | "utf8" => {
            if case_sensitive {
                search_text.as_bytes().to_vec()
            } else {
                search_text.as_bytes().to_vec()
            }
        }
        "utf-16le" | "utf16le" => search_text
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect(),
        "utf-16be" | "utf16be" => search_text
            .encode_utf16()
            .flat_map(|u| u.to_be_bytes())
            .collect(),
        _ => search_text.as_bytes().to_vec(),
    };

    if !case_sensitive && matches!(encoding.to_lowercase().as_str(), "ascii" | "utf-8" | "utf8") {
        let mut results = Vec::new();
        let plen = encoded.len();

        for i in 0..=data.len().saturating_sub(plen) {
            if results.len() >= max_results {
                break;
            }

            let window = &data[i..i + plen];
            let window_lower: Vec<u8> = window.iter().map(|b| b.to_ascii_lowercase()).collect();

            if window_lower == encoded {
                results.push(SearchResult {
                    offset: i,
                    length: plen,
                    matched_bytes: window.to_vec(),
                });
            }
        }
        results
    } else {
        search_bytes(data, &encoded, max_results)
    }
}

pub fn search_regex(data: &[u8], pattern: &str, max_results: usize) -> Vec<SearchResult> {
    let re = match regex::bytes::Regex::new(pattern) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut results = Vec::new();
    for m in re.find_iter(data) {
        if results.len() >= max_results {
            break;
        }
        results.push(SearchResult {
            offset: m.start(),
            length: m.len(),
            matched_bytes: m.as_bytes().to_vec(),
        });
    }
    results
}

pub fn replace_all(
    data: &[u8],
    pattern: &[u8],
    replacement: &[u8],
) -> (Vec<u8>, usize) {
    if pattern.is_empty() {
        return (data.to_vec(), 0);
    }

    let matches = search_bytes(data, pattern, usize::MAX);
    if matches.is_empty() {
        return (data.to_vec(), 0);
    }

    let count = matches.len();
    let new_len = data.len() + count * replacement.len() - count * pattern.len();
    let mut result = Vec::with_capacity(new_len);
    let mut last_end: usize = 0;

    for m in &matches {
        result.extend_from_slice(&data[last_end..m.offset]);
        result.extend_from_slice(replacement);
        last_end = m.offset + m.length;
    }
    result.extend_from_slice(&data[last_end..]);

    (result, count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_bytes_exact() {
        let data = b"Hello World Hello";
        let results = search_bytes(data, b"Hello", 10);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].offset, 0);
        assert_eq!(results[1].offset, 12);
    }

    #[test]
    fn test_search_bytes_no_match() {
        let data = b"Hello World";
        let results = search_bytes(data, b"xyz", 10);
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_bytes_max_results() {
        let data = b"AAAA";
        let results = search_bytes(data, b"A", 2);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_search_hex_exact() {
        let data = vec![0x4D, 0x5A, 0x90, 0x00, 0x03];
        let results = search_hex_with_wildcards(&data, "4D 5A", 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 0);
    }

    #[test]
    fn test_search_hex_wildcard() {
        let data = vec![0x4D, 0x5A, 0x90, 0x00, 0x4D, 0xFF, 0x90];
        let results = search_hex_with_wildcards(&data, "4D ?? 90", 10);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].offset, 0);
        assert_eq!(results[1].offset, 4);
    }

    #[test]
    fn test_search_hex_nibble_wildcard() {
        let data = vec![0xA0, 0xA1, 0xA2, 0xB0];
        let results = search_hex_with_wildcards(&data, "A?", 10);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_search_text_case_sensitive() {
        let data = b"Hello hello HELLO";
        let results = search_text(data, "Hello", "utf-8", true, 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 0);
    }

    #[test]
    fn test_search_text_case_insensitive() {
        let data = b"Hello hello HELLO";
        let results = search_text(data, "hello", "utf-8", false, 10);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_search_text_utf16le() {
        let text = "AB";
        let encoded: Vec<u8> = text
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let mut data = vec![0x00; 10];
        data.extend_from_slice(&encoded);
        data.extend_from_slice(&[0x00; 10]);

        let results = search_text(&data, "AB", "utf-16le", true, 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 10);
    }

    #[test]
    fn test_search_regex_basic() {
        let data = b"test123 test456";
        let results = search_regex(data, r"test\d+", 10);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_search_regex_no_match() {
        let data = b"hello world";
        let results = search_regex(data, r"\d+", 10);
        assert!(results.is_empty());
    }

    #[test]
    fn test_replace_all() {
        let data = b"AABAA";
        let (result, count) = replace_all(data, b"AA", b"X");
        assert_eq!(count, 2);
        assert_eq!(result, b"XBX".to_vec());
    }

    #[test]
    fn test_replace_all_no_match() {
        let data = b"ABC";
        let (result, count) = replace_all(data, b"XY", b"Z");
        assert_eq!(count, 0);
        assert_eq!(result, data.to_vec());
    }

    #[test]
    fn test_search_empty_pattern() {
        let data = b"Hello";
        let results = search_bytes(data, b"", 10);
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_pattern_longer_than_data() {
        let data = b"Hi";
        let results = search_bytes(data, b"Hello World", 10);
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_hex_pattern_valid() {
        let result = parse_hex_pattern("4D 5A ?? 00").unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], (0x4D, 0xFF));
        assert_eq!(result[1], (0x5A, 0xFF));
        assert_eq!(result[2], (0x00, 0x00));
        assert_eq!(result[3], (0x00, 0xFF));
    }
}
