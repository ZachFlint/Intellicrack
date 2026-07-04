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

fn build_good_suffix_table(pattern: &[u8]) -> Vec<usize> {
    let m = pattern.len();
    if m == 0 {
        return Vec::new();
    }
    let mut table = vec![m; m];
    let mut suffix = vec![0usize; m];

    suffix[m - 1] = m;
    let mut g: isize = m.cast_signed() - 1;
    let mut f: usize = 0;

    for i in (0..m - 1).rev() {
        let i_signed = i.cast_signed();
        if i_signed > g && suffix[i + m - 1 - f] < (i_signed - g).cast_unsigned() {
            suffix[i] = suffix[i + m - 1 - f];
        } else {
            if i_signed < g {
                g = i_signed;
            }
            f = i;
            while g >= 0 && pattern[g.cast_unsigned()] == pattern[g.cast_unsigned() + m - 1 - f] {
                g -= 1;
            }
            suffix[i] = (f.cast_signed() - g).cast_unsigned();
        }
    }

    let mut j = 0usize;
    for i in (0..m).rev() {
        if suffix[i] == i + 1 {
            while j < m - 1 - i {
                if table[j] == m {
                    table[j] = m - 1 - i;
                }
                j += 1;
            }
        }
    }

    for i in 0..m - 1 {
        table[m - 1 - suffix[i]] = m - 1 - i;
    }

    table
}

#[must_use]
pub fn search_bytes(data: &[u8], pattern: &[u8], max_results: usize) -> Vec<SearchResult> {
    if pattern.is_empty() || data.len() < pattern.len() {
        return Vec::new();
    }

    if data.len() <= CHUNK_SIZE {
        return search_bytes_single(data, pattern, max_results, 0);
    }

    let overlap = pattern.len().saturating_sub(1);
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
    let good_suffix = build_good_suffix_table(pattern);
    let mut results = Vec::new();
    let mut i: usize = 0;

    while i <= data.len() - plen && results.len() < max_results {
        let mut j = plen;
        while j > 0 && pattern[j - 1] == data[i + j - 1] {
            j -= 1;
        }

        if j == 0 {
            results.push(SearchResult {
                offset: base_offset + i,
                length: plen,
                matched_bytes: data[i..i + plen].to_vec(),
            });
            i += good_suffix[0];
        } else {
            let bc_shift = if bad_char[data[i + j - 1] as usize] > plen - j {
                bad_char[data[i + j - 1] as usize] - (plen - j)
            } else {
                1
            };
            let gs_shift = good_suffix[j - 1];
            i += bc_shift.max(gs_shift);
        }
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
            let val = u8::try_from(ch.to_digit(16).unwrap()).unwrap();
            nibbles.push(HexNibble::Value(val));
            chars.next();
            continue;
        }
        chars.next();
    }

    if !nibbles.len().is_multiple_of(2) {
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

#[must_use]
pub fn search_hex_with_wildcards(
    data: &[u8],
    pattern_str: &str,
    max_results: usize,
) -> Vec<SearchResult> {
    let Some(pattern) = parse_hex_pattern(pattern_str) else {
        return Vec::new();
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

    if data.len() <= CHUNK_SIZE {
        return search_masked_single(data, &pattern, max_results, 0);
    }

    let overlap = plen.saturating_sub(1);
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

#[must_use]
pub fn search_text(
    data: &[u8],
    text: &str,
    encoding: &str,
    case_sensitive: bool,
    max_results: usize,
) -> Vec<SearchResult> {
    if text.is_empty() {
        return Vec::new();
    }

    let encoded: Vec<u8> = match encoding.to_lowercase().as_str() {
        "utf-16le" | "utf16le" => text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        "utf-16be" | "utf16be" => text.encode_utf16().flat_map(u16::to_be_bytes).collect(),
        _ => text.as_bytes().to_vec(),
    };

    if encoded.is_empty() {
        return Vec::new();
    }

    if case_sensitive {
        return search_bytes(data, &encoded, max_results);
    }

    let plen = encoded.len();
    if data.len() < plen {
        return Vec::new();
    }

    let step = match encoding.to_lowercase().as_str() {
        "utf-16le" | "utf16le" | "utf-16be" | "utf16be" => 2,
        _ => 1,
    };
    let needle_lower = text.to_lowercase();
    let mut results = Vec::new();
    let last_start = data.len() - plen;
    let mut i: usize = 0;

    while i <= last_start && results.len() < max_results {
        let window = &data[i..i + plen];
        if window_matches_ci(window, &needle_lower, encoding) {
            results.push(SearchResult {
                offset: i,
                length: plen,
                matched_bytes: window.to_vec(),
            });
            i += plen.max(step);
        } else {
            i += step;
        }
    }
    results
}

fn window_matches_ci(window: &[u8], needle_lower: &str, encoding: &str) -> bool {
    let lower = encoding.to_lowercase();
    let decoded: String = match lower.as_str() {
        "utf-16le" | "utf16le" => {
            if !window.len().is_multiple_of(2) {
                return false;
            }
            let units: Vec<u16> = window
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            match String::from_utf16(&units) {
                Ok(s) => s,
                Err(_) => return false,
            }
        }
        "utf-16be" | "utf16be" => {
            if !window.len().is_multiple_of(2) {
                return false;
            }
            let units: Vec<u16> = window
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            match String::from_utf16(&units) {
                Ok(s) => s,
                Err(_) => return false,
            }
        }
        "utf-8" | "utf8" => match std::str::from_utf8(window) {
            Ok(s) => s.to_string(),
            Err(_) => return false,
        },
        "ascii" => {
            if window.iter().any(|&b| b & 0x80 != 0) {
                return false;
            }
            window.iter().map(|&b| b as char).collect()
        }
        _ => {
            let Some(enc) = encoding_rs::Encoding::for_label(encoding.as_bytes()) else {
                return false;
            };
            let (cow, had_errors) = enc.decode_without_bom_handling(window);
            if had_errors {
                return false;
            }
            cow.into_owned()
        }
    };

    decoded.to_lowercase() == needle_lower
}

#[must_use]
pub fn search_regex(data: &[u8], pattern: &str, max_results: usize) -> Vec<SearchResult> {
    let Some(re) = regex::bytes::Regex::new(pattern).ok() else {
        return Vec::new();
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

#[must_use]
pub fn replace_all(data: &[u8], pattern: &[u8], replacement: &[u8]) -> (Vec<u8>, usize) {
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

fn decode_uint(bytes: &[u8], size: usize, big_endian: bool) -> u64 {
    match size {
        1 => u64::from(bytes[0]),
        2 => {
            let arr = [bytes[0], bytes[1]];
            if big_endian {
                u64::from(u16::from_be_bytes(arr))
            } else {
                u64::from(u16::from_le_bytes(arr))
            }
        }
        3 => {
            if big_endian {
                (u64::from(bytes[0]) << 16) | (u64::from(bytes[1]) << 8) | u64::from(bytes[2])
            } else {
                u64::from(bytes[0]) | (u64::from(bytes[1]) << 8) | (u64::from(bytes[2]) << 16)
            }
        }
        4 => {
            let arr = [bytes[0], bytes[1], bytes[2], bytes[3]];
            if big_endian {
                u64::from(u32::from_be_bytes(arr))
            } else {
                u64::from(u32::from_le_bytes(arr))
            }
        }
        8 => {
            let arr = [
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ];
            if big_endian {
                u64::from_be_bytes(arr)
            } else {
                u64::from_le_bytes(arr)
            }
        }
        _ => 0,
    }
}

fn sign_extend(raw: u64, size: usize) -> i64 {
    match size {
        1 => {
            let byte = u8::try_from(raw & 0xFF).unwrap();
            i64::from(byte.cast_signed())
        }
        2 => {
            let half = u16::try_from(raw & 0xFFFF).unwrap();
            i64::from(half.cast_signed())
        }
        3 => {
            let shifted = raw << 40;
            shifted.cast_signed() >> 40
        }
        4 => {
            let word = u32::try_from(raw & 0xFFFF_FFFF).unwrap();
            i64::from(word.cast_signed())
        }
        _ => raw.cast_signed(),
    }
}

fn encode_uint_target(value: i64, size: usize, signed: bool, big_endian: bool) -> Option<Vec<u8>> {
    let raw: u64 = if signed {
        match size {
            1 => {
                let v = i8::try_from(value).ok()?;
                u64::from(v.cast_unsigned())
            }
            2 => {
                let v = i16::try_from(value).ok()?;
                u64::from(v.cast_unsigned())
            }
            3 => {
                if !(-8_388_608..=8_388_607).contains(&value) {
                    return None;
                }
                value.cast_unsigned() & 0xFF_FFFF
            }
            4 => {
                let v = i32::try_from(value).ok()?;
                u64::from(v.cast_unsigned())
            }
            8 => value.cast_unsigned(),
            _ => return None,
        }
    } else {
        if value < 0 {
            return None;
        }
        let uval = value.cast_unsigned();
        match size {
            1 => {
                if uval > 0xFF {
                    return None;
                }
                uval
            }
            2 => {
                if uval > 0xFFFF {
                    return None;
                }
                uval
            }
            3 => {
                if uval > 0xFF_FFFF {
                    return None;
                }
                uval
            }
            4 => {
                if uval > 0xFFFF_FFFF {
                    return None;
                }
                uval
            }
            8 => uval,
            _ => return None,
        }
    };

    let bytes = match size {
        1 => vec![u8::try_from(raw & 0xFF).unwrap()],
        2 => {
            let v = u16::try_from(raw & 0xFFFF).unwrap();
            if big_endian {
                v.to_be_bytes().to_vec()
            } else {
                v.to_le_bytes().to_vec()
            }
        }
        3 => {
            let b2 = u8::try_from((raw >> 16) & 0xFF).unwrap();
            let b1 = u8::try_from((raw >> 8) & 0xFF).unwrap();
            let b0 = u8::try_from(raw & 0xFF).unwrap();
            if big_endian {
                vec![b2, b1, b0]
            } else {
                vec![b0, b1, b2]
            }
        }
        4 => {
            let v = u32::try_from(raw & 0xFFFF_FFFF).unwrap();
            if big_endian {
                v.to_be_bytes().to_vec()
            } else {
                v.to_le_bytes().to_vec()
            }
        }
        8 => {
            if big_endian {
                raw.to_be_bytes().to_vec()
            } else {
                raw.to_le_bytes().to_vec()
            }
        }
        _ => return None,
    };

    Some(bytes)
}

#[must_use]
pub fn search_numeric_int(
    data: &[u8],
    value: i64,
    size: usize,
    signed: bool,
    big_endian: bool,
    alignment: usize,
    max_results: usize,
) -> Vec<SearchResult> {
    if size == 0 || size > 8 || data.len() < size {
        return Vec::new();
    }

    let Some(target) = encode_uint_target(value, size, signed, big_endian) else {
        return Vec::new();
    };

    let step = if alignment == 0 { 1 } else { alignment };

    if data.len() > CHUNK_SIZE {
        let num_positions = (data.len() - size) / step + 1;
        let chunk_positions = (CHUNK_SIZE / step).max(1);

        let position_chunks: Vec<(usize, usize)> = {
            let mut chunks = Vec::new();
            let mut pos = 0usize;
            while pos < num_positions {
                let end = (pos + chunk_positions).min(num_positions);
                chunks.push((pos, end));
                pos = end;
            }
            chunks
        };

        let mut all_results: Vec<SearchResult> = position_chunks
            .par_iter()
            .flat_map(|(chunk_start, chunk_end)| {
                let mut local = Vec::new();
                for idx in *chunk_start..*chunk_end {
                    if local.len() >= max_results {
                        break;
                    }
                    let offset = idx * step;
                    if offset + size > data.len() {
                        break;
                    }
                    if &data[offset..offset + size] == target.as_slice() {
                        local.push(SearchResult {
                            offset,
                            length: size,
                            matched_bytes: data[offset..offset + size].to_vec(),
                        });
                    }
                }
                local
            })
            .collect();

        all_results.sort_by_key(|r| r.offset);
        all_results.truncate(max_results);
        return all_results;
    }

    let mut results = Vec::new();
    let mut offset = 0usize;
    while offset + size <= data.len() {
        if results.len() >= max_results {
            break;
        }
        if &data[offset..offset + size] == target.as_slice() {
            results.push(SearchResult {
                offset,
                length: size,
                matched_bytes: data[offset..offset + size].to_vec(),
            });
        }
        offset += step;
    }
    results
}

#[must_use]
pub fn search_numeric_float(
    data: &[u8],
    value: f64,
    size: usize,
    big_endian: bool,
    tolerance: f64,
    alignment: usize,
    max_results: usize,
) -> Vec<SearchResult> {
    if (size != 4 && size != 8) || data.len() < size {
        return Vec::new();
    }

    let step = if alignment == 0 { 1 } else { alignment };

    let matches_value = |bytes: &[u8]| -> bool {
        let decoded: f64 = if size == 4 {
            let arr = [bytes[0], bytes[1], bytes[2], bytes[3]];
            let fv = if big_endian {
                f32::from_be_bytes(arr)
            } else {
                f32::from_le_bytes(arr)
            };
            if !fv.is_finite() {
                return false;
            }
            f64::from(fv)
        } else {
            let arr = [
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ];
            let fv = if big_endian {
                f64::from_be_bytes(arr)
            } else {
                f64::from_le_bytes(arr)
            };
            if !fv.is_finite() {
                return false;
            }
            fv
        };
        (decoded - value).abs() <= tolerance
    };

    if data.len() > CHUNK_SIZE {
        let num_positions = (data.len() - size) / step + 1;
        let chunk_positions = (CHUNK_SIZE / step).max(1);

        let position_chunks: Vec<(usize, usize)> = {
            let mut chunks = Vec::new();
            let mut pos = 0usize;
            while pos < num_positions {
                let end = (pos + chunk_positions).min(num_positions);
                chunks.push((pos, end));
                pos = end;
            }
            chunks
        };

        let mut all_results: Vec<SearchResult> = position_chunks
            .par_iter()
            .flat_map(|(chunk_start, chunk_end)| {
                let mut local = Vec::new();
                for idx in *chunk_start..*chunk_end {
                    if local.len() >= max_results {
                        break;
                    }
                    let offset = idx * step;
                    if offset + size > data.len() {
                        break;
                    }
                    if matches_value(&data[offset..offset + size]) {
                        local.push(SearchResult {
                            offset,
                            length: size,
                            matched_bytes: data[offset..offset + size].to_vec(),
                        });
                    }
                }
                local
            })
            .collect();

        all_results.sort_by_key(|r| r.offset);
        all_results.truncate(max_results);
        return all_results;
    }

    let mut results = Vec::new();
    let mut offset = 0usize;
    while offset + size <= data.len() {
        if results.len() >= max_results {
            break;
        }
        if matches_value(&data[offset..offset + size]) {
            results.push(SearchResult {
                offset,
                length: size,
                matched_bytes: data[offset..offset + size].to_vec(),
            });
        }
        offset += step;
    }
    results
}

#[must_use]
pub fn search_numeric_range(
    data: &[u8],
    min_val: i64,
    max_val: i64,
    size: usize,
    signed: bool,
    big_endian: bool,
    alignment: usize,
    max_results: usize,
) -> Vec<SearchResult> {
    if size == 0 || size > 8 || data.len() < size {
        return Vec::new();
    }

    let step = if alignment == 0 { 1 } else { alignment };

    let in_range = |bytes: &[u8]| -> bool {
        let raw = decode_uint(bytes, size, big_endian);
        let decoded: i64 = if signed {
            sign_extend(raw, size)
        } else {
            i64::try_from(raw).unwrap_or(i64::MAX)
        };
        decoded >= min_val && decoded <= max_val
    };

    if data.len() > CHUNK_SIZE {
        let num_positions = (data.len() - size) / step + 1;
        let chunk_positions = (CHUNK_SIZE / step).max(1);

        let position_chunks: Vec<(usize, usize)> = {
            let mut chunks = Vec::new();
            let mut pos = 0usize;
            while pos < num_positions {
                let end = (pos + chunk_positions).min(num_positions);
                chunks.push((pos, end));
                pos = end;
            }
            chunks
        };

        let mut all_results: Vec<SearchResult> = position_chunks
            .par_iter()
            .flat_map(|(chunk_start, chunk_end)| {
                let mut local = Vec::new();
                for idx in *chunk_start..*chunk_end {
                    if local.len() >= max_results {
                        break;
                    }
                    let offset = idx * step;
                    if offset + size > data.len() {
                        break;
                    }
                    if in_range(&data[offset..offset + size]) {
                        local.push(SearchResult {
                            offset,
                            length: size,
                            matched_bytes: data[offset..offset + size].to_vec(),
                        });
                    }
                }
                local
            })
            .collect();

        all_results.sort_by_key(|r| r.offset);
        all_results.truncate(max_results);
        return all_results;
    }

    let mut results = Vec::new();
    let mut offset = 0usize;
    while offset + size <= data.len() {
        if results.len() >= max_results {
            break;
        }
        if in_range(&data[offset..offset + size]) {
            results.push(SearchResult {
                offset,
                length: size,
                matched_bytes: data[offset..offset + size].to_vec(),
            });
        }
        offset += step;
    }
    results
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
    fn test_search_text_mixed_case_needle() {
        let data = b"say hello world hello";
        let results = search_text(data, "HeLLo", "utf-8", false, 10);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].offset, 4);
        assert_eq!(results[1].offset, 16);
    }

    #[test]
    fn test_search_text_mixed_case_cyrillic_utf16le() {
        let target = "привет";
        let haystack: Vec<u8> = target.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let results = search_text(&haystack, "ПрИвЕт", "utf-16le", false, 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 0);
        assert_eq!(results[0].length, haystack.len());
    }

    #[test]
    fn test_search_text_utf16le() {
        let text = "AB";
        let encoded: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
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

    #[test]
    fn test_search_numeric_int_le() {
        let val: u32 = 0x1234_5678;
        let mut data = vec![0u8; 100];
        data[20..24].copy_from_slice(&val.to_le_bytes());
        data[50..54].copy_from_slice(&val.to_le_bytes());
        let results = search_numeric_int(&data, 0x1234_5678, 4, false, false, 1, 100);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].offset, 20);
        assert_eq!(results[1].offset, 50);
    }

    #[test]
    fn test_search_numeric_int_be() {
        let val: u32 = 0x1234_5678;
        let mut data = vec![0u8; 100];
        data[20..24].copy_from_slice(&val.to_be_bytes());
        let results = search_numeric_int(&data, 0x1234_5678, 4, false, true, 1, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 20);
    }

    #[test]
    fn test_search_numeric_float() {
        let val: f32 = 1.234;
        let mut data = vec![0u8; 100];
        data[40..44].copy_from_slice(&val.to_le_bytes());
        let results = search_numeric_float(&data, 1.234, 4, false, 0.001, 1, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 40);
    }

    #[test]
    fn test_search_numeric_range() {
        let mut data = vec![0u8; 100];
        data[0..4].copy_from_slice(&10u32.to_le_bytes());
        data[4..8].copy_from_slice(&20u32.to_le_bytes());
        data[8..12].copy_from_slice(&30u32.to_le_bytes());
        let results = search_numeric_range(&data, 15, 25, 4, false, false, 4, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 4);
    }

    #[test]
    fn test_search_numeric_alignment() {
        let val: u16 = 0x1234;
        let mut data = vec![0u8; 100];
        data[3..5].copy_from_slice(&val.to_le_bytes());
        data[4..6].copy_from_slice(&val.to_le_bytes());
        let results = search_numeric_int(&data, 0x1234, 2, false, false, 2, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 4);
    }

    #[test]
    fn test_search_numeric_signed() {
        let val: i32 = -1;
        let mut data = vec![0u8; 100];
        data[10..14].copy_from_slice(&val.to_le_bytes());
        let results = search_numeric_int(&data, -1, 4, true, false, 1, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 10);
    }

    #[test]
    fn test_search_bytes_good_suffix() {
        let data = b"AAAABAAAABAAAAAB";
        let results = search_bytes(data, b"AAAAAB", 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 10);

        let data2 = b"ABCABCABCABC";
        let results2 = search_bytes(data2, b"ABCABC", 10);
        assert_eq!(results2.len(), 3);
        assert_eq!(results2[0].offset, 0);
        assert_eq!(results2[1].offset, 3);
        assert_eq!(results2[2].offset, 6);
    }

    fn buf_with(total: usize, fill: u8, pat: &[u8], offsets: &[usize]) -> Vec<u8> {
        let mut d = vec![fill; total];
        for &off in offsets {
            d[off..off + pat.len()].copy_from_slice(pat);
        }
        d
    }

    #[test]
    fn test_search_bytes_parallel_over_chunk_boundary() {
        // >4 MiB forces the rayon chunked path; one match straddles the CHUNK_SIZE seam.
        let pat = [0xDEu8, 0xAD, 0xBE, 0xEF, 0xCA];
        let total = CHUNK_SIZE + 300_000;
        let offsets = [100usize, CHUNK_SIZE - 2, CHUNK_SIZE + 50_000];
        let data = buf_with(total, 0x00, &pat, &offsets);
        let results = search_bytes(&data, &pat, 100);
        let found: Vec<usize> = results.iter().map(|r| r.offset).collect();
        assert_eq!(found, vec![100, CHUNK_SIZE - 2, CHUNK_SIZE + 50_000]);
        // dedup_by_key must collapse any boundary double-report to a single hit.
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_search_hex_wildcards_parallel_over_chunk() {
        // Wildcards keep it on the masked parallel path (not delegated to search_bytes).
        let total = CHUNK_SIZE + 200_000;
        let mut data = vec![0x11u8; total];
        // Matches for "DE AD ?? EF": 0xDE 0xAD <any> 0xEF
        for &off in &[500usize, CHUNK_SIZE + 1000] {
            data[off] = 0xDE;
            data[off + 1] = 0xAD;
            data[off + 2] = 0x77;
            data[off + 3] = 0xEF;
        }
        let results = search_hex_with_wildcards(&data, "DE AD ?? EF", 100);
        let found: Vec<usize> = results.iter().map(|r| r.offset).collect();
        assert_eq!(found, vec![500, CHUNK_SIZE + 1000]);
    }

    #[test]
    fn test_search_numeric_int_parallel_over_chunk() {
        let total = CHUNK_SIZE + 100_000;
        let mut data = vec![0x11u8; total];
        let val: u32 = 0xDEAD_BEEF;
        data[64..68].copy_from_slice(&val.to_le_bytes());
        data[CHUNK_SIZE + 40..CHUNK_SIZE + 44].copy_from_slice(&val.to_le_bytes());
        let results = search_numeric_int(&data, 0xDEAD_BEEF, 4, false, false, 1, 100);
        let found: Vec<usize> = results.iter().map(|r| r.offset).collect();
        assert_eq!(found, vec![64, CHUNK_SIZE + 40]);
    }

    #[test]
    fn test_search_numeric_float_parallel_over_chunk_f64_be() {
        let total = CHUNK_SIZE + 80_000;
        let mut data = vec![0x11u8; total];
        let val: f64 = 12_345.678_9;
        data[32..40].copy_from_slice(&val.to_be_bytes());
        data[CHUNK_SIZE + 8..CHUNK_SIZE + 16].copy_from_slice(&val.to_be_bytes());
        let results = search_numeric_float(&data, 12_345.678_9, 8, true, 1e-9, 8, 100);
        let found: Vec<usize> = results.iter().map(|r| r.offset).collect();
        assert_eq!(found, vec![32, CHUNK_SIZE + 8]);
    }

    #[test]
    fn test_search_numeric_range_parallel_over_chunk() {
        let total = CHUNK_SIZE + 60_000;
        let mut data = vec![0x00u8; total];
        // value 500 (LE) is inside [100, 1000]; place at two positions.
        data[16..20].copy_from_slice(&500u32.to_le_bytes());
        data[CHUNK_SIZE + 4..CHUNK_SIZE + 8].copy_from_slice(&500u32.to_le_bytes());
        // A zero window (fill) decodes to 0, outside [100,1000]; must not match.
        let results = search_numeric_range(&data, 100, 1000, 4, false, false, 4, 100);
        let found: Vec<usize> = results.iter().map(|r| r.offset).collect();
        assert_eq!(found, vec![16, CHUNK_SIZE + 4]);
    }

    #[test]
    fn test_parse_hex_pattern_odd_nibble_count_returns_none() {
        assert!(parse_hex_pattern("4D 5").is_none());
    }

    #[test]
    fn test_parse_hex_pattern_high_nibble_wildcard() {
        // "?A" -> low nibble 0xA known, high nibble wildcard -> (value 0x0A, mask 0x0F)
        let result = parse_hex_pattern("?A").unwrap();
        assert_eq!(result, vec![(0x0A, 0x0F)]);
    }

    #[test]
    fn test_parse_hex_pattern_empty_returns_empty_vec() {
        // Empty (and all-non-hex) input yields zero nibbles: 0 is even -> Some(empty).
        assert_eq!(parse_hex_pattern("").unwrap(), Vec::<(u8, u8)>::new());
        assert_eq!(parse_hex_pattern("GG!!").unwrap(), Vec::<(u8, u8)>::new());
    }

    #[test]
    fn test_search_hex_empty_pattern_returns_empty() {
        // parse succeeds with an empty pattern -> guard returns no results.
        let results = search_hex_with_wildcards(b"anything", "", 10);
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_text_empty_text_returns_empty() {
        assert!(search_text(b"data", "", "utf-8", true, 10).is_empty());
    }

    #[test]
    fn test_search_text_utf16be_case_sensitive() {
        let encoded: Vec<u8> = "OK".encode_utf16().flat_map(u16::to_be_bytes).collect();
        let mut data = vec![0x00u8; 6];
        data.extend_from_slice(&encoded);
        let results = search_text(&data, "OK", "utf-16be", true, 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 6);
    }

    #[test]
    fn test_search_text_ci_data_shorter_than_needle_returns_empty() {
        // Case-insensitive branch: data.len() < encoded.len() -> early empty.
        let results = search_text(b"ab", "abcdef", "utf-8", false, 10);
        assert!(results.is_empty());
    }

    #[test]
    fn test_window_matches_ci_utf16be() {
        let window: Vec<u8> = "AB".encode_utf16().flat_map(u16::to_be_bytes).collect();
        assert!(window_matches_ci(&window, "ab", "utf-16be"));
    }

    #[test]
    fn test_window_matches_ci_odd_length_utf16_rejected() {
        assert!(!window_matches_ci(&[0x41], "a", "utf-16le"));
        assert!(!window_matches_ci(&[0x41], "a", "utf-16be"));
    }

    #[test]
    fn test_window_matches_ci_invalid_utf16_rejected() {
        // Lone high surrogate D800 (LE bytes 0x00,0xD8) is invalid UTF-16.
        assert!(!window_matches_ci(&[0x00, 0xD8], "x", "utf-16le"));
        assert!(!window_matches_ci(&[0xD8, 0x00], "x", "utf-16be"));
    }

    #[test]
    fn test_window_matches_ci_invalid_utf8_rejected() {
        assert!(!window_matches_ci(&[0xFF, 0xFE], "x", "utf-8"));
    }

    #[test]
    fn test_window_matches_ci_ascii_high_bit_rejected_and_valid_accepted() {
        assert!(!window_matches_ci(&[0x80], "x", "ascii"));
        assert!(window_matches_ci(b"AB", "ab", "ascii"));
    }

    #[test]
    fn test_window_matches_ci_encoding_rs_fallback_windows1252_and_latin1() {
        // 0xC9 is 'É' in windows-1252/latin1; lowercased 'é'.
        assert!(window_matches_ci(&[0xC9], "é", "windows-1252"));
        assert!(window_matches_ci(&[0xC9], "é", "latin1"));
    }

    #[test]
    fn test_window_matches_ci_encoding_rs_had_errors_rejected() {
        // Lone Shift_JIS lead byte 0x81 cannot decode -> had_errors -> reject.
        assert!(!window_matches_ci(&[0x81], "x", "shift_jis"));
    }

    #[test]
    fn test_window_matches_ci_unknown_label_rejected() {
        assert!(!window_matches_ci(b"AB", "ab", "no-such-encoding-xyz"));
    }

    #[test]
    fn test_search_regex_invalid_pattern_returns_empty() {
        assert!(search_regex(b"data", "[unclosed", 10).is_empty());
    }

    #[test]
    fn test_search_regex_max_results_break() {
        let data = b"a a a a a";
        let results = search_regex(data, "a", 2);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_replace_all_empty_pattern_returns_copy_and_zero() {
        let (out, count) = replace_all(b"abc", b"", b"z");
        assert_eq!(out, b"abc".to_vec());
        assert_eq!(count, 0);
    }

    #[test]
    fn test_decode_uint_all_sizes_and_endianness() {
        assert_eq!(decode_uint(&[0xAB], 1, false), 0xAB);
        assert_eq!(decode_uint(&[0x12, 0x34], 2, false), 0x3412);
        assert_eq!(decode_uint(&[0x12, 0x34], 2, true), 0x1234);
        assert_eq!(decode_uint(&[0x12, 0x34, 0x56], 3, false), 0x0056_3412);
        assert_eq!(decode_uint(&[0x12, 0x34, 0x56], 3, true), 0x0012_3456);
        assert_eq!(decode_uint(&[1, 2, 3, 4], 4, false), 0x0403_0201);
        assert_eq!(decode_uint(&[1, 2, 3, 4], 4, true), 0x0102_0304);
        let eight = [1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(decode_uint(&eight, 8, true), 0x0102_0304_0506_0708);
        assert_eq!(decode_uint(&eight, 8, false), 0x0807_0605_0403_0201);
        // Unsupported width (5/6/7) falls through to 0.
        assert_eq!(decode_uint(&[1, 2, 3, 4, 5], 5, false), 0);
    }

    #[test]
    fn test_sign_extend_all_sizes() {
        assert_eq!(sign_extend(0xFF, 1), -1);
        assert_eq!(sign_extend(0x7F, 1), 127);
        assert_eq!(sign_extend(0xFFFF, 2), -1);
        assert_eq!(sign_extend(0xFF_FFFF, 3), -1);
        assert_eq!(sign_extend(0x80_0000, 3), -8_388_608);
        assert_eq!(sign_extend(0xFFFF_FFFF, 4), -1);
        // Width 8 (and unsupported widths) just reinterpret the bits.
        assert_eq!(sign_extend(u64::MAX, 8), -1);
    }

    #[test]
    fn test_encode_uint_target_unsigned_widths_and_overflow() {
        assert_eq!(encode_uint_target(200, 1, false, false), Some(vec![200]));
        assert_eq!(encode_uint_target(256, 1, false, false), None);
        assert_eq!(encode_uint_target(-1, 1, false, false), None);
        assert_eq!(encode_uint_target(0x1234, 2, false, true), Some(vec![0x12, 0x34]));
        assert_eq!(encode_uint_target(0x1234, 2, false, false), Some(vec![0x34, 0x12]));
        assert_eq!(encode_uint_target(0x1_0000, 2, false, false), None);
        assert_eq!(
            encode_uint_target(0x0012_3456, 3, false, true),
            Some(vec![0x12, 0x34, 0x56])
        );
        assert_eq!(
            encode_uint_target(0x0012_3456, 3, false, false),
            Some(vec![0x56, 0x34, 0x12])
        );
        assert_eq!(encode_uint_target(0x0100_0000, 3, false, false), None);
        assert_eq!(encode_uint_target(0x1_0000_0000, 4, false, false), None);
        assert_eq!(
            encode_uint_target(0xABCD, 4, false, true),
            Some(vec![0x00, 0x00, 0xAB, 0xCD])
        );
        assert_eq!(
            encode_uint_target(1, 8, false, true),
            Some(vec![0, 0, 0, 0, 0, 0, 0, 1])
        );
        // Unsupported width -> None.
        assert_eq!(encode_uint_target(1, 5, false, false), None);
    }

    #[test]
    fn test_encode_uint_target_signed_widths_and_overflow() {
        assert_eq!(encode_uint_target(-1, 1, true, false), Some(vec![0xFF]));
        assert_eq!(encode_uint_target(200, 1, true, false), None);
        assert_eq!(encode_uint_target(-1, 2, true, true), Some(vec![0xFF, 0xFF]));
        assert_eq!(encode_uint_target(8_388_607, 3, true, false).unwrap().len(), 3);
        assert_eq!(encode_uint_target(8_388_608, 3, true, false), None);
        assert_eq!(encode_uint_target(-8_388_608, 3, true, false).unwrap().len(), 3);
        assert_eq!(encode_uint_target(-8_388_609, 3, true, false), None);
        assert_eq!(
            encode_uint_target(-1, 4, true, false),
            Some(vec![0xFF, 0xFF, 0xFF, 0xFF])
        );
        assert_eq!(
            encode_uint_target(-1, 8, true, true),
            Some(vec![0xFF; 8])
        );
        assert_eq!(encode_uint_target(1, 7, true, false), None);
    }

    #[test]
    fn test_search_numeric_int_size_guards_and_encode_none() {
        assert!(search_numeric_int(b"abcd", 1, 0, false, false, 1, 10).is_empty());
        assert!(search_numeric_int(b"abcd", 1, 9, false, false, 1, 10).is_empty());
        assert!(search_numeric_int(b"a", 1, 4, false, false, 1, 10).is_empty());
        // value 256 does not fit in 1 unsigned byte -> encode returns None -> empty.
        assert!(search_numeric_int(b"abcd", 256, 1, false, false, 1, 10).is_empty());
    }

    #[test]
    fn test_search_numeric_int_size3_and_size8_small_path() {
        let mut data = vec![0x00u8; 32];
        // 24-bit value 0x0056_3412 little-endian == bytes 12 34 56
        data[4..7].copy_from_slice(&[0x12, 0x34, 0x56]);
        let r3 = search_numeric_int(&data, 0x0056_3412, 3, false, false, 1, 10);
        assert_eq!(r3.iter().map(|r| r.offset).collect::<Vec<_>>(), vec![4]);
        let v: u64 = 0x0102_0304_0506_0708;
        data[8..16].copy_from_slice(&v.to_le_bytes());
        let r8 = search_numeric_int(&data, v.cast_signed(), 8, false, false, 1, 10);
        assert_eq!(r8.iter().map(|r| r.offset).collect::<Vec<_>>(), vec![8]);
    }

    #[test]
    fn test_search_numeric_float_size_guard_and_non_finite_skip() {
        // size 2 is invalid for float search.
        assert!(search_numeric_float(b"abcdef", 1.0, 2, false, 0.0, 1, 10).is_empty());
        // An f32 +inf window must be skipped (non-finite guard); a real 5.0 must match.
        let mut data = vec![0x11u8; 64];
        data[8..12].copy_from_slice(&[0x00, 0x00, 0x80, 0x7F]); // f32 +inf LE
        data[20..24].copy_from_slice(&5.0f32.to_le_bytes());
        let results = search_numeric_float(&data, 5.0, 4, false, 0.001, 1, 10);
        let found: Vec<usize> = results.iter().map(|r| r.offset).collect();
        assert_eq!(found, vec![20]);
    }

    #[test]
    fn test_search_numeric_range_signed_negative_small_path() {
        let mut data = vec![0x00u8; 32];
        data[4..8].copy_from_slice(&(-50i32).to_le_bytes());
        data[8..12].copy_from_slice(&25i32.to_le_bytes());
        // range [-100, -1] signed matches only the -50 window (zero-fill windows decode to 0).
        let results = search_numeric_range(&data, -100, -1, 4, true, false, 4, 10);
        let found: Vec<usize> = results.iter().map(|r| r.offset).collect();
        assert_eq!(found, vec![4]);
    }
}
