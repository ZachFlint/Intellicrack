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
        assert!(results.iter().any(|r| r.offset == 10));
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
}
