use thiserror::Error;

#[derive(Error, Debug)]
pub enum EncodingError {
    #[error("unsupported encoding: {0}")]
    UnsupportedEncoding(String),
    #[error("encode failed: {0}")]
    EncodeFailed(String),
}

static EBCDIC_TO_UNICODE: [char; 256] = [
    // 0x00-0x0F
    '\0', '\x01', '\x02', '\x03', '\u{009C}', '\x09', '\u{0086}', '\x7F', '\u{0097}', '\u{008D}',
    '\u{008E}', '\x0B', '\x0C', '\r', '\x0E', '\x0F', // 0x10-0x1F
    '\x10', '\x11', '\x12', '\x13', '\u{009D}', '\u{0085}', '\x08', '\u{0087}', '\x18', '\x19',
    '\u{0092}', '\u{008F}', '\x1C', '\x1D', '\x1E', '\x1F', // 0x20-0x2F
    '\u{0080}', '\u{0081}', '\u{0082}', '\u{0083}', '\u{0084}', '\n', '\x17', '\x1B', '\u{0088}',
    '\u{0089}', '\u{008A}', '\u{008B}', '\u{008C}', '\x05', '\x06', '\x07',
    // 0x30-0x3F
    '\u{0090}', '\u{0091}', '\x16', '\u{0093}', '\u{0094}', '\u{0095}', '\u{0096}', '\x04',
    '\u{0098}', '\u{0099}', '\u{009A}', '\u{009B}', '\x14', '\x15', '\u{009E}', '\x1A',
    // 0x40-0x4F
    ' ', '\u{00A0}', '\u{00E2}', '\u{00E4}', '\u{00E0}', '\u{00E1}', '\u{00E3}', '\u{00E5}',
    '\u{00E7}', '\u{00F1}', '\u{00A2}', '.', '<', '(', '+', '|', // 0x50-0x5F
    '&', '\u{00E9}', '\u{00EA}', '\u{00EB}', '\u{00E8}', '\u{00ED}', '\u{00EE}', '\u{00EF}',
    '\u{00EC}', '\u{00DF}', '!', '$', '*', ')', ';', '\u{00AC}', // 0x60-0x6F
    '-', '/', '\u{00C2}', '\u{00C4}', '\u{00C0}', '\u{00C1}', '\u{00C3}', '\u{00C5}', '\u{00C7}',
    '\u{00D1}', '\u{00A6}', ',', '%', '_', '>', '?', // 0x70-0x7F
    '\u{00F8}', '\u{00C9}', '\u{00CA}', '\u{00CB}', '\u{00C8}', '\u{00CD}', '\u{00CE}', '\u{00CF}',
    '\u{00CC}', '`', ':', '#', '@', '\'', '=', '"', // 0x80-0x8F
    '\u{00D8}', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', '\u{00AB}', '\u{00BB}', '\u{00F0}',
    '\u{00FD}', '\u{00FE}', '\u{00B1}', // 0x90-0x9F
    '\u{00B0}', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', '\u{00AA}', '\u{00BA}', '\u{00E6}',
    '\u{00B8}', '\u{00C6}', '\u{00A4}', // 0xA0-0xAF
    '\u{00B5}', '~', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '\u{00A1}', '\u{00BF}', '\u{00D0}',
    '\u{00DD}', '\u{00DE}', '\u{00AE}', // 0xB0-0xBF
    '^', '\u{00A3}', '\u{00A5}', '\u{00B7}', '\u{00A9}', '\u{00A7}', '\u{00B6}', '\u{00BC}',
    '\u{00BD}', '\u{00BE}', '[', ']', '\u{00AF}', '\u{00A8}', '\u{00B4}', '\u{00D7}',
    // 0xC0-0xCF
    '{', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', '\u{00AD}', '\u{00F4}', '\u{00F6}',
    '\u{00F2}', '\u{00F3}', '\u{00F5}', // 0xD0-0xDF
    '}', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', '\u{00B9}', '\u{00FB}', '\u{00FC}',
    '\u{00F9}', '\u{00FA}', '\u{00FF}', // 0xE0-0xEF
    '\\', '\u{00F7}', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '\u{00B2}', '\u{00D4}', '\u{00D6}',
    '\u{00D2}', '\u{00D3}', '\u{00D5}', // 0xF0-0xFF
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '\u{00B3}', '\u{00DB}', '\u{00DC}',
    '\u{00D9}', '\u{00DA}', '\u{009F}',
];

fn resolve_encoding(name: &str) -> Result<&'static encoding_rs::Encoding, EncodingError> {
    let lower = name.to_lowercase();
    let enc = match lower.as_str() {
        "utf-8" | "utf8" => encoding_rs::UTF_8,
        "utf-16le" | "utf16le" => encoding_rs::UTF_16LE,
        "utf-16be" | "utf16be" => encoding_rs::UTF_16BE,
        "iso-8859-1" | "iso8859-1" | "iso_8859-1" | "latin1" | "latin-1" | "windows-1252"
        | "cp1252" => encoding_rs::WINDOWS_1252,
        "iso-8859-2" | "iso8859-2" => encoding_rs::ISO_8859_2,
        "iso-8859-3" | "iso8859-3" => encoding_rs::ISO_8859_3,
        "iso-8859-4" | "iso8859-4" => encoding_rs::ISO_8859_4,
        "iso-8859-5" | "iso8859-5" => encoding_rs::ISO_8859_5,
        "iso-8859-6" | "iso8859-6" => encoding_rs::ISO_8859_6,
        "iso-8859-7" | "iso8859-7" => encoding_rs::ISO_8859_7,
        "iso-8859-8" | "iso8859-8" => encoding_rs::ISO_8859_8,
        "iso-8859-10" | "iso8859-10" => encoding_rs::ISO_8859_10,
        "iso-8859-13" | "iso8859-13" => encoding_rs::ISO_8859_13,
        "iso-8859-14" | "iso8859-14" => encoding_rs::ISO_8859_14,
        "iso-8859-15" | "iso8859-15" => encoding_rs::ISO_8859_15,
        "iso-8859-16" | "iso8859-16" => encoding_rs::ISO_8859_16,
        "windows-1250" | "cp1250" => encoding_rs::WINDOWS_1250,
        "windows-1251" | "cp1251" => encoding_rs::WINDOWS_1251,
        "windows-1253" | "cp1253" => encoding_rs::WINDOWS_1253,
        "windows-1254" | "cp1254" => encoding_rs::WINDOWS_1254,
        "windows-1255" | "cp1255" => encoding_rs::WINDOWS_1255,
        "windows-1256" | "cp1256" => encoding_rs::WINDOWS_1256,
        "windows-1257" | "cp1257" => encoding_rs::WINDOWS_1257,
        "windows-1258" | "cp1258" => encoding_rs::WINDOWS_1258,
        "shift_jis" | "shift-jis" | "sjis" | "shiftjis" => encoding_rs::SHIFT_JIS,
        "euc-jp" | "eucjp" => encoding_rs::EUC_JP,
        "iso-2022-jp" | "iso2022jp" => encoding_rs::ISO_2022_JP,
        "euc-kr" | "euckr" => encoding_rs::EUC_KR,
        "gb2312" | "gbk" | "gb_2312" | "gb-2312" => encoding_rs::GBK,
        "gb18030" => encoding_rs::GB18030,
        "big5" | "big-5" => encoding_rs::BIG5,
        "koi8-r" | "koi8r" => encoding_rs::KOI8_R,
        "koi8-u" | "koi8u" => encoding_rs::KOI8_U,
        _ => {
            return Err(EncodingError::UnsupportedEncoding(name.to_string()));
        }
    };
    Ok(enc)
}

fn decode_ebcdic(data: &[u8]) -> (String, bool) {
    let mut result = String::with_capacity(data.len());
    let mut had_replacement = false;
    for &byte in data {
        let ch = EBCDIC_TO_UNICODE[byte as usize];
        if ch == '\u{FFFD}' {
            had_replacement = true;
        }
        result.push(ch);
    }
    (result, had_replacement)
}

fn build_ebcdic_reverse_table() -> std::collections::HashMap<char, u8> {
    let mut map = std::collections::HashMap::with_capacity(256);
    for (byte_val, &ch) in EBCDIC_TO_UNICODE.iter().enumerate() {
        if let Ok(b) = u8::try_from(byte_val) {
            map.entry(ch).or_insert(b);
        }
    }
    map
}

fn encode_ebcdic(text: &str) -> Result<Vec<u8>, EncodingError> {
    let reverse = build_ebcdic_reverse_table();
    let mut result = Vec::with_capacity(text.len());
    for ch in text.chars() {
        match reverse.get(&ch) {
            Some(&b) => result.push(b),
            None => {
                return Err(EncodingError::EncodeFailed(format!(
                    "character '{}' (U+{:04X}) cannot be encoded in EBCDIC CP037",
                    ch, ch as u32
                )));
            }
        }
    }
    Ok(result)
}

/// Decodes raw bytes into a string using the specified encoding.
///
/// # Errors
///
/// Returns `EncodingError::UnsupportedEncoding` if the encoding name is not recognized.
pub fn decode_text(data: &[u8], encoding_name: &str) -> Result<(String, bool), EncodingError> {
    let lower = encoding_name.to_lowercase();
    match lower.as_str() {
        "ascii" => {
            let s: String = data.iter().map(|&b| (b & 0x7F) as char).collect();
            let had_replacement = data.iter().any(|&b| b & 0x80 != 0);
            Ok((s, had_replacement))
        }
        "ebcdic" | "ebcdic-cp037" | "cp037" => Ok(decode_ebcdic(data)),
        _ => {
            let enc = resolve_encoding(encoding_name)?;
            let (cow, _enc_used, had_errors) = enc.decode(data);
            Ok((cow.into_owned(), had_errors))
        }
    }
}

/// Encodes a string into raw bytes using the specified encoding.
///
/// # Errors
///
/// Returns `EncodingError::UnsupportedEncoding` if the encoding name is not recognized,
/// or `EncodingError::EncodeFailed` if the text contains unmappable characters.
pub fn encode_text(text: &str, encoding_name: &str) -> Result<Vec<u8>, EncodingError> {
    let lower = encoding_name.to_lowercase();
    match lower.as_str() {
        "ascii" => {
            let mut bytes = Vec::with_capacity(text.len());
            for ch in text.chars() {
                let cp = ch as u32;
                if cp > 0x7F {
                    return Err(EncodingError::EncodeFailed(format!(
                        "U+{cp:04X} cannot be encoded in ASCII"
                    )));
                }
                bytes.push(ch as u8);
            }
            Ok(bytes)
        }
        "utf-8" | "utf8" => Ok(text.as_bytes().to_vec()),
        "utf-16le" | "utf16le" => {
            let encoded: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
            Ok(encoded)
        }
        "utf-16be" | "utf16be" => {
            let encoded: Vec<u8> = text.encode_utf16().flat_map(u16::to_be_bytes).collect();
            Ok(encoded)
        }
        "ebcdic" | "ebcdic-cp037" | "cp037" => encode_ebcdic(text),
        _ => {
            let enc = resolve_encoding(encoding_name)?;
            let (cow, _enc_used, had_unmappable) = enc.encode(text);
            if had_unmappable {
                return Err(EncodingError::EncodeFailed(format!(
                    "text contains characters that cannot be encoded in '{encoding_name}'"
                )));
            }
            Ok(cow.into_owned())
        }
    }
}

#[must_use]
pub fn search_text_encoded(
    data: &[u8],
    text: &str,
    encoding_name: &str,
    case_sensitive: bool,
    max_results: usize,
) -> Vec<(usize, usize)> {
    if text.is_empty() || max_results == 0 {
        return Vec::new();
    }

    let Ok(search_bytes) = encode_text(text, encoding_name) else {
        return Vec::new();
    };

    if search_bytes.is_empty() {
        return Vec::new();
    }

    if case_sensitive {
        let mut results: Vec<(usize, usize)> = Vec::new();
        find_pattern(data, &search_bytes, max_results, &mut results);
        return results;
    }

    search_text_case_insensitive(data, text, encoding_name, search_bytes.len(), max_results)
}

fn unit_width(encoding_name: &str) -> usize {
    match encoding_name.to_lowercase().as_str() {
        "utf-16le" | "utf16le" | "utf-16be" | "utf16be" => 2,
        _ => 1,
    }
}

fn search_text_case_insensitive(
    data: &[u8],
    needle: &str,
    encoding_name: &str,
    window_len: usize,
    max_results: usize,
) -> Vec<(usize, usize)> {
    if window_len == 0 || data.len() < window_len {
        return Vec::new();
    }

    let needle_lower = needle.to_lowercase();
    let step = unit_width(encoding_name);
    let mut results: Vec<(usize, usize)> = Vec::new();
    let last_start = data.len() - window_len;
    let mut offset: usize = 0;

    while offset <= last_start && results.len() < max_results {
        let window = &data[offset..offset + window_len];
        if window_matches_case_insensitive(window, &needle_lower, encoding_name) {
            results.push((offset, window_len));
            offset += window_len.max(step);
        } else {
            offset += step;
        }
    }

    results
}

fn window_matches_case_insensitive(window: &[u8], needle_lower: &str, encoding_name: &str) -> bool {
    let lower = encoding_name.to_lowercase();
    let decoded: String = match lower.as_str() {
        "ascii" => {
            if window.iter().any(|&b| b & 0x80 != 0) {
                return false;
            }
            window.iter().map(|&b| b as char).collect()
        }
        "ebcdic" | "ebcdic-cp037" | "cp037" => {
            let (s, had_replacement) = decode_ebcdic(window);
            if had_replacement {
                return false;
            }
            s
        }
        _ => {
            let Ok(enc) = resolve_encoding(encoding_name) else {
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

fn find_pattern(
    data: &[u8],
    pattern: &[u8],
    max_results: usize,
    results: &mut Vec<(usize, usize)>,
) {
    if pattern.is_empty() || results.len() >= max_results {
        return;
    }
    let pat_len = pattern.len();
    let data_len = data.len();
    if pat_len > data_len {
        return;
    }
    let mut pos = 0;
    while pos <= data_len - pat_len && results.len() < max_results {
        if data[pos..pos + pat_len] == *pattern {
            results.push((pos, pat_len));
            pos += pat_len;
        } else {
            pos += 1;
        }
    }
}

const ENCODING_LIST: &[(&str, &str)] = &[
    ("utf-8", "UTF-8"),
    ("utf-16le", "UTF-16 Little Endian"),
    ("utf-16be", "UTF-16 Big Endian"),
    ("ascii", "ASCII (7-bit)"),
    ("ebcdic", "EBCDIC Code Page 037"),
    ("iso-8859-1", "ISO-8859-1 (Latin-1)"),
    ("iso-8859-2", "ISO-8859-2 (Latin-2, Central European)"),
    ("iso-8859-3", "ISO-8859-3 (Latin-3, South European)"),
    ("iso-8859-4", "ISO-8859-4 (Latin-4, North European)"),
    ("iso-8859-5", "ISO-8859-5 (Latin/Cyrillic)"),
    ("iso-8859-6", "ISO-8859-6 (Latin/Arabic)"),
    ("iso-8859-7", "ISO-8859-7 (Latin/Greek)"),
    ("iso-8859-8", "ISO-8859-8 (Latin/Hebrew)"),
    ("iso-8859-10", "ISO-8859-10 (Latin-6, Nordic)"),
    ("iso-8859-13", "ISO-8859-13 (Latin-7, Baltic Rim)"),
    ("iso-8859-14", "ISO-8859-14 (Latin-8, Celtic)"),
    ("iso-8859-15", "ISO-8859-15 (Latin-9)"),
    (
        "iso-8859-16",
        "ISO-8859-16 (Latin-10, South-Eastern European)",
    ),
    ("windows-1250", "Windows-1250 (Central European)"),
    ("windows-1251", "Windows-1251 (Cyrillic)"),
    ("windows-1252", "Windows-1252 (Western European)"),
    ("windows-1253", "Windows-1253 (Greek)"),
    ("windows-1254", "Windows-1254 (Turkish)"),
    ("windows-1255", "Windows-1255 (Hebrew)"),
    ("windows-1256", "Windows-1256 (Arabic)"),
    ("windows-1257", "Windows-1257 (Baltic)"),
    ("windows-1258", "Windows-1258 (Vietnamese)"),
    ("shift_jis", "Shift_JIS (Japanese)"),
    ("euc-jp", "EUC-JP (Japanese)"),
    ("iso-2022-jp", "ISO-2022-JP (Japanese)"),
    ("euc-kr", "EUC-KR (Korean)"),
    ("gb2312", "GB2312/GBK (Chinese Simplified)"),
    ("gb18030", "GB18030 (Chinese National Standard)"),
    ("big5", "Big5 (Chinese Traditional)"),
    ("koi8-r", "KOI8-R (Russian)"),
    ("koi8-u", "KOI8-U (Ukrainian)"),
];

#[must_use]
pub fn list_encodings() -> Vec<(String, String)> {
    ENCODING_LIST
        .iter()
        .map(|&(name, desc)| (name.to_string(), desc.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_utf8() {
        let data = "Hello, world!".as_bytes();
        let (text, had_replacement) = decode_text(data, "utf-8").unwrap();
        assert_eq!(text, "Hello, world!");
        assert!(!had_replacement);
    }

    #[test]
    fn test_decode_utf8_unicode() {
        let data = "こんにちは".as_bytes();
        let (text, had_replacement) = decode_text(data, "utf-8").unwrap();
        assert_eq!(text, "こんにちは");
        assert!(!had_replacement);
    }

    #[test]
    fn test_decode_utf16le() {
        let data: Vec<u8> = "Hello".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let (text, had_replacement) = decode_text(&data, "utf-16le").unwrap();
        assert_eq!(text, "Hello");
        assert!(!had_replacement);
    }

    #[test]
    fn test_decode_utf16le_unicode() {
        let original = "日本語";
        let data: Vec<u8> = original.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let (text, had_replacement) = decode_text(&data, "utf-16le").unwrap();
        assert_eq!(text, original);
        assert!(!had_replacement);
    }

    #[test]
    fn test_decode_shift_jis() {
        let enc = encoding_rs::SHIFT_JIS;
        let (encoded, _, _) = enc.encode("テスト");
        let (text, had_replacement) = decode_text(&encoded, "shift_jis").unwrap();
        assert_eq!(text, "テスト");
        assert!(!had_replacement);
    }

    #[test]
    fn test_decode_windows_1252() {
        let data: Vec<u8> = vec![0xE9, 0xE0, 0xFC];
        let (text, had_replacement) = decode_text(&data, "windows-1252").unwrap();
        assert_eq!(text, "\u{00E9}\u{00E0}\u{00FC}");
        assert!(!had_replacement);
    }

    #[test]
    fn test_decode_ascii() {
        let data = b"Hello";
        let (text, had_replacement) = decode_text(data, "ascii").unwrap();
        assert_eq!(text, "Hello");
        assert!(!had_replacement);
    }

    #[test]
    fn test_decode_ascii_strips_high_bit() {
        let data: Vec<u8> = vec![0xC8, 0xE5, 0xEC, 0xEC, 0xEF];
        let (text, had_replacement) = decode_text(&data, "ascii").unwrap();
        assert_eq!(text, "Hello");
        assert!(had_replacement);
    }

    #[test]
    fn test_encode_utf8_roundtrip() {
        let original = "Hello, world! こんにちは";
        let encoded = encode_text(original, "utf-8").unwrap();
        let (decoded, had_replacement) = decode_text(&encoded, "utf-8").unwrap();
        assert_eq!(decoded, original);
        assert!(!had_replacement);
    }

    #[test]
    fn test_encode_ascii() {
        let encoded = encode_text("Hi", "ascii").unwrap();
        assert_eq!(encoded, b"Hi");
    }

    #[test]
    fn test_encode_windows_1252_roundtrip() {
        let original = "café";
        let encoded = encode_text(original, "windows-1252").unwrap();
        let (decoded, _) = decode_text(&encoded, "windows-1252").unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_ebcdic_decode_known_bytes() {
        let data: Vec<u8> = vec![0xC1, 0xC2, 0xC3];
        let (text, had_replacement) = decode_text(&data, "ebcdic").unwrap();
        assert_eq!(text, "ABC");
        assert!(!had_replacement);
    }

    #[test]
    fn test_ebcdic_decode_digits() {
        let data: Vec<u8> = vec![0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9];
        let (text, _) = decode_text(&data, "ebcdic").unwrap();
        assert_eq!(text, "0123456789");
    }

    #[test]
    fn test_ebcdic_decode_space() {
        let data: Vec<u8> = vec![0x40];
        let (text, _) = decode_text(&data, "ebcdic").unwrap();
        assert_eq!(text, " ");
    }

    #[test]
    fn test_ebcdic_decode_lowercase() {
        let data: Vec<u8> = vec![0x81, 0x82, 0x83];
        let (text, _) = decode_text(&data, "ebcdic").unwrap();
        assert_eq!(text, "abc");
    }

    #[test]
    fn test_ebcdic_roundtrip() {
        let original = "Hello World 0123";
        let encoded = encode_text(original, "ebcdic").unwrap();
        let (decoded, _) = decode_text(&encoded, "ebcdic").unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_ebcdic_alias_cp037() {
        let data: Vec<u8> = vec![0xC8, 0x85, 0x93, 0x93, 0x96];
        let (text, _) = decode_text(&data, "cp037").unwrap();
        assert_eq!(text, "Hello");
    }

    #[test]
    fn test_list_encodings_count() {
        let encodings = list_encodings();
        assert!(encodings.len() > 30);
    }

    #[test]
    fn test_list_encodings_has_required() {
        let encodings = list_encodings();
        let names: Vec<&str> = encodings.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"utf-8"));
        assert!(names.contains(&"utf-16le"));
        assert!(names.contains(&"utf-16be"));
        assert!(names.contains(&"ascii"));
        assert!(names.contains(&"ebcdic"));
        assert!(names.contains(&"shift_jis"));
        assert!(names.contains(&"euc-jp"));
        assert!(names.contains(&"gb18030"));
        assert!(names.contains(&"koi8-r"));
        assert!(names.contains(&"koi8-u"));
    }

    #[test]
    fn test_search_text_utf8() {
        let data = b"Hello, world! Hello again!";
        let results = search_text_encoded(data, "Hello", "utf-8", true, 10);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], (0, 5));
        assert_eq!(results[1], (14, 5));
    }

    #[test]
    fn test_search_text_utf8_not_found() {
        let data = b"Hello, world!";
        let results = search_text_encoded(data, "xyz", "utf-8", true, 10);
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_text_utf16le() {
        let haystack_str = "Hello World Hello";
        let haystack: Vec<u8> = haystack_str
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let results = search_text_encoded(&haystack, "Hello", "utf-16le", true, 10);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_search_text_max_results() {
        let data = b"aaa aaa aaa aaa aaa";
        let results = search_text_encoded(data, "aaa", "utf-8", true, 2);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_search_text_case_insensitive() {
        let data = b"Hello hello HELLO";
        let results = search_text_encoded(data, "hello", "utf-8", false, 10);
        assert!(results.len() >= 2);
    }

    #[test]
    fn test_search_text_mixed_case_ascii() {
        let data = b"say hello to the world";
        let results = search_text_encoded(data, "HeLLo", "utf-8", false, 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], (4, 5));
    }

    #[test]
    fn test_search_text_mixed_case_matches_upper() {
        let data = b"the WORLD is here";
        let results = search_text_encoded(data, "WoRlD", "utf-8", false, 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], (4, 5));
    }

    #[test]
    fn test_search_text_mixed_case_cyrillic_utf16le() {
        let target = "привет";
        let haystack: Vec<u8> = target.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let results = search_text_encoded(&haystack, "ПрИвЕт", "utf-16le", false, 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 0);
        assert_eq!(results[0].1, haystack.len());
    }

    #[test]
    fn test_encode_ascii_rejects_non_ascii() {
        let result = encode_text("café", "ascii");
        assert!(result.is_err());
        if let Err(EncodingError::EncodeFailed(msg)) = result {
            assert!(msg.contains("U+00E9"));
        } else {
            panic!("expected EncodeFailed");
        }
    }

    #[test]
    fn test_unsupported_encoding() {
        let result = decode_text(b"test", "unknown-encoding-xyz");
        assert!(result.is_err());
        if let Err(EncodingError::UnsupportedEncoding(name)) = result {
            assert_eq!(name, "unknown-encoding-xyz");
        }
    }

    #[test]
    fn test_case_insensitive_encoding_name() {
        let data = b"Hello";
        assert!(decode_text(data, "UTF-8").is_ok());
        assert!(decode_text(data, "Utf-8").is_ok());
        assert!(decode_text(data, "ASCII").is_ok());
    }

    #[test]
    fn test_search_empty_text() {
        let data = b"Hello";
        let results = search_text_encoded(data, "", "utf-8", true, 10);
        assert!(results.is_empty());
    }

    #[test]
    fn test_encode_ebcdic_unmappable_char() {
        let err = encode_text("日", "ebcdic").unwrap_err();
        assert!(
            matches!(&err, EncodingError::EncodeFailed(m) if m.contains("EBCDIC")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_encode_generic_unmappable_char() {
        // A CJK char cannot be represented in windows-1252.
        let err = encode_text("日", "windows-1252").unwrap_err();
        assert!(
            matches!(&err, EncodingError::EncodeFailed(m) if m.contains("windows-1252")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_encode_utf16be_arm() {
        let encoded = encode_text("Hi", "utf-16be").unwrap();
        assert_eq!(encoded, vec![0x00, 0x48, 0x00, 0x69]);
    }

    #[test]
    fn test_decode_shift_jis_had_errors() {
        // A lone Shift_JIS lead byte cannot be decoded -> had_errors is true.
        let (_text, had_errors) = decode_text(&[0x81], "shift_jis").unwrap();
        assert!(had_errors);
    }

    #[test]
    fn test_search_text_encoded_guards() {
        // max_results == 0
        assert!(search_text_encoded(b"hello", "he", "utf-8", true, 0).is_empty());
        // unsupported encoding -> encode_text fails -> empty
        assert!(search_text_encoded(b"hello", "he", "no-such-enc", true, 10).is_empty());
    }

    #[test]
    fn test_search_case_insensitive_data_shorter_than_window() {
        // window_len (6) > data.len() (2) -> empty
        assert!(search_text_encoded(b"ab", "abcdef", "utf-8", false, 10).is_empty());
    }

    #[test]
    fn test_find_pattern_oversize_pattern_via_search() {
        // case-sensitive path: pattern longer than data -> no results
        assert!(search_text_encoded(b"ab", "abcdef", "utf-8", true, 10).is_empty());
    }

    #[test]
    fn test_window_matches_case_insensitive_reject_arms() {
        // ASCII high bit -> reject
        assert!(!window_matches_case_insensitive(&[0x80], "x", "ascii"));
        // EBCDIC decode-and-compare: 0xC1 -> 'A' lowercased 'a' matches
        assert!(window_matches_case_insensitive(&[0xC1], "a", "ebcdic"));
        assert!(!window_matches_case_insensitive(&[0xC2], "a", "ebcdic"));
        // resolve_encoding error -> reject
        assert!(!window_matches_case_insensitive(
            &[0x41],
            "a",
            "no-such-enc"
        ));
        // decode had_errors (lone Shift_JIS lead byte) -> reject
        assert!(!window_matches_case_insensitive(&[0x81], "x", "shift_jis"));
    }

    #[test]
    fn test_decode_text_resolves_every_encoding_alias() {
        let names = [
            "utf-16le",
            "utf-16be",
            "iso-8859-1",
            "windows-1252",
            "iso-8859-2",
            "iso-8859-3",
            "iso-8859-4",
            "iso-8859-5",
            "iso-8859-6",
            "iso-8859-7",
            "iso-8859-8",
            "iso-8859-10",
            "iso-8859-13",
            "iso-8859-14",
            "iso-8859-15",
            "iso-8859-16",
            "windows-1250",
            "windows-1251",
            "windows-1253",
            "windows-1254",
            "windows-1255",
            "windows-1256",
            "windows-1257",
            "windows-1258",
            "shift_jis",
            "euc-jp",
            "iso-2022-jp",
            "euc-kr",
            "gb2312",
            "gb18030",
            "big5",
            "koi8-r",
            "koi8-u",
        ];
        for n in names {
            assert!(
                decode_text(&[0x41], n).is_ok(),
                "encoding {n} should resolve"
            );
        }
    }
}
