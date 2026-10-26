// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Zachary Flint
//
// This file is part of Intellicrack. See LICENSE for details.

//! Text in named encodings: decoding and encoding for UTF-8, UTF-16 in both
//! byte orders, strict ASCII, EBCDIC code page 037 and every `encoding_rs`
//! code page, and searching a buffer for text in any of them.

use std::ops::ControlFlow;

use thiserror::Error;

/// Errors raised while resolving, encoding or decoding text.
#[derive(Error, Debug)]
pub enum EncodingError {
    /// The encoding name is not recognized.
    #[error("unsupported encoding: {0}")]
    UnsupportedEncoding(String),
    /// The text contains a character the encoding cannot represent.
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
        let ch = EBCDIC_TO_UNICODE[usize::from(byte)];
        if ch == '\u{FFFD}' {
            had_replacement = true;
        }
        result.push(ch);
    }
    (result, had_replacement)
}

fn encode_ebcdic(text: &str) -> Result<Vec<u8>, EncodingError> {
    let mut result = Vec::with_capacity(text.len());
    for ch in text.chars() {
        let Some(byte) = EBCDIC_TO_UNICODE
            .iter()
            .position(|&mapped| mapped == ch)
            .and_then(|index| u8::try_from(index).ok())
        else {
            return Err(EncodingError::EncodeFailed(format!(
                "character '{}' (U+{:04X}) cannot be encoded in EBCDIC CP037",
                ch, ch as u32
            )));
        };
        result.push(byte);
    }
    Ok(result)
}

/// A resolved text encoding, looked up once and reused for every window.
#[derive(Clone, Copy)]
pub enum Codec {
    /// 7-bit ASCII; bytes with the high bit set are invalid.
    Ascii,
    /// IBM EBCDIC code page 037.
    Ebcdic,
    /// UTF-8.
    Utf8,
    /// UTF-16, little-endian code units.
    Utf16Le,
    /// UTF-16, big-endian code units.
    Utf16Be,
    /// Any other encoding supported by `encoding_rs`.
    Other(&'static encoding_rs::Encoding),
}

impl Codec {
    /// Resolves an encoding name or WHATWG label, case-insensitively.
    ///
    /// The crate's own names are tried first, then any `encoding_rs` label.
    /// UTF-16 labels such as `"utf-16"` or `"unicode"` resolve to the matching
    /// UTF-16 codec rather than to `encoding_rs`'s UTF-16 encodings, whose
    /// encoder emits UTF-8.
    ///
    /// # Errors
    ///
    /// Returns `EncodingError::UnsupportedEncoding` for an unknown name, or
    /// for the WHATWG `replacement` pseudo-encoding.
    pub fn resolve(name: &str) -> Result<Self, EncodingError> {
        let trimmed = name.trim();
        match trimmed.to_lowercase().as_str() {
            "ascii" | "us-ascii" => return Ok(Self::Ascii),
            "ebcdic" | "ebcdic-cp037" | "cp037" => return Ok(Self::Ebcdic),
            _ => {}
        }
        let enc = resolve_encoding(trimmed).or_else(|unsupported| {
            encoding_rs::Encoding::for_label(trimmed.as_bytes()).ok_or(unsupported)
        })?;
        if enc == encoding_rs::UTF_8 {
            Ok(Self::Utf8)
        } else if enc == encoding_rs::UTF_16LE {
            Ok(Self::Utf16Le)
        } else if enc == encoding_rs::UTF_16BE {
            Ok(Self::Utf16Be)
        } else if enc == encoding_rs::REPLACEMENT {
            Err(EncodingError::UnsupportedEncoding(name.to_string()))
        } else {
            Ok(Self::Other(enc))
        }
    }

    /// Encodes `text`.
    ///
    /// # Errors
    ///
    /// Returns `EncodingError::EncodeFailed` if a character has no mapping.
    pub fn encode(self, text: &str) -> Result<Vec<u8>, EncodingError> {
        match self {
            Self::Ascii => text
                .chars()
                .map(|ch| {
                    u8::try_from(ch).ok().filter(u8::is_ascii).ok_or_else(|| {
                        EncodingError::EncodeFailed(format!(
                            "U+{:04X} cannot be encoded in ASCII",
                            ch as u32
                        ))
                    })
                })
                .collect(),
            Self::Ebcdic => encode_ebcdic(text),
            Self::Utf8 => Ok(text.as_bytes().to_vec()),
            Self::Utf16Le => Ok(text.encode_utf16().flat_map(u16::to_le_bytes).collect()),
            Self::Utf16Be => Ok(text.encode_utf16().flat_map(u16::to_be_bytes).collect()),
            Self::Other(enc) => {
                let (cow, _, had_unmappable) = enc.encode(text);
                if had_unmappable {
                    return Err(EncodingError::EncodeFailed(format!(
                        "text contains characters that cannot be encoded in '{}'",
                        enc.name()
                    )));
                }
                Ok(cow.into_owned())
            }
        }
    }

    /// Decodes `data` exactly as the requested encoding, never sniffing a
    /// byte-order mark. Returns the text and whether any byte was invalid.
    #[must_use]
    pub fn decode(self, data: &[u8]) -> (String, bool) {
        match self {
            Self::Ascii => (
                data.iter().map(|&b| char::from(b & 0x7F)).collect(),
                data.iter().any(|&b| b & 0x80 != 0),
            ),
            Self::Ebcdic => decode_ebcdic(data),
            Self::Utf8 => {
                let (cow, had_errors) = encoding_rs::UTF_8.decode_without_bom_handling(data);
                (cow.into_owned(), had_errors)
            }
            Self::Utf16Le => {
                let (cow, had_errors) = encoding_rs::UTF_16LE.decode_without_bom_handling(data);
                (cow.into_owned(), had_errors)
            }
            Self::Utf16Be => {
                let (cow, had_errors) = encoding_rs::UTF_16BE.decode_without_bom_handling(data);
                (cow.into_owned(), had_errors)
            }
            Self::Other(enc) => {
                let (cow, had_errors) = enc.decode_without_bom_handling(data);
                (cow.into_owned(), had_errors)
            }
        }
    }

    /// Returns `true` when `window` decodes cleanly to text equal to
    /// `needle_lower` after lowercasing.
    ///
    /// The window is decoded one character at a time and compared as it goes,
    /// so a window that differs early costs a few characters rather than a
    /// full decode; only a window whose characters fold onto the whole needle
    /// is decoded in full to confirm the match exactly.
    #[must_use]
    pub fn window_matches_ignore_case(self, window: &[u8], needle_lower: &str) -> bool {
        self.folded_prefix_end(window, needle_lower).is_some()
            && self.lowercases_to(window, needle_lower)
    }

    /// The length of the text at the start of `data` that decodes cleanly and
    /// lowercases to `needle_lower`, or `None` when no prefix of `data` does.
    ///
    /// The match may be longer or shorter than the needle's own encoding: the
    /// case variant of a character can take a different number of bytes, as
    /// `Ⱥ` (two UTF-8 bytes) and its lowercase `ⱥ` (three) do, or the Kelvin
    /// sign (three) and `k` (one). The shortest such prefix is reported.
    #[must_use]
    pub fn match_len_ignore_case(self, data: &[u8], needle_lower: &str) -> Option<usize> {
        let end = self.folded_prefix_end(data, needle_lower)?;
        self.lowercases_to(&data[..end], needle_lower)
            .then_some(end)
    }

    /// Whether `bytes` decode cleanly to text whose lowercase is
    /// `needle_lower`, by a full decode.
    fn lowercases_to(self, bytes: &[u8], needle_lower: &str) -> bool {
        let (decoded, had_errors) = self.decode(bytes);
        !had_errors && decoded.to_lowercase() == needle_lower
    }

    /// Decodes `data` a character at a time, folding each to lowercase against
    /// the rest of `needle_lower`, and returns the end of the character that
    /// completes the needle.
    ///
    /// Decoding stops at the first character that cannot continue the needle
    /// and at malformed input. Characters fold one at a time, which agrees with
    /// `str::to_lowercase` except for a capital sigma, lowercased by context to
    /// `σ` or `ς`; it accepts either here, so this never rejects a true match,
    /// and callers confirm a candidate with a full decode.
    fn folded_prefix_end(self, data: &[u8], needle_lower: &str) -> Option<usize> {
        let mut expected = needle_lower.chars();
        let mut found = None;
        self.each_char(data, |ch, end| {
            let folded = if ch == 'Σ' {
                matches!(expected.next(), Some('σ' | 'ς'))
            } else {
                ch.to_lowercase()
                    .all(|lower| expected.next() == Some(lower))
            };
            if !folded {
                return ControlFlow::Break(());
            }
            if expected.as_str().is_empty() {
                found = Some(end);
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        });
        found
    }

    /// Calls `visit` with each character `data` decodes to and the offset just
    /// past its last byte, in order, until `visit` breaks or the input is
    /// malformed or exhausted.
    ///
    /// Only as much of `data` is decoded as `visit` consumes, so a caller that
    /// stops early pays for the characters it saw and no more.
    fn each_char(self, data: &[u8], mut visit: impl FnMut(char, usize) -> ControlFlow<()>) {
        match self {
            Self::Ascii => {
                for (index, &byte) in data.iter().enumerate() {
                    if !byte.is_ascii() || visit(char::from(byte), index + 1).is_break() {
                        return;
                    }
                }
            }
            Self::Ebcdic => {
                for (index, &byte) in data.iter().enumerate() {
                    if visit(EBCDIC_TO_UNICODE[usize::from(byte)], index + 1).is_break() {
                        return;
                    }
                }
            }
            Self::Utf8 => {
                let mut pos = 0;
                while let Some(&lead) = data.get(pos) {
                    let width = match lead {
                        0x00..=0x7F => 1,
                        0xC2..=0xDF => 2,
                        0xE0..=0xEF => 3,
                        0xF0..=0xF4 => 4,
                        _ => return,
                    };
                    let Some(ch) = data
                        .get(pos..pos + width)
                        .and_then(|bytes| std::str::from_utf8(bytes).ok())
                        .and_then(|text| text.chars().next())
                    else {
                        return;
                    };
                    pos += width;
                    if visit(ch, pos).is_break() {
                        return;
                    }
                }
            }
            Self::Utf16Le | Self::Utf16Be => {
                let big_endian = matches!(self, Self::Utf16Be);
                let units = data.as_chunks::<2>().0.iter().map(|&pair| {
                    if big_endian {
                        u16::from_be_bytes(pair)
                    } else {
                        u16::from_le_bytes(pair)
                    }
                });
                let mut pos = 0;
                for decoded in char::decode_utf16(units) {
                    let Ok(ch) = decoded else {
                        return;
                    };
                    pos += ch.len_utf16() * 2;
                    if visit(ch, pos).is_break() {
                        return;
                    }
                }
            }
            Self::Other(enc) => each_char_streaming(enc, data, visit),
        }
    }
}

/// [`Codec::each_char`] for an `encoding_rs` encoding: the decoder is fed one
/// byte at a time, so every character it emits ends at the byte just fed.
fn each_char_streaming(
    encoding: &'static encoding_rs::Encoding,
    data: &[u8],
    mut visit: impl FnMut(char, usize) -> ControlFlow<()>,
) {
    let mut decoder = encoding.new_decoder_without_bom_handling();
    let mut storage = [0u8; 32];
    let Ok(out) = std::str::from_utf8_mut(&mut storage) else {
        return;
    };
    for (index, byte) in data.iter().enumerate() {
        let mut input = std::slice::from_ref(byte);
        let last = index + 1 == data.len();
        loop {
            let (result, read, written) =
                decoder.decode_to_str_without_replacement(input, out, last);
            if matches!(result, encoding_rs::DecoderResult::Malformed(..)) {
                return;
            }
            for ch in out[..written].chars() {
                if visit(ch, index + 1).is_break() {
                    return;
                }
            }
            input = &input[read..];
            if matches!(result, encoding_rs::DecoderResult::InputEmpty) {
                break;
            }
        }
    }
}

/// Decodes raw bytes into a string using the specified encoding.
///
/// The bytes are decoded as the requested encoding even when they start with
/// a byte-order mark for another one, so `encode_text(decode_text(x))`
/// round-trips for lossless encodings.
///
/// # Errors
///
/// Returns `EncodingError::UnsupportedEncoding` if the encoding name is not recognized.
pub fn decode_text(data: &[u8], encoding_name: &str) -> Result<(String, bool), EncodingError> {
    Ok(Codec::resolve(encoding_name)?.decode(data))
}

/// Encodes a string into raw bytes using the specified encoding.
///
/// # Errors
///
/// Returns `EncodingError::UnsupportedEncoding` if the encoding name is not recognized,
/// or `EncodingError::EncodeFailed` if the text contains unmappable characters.
pub fn encode_text(text: &str, encoding_name: &str) -> Result<Vec<u8>, EncodingError> {
    Codec::resolve(encoding_name)?.encode(text)
}

/// Finds every occurrence of `text` encoded in `encoding_name`, overlapping
/// ones included.
///
/// Matches may start at any byte offset, including odd offsets for UTF-16,
/// and may overlap, as byte and hex searches do: `aa` occurs at 0, 1 and 2
/// in `aaaa`. Returns at most `max_results` `(offset, length)` pairs in
/// ascending order. This is the one text-search engine; `search::search_text`
/// reports the same matches.
///
/// A case-sensitive search matches the exact encoding of `text`, so text the
/// encoding cannot represent matches nothing, and it costs time linear in
/// `data` plus the bytes of the matches it reports, whatever the pattern. A
/// case-insensitive search matches any text whose lowercase equals that of
/// `text`, even where a case variant encodes to a different number of bytes,
/// so each match carries its own length; each offset decodes only until the
/// first character that cannot continue the match.
///
/// # Errors
///
/// Returns `EncodingError::UnsupportedEncoding` if the encoding name is not
/// recognized, so a typo is never mistaken for "no matches".
pub fn search_text_encoded(
    data: &[u8],
    text: &str,
    encoding_name: &str,
    case_sensitive: bool,
    max_results: usize,
) -> Result<Vec<(usize, usize)>, EncodingError> {
    let codec = Codec::resolve(encoding_name)?;
    if text.is_empty() || max_results == 0 {
        return Ok(Vec::new());
    }
    let mut results: Vec<(usize, usize)> = Vec::new();

    if !case_sensitive {
        let needle_lower = text.to_lowercase();
        results.extend(
            (0..data.len())
                .filter_map(|offset| {
                    codec
                        .match_len_ignore_case(&data[offset..], &needle_lower)
                        .map(|length| (offset, length))
                })
                .take(max_results),
        );
        return Ok(results);
    }

    let Ok(search_bytes) = codec.encode(text) else {
        return Ok(Vec::new());
    };
    if search_bytes.is_empty() || search_bytes.len() > data.len() {
        return Ok(Vec::new());
    }
    // `find_iter` resumes after each match and so skips overlapping ones;
    // resuming one byte past each match start keeps them, and the finder's
    // two-way search stays linear on the bytes it scans.
    let finder = memchr::memmem::Finder::new(&search_bytes);
    let mut start = 0;
    while results.len() < max_results {
        let Some(found) = finder.find(&data[start..]) else {
            break;
        };
        let offset = start + found;
        results.push((offset, search_bytes.len()));
        start = offset + 1;
    }
    Ok(results)
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

/// Returns `(name, description)` for every encoding offered to users.
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
        assert_eq!(encodings.len(), 36);
        for (name, _) in &encodings {
            assert!(
                Codec::resolve(name).is_ok(),
                "listed encoding {name} must resolve"
            );
        }
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
        let results = search_text_encoded(data, "Hello", "utf-8", true, 10).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], (0, 5));
        assert_eq!(results[1], (14, 5));
    }

    #[test]
    fn test_search_text_utf8_not_found() {
        let data = b"Hello, world!";
        let results = search_text_encoded(data, "xyz", "utf-8", true, 10).unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_search_text_utf16le() {
        let haystack_str = "Hello World Hello";
        let haystack: Vec<u8> = haystack_str
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let results = search_text_encoded(&haystack, "Hello", "utf-16le", true, 10).unwrap();
        assert_eq!(results, vec![(0, 10), (24, 10)]);
    }

    #[test]
    fn test_search_text_max_results() {
        let data = b"aaa aaa aaa aaa aaa";
        let results = search_text_encoded(data, "aaa", "utf-8", true, 2).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_search_text_case_insensitive() {
        let data = b"Hello hello HELLO";
        let results = search_text_encoded(data, "hello", "utf-8", false, 10).unwrap();
        assert_eq!(results, vec![(0, 5), (6, 5), (12, 5)]);
    }

    #[test]
    fn test_search_text_mixed_case_ascii() {
        let data = b"say hello to the world";
        let results = search_text_encoded(data, "HeLLo", "utf-8", false, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], (4, 5));
    }

    #[test]
    fn test_search_text_mixed_case_matches_upper() {
        let data = b"the WORLD is here";
        let results = search_text_encoded(data, "WoRlD", "utf-8", false, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], (4, 5));
    }

    #[test]
    fn test_search_text_mixed_case_cyrillic_utf16le() {
        let target = "привет";
        let haystack: Vec<u8> = target.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let results = search_text_encoded(&haystack, "ПрИвЕт", "utf-16le", false, 10).unwrap();
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
        assert!(matches!(
            result,
            Err(EncodingError::UnsupportedEncoding(ref n)) if n == "unknown-encoding-xyz"
        ));
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
        let results = search_text_encoded(data, "", "utf-8", true, 10).unwrap();
        assert_eq!(results.len(), 0);
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
        assert_eq!(
            search_text_encoded(b"hello", "he", "utf-8", true, 0)
                .unwrap()
                .len(),
            0
        );
        // text unrepresentable in the encoding -> no match, not an error
        assert_eq!(
            search_text_encoded(b"hello", "\u{0416}", "ascii", true, 10)
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn test_search_case_insensitive_data_shorter_than_window() {
        // window_len (6) > data.len() (2) -> empty
        assert_eq!(
            search_text_encoded(b"ab", "abcdef", "utf-8", false, 10)
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn test_find_pattern_oversize_pattern_via_search() {
        // case-sensitive path: pattern longer than data -> no results
        assert_eq!(
            search_text_encoded(b"ab", "abcdef", "utf-8", true, 10)
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn test_window_matches_ignore_case_reject_arms() {
        // ASCII high bit -> reject
        assert!(!Codec::Ascii.window_matches_ignore_case(&[0x80], "x"));
        // EBCDIC decode-and-compare: 0xC1 -> 'A' lowercased 'a' matches
        assert!(Codec::Ebcdic.window_matches_ignore_case(&[0xC1], "a"));
        assert!(!Codec::Ebcdic.window_matches_ignore_case(&[0xC2], "a"));
        assert!(matches!(
            Codec::resolve("no-such-enc"),
            Err(EncodingError::UnsupportedEncoding(ref n)) if n == "no-such-enc"
        ));
        // decode had_errors (lone Shift_JIS lead byte) -> reject
        let sjis = Codec::resolve("shift_jis").unwrap();
        assert!(!sjis.window_matches_ignore_case(&[0x81], "x"));
    }

    /// A window that is a multi-byte character lowercasing to an ASCII needle
    /// (U+212A KELVIN SIGN, bytes E2 84 AA, lowercases to 'k') must still match
    /// case-insensitively; a length-blind ASCII fast path rejects it because
    /// the three-byte window differs in length from the one-byte needle.
    #[test]
    fn test_window_matches_ignore_case_folds_multibyte_to_ascii_needle() {
        assert!(Codec::Utf8.window_matches_ignore_case("\u{212A}".as_bytes(), "k"));
    }

    /// The UTF-16 case-insensitive fast path folds printable-ASCII code units
    /// directly in both byte orders, but a non-ASCII unit (the one-unit Kelvin
    /// sign U+212A, which lowercases to `'k'`) must defer to the decode so it
    /// still matches. Folding the raw bytes would miss it.
    #[test]
    fn test_utf16_case_insensitive_folds_ascii_and_defers_non_ascii() {
        let little = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        let big = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_be_bytes).collect() };
        assert!(Codec::Utf16Le.window_matches_ignore_case(&little("HeLLo"), "hello"));
        assert!(Codec::Utf16Be.window_matches_ignore_case(&big("HeLLo"), "hello"));
        assert!(!Codec::Utf16Le.window_matches_ignore_case(&little("World"), "hello"));
        assert!(Codec::Utf16Le.window_matches_ignore_case(&little("\u{212A}"), "k"));
        assert!(Codec::Utf16Be.window_matches_ignore_case(&big("\u{212A}"), "k"));
    }

    /// "us-ascii" and a space-padded "ascii" must resolve to the strict ASCII
    /// codec, not fall through to windows-1252, which would decode 0xC8 as 'È'
    /// with no error instead of masking it to 'H' and flagging the loss.
    #[test]
    fn test_resolve_ascii_aliases_use_the_strict_codec() {
        assert_eq!(
            decode_text(&[0xC8], "us-ascii").unwrap(),
            ("H".to_string(), true)
        );
        assert_eq!(
            decode_text(&[0xC8], " ascii ").unwrap(),
            ("H".to_string(), true)
        );
    }

    /// An unknown encoding name must make the search return an error rather
    /// than no matches, so a typo is not reported to the user as "0 matches",
    /// per the bridge's raise-on-unsupported contract.
    #[test]
    fn test_search_text_encoded_rejects_unknown_encoding() {
        assert!(matches!(
            search_text_encoded(b"hello", "he", "no-such-enc", true, 10),
            Err(EncodingError::UnsupportedEncoding(ref n)) if n == "no-such-enc"
        ));
        assert!(matches!(
            search_text_encoded(b"hello", "", "no-such-enc", true, 10),
            Err(EncodingError::UnsupportedEncoding(_))
        ));
    }

    /// Case-insensitive UTF-16 search must not step two bytes at a time, or
    /// UTF-16 text at an odd offset is found case-sensitively but missed
    /// case-insensitively.
    #[test]
    fn test_search_text_encoded_utf16_case_insensitive_odd_offset() {
        let data = [0x41, 0x48, 0x00, 0x49, 0x00];
        assert_eq!(
            search_text_encoded(&data, "hi", "utf-16le", false, 10).unwrap(),
            vec![(1, 4)]
        );
        assert_eq!(
            search_text_encoded(&data, "HI", "utf-16le", true, 10).unwrap(),
            vec![(1, 4)]
        );
    }

    /// `decode_text` must not use `encoding_rs`'s BOM-sniffing decode, which
    /// decodes bytes starting with a byte-order mark as the sniffed encoding
    /// with the BOM stripped instead of as the one requested.
    #[test]
    fn test_decode_text_does_not_sniff_bom() {
        assert_eq!(
            decode_text(&[0xFE, 0xFF, 0x41, 0x00], "utf-16le").unwrap(),
            ("\u{FFFE}A".to_string(), false)
        );
        assert_eq!(
            decode_text(&[0xEF, 0xBB, 0xBF, 0x41], "utf-8").unwrap(),
            ("\u{FEFF}A".to_string(), false)
        );
        assert_eq!(
            decode_text(&[0xEF, 0xBB, 0xBF, 0x41], "windows-1252").unwrap(),
            ("\u{EF}\u{BB}\u{BF}A".to_string(), false)
        );
    }

    /// WHATWG UTF-16 labels such as `"utf-16"` must resolve to the crate's
    /// UTF-16 codec, not be rejected or resolved to `encoding_rs`'s UTF-16
    /// encoding, whose encoder emits UTF-8 (a search for `"AB"` would look for
    /// `41 42`).
    #[test]
    fn test_utf16_labels_resolve_to_utf16_codecs() {
        assert_eq!(
            encode_text("AB", "utf-16").unwrap(),
            vec![0x41, 0x00, 0x42, 0x00]
        );
        assert_eq!(
            encode_text("AB", "unicodefffe").unwrap(),
            vec![0x00, 0x41, 0x00, 0x42]
        );
        assert!(matches!(
            Codec::resolve("replacement"),
            Err(EncodingError::UnsupportedEncoding(_))
        ));
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
            let ascii_a: &[u8] = match n {
                "utf-16le" => &[0x41, 0x00],
                "utf-16be" => &[0x00, 0x41],
                _ => b"A",
            };
            assert_eq!(
                decode_text(ascii_a, n).unwrap(),
                ("A".to_string(), false),
                "encoding {n}"
            );
        }
    }

    /// Each code-page name resolves to its own code page: a byte that differs
    /// between them decodes to that code page's character, as Python's codecs
    /// decode it.
    #[test]
    fn test_code_page_names_decode_their_own_characters() {
        let cases: [(&str, &[u8], char); 17] = [
            ("windows-1252", &[0x80], '\u{20AC}'),
            ("iso-8859-2", &[0xB1], '\u{0105}'),
            ("iso-8859-5", &[0xE9], '\u{0449}'),
            ("windows-1251", &[0xE9], '\u{0439}'),
            ("koi8-r", &[0xA4], '\u{2553}'),
            ("koi8-u", &[0xA4], '\u{0454}'),
            ("windows-1253", &[0xE9], '\u{03B9}'),
            ("iso-8859-7", &[0xE9], '\u{03B9}'),
            ("windows-1255", &[0xE9], '\u{05D9}'),
            ("iso-8859-15", &[0xA4], '\u{20AC}'),
            ("windows-1250", &[0xB9], '\u{0105}'),
            ("shift_jis", &[0x82, 0xA0], '\u{3042}'),
            ("euc-jp", &[0xA4, 0xA2], '\u{3042}'),
            ("euc-kr", &[0xB0, 0xA1], '\u{AC00}'),
            ("gb2312", &[0xB0, 0xA1], '\u{554A}'),
            ("big5", &[0xA4, 0x40], '\u{4E00}'),
            ("gb18030", &[0xB0, 0xA1], '\u{554A}'),
        ];
        for (name, bytes, expected) in cases {
            assert_eq!(
                decode_text(bytes, name).unwrap(),
                (expected.to_string(), false),
                "{name}"
            );
        }
    }

    /// A UTF-16 buffer with a dangling odd byte decodes the complete units and
    /// a replacement character for the dangling byte, and reports the loss.
    #[test]
    fn test_utf16le_odd_trailing_byte_is_lossy() {
        assert_eq!(
            decode_text(&[0x41, 0x00, 0x42], "utf-16le").unwrap(),
            ("A\u{FFFD}".to_string(), true)
        );
        assert_eq!(
            decode_text(&[0x00, 0x41, 0x00], "utf-16be").unwrap(),
            ("A\u{FFFD}".to_string(), true)
        );
    }

    /// A case-sensitive search reports every occurrence, overlapping ones
    /// included, and keeps its result cap and its odd-offset UTF-16 matches.
    #[test]
    fn test_case_sensitive_search_semantics() {
        assert_eq!(
            search_text_encoded(b"aaaaa", "aa", "ascii", true, 10).unwrap(),
            vec![(0, 2), (1, 2), (2, 2), (3, 2)]
        );
        assert_eq!(
            search_text_encoded(b"aaaaa", "aa", "ascii", true, 1).unwrap(),
            vec![(0, 2)]
        );
        assert_eq!(
            search_text_encoded(b"\x00h\x00i\x00", "hi", "utf-16le", true, 10).unwrap(),
            vec![(1, 4)]
        );
        assert_eq!(
            search_text_encoded(b"xyz", "xyz", "ascii", true, 10).unwrap(),
            vec![(0, 3)]
        );
    }

    /// `search_text_encoded` and `search::search_text` are one engine: the
    /// hex editor falls back from one to the other, so on self-overlapping
    /// patterns, in both case modes and at odd UTF-16 offsets, they report
    /// identical matches.
    #[test]
    fn test_text_search_entry_points_report_identical_matches() {
        let wide_aba: Vec<u8> = "xABABAy"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut odd_wide = vec![0xFF];
        odd_wide.extend_from_slice(&wide_aba);
        let cases: [(&[u8], &str, &str); 4] = [
            (b"aaaaaa", "aa", "ascii"),
            (b"xAbAbAbAy", "aba", "ascii"),
            (&wide_aba, "ABA", "utf-16le"),
            (&odd_wide, "aba", "utf-16le"),
        ];
        for (data, text, encoding) in cases {
            for case_sensitive in [true, false] {
                let encoded =
                    search_text_encoded(data, text, encoding, case_sensitive, 100).unwrap();
                let searched: Vec<(usize, usize)> =
                    crate::search::search_text(data, text, encoding, case_sensitive, 100)
                        .unwrap()
                        .into_iter()
                        .map(|r| (r.offset, r.length))
                        .collect();
                assert_eq!(
                    encoded, searched,
                    "{text:?} in {data:?}, case_sensitive={case_sensitive}"
                );
            }
        }
        assert_eq!(
            search_text_encoded(b"xAbAbAbAy", "aba", "ascii", false, 100).unwrap(),
            vec![(1, 3), (3, 3), (5, 3)]
        );
        assert_eq!(
            search_text_encoded(&wide_aba, "ABA", "utf-16le", true, 100).unwrap(),
            vec![(2, 6), (6, 6)]
        );
    }

    /// A case-sensitive search over repetitive data takes linear time.
    ///
    /// Every offset of 64 MiB of zeros is a near miss for 4 KiB of zeros ending
    /// in 0x01, so a window compare checks each offset to its last byte.
    #[test]
    fn test_case_sensitive_search_is_linear_on_near_misses() {
        let mut pattern = "\0".repeat(4095);
        pattern.push('\u{1}');
        let data = vec![0u8; 64 << 20];

        let started = std::time::Instant::now();
        let found = search_text_encoded(&data, &pattern, "ascii", true, 10).unwrap();
        let elapsed = started.elapsed();

        assert_eq!(found, Vec::<(usize, usize)>::new());
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "64 MiB near-miss search took {elapsed:?}"
        );
    }

    /// A case-insensitive search reports each match at its own width when a
    /// case variant encodes to a different number of bytes than the needle:
    /// `ⱥ` is three UTF-8 bytes and its uppercase `Ⱥ` two, the Kelvin sign is
    /// three bytes and lowercases to the one-byte `k`, and a needle the
    /// encoding cannot represent still finds its case variants that it can.
    #[test]
    fn test_case_insensitive_matches_case_variants_of_another_width() {
        assert_eq!(
            search_text_encoded("\u{2C65}".as_bytes(), "\u{023A}", "utf-8", false, 10).unwrap(),
            vec![(0, 3)]
        );
        assert_eq!(
            search_text_encoded("x\u{023A}y".as_bytes(), "\u{2C65}", "utf-8", false, 10).unwrap(),
            vec![(1, 2)]
        );
        assert_eq!(
            search_text_encoded("a\u{212A}b".as_bytes(), "K", "utf-8", false, 10).unwrap(),
            vec![(1, 3)]
        );
        assert_eq!(
            search_text_encoded(b"okay", "\u{212A}", "ascii", false, 10).unwrap(),
            vec![(1, 1)]
        );
        assert_eq!(
            search_text_encoded(b"okay", "\u{212A}", "ascii", true, 10).unwrap(),
            Vec::<(usize, usize)>::new()
        );
    }

    /// A case-insensitive search through a streaming `encoding_rs` codec or the
    /// EBCDIC table decodes each offset only until its first character fails
    /// to match, so a 1 KiB needle over 1 MiB that never matches past its first
    /// character costs one character per offset, not a 1 KiB decode.
    #[test]
    fn test_case_insensitive_search_is_linear_on_near_misses() {
        let needle = "a".repeat(1024);
        let data = vec![0u8; 1 << 20];
        for encoding in ["windows-1252", "shift_jis", "ebcdic", "utf-16le", "utf-8"] {
            let started = std::time::Instant::now();
            let found = search_text_encoded(&data, &needle, encoding, false, 10).unwrap();
            let elapsed = started.elapsed();
            assert_eq!(found, Vec::<(usize, usize)>::new(), "{encoding}");
            assert!(
                elapsed < std::time::Duration::from_secs(5),
                "{encoding}: 1 MiB near-miss case-insensitive search took {elapsed:?}"
            );
        }
    }

    /// A capital sigma lowercases to `ς` at the end of a word and to `σ`
    /// elsewhere, so the case-insensitive match agrees with
    /// `str::to_lowercase` on both.
    #[test]
    fn test_case_insensitive_sigma_follows_word_final_lowercasing() {
        let upper_final = "\u{039F}\u{0394}\u{039F}\u{03A3}".as_bytes();
        let medial = "\u{03BF}\u{03B4}\u{03BF}\u{03C3}";
        let word_final = "\u{03BF}\u{03B4}\u{03BF}\u{03C2}";
        assert_eq!(
            search_text_encoded(upper_final, medial, "utf-8", false, 10).unwrap(),
            Vec::<(usize, usize)>::new()
        );
        assert_eq!(
            search_text_encoded(upper_final, word_final, "utf-8", false, 10).unwrap(),
            vec![(0, 8)]
        );
        let upper_initial = "\u{03A3}\u{0391}".as_bytes();
        assert_eq!(
            search_text_encoded(upper_initial, "\u{03C3}\u{03B1}", "utf-8", false, 10).unwrap(),
            vec![(0, 4)]
        );
    }
}
