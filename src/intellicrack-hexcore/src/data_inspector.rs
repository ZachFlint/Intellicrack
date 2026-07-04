use std::collections::HashMap;

pub struct DataInspection {
    pub values: HashMap<String, String>,
}

impl DataInspection {
    #[must_use]
    pub fn to_map(&self) -> &HashMap<String, String> {
        &self.values
    }
}

fn read_u24_le(data: &[u8], offset: usize) -> u32 {
    u32::from(data[offset])
        | (u32::from(data[offset + 1]) << 8)
        | (u32::from(data[offset + 2]) << 16)
}

fn read_u24_be(data: &[u8], offset: usize) -> u32 {
    (u32::from(data[offset]) << 16)
        | (u32::from(data[offset + 1]) << 8)
        | u32::from(data[offset + 2])
}

fn sign_extend_24(val: u32) -> i32 {
    if val & 0x80_0000 != 0 {
        (val | 0xFF00_0000).cast_signed()
    } else {
        val.cast_signed()
    }
}

fn read_u48_le(data: &[u8], offset: usize) -> u64 {
    let mut val: u64 = 0;
    for i in 0..6 {
        val |= u64::from(data[offset + i]) << (i * 8);
    }
    val
}

fn read_u48_be(data: &[u8], offset: usize) -> u64 {
    let mut val: u64 = 0;
    for i in 0..6 {
        val |= u64::from(data[offset + i]) << ((5 - i) * 8);
    }
    val
}

fn sign_extend_48(val: u64) -> i64 {
    if val & 0x0000_8000_0000_0000 != 0 {
        (val | 0xFFFF_0000_0000_0000).cast_signed()
    } else {
        val.cast_signed()
    }
}

fn decode_uleb128(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    let mut bytes_read: usize = 0;
    let max_bytes = 10.min(data.len() - offset);

    for i in 0..max_bytes {
        let byte = data[offset + i];
        bytes_read += 1;
        result |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Some((result, bytes_read));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

fn decode_sleb128(data: &[u8], offset: usize) -> Option<(i64, usize)> {
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    let mut bytes_read: usize = 0;
    let max_bytes = 10.min(data.len() - offset);

    for i in 0..max_bytes {
        let byte = data[offset + i];
        bytes_read += 1;
        result |= i64::from(byte & 0x7F) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && byte & 0x40 != 0 {
                result |= !0i64 << shift;
            }
            return Some((result, bytes_read));
        }
        if shift >= 64 {
            return None;
        }
    }
    None
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn inspect_8bit(
    values: &mut HashMap<String, String>,
    data: &[u8],
    offset: usize,
    remaining: usize,
) {
    let byte = data[offset];
    values.insert("int8".to_string(), format!("{}", byte.cast_signed()));
    values.insert("uint8".to_string(), format!("{byte}"));

    if byte.is_ascii_graphic() || byte == b' ' {
        values.insert("ascii_char".to_string(), format!("{}", byte as char));
    }

    if remaining >= 1 {
        if let Ok(s) = std::str::from_utf8(&data[offset..offset + remaining.min(4)]) {
            if let Some(ch) = s.chars().next() {
                if !ch.is_control() {
                    values.insert("utf8_char".to_string(), ch.to_string());
                }
            }
        }
    }

    if remaining >= 1 {
        if let Some((val, count)) = decode_uleb128(data, offset) {
            values.insert("uleb128".to_string(), format!("{val} ({count} bytes)"));
        }
        if let Some((val, count)) = decode_sleb128(data, offset) {
            values.insert("sleb128".to_string(), format!("{val} ({count} bytes)"));
        }
    }
}

fn inspect_16bit(values: &mut HashMap<String, String>, data: &[u8], offset: usize) {
    let b = [data[offset], data[offset + 1]];
    let le_val = u16::from_le_bytes(b);
    let be_val = u16::from_be_bytes(b);
    values.insert("int16_le".to_string(), format!("{}", le_val.cast_signed()));
    values.insert("int16_be".to_string(), format!("{}", be_val.cast_signed()));
    values.insert("uint16_le".to_string(), format!("{le_val}"));
    values.insert("uint16_be".to_string(), format!("{be_val}"));

    let f16_little = half::f16::from_le_bytes(b);
    let f16_big = half::f16::from_be_bytes(b);
    if f16_little.is_finite() {
        values.insert("float16_le".to_string(), format!("{f16_little}"));
    }
    if f16_big.is_finite() {
        values.insert("float16_be".to_string(), format!("{f16_big}"));
    }

    let r = ((le_val >> 11) & 0x1F) as u8;
    let g = ((le_val >> 5) & 0x3F) as u8;
    let blue = (le_val & 0x1F) as u8;
    let r8 = ((u32::from(r) * 255 / 31) & 0xFF) as u8;
    let g8 = ((u32::from(g) * 255 / 63) & 0xFF) as u8;
    let b8 = ((u32::from(blue) * 255 / 31) & 0xFF) as u8;
    values.insert("rgb565".to_string(), format!("R:{r8} G:{g8} B:{b8}"));

    let time_bits = le_val;
    let hour = (time_bits >> 11) & 0x1F;
    let minute = (time_bits >> 5) & 0x3F;
    let second = (time_bits & 0x1F) * 2;
    if hour < 24 && minute < 60 && second < 60 {
        values.insert(
            "dos_time".to_string(),
            format!("{hour:02}:{minute:02}:{second:02}"),
        );
    }

    let date_bits = le_val;
    let year = u32::from((date_bits >> 9) & 0x7F) + 1980;
    let month = (date_bits >> 5) & 0x0F;
    let day = date_bits & 0x1F;
    if (1..=12).contains(&month) && (1..=31).contains(&day) && year <= 2107 {
        values.insert(
            "dos_date".to_string(),
            format!("{year:04}-{month:02}-{day:02}"),
        );
    }
}

fn inspect_24bit(values: &mut HashMap<String, String>, data: &[u8], offset: usize) {
    let le_val = read_u24_le(data, offset);
    let be_val = read_u24_be(data, offset);
    values.insert("uint24_le".to_string(), format!("{le_val}"));
    values.insert("uint24_be".to_string(), format!("{be_val}"));
    values.insert(
        "int24_le".to_string(),
        format!("{}", sign_extend_24(le_val)),
    );
    values.insert(
        "int24_be".to_string(),
        format!("{}", sign_extend_24(be_val)),
    );
}

fn inspect_32bit(values: &mut HashMap<String, String>, data: &[u8], offset: usize) {
    let b = [
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ];
    let le_val = u32::from_le_bytes(b);
    let be_val = u32::from_be_bytes(b);
    values.insert("int32_le".to_string(), format!("{}", le_val.cast_signed()));
    values.insert("int32_be".to_string(), format!("{}", be_val.cast_signed()));
    values.insert("uint32_le".to_string(), format!("{le_val}"));
    values.insert("uint32_be".to_string(), format!("{be_val}"));

    let f32_little = f32::from_le_bytes(b);
    let f32_big = f32::from_be_bytes(b);
    if f32_little.is_finite() {
        values.insert("float32_le".to_string(), format!("{f32_little}"));
    }
    if f32_big.is_finite() {
        values.insert("float32_be".to_string(), format!("{f32_big}"));
    }

    values.insert(
        "rgba8".to_string(),
        format!("#{:02X}{:02X}{:02X}{:02X}", b[0], b[1], b[2], b[3]),
    );

    values.insert(
        "ipv4".to_string(),
        format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
    );

    inspect_unix_timestamp(values, le_val);
}

fn inspect_unix_timestamp(values: &mut HashMap<String, String>, raw: u32) {
    let timestamp = i64::from(raw);
    if timestamp > 0 && timestamp < 4_102_444_800 {
        let secs = timestamp;
        let days = secs / 86400;
        let time_of_day = secs % 86400;
        let hours = time_of_day / 3600;
        let minutes = (time_of_day % 3600) / 60;
        let seconds = time_of_day % 60;

        let mut y = 1970i64;
        let mut remaining_days = days;
        loop {
            let days_in_year = if is_leap_year(y) { 366 } else { 365 };
            if remaining_days < days_in_year {
                break;
            }
            remaining_days -= days_in_year;
            y += 1;
        }

        let leap = is_leap_year(y);
        let month_days: [i64; 12] = if leap {
            [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        } else {
            [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        };

        let mut m = 0usize;
        while m < 12 && remaining_days >= month_days[m] {
            remaining_days -= month_days[m];
            m += 1;
        }

        values.insert(
            "unix_timestamp".to_string(),
            format!(
                "{y:04}-{:02}-{:02} {hours:02}:{minutes:02}:{seconds:02} UTC",
                m + 1,
                remaining_days + 1,
            ),
        );
    }
}

fn inspect_48bit(values: &mut HashMap<String, String>, data: &[u8], offset: usize) {
    let le_val = read_u48_le(data, offset);
    let be_val = read_u48_be(data, offset);
    values.insert("uint48_le".to_string(), format!("{le_val}"));
    values.insert("uint48_be".to_string(), format!("{be_val}"));
    values.insert(
        "int48_le".to_string(),
        format!("{}", sign_extend_48(le_val)),
    );
    values.insert(
        "int48_be".to_string(),
        format!("{}", sign_extend_48(be_val)),
    );
}

fn inspect_64bit(values: &mut HashMap<String, String>, data: &[u8], offset: usize) {
    let b = [
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ];
    let le_val = u64::from_le_bytes(b);
    let be_val = u64::from_be_bytes(b);
    values.insert("int64_le".to_string(), format!("{}", le_val.cast_signed()));
    values.insert("int64_be".to_string(), format!("{}", be_val.cast_signed()));
    values.insert("uint64_le".to_string(), format!("{le_val}"));
    values.insert("uint64_be".to_string(), format!("{be_val}"));

    let f64_little = f64::from_le_bytes(b);
    let f64_big = f64::from_be_bytes(b);
    if f64_little.is_finite() {
        values.insert("float64_le".to_string(), format!("{f64_little}"));
    }
    if f64_big.is_finite() {
        values.insert("float64_be".to_string(), format!("{f64_big}"));
    }

    inspect_filetime(values, le_val);
}

fn inspect_filetime(values: &mut HashMap<String, String>, filetime: u64) {
    if filetime > 116_444_736_000_000_000 && filetime < 200_000_000_000_000_000 {
        let unix_100ns = filetime - 116_444_736_000_000_000;
        let unix_secs = (unix_100ns / 10_000_000).cast_signed();

        let days = unix_secs / 86400;
        let time_of_day = unix_secs % 86400;
        let hours = time_of_day / 3600;
        let minutes = (time_of_day % 3600) / 60;
        let seconds = time_of_day % 60;

        let mut y = 1970i64;
        let mut rd = days;
        loop {
            let diy = if is_leap_year(y) { 366 } else { 365 };
            if rd < diy {
                break;
            }
            rd -= diy;
            y += 1;
        }

        let leap = is_leap_year(y);
        let md: [i64; 12] = if leap {
            [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        } else {
            [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        };
        let mut m = 0usize;
        while m < 12 && rd >= md[m] {
            rd -= md[m];
            m += 1;
        }

        values.insert(
            "filetime".to_string(),
            format!(
                "{y:04}-{:02}-{:02} {hours:02}:{minutes:02}:{seconds:02} UTC",
                m + 1,
                rd + 1,
            ),
        );
    }
}

fn inspect_128bit(values: &mut HashMap<String, String>, data: &[u8], offset: usize) {
    let d = &data[offset..offset + 16];
    values.insert(
        "guid".to_string(),
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            d[3], d[2], d[1], d[0],
            d[5], d[4],
            d[7], d[6],
            d[8], d[9],
            d[10], d[11], d[12], d[13], d[14], d[15]
        ),
    );

    let segments: Vec<u16> = (0..8)
        .map(|i| u16::from_be_bytes([d[i * 2], d[i * 2 + 1]]))
        .collect();
    values.insert(
        "ipv6".to_string(),
        format!(
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            segments[0],
            segments[1],
            segments[2],
            segments[3],
            segments[4],
            segments[5],
            segments[6],
            segments[7]
        ),
    );
}

fn inspect_wide_string(
    values: &mut HashMap<String, String>,
    data: &[u8],
    offset: usize,
    remaining: usize,
) {
    let mut wide_chars: Vec<u16> = Vec::new();
    let max_wide = remaining.min(64) / 2;
    for i in 0..max_wide {
        let idx = offset + i * 2;
        let code_unit = u16::from_le_bytes([data[idx], data[idx + 1]]);
        if code_unit == 0 {
            break;
        }
        wide_chars.push(code_unit);
        if wide_chars.len() >= 32 {
            break;
        }
    }
    if !wide_chars.is_empty() {
        if let Ok(s) = String::from_utf16(&wide_chars) {
            if s.chars().all(|c| !c.is_control() || c == '\t') {
                values.insert("wide_string".to_string(), s);
            }
        }
    }
}

#[must_use]
pub fn inspect_at(data: &[u8], offset: usize) -> DataInspection {
    let mut values = HashMap::new();
    let remaining = if offset < data.len() {
        data.len() - offset
    } else {
        0
    };

    if remaining == 0 {
        return DataInspection { values };
    }

    inspect_8bit(&mut values, data, offset, remaining);

    if remaining >= 2 {
        inspect_16bit(&mut values, data, offset);
    }

    if remaining >= 3 {
        inspect_24bit(&mut values, data, offset);
    }

    if remaining >= 4 {
        inspect_32bit(&mut values, data, offset);
    }

    if remaining >= 6 {
        inspect_48bit(&mut values, data, offset);
    }

    if remaining >= 8 {
        inspect_64bit(&mut values, data, offset);
    }

    if remaining >= 16 {
        inspect_128bit(&mut values, data, offset);
    }

    if remaining >= 2 {
        inspect_wide_string(&mut values, data, offset, remaining);
    }

    DataInspection { values }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inspect_single_byte() {
        let data = [0x41u8];
        let result = inspect_at(&data, 0);
        assert_eq!(result.values.get("uint8").unwrap(), "65");
        assert_eq!(result.values.get("int8").unwrap(), "65");
        assert_eq!(result.values.get("ascii_char").unwrap(), "A");
    }

    #[test]
    fn test_inspect_negative_int8() {
        let data = [0xFFu8];
        let result = inspect_at(&data, 0);
        assert_eq!(result.values.get("int8").unwrap(), "-1");
        assert_eq!(result.values.get("uint8").unwrap(), "255");
    }

    #[test]
    fn test_inspect_16bit() {
        let data = [0x01u8, 0x00];
        let result = inspect_at(&data, 0);
        assert_eq!(result.values.get("uint16_le").unwrap(), "1");
        assert_eq!(result.values.get("uint16_be").unwrap(), "256");
    }

    #[test]
    fn test_inspect_32bit() {
        let data = [0x01u8, 0x00, 0x00, 0x00];
        let result = inspect_at(&data, 0);
        assert_eq!(result.values.get("uint32_le").unwrap(), "1");
        assert_eq!(result.values.get("uint32_be").unwrap(), "16777216");
    }

    #[test]
    fn test_inspect_64bit() {
        let data = [0x01u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = inspect_at(&data, 0);
        assert_eq!(result.values.get("uint64_le").unwrap(), "1");
    }

    #[test]
    fn test_inspect_float32() {
        let val: f32 = 3.125;
        let bytes = val.to_le_bytes();
        let mut data = [0u8; 8];
        data[..4].copy_from_slice(&bytes);
        let result = inspect_at(&data, 0);
        let f_str = result.values.get("float32_le").unwrap();
        let parsed: f32 = f_str.parse().unwrap();
        assert!((parsed - 3.125).abs() < 0.001);
    }

    #[test]
    fn test_inspect_unix_timestamp() {
        let ts: u32 = 1_704_067_200;
        let data = ts.to_le_bytes();
        let result = inspect_at(&data, 0);
        let ts_str = result.values.get("unix_timestamp").unwrap();
        assert!(ts_str.starts_with("2024-01-01"));
    }

    #[test]
    fn test_inspect_empty_data() {
        let data: [u8; 0] = [];
        let result = inspect_at(&data, 0);
        assert!(result.values.is_empty());
    }

    #[test]
    fn test_inspect_offset_out_of_bounds() {
        let data = [0x41u8];
        let result = inspect_at(&data, 5);
        assert!(result.values.is_empty());
    }

    #[test]
    fn test_non_ascii_byte() {
        let data = [0x00u8];
        let result = inspect_at(&data, 0);
        assert!(!result.values.contains_key("ascii_char"));
    }

    #[test]
    fn test_inspect_24bit() {
        let data = [0x56, 0x34, 0x12, 0x00];
        let result = inspect_at(&data, 0);
        assert_eq!(result.values.get("uint24_le").unwrap(), "1193046");
        assert_eq!(result.values.get("uint24_be").unwrap(), "5649426");
    }

    #[test]
    fn test_inspect_24bit_signed() {
        let data = [0x00, 0x00, 0x80, 0x00];
        let result = inspect_at(&data, 0);
        assert_eq!(result.values.get("int24_le").unwrap(), "-8388608");
    }

    #[test]
    fn test_inspect_48bit() {
        let data = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = inspect_at(&data, 0);
        assert_eq!(result.values.get("uint48_le").unwrap(), "1");
    }

    #[test]
    fn test_inspect_float16() {
        let val = half::f16::from_f32(1.5);
        let bytes = val.to_le_bytes();
        let mut data = [0u8; 4];
        data[..2].copy_from_slice(&bytes);
        let result = inspect_at(&data, 0);
        assert_eq!(result.values.get("float16_le").unwrap(), "1.5");
    }

    #[test]
    fn test_inspect_uleb128() {
        let data = [0x80, 0x01];
        let result = inspect_at(&data, 0);
        let uleb = result.values.get("uleb128").unwrap();
        assert!(uleb.starts_with("128"));
    }

    #[test]
    fn test_inspect_sleb128() {
        let data = [0x7F];
        let result = inspect_at(&data, 0);
        let sleb = result.values.get("sleb128").unwrap();
        assert!(sleb.starts_with("-1"));
    }

    #[test]
    fn test_inspect_rgb565() {
        let data = [0x00, 0xF8, 0x00, 0x00];
        let result = inspect_at(&data, 0);
        // le_val 0xF800 -> R=31,G=0,B=0 scaled to 8-bit -> pure red.
        assert_eq!(result.values.get("rgb565").unwrap(), "R:255 G:0 B:0");
    }

    #[test]
    fn test_inspect_rgba8() {
        let data = [0xFF, 0x00, 0x80, 0xC0];
        let result = inspect_at(&data, 0);
        assert_eq!(result.values.get("rgba8").unwrap(), "#FF0080C0");
    }

    #[test]
    fn test_inspect_ipv4() {
        let data = [192, 168, 1, 1];
        let result = inspect_at(&data, 0);
        assert_eq!(result.values.get("ipv4").unwrap(), "192.168.1.1");
    }

    #[test]
    fn test_inspect_guid() {
        let data = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let result = inspect_at(&data, 0);
        let guid = result.values.get("guid").unwrap();
        assert_eq!(guid, "04030201-0605-0807-090a-0b0c0d0e0f10");
    }

    #[test]
    fn test_inspect_ipv6() {
        let data = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let result = inspect_at(&data, 0);
        let ipv6 = result.values.get("ipv6").unwrap();
        assert_eq!(ipv6, "2001:db8:0:0:0:0:0:1");
    }

    #[test]
    fn test_inspect_wide_string() {
        let text = "Hi";
        let encoded: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut data = encoded;
        data.push(0);
        data.push(0);
        let result = inspect_at(&data, 0);
        assert_eq!(result.values.get("wide_string").unwrap(), "Hi");
    }

    #[test]
    fn test_to_map_returns_values_reference() {
        let result = inspect_at(&[0x41u8], 0);
        let map = result.to_map();
        assert_eq!(map.get("uint8").map(String::as_str), Some("65"));
        assert_eq!(map.len(), result.values.len());
    }

    #[test]
    fn test_is_leap_year_century_and_400_rules() {
        assert!(is_leap_year(2000)); // divisible by 400
        assert!(!is_leap_year(1900)); // divisible by 100, not 400
        assert!(is_leap_year(2004)); // divisible by 4, not 100
        assert!(!is_leap_year(2001)); // not divisible by 4
    }

    #[test]
    fn test_decode_uleb128_overflow_returns_none() {
        // 10 continuation bytes push shift past 63 with no terminator.
        assert!(decode_uleb128(&[0x80; 10], 0).is_none());
    }

    #[test]
    fn test_decode_sleb128_overflow_returns_none() {
        assert!(decode_sleb128(&[0x80; 10], 0).is_none());
    }

    #[test]
    fn test_sign_extend_48_negative() {
        // Bit 47 set -> value is sign-extended negative.
        assert_eq!(sign_extend_48(0x0000_8000_0000_0000), -140_737_488_355_328);
        assert_eq!(sign_extend_48(1), 1);
    }

    #[test]
    fn test_inspect_filetime_valid() {
        // FILETIME for 2024-01-01 00:00:00 UTC.
        let filetime: u64 = 133_485_408_000_000_000;
        let data = filetime.to_le_bytes();
        let result = inspect_at(&data, 0);
        assert!(result.values.get("filetime").unwrap().starts_with("2024-01-01"));
    }

    #[test]
    fn test_inspect_unix_timestamp_disabled_for_out_of_range() {
        // Zero -> not > 0, so no unix_timestamp key.
        let result0 = inspect_at(&0u32.to_le_bytes(), 0);
        assert!(!result0.values.contains_key("unix_timestamp"));
        // Far future -> >= 4_102_444_800, also skipped.
        let result_max = inspect_at(&u32::MAX.to_le_bytes(), 0);
        assert!(!result_max.values.contains_key("unix_timestamp"));
    }

    #[test]
    fn test_inspect_float16_infinity_skipped() {
        // f16 +inf little-endian bytes.
        let data = half::f16::INFINITY.to_le_bytes();
        let result = inspect_at(&data, 0);
        assert!(!result.values.contains_key("float16_le"));
    }

    #[test]
    fn test_inspect_float32_infinity_skipped() {
        let data = f32::INFINITY.to_le_bytes();
        let result = inspect_at(&data, 0);
        assert!(!result.values.contains_key("float32_le"));
    }

    #[test]
    fn test_inspect_float64_infinity_skipped() {
        let data = f64::INFINITY.to_le_bytes();
        let result = inspect_at(&data, 0);
        assert!(!result.values.contains_key("float64_le"));
    }

    #[test]
    fn test_inspect_dos_date_valid_and_invalid() {
        // 0x50CF encodes 2020-06-15 (valid date) and 10:06:30 (valid time).
        let result = inspect_at(&0x50CFu16.to_le_bytes(), 0);
        assert_eq!(result.values.get("dos_date").unwrap(), "2020-06-15");
        // 0xFFFF: hour 31 and month 15 -> both invalid, neither key present.
        let bad = inspect_at(&0xFFFFu16.to_le_bytes(), 0);
        assert!(!bad.values.contains_key("dos_time"));
        assert!(!bad.values.contains_key("dos_date"));
    }

    #[test]
    fn test_inspect_wide_string_empty_first_unit() {
        let result = inspect_at(&[0x00, 0x00, 0x00, 0x00], 0);
        assert!(!result.values.contains_key("wide_string"));
    }

    #[test]
    fn test_inspect_wide_string_caps_at_32_chars() {
        let data: Vec<u8> = std::iter::repeat_n([0x41u8, 0x00], 40).flatten().collect();
        let result = inspect_at(&data, 0);
        assert_eq!(result.values.get("wide_string").unwrap(), &"A".repeat(32));
    }

    #[test]
    fn test_inspect_wide_string_invalid_utf16_skipped() {
        // Lone high surrogate 0xD800 then terminator.
        let result = inspect_at(&[0x00, 0xD8, 0x00, 0x00], 0);
        assert!(!result.values.contains_key("wide_string"));
    }

    #[test]
    fn test_inspect_wide_string_control_char_skipped() {
        // "A" then U+0001 control char.
        let result = inspect_at(&[0x41, 0x00, 0x01, 0x00, 0x00, 0x00], 0);
        assert!(!result.values.contains_key("wide_string"));
    }

    #[test]
    fn test_inspect_8bit_space_char() {
        let result = inspect_at(&[0x20u8], 0);
        assert_eq!(result.values.get("ascii_char").unwrap(), " ");
    }

    #[test]
    fn test_inspect_8bit_multibyte_utf8_char() {
        // UTF-8 encoding of 'é' (U+00E9).
        let result = inspect_at(&[0xC3, 0xA9], 0);
        assert_eq!(result.values.get("utf8_char").unwrap(), "é");
    }
}
