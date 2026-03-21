use std::collections::HashMap;

pub struct DataInspection {
    pub values: HashMap<String, String>,
}

impl DataInspection {
    pub fn to_map(&self) -> &HashMap<String, String> {
        &self.values
    }
}

fn read_u24_le(data: &[u8], offset: usize) -> u32 {
    u32::from(data[offset]) | (u32::from(data[offset + 1]) << 8) | (u32::from(data[offset + 2]) << 16)
}

fn read_u24_be(data: &[u8], offset: usize) -> u32 {
    (u32::from(data[offset]) << 16) | (u32::from(data[offset + 1]) << 8) | u32::from(data[offset + 2])
}

fn sign_extend_24(val: u32) -> i32 {
    if val & 0x80_0000 != 0 {
        (val | 0xFF00_0000) as i32
    } else {
        val as i32
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
        (val | 0xFFFF_0000_0000_0000) as i64
    } else {
        val as i64
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

    let byte = data[offset];
    values.insert("int8".to_string(), format!("{}", byte as i8));
    values.insert("uint8".to_string(), format!("{}", byte));

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
            values.insert("uleb128".to_string(), format!("{} ({} bytes)", val, count));
        }
        if let Some((val, count)) = decode_sleb128(data, offset) {
            values.insert("sleb128".to_string(), format!("{} ({} bytes)", val, count));
        }
    }

    if remaining >= 2 {
        let b = [data[offset], data[offset + 1]];
        let u16_le = u16::from_le_bytes(b);
        let u16_be = u16::from_be_bytes(b);
        values.insert("int16_le".to_string(), format!("{}", u16_le as i16));
        values.insert("int16_be".to_string(), format!("{}", u16_be as i16));
        values.insert("uint16_le".to_string(), format!("{}", u16_le));
        values.insert("uint16_be".to_string(), format!("{}", u16_be));

        let f16_le = half::f16::from_le_bytes(b);
        let f16_be = half::f16::from_be_bytes(b);
        if f16_le.is_finite() {
            values.insert("float16_le".to_string(), format!("{}", f16_le));
        }
        if f16_be.is_finite() {
            values.insert("float16_be".to_string(), format!("{}", f16_be));
        }

        let r = ((u16_le >> 11) & 0x1F) as u8;
        let g = ((u16_le >> 5) & 0x3F) as u8;
        let b_val = (u16_le & 0x1F) as u8;
        let r8 = (u32::from(r) * 255 / 31) as u8;
        let g8 = (u32::from(g) * 255 / 63) as u8;
        let b8 = (u32::from(b_val) * 255 / 31) as u8;
        values.insert("rgb565".to_string(), format!("R:{} G:{} B:{}", r8, g8, b8));

        let time_bits = u16_le;
        let hour = (time_bits >> 11) & 0x1F;
        let minute = (time_bits >> 5) & 0x3F;
        let second = (time_bits & 0x1F) * 2;
        if hour < 24 && minute < 60 && second < 60 {
            values.insert(
                "dos_time".to_string(),
                format!("{:02}:{:02}:{:02}", hour, minute, second),
            );
        }

        let date_bits = u16_le;
        let year = ((date_bits >> 9) & 0x7F) as u32 + 1980;
        let month = (date_bits >> 5) & 0x0F;
        let day = date_bits & 0x1F;
        if month >= 1 && month <= 12 && day >= 1 && day <= 31 && year <= 2107 {
            values.insert(
                "dos_date".to_string(),
                format!("{:04}-{:02}-{:02}", year, month, day),
            );
        }
    }

    if remaining >= 3 {
        let u24_le = read_u24_le(data, offset);
        let u24_be = read_u24_be(data, offset);
        values.insert("uint24_le".to_string(), format!("{}", u24_le));
        values.insert("uint24_be".to_string(), format!("{}", u24_be));
        values.insert("int24_le".to_string(), format!("{}", sign_extend_24(u24_le)));
        values.insert("int24_be".to_string(), format!("{}", sign_extend_24(u24_be)));
    }

    if remaining >= 4 {
        let b = [
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ];
        let u32_le = u32::from_le_bytes(b);
        let u32_be = u32::from_be_bytes(b);
        values.insert("int32_le".to_string(), format!("{}", u32_le as i32));
        values.insert("int32_be".to_string(), format!("{}", u32_be as i32));
        values.insert("uint32_le".to_string(), format!("{}", u32_le));
        values.insert("uint32_be".to_string(), format!("{}", u32_be));

        let f32_le = f32::from_le_bytes(b);
        let f32_be = f32::from_be_bytes(b);
        if f32_le.is_finite() {
            values.insert("float32_le".to_string(), format!("{}", f32_le));
        }
        if f32_be.is_finite() {
            values.insert("float32_be".to_string(), format!("{}", f32_be));
        }

        values.insert(
            "rgba8".to_string(),
            format!("#{:02X}{:02X}{:02X}{:02X}", b[0], b[1], b[2], b[3]),
        );

        values.insert(
            "ipv4".to_string(),
            format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
        );

        let timestamp = u32_le as i64;
        if timestamp > 0 && timestamp < 4102444800 {
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
                    "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                    y,
                    m + 1,
                    remaining_days + 1,
                    hours,
                    minutes,
                    seconds
                ),
            );
        }
    }

    if remaining >= 6 {
        let u48_le = read_u48_le(data, offset);
        let u48_be = read_u48_be(data, offset);
        values.insert("uint48_le".to_string(), format!("{}", u48_le));
        values.insert("uint48_be".to_string(), format!("{}", u48_be));
        values.insert("int48_le".to_string(), format!("{}", sign_extend_48(u48_le)));
        values.insert("int48_be".to_string(), format!("{}", sign_extend_48(u48_be)));
    }

    if remaining >= 8 {
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
        let u64_le = u64::from_le_bytes(b);
        let u64_be = u64::from_be_bytes(b);
        values.insert("int64_le".to_string(), format!("{}", u64_le as i64));
        values.insert("int64_be".to_string(), format!("{}", u64_be as i64));
        values.insert("uint64_le".to_string(), format!("{}", u64_le));
        values.insert("uint64_be".to_string(), format!("{}", u64_be));

        let f64_le = f64::from_le_bytes(b);
        let f64_be = f64::from_be_bytes(b);
        if f64_le.is_finite() {
            values.insert("float64_le".to_string(), format!("{}", f64_le));
        }
        if f64_be.is_finite() {
            values.insert("float64_be".to_string(), format!("{}", f64_be));
        }

        let filetime = u64_le;
        if filetime > 116_444_736_000_000_000 && filetime < 200_000_000_000_000_000 {
            let unix_100ns = filetime - 116_444_736_000_000_000;
            let unix_secs = (unix_100ns / 10_000_000) as i64;

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
                    "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                    y,
                    m + 1,
                    rd + 1,
                    hours,
                    minutes,
                    seconds
                ),
            );
        }
    }

    if remaining >= 16 {
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
                segments[0], segments[1], segments[2], segments[3],
                segments[4], segments[5], segments[6], segments[7]
            ),
        );
    }

    if remaining >= 2 {
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

    DataInspection { values }
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
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
        let val: f32 = 3.14;
        let bytes = val.to_le_bytes();
        let mut data = [0u8; 8];
        data[..4].copy_from_slice(&bytes);
        let result = inspect_at(&data, 0);
        let f_str = result.values.get("float32_le").unwrap();
        let parsed: f32 = f_str.parse().unwrap();
        assert!((parsed - 3.14).abs() < 0.001);
    }

    #[test]
    fn test_inspect_unix_timestamp() {
        let ts: u32 = 1704067200;
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
        assert!(result.values.contains_key("float16_le"));
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
        assert!(result.values.contains_key("rgb565"));
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
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06,
            0x07, 0x08,
            0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        let result = inspect_at(&data, 0);
        let guid = result.values.get("guid").unwrap();
        assert_eq!(guid, "04030201-0605-0807-090a-0b0c0d0e0f10");
    }

    #[test]
    fn test_inspect_ipv6() {
        let data = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let result = inspect_at(&data, 0);
        let ipv6 = result.values.get("ipv6").unwrap();
        assert_eq!(ipv6, "2001:db8:0:0:0:0:0:1");
    }

    #[test]
    fn test_inspect_wide_string() {
        let text = "Hi";
        let encoded: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let mut data = Vec::from(encoded);
        data.push(0);
        data.push(0);
        let result = inspect_at(&data, 0);
        assert_eq!(result.values.get("wide_string").unwrap(), "Hi");
    }
}
