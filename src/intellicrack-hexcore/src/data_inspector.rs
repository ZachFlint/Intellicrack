use std::collections::HashMap;

pub struct DataInspection {
    pub values: HashMap<String, String>,
}

impl DataInspection {
    pub fn to_map(&self) -> &HashMap<String, String> {
        &self.values
    }
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

    if remaining >= 2 {
        let b = [data[offset], data[offset + 1]];
        let u16_le = u16::from_le_bytes(b);
        let u16_be = u16::from_be_bytes(b);
        values.insert("int16_le".to_string(), format!("{}", u16_le as i16));
        values.insert("int16_be".to_string(), format!("{}", u16_be as i16));
        values.insert("uint16_le".to_string(), format!("{}", u16_le));
        values.insert("uint16_be".to_string(), format!("{}", u16_be));

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
}
