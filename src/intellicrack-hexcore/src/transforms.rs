use std::collections::HashMap;
use std::io::{Read, Write};

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TransformError {
    #[error("unknown transform: {0}")]
    UnknownTransform(String),
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
    #[error("transform failed: {0}")]
    Failed(String),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TransformInfo {
    pub name: String,
    pub category: String,
    pub description: String,
}

fn get_param<'a>(params: &'a HashMap<String, Vec<u8>>, key: &str) -> Result<&'a [u8], TransformError> {
    params
        .get(key)
        .map(|v| v.as_slice())
        .ok_or_else(|| TransformError::InvalidParameter(format!("missing parameter: {}", key)))
}

fn get_param_u8(params: &HashMap<String, Vec<u8>>, key: &str) -> Result<u8, TransformError> {
    let bytes = get_param(params, key)?;
    if bytes.is_empty() {
        return Err(TransformError::InvalidParameter(format!("{} must not be empty", key)));
    }
    Ok(bytes[0])
}

pub fn apply_transform(
    name: &str,
    data: &[u8],
    params: &HashMap<String, Vec<u8>>,
) -> Result<Vec<u8>, TransformError> {
    match name {
        "xor_single" => {
            let key = get_param_u8(params, "key")?;
            Ok(data.iter().map(|b| b ^ key).collect())
        }
        "xor_repeating" => {
            let key = get_param(params, "key")?;
            if key.is_empty() {
                return Err(TransformError::InvalidParameter("key must not be empty".to_string()));
            }
            Ok(data.iter().enumerate().map(|(i, b)| b ^ key[i % key.len()]).collect())
        }
        "xor_rolling" => {
            let key_start = get_param_u8(params, "key")?;
            let increment = params
                .get("increment")
                .and_then(|v| v.first().copied())
                .unwrap_or(1);
            let mut result = Vec::with_capacity(data.len());
            let mut current_key = key_start;
            for &b in data {
                result.push(b ^ current_key);
                current_key = current_key.wrapping_add(increment);
            }
            Ok(result)
        }
        "rot_n" => {
            let shift = get_param_u8(params, "shift")? % 26;
            Ok(data
                .iter()
                .map(|&b| {
                    if b.is_ascii_lowercase() {
                        b"abcdefghijklmnopqrstuvwxyz"[((b - b'a') + shift) as usize % 26]
                    } else if b.is_ascii_uppercase() {
                        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"[((b - b'A') + shift) as usize % 26]
                    } else {
                        b
                    }
                })
                .collect())
        }
        "aes_ecb_decrypt" => {
            let key = get_param(params, "key")?;
            aes_ecb_process(data, key, false)
        }
        "aes_ecb_encrypt" => {
            let key = get_param(params, "key")?;
            aes_ecb_process(data, key, true)
        }
        "base64_encode" => {
            use base64::Engine;
            Ok(base64::engine::general_purpose::STANDARD.encode(data).into_bytes())
        }
        "base64_decode" => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(data)
                .map_err(|e| TransformError::Failed(format!("base64 decode: {}", e)))
        }
        "zlib_inflate" => {
            let mut decoder = flate2::read::ZlibDecoder::new(data);
            let mut output = Vec::new();
            decoder
                .read_to_end(&mut output)
                .map_err(|e| TransformError::Failed(format!("zlib inflate: {}", e)))?;
            Ok(output)
        }
        "zlib_deflate" => {
            let mut encoder =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            encoder
                .write_all(data)
                .map_err(|e| TransformError::Failed(format!("zlib deflate: {}", e)))?;
            encoder
                .finish()
                .map_err(|e| TransformError::Failed(format!("zlib deflate finish: {}", e)))
        }
        "bit_shift_left" => {
            let count = get_param_u8(params, "count")?.min(7);
            Ok(data.iter().map(|b| b << count).collect())
        }
        "bit_shift_right" => {
            let count = get_param_u8(params, "count")?.min(7);
            Ok(data.iter().map(|b| b >> count).collect())
        }
        "bit_rotate_left" => {
            let count = get_param_u8(params, "count")? % 8;
            Ok(data.iter().map(|b| b.rotate_left(u32::from(count))).collect())
        }
        "bit_rotate_right" => {
            let count = get_param_u8(params, "count")? % 8;
            Ok(data.iter().map(|b| b.rotate_right(u32::from(count))).collect())
        }
        "bit_invert" => Ok(data.iter().map(|b| !b).collect()),
        "byte_reverse" => {
            let mut result = data.to_vec();
            result.reverse();
            Ok(result)
        }
        "byte_swap_16" => {
            let mut result = data.to_vec();
            for chunk in result.chunks_exact_mut(2) {
                chunk.swap(0, 1);
            }
            Ok(result)
        }
        "byte_swap_32" => {
            let mut result = data.to_vec();
            for chunk in result.chunks_exact_mut(4) {
                chunk.reverse();
            }
            Ok(result)
        }
        "byte_swap_64" => {
            let mut result = data.to_vec();
            for chunk in result.chunks_exact_mut(8) {
                chunk.reverse();
            }
            Ok(result)
        }
        "remove_nulls" => Ok(data.iter().copied().filter(|&b| b != 0).collect()),
        "mask_and" => {
            let pattern = get_param(params, "pattern")?;
            if pattern.is_empty() {
                return Err(TransformError::InvalidParameter("pattern must not be empty".to_string()));
            }
            Ok(data
                .iter()
                .enumerate()
                .map(|(i, b)| b & pattern[i % pattern.len()])
                .collect())
        }
        "mask_or" => {
            let pattern = get_param(params, "pattern")?;
            if pattern.is_empty() {
                return Err(TransformError::InvalidParameter("pattern must not be empty".to_string()));
            }
            Ok(data
                .iter()
                .enumerate()
                .map(|(i, b)| b | pattern[i % pattern.len()])
                .collect())
        }
        "mask_xor" => {
            let pattern = get_param(params, "pattern")?;
            if pattern.is_empty() {
                return Err(TransformError::InvalidParameter("pattern must not be empty".to_string()));
            }
            Ok(data
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ pattern[i % pattern.len()])
                .collect())
        }
        other => Err(TransformError::UnknownTransform(other.to_string())),
    }
}

fn aes_ecb_process(data: &[u8], key: &[u8], encrypt: bool) -> Result<Vec<u8>, TransformError> {
    let padded = if data.len() % 16 != 0 {
        if encrypt {
            return Err(TransformError::InvalidParameter(
                "data length must be multiple of 16 for AES encrypt".to_string(),
            ));
        }
        let mut p = data.to_vec();
        p.resize(((data.len() + 15) / 16) * 16, 0);
        p
    } else {
        data.to_vec()
    };

    let mut result = padded;

    match key.len() {
        16 => {
            let cipher = aes::Aes128::new(GenericArray::from_slice(key));
            for chunk in result.chunks_exact_mut(16) {
                let block = GenericArray::from_mut_slice(chunk);
                if encrypt {
                    cipher.encrypt_block(block);
                } else {
                    cipher.decrypt_block(block);
                }
            }
        }
        24 => {
            let cipher = aes::Aes192::new(GenericArray::from_slice(key));
            for chunk in result.chunks_exact_mut(16) {
                let block = GenericArray::from_mut_slice(chunk);
                if encrypt {
                    cipher.encrypt_block(block);
                } else {
                    cipher.decrypt_block(block);
                }
            }
        }
        32 => {
            let cipher = aes::Aes256::new(GenericArray::from_slice(key));
            for chunk in result.chunks_exact_mut(16) {
                let block = GenericArray::from_mut_slice(chunk);
                if encrypt {
                    cipher.encrypt_block(block);
                } else {
                    cipher.decrypt_block(block);
                }
            }
        }
        _ => {
            return Err(TransformError::InvalidParameter(
                "AES key must be 16, 24, or 32 bytes".to_string(),
            ));
        }
    }

    Ok(result)
}

pub fn list_transforms() -> Vec<TransformInfo> {
    vec![
        TransformInfo { name: "xor_single".into(), category: "xor".into(), description: "XOR with single byte key".into() },
        TransformInfo { name: "xor_repeating".into(), category: "xor".into(), description: "XOR with repeating multi-byte key".into() },
        TransformInfo { name: "xor_rolling".into(), category: "xor".into(), description: "XOR with incrementing key".into() },
        TransformInfo { name: "rot_n".into(), category: "cipher".into(), description: "Caesar/ROT-N cipher on ASCII letters".into() },
        TransformInfo { name: "aes_ecb_decrypt".into(), category: "cipher".into(), description: "AES ECB mode decryption".into() },
        TransformInfo { name: "aes_ecb_encrypt".into(), category: "cipher".into(), description: "AES ECB mode encryption".into() },
        TransformInfo { name: "base64_encode".into(), category: "encoding".into(), description: "Base64 encode".into() },
        TransformInfo { name: "base64_decode".into(), category: "encoding".into(), description: "Base64 decode".into() },
        TransformInfo { name: "zlib_inflate".into(), category: "compression".into(), description: "Decompress zlib/deflate data".into() },
        TransformInfo { name: "zlib_deflate".into(), category: "compression".into(), description: "Compress with zlib/deflate".into() },
        TransformInfo { name: "bit_shift_left".into(), category: "bitops".into(), description: "Shift each byte left by N bits".into() },
        TransformInfo { name: "bit_shift_right".into(), category: "bitops".into(), description: "Shift each byte right by N bits".into() },
        TransformInfo { name: "bit_rotate_left".into(), category: "bitops".into(), description: "Rotate each byte left by N bits".into() },
        TransformInfo { name: "bit_rotate_right".into(), category: "bitops".into(), description: "Rotate each byte right by N bits".into() },
        TransformInfo { name: "bit_invert".into(), category: "bitops".into(), description: "Bitwise NOT each byte".into() },
        TransformInfo { name: "byte_reverse".into(), category: "byteops".into(), description: "Reverse byte order".into() },
        TransformInfo { name: "byte_swap_16".into(), category: "byteops".into(), description: "Swap endianness of 16-bit words".into() },
        TransformInfo { name: "byte_swap_32".into(), category: "byteops".into(), description: "Swap endianness of 32-bit words".into() },
        TransformInfo { name: "byte_swap_64".into(), category: "byteops".into(), description: "Swap endianness of 64-bit words".into() },
        TransformInfo { name: "remove_nulls".into(), category: "byteops".into(), description: "Remove all null bytes".into() },
        TransformInfo { name: "mask_and".into(), category: "mask".into(), description: "AND each byte with repeating pattern".into() },
        TransformInfo { name: "mask_or".into(), category: "mask".into(), description: "OR each byte with repeating pattern".into() },
        TransformInfo { name: "mask_xor".into(), category: "mask".into(), description: "XOR each byte with repeating pattern".into() },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_params(entries: &[(&str, &[u8])]) -> HashMap<String, Vec<u8>> {
        entries.iter().map(|(k, v)| (k.to_string(), v.to_vec())).collect()
    }

    #[test]
    fn test_xor_single_roundtrip() {
        let data = b"Hello World";
        let params = make_params(&[("key", &[0x42])]);
        let encrypted = apply_transform("xor_single", data, &params).unwrap();
        let decrypted = apply_transform("xor_single", &encrypted, &params).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_xor_repeating() {
        let data = b"AAAA";
        let params = make_params(&[("key", b"AB")]);
        let result = apply_transform("xor_repeating", data, &params).unwrap();
        assert_eq!(result, vec![0x41 ^ 0x41, 0x41 ^ 0x42, 0x41 ^ 0x41, 0x41 ^ 0x42]);
    }

    #[test]
    fn test_xor_rolling() {
        let data = b"\x00\x00\x00";
        let params = make_params(&[("key", &[0x10]), ("increment", &[0x01])]);
        let result = apply_transform("xor_rolling", data, &params).unwrap();
        assert_eq!(result, vec![0x10, 0x11, 0x12]);
    }

    #[test]
    fn test_rot13_roundtrip() {
        let data = b"Hello World";
        let params = make_params(&[("shift", &[13])]);
        let rotated = apply_transform("rot_n", data, &params).unwrap();
        let original = apply_transform("rot_n", &rotated, &params).unwrap();
        assert_eq!(original, data);
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello World!";
        let empty = HashMap::new();
        let encoded = apply_transform("base64_encode", data, &empty).unwrap();
        let decoded = apply_transform("base64_decode", &encoded, &empty).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_zlib_roundtrip() {
        let data = b"Hello World! ".repeat(100);
        let empty = HashMap::new();
        let compressed = apply_transform("zlib_deflate", &data, &empty).unwrap();
        let decompressed = apply_transform("zlib_inflate", &compressed, &empty).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_bit_invert_roundtrip() {
        let data = b"Test";
        let empty = HashMap::new();
        let inverted = apply_transform("bit_invert", data, &empty).unwrap();
        let original = apply_transform("bit_invert", &inverted, &empty).unwrap();
        assert_eq!(original, data);
    }

    #[test]
    fn test_byte_reverse_roundtrip() {
        let data = b"ABCDE";
        let empty = HashMap::new();
        let reversed = apply_transform("byte_reverse", data, &empty).unwrap();
        assert_eq!(reversed, b"EDCBA");
        let original = apply_transform("byte_reverse", &reversed, &empty).unwrap();
        assert_eq!(original, data);
    }

    #[test]
    fn test_byte_swap_16() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let empty = HashMap::new();
        let swapped = apply_transform("byte_swap_16", &data, &empty).unwrap();
        assert_eq!(swapped, vec![0x02, 0x01, 0x04, 0x03]);
    }

    #[test]
    fn test_remove_nulls() {
        let data = [0x41, 0x00, 0x42, 0x00, 0x43];
        let empty = HashMap::new();
        let result = apply_transform("remove_nulls", &data, &empty).unwrap();
        assert_eq!(result, b"ABC");
    }

    #[test]
    fn test_mask_and() {
        let data = [0xFF, 0xFF];
        let params = make_params(&[("pattern", &[0x0F])]);
        let result = apply_transform("mask_and", &data, &params).unwrap();
        assert_eq!(result, vec![0x0F, 0x0F]);
    }

    #[test]
    fn test_aes_ecb_roundtrip() {
        let key = [0u8; 16];
        let data = [0x41u8; 16];
        let encrypt_params = make_params(&[("key", &key)]);
        let encrypted = apply_transform("aes_ecb_encrypt", &data, &encrypt_params).unwrap();
        assert_ne!(encrypted, data.to_vec());
        let decrypted = apply_transform("aes_ecb_decrypt", &encrypted, &encrypt_params).unwrap();
        assert_eq!(decrypted, data.to_vec());
    }

    #[test]
    fn test_unknown_transform() {
        let empty = HashMap::new();
        assert!(apply_transform("nonexistent", &[], &empty).is_err());
    }

    #[test]
    fn test_list_transforms() {
        let transforms = list_transforms();
        assert!(transforms.len() >= 20);
    }

    #[test]
    fn test_bit_shift() {
        let data = [0b0000_0001];
        let params = make_params(&[("count", &[2])]);
        let shifted = apply_transform("bit_shift_left", &data, &params).unwrap();
        assert_eq!(shifted, vec![0b0000_0100]);
    }

    #[test]
    fn test_bit_rotate() {
        let data = [0b1000_0001];
        let params = make_params(&[("count", &[1])]);
        let rotated = apply_transform("bit_rotate_left", &data, &params).unwrap();
        assert_eq!(rotated, vec![0b0000_0011]);
    }
}
