use blake2::Blake2s256;
use blake2::digest::consts::U32;

type Blake2b256 = blake2::Blake2b<U32>;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_512};
use siphasher::sip128::Hasher128;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct HashResult {
    pub algorithm: String,
    pub hex_digest: String,
}

#[derive(Error, Debug)]
pub enum HashError {
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("invalid range: start={start}, end={end}, data_len={data_len}")]
    InvalidRange {
        start: usize,
        end: usize,
        data_len: usize,
    },
    #[error("invalid CRC width: {0} (must be 8, 16, 32, or 64)")]
    InvalidCrcWidth(u8),
}

fn fnv1_32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &byte in data {
        hash = hash.wrapping_mul(0x0100_0193);
        hash ^= u32::from(byte);
    }
    hash
}

fn fnv1_64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in data {
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
        hash ^= u64::from(byte);
    }
    hash
}

fn fnv1a_32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &byte in data {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

pub fn compute_hash(data: &[u8], algorithm: &str) -> Result<HashResult, HashError> {
    let hex_digest = match algorithm.to_lowercase().as_str() {
        "md5" => {
            let mut hasher = Md5::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        "sha1" => {
            let mut hasher = Sha1::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        "sha224" | "sha-224" => {
            let mut hasher = Sha224::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        "sha256" | "sha-256" => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        "sha384" | "sha-384" => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        "sha512" | "sha-512" => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        "sha3-256" | "sha3_256" => {
            let mut hasher = Sha3_256::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        "sha3-512" | "sha3_512" => {
            let mut hasher = Sha3_512::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        "blake2b" | "blake2b-256" | "blake2b256" => {
            let mut hasher = Blake2b256::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        "blake2s" | "blake2s-256" | "blake2s256" => {
            let mut hasher = Blake2s256::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        "xxhash32" | "xxh32" => {
            let hash = xxhash_rust::xxh32::xxh32(data, 0);
            format!("{:08x}", hash)
        }
        "xxhash64" | "xxh64" => {
            let hash = xxhash_rust::xxh64::xxh64(data, 0);
            format!("{:016x}", hash)
        }
        "xxh3" | "xxh3-64" => {
            let hash = xxhash_rust::xxh3::xxh3_64(data);
            format!("{:016x}", hash)
        }
        "siphash64" | "siphash-2-4" | "siphash" => {
            use std::hash::Hasher;
            let mut hasher = siphasher::sip::SipHasher24::new();
            hasher.write(data);
            let hash = hasher.finish();
            format!("{:016x}", hash)
        }
        "siphash128" | "siphash-2-4-128" => {
            use std::hash::Hasher;
            let mut hasher = siphasher::sip128::SipHasher24::new();
            hasher.write(data);
            let hash = hasher.finish128();
            format!("{:016x}{:016x}", hash.h1, hash.h2)
        }
        "adler32" => {
            let hash = adler::adler32_slice(data);
            format!("{:08x}", hash)
        }
        "crc8" => {
            let crc_algo = crc::Crc::<u8>::new(&crc::CRC_8_SMBUS);
            let hash = crc_algo.checksum(data);
            format!("{:02x}", hash)
        }
        "crc16" => {
            let crc_algo = crc::Crc::<u16>::new(&crc::CRC_16_IBM_SDLC);
            let hash = crc_algo.checksum(data);
            format!("{:04x}", hash)
        }
        "crc32" => {
            let crc = crc32fast::hash(data);
            format!("{:08x}", crc)
        }
        "crc64" | "crc64-ecma" => {
            let crc_algo = crc::Crc::<u64>::new(&crc::CRC_64_ECMA_182);
            let hash = crc_algo.checksum(data);
            format!("{:016x}", hash)
        }
        "fnv1-32" | "fnv1_32" => {
            format!("{:08x}", fnv1_32(data))
        }
        "fnv1-64" | "fnv1_64" => {
            format!("{:016x}", fnv1_64(data))
        }
        "fnv1a-32" | "fnv1a_32" => {
            format!("{:08x}", fnv1a_32(data))
        }
        "fnv1a-64" | "fnv1a_64" => {
            format!("{:016x}", fnv1a_64(data))
        }
        other => return Err(HashError::UnsupportedAlgorithm(other.to_string())),
    };

    Ok(HashResult {
        algorithm: algorithm.to_lowercase(),
        hex_digest,
    })
}

pub fn compute_hash_range(
    data: &[u8],
    start: usize,
    end: usize,
    algorithm: &str,
) -> Result<HashResult, HashError> {
    if start > end || end > data.len() {
        return Err(HashError::InvalidRange {
            start,
            end,
            data_len: data.len(),
        });
    }
    compute_hash(&data[start..end], algorithm)
}

pub fn compute_crc_custom(
    data: &[u8],
    width: u8,
    poly: u64,
    init: u64,
    refin: bool,
    refout: bool,
    xorout: u64,
) -> Result<String, HashError> {
    if !matches!(width, 8 | 16 | 32 | 64) {
        return Err(HashError::InvalidCrcWidth(width));
    }

    let w = u32::from(width);
    let mask: u64 = if w >= 64 { u64::MAX } else { (1u64 << w) - 1 };

    fn reflect(mut val: u64, bits: u32) -> u64 {
        let mut result: u64 = 0;
        for i in 0..bits {
            if val & 1 != 0 {
                result |= 1u64 << (bits - 1 - i);
            }
            val >>= 1;
        }
        result
    }

    let mut table = [0u64; 256];
    for i in 0u64..256 {
        let mut crc_val = i << (w - 8);
        for _ in 0..8 {
            if crc_val & (1u64 << (w - 1)) != 0 {
                crc_val = ((crc_val << 1) ^ poly) & mask;
            } else {
                crc_val = (crc_val << 1) & mask;
            }
        }
        table[i as usize] = crc_val;
    }

    let mut crc = init & mask;
    for &byte in data {
        let b = if refin {
            reflect(u64::from(byte), 8) as u8
        } else {
            byte
        };
        let idx = ((crc >> (w - 8)) ^ u64::from(b)) as u8;
        crc = (table[idx as usize] ^ (crc << 8)) & mask;
    }
    if refout {
        crc = reflect(crc, w);
    }
    crc = (crc ^ xorout) & mask;

    match width {
        8 => Ok(format!("{:02x}", crc as u8)),
        16 => Ok(format!("{:04x}", crc as u16)),
        32 => Ok(format!("{:08x}", crc as u32)),
        64 => Ok(format!("{:016x}", crc)),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_empty() {
        let result = compute_hash(b"", "md5").unwrap();
        assert_eq!(result.hex_digest, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_md5_abc() {
        let result = compute_hash(b"abc", "md5").unwrap();
        assert_eq!(result.hex_digest, "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn test_sha1_empty() {
        let result = compute_hash(b"", "sha1").unwrap();
        assert_eq!(result.hex_digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn test_sha1_abc() {
        let result = compute_hash(b"abc", "sha1").unwrap();
        assert_eq!(result.hex_digest, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn test_sha224_abc() {
        let result = compute_hash(b"abc", "sha224").unwrap();
        assert_eq!(
            result.hex_digest,
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
    }

    #[test]
    fn test_sha256_empty() {
        let result = compute_hash(b"", "sha256").unwrap();
        assert_eq!(
            result.hex_digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_abc() {
        let result = compute_hash(b"abc", "sha256").unwrap();
        assert_eq!(
            result.hex_digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha384_abc() {
        let result = compute_hash(b"abc", "sha384").unwrap();
        assert!(result.hex_digest.starts_with("cb00753f45a35e8b"));
    }

    #[test]
    fn test_sha512_abc() {
        let result = compute_hash(b"abc", "sha512").unwrap();
        assert!(result.hex_digest.starts_with("ddaf35a193617aba"));
    }

    #[test]
    fn test_sha3_256_empty() {
        let result = compute_hash(b"", "sha3-256").unwrap();
        assert_eq!(
            result.hex_digest,
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    #[test]
    fn test_sha3_512_empty() {
        let result = compute_hash(b"", "sha3-512").unwrap();
        assert!(result.hex_digest.starts_with("a69f73cca23a9ac5"));
    }

    #[test]
    fn test_blake2b_empty() {
        let result = compute_hash(b"", "blake2b").unwrap();
        assert_eq!(result.hex_digest.len(), 64);
    }

    #[test]
    fn test_blake2s_empty() {
        let result = compute_hash(b"", "blake2s").unwrap();
        assert_eq!(result.hex_digest.len(), 64);
    }

    #[test]
    fn test_xxhash32() {
        let result = compute_hash(b"", "xxhash32").unwrap();
        assert_eq!(result.hex_digest, "02cc5d05");
    }

    #[test]
    fn test_xxhash64() {
        let result = compute_hash(b"", "xxhash64").unwrap();
        assert_eq!(result.hex_digest, "ef46db3751d8e999");
    }

    #[test]
    fn test_xxh3() {
        let result = compute_hash(b"test", "xxh3").unwrap();
        assert_eq!(result.hex_digest.len(), 16);
    }

    #[test]
    fn test_siphash64() {
        let result = compute_hash(b"test", "siphash64").unwrap();
        assert_eq!(result.hex_digest.len(), 16);
    }

    #[test]
    fn test_siphash128() {
        let result = compute_hash(b"test", "siphash128").unwrap();
        assert_eq!(result.hex_digest.len(), 32);
    }

    #[test]
    fn test_adler32() {
        let result = compute_hash(b"", "adler32").unwrap();
        assert_eq!(result.hex_digest, "00000001");
    }

    #[test]
    fn test_crc8() {
        let result = compute_hash(b"123456789", "crc8").unwrap();
        assert_eq!(result.hex_digest.len(), 2);
    }

    #[test]
    fn test_crc16() {
        let result = compute_hash(b"123456789", "crc16").unwrap();
        assert_eq!(result.hex_digest.len(), 4);
    }

    #[test]
    fn test_crc32_empty() {
        let result = compute_hash(b"", "crc32").unwrap();
        assert_eq!(result.hex_digest, "00000000");
    }

    #[test]
    fn test_crc32_known() {
        let result = compute_hash(b"123456789", "crc32").unwrap();
        assert_eq!(result.hex_digest, "cbf43926");
    }

    #[test]
    fn test_crc64() {
        let result = compute_hash(b"123456789", "crc64").unwrap();
        assert_eq!(result.hex_digest.len(), 16);
    }

    #[test]
    fn test_fnv1_32() {
        let result = compute_hash(b"", "fnv1-32").unwrap();
        assert_eq!(result.hex_digest, "811c9dc5");
    }

    #[test]
    fn test_fnv1_64() {
        let result = compute_hash(b"", "fnv1-64").unwrap();
        assert_eq!(result.hex_digest, "cbf29ce484222325");
    }

    #[test]
    fn test_fnv1a_32() {
        let result = compute_hash(b"", "fnv1a-32").unwrap();
        assert_eq!(result.hex_digest, "811c9dc5");
    }

    #[test]
    fn test_fnv1a_64() {
        let result = compute_hash(b"", "fnv1a-64").unwrap();
        assert_eq!(result.hex_digest, "cbf29ce484222325");
    }

    #[test]
    fn test_unsupported_algorithm() {
        let result = compute_hash(b"test", "nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_hash_range() {
        let data = b"Hello World";
        let full = compute_hash(b"World", "sha256").unwrap();
        let range = compute_hash_range(data, 6, 11, "sha256").unwrap();
        assert_eq!(full.hex_digest, range.hex_digest);
    }

    #[test]
    fn test_hash_range_invalid() {
        let result = compute_hash_range(b"ABC", 2, 5, "md5");
        assert!(result.is_err());
    }

    #[test]
    fn test_algorithm_case_insensitive() {
        let r1 = compute_hash(b"test", "SHA256").unwrap();
        let r2 = compute_hash(b"test", "sha256").unwrap();
        assert_eq!(r1.hex_digest, r2.hex_digest);
    }

    #[test]
    fn test_custom_crc32() {
        let result = compute_crc_custom(b"123456789", 32, 0x04C11DB7, 0xFFFFFFFF, true, true, 0xFFFFFFFF).unwrap();
        assert_eq!(result, "cbf43926");
    }

    #[test]
    fn test_custom_crc_invalid_width() {
        let result = compute_crc_custom(b"test", 12, 0, 0, false, false, 0);
        assert!(result.is_err());
    }
}
