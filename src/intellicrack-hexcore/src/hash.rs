use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
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
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        "sha512" => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        "crc32" => {
            let crc = crc32fast::hash(data);
            format!("{:08x}", crc)
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
    fn test_sha512_abc() {
        let result = compute_hash(b"abc", "sha512").unwrap();
        assert!(result.hex_digest.starts_with("ddaf35a193617aba"));
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
    fn test_unsupported_algorithm() {
        let result = compute_hash(b"test", "blake2");
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
}
