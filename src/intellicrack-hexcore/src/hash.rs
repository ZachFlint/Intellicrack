use blake2::digest::consts::U32;
use blake2::Blake2s256;

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

/// Compute the hash digest for the given data using the specified algorithm.
///
/// # Errors
///
/// Returns `HashError::UnsupportedAlgorithm` if the algorithm name is not recognized.
pub fn compute_hash(data: &[u8], algorithm: &str) -> Result<HashResult, HashError> {
    let hex_digest = match algorithm.to_lowercase().as_str() {
        "md5" => compute_digest_hash::<Md5>(data),
        "sha1" => compute_digest_hash::<Sha1>(data),
        "sha224" | "sha-224" => compute_digest_hash::<Sha224>(data),
        "sha256" | "sha-256" => compute_digest_hash::<Sha256>(data),
        "sha384" | "sha-384" => compute_digest_hash::<Sha384>(data),
        "sha512" | "sha-512" => compute_digest_hash::<Sha512>(data),
        "sha3-256" | "sha3_256" => compute_digest_hash::<Sha3_256>(data),
        "sha3-512" | "sha3_512" => compute_digest_hash::<Sha3_512>(data),
        "blake2b" | "blake2b-256" | "blake2b256" => compute_digest_hash::<Blake2b256>(data),
        "blake2s" | "blake2s-256" | "blake2s256" => compute_digest_hash::<Blake2s256>(data),
        "xxhash32" | "xxh32" => compute_xxh32(data),
        "xxhash64" | "xxh64" => compute_xxh64(data),
        "xxh3" | "xxh3-64" => compute_xxh3(data),
        "siphash64" | "siphash-2-4" | "siphash" => compute_siphash64(data),
        "siphash128" | "siphash-2-4-128" => compute_siphash128(data),
        "adler32" => compute_adler32(data),
        "crc8" => compute_crc8(data),
        "crc16" => compute_crc16(data),
        "crc32" => compute_crc32(data),
        "crc64" | "crc64-ecma" => compute_crc64(data),
        "fnv1-32" | "fnv1_32" => format!("{:08x}", fnv1_32(data)),
        "fnv1-64" | "fnv1_64" => format!("{:016x}", fnv1_64(data)),
        "fnv1a-32" | "fnv1a_32" => format!("{:08x}", fnv1a_32(data)),
        "fnv1a-64" | "fnv1a_64" => format!("{:016x}", fnv1a_64(data)),
        other => return Err(HashError::UnsupportedAlgorithm(other.to_string())),
    };

    Ok(HashResult {
        algorithm: algorithm.to_lowercase(),
        hex_digest,
    })
}

fn compute_digest_hash<D: Digest>(data: &[u8]) -> String {
    let mut hasher = D::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hex = String::with_capacity(result.len() * 2);
    for byte in result {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn compute_xxh32(data: &[u8]) -> String {
    let hash = xxhash_rust::xxh32::xxh32(data, 0);
    format!("{hash:08x}")
}

fn compute_xxh64(data: &[u8]) -> String {
    let hash = xxhash_rust::xxh64::xxh64(data, 0);
    format!("{hash:016x}")
}

fn compute_xxh3(data: &[u8]) -> String {
    let hash = xxhash_rust::xxh3::xxh3_64(data);
    format!("{hash:016x}")
}

fn compute_siphash64(data: &[u8]) -> String {
    use std::hash::Hasher;
    let mut hasher = siphasher::sip::SipHasher24::new();
    hasher.write(data);
    let hash = hasher.finish();
    format!("{hash:016x}")
}

fn compute_siphash128(data: &[u8]) -> String {
    use std::hash::Hasher;
    let mut hasher = siphasher::sip128::SipHasher24::new();
    hasher.write(data);
    let hash = hasher.finish128();
    format!("{:016x}{:016x}", hash.h1, hash.h2)
}

fn compute_adler32(data: &[u8]) -> String {
    let hash = adler2::adler32_slice(data);
    format!("{hash:08x}")
}

fn compute_crc8(data: &[u8]) -> String {
    let crc_algo = crc::Crc::<u8>::new(&crc::CRC_8_SMBUS);
    let hash = crc_algo.checksum(data);
    format!("{hash:02x}")
}

fn compute_crc16(data: &[u8]) -> String {
    let crc_algo = crc::Crc::<u16>::new(&crc::CRC_16_IBM_SDLC);
    let hash = crc_algo.checksum(data);
    format!("{hash:04x}")
}

fn compute_crc32(data: &[u8]) -> String {
    let crc_val = crc32fast::hash(data);
    format!("{crc_val:08x}")
}

fn compute_crc64(data: &[u8]) -> String {
    let crc_algo = crc::Crc::<u64>::new(&crc::CRC_64_ECMA_182);
    let hash = crc_algo.checksum(data);
    format!("{hash:016x}")
}

/// Compute the hash digest for a sub-range of the given data.
///
/// # Errors
///
/// Returns `HashError::InvalidRange` if the range is out of bounds, or
/// `HashError::UnsupportedAlgorithm` if the algorithm is not recognized.
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

/// Compute a CRC checksum with custom parameters.
///
/// # Errors
///
/// Returns `HashError::InvalidCrcWidth` if width is not 8, 16, 32, or 64.
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

    let table = build_crc_table(w, poly, mask);

    let mut crc = init & mask;
    for &byte in data {
        let b = if refin {
            (crc_reflect(u64::from(byte), 8) & 0xFF) as u8
        } else {
            byte
        };
        let idx = ((crc >> (w - 8)) ^ u64::from(b)) & 0xFF;
        crc = (table[idx as usize] ^ (crc << 8)) & mask;
    }
    if refout {
        crc = crc_reflect(crc, w);
    }
    crc = (crc ^ xorout) & mask;

    match width {
        8 => Ok(format!("{:02x}", (crc & 0xFF) as u8)),
        16 => Ok(format!("{:04x}", (crc & 0xFFFF) as u16)),
        32 => Ok(format!("{:08x}", (crc & 0xFFFF_FFFF) as u32)),
        64 => Ok(format!("{crc:016x}")),
        _ => unreachable!(),
    }
}

fn crc_reflect(mut val: u64, bits: u32) -> u64 {
    let mut result: u64 = 0;
    for i in 0..bits {
        if val & 1 != 0 {
            result |= 1u64 << (bits - 1 - i);
        }
        val >>= 1;
    }
    result
}

fn build_crc_table(w: u32, poly: u64, mask: u64) -> [u64; 256] {
    let mut table = [0u64; 256];
    for (idx, entry) in table.iter_mut().enumerate() {
        let mut crc_val = (idx as u64) << (w - 8);
        for _ in 0..8 {
            if crc_val & (1u64 << (w - 1)) != 0 {
                crc_val = ((crc_val << 1) ^ poly) & mask;
            } else {
                crc_val = (crc_val << 1) & mask;
            }
        }
        *entry = crc_val;
    }
    table
}

/// Result of verifying a PE file checksum.
#[derive(Debug, Clone)]
pub struct PeChecksumResult {
    /// Stored checksum value from the PE header.
    pub stored: u32,
    /// Calculated checksum value.
    pub calculated: u32,
    /// Byte offset of the checksum field in the file.
    pub offset: usize,
    /// Whether the stored and calculated values match.
    pub valid: bool,
}

/// Compute the PE file checksum using the standard Windows algorithm.
///
/// Sums all 16-bit words with carry folding, skipping the `CheckSum` field,
/// then adds the file length.
///
/// # Panics
///
/// Panics are unreachable in practice; the file length is masked to 32 bits
/// before conversion.
#[must_use]
pub fn compute_pe_checksum(data: &[u8], checksum_offset: usize) -> u32 {
    let mut checksum: u32 = 0;
    let skip_start = checksum_offset;
    let skip_end = checksum_offset + 4;

    let mut i = 0;
    while i + 1 < data.len() {
        if i >= skip_start && i < skip_end {
            i += 2;
            continue;
        }
        let word = u32::from(data[i]) | (u32::from(data[i + 1]) << 8);
        checksum += word;
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
        i += 2;
    }

    if i < data.len() && !(i >= skip_start && i < skip_end) {
        checksum += u32::from(data[i]);
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }

    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    let masked_len = data.len() & 0xFFFF_FFFF;
    checksum + u32::try_from(masked_len).expect("length masked to u32 range")
}

/// Verify the PE checksum of a binary file.
///
/// Locates the `CheckSum` field in the PE Optional Header and compares
/// the stored value against the computed value.
///
/// # Errors
///
/// Returns `HashError::UnsupportedAlgorithm` if the data is not a valid
/// PE file or the checksum offset is beyond file bounds.
pub fn verify_pe_checksum(data: &[u8]) -> Result<PeChecksumResult, HashError> {
    if data.len() < 0x40 {
        return Err(HashError::UnsupportedAlgorithm(
            "file too short for PE header".to_string(),
        ));
    }
    if &data[0..2] != b"MZ" {
        return Err(HashError::UnsupportedAlgorithm(
            "not a PE file (missing MZ signature)".to_string(),
        ));
    }

    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    let checksum_offset = e_lfanew + 0x58;

    if checksum_offset + 4 > data.len() {
        return Err(HashError::UnsupportedAlgorithm(
            "PE header checksum offset beyond file bounds".to_string(),
        ));
    }

    if &data[e_lfanew..e_lfanew + 4] != b"PE\x00\x00" {
        return Err(HashError::UnsupportedAlgorithm(
            "invalid PE signature".to_string(),
        ));
    }

    let stored = u32::from_le_bytes([
        data[checksum_offset],
        data[checksum_offset + 1],
        data[checksum_offset + 2],
        data[checksum_offset + 3],
    ]);

    let calculated = compute_pe_checksum(data, checksum_offset);

    Ok(PeChecksumResult {
        stored,
        calculated,
        offset: checksum_offset,
        valid: stored == calculated,
    })
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
        assert_eq!(
            result.hex_digest,
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn test_sha1_abc() {
        let result = compute_hash(b"abc", "sha1").unwrap();
        assert_eq!(
            result.hex_digest,
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
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
        let result = compute_crc_custom(
            b"123456789",
            32,
            0x04C1_1DB7,
            0xFFFF_FFFF,
            true,
            true,
            0xFFFF_FFFF,
        )
        .unwrap();
        assert_eq!(result, "cbf43926");
    }

    #[test]
    fn test_custom_crc_invalid_width() {
        let result = compute_crc_custom(b"test", 12, 0, 0, false, false, 0);
        assert!(result.is_err());
    }
}
