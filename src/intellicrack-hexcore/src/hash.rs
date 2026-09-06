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

const FNV32_INIT: u32 = 0x811c_9dc5;
const FNV64_INIT: u64 = 0xcbf2_9ce4_8422_2325;
const FNV32_PRIME: u32 = 0x0100_0193;
const FNV64_PRIME: u64 = 0x0000_0100_0000_01B3;

static CRC8_ALGO: crc::Crc<u8> = crc::Crc::<u8>::new(&crc::CRC_8_SMBUS);
static CRC16_ALGO: crc::Crc<u16> = crc::Crc::<u16>::new(&crc::CRC_16_IBM_SDLC);
static CRC64_ALGO: crc::Crc<u64> = crc::Crc::<u64>::new(&crc::CRC_64_ECMA_182);

fn fnv1_32_step(mut hash: u32, data: &[u8]) -> u32 {
    for &byte in data {
        hash = hash.wrapping_mul(FNV32_PRIME);
        hash ^= u32::from(byte);
    }
    hash
}

fn fnv1_64_step(mut hash: u64, data: &[u8]) -> u64 {
    for &byte in data {
        hash = hash.wrapping_mul(FNV64_PRIME);
        hash ^= u64::from(byte);
    }
    hash
}

fn fnv1a_32_step(mut hash: u32, data: &[u8]) -> u32 {
    for &byte in data {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(FNV32_PRIME);
    }
    hash
}

fn fnv1a_64_step(mut hash: u64, data: &[u8]) -> u64 {
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV64_PRIME);
    }
    hash
}

fn fnv1_32(data: &[u8]) -> u32 {
    fnv1_32_step(FNV32_INIT, data)
}

fn fnv1_64(data: &[u8]) -> u64 {
    fnv1_64_step(FNV64_INIT, data)
}

fn fnv1a_32(data: &[u8]) -> u32 {
    fnv1a_32_step(FNV32_INIT, data)
}

fn fnv1a_64(data: &[u8]) -> u64 {
    fnv1a_64_step(FNV64_INIT, data)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
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
    hex_encode(&hasher.finalize())
}

enum HasherState {
    Md5(Box<Md5>),
    Sha1(Box<Sha1>),
    Sha224(Box<Sha224>),
    Sha256(Box<Sha256>),
    Sha384(Box<Sha384>),
    Sha512(Box<Sha512>),
    Sha3_256(Box<Sha3_256>),
    Sha3_512(Box<Sha3_512>),
    Blake2b(Box<Blake2b256>),
    Blake2s(Box<Blake2s256>),
    Xxh32(xxhash_rust::xxh32::Xxh32),
    Xxh64(xxhash_rust::xxh64::Xxh64),
    Xxh3(Box<xxhash_rust::xxh3::Xxh3>),
    SipHash64(siphasher::sip::SipHasher24),
    SipHash128(siphasher::sip128::SipHasher24),
    Adler32(adler2::Adler32),
    Crc8(crc::Digest<'static, u8>),
    Crc16(crc::Digest<'static, u16>),
    Crc32(crc32fast::Hasher),
    Crc64(crc::Digest<'static, u64>),
    Fnv1_32(u32),
    Fnv1_64(u64),
    Fnv1a32(u32),
    Fnv1a64(u64),
}

/// Incremental hasher that consumes a document in chunks.
///
/// Produces digests identical to [`compute_hash`] over the concatenation of
/// every chunk passed to [`StreamingHasher::update`], without requiring the
/// whole input to be resident in memory.
pub struct StreamingHasher {
    algorithm: String,
    state: HasherState,
}

impl StreamingHasher {
    /// Creates an incremental hasher for the named algorithm.
    ///
    /// # Errors
    ///
    /// Returns `HashError::UnsupportedAlgorithm` if the algorithm name is not recognized.
    pub fn new(algorithm: &str) -> Result<Self, HashError> {
        let normalized = algorithm.to_lowercase();
        let state = match normalized.as_str() {
            "md5" => HasherState::Md5(Box::new(Md5::new())),
            "sha1" => HasherState::Sha1(Box::new(Sha1::new())),
            "sha224" | "sha-224" => HasherState::Sha224(Box::new(Sha224::new())),
            "sha256" | "sha-256" => HasherState::Sha256(Box::new(Sha256::new())),
            "sha384" | "sha-384" => HasherState::Sha384(Box::new(Sha384::new())),
            "sha512" | "sha-512" => HasherState::Sha512(Box::new(Sha512::new())),
            "sha3-256" | "sha3_256" => HasherState::Sha3_256(Box::new(Sha3_256::new())),
            "sha3-512" | "sha3_512" => HasherState::Sha3_512(Box::new(Sha3_512::new())),
            "blake2b" | "blake2b-256" | "blake2b256" => {
                HasherState::Blake2b(Box::new(Blake2b256::new()))
            }
            "blake2s" | "blake2s-256" | "blake2s256" => {
                HasherState::Blake2s(Box::new(Blake2s256::new()))
            }
            "xxhash32" | "xxh32" => HasherState::Xxh32(xxhash_rust::xxh32::Xxh32::new(0)),
            "xxhash64" | "xxh64" => HasherState::Xxh64(xxhash_rust::xxh64::Xxh64::new(0)),
            "xxh3" | "xxh3-64" => HasherState::Xxh3(Box::new(xxhash_rust::xxh3::Xxh3::new())),
            "siphash64" | "siphash-2-4" | "siphash" => {
                HasherState::SipHash64(siphasher::sip::SipHasher24::new())
            }
            "siphash128" | "siphash-2-4-128" => {
                HasherState::SipHash128(siphasher::sip128::SipHasher24::new())
            }
            "adler32" => HasherState::Adler32(adler2::Adler32::new()),
            "crc8" => HasherState::Crc8(CRC8_ALGO.digest()),
            "crc16" => HasherState::Crc16(CRC16_ALGO.digest()),
            "crc32" => HasherState::Crc32(crc32fast::Hasher::new()),
            "crc64" | "crc64-ecma" => HasherState::Crc64(CRC64_ALGO.digest()),
            "fnv1-32" | "fnv1_32" => HasherState::Fnv1_32(FNV32_INIT),
            "fnv1-64" | "fnv1_64" => HasherState::Fnv1_64(FNV64_INIT),
            "fnv1a-32" | "fnv1a_32" => HasherState::Fnv1a32(FNV32_INIT),
            "fnv1a-64" | "fnv1a_64" => HasherState::Fnv1a64(FNV64_INIT),
            other => return Err(HashError::UnsupportedAlgorithm(other.to_string())),
        };

        Ok(Self {
            algorithm: normalized,
            state,
        })
    }

    /// Feeds the next chunk of input into the running digest.
    pub fn update(&mut self, data: &[u8]) {
        use std::hash::Hasher as _;

        match &mut self.state {
            HasherState::Md5(h) => h.update(data),
            HasherState::Sha1(h) => h.update(data),
            HasherState::Sha224(h) => h.update(data),
            HasherState::Sha256(h) => h.update(data),
            HasherState::Sha384(h) => h.update(data),
            HasherState::Sha512(h) => h.update(data),
            HasherState::Sha3_256(h) => h.update(data),
            HasherState::Sha3_512(h) => h.update(data),
            HasherState::Blake2b(h) => h.update(data),
            HasherState::Blake2s(h) => h.update(data),
            HasherState::Xxh32(h) => h.update(data),
            HasherState::Xxh64(h) => h.update(data),
            HasherState::Xxh3(h) => h.update(data),
            HasherState::SipHash64(h) => h.write(data),
            HasherState::SipHash128(h) => h.write(data),
            HasherState::Adler32(h) => h.write_slice(data),
            HasherState::Crc8(h) => h.update(data),
            HasherState::Crc16(h) => h.update(data),
            HasherState::Crc32(h) => h.update(data),
            HasherState::Crc64(h) => h.update(data),
            HasherState::Fnv1_32(h) => *h = fnv1_32_step(*h, data),
            HasherState::Fnv1_64(h) => *h = fnv1_64_step(*h, data),
            HasherState::Fnv1a32(h) => *h = fnv1a_32_step(*h, data),
            HasherState::Fnv1a64(h) => *h = fnv1a_64_step(*h, data),
        }
    }

    /// Consumes the hasher and returns the final digest.
    #[must_use]
    pub fn finalize(self) -> HashResult {
        use std::hash::Hasher as _;

        let hex_digest = match self.state {
            HasherState::Md5(h) => hex_encode(&h.finalize()),
            HasherState::Sha1(h) => hex_encode(&h.finalize()),
            HasherState::Sha224(h) => hex_encode(&h.finalize()),
            HasherState::Sha256(h) => hex_encode(&h.finalize()),
            HasherState::Sha384(h) => hex_encode(&h.finalize()),
            HasherState::Sha512(h) => hex_encode(&h.finalize()),
            HasherState::Sha3_256(h) => hex_encode(&h.finalize()),
            HasherState::Sha3_512(h) => hex_encode(&h.finalize()),
            HasherState::Blake2b(h) => hex_encode(&h.finalize()),
            HasherState::Blake2s(h) => hex_encode(&h.finalize()),
            HasherState::Xxh32(h) => format!("{:08x}", h.digest()),
            HasherState::Xxh64(h) => format!("{:016x}", h.digest()),
            HasherState::Xxh3(h) => format!("{:016x}", h.digest()),
            HasherState::SipHash64(h) => format!("{:016x}", h.finish()),
            HasherState::SipHash128(h) => {
                let hash = h.finish128();
                format!("{:016x}{:016x}", hash.h1, hash.h2)
            }
            HasherState::Adler32(h) => format!("{:08x}", h.checksum()),
            HasherState::Crc8(h) => format!("{:02x}", h.finalize()),
            HasherState::Crc16(h) => format!("{:04x}", h.finalize()),
            HasherState::Crc32(h) => format!("{:08x}", h.finalize()),
            HasherState::Crc64(h) => format!("{:016x}", h.finalize()),
            HasherState::Fnv1_32(h) | HasherState::Fnv1a32(h) => format!("{h:08x}"),
            HasherState::Fnv1_64(h) | HasherState::Fnv1a64(h) => format!("{h:016x}"),
        };

        HashResult {
            algorithm: self.algorithm,
            hex_digest,
        }
    }
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

/// Fold the 32-bit-masked file length into the accumulated PE checksum.
///
/// The Windows PE checksum ends by adding the file size to the folded word
/// sum. Windows keeps the running value in a 32-bit register, so this final
/// addition wraps rather than trapping; a multi-gigabyte file whose masked
/// length approaches `u32::MAX` would otherwise overflow a checked `+` and
/// panic across the FFI boundary. `wrapping_add` reproduces the Windows DWORD
/// semantics exactly and is a no-op for every file below 4 GiB.
fn add_masked_length(checksum: u32, data_len: usize) -> u32 {
    let masked_len = u32::try_from(data_len & 0xFFFF_FFFF).expect("length masked to u32 range");
    checksum.wrapping_add(masked_len)
}

/// Compute the PE file checksum using the standard Windows algorithm.
///
/// Sums all 16-bit words with carry folding, skipping the `CheckSum` field,
/// then adds the file length.
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
    add_masked_length(checksum, data.len())
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
        assert_eq!(
            result.hex_digest,
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn test_sha512_abc() {
        let result = compute_hash(b"abc", "sha512").unwrap();
        assert_eq!(
            result.hex_digest,
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
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
        assert_eq!(
            result.hex_digest,
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
    }

    #[test]
    fn test_blake2b_empty() {
        let result = compute_hash(b"", "blake2b").unwrap();
        // BLAKE2b-256 KAT for empty input (independent oracle: Python hashlib.blake2b digest_size=32)
        assert_eq!(
            result.hex_digest,
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
    }

    #[test]
    fn test_blake2s_empty() {
        let result = compute_hash(b"", "blake2s").unwrap();
        // BLAKE2s-256 KAT: RFC 7693 / official test-vector for empty input
        assert_eq!(
            result.hex_digest,
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
        );
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
        // xxh3-64 with seed=0 on b"test" — pinned from xxhash-rust crate output
        assert_eq!(result.hex_digest, "9ec9f7918d7dfc40");
    }

    #[test]
    fn test_siphash64() {
        let result = compute_hash(b"test", "siphash64").unwrap();
        // SipHash-2-4-64 with all-zero key on b"test" — pinned from siphasher crate output
        assert_eq!(result.hex_digest, "3d5124c4cd58914e");
    }

    #[test]
    fn test_siphash128() {
        let result = compute_hash(b"test", "siphash128").unwrap();
        // SipHash-2-4-128 with all-zero key on b"test" — pinned from siphasher crate output
        assert_eq!(result.hex_digest, "1db83d391aa42131ee6b5493810c6370");
    }

    #[test]
    fn test_adler32() {
        let result = compute_hash(b"", "adler32").unwrap();
        assert_eq!(result.hex_digest, "00000001");
    }

    #[test]
    fn test_crc8() {
        let result = compute_hash(b"123456789", "crc8").unwrap();
        // CRC-8/SMBUS check value for "123456789" per the CRC catalogue
        assert_eq!(result.hex_digest, "f4");
    }

    #[test]
    fn test_crc16() {
        let result = compute_hash(b"123456789", "crc16").unwrap();
        // CRC-16/IBM-SDLC (X-25) check value for "123456789" per the CRC catalogue
        assert_eq!(result.hex_digest, "906e");
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
        // CRC-64/ECMA-182 check value for "123456789" per the CRC catalogue
        assert_eq!(result.hex_digest, "6c40df5f0b497347");
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

    #[test]
    fn test_custom_crc8_smbus_no_reflection() {
        // width 8, refin=false, refout=false -> matches the CRC-8/SMBUS catalogue check.
        let result = compute_crc_custom(b"123456789", 8, 0x07, 0x00, false, false, 0x00).unwrap();
        assert_eq!(result, "f4");
    }

    #[test]
    fn test_custom_crc16_xmodem_no_reflection() {
        // CRC-16/XMODEM catalogue check value is 0x31C3.
        let result =
            compute_crc_custom(b"123456789", 16, 0x1021, 0x0000, false, false, 0x0000).unwrap();
        assert_eq!(result, "31c3");
    }

    #[test]
    fn test_custom_crc64_ecma_full_mask() {
        // width 64 exercises the `w >= 64 -> u64::MAX` mask branch and the 64-bit format arm.
        let result = compute_crc_custom(
            b"123456789",
            64,
            0x42F0_E1EB_A9EA_3693,
            0x0000_0000_0000_0000,
            false,
            false,
            0x0000_0000_0000_0000,
        )
        .unwrap();
        assert_eq!(result, "6c40df5f0b497347");
    }

    #[test]
    fn test_fnv1_and_fnv1a_nonempty_published_vectors() {
        // Non-empty input drives the FNV loop bodies; canonical published vectors for "a".
        assert_eq!(
            compute_hash(b"a", "fnv1-32").unwrap().hex_digest,
            "050c5d7e"
        );
        assert_eq!(
            compute_hash(b"a", "fnv1a-32").unwrap().hex_digest,
            "e40c292c"
        );
        assert_eq!(
            compute_hash(b"a", "fnv1-64").unwrap().hex_digest,
            "af63bd4c8601b7be"
        );
        assert_eq!(
            compute_hash(b"a", "fnv1a-64").unwrap().hex_digest,
            "af63dc4c8601ec8c"
        );
    }

    #[test]
    fn test_compute_hash_range_start_greater_than_end() {
        // Isolates the `start > end` sub-condition (end is within bounds).
        let err = compute_hash_range(b"ABCDE", 4, 2, "md5").unwrap_err();
        assert!(
            matches!(
                err,
                HashError::InvalidRange {
                    start: 4,
                    end: 2,
                    data_len: 5
                }
            ),
            "expected InvalidRange{{4,2,5}}, got {err:?}"
        );
    }

    fn build_pe(e_lfanew: usize, stored_checksum: u32, total: usize) -> Vec<u8> {
        let mut d = vec![0u8; total];
        d[0..2].copy_from_slice(b"MZ");
        d[0x3C..0x40].copy_from_slice(&u32::try_from(e_lfanew).unwrap().to_le_bytes());
        d[e_lfanew..e_lfanew + 4].copy_from_slice(b"PE\x00\x00");
        let co = e_lfanew + 0x58;
        d[co..co + 4].copy_from_slice(&stored_checksum.to_le_bytes());
        d
    }

    #[test]
    fn test_verify_pe_too_short() {
        let err = verify_pe_checksum(&[0u8; 0x20]).unwrap_err();
        assert!(
            matches!(&err, HashError::UnsupportedAlgorithm(m) if m.contains("too short")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_verify_pe_bad_mz_signature() {
        let mut d = vec![0u8; 0x100];
        d[0] = b'X';
        let err = verify_pe_checksum(&d).unwrap_err();
        assert!(
            matches!(&err, HashError::UnsupportedAlgorithm(m) if m.contains("MZ")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_verify_pe_checksum_offset_beyond_bounds() {
        // Valid MZ, but e_lfanew points far past the buffer so checksum_offset+4 > len.
        let mut d = vec![0u8; 0x80];
        d[0..2].copy_from_slice(b"MZ");
        d[0x3C..0x40].copy_from_slice(&0x0000_0400u32.to_le_bytes());
        let err = verify_pe_checksum(&d).unwrap_err();
        assert!(
            matches!(&err, HashError::UnsupportedAlgorithm(m) if m.contains("beyond file bounds")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_verify_pe_invalid_pe_signature() {
        // MZ + in-bounds checksum offset, but the PE\0\0 magic is absent.
        let mut d = vec![0u8; 0x100];
        d[0..2].copy_from_slice(b"MZ");
        d[0x3C..0x40].copy_from_slice(&0x0000_0080u32.to_le_bytes());
        let err = verify_pe_checksum(&d).unwrap_err();
        assert!(
            matches!(&err, HashError::UnsupportedAlgorithm(m) if m.contains("invalid PE signature")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_verify_pe_valid_and_mismatch() {
        let e_lfanew = 0x80usize;
        let co = e_lfanew + 0x58;
        // Fill the header region with varied bytes so the checksum sum is non-trivial.
        let mut d = build_pe(e_lfanew, 0, 0x100);
        for (i, b) in d.iter_mut().enumerate().skip(0x40) {
            if !(co..co + 4).contains(&i) && !(e_lfanew..e_lfanew + 4).contains(&i) {
                *b = u8::try_from(i & 0xFF).unwrap();
            }
        }
        let calc = compute_pe_checksum(&d, co);
        d[co..co + 4].copy_from_slice(&calc.to_le_bytes());
        let ok = verify_pe_checksum(&d).unwrap();
        assert_eq!(ok.offset, co);
        assert_eq!(ok.stored, calc);
        assert_eq!(ok.calculated, calc);
        assert!(ok.valid);

        // Corrupt the stored checksum -> valid must become false, calculated unchanged.
        d[co..co + 4].copy_from_slice(&calc.wrapping_add(1).to_le_bytes());
        let bad = verify_pe_checksum(&d).unwrap();
        assert_eq!(bad.calculated, calc);
        assert_eq!(bad.stored, calc.wrapping_add(1));
        assert!(!bad.valid);
    }

    /// F-0079 regression: the PE checksum ends by adding the file length to the
    /// folded word sum. That add used a checked `+`, so a file whose
    /// 32-bit-masked length approaches `u32::MAX` (a ~4 GiB PE, which this
    /// engine's large-file path can materialize) overflowed `u32` and panicked
    /// across the FFI boundary. Windows keeps the value in a DWORD and lets it
    /// wrap; `add_masked_length` must do the same. Exercised on the extracted
    /// finalizer so the case is reachable without a 4 GiB allocation.
    ///
    /// Mutation caught: reverting to `checksum + (masked_len)` overflow-panics
    /// on these values under the debug overflow checks `cargo test` uses, so
    /// the equality assertion is never reached.
    #[test]
    fn test_pe_checksum_length_add_wraps_instead_of_panicking() {
        // 0x0001_0000 + 0xFFFF_FFFF == 0x1_0000_FFFF, truncated to 0x0000_FFFF.
        assert_eq!(add_masked_length(0x0001_0000, 0xFFFF_FFFF), 0x0000_FFFF);
        // Below 4 GiB the add cannot overflow: behavior is a plain sum.
        assert_eq!(add_masked_length(0x0000_1234, 0x0000_1000), 0x0000_2234);
    }

    const STREAMING_ALGORITHMS: &[&str] = &[
        "md5",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha3-256",
        "sha3-512",
        "blake2b",
        "blake2s",
        "xxhash32",
        "xxhash64",
        "xxh3",
        "siphash64",
        "siphash128",
        "adler32",
        "crc8",
        "crc16",
        "crc32",
        "crc64",
        "fnv1-32",
        "fnv1-64",
        "fnv1a-32",
        "fnv1a-64",
    ];

    #[test]
    fn test_streaming_hasher_matches_oneshot_across_chunk_sizes() {
        let data: Vec<u8> = (0..1000u32)
            .map(|i| u8::try_from((i.wrapping_mul(37).wrapping_add(11)) % 256).unwrap())
            .collect();

        for algorithm in STREAMING_ALGORITHMS {
            let expected = compute_hash(&data, algorithm).unwrap().hex_digest;

            for chunk_size in [1usize, 3, 7, 64, 127, 512, 1000] {
                let mut hasher = StreamingHasher::new(algorithm).unwrap();
                for chunk in data.chunks(chunk_size) {
                    hasher.update(chunk);
                }
                let streamed = hasher.finalize();

                assert_eq!(
                    streamed.hex_digest, expected,
                    "{algorithm} diverged at chunk size {chunk_size}"
                );
                assert_eq!(streamed.algorithm, *algorithm);
            }
        }
    }

    #[test]
    fn test_streaming_hasher_empty_input_matches_oneshot() {
        for algorithm in STREAMING_ALGORITHMS {
            let expected = compute_hash(&[], algorithm).unwrap().hex_digest;
            let streamed = StreamingHasher::new(algorithm).unwrap().finalize();
            assert_eq!(streamed.hex_digest, expected, "{algorithm} empty mismatch");
        }
    }

    #[test]
    fn test_streaming_hasher_rejects_unsupported_algorithm() {
        let Err(err) = StreamingHasher::new("not-a-real-hash") else {
            panic!("expected unsupported algorithm error");
        };
        assert!(
            matches!(&err, HashError::UnsupportedAlgorithm(name) if name == "not-a-real-hash"),
            "got {err:?}"
        );
    }

    #[test]
    fn test_compute_pe_checksum_odd_length_trailing_byte() {
        // Odd length drives the trailing-byte branch; checksum_offset far away -> no skip.
        // Hand-traced: words 0x0201+0x0403+0x0605 = 3081, + trailing 7 = 3088, + len 7 = 3095.
        assert_eq!(compute_pe_checksum(&[1, 2, 3, 4, 5, 6, 7], 1000), 3095);
        // Flipping the trailing byte must change the result (byte is not ignored).
        assert_eq!(compute_pe_checksum(&[1, 2, 3, 4, 5, 6, 8], 1000), 3096);
    }
}
