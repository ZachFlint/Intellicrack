# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexDocument hash computation methods."""

from __future__ import annotations

import binascii
import hashlib
import string
import zlib
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    import types

    from intellicrack_hexcore import HexDocument


def _crc16_arc(data: bytes) -> int:
    """Compute CRC-16/ARC over the given data bytes.

    Uses poly=0x8005, init=0x0000, refin=True, refout=True, xorout=0x0000.

    Args:
        data: Input bytes to compute CRC over.

    Returns:
        int: The 16-bit CRC value.
    """
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


class TestHashAlgorithms:
    """E2E tests for HexDocument.compute_hash against standard algorithm names."""

    def test_md5_matches_hashlib(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that compute_hash('md5') produces the same digest as hashlib.md5.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
            sample_bytes: 256-byte test payload (0x00-0xFF).
        """
        expected: str = hashlib.new("md5", sample_bytes, usedforsecurity=False).hexdigest()
        result: str = sample_doc_from_bytes.compute_hash("md5")
        assert result.lower() == expected.lower()

    def test_sha1_matches_hashlib(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that compute_hash('sha1') produces the same digest as hashlib.sha1.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
            sample_bytes: 256-byte test payload (0x00-0xFF).
        """
        expected: str = hashlib.new("sha1", sample_bytes, usedforsecurity=False).hexdigest()
        result: str = sample_doc_from_bytes.compute_hash("sha1")
        assert result.lower() == expected.lower()

    def test_sha256_matches_hashlib(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that compute_hash('sha256') produces the same digest as hashlib.sha256.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
            sample_bytes: 256-byte test payload (0x00-0xFF).
        """
        expected: str = hashlib.sha256(sample_bytes).hexdigest()
        result: str = sample_doc_from_bytes.compute_hash("sha256")
        assert result.lower() == expected.lower()

    def test_sha512_matches_hashlib(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that compute_hash('sha512') produces the same digest as hashlib.sha512.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
            sample_bytes: 256-byte test payload (0x00-0xFF).
        """
        expected: str = hashlib.sha512(sample_bytes).hexdigest()
        result: str = sample_doc_from_bytes.compute_hash("sha512")
        assert result.lower() == expected.lower()

    def test_crc32_matches_binascii(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that compute_hash('crc32') produces the same value as binascii.crc32.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
            sample_bytes: 256-byte test payload (0x00-0xFF).
        """
        crc_val: int = binascii.crc32(sample_bytes) & 0xFFFFFFFF
        expected: str = f"{crc_val:08x}"
        result: str = sample_doc_from_bytes.compute_hash("crc32")
        assert result.lower() == expected.lower()

    def test_sha3_256_matches_hashlib(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that compute_hash('sha3-256') unconditionally matches hashlib.sha3_256.

        SHA3-256 is an unconditional match arm in the hexcore Rust hash module, so it
        must always be available; this test never skips and fails if the digest is wrong.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
            sample_bytes: 256-byte test payload (0x00-0xFF).
        """
        expected: str = hashlib.sha3_256(sample_bytes).hexdigest()
        result: str = sample_doc_from_bytes.compute_hash("sha3-256")
        assert result.lower() == expected.lower()

    def test_sha3_512_matches_hashlib(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that compute_hash('sha3-512') unconditionally matches hashlib.sha3_512.

        SHA3-512 is an unconditional match arm in the hexcore Rust hash module, so it
        must always be available; this test never skips and fails if the digest is wrong.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
            sample_bytes: 256-byte test payload (0x00-0xFF).
        """
        expected: str = hashlib.sha3_512(sample_bytes).hexdigest()
        result: str = sample_doc_from_bytes.compute_hash("sha3-512")
        assert result.lower() == expected.lower()

    def test_sha3_256_empty_matches_nist_known_answer(self, empty_doc: HexDocument) -> None:
        """Verify that compute_hash('sha3-256') over zero bytes equals the published NIST KAT.

        The expected digest is the NIST/FIPS 202 SHA3-256("") known-answer value, an
        independent published constant, not derived from this implementation.

        Args:
            empty_doc: A zero-length HexDocument.
        """
        nist_sha3_256_empty: str = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        result: str = empty_doc.compute_hash("sha3-256")
        assert result.lower() == nist_sha3_256_empty

    def test_sha3_underscore_alias_matches_hyphen(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify the 'sha3_256' underscore alias yields the same digest as 'sha3-256'.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
        """
        hyphen: str = sample_doc_from_bytes.compute_hash("sha3-256")
        underscore: str = sample_doc_from_bytes.compute_hash("sha3_256")
        assert underscore.lower() == hyphen.lower()

    def test_blake2b_matches_hashlib_256bit_digest(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify compute_hash('blake2b') unconditionally matches hashlib BLAKE2b-256.

        The hexcore 'blake2b' algorithm is BLAKE2b with a 256-bit (32-byte) digest, so the
        hashlib reference must use ``digest_size=32`` to match. BLAKE2b is an unconditional
        match arm in the Rust hash module, so this test never skips.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
            sample_bytes: 256-byte test payload (0x00-0xFF).
        """
        expected: str = hashlib.blake2b(sample_bytes, digest_size=32).hexdigest()
        result: str = sample_doc_from_bytes.compute_hash("blake2b")
        assert len(result) == 64
        assert result.lower() == expected.lower()

    def test_blake2b_differs_from_blake2s(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify the distinct BLAKE2b and BLAKE2s algorithms produce different 256-bit digests.

        Both yield 64 hex characters, so a length-only check could not tell them apart; this
        asserts the two algorithm arms are wired to genuinely different primitives.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
        """
        blake2b: str = sample_doc_from_bytes.compute_hash("blake2b")
        blake2s: str = sample_doc_from_bytes.compute_hash("blake2s")
        assert len(blake2b) == 64
        assert len(blake2s) == 64
        assert blake2b.lower() != blake2s.lower()

    def test_unsupported_algorithm_raises_value_error(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that compute_hash raises ValueError with the offending name for an unknown algorithm.

        The hexcore binding maps the Rust ``UnsupportedAlgorithm`` error onto a Python
        ``ValueError`` whose message echoes the lowercased algorithm name.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
        """
        with pytest.raises(ValueError, match="not_a_real_hash_algo_xyz") as exc_info:
            sample_doc_from_bytes.compute_hash("not_a_real_hash_algo_xyz")
        assert "unsupported algorithm" in str(exc_info.value).lower()

    def test_sha256_output_is_64_hex_chars(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that compute_hash('sha256') returns a 64-character hex string.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
        """
        result: str = sample_doc_from_bytes.compute_hash("sha256")
        assert len(result) == 64
        assert all(c in string.hexdigits for c in result)

    def test_md5_output_is_32_hex_chars(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that compute_hash('md5') returns a 32-character hex string.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
        """
        result: str = sample_doc_from_bytes.compute_hash("md5")
        assert len(result) == 32
        assert all(c in string.hexdigits for c in result)

    def test_sha1_output_is_40_hex_chars(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that compute_hash('sha1') returns a 40-character hex string.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
        """
        result: str = sample_doc_from_bytes.compute_hash("sha1")
        assert len(result) == 40
        assert all(c in string.hexdigits for c in result)

    def test_sha512_output_is_128_hex_chars(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that compute_hash('sha512') returns a 128-character hex string.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
        """
        result: str = sample_doc_from_bytes.compute_hash("sha512")
        assert len(result) == 128
        assert all(c in string.hexdigits for c in result)


class TestHashRange:
    """E2E tests for HexDocument.compute_hash_range."""

    def test_full_range_equals_full_hash(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that compute_hash_range(0, length) equals compute_hash for the full document.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
        """
        doc_length: int = sample_doc_from_bytes.length()
        full_hash: str = sample_doc_from_bytes.compute_hash("sha256")
        range_hash: str = sample_doc_from_bytes.compute_hash_range(0, doc_length, "sha256")
        assert full_hash.lower() == range_hash.lower()

    def test_subrange_matches_hashlib_slice(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that compute_hash_range on a slice matches hashlib on the same slice.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
            sample_bytes: 256-byte test payload (0x00-0xFF).
        """
        start = 10
        end = 50
        expected: str = hashlib.sha256(sample_bytes[start:end]).hexdigest()
        result: str = sample_doc_from_bytes.compute_hash_range(start, end, "sha256")
        assert result.lower() == expected.lower()

    def test_single_byte_range(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that compute_hash_range over a single byte matches hashlib on that byte.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
            sample_bytes: 256-byte test payload (0x00-0xFF).
        """
        offset = 10
        expected: str = hashlib.sha256(bytes([sample_bytes[offset]])).hexdigest()
        result: str = sample_doc_from_bytes.compute_hash_range(offset, offset + 1, "sha256")
        assert result.lower() == expected.lower()

    def test_range_md5_matches_hashlib(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that compute_hash_range uses the specified algorithm for a sub-slice.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
            sample_bytes: 256-byte test payload (0x00-0xFF).
        """
        start = 0
        end = 128
        expected: str = hashlib.new("md5", sample_bytes[start:end], usedforsecurity=False).hexdigest()
        result: str = sample_doc_from_bytes.compute_hash_range(start, end, "md5")
        assert result.lower() == expected.lower()

    def test_range_sha512_matches_hashlib(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that compute_hash_range('sha512') matches hashlib on the same subrange.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
            sample_bytes: 256-byte test payload (0x00-0xFF).
        """
        start = 64
        end = 192
        expected: str = hashlib.sha512(sample_bytes[start:end]).hexdigest()
        result: str = sample_doc_from_bytes.compute_hash_range(start, end, "sha512")
        assert result.lower() == expected.lower()

    def test_different_ranges_produce_different_hashes(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that two non-overlapping sub-ranges produce distinct SHA-256 digests.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
        """
        hash_a: str = sample_doc_from_bytes.compute_hash_range(0, 128, "sha256")
        hash_b: str = sample_doc_from_bytes.compute_hash_range(128, 256, "sha256")
        assert hash_a != hash_b


class TestCustomCRC:
    """E2E tests for HexDocument.compute_hash_custom_crc."""

    def test_crc32_standard_matches_binascii(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that CRC-32/ISO-HDLC parameters produce the same value as binascii.crc32.

        Uses poly=0x04C11DB7, init=0xFFFFFFFF, width=32, refin=True, refout=True,
        xorout=0xFFFFFFFF, which is the standard Ethernet/ZIP CRC-32.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
            sample_bytes: 256-byte test payload (0x00-0xFF).
        """
        doc_length: int = sample_doc_from_bytes.length()
        crc_val: int = binascii.crc32(sample_bytes) & 0xFFFFFFFF
        expected: str = f"{crc_val:08x}"
        result: str = sample_doc_from_bytes.compute_hash_custom_crc(
            (0, doc_length),
            0x04C11DB7,
            0xFFFFFFFF,
            32,
            (True, True),
            0xFFFFFFFF,
        )
        assert result.lower() == expected.lower()

    def test_crc32_standard_subrange_matches_binascii(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that CRC-32/ISO-HDLC on a sub-range matches binascii.crc32 on the same slice.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
            sample_bytes: 256-byte test payload (0x00-0xFF).
        """
        start = 32
        end = 128
        crc_val: int = binascii.crc32(sample_bytes[start:end]) & 0xFFFFFFFF
        expected: str = f"{crc_val:08x}"
        result: str = sample_doc_from_bytes.compute_hash_custom_crc(
            (start, end),
            0x04C11DB7,
            0xFFFFFFFF,
            32,
            (True, True),
            0xFFFFFFFF,
        )
        assert result.lower() == expected.lower()

    def test_crc16_arc_matches_reference_implementation(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that CRC-16/ARC parameters produce the same value as a Python reference.

        Uses poly=0x8005, init=0x0000, width=16, refin=True, refout=True, xorout=0x0000.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
            sample_bytes: 256-byte test payload (0x00-0xFF).
        """
        doc_length: int = sample_doc_from_bytes.length()
        crc_val: int = _crc16_arc(sample_bytes)
        expected: str = f"{crc_val:04x}"
        result: str = sample_doc_from_bytes.compute_hash_custom_crc(
            (0, doc_length),
            0x8005,
            0x0000,
            16,
            (True, True),
            0x0000,
        )
        assert result.lower() == expected.lower()

    def test_crc16_arc_subrange_matches_reference(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that CRC-16/ARC on a sub-range matches the Python reference on the same slice.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
            sample_bytes: 256-byte test payload (0x00-0xFF).
        """
        start = 0
        end = 64
        crc_val: int = _crc16_arc(sample_bytes[start:end])
        expected: str = f"{crc_val:04x}"
        result: str = sample_doc_from_bytes.compute_hash_custom_crc((start, end), 0x8005, 0x0000, 16, (True, True), 0x0000)
        assert result.lower() == expected.lower()

    def test_crc32_output_format_is_hex_string(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that compute_hash_custom_crc returns a non-empty hex string.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
        """
        doc_length: int = sample_doc_from_bytes.length()
        result: str = sample_doc_from_bytes.compute_hash_custom_crc(
            (0, doc_length),
            0x04C11DB7,
            0xFFFFFFFF,
            32,
            (True, True),
            0xFFFFFFFF,
        )
        assert isinstance(result, str)
        assert result
        assert all(c in string.hexdigits for c in result)

    def test_crc32_single_byte_range(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that CRC-32 over a single byte matches binascii.crc32 on that byte.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
            sample_bytes: 256-byte test payload (0x00-0xFF).
        """
        offset = 5
        crc_val: int = binascii.crc32(bytes([sample_bytes[offset]])) & 0xFFFFFFFF
        expected: str = f"{crc_val:08x}"
        result: str = sample_doc_from_bytes.compute_hash_custom_crc(
            (offset, offset + 1),
            0x04C11DB7,
            0xFFFFFFFF,
            32,
            (True, True),
            0xFFFFFFFF,
        )
        assert result.lower() == expected.lower()

    def test_different_ranges_produce_different_crcs(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that two distinct sub-ranges produce different CRC-32 values.

        Args:
            sample_doc_from_bytes: HexDocument created from sample_bytes.
        """
        crc_a: str = sample_doc_from_bytes.compute_hash_custom_crc(
            (0, 64),
            0x04C11DB7,
            0xFFFFFFFF,
            32,
            (True, True),
            0xFFFFFFFF,
        )
        crc_b: str = sample_doc_from_bytes.compute_hash_custom_crc(
            (64, 128),
            0x04C11DB7,
            0xFFFFFFFF,
            32,
            (True, True),
            0xFFFFFFFF,
        )
        assert crc_a != crc_b


MULTI_CHUNK_LENGTH = 200_003
CHUNK_FLOOR = 65536


@pytest.fixture
def multi_chunk_bytes() -> bytes:
    """Provide a payload spanning several hash chunks.

    The length exceeds the chunk floor and is deliberately not a multiple of
    it, so streaming must also handle a short trailing chunk.

    Returns:
        bytes: A deterministic payload of MULTI_CHUNK_LENGTH bytes.
    """
    return bytes((i * 37 + 11) % 256 for i in range(MULTI_CHUNK_LENGTH))


@pytest.fixture
def multi_chunk_doc(hexcore: types.ModuleType, multi_chunk_bytes: bytes) -> HexDocument:
    """Create a HexDocument spanning several hash chunks.

    Args:
        hexcore: The native module fixture.
        multi_chunk_bytes: The multi-chunk payload fixture.

    Returns:
        HexDocument: HexDocument created via open_bytes.
    """
    return hexcore.HexDocument.open_bytes(multi_chunk_bytes)


class TestMultiChunkHashStreaming:
    """Gates compute_hash where the document spans more than one chunk.

    compute_hash consumes the document incrementally, so a digest is correct
    only if hasher state carries across chunk boundaries. Payloads below the
    chunk floor exercise a single chunk and cannot detect that defect class.
    """

    def test_sha256_multi_chunk_matches_hashlib(
        self,
        multi_chunk_doc: HexDocument,
        multi_chunk_bytes: bytes,
    ) -> None:
        """Verify a multi-chunk SHA-256 digest matches hashlib over the payload.

        Args:
            multi_chunk_doc: HexDocument spanning several chunks.
            multi_chunk_bytes: The payload backing the document.
        """
        expected: str = hashlib.sha256(multi_chunk_bytes).hexdigest()
        assert multi_chunk_doc.compute_hash("sha256").lower() == expected

    def test_md5_multi_chunk_matches_hashlib(
        self,
        multi_chunk_doc: HexDocument,
        multi_chunk_bytes: bytes,
    ) -> None:
        """Verify a multi-chunk MD5 digest matches hashlib over the payload.

        Args:
            multi_chunk_doc: HexDocument spanning several chunks.
            multi_chunk_bytes: The payload backing the document.
        """
        expected: str = hashlib.new("md5", multi_chunk_bytes, usedforsecurity=False).hexdigest()
        assert multi_chunk_doc.compute_hash("md5").lower() == expected

    def test_crc32_multi_chunk_matches_binascii(
        self,
        multi_chunk_doc: HexDocument,
        multi_chunk_bytes: bytes,
    ) -> None:
        """Verify a multi-chunk CRC-32 matches binascii over the payload.

        Args:
            multi_chunk_doc: HexDocument spanning several chunks.
            multi_chunk_bytes: The payload backing the document.
        """
        expected: int = binascii.crc32(multi_chunk_bytes) & 0xFFFFFFFF
        assert int(multi_chunk_doc.compute_hash("crc32"), 16) == expected

    def test_adler32_multi_chunk_matches_zlib(
        self,
        multi_chunk_doc: HexDocument,
        multi_chunk_bytes: bytes,
    ) -> None:
        """Verify a multi-chunk Adler-32 matches zlib over the payload.

        Args:
            multi_chunk_doc: HexDocument spanning several chunks.
            multi_chunk_bytes: The payload backing the document.
        """
        expected: int = zlib.adler32(multi_chunk_bytes) & 0xFFFFFFFF
        assert int(multi_chunk_doc.compute_hash("adler32"), 16) == expected

    @pytest.mark.parametrize(
        "algorithm",
        ["xxh3", "xxhash64", "xxhash32", "siphash128", "siphash64", "fnv1a-64", "crc64", "crc8"],
    )
    def test_digest_invariant_across_chunk_sizes(
        self,
        multi_chunk_doc: HexDocument,
        algorithm: str,
    ) -> None:
        """Verify the digest does not depend on how the payload is chunked.

        The chunk size is floored at CHUNK_FLOOR, so these hints split the
        payload into four, two, and one chunk respectively. Algorithms with no
        standard-library reference are gated here: a hasher that mishandles a
        chunk boundary yields different digests for different splits.

        Args:
            multi_chunk_doc: HexDocument spanning several chunks.
            algorithm: Hash algorithm name to evaluate.
        """
        digests: list[str] = []
        for hint in (CHUNK_FLOOR, CHUNK_FLOOR * 2, CHUNK_FLOOR * 4):
            multi_chunk_doc.set_chunk_size_hint(hint)
            digests.append(multi_chunk_doc.compute_hash(algorithm))

        assert len(set(digests)) == 1, f"{algorithm} digest varied by chunk size: {digests}"
