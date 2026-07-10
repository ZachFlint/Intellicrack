# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for ``hex_editor.base`` hash and CRC utilities.

The audit (shard 13, base.py and hashing gaps) flagged that the full hash
algorithm surface of :mod:`intellicrack.ui.panels.hex_editor.base` was only
exercised indirectly. These tests drive every documented hash/checksum
algorithm and the parametric CRC engine over a REAL Windows PE binary
(``C:/Windows/System32/kernel32.dll``) and assert the produced digests
against independent reference implementations (Python's :mod:`hashlib`,
:mod:`zlib`, and the canonical CRC catalogue check values).
"""

from __future__ import annotations

import hashlib
import zlib
from typing import TYPE_CHECKING

import pytest

from intellicrack.ui.panels.hex_editor.base import (
    compute_custom_crc,
    compute_hash,
    compute_streaming_custom_crc,
    format_size,
)


if TYPE_CHECKING:
    from pathlib import Path


pytestmark = pytest.mark.integration


def _read_real_pe(path: Path) -> bytes:
    """Read the full body of a real PE binary.

    Args:
        path: Path to a real PE binary on disk.

    Returns:
        bytes: Complete file contents.
    """
    return path.read_bytes()


class TestStdlibHashesMatchReference:
    """``compute_hash`` must match :mod:`hashlib` on a real PE body."""

    @pytest.mark.parametrize(
        ("algo", "ref_name"),
        [
            ("MD5", "md5"),
            ("SHA-1", "sha1"),
            ("SHA-224", "sha224"),
            ("SHA-256", "sha256"),
            ("SHA-384", "sha384"),
            ("SHA-512", "sha512"),
            ("SHA3-256", "sha3_256"),
            ("SHA3-512", "sha3_512"),
        ],
    )
    def test_hash_matches_hashlib(self, real_pe_dll: Path, algo: str, ref_name: str) -> None:
        """Verify each stdlib digest equals the hashlib reference on real bytes.

        Args:
            real_pe_dll: Real PE DLL fixture path.
            algo: Algorithm label accepted by ``compute_hash``.
            ref_name: Corresponding :func:`hashlib.new` algorithm name.
        """
        data = _read_real_pe(real_pe_dll)
        expected = hashlib.new(ref_name, data).hexdigest()
        assert compute_hash(algo, data) == expected

    def test_blake2_digests_match_reference(self, real_pe_dll: Path) -> None:
        """Verify Blake2b-256 and Blake2s-256 digests over a real PE body.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        data = _read_real_pe(real_pe_dll)
        assert compute_hash("Blake2b-256", data) == hashlib.blake2b(data, digest_size=32).hexdigest()
        assert compute_hash("Blake2s-256", data) == hashlib.blake2s(data, digest_size=32).hexdigest()


class TestChecksumsMatchReference:
    """CRC and Adler checksums must match canonical references."""

    def test_crc32_matches_zlib(self, real_pe_dll: Path) -> None:
        """Verify CRC-32 over a real PE matches :func:`zlib.crc32`.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        data = _read_real_pe(real_pe_dll)
        assert compute_hash("CRC-32", data) == f"{zlib.crc32(data) & 0xFFFFFFFF:08x}"

    def test_adler32_matches_zlib(self, real_pe_dll: Path) -> None:
        """Verify Adler-32 over a real PE matches :func:`zlib.adler32`.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        data = _read_real_pe(real_pe_dll)
        assert compute_hash("Adler32", data) == f"{zlib.adler32(data) & 0xFFFFFFFF:08x}"

    def test_crc8_engine_matches_production_dispatch(self) -> None:
        """Verify the CRC-8 engine against the published catalogue check value.

        The standard CRC-8 algorithm (poly=0x07, init=0x00, ref_in=False,
        ref_out=False, xor_out=0x00) applied to the canonical test vector
        ``b"123456789"`` must produce 0xF4.  This catalogue constant (Greg
        Cook's CRC Catalogue, CRC-8/SMBUS) is derived independently of the
        production implementation by the CRC RevEng project.

        ``compute_hash("CRC-8", ...)`` must produce the same formatted result,
        proving the dispatcher wires the correct parameters to the engine.

        Mutation proof: flip ``ref_in=True`` inside the CRC-8 branch of
        ``_compute_hash_checksums`` in ``base.py``; the reflected computation
        yields 0x97 for the test vector, so ``compute_custom_crc(...) == 0xF4``
        fails immediately.
        """
        check_vector = b"123456789"
        catalogue_crc8 = 0xF4
        assert compute_custom_crc(check_vector, 8, 0x07, 0x00, ref_in=False, ref_out=False, xor_out=0x00) == catalogue_crc8
        assert compute_hash("CRC-8", check_vector) == f"{catalogue_crc8:02x}"

    def test_crc16_engine_matches_production_dispatch(self) -> None:
        """Verify the CRC-16 engine against the published catalogue check value.

        The standard CRC-16/ARC algorithm (poly=0x8005, init=0x0000,
        ref_in=True, ref_out=True, xor_out=0x0000) applied to the canonical
        test vector ``b"123456789"`` must produce 0xBB3D.  This constant is
        from the CRC Catalogue (CRC-16/ARC, also known as CRC-16/IBM) and
        is derived independently of the production implementation.

        ``compute_hash("CRC-16", ...)`` must produce the same formatted result,
        proving the dispatcher wires the correct parameters to the engine.

        Mutation proof: change ``ref_in=False`` in the CRC-16 branch of
        ``_compute_hash_checksums`` in ``base.py``; the unreflected computation
        yields 0xFEE8 for the test vector, so
        ``compute_custom_crc(...) == 0xBB3D`` fails immediately.
        """
        check_vector = b"123456789"
        catalogue_crc16 = 0xBB3D
        assert compute_custom_crc(check_vector, 16, 0x8005, 0x0000, ref_in=True, ref_out=True, xor_out=0x0000) == catalogue_crc16
        assert compute_hash("CRC-16", check_vector) == f"{catalogue_crc16:04x}"

    def test_crc64_engine_matches_production_dispatch(self) -> None:
        """Verify the CRC-64 engine against the published catalogue check value.

        The CRC-64/ECMA-182 algorithm (poly=0x42F0E1EBA9EA3693,
        init=0xFFFFFFFFFFFFFFFF, ref_in=False, ref_out=False,
        xor_out=0xFFFFFFFFFFFFFFFF) applied to the canonical test vector
        ``b"123456789"`` must produce 0x62EC59E3F1A4F00A.  This constant is
        from the CRC Catalogue (CRC-64/ECMA-182 / CRC-64/WE) and is derived
        independently of the production implementation by the CRC RevEng
        project.

        ``compute_hash("CRC-64", ...)`` must produce the same formatted result,
        proving the dispatcher wires the correct parameters to the engine.

        Mutation proof: flip ``ref_in=True`` inside the CRC-64 branch of
        ``_compute_hash_checksums`` in ``base.py``; the reflected computation
        yields a different value for the test vector, so
        ``compute_custom_crc(...) == 0x62EC59E3F1A4F00A`` fails immediately.
        """
        check_vector = b"123456789"
        catalogue_crc64 = 0x62EC59E3F1A4F00A
        assert (
            compute_custom_crc(
                check_vector,
                64,
                0x42F0E1EBA9EA3693,
                0xFFFFFFFFFFFFFFFF,
                ref_in=False,
                ref_out=False,
                xor_out=0xFFFFFFFFFFFFFFFF,
            )
            == catalogue_crc64
        )
        assert compute_hash("CRC-64", check_vector) == f"{catalogue_crc64:016x}"

    def test_unreflected_crc32_engine_matches_bit_serial(self, real_pe_dll: Path) -> None:
        """Verify the parametric engine produces the catalogue value for CRC-32/BZIP2-no-xor.

        The CRC-32 parameters poly=0x04C11DB7, init=0xFFFFFFFF, ref_in=False,
        ref_out=False, xor_out=0x00 applied to the check vector ``b"123456789"``
        must yield 0x0376E6E7 — the complement of the CRC-32/BZIP2 catalogue
        check value 0xFC891918 (which uses xor_out=0xFFFFFFFF). This
        independently derived constant is computed a different way than the
        production code, so any wrong-constant-return regression in
        ``compute_custom_crc`` fails the assertion. The real PE body is also
        hashed and its digest must change when one byte is removed, proving the
        full-stream avalanche property on real data.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        check_vector = b"123456789"
        expected_check_value = 0x0376E6E7
        assert (
            compute_custom_crc(
                check_vector,
                32,
                0x04C11DB7,
                0xFFFFFFFF,
                ref_in=False,
                ref_out=False,
                xor_out=0x00,
            )
            == expected_check_value
        )
        data = _read_real_pe(real_pe_dll)
        full = compute_custom_crc(data, 32, 0x04C11DB7, 0xFFFFFFFF, ref_in=False, ref_out=False, xor_out=0x00)
        assert full != compute_custom_crc(
            data[:-1],
            32,
            0x04C11DB7,
            0xFFFFFFFF,
            ref_in=False,
            ref_out=False,
            xor_out=0x00,
        )


class TestFnvHashes:
    """FNV-1 and FNV-1a digests must match an independent reimplementation."""

    @staticmethod
    def _fnv(data: bytes, *, variant: str, bits: int) -> int:
        """Reference FNV implementation independent of the production code.

        Args:
            data: Bytes to hash.
            variant: ``"fnv1"`` or ``"fnv1a"``.
            bits: Hash width, 32 or 64.

        Returns:
            int: Computed FNV hash value.
        """
        prime = 16777619 if bits == 32 else 1099511628211
        offset = 2166136261 if bits == 32 else 14695981039346656037
        mask = (1 << bits) - 1
        h = offset
        for b in data:
            h = ((h * prime) ^ b) & mask if variant == "fnv1" else ((h ^ b) * prime) & mask
        return h

    def test_fnv_variants_match_reference(self, real_pe_dll: Path) -> None:
        """Verify all four FNV variants over a real PE body.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        data = _read_real_pe(real_pe_dll)
        assert compute_hash("FNV1-32", data) == f"{self._fnv(data, variant='fnv1', bits=32):08x}"
        assert compute_hash("FNV1-64", data) == f"{self._fnv(data, variant='fnv1', bits=64):016x}"
        assert compute_hash("FNV1a-32", data) == f"{self._fnv(data, variant='fnv1a', bits=32):08x}"
        assert compute_hash("FNV1a-64", data) == f"{self._fnv(data, variant='fnv1a', bits=64):016x}"


class TestStreamingCrcMatchesInMemory:
    """Streaming CRC over a real file must equal the in-memory CRC."""

    @staticmethod
    def _bitserial_crc_unreflected(data: bytes, width: int, poly: int, init: int, xor_out: int) -> int:
        """Compute an MSB-first, unreflected CRC one bit at a time.

        This reference is structurally independent of the production
        table-driven, byte-at-a-time engine: it processes the message bit by
        bit using only shifts and the polynomial, so a regression in the
        production CRC table, chunk offsets, or reflection handling produces a
        divergent value here.

        Args:
            data: Message bytes to checksum.
            width: CRC width in bits.
            poly: Generator polynomial (unreflected, MSB-first).
            init: Initial register value.
            xor_out: Final XOR value applied to the register.

        Returns:
            int: The width-bit CRC of ``data``.
        """
        topbit = 1 << (width - 1)
        mask = (1 << width) - 1
        crc = init & mask
        for byte in data:
            crc ^= (byte << (width - 8)) & mask
            for _ in range(8):
                crc = ((crc << 1) ^ poly) & mask if crc & topbit else (crc << 1) & mask
        return (crc ^ xor_out) & mask

    def test_streaming_file_path_matches_bitserial_reference(self, real_pe_dll: Path) -> None:
        """Verify the mmap-streamed table-driven CRC-32 over a real PE.

        Uses CRC-32/BZIP2-style parameters with ``ref_in=False`` /
        ``ref_out=False`` so the standard zlib short-circuit in
        ``_crc_over_chunks`` is NOT taken and the production table-driven,
        mmap-chunked streaming engine is genuinely exercised.  The independent
        oracle is :meth:`_bitserial_crc_unreflected`, a bit-at-a-time CRC that
        shares no code with the production byte-at-a-time engine, so any
        regression in the CRC table, the chunk boundaries, or the streaming
        loop yields a divergent value and fails the assertion.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        data = _read_real_pe(real_pe_dll)
        crc = compute_streaming_custom_crc(
            str(real_pe_dll),
            None,
            32,
            0x04C11DB7,
            0xFFFFFFFF,
            ref_in=False,
            ref_out=False,
            xor_out=0x00,
        )
        expected = self._bitserial_crc_unreflected(data, 32, 0x04C11DB7, 0xFFFFFFFF, 0x00)
        assert crc == expected

    def test_streaming_standard_crc32_matches_zlib(self, real_pe_dll: Path) -> None:
        """Verify mmap-streamed standard CRC-32 over a real PE matches zlib.

        This complements
        :meth:`test_streaming_file_path_matches_bitserial_reference` by
        confirming the standard (reflected) CRC-32 path agrees with the
        independent ``zlib.crc32`` implementation over the real binary.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        data = _read_real_pe(real_pe_dll)
        crc = compute_streaming_custom_crc(
            str(real_pe_dll),
            None,
            32,
            0x04C11DB7,
            0xFFFFFFFF,
            ref_in=True,
            ref_out=True,
            xor_out=0xFFFFFFFF,
        )
        assert crc == (zlib.crc32(data) & 0xFFFFFFFF)

    def test_streaming_file_path_matches_document_path(self, real_pe_dll: Path) -> None:
        """Verify the mmap file path and the document path agree on a real PE.

        Uses CRC-16/ARC parameters so the standard zlib short-circuit is not
        taken and the table-driven streaming engine is genuinely exercised.
        The mmap-backed and ``document.read``-backed code paths must produce
        the identical CRC for the same real binary.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        hexcore = pytest.importorskip(
            "intellicrack_hexcore",
            reason="intellicrack_hexcore backend required for document-backed streaming CRC",
        )
        document = hexcore.HexDocument.open(str(real_pe_dll))
        via_file = compute_streaming_custom_crc(
            str(real_pe_dll),
            None,
            16,
            0x8005,
            0x0000,
            ref_in=True,
            ref_out=True,
            xor_out=0x0000,
        )
        via_document = compute_streaming_custom_crc(
            None,
            document,
            16,
            0x8005,
            0x0000,
            ref_in=True,
            ref_out=True,
            xor_out=0x0000,
        )
        assert via_file == via_document


class TestFormatSize:
    """``format_size`` must produce human-readable sizes for a real PE."""

    def test_real_pe_size_is_kb_or_mb(self, real_pe_dll: Path) -> None:
        """Verify a real PE size formats to the exact human-readable string.

        The independent oracle recomputes the expected string a different way
        from the 1024-based unit boundaries, asserting exact equality rather
        than a ``.endswith`` proxy (which would pass a wrong-divisor MB branch).
        Explicit MB and GB checks deterministically gate those branches
        regardless of the real fixture's size.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        kib = 1 << 10
        mib = 1 << 20
        gib = 1 << 30

        size = real_pe_dll.stat().st_size
        if size < kib:
            expected = f"{size} B"
        elif size < mib:
            expected = f"{size / kib:.1f} KB"
        elif size < gib:
            expected = f"{size / mib:.1f} MB"
        else:
            expected = f"{size / gib:.2f} GB"
        assert format_size(size) == expected

        assert format_size(0) == "0 B"
        assert format_size(1536) == "1.5 KB"
        assert format_size(3 * mib // 2) == "1.5 MB"
        assert format_size(3 * gib // 2) == "1.50 GB"
