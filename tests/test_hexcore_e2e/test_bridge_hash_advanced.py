# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge range hash and custom CRC methods."""

from __future__ import annotations

import asyncio
import binascii
import hashlib
import struct
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore native module not built")


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        T: The result of the coroutine.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def _crc16_ccitt(data: bytes) -> int:
    """Compute CRC-16/CCITT-FALSE over the given data bytes.

    Uses poly=0x1021, init=0xFFFF, refin=False, refout=False, xorout=0x0000.

    Args:
        data: Input bytes to compute CRC over.

    Returns:
        int: The 16-bit CRC value.
    """
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc & 0xFFFF


def _crc8_smbus(data: bytes) -> int:
    """Compute CRC-8/SMBUS over the given data bytes.

    Uses poly=0x07, init=0x00, refin=False, refout=False, xorout=0x00.

    Args:
        data: Input bytes to compute CRC over.

    Returns:
        int: The 8-bit CRC value.
    """
    crc = 0x00
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc & 0xFF


_KNOWN_PAYLOAD: bytes = bytes(range(64)) + bytes(range(64, 128)) + bytes(range(128))
_PAYLOAD_LEN: int = len(_KNOWN_PAYLOAD)
_PE_TEXT_OFFSET: int = 0x200
_FIRST_16_BYTES: int = 16


class TestCalculateHashRange:
    """Tests for HexEditorBridge.calculate_hash_range using real document data."""

    def _make_bridge_with_payload(self, bridge: HexEditorBridge, tmp_path: Path, payload: bytes) -> None:
        """Write payload to a temp file and open it with the given bridge.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
            payload: Binary data to write.
        """
        f = tmp_path / "hash_range.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))

    def test_sha256_on_first_16_bytes_of_pe_is_nonempty_hex(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify calculate_hash_range(sha256) on first 16 PE bytes returns non-empty hex.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the minimal PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        result: str = _run(bridge.calculate_hash_range(0, _FIRST_16_BYTES, "sha256"))
        assert isinstance(result, str)
        assert result
        bytes.fromhex(result)

    def test_sha256_result_matches_hashlib_on_same_slice(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify calculate_hash_range(sha256) matches hashlib.sha256 on the same byte slice.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        self._make_bridge_with_payload(bridge, tmp_path, _KNOWN_PAYLOAD)
        start, end = 10, 60
        expected: str = hashlib.sha256(_KNOWN_PAYLOAD[start:end]).hexdigest()
        result: str = _run(bridge.calculate_hash_range(start, end, "sha256"))
        assert result.lower() == expected.lower()

    def test_md5_range_differs_from_sha256_range(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that md5 and sha256 produce different digests for the same range.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        self._make_bridge_with_payload(bridge, tmp_path, _KNOWN_PAYLOAD)
        sha256_result: str = _run(bridge.calculate_hash_range(0, 64, "sha256"))
        md5_result: str = _run(bridge.calculate_hash_range(0, 64, "md5"))
        assert sha256_result != md5_result

    def test_md5_range_matches_hashlib(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify calculate_hash_range(md5) matches hashlib.md5 on the same slice.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        self._make_bridge_with_payload(bridge, tmp_path, _KNOWN_PAYLOAD)
        start, end = 0, 128
        expected: str = hashlib.new("md5", _KNOWN_PAYLOAD[start:end], usedforsecurity=False).hexdigest()
        result: str = _run(bridge.calculate_hash_range(start, end, "md5"))
        assert result.lower() == expected.lower()

    def test_sha1_range_is_valid_hex_digest(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify calculate_hash_range(sha1) returns a valid 40-character hex digest.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        self._make_bridge_with_payload(bridge, tmp_path, _KNOWN_PAYLOAD)
        result: str = _run(bridge.calculate_hash_range(0, 64, "sha1"))
        assert len(result) == 40
        bytes.fromhex(result)

    def test_sha1_range_matches_hashlib(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify calculate_hash_range(sha1) matches hashlib.sha1 on the same slice.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        self._make_bridge_with_payload(bridge, tmp_path, _KNOWN_PAYLOAD)
        start, end = 32, 96
        expected: str = hashlib.new("sha1", _KNOWN_PAYLOAD[start:end], usedforsecurity=False).hexdigest()
        result: str = _run(bridge.calculate_hash_range(start, end, "sha1"))
        assert result.lower() == expected.lower()

    def test_crc32_range_matches_binascii(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify calculate_hash_range(crc32) matches binascii.crc32 on the same slice.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        self._make_bridge_with_payload(bridge, tmp_path, _KNOWN_PAYLOAD)
        start, end = 0, _PAYLOAD_LEN
        crc_val: int = binascii.crc32(_KNOWN_PAYLOAD[start:end]) & 0xFFFFFFFF
        expected: str = f"{crc_val:08x}"
        result: str = _run(bridge.calculate_hash_range(start, end, "crc32"))
        assert result.lower() == expected.lower()

    def test_full_document_range_matches_hashlib_sha256(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify calculate_hash_range over full document matches hashlib on all bytes.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        self._make_bridge_with_payload(bridge, tmp_path, _KNOWN_PAYLOAD)
        expected: str = hashlib.sha256(_KNOWN_PAYLOAD).hexdigest()
        result: str = _run(bridge.calculate_hash_range(0, _PAYLOAD_LEN, "sha256"))
        assert result.lower() == expected.lower()

    def test_pe_text_section_sha256_range(self, bridge: HexEditorBridge, pe_binary: Path, pe_bytes: bytes) -> None:
        """Verify calculate_hash_range on PE .text section matches hashlib on that slice.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the minimal PE binary fixture.
            pe_bytes: PE binary content as bytes.
        """
        _run(bridge.open_file(str(pe_binary)))
        start = _PE_TEXT_OFFSET
        end = _PE_TEXT_OFFSET + 4
        expected: str = hashlib.sha256(pe_bytes[start:end]).hexdigest()
        result: str = _run(bridge.calculate_hash_range(start, end, "sha256"))
        assert result.lower() == expected.lower()

    def test_empty_range_returns_hash_of_empty_bytes(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify calculate_hash_range with start==end returns hash of empty bytes.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        self._make_bridge_with_payload(bridge, tmp_path, _KNOWN_PAYLOAD)
        result: str = _run(bridge.calculate_hash_range(0, 0, "sha256"))
        expected: str = hashlib.sha256(b"").hexdigest()
        assert result.lower() == expected.lower()


class TestCalculateHashCustomCrc:
    """Tests for HexEditorBridge.calculate_hash_custom_crc with real document data."""

    def _open_payload(self, bridge: HexEditorBridge, tmp_path: Path, payload: bytes, name: str = "crc.bin") -> None:
        """Write payload to disk and open it in the bridge.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
            payload: Binary content to write.
            name: Filename to use in tmp_path.
        """
        f = tmp_path / name
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))

    def test_crc32_iso_hdlc_matches_binascii(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify custom CRC-32/ISO-HDLC matches binascii.crc32 on the full payload.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = _KNOWN_PAYLOAD
        self._open_payload(bridge, tmp_path, payload, "crc32_iso.bin")
        crc_val: int = binascii.crc32(payload) & 0xFFFFFFFF
        expected: str = f"{crc_val:08x}"
        result: str = _run(
            bridge.calculate_hash_custom_crc(0, len(payload), 0x04C11DB7, 0xFFFFFFFF, 32, refin=True, refout=True, xorout=0xFFFFFFFF)
        )
        assert result.lower() == expected.lower()

    def test_crc32_on_subrange_matches_binascii_slice(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify custom CRC-32/ISO-HDLC on a sub-range matches binascii on the same slice.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = _KNOWN_PAYLOAD
        self._open_payload(bridge, tmp_path, payload, "crc32_sub.bin")
        start, end = 16, 80
        crc_val: int = binascii.crc32(payload[start:end]) & 0xFFFFFFFF
        expected: str = f"{crc_val:08x}"
        result: str = _run(
            bridge.calculate_hash_custom_crc(start, end, 0x04C11DB7, 0xFFFFFFFF, 32, refin=True, refout=True, xorout=0xFFFFFFFF)
        )
        assert result.lower() == expected.lower()

    def test_crc16_ccitt_matches_reference_implementation(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify custom CRC-16/CCITT-FALSE matches Python reference on same payload.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = bytes(range(64))
        self._open_payload(bridge, tmp_path, payload, "crc16.bin")
        crc_val: int = _crc16_ccitt(payload)
        expected: str = f"{crc_val:04x}"
        result: str = _run(bridge.calculate_hash_custom_crc(0, len(payload), 0x1021, 0xFFFF, 16, refin=False, refout=False, xorout=0x0000))
        assert result.lower() == expected.lower()

    def test_crc16_on_pe_bytes_returns_hex_string(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify custom CRC-16 on the PE header bytes returns a valid 4-char hex string.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the minimal PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        result: str = _run(
            bridge.calculate_hash_custom_crc(0, _FIRST_16_BYTES, 0x1021, 0xFFFF, 16, refin=False, refout=False, xorout=0x0000)
        )
        assert isinstance(result, str)
        assert result
        bytes.fromhex(result)

    def test_crc8_smbus_matches_reference_implementation(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify custom CRC-8/SMBUS matches Python reference on same payload.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = bytes(range(32))
        self._open_payload(bridge, tmp_path, payload, "crc8.bin")
        crc_val: int = _crc8_smbus(payload)
        expected: str = f"{crc_val:02x}"
        result: str = _run(bridge.calculate_hash_custom_crc(0, len(payload), 0x07, 0x00, 8, refin=False, refout=False, xorout=0x00))
        assert result.lower() == expected.lower()

    def test_crc8_returns_valid_hex_string(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify custom CRC-8 returns a non-empty hex string for any payload.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = bytes(range(16))
        self._open_payload(bridge, tmp_path, payload, "crc8_fmt.bin")
        result: str = _run(bridge.calculate_hash_custom_crc(0, len(payload), 0x07, 0x00, 8, refin=False, refout=False, xorout=0x00))
        assert isinstance(result, str)
        assert result
        bytes.fromhex(result)

    def test_crc32_result_is_8_hex_chars(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify custom CRC-32 result is at most 8 hex characters.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = bytes(range(64))
        self._open_payload(bridge, tmp_path, payload, "crc32_len.bin")
        result: str = _run(
            bridge.calculate_hash_custom_crc(0, len(payload), 0x04C11DB7, 0xFFFFFFFF, 32, refin=True, refout=True, xorout=0xFFFFFFFF)
        )
        assert len(result) <= 8

    def test_different_crc32_ranges_produce_different_values(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that two non-overlapping ranges produce distinct CRC-32 values.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = _KNOWN_PAYLOAD
        self._open_payload(bridge, tmp_path, payload, "crc32_diff.bin")
        crc_a: str = _run(bridge.calculate_hash_custom_crc(0, 64, 0x04C11DB7, 0xFFFFFFFF, 32, refin=True, refout=True, xorout=0xFFFFFFFF))
        crc_b: str = _run(bridge.calculate_hash_custom_crc(64, 128, 0x04C11DB7, 0xFFFFFFFF, 32, refin=True, refout=True, xorout=0xFFFFFFFF))
        assert crc_a != crc_b

    def test_invalid_crc_width_raises_value_error(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that an unsupported CRC width raises ValueError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = bytes(range(16))
        self._open_payload(bridge, tmp_path, payload, "crc_bad_width.bin")
        with pytest.raises((ValueError, RuntimeError)):
            _run(bridge.calculate_hash_custom_crc(0, len(payload), 0x07, 0x00, 24, refin=False, refout=False, xorout=0x00))

    def test_crc32_single_known_byte_matches_binascii(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify CRC-32 over a single known byte matches binascii.crc32 on that byte.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = struct.pack("B", 0xAB) + bytes(15)
        self._open_payload(bridge, tmp_path, payload, "crc32_single.bin")
        crc_val: int = binascii.crc32(bytes([0xAB])) & 0xFFFFFFFF
        expected: str = f"{crc_val:08x}"
        result: str = _run(bridge.calculate_hash_custom_crc(0, 1, 0x04C11DB7, 0xFFFFFFFF, 32, refin=True, refout=True, xorout=0xFFFFFFFF))
        assert result.lower() == expected.lower()
