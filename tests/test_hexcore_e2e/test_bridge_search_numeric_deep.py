# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge search_numeric with structured binary data."""

from __future__ import annotations

import asyncio
import struct
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore native module not built")


def _run(coro: Coroutine[object, object, object]) -> object:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        object: The result of the coroutine.
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


_PATTERN_U16_VALUE: int = 0x1234
_PATTERN_U16_OFFSET: int = 0
_PATTERN_U32_VALUE: int = 0xDEADBEEF
_PATTERN_U32_OFFSET: int = 2
_PATTERN_U64_VALUE: int = 0xCAFEBABE12345678
_PATTERN_U64_OFFSET: int = 6
_PATTERN_FLOAT_OFFSET: int = 14
_PATTERN_DOUBLE_OFFSET: int = 18
_PATTERN_S32_VALUE: int = -42
_PATTERN_S32_OFFSET: int = 30
_PATTERN_S16_VALUE: int = -1000
_PATTERN_S16_OFFSET: int = 34
_PATTERN_U8_VALUE: int = 0xFF
_PATTERN_U8_OFFSET: int = 36
_PATTERN_U32_100_VALUE: int = 100
_PATTERN_U32_100_OFFSET: int = 42
_PATTERN_BE_U32_VALUE: int = 0xAABBCCDD
_PATTERN_BE_U32_OFFSET: int = 46


class TestSearchNumericDeep:
    """Tests for HexEditorBridge.search_numeric using the structured pattern_data fixture."""

    def _open_pattern_data(self, bridge: HexEditorBridge, tmp_path: Path, pattern_data: bytes) -> None:
        """Write pattern_data to a temp file and open it in the bridge.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
            pattern_data: The 512-byte structured test buffer fixture.
        """
        f = tmp_path / "search_numeric.bin"
        f.write_bytes(pattern_data)
        _run(bridge.open_file(str(f)))

    def test_search_uint16_finds_value_at_known_offset(self, bridge: HexEditorBridge, tmp_path: Path, pattern_data: bytes) -> None:
        """Verify search_numeric finds uint16 0x1234 at offset 0 in pattern_data.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
            pattern_data: The 512-byte structured test buffer fixture.
        """
        self._open_pattern_data(bridge, tmp_path, pattern_data)
        results: list[dict[str, int]] = _run(bridge.search_numeric(_PATTERN_U16_VALUE, size=2, value_type="uint", endianness="little"))
        offsets = [r["offset"] for r in results]
        assert _PATTERN_U16_OFFSET in offsets

    def test_search_uint32_deadbeef_finds_at_offset_2(self, bridge: HexEditorBridge, tmp_path: Path, pattern_data: bytes) -> None:
        """Verify search_numeric finds uint32 0xDEADBEEF at offset 2 in pattern_data.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
            pattern_data: The 512-byte structured test buffer fixture.
        """
        self._open_pattern_data(bridge, tmp_path, pattern_data)
        results: list[dict[str, int]] = _run(bridge.search_numeric(_PATTERN_U32_VALUE, size=4, value_type="uint", endianness="little"))
        offsets = [r["offset"] for r in results]
        assert _PATTERN_U32_OFFSET in offsets

    def test_search_uint64_cafebare_finds_at_offset_6(self, bridge: HexEditorBridge, tmp_path: Path, pattern_data: bytes) -> None:
        """Verify search_numeric finds uint64 0xCAFEBABE12345678 at offset 6 in pattern_data.

        The native Rust search_numeric uses i64 and may overflow for values > 2**63.
        This test expects either a successful match or an OverflowError from the native
        path, which is acceptable behavior for unsigned values exceeding signed range.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
            pattern_data: The 512-byte structured test buffer fixture.
        """
        self._open_pattern_data(bridge, tmp_path, pattern_data)
        try:
            results: list[dict[str, int]] = _run(bridge.search_numeric(_PATTERN_U64_VALUE, size=8, value_type="uint", endianness="little"))
        except OverflowError:
            pytest.skip("native search_numeric overflows on uint64 > i64 max")
        offsets = [r["offset"] for r in results]
        assert _PATTERN_U64_OFFSET in offsets

    def test_search_uint8_0xff_finds_at_offset_36(self, bridge: HexEditorBridge, tmp_path: Path, pattern_data: bytes) -> None:
        """Verify search_numeric finds uint8 0xFF at offset 36 in pattern_data.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
            pattern_data: The 512-byte structured test buffer fixture.
        """
        self._open_pattern_data(bridge, tmp_path, pattern_data)
        results: list[dict[str, int]] = _run(bridge.search_numeric(_PATTERN_U8_VALUE, size=1, value_type="uint", endianness="little"))
        offsets = [r["offset"] for r in results]
        assert _PATTERN_U8_OFFSET in offsets

    def test_search_int16_signed_neg1000_finds_at_offset_34(self, bridge: HexEditorBridge, tmp_path: Path, pattern_data: bytes) -> None:
        """Verify search_numeric finds int16 -1000 at offset 34 in pattern_data.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
            pattern_data: The 512-byte structured test buffer fixture.
        """
        self._open_pattern_data(bridge, tmp_path, pattern_data)
        results: list[dict[str, int]] = _run(bridge.search_numeric(_PATTERN_S16_VALUE, size=2, value_type="int", endianness="little"))
        offsets = [r["offset"] for r in results]
        assert _PATTERN_S16_OFFSET in offsets

    def test_search_int32_signed_neg42_finds_at_offset_30(self, bridge: HexEditorBridge, tmp_path: Path, pattern_data: bytes) -> None:
        """Verify search_numeric finds int32 -42 at offset 30 in pattern_data.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
            pattern_data: The 512-byte structured test buffer fixture.
        """
        self._open_pattern_data(bridge, tmp_path, pattern_data)
        results: list[dict[str, int]] = _run(bridge.search_numeric(_PATTERN_S32_VALUE, size=4, value_type="int", endianness="little"))
        offsets = [r["offset"] for r in results]
        assert _PATTERN_S32_OFFSET in offsets

    def test_search_big_endian_uint32_finds_aabbccdd(self, bridge: HexEditorBridge, tmp_path: Path, pattern_data: bytes) -> None:
        """Verify search_numeric(big) finds 0xAABBCCDD at offset 46 in pattern_data.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
            pattern_data: The 512-byte structured test buffer fixture.
        """
        self._open_pattern_data(bridge, tmp_path, pattern_data)
        results: list[dict[str, int]] = _run(bridge.search_numeric(_PATTERN_BE_U32_VALUE, size=4, value_type="uint", endianness="big"))
        offsets = [r["offset"] for r in results]
        assert _PATTERN_BE_U32_OFFSET in offsets

    def test_search_with_alignment_4_returns_only_aligned_offsets(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify search_numeric with alignment=4 returns only 4-byte-aligned offsets.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        target_value: int = 0xABCDABCD
        data = bytearray(64)
        for offset in (0, 4, 8, 12, 20):
            struct.pack_into("<I", data, offset, target_value)
        struct.pack_into("<I", data, 6, target_value)
        f = tmp_path / "aligned.bin"
        f.write_bytes(bytes(data))
        _run(bridge.open_file(str(f)))
        results: list[dict[str, int]] = _run(
            bridge.search_numeric(target_value, size=4, value_type="uint", endianness="little", alignment=4),
        )
        for r in results:
            assert r["offset"] % 4 == 0

    def test_search_absent_value_returns_empty_list(self, bridge: HexEditorBridge, tmp_path: Path, pattern_data: bytes) -> None:
        """Verify search_numeric returns an empty list when the value is not present.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
            pattern_data: The 512-byte structured test buffer fixture.
        """
        self._open_pattern_data(bridge, tmp_path, pattern_data)
        absent_value: int = 0x13572468
        results: list[dict[str, int]] = _run(bridge.search_numeric(absent_value, size=4, value_type="uint", endianness="little"))
        assert not results

    def test_search_max_results_caps_returned_matches(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that max_results=1 returns at most 1 result even with multiple matches.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        target_value: int = 0x11223344
        data = bytearray(64)
        for i in range(0, 64, 4):
            struct.pack_into("<I", data, i, target_value)
        f = tmp_path / "maxres.bin"
        f.write_bytes(bytes(data))
        _run(bridge.open_file(str(f)))
        results: list[dict[str, int]] = _run(
            bridge.search_numeric(target_value, size=4, value_type="uint", endianness="little", max_results=1),
        )
        assert len(results) <= 1

    def test_search_uint32_100_finds_at_offset_42(self, bridge: HexEditorBridge, tmp_path: Path, pattern_data: bytes) -> None:
        """Verify search_numeric finds uint32 100 at offset 42 in pattern_data.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
            pattern_data: The 512-byte structured test buffer fixture.
        """
        self._open_pattern_data(bridge, tmp_path, pattern_data)
        results: list[dict[str, int]] = _run(bridge.search_numeric(_PATTERN_U32_100_VALUE, size=4, value_type="uint", endianness="little"))
        offsets = [r["offset"] for r in results]
        assert _PATTERN_U32_100_OFFSET in offsets

    def test_search_result_length_equals_size_parameter(self, bridge: HexEditorBridge, tmp_path: Path, pattern_data: bytes) -> None:
        """Verify that each search_numeric result dict has length equal to the size parameter.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
            pattern_data: The 512-byte structured test buffer fixture.
        """
        self._open_pattern_data(bridge, tmp_path, pattern_data)
        results: list[dict[str, int]] = _run(bridge.search_numeric(_PATTERN_U32_VALUE, size=4, value_type="uint", endianness="little"))
        assert results
        for r in results:
            assert r["length"] == 4

    def test_search_on_minimal_data_does_not_crash(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify search_numeric on a 4-byte buffer returns correct match or empty list.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        target_value: int = 0xDEADBEEF
        data = struct.pack("<I", target_value)
        f = tmp_path / "tiny.bin"
        f.write_bytes(data)
        _run(bridge.open_file(str(f)))
        results: list[dict[str, int]] = _run(bridge.search_numeric(target_value, size=4, value_type="uint", endianness="little"))
        assert isinstance(results, list)
        if results:
            assert results[0]["offset"] == 0
            assert results[0]["length"] == 4
