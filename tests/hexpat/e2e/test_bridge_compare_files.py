# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge compare_files operation.

``HexEditorBridge.compare_files`` wraps the native ``diff_files`` engine and
returns a dict with exactly three keys: ``files_identical`` (bool),
``total_differences`` (int), and ``regions`` (list of ``offset_a``/``offset_b``/
``length``/``diff_type`` dicts). Expected region layouts and difference counts
are cross-checked against Python's ``difflib.SequenceMatcher`` (an independent
reference for the same Myers edit-script family) so the oracle is never the
engine's own output.
"""

from __future__ import annotations

import asyncio
import difflib
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


pytest.importorskip("intellicrack_hexcore")

_DIFF_TYPES: frozenset[str] = frozenset({"match", "modified", "inserted_a", "inserted_b"})


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        T: The result of the coroutine.
    """
    loop: asyncio.AbstractEventLoop
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def _write_bin(directory: Path, name: str, data: bytes) -> Path:
    """Write bytes to a named file in the given directory.

    Args:
        directory: Target directory for the file.
        name: Filename to create.
        data: Raw bytes to write.

    Returns:
        Path: Absolute path to the created file.
    """
    p = directory / name
    p.write_bytes(data)
    return p


def _assert_schema(result: dict[str, Any], len_a: int, len_b: int) -> list[dict[str, Any]]:
    """Validate the compare_files result schema and return its regions list.

    Asserts the result has exactly the three documented keys with correctly typed
    values and well-formed regions bounded by the input lengths.

    Args:
        result: The dict returned by ``compare_files``.
        len_a: Length of the first input file.
        len_b: Length of the second input file.

    Returns:
        list[dict[str, Any]]: The validated ``regions`` list.
    """
    assert set(result.keys()) == {"files_identical", "total_differences", "regions"}
    assert isinstance(result["files_identical"], bool)
    assert isinstance(result["total_differences"], int)
    regions: list[dict[str, Any]] = result["regions"]
    assert isinstance(regions, list)
    for region in regions:
        assert set(region.keys()) == {"offset_a", "offset_b", "length", "diff_type"}
        assert region["diff_type"] in _DIFF_TYPES
        assert isinstance(region["offset_a"], int)
        assert isinstance(region["offset_b"], int)
        assert isinstance(region["length"], int)
        assert 0 <= region["offset_a"] <= len_a
        assert 0 <= region["offset_b"] <= len_b
        assert region["length"] >= 0
    return regions


def _oracle_match_bytes(data_a: bytes, data_b: bytes) -> int:
    """Compute the total matched byte count via difflib as an independent oracle.

    Args:
        data_a: First buffer.
        data_b: Second buffer.

    Returns:
        int: Sum of equal-block lengths from ``difflib.SequenceMatcher``.
    """
    matcher = difflib.SequenceMatcher(a=data_a, b=data_b, autojunk=False)
    return sum(size for _i, _j, size in matcher.get_matching_blocks())


class TestBridgeCompareFiles:
    """Tests covering HexEditorBridge.compare_files() byte-comparison logic."""

    def test_identical_files_reports_identical(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify identical files report exact equality with zero differences and a match region.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data = bytes(range(128))
        f_a = _write_bin(tmp_path, "a.bin", data)
        f_b = _write_bin(tmp_path, "b.bin", data)
        result: dict[str, Any] = _run(bridge.compare_files(str(f_a), str(f_b)))
        regions = _assert_schema(result, len(data), len(data))
        assert result["files_identical"] is True
        assert result["total_differences"] == 0
        assert regions == [{"offset_a": 0, "offset_b": 0, "length": 128, "diff_type": "match"}]

    def test_identical_files_have_zero_differences(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify identical files report exactly zero total_differences with no non-match regions.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data = bytes(range(64))
        f_a = _write_bin(tmp_path, "a.bin", data)
        f_b = _write_bin(tmp_path, "b.bin", data)
        result: dict[str, Any] = _run(bridge.compare_files(str(f_a), str(f_b)))
        regions = _assert_schema(result, len(data), len(data))
        assert result["total_differences"] == 0
        assert result["files_identical"] is True
        diff_bytes = sum(r["length"] for r in regions if r["diff_type"] != "match")
        assert diff_bytes == 0

    def test_single_byte_difference_detected(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify a single changed byte at offset 32 yields one modified region.

        The difflib oracle establishes a 63-byte match total and a single
        differing byte; the bridge must report ``total_differences == 1`` with a
        one-byte ``modified`` region at offset 32 flanked by matches.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data_a = bytes(64)
        data_b = bytearray(64)
        data_b[32] = 0xFF
        oracle_match = _oracle_match_bytes(data_a, bytes(data_b))
        assert oracle_match == 63

        f_a = _write_bin(tmp_path, "a.bin", data_a)
        f_b = _write_bin(tmp_path, "b.bin", bytes(data_b))
        result: dict[str, Any] = _run(bridge.compare_files(str(f_a), str(f_b)))
        regions = _assert_schema(result, 64, 64)
        assert result["files_identical"] is False
        assert result["total_differences"] == 1
        assert regions == [
            {"offset_a": 0, "offset_b": 0, "length": 32, "diff_type": "match"},
            {"offset_a": 32, "offset_b": 32, "length": 1, "diff_type": "modified"},
            {"offset_a": 33, "offset_b": 33, "length": 31, "diff_type": "match"},
        ]

    def test_modified_tail_region_pinpointed(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify the exact modified tail region for partially differing files.

        ``0x00*50 + 0xff*50`` versus ``0x00*100`` must produce a 50-byte match
        prefix and a 50-byte ``modified`` region at offset 50, with
        ``total_differences == 50``. The difflib oracle confirms 50 matched
        bytes.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data_a = b"\x00" * 50 + b"\xff" * 50
        data_b = b"\x00" * 100
        oracle_match = _oracle_match_bytes(data_a, data_b)
        assert oracle_match == 50

        f_a = _write_bin(tmp_path, "a.bin", data_a)
        f_b = _write_bin(tmp_path, "b.bin", data_b)
        result: dict[str, Any] = _run(bridge.compare_files(str(f_a), str(f_b)))
        regions = _assert_schema(result, 100, 100)
        assert result["files_identical"] is False
        assert result["total_differences"] == 50
        modified = [r for r in regions if r["diff_type"] == "modified"]
        assert modified == [{"offset_a": 50, "offset_b": 50, "length": 50, "diff_type": "modified"}]
        match_total = sum(r["length"] for r in regions if r["diff_type"] == "match")
        assert match_total == 50

    def test_different_size_truncation_is_inserted_region(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify a truncated file's lost tail is reported as an inserted region.

        ``0xaa*256`` versus ``0xaa*128`` shares a 128-byte prefix; the extra 128
        bytes present only in the larger file must form a single 128-byte
        ``inserted_a`` region at offset 128 with ``total_differences == 128``.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data_a = b"\xaa" * 256
        data_b = b"\xaa" * 128
        oracle_match = _oracle_match_bytes(data_a, data_b)
        assert oracle_match == 128

        f_a = _write_bin(tmp_path, "big.bin", data_a)
        f_b = _write_bin(tmp_path, "small.bin", data_b)
        result: dict[str, Any] = _run(bridge.compare_files(str(f_a), str(f_b)))
        regions = _assert_schema(result, 256, 128)
        assert result["files_identical"] is False
        assert result["total_differences"] == 128
        assert regions == [
            {"offset_a": 0, "offset_b": 0, "length": 128, "diff_type": "match"},
            {"offset_a": 128, "offset_b": 128, "length": 128, "diff_type": "inserted_a"},
        ]

    def test_empty_files_are_identical(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify two empty files report exact equality with no regions.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f_a = _write_bin(tmp_path, "ea.bin", b"")
        f_b = _write_bin(tmp_path, "eb.bin", b"")
        result: dict[str, Any] = _run(bridge.compare_files(str(f_a), str(f_b)))
        regions = _assert_schema(result, 0, 0)
        assert result["files_identical"] is True
        assert result["total_differences"] == 0
        assert regions == []

    def test_same_path_twice_is_identical(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify comparing a file against itself reports exact identity.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data = bytes(range(32))
        f = _write_bin(tmp_path, "self.bin", data)
        result: dict[str, Any] = _run(bridge.compare_files(str(f), str(f)))
        regions = _assert_schema(result, len(data), len(data))
        assert result["files_identical"] is True
        assert result["total_differences"] == 0
        assert regions == [{"offset_a": 0, "offset_b": 0, "length": 32, "diff_type": "match"}]

    def test_pe_vs_elf_not_identical(self, bridge: HexEditorBridge, pe_binary: Path, elf_binary: Path) -> None:
        """Verify comparing a real PE binary to a real ELF binary reports a real difference.

        The two distinct executable formats differ at offset 0 (``MZ`` versus
        the ELF magic), so the bridge must report ``files_identical is False``,
        a non-empty modified/inserted region set whose byte total equals
        ``total_differences``, and a first region starting at offset 0 of a
        non-match type.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
            elf_binary: Path to the ELF binary fixture.
        """
        data_a = pe_binary.read_bytes()
        data_b = elf_binary.read_bytes()
        assert data_a[:2] == b"MZ"
        assert data_b[:4] == b"\x7fELF"

        result: dict[str, Any] = _run(bridge.compare_files(str(pe_binary), str(elf_binary)))
        regions = _assert_schema(result, len(data_a), len(data_b))
        assert result["files_identical"] is False
        diff_total = sum(r["length"] for r in regions if r["diff_type"] in {"modified", "inserted_a", "inserted_b"})
        assert diff_total == result["total_differences"]
        assert diff_total > 0
        first_region = regions[0]
        assert first_region["offset_a"] == 0
        assert first_region["offset_b"] == 0
        assert first_region["diff_type"] in {"modified", "inserted_a", "inserted_b"}

    def test_real_pe_single_byte_patch_pinpointed(self, bridge: HexEditorBridge, pe_binary: Path, tmp_path: Path) -> None:
        """Verify a one-byte patch to a real PE binary is pinpointed exactly.

        A genuine PE fixture is copied and its entry-point opcode at the .text
        raw offset (0x200) is flipped from ``0xCC`` to ``0x90``. The difflib
        oracle confirms a single replaced byte; the bridge must report
        ``total_differences == 1`` with a one-byte ``modified`` region at offset
        0x200 surrounded by matches.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
            tmp_path: Pytest temporary directory.
        """
        original = pe_binary.read_bytes()
        patch_offset = 0x200
        assert original[patch_offset] == 0xCC
        patched = bytearray(original)
        patched[patch_offset] = 0x90
        oracle_match = _oracle_match_bytes(original, bytes(patched))
        assert oracle_match == len(original) - 1

        f_patched = _write_bin(tmp_path, "patched.exe", bytes(patched))
        result: dict[str, Any] = _run(bridge.compare_files(str(pe_binary), str(f_patched)))
        regions = _assert_schema(result, len(original), len(patched))
        assert result["files_identical"] is False
        assert result["total_differences"] == 1
        modified = [r for r in regions if r["diff_type"] == "modified"]
        assert modified == [{"offset_a": patch_offset, "offset_b": patch_offset, "length": 1, "diff_type": "modified"}]

    def test_completely_different_files_single_modified_region(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify two fully disjoint same-length files yield one modified region.

        ``0x00*64`` versus ``0xff*64`` share no bytes; the difflib oracle
        confirms zero matched bytes, and the bridge must report a single 64-byte
        ``modified`` region.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data_a = b"\x00" * 64
        data_b = b"\xff" * 64
        oracle_match = _oracle_match_bytes(data_a, data_b)
        assert oracle_match == 0

        f_a = _write_bin(tmp_path, "ka.bin", data_a)
        f_b = _write_bin(tmp_path, "kb.bin", data_b)
        result: dict[str, Any] = _run(bridge.compare_files(str(f_a), str(f_b)))
        regions = _assert_schema(result, 64, 64)
        assert result["files_identical"] is False
        assert result["total_differences"] == 64
        assert regions == [{"offset_a": 0, "offset_b": 0, "length": 64, "diff_type": "modified"}]

    def test_missing_file_raises_oserror(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify compare_files surfaces an OSError when an input file is missing.

        The failure must propagate rather than be swallowed into a result dict.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        existing = _write_bin(tmp_path, "present.bin", bytes(range(16)))
        missing = tmp_path / "does_not_exist.bin"
        assert not missing.exists()
        with pytest.raises(OSError, match="Failed to read"):
            _run(bridge.compare_files(str(existing), str(missing)))

    def test_unavailable_hexcore_raises_runtime_error(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify compare_files raises RuntimeError when the native core is unavailable.

        The bridge guards on ``_hexcore_available``; with the flag cleared the
        operation must raise rather than silently returning an empty diff.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f_a = _write_bin(tmp_path, "ua.bin", b"\x00" * 8)
        f_b = _write_bin(tmp_path, "ub.bin", b"\x00" * 8)
        flag = "_hexcore_available"
        original: bool = getattr(bridge, flag)
        setattr(bridge, flag, False)
        try:
            with pytest.raises(RuntimeError, match="intellicrack_hexcore"):
                _run(bridge.compare_files(str(f_a), str(f_b)))
        finally:
            setattr(bridge, flag, original)
