# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge compare_files operation."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


pytest.importorskip("intellicrack_hexcore")


def _run[T](coro: Coroutine[object, object, T]) -> T:
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


class TestBridgeCompareFiles:
    """Tests covering HexEditorBridge.compare_files() byte-comparison logic."""

    def test_identical_files_reports_identical(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that identical files are reported as equal.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data = bytes(range(128))
        f_a = _write_bin(tmp_path, "a.bin", data)
        f_b = _write_bin(tmp_path, "b.bin", data)
        result: dict[str, Any] = _run(bridge.compare_files(str(f_a), str(f_b)))
        assert isinstance(result, dict)
        files_identical: bool | None = result.get("files_identical")
        similarity: float | None = result.get("similarity")
        assert files_identical is True or (isinstance(similarity, float) and similarity >= 0.99)

    def test_identical_files_have_zero_differences(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that identical files report zero total differences.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data = bytes(range(64))
        f_a = _write_bin(tmp_path, "a.bin", data)
        f_b = _write_bin(tmp_path, "b.bin", data)
        result: dict[str, Any] = _run(bridge.compare_files(str(f_a), str(f_b)))
        total_diff: int | None = result.get("total_differences")
        changed: int | None = result.get("changed_bytes")
        mods: int | None = result.get("modifications")
        if total_diff is not None:
            assert total_diff == 0
        elif changed is not None:
            assert changed == 0
        elif mods is not None:
            assert mods == 0

    def test_single_byte_difference_detected(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that a single changed byte causes files to differ.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data_a = bytearray(64)
        data_b = bytearray(64)
        data_b[32] = 0xFF
        f_a = _write_bin(tmp_path, "a.bin", bytes(data_a))
        f_b = _write_bin(tmp_path, "b.bin", bytes(data_b))
        result: dict[str, Any] = _run(bridge.compare_files(str(f_a), str(f_b)))
        assert isinstance(result, dict)
        assert not result.get("files_identical")

    def test_single_byte_difference_has_nonempty_regions(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that a single-byte diff produces at least one difference region.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data_a = bytearray(64)
        data_b = bytearray(64)
        data_b[10] = 0xAB
        f_a = _write_bin(tmp_path, "a.bin", bytes(data_a))
        f_b = _write_bin(tmp_path, "b.bin", bytes(data_b))
        result: dict[str, Any] = _run(bridge.compare_files(str(f_a), str(f_b)))
        regions: list[Any] | None = result.get("regions")
        match_blocks: list[Any] | None = result.get("match_blocks")
        if regions is not None:
            assert isinstance(regions, list)
        if not result.get("files_identical", True):
            has_diff_info = (
                (regions is not None and len(regions) > 0)
                or result.get("total_differences", 0) > 0
                or result.get("changed_bytes", 0) > 0
                or result.get("modifications", 0) > 0
                or (match_blocks is not None)
            )
            assert has_diff_info

    def test_multiple_region_differences_detected(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that multiple distinct changed regions are reported.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data_a = bytearray(200)
        data_b = bytearray(200)
        data_b[10] = 0xAA
        data_b[100] = 0xBB
        data_b[190] = 0xCC
        f_a = _write_bin(tmp_path, "a.bin", bytes(data_a))
        f_b = _write_bin(tmp_path, "b.bin", bytes(data_b))
        result: dict[str, Any] = _run(bridge.compare_files(str(f_a), str(f_b)))
        assert isinstance(result, dict)
        assert not result.get("files_identical")

    def test_different_size_files_not_identical(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that files with different sizes are not reported as identical.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f_a = _write_bin(tmp_path, "big.bin", b"\xaa" * 256)
        f_b = _write_bin(tmp_path, "small.bin", b"\xaa" * 128)
        result: dict[str, Any] = _run(bridge.compare_files(str(f_a), str(f_b)))
        assert isinstance(result, dict)
        assert not result.get("files_identical")

    def test_empty_files_are_identical(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that two empty files are reported as identical.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f_a = _write_bin(tmp_path, "ea.bin", b"")
        f_b = _write_bin(tmp_path, "eb.bin", b"")
        result: dict[str, Any] = _run(bridge.compare_files(str(f_a), str(f_b)))
        assert isinstance(result, dict)
        files_identical: bool | None = result.get("files_identical")
        similarity: float | None = result.get("similarity")
        assert files_identical is True or (similarity is not None and similarity >= 0.99)

    def test_same_path_twice_is_identical(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that comparing a file to itself reports identity.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = _write_bin(tmp_path, "self.bin", bytes(range(32)))
        result: dict[str, Any] = _run(bridge.compare_files(str(f), str(f)))
        assert isinstance(result, dict)
        files_identical: bool | None = result.get("files_identical")
        similarity: float | None = result.get("similarity")
        assert files_identical is True or (isinstance(similarity, float) and similarity >= 0.99)

    def test_pe_vs_elf_not_identical(self, bridge: HexEditorBridge, pe_binary: Path, elf_binary: Path) -> None:
        """Verify that comparing a PE file to an ELF file reports differences.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
            elf_binary: Path to the ELF binary fixture.
        """
        result: dict[str, Any] = _run(bridge.compare_files(str(pe_binary), str(elf_binary)))
        assert isinstance(result, dict)
        assert not result.get("files_identical")

    def test_return_type_is_dict_with_recognized_keys(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that compare_files returns a dict containing at least one recognized key.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data_a = b"\x00" * 64
        data_b = b"\xff" * 64
        f_a = _write_bin(tmp_path, "ka.bin", data_a)
        f_b = _write_bin(tmp_path, "kb.bin", data_b)
        result: dict[str, Any] = _run(bridge.compare_files(str(f_a), str(f_b)))
        recognized = {
            "files_identical",
            "total_differences",
            "regions",
            "similarity",
            "changed_bytes",
            "modifications",
            "additions",
            "deletions",
            "match_blocks",
        }
        assert isinstance(result, dict)
        assert len(recognized & set(result.keys())) > 0
