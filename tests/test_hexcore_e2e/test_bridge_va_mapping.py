# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge virtual address mapping operations."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path


hexcore_mod: Any = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)


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


def _has_native_va_mapping() -> bool:
    """Check if the native HexDocument exposes VA mapping methods.

    Returns:
        bool: True if native VA mapping is available.
    """
    doc = hexcore_mod.HexDocument()
    return hasattr(doc, "add_va_mapping")


class TestManualVAMappings:
    """Tests for manually adding, removing, and listing VA mappings."""

    @pytest.mark.skipif(not _has_native_va_mapping(), reason="native VA mapping not available")
    def test_set_va_base_and_list(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify adding a VA mapping and listing it returns correct values.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "va.bin"
        f.write_bytes(b"\x00" * 1024)
        _run(bridge.open_file(str(f)))
        _run(bridge.set_va_base(0, 0x400000, 0x200))
        mappings = cast("list[dict[str, int]]", _run(bridge.list_va_mappings()))
        assert len(mappings) >= 1
        found = any(m["file_offset"] == 0 and m["virtual_address"] == 0x400000 for m in mappings)
        assert found

    def test_set_va_base_returns_true(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify set_va_base returns True even without native support.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "va_ret.bin"
        f.write_bytes(b"\x00" * 1024)
        _run(bridge.open_file(str(f)))
        result = cast(bool, _run(bridge.set_va_base(0, 0x400000, 0x200)))
        assert result is True

    @pytest.mark.skipif(not _has_native_va_mapping(), reason="native VA mapping not available")
    def test_remove_va_mapping(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify removing a VA mapping reduces the list count.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "va_rm.bin"
        f.write_bytes(b"\x00" * 1024)
        _run(bridge.open_file(str(f)))
        _run(bridge.set_va_base(0, 0x400000, 0x200))
        _run(bridge.set_va_base(0x200, 0x401000, 0x100))
        before = cast("list[dict[str, int]]", _run(bridge.list_va_mappings()))
        _run(bridge.remove_va_mapping(0))
        after = cast("list[dict[str, int]]", _run(bridge.list_va_mappings()))
        assert len(after) == len(before) - 1


class TestVAConversion:
    """Tests for file offset to VA and VA to file offset conversions."""

    @pytest.mark.skipif(not _has_native_va_mapping(), reason="native VA mapping not available")
    def test_file_offset_to_va(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify file_offset_to_va returns the correct virtual address.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "va_conv.bin"
        f.write_bytes(b"\x00" * 8192)
        _run(bridge.open_file(str(f)))
        _run(bridge.set_va_base(0x1000, 0x401000, 0x200))
        result = cast("int | None", _run(bridge.file_offset_to_va(0x1000)))
        assert result == 0x401000

    @pytest.mark.skipif(not _has_native_va_mapping(), reason="native VA mapping not available")
    def test_va_to_file_offset(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify va_to_file_offset returns the correct file offset.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "va_conv2.bin"
        f.write_bytes(b"\x00" * 8192)
        _run(bridge.open_file(str(f)))
        _run(bridge.set_va_base(0x1000, 0x401000, 0x200))
        result = cast("int | None", _run(bridge.va_to_file_offset(0x401000)))
        assert result == 0x1000

    def test_unmapped_offset_returns_none(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that an unmapped offset returns None.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "va_unmapped.bin"
        f.write_bytes(b"\x00" * 8192)
        _run(bridge.open_file(str(f)))
        _run(bridge.set_va_base(0, 0x400000, 0x200))
        result = _run(bridge.file_offset_to_va(0x5000))
        assert result is None


class TestAutoDetectVAMappings:
    """Tests for auto-detecting VA mappings from PE and ELF headers."""

    def test_auto_detect_pe_va_mappings(self, bridge: HexEditorBridge, pe_binary_full: Path) -> None:
        """Verify auto-detection on PE produces mappings with ImageBase-based VAs.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary_full: Path to a PE binary with full Optional Header.
        """
        _run(bridge.open_file(str(pe_binary_full)))
        mappings = cast("list[dict[str, int]]", _run(bridge.auto_detect_va_mappings()))
        assert len(mappings) >= 2
        vas = [m["virtual_address"] for m in mappings]
        assert any(va >= 0x400000 for va in vas)

    def test_auto_detect_elf_va_mappings(self, bridge: HexEditorBridge, elf_binary_with_loads: Path) -> None:
        """Verify auto-detection on ELF produces PT_LOAD segment mappings.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            elf_binary_with_loads: Path to an ELF binary with PT_LOAD segments.
        """
        _run(bridge.open_file(str(elf_binary_with_loads)))
        mappings = cast("list[dict[str, int]]", _run(bridge.auto_detect_va_mappings()))
        assert len(mappings) == 2
        offsets = {m["file_offset"] for m in mappings}
        assert 0x1000 in offsets
        assert 0x2000 in offsets

    def test_auto_detect_non_pe_elf_returns_empty(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify auto-detection on a non-PE/ELF file returns an empty list.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "random.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        mappings = cast("list[dict[str, int]]", _run(bridge.auto_detect_va_mappings()))
        assert mappings == []

    def test_no_document_raises(self, bridge: HexEditorBridge) -> None:
        """Verify auto_detect_va_mappings raises RuntimeError without a document.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.auto_detect_va_mappings())
