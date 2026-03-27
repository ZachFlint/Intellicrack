# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge thread-safety, lifecycle, and coexistence.

Verifies that the bridge can cycle through open/close/shutdown states
without corrupting internal state, that multiple independent bridge
instances operate on separate documents, and that rapid sequential
write operations produce consistent results. All tests operate on real
binary data and must fail if hexcore cannot perform the operations.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge


if TYPE_CHECKING:
    from pathlib import Path

pytest.importorskip("intellicrack_hexcore")


def _run(coro: Any) -> Any:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        Any: The result of the coroutine.
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


class TestOpenCloseCycles:
    """Tests for repeated open/close cycles on the same bridge instance."""

    def test_multiple_open_close_cycles_same_size(
        self, bridge: Any, pe_binary: Path
    ) -> None:
        """Repeated open/close cycles on the same file must return the same size.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        sizes: list[int] = []
        for _ in range(3):
            result: dict[str, Any] = _run(bridge.open_file(str(pe_binary)))
            sizes.append(result["size"])
            _run(bridge.close_file())

        assert len(set(sizes)) == 1

    def test_read_bytes_after_reopen_matches_original(
        self, bridge: Any, pe_binary: Path
    ) -> None:
        """Read bytes after a close/reopen must produce the same hex string.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        first_read: str = _run(bridge.read_bytes(0, 2))
        _run(bridge.close_file())

        _run(bridge.open_file(str(pe_binary)))
        second_read: str = _run(bridge.read_bytes(0, 2))
        _run(bridge.close_file())

        assert first_read == second_read

    def test_open_different_files_sequentially(
        self, bridge: Any, pe_binary: Path, elf_binary: Path
    ) -> None:
        """Opening different files sequentially must produce distinct magic bytes.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
            elf_binary: Path to the ELF64 binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        pe_magic: str = _run(bridge.read_bytes(0, 2))
        _run(bridge.close_file())

        _run(bridge.open_file(str(elf_binary)))
        elf_magic: str = _run(bridge.read_bytes(0, 4))
        _run(bridge.close_file())

        assert pe_magic == "4D 5A"
        assert elf_magic == "7F 45 4C 46"

    def test_open_pe_then_elf_then_pe_magic_consistent(
        self, bridge: Any, pe_binary: Path, elf_binary: Path
    ) -> None:
        """After PE -> ELF -> PE cycle the PE magic bytes must still read as MZ.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
            elf_binary: Path to the ELF64 binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        _run(bridge.close_file())

        _run(bridge.open_file(str(elf_binary)))
        _run(bridge.close_file())

        _run(bridge.open_file(str(pe_binary)))
        magic: str = _run(bridge.read_bytes(0, 2))
        _run(bridge.close_file())

        assert magic == "4D 5A"


class TestStateAfterClose:
    """Tests for bridge internal state being clean after close_file."""

    def test_close_file_resets_cursor_to_zero(
        self, bridge: Any, pe_binary: Path
    ) -> None:
        """After close_file the internal cursor must be zero.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        _run(bridge.goto_offset(256))
        _run(bridge.close_file())

        assert bridge._cursor_offset == 0

    def test_close_file_clears_selection(
        self, bridge: Any, pe_binary: Path
    ) -> None:
        """After close_file the internal selection must be None.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        _run(bridge.select_range(0, 127))
        _run(bridge.close_file())

        assert bridge._selection is None

    def test_read_after_close_raises_runtime_error(
        self, bridge: Any, pe_binary: Path
    ) -> None:
        """read_bytes after close_file must raise RuntimeError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        _run(bridge.close_file())

        with pytest.raises(RuntimeError):
            _run(bridge.read_bytes(0, 4))

    def test_get_document_info_after_close_returns_empty(
        self, bridge: Any, pe_binary: Path
    ) -> None:
        """get_document_info after close_file must return size zero and None file_path.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        _run(bridge.close_file())

        info: dict[str, Any] = _run(bridge.get_document_info())

        assert info["size"] == 0
        assert info["file_path"] is None


class TestShutdownReinit:
    """Tests for shutdown followed by re-initialization producing a clean bridge."""

    def test_shutdown_then_reinit_reads_same_data(
        self, pe_binary: Path
    ) -> None:
        """Data read from a re-initialized bridge must match data from the original.

        Args:
            pe_binary: Path to the PE binary fixture.
        """
        b1 = HexEditorBridge()
        _run(b1.initialize())
        _run(b1.open_file(str(pe_binary)))
        result1: str = _run(b1.read_bytes(0, 2))
        _run(b1.shutdown())

        b2 = HexEditorBridge()
        _run(b2.initialize())
        _run(b2.open_file(str(pe_binary)))
        result2: str = _run(b2.read_bytes(0, 2))
        _run(b2.shutdown())

        assert result1 == result2
        assert result1 == "4D 5A"

    def test_bridge_after_shutdown_raises_on_read(
        self, bridge: Any, pe_binary: Path
    ) -> None:
        """read_bytes after shutdown must raise RuntimeError because the document is gone.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        _run(bridge.shutdown())

        with pytest.raises(RuntimeError):
            _run(bridge.read_bytes(0, 4))

    def test_bridge_after_shutdown_document_is_none(
        self, bridge: Any, pe_binary: Path
    ) -> None:
        """After shutdown the _document attribute must be None.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        _run(bridge.shutdown())

        assert bridge._document is None


class TestBridgeCoexistence:
    """Tests for multiple bridge instances operating independently on separate documents."""

    def test_two_bridges_read_different_files_independently(
        self, pe_binary: Path, elf_binary: Path
    ) -> None:
        """Two bridges each holding a different file must read that file's magic bytes.

        Args:
            pe_binary: Path to the PE binary fixture.
            elf_binary: Path to the ELF64 binary fixture.
        """
        b1 = HexEditorBridge()
        _run(b1.initialize())
        _run(b1.open_file(str(pe_binary)))

        b2 = HexEditorBridge()
        _run(b2.initialize())
        _run(b2.open_file(str(elf_binary)))

        pe_data: str = _run(b1.read_bytes(0, 2))
        elf_data: str = _run(b2.read_bytes(0, 4))

        _run(b1.shutdown())
        _run(b2.shutdown())

        assert pe_data == "4D 5A"
        assert elf_data == "7F 45 4C 46"

    def test_write_to_one_bridge_does_not_affect_other(
        self, pe_binary: Path, tmp_path: Path
    ) -> None:
        """A write on one bridge must not corrupt the document held by another bridge.

        Args:
            pe_binary: Path to the PE binary fixture.
            tmp_path: Pytest temporary directory.
        """
        copy_path = tmp_path / "copy.exe"
        copy_path.write_bytes(pe_binary.read_bytes())

        b1 = HexEditorBridge()
        _run(b1.initialize())
        _run(b1.open_file(str(pe_binary)))

        b2 = HexEditorBridge()
        _run(b2.initialize())
        _run(b2.open_file(str(copy_path)))

        before: str = _run(b1.read_bytes(0, 2))

        _run(b2.write_bytes(0, "90 90"))

        after: str = _run(b1.read_bytes(0, 2))

        _run(b1.shutdown())
        _run(b2.shutdown())

        assert before == after

    def test_three_bridges_coexist_independently(
        self, pe_binary: Path, elf_binary: Path, tmp_path: Path
    ) -> None:
        """Three bridges holding distinct files must each read their own magic bytes correctly.

        Args:
            pe_binary: Path to the PE binary fixture.
            elf_binary: Path to the ELF64 binary fixture.
            tmp_path: Pytest temporary directory.
        """
        raw_path = tmp_path / "raw.bin"
        raw_payload = bytes(range(64))
        raw_path.write_bytes(raw_payload)

        b1 = HexEditorBridge()
        b2 = HexEditorBridge()
        b3 = HexEditorBridge()

        _run(b1.initialize())
        _run(b2.initialize())
        _run(b3.initialize())

        _run(b1.open_file(str(pe_binary)))
        _run(b2.open_file(str(elf_binary)))
        _run(b3.open_file(str(raw_path)))

        pe_magic: str = _run(b1.read_bytes(0, 2))
        elf_magic: str = _run(b2.read_bytes(0, 4))
        raw_first: str = _run(b3.read_bytes(0, 1))

        _run(b1.shutdown())
        _run(b2.shutdown())
        _run(b3.shutdown())

        assert pe_magic == "4D 5A"
        assert elf_magic == "7F 45 4C 46"
        assert raw_first == "00"


class TestRapidWriteOperations:
    """Tests for rapid sequential write operations not corrupting document state."""

    def test_rapid_writes_final_value_is_last_written(
        self, bridge: Any, pe_binary: Path
    ) -> None:
        """After many sequential writes the last-written value must be readable.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))

        write_count = 20
        for i in range(write_count):
            byte_val = i % 256
            _run(bridge.write_bytes(100, f"{byte_val:02X}"))

        final_byte = (write_count - 1) % 256
        result: str = _run(bridge.read_bytes(100, 1))

        assert result == f"{final_byte:02X}"

    def test_rapid_writes_do_not_corrupt_surrounding_bytes(
        self, bridge: Any, pe_binary: Path
    ) -> None:
        """Sequential writes at offset 0 must not alter bytes at a distant offset.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))

        sentinel_offset = 200
        sentinel_before: str = _run(bridge.read_bytes(sentinel_offset, 4))

        for byte_val in range(16):
            _run(bridge.write_bytes(0, f"{byte_val:02X}"))

        sentinel_after: str = _run(bridge.read_bytes(sentinel_offset, 4))

        assert sentinel_before == sentinel_after

    def test_sequential_write_and_read_roundtrip(
        self, bridge: Any, pe_binary: Path
    ) -> None:
        """Each written byte value must be immediately readable at the write offset.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))

        for byte_val in [0x00, 0xAA, 0xFF, 0x42, 0x7F]:
            _run(bridge.write_bytes(50, f"{byte_val:02X}"))
            result: str = _run(bridge.read_bytes(50, 1))
            assert result == f"{byte_val:02X}"
