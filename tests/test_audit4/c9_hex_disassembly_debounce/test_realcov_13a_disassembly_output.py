# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for disassembly instruction output rendering.

The shard 13 audit notes that the existing C9 debounce tests validate timing
and dispatch count but do NOT verify the disassembly output is correct
(mnemonics, operands, hex bytes, addressing). This module closes that gap.

It opens a REAL Windows PE (``kernel32.dll``) through the real
:class:`HexEditorBridge`, disassembles real bytes from the real ``.text``
section with the real x86-64 backend, then renders the genuine instruction
records through the production :meth:`DisassemblyMixin._apply_disassemble_result`.
Assertions check verifiable real properties: the deterministic ``int3`` decode
of real ``0xCC`` padding bytes, that rendered hex-byte columns match the real
document bytes, that addresses are monotonically increasing by instruction
size, and that the table row count equals the number of decoded instructions.
"""

from __future__ import annotations

import asyncio
import itertools
from typing import TYPE_CHECKING, Any, cast

import pytest
from PyQt6.QtWidgets import QApplication, QTableWidget, QWidget

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.ui.panels.hex_editor.disassembly import DisassemblyMixin


if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication]:
    """Provide a process-wide ``QApplication`` for Qt widget construction.

    Yields:
        Generator[QApplication]: Qt application instance shared across tests.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


class _DisasmRenderHarness(DisassemblyMixin, QWidget):
    """Host widget exposing the real disassembly table for rendering."""

    def __init__(self) -> None:
        """Initialise the real disassembly table."""
        super().__init__()
        self._disasm_table: QTableWidget | None = QTableWidget(0, 4, self)

    def render_instructions(self, instructions: object) -> list[tuple[str, str, str, str]]:
        """Render bridge instruction records and return the table rows.

        Args:
            instructions: Bridge ``disassemble`` result.

        Returns:
            list[tuple[str, str, str, str]]: (address, hex bytes, mnemonic, operands).
        """
        self._apply_disassemble_result(instructions)
        table = self._disasm_table
        return [] if table is None else _read_table(table)


def _open_real_pe(path: Path) -> HexEditorBridge:
    """Open a real PE file on a fresh bridge.

    Args:
        path: Path to a real PE binary on disk.

    Returns:
        HexEditorBridge: Bridge with the PE document loaded.
    """
    bridge = HexEditorBridge()
    asyncio.run(bridge.open_file(str(path)))
    return bridge


def _text_raw_offset(bridge: HexEditorBridge) -> int:
    """Return the raw file offset of the real ``.text`` section.

    Args:
        bridge: Bridge with a PE document loaded.

    Returns:
        int: File offset of the ``.text`` section.
    """
    sections = asyncio.run(bridge.get_pe_sections())
    text = next(s for s in sections if s["name"] == ".text")
    return int(text["raw_offset"])


def _read_doc_bytes(bridge: HexEditorBridge, offset: int, length: int) -> bytes:
    """Read raw bytes from the bridge's loaded document.

    Args:
        bridge: Bridge with a document loaded.
        offset: Byte offset to read from.
        length: Number of bytes to read.

    Returns:
        bytes: The requested document bytes.
    """
    document = bridge.document
    assert document is not None, "the bridge must have a document loaded"
    raw: object = document.read(offset, length)
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, bytearray):
        return bytes(raw)
    if isinstance(raw, list):
        return bytes(cast("list[int]", raw))
    return b""


def _read_table(table: QTableWidget) -> list[tuple[str, str, str, str]]:
    """Read every rendered row from a disassembly table.

    Args:
        table: The populated disassembly table.

    Returns:
        list[tuple[str, str, str, str]]: (address, hex bytes, mnemonic, operands).
    """
    rows: list[tuple[str, str, str, str]] = []
    for r in range(table.rowCount()):
        cells: list[str] = []
        for c in range(4):
            item = table.item(r, c)
            cells.append(item.text() if item is not None else "")
        rows.append((cells[0], cells[1], cells[2], cells[3]))
    return rows


@pytest.mark.usefixtures("qapp")
class TestRealDisassemblyOutput:
    """Disassembly of real PE bytes must render correct instruction records."""

    @staticmethod
    def test_int3_padding_decodes_deterministically(qapp: QApplication, real_pe_dll: Path) -> None:
        """Real 0xCC padding at ``.text`` start decodes to ``int3`` instructions.

        Args:
            qapp: Qt application fixture.
            real_pe_dll: Path to a real System32 DLL.
        """
        del qapp
        bridge = _open_real_pe(real_pe_dll)
        text_off = _text_raw_offset(bridge)

        real_bytes = _read_doc_bytes(bridge, text_off, 8)
        assert real_bytes == b"\xcc" * 8, "kernel32 .text begins with int3 padding"

        instructions = asyncio.run(bridge.disassemble(text_off, 8, "x86", "64"))
        assert len(instructions) == 8
        assert all(insn["mnemonic"] == "int3" for insn in instructions)
        assert all(insn["bytes"] == "cc" for insn in instructions)
        assert all(insn["size"] == 1 for insn in instructions)

    @staticmethod
    def test_rendered_table_matches_real_instructions(qapp: QApplication, real_pe_dll: Path) -> None:
        """The rendered table mirrors the real bridge instruction records.

        Args:
            qapp: Qt application fixture.
            real_pe_dll: Path to a real System32 DLL.
        """
        del qapp
        bridge = _open_real_pe(real_pe_dll)
        text_off = _text_raw_offset(bridge)
        instructions: list[dict[str, Any]] = asyncio.run(
            bridge.disassemble(text_off, 12, "x86", "64"),
        )
        assert instructions

        rows = _DisasmRenderHarness().render_instructions(instructions)
        assert len(rows) == len(instructions)

        for rendered, insn in zip(rows, instructions, strict=True):
            address_text, hex_text, mnemonic, operands = rendered
            assert address_text == f"0x{int(insn['address']):08X}"
            assert mnemonic == str(insn["mnemonic"])
            assert operands == str(insn["operands"])
            compact = hex_text.replace(" ", "")
            assert compact == str(insn["bytes"])

    @staticmethod
    def test_addresses_advance_by_instruction_size(qapp: QApplication, real_pe_dll: Path) -> None:
        """Each instruction address advances by exactly the previous size.

        Args:
            qapp: Qt application fixture.
            real_pe_dll: Path to a real System32 DLL.
        """
        del qapp
        bridge = _open_real_pe(real_pe_dll)
        text_off = _text_raw_offset(bridge)
        instructions = asyncio.run(bridge.disassemble(text_off, 16, "x86", "64"))
        assert len(instructions) >= 2

        for prev, curr in itertools.pairwise(instructions):
            assert int(curr["address"]) == int(prev["address"]) + int(prev["size"])

    @staticmethod
    def test_rendered_hex_bytes_match_document_bytes(qapp: QApplication, real_pe_dll: Path) -> None:
        """Rendered hex bytes reconstruct the exact real document bytes.

        Args:
            qapp: Qt application fixture.
            real_pe_dll: Path to a real System32 DLL.
        """
        del qapp
        bridge = _open_real_pe(real_pe_dll)
        text_off = _text_raw_offset(bridge)
        instructions = asyncio.run(bridge.disassemble(text_off, 10, "x86", "64"))
        assert instructions

        total = sum(int(insn["size"]) for insn in instructions)
        real_region = _read_doc_bytes(bridge, text_off, total)

        reconstructed = b"".join(bytes.fromhex(str(insn["bytes"])) for insn in instructions)
        assert reconstructed == real_region
