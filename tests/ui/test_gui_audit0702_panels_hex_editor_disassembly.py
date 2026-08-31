# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for the GUI audit finding M50 in ``hex_editor.disassembly``.

* ``test_m50_*``: the Disassembly table's "Hex Bytes" column (index 1) must
  be configured to ``ResizeToContents`` and must actually widen to fit long
  instruction byte dumps (up to 15 bytes / 44 characters, e.g. for
  AVX/EVEX-prefixed x86 instructions) instead of clipping them at Qt's
  default ~100px ``Interactive`` section width. Each populated cell must
  also carry a tooltip with the full, untruncated hex dump as a fallback
  when the resized column is still narrower than the viewport allows.

All tests drive a real :class:`HexEditorPanel` (which mixes in
``DisassemblyMixin``) and its real ``_apply_disassemble_result`` rendering
method under an offscreen QApplication; no table or header behaviour is
mocked or stubbed.
"""

from __future__ import annotations

from typing import Any

from PyQt6.QtGui import QFontMetrics
from PyQt6.QtWidgets import QApplication, QHeaderView

from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel


_LONG_INSTRUCTION_HEX: str = "".join(f"{byte:02X}" for byte in range(15))


def _spaced_hex_dump(raw_hex: str) -> str:
    """Space-join a contiguous hex-pair string, mirroring the mixin's own formatting.

    Args:
        raw_hex: Contiguous uppercase hex digits with an even length.

    Returns:
        str: The same digits grouped into space-separated byte pairs.
    """
    return " ".join(raw_hex[i : i + 2] for i in range(0, len(raw_hex), 2))


class TestM50HexBytesColumnNotClipped:
    """M50: the Hex Bytes column resizes to fit long instruction byte dumps."""

    def test_m50_hex_bytes_header_section_is_resize_to_contents(self, qapp: QApplication) -> None:
        """Column index 1 ("Hex Bytes") must use the ``ResizeToContents`` resize mode.

        Pre-fix, ``_create_disassembly_tab`` only called
        ``h_header.setStretchLastSection(True)``, which per Qt semantics only
        stretches the final section (index 3, "Operands"). Column 1 was left
        at the header's default ``Interactive`` resize mode, so its width
        never grew to accommodate longer hex dumps.

        Args:
            qapp: The shared QApplication fixture.
        """
        panel = HexEditorPanel()
        try:
            table = panel._disasm_table
            assert table is not None
            header = table.horizontalHeader()
            assert header is not None
            assert header.sectionResizeMode(1) == QHeaderView.ResizeMode.ResizeToContents, (
                "Hex Bytes column (index 1) is not configured to resize to its contents"
            )
            qapp.processEvents()
        finally:
            panel.deleteLater()

    def test_m50_long_instruction_hex_dump_widens_column_and_is_not_clipped(self, qapp: QApplication) -> None:
        """A 15-byte instruction's hex dump must widen column 1 to fit its full text.

        Feeds ``_apply_disassemble_result`` a real result dict shaped exactly
        like the payload returned by ``HexEditorBridge.disassemble`` -- a
        15-byte-encoded instruction (the legal x86 maximum), which renders as
        a 44-character space-joined uppercase hex dump. Pre-fix, column 1
        stayed pinned near Qt's ~100px default ``Interactive`` width
        regardless of content length, so this dump was clipped; post-fix the
        ``ResizeToContents`` mode measured against the table's actual
        (Consolas 9pt) font must grow the column to fit it.

        Args:
            qapp: The shared QApplication fixture.
        """
        panel = HexEditorPanel()
        try:
            table = panel._disasm_table
            assert table is not None
            table.resize(760, 300)
            table.show()
            qapp.processEvents()

            result: list[dict[str, Any]] = [
                {
                    "address": 0x401000,
                    "bytes": _LONG_INSTRUCTION_HEX,
                    "mnemonic": "vpternlogd",
                    "operands": "zmm0, zmm1, zmm2, 0x1",
                    "size": 15,
                },
            ]
            panel._apply_disassemble_result(result)
            qapp.processEvents()

            hex_str = _spaced_hex_dump(_LONG_INSTRUCTION_HEX)
            assert len(hex_str) == 44, "test premise: a 15-byte dump is 44 characters"

            item = table.item(0, 1)
            assert item is not None
            assert item.text() == hex_str

            fm = QFontMetrics(table.font())
            text_width = fm.horizontalAdvance(hex_str)
            column_width = table.columnWidth(1)
            assert column_width >= text_width, (
                f"Hex Bytes column ({column_width}px) did not grow to fit the {text_width}px-wide "
                f"15-byte instruction dump; long instructions remain clipped"
            )
        finally:
            panel.deleteLater()

    def test_m50_short_instruction_dump_still_renders_correctly(self, qapp: QApplication) -> None:
        """A short 1-byte instruction dump renders exactly, unaffected by the resize fix.

        Guards against a resize-mode regression that would only satisfy the
        long-dump case by, e.g., always maximizing the column width
        regardless of content.

        Args:
            qapp: The shared QApplication fixture.
        """
        panel = HexEditorPanel()
        try:
            table = panel._disasm_table
            assert table is not None
            table.resize(760, 300)
            table.show()
            qapp.processEvents()

            result: list[dict[str, Any]] = [
                {
                    "address": 0x401005,
                    "bytes": "C3",
                    "mnemonic": "ret",
                    "operands": "",
                    "size": 1,
                },
            ]
            panel._apply_disassemble_result(result)
            qapp.processEvents()

            item = table.item(0, 1)
            assert item is not None
            assert item.text() == "C3"
        finally:
            panel.deleteLater()

    def test_m50_hex_bytes_cell_tooltip_exposes_full_untruncated_dump(self, qapp: QApplication) -> None:
        """Each Hex Bytes cell must carry a tooltip with the full dump as a fallback.

        Pre-fix, ``QTableWidgetItem(hex_str)`` was inserted with no tooltip,
        so a narrow viewport (side panel resized, splitter dragged) offered
        no way to recover the untruncated dump short of widening the column
        by hand. Post-fix, ``hex_item.setToolTip(hex_str)`` guarantees the
        full text is always available on hover regardless of column width.

        Args:
            qapp: The shared QApplication fixture.
        """
        panel = HexEditorPanel()
        try:
            table = panel._disasm_table
            assert table is not None

            result: list[dict[str, Any]] = [
                {
                    "address": 0x401010,
                    "bytes": _LONG_INSTRUCTION_HEX,
                    "mnemonic": "vpternlogd",
                    "operands": "zmm0, zmm1, zmm2, 0x1",
                    "size": 15,
                },
            ]
            panel._apply_disassemble_result(result)
            qapp.processEvents()

            hex_str = _spaced_hex_dump(_LONG_INSTRUCTION_HEX)
            item = table.item(0, 1)
            assert item is not None
            assert item.toolTip() == hex_str, "Hex Bytes cell does not expose the full dump via tooltip"
        finally:
            panel.deleteLater()
