# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Disassembly mixin for the hex editor panel."""

from __future__ import annotations

from typing import Any, cast

from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.ui.panels.hex_editor._base import (
    DEFAULT_DISASM_COUNT,
    MAX_INSN_BYTES,
    HexDisassembler_cls,
    disassembler_available,
    logger,
)


class DisassemblyMixin:
    """Mixin providing disassembly functionality for the hex editor panel."""

    _document: Any | None
    _hex_widget: Any | None
    _disasm_arch_combo: QComboBox | None
    _disasm_mode_combo: QComboBox | None
    _disasm_count_spin: QSpinBox | None
    _disasm_follow_cursor: QCheckBox | None
    _disasm_table: QTableWidget | None

    def goto_offset(self, offset: int) -> None: ...

    def _create_disassembly_tab(self) -> QWidget:
        """Create the Disassembly side panel tab widget.

        Returns:
            QWidget: Container widget with disassembly toolbar and table.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(2, 2, 2, 2)

        toolbar_row = QHBoxLayout()

        self._disasm_arch_combo = QComboBox()
        self._disasm_arch_combo.addItems([
            "Auto Detect", "x86", "ARM", "ARM64", "MIPS", "PPC", "SPARC", "SystemZ", "RISC-V",
        ])
        toolbar_row.addWidget(self._disasm_arch_combo)

        self._disasm_mode_combo = QComboBox()
        self._disasm_mode_combo.addItems(["64-bit", "32-bit", "16-bit", "ARM", "Thumb"])
        toolbar_row.addWidget(self._disasm_mode_combo)

        self._disasm_count_spin = QSpinBox()
        self._disasm_count_spin.setRange(1, 500)
        self._disasm_count_spin.setValue(DEFAULT_DISASM_COUNT)
        self._disasm_count_spin.setFixedWidth(60)
        toolbar_row.addWidget(self._disasm_count_spin)

        self._disasm_follow_cursor = QCheckBox("Follow Cursor")
        self._disasm_follow_cursor.setChecked(True)
        toolbar_row.addWidget(self._disasm_follow_cursor)

        disasm_btn = QPushButton("Disassemble")
        disasm_btn.clicked.connect(self._on_disassemble)
        toolbar_row.addWidget(disasm_btn)
        toolbar_row.addStretch()

        layout.addLayout(toolbar_row)

        self._disasm_table = QTableWidget(0, 4)
        self._disasm_table.setHorizontalHeaderLabels(["Address", "Hex Bytes", "Mnemonic", "Operands"])
        self._disasm_table.setSelectionBehavior(self._disasm_table.SelectionBehavior.SelectRows)
        self._disasm_table.setEditTriggers(self._disasm_table.EditTrigger.NoEditTriggers)
        self._disasm_table.setAlternatingRowColors(True)
        table_font = self._disasm_table.font()
        table_font.setFamily("Consolas")
        table_font.setPointSize(9)
        self._disasm_table.setFont(table_font)
        h_header = self._disasm_table.horizontalHeader()
        if h_header is not None:
            h_header.setStretchLastSection(True)
        v_header = self._disasm_table.verticalHeader()
        if v_header is not None:
            v_header.setVisible(False)
        self._disasm_table.cellDoubleClicked.connect(self._on_disasm_row_double_clicked)
        layout.addWidget(self._disasm_table)

        return container

    def _on_disassemble(self) -> None:
        """Disassemble bytes at the current cursor offset and populate the table."""
        if self._document is None or self._disasm_table is None:
            return

        if not disassembler_available or HexDisassembler_cls is None:
            logger.debug("disasm_capstone_unavailable")
            return

        count = self._disasm_count_spin.value() if self._disasm_count_spin is not None else DEFAULT_DISASM_COUNT
        cursor_offset = 0
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)

        read_len = count * MAX_INSN_BYTES
        try:
            doc_len: int = self._document.length()
            available = doc_len - cursor_offset
            if available <= 0:
                return
            read_len = min(read_len, available)
            raw: object = self._document.read(cursor_offset, read_len)
            if isinstance(raw, (list, bytearray)):
                data = bytes(cast("list[int]", raw) if isinstance(raw, list) else raw)
            elif isinstance(raw, bytes):
                data = raw
            else:
                return
        except (AttributeError, ValueError) as exc:
            logger.debug("disasm_read_failed", error=str(exc))
            return

        disassembler = HexDisassembler_cls()
        if not disassembler.available:
            logger.debug("disasm_capstone_unavailable")
            return

        arch_text = self._disasm_arch_combo.currentText() if self._disasm_arch_combo is not None else "Auto Detect"
        mode_text = self._disasm_mode_combo.currentText() if self._disasm_mode_combo is not None else "64-bit"

        mode_map: dict[str, str] = {
            "64-bit": "64",
            "32-bit": "32",
            "16-bit": "16",
            "ARM": "arm",
            "Thumb": "thumb",
        }
        mode_str = mode_map.get(mode_text, "64")

        if arch_text == "Auto Detect":
            arch_str, mode_str = disassembler.auto_detect_arch(data)
        else:
            arch_map: dict[str, str] = {
                "x86": "x86",
                "ARM": "arm",
                "ARM64": "arm64",
                "MIPS": "mips",
                "PPC": "ppc",
                "SPARC": "sparc",
                "SystemZ": "systemz",
                "RISC-V": "riscv",
            }
            arch_str = arch_map.get(arch_text, "x86")

        try:
            instructions = disassembler.disassemble(
                data, base_addr=cursor_offset, arch=arch_str, mode=mode_str, count=count
            )
        except (RuntimeError, ValueError) as exc:
            logger.debug("disasm_failed", error=str(exc))
            return

        self._disasm_table.setRowCount(0)
        for insn in instructions:
            row = self._disasm_table.rowCount()
            self._disasm_table.insertRow(row)
            hex_str = " ".join(f"{b:02x}" for b in insn.raw_bytes)
            self._disasm_table.setItem(row, 0, QTableWidgetItem(f"0x{insn.address:08X}"))
            self._disasm_table.setItem(row, 1, QTableWidgetItem(hex_str))
            self._disasm_table.setItem(row, 2, QTableWidgetItem(insn.mnemonic))
            self._disasm_table.setItem(row, 3, QTableWidgetItem(insn.op_str))

        logger.debug("disasm_complete", instruction_count=len(instructions))

    def _on_cursor_moved_disasm(self, offset: int) -> None:
        """Auto-disassemble when Follow Cursor is active.

        Args:
            offset: New cursor byte offset.
        """
        _ = offset
        if self._disasm_follow_cursor is not None and self._disasm_follow_cursor.isChecked():
            self._on_disassemble()

    def _on_disasm_row_double_clicked(self, row: int, column: int) -> None:
        """Navigate the hex view to the instruction address on double-click.

        Args:
            row: The double-clicked row index.
            column: The double-clicked column index.
        """
        _ = column
        if self._disasm_table is None:
            return
        addr_item = self._disasm_table.item(row, 0)
        if addr_item is None:
            return
        addr_text = addr_item.text()
        try:
            offset = int(addr_text, 16)
        except ValueError:
            pass
        else:
            self.goto_offset(offset)
