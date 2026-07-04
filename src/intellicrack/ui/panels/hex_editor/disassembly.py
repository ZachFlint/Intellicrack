# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Disassembly mixin for the hex editor panel."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final, cast

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.dialogs_helpers import show_warning
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged
from intellicrack.ui.panels.hex_editor.base import DEFAULT_DISASM_COUNT, MAX_INSN_BYTES


if TYPE_CHECKING:
    from intellicrack.bridges.hex_editor import HexEditorBridge


_logger = get_logger(__name__)


_LAYOUT_MARGIN: Final[int] = 2
_SPIN_WIDTH: Final[int] = 60
_FOLLOW_CURSOR_DEBOUNCE_MS: Final[int] = 150


class DisassemblyMixin:
    """Mixin providing disassembly functionality for the hex editor panel."""

    _document: Any | None
    document: Any | None
    _hex_widget: Any | None
    _disasm_arch_combo: QComboBox | None
    _disasm_mode_combo: QComboBox | None
    _disasm_count_spin: QSpinBox | None
    _disasm_follow_cursor: QCheckBox | None
    _disasm_table: QTableWidget | None
    _bridge: HexEditorBridge | None
    _disasm_follow_timer: QTimer | None
    _disasm_pending_offset: int | None
    _disasm_last_dispatched_offset: int | None
    _disasm_in_flight: bool

    def goto_offset(self, offset: int) -> None:
        """Navigate the hex widget to the given byte offset.

        Args:
            offset: Absolute byte offset within the active document.
        """
        if self._hex_widget is None:
            return
        goto_fn = getattr(self._hex_widget, "goto_offset", None)
        if callable(goto_fn):
            goto_fn(offset)

    def _create_disassembly_tab(self) -> QWidget:
        """Create the Disassembly side panel tab widget.

        Returns:
            QWidget: Container widget with disassembly toolbar and table.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_LAYOUT_MARGIN, _LAYOUT_MARGIN, _LAYOUT_MARGIN, _LAYOUT_MARGIN)

        toolbar_row = QHBoxLayout()

        self._disasm_arch_combo = QComboBox()
        self._disasm_arch_combo.addItems([
            "Auto Detect",
            "x86",
            "ARM",
            "ARM64",
            "MIPS",
            "PPC",
            "SPARC",
            "SystemZ",
            "RISC-V",
        ])
        toolbar_row.addWidget(self._disasm_arch_combo)

        self._disasm_mode_combo = QComboBox()
        self._disasm_mode_combo.addItems(["64-bit", "32-bit", "16-bit", "ARM", "Thumb"])
        toolbar_row.addWidget(self._disasm_mode_combo)

        self._disasm_count_spin = QSpinBox()
        self._disasm_count_spin.setRange(1, 500)
        self._disasm_count_spin.setValue(DEFAULT_DISASM_COUNT)
        self._disasm_count_spin.setFixedWidth(_SPIN_WIDTH)
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
            h_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            h_header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            h_header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            h_header.setStretchLastSection(True)
        v_header = self._disasm_table.verticalHeader()
        if v_header is not None:
            v_header.setVisible(False)
        self._disasm_table.cellDoubleClicked.connect(self._on_disasm_row_double_clicked)
        layout.addWidget(self._disasm_table)

        parent_obj = self if isinstance(self, QWidget) else None
        timer = QTimer(parent_obj)
        timer.setSingleShot(True)
        timer.setInterval(_FOLLOW_CURSOR_DEBOUNCE_MS)
        timer.timeout.connect(self._on_follow_cursor_debounced)
        self._disasm_follow_timer = timer
        self._disasm_pending_offset = None
        self._disasm_last_dispatched_offset = None
        self._disasm_in_flight = False

        return container

    def _on_disassemble(self) -> None:
        """Disassemble bytes at the current cursor offset and populate the table.

        Routes the request through :meth:`HexEditorBridge.disassemble` via :func:`run_bridge_coroutine_logged` so the operation runs on the
        persistent bridge event loop and the Qt main thread stays responsive. Results and errors are delivered back via signal callbacks.
        """
        if self.document is None or self._disasm_table is None:
            return

        bridge = getattr(self, "_bridge", None)
        if bridge is None:
            parent = self if isinstance(self, QWidget) else None
            show_warning(
                parent,
                "Hex Editor Bridge Unavailable",
                "The hex editor bridge is not attached to this panel.",
            )
            return

        count = self._disasm_count_spin.value() if self._disasm_count_spin is not None else DEFAULT_DISASM_COUNT
        cursor_offset = 0
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)

        try:
            doc_len: int = self.document.length()
        except (AttributeError, ValueError):
            _logger.exception("disasm_doc_length_failed")
            return
        if doc_len - cursor_offset <= 0:
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
        arch_map: dict[str, str] = {
            "Auto Detect": "auto",
            "x86": "x86",
            "ARM": "arm",
            "ARM64": "arm64",
            "MIPS": "mips",
            "PPC": "ppc",
            "SPARC": "sparc",
            "SystemZ": "systemz",
            "RISC-V": "riscv",
        }
        arch_str = arch_map.get(arch_text, "auto")

        binary_path = getattr(self, "file_path", None)
        binary_path_str = str(binary_path) if binary_path is not None else "<in-memory>"
        _logger.info(
            "disasm_invoke",
            binary_path=binary_path_str,
            offset=cursor_offset,
            arch=arch_str,
            mode=mode_str,
            count=count,
            read_window=count * MAX_INSN_BYTES,
        )
        self._disasm_in_flight = True
        self._disasm_last_dispatched_offset = cursor_offset
        parent_obj = self if isinstance(self, QWidget) else None
        run_bridge_coroutine_logged(
            bridge.disassemble(cursor_offset, count, arch_str, mode_str),
            on_success=self._on_disassemble_success,
            on_error=self._on_disassemble_error,
            parent=parent_obj,
            event="hex_editor_disassemble",
            logger=_logger,
            offset=cursor_offset,
            count=count,
            arch=arch_str,
            mode=mode_str,
        )

    def _apply_disassemble_result(self, result: object) -> None:
        """Render ``result`` into the disassembly table.

        Args:
            result: ``list[dict]`` payload returned by
                :meth:`HexEditorBridge.disassemble`. Each dict contains
                ``address``, ``bytes`` (hex string), ``mnemonic``,
                ``operands``, and ``size`` keys.
        """
        if self._disasm_table is None:
            return
        if not isinstance(result, list):
            _logger.warning("disasm_unexpected_result_type", result_type=type(result).__name__)
            return

        instructions = cast("list[dict[str, Any]]", result)
        self._disasm_table.setRowCount(0)
        for insn in instructions:
            address_val = insn.get("address", 0)
            bytes_hex = str(insn.get("bytes", ""))
            mnemonic = str(insn.get("mnemonic", ""))
            operands = str(insn.get("operands", ""))
            try:
                address_int = int(address_val)
            except (TypeError, ValueError) as exc:
                _logger.debug(
                    "disasm_address_parse_fallback",
                    raw_address=address_val,
                    raw_address_type=type(address_val).__name__,
                    error_type=type(exc).__name__,
                    exc_info=True,
                )
                address_int = 0
            hex_str = " ".join(bytes_hex[i : i + 2] for i in range(0, len(bytes_hex), 2))
            row = self._disasm_table.rowCount()
            self._disasm_table.insertRow(row)
            self._disasm_table.setItem(row, 0, QTableWidgetItem(f"0x{address_int:08X}"))
            hex_item = QTableWidgetItem(hex_str)
            hex_item.setToolTip(hex_str)
            self._disasm_table.setItem(row, 1, hex_item)
            self._disasm_table.setItem(row, 2, QTableWidgetItem(mnemonic))
            self._disasm_table.setItem(row, 3, QTableWidgetItem(operands))

        _logger.info("disasm_complete", instruction_count=len(instructions))

    def _on_disassemble_success(self, result: object) -> None:
        """Populate the disassembly table from the bridge result.

        Args:
            result: ``list[dict]`` payload returned by
                :meth:`HexEditorBridge.disassemble`. Each dict contains
                ``address``, ``bytes`` (hex string), ``mnemonic``,
                ``operands``, and ``size`` keys.
        """
        self._disasm_in_flight = False
        try:
            self._apply_disassemble_result(result)
        finally:
            self._flush_pending_follow_cursor()

    def _on_disassemble_error(self, exc: object) -> None:
        """Log a disassembly failure raised by the bridge.

        Args:
            exc: Exception object emitted by the bridge worker.
        """
        self._disasm_in_flight = False
        _logger.warning("disasm_failed", error_type=type(exc).__name__, error=str(exc))
        self._flush_pending_follow_cursor()

    def _on_cursor_moved_disasm(self, offset: int) -> None:
        """Schedule a debounced auto-disassemble when Follow Cursor is active.

        The bridge call is intentionally not invoked here; instead the
        offset is parked in ``_disasm_pending_offset`` and a single-shot
        timer is restarted. When the timer fires we dispatch at most one
        disassemble for the most recent offset, suppress dispatch if the
        offset matches the last successfully dispatched value, and defer
        dispatch entirely while a previous bridge call is still in
        flight. This eliminates the spam where holding an arrow key
        triggered hundreds of bridge calls per second.

        Args:
            offset: New cursor byte offset reported by the hex widget.
        """
        if self._disasm_follow_cursor is None or not self._disasm_follow_cursor.isChecked():
            return
        self._disasm_pending_offset = offset
        if self._disasm_follow_timer is None:
            self._on_follow_cursor_debounced()
            return
        self._disasm_follow_timer.start()

    def _on_follow_cursor_debounced(self) -> None:
        """Dispatch the most recent pending follow-cursor offset, with guards.

        Skip dispatch when:

        - a previous bridge call is still in flight (the success/error
          handler will re-flush via :meth:`_flush_pending_follow_cursor`),
        - no offset is pending,
        - the pending offset equals the last dispatched offset (the
          cursor moved and came back to the same byte; the existing
          table is still correct),
        - Follow Cursor was unchecked between debounce arming and fire.
        """
        if self._disasm_follow_cursor is None or not self._disasm_follow_cursor.isChecked():
            self._disasm_pending_offset = None
            return
        if self._disasm_in_flight:
            return
        offset = self._disasm_pending_offset
        if offset is None:
            return
        self._disasm_pending_offset = None
        if offset == self._disasm_last_dispatched_offset:
            return
        self._on_disassemble()

    def _flush_pending_follow_cursor(self) -> None:
        """Re-arm the debounce timer if a newer offset arrived during a bridge call.

        Called from both completion handlers so a follow-cursor request that landed while a disassemble was in flight is not silently
        dropped.
        """
        if self._disasm_pending_offset is None:
            return
        if self._disasm_follow_timer is None:
            self._on_follow_cursor_debounced()
            return
        self._disasm_follow_timer.start()

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
            _logger.warning("hex_editor_disasm_row_invalid_address", input_text=addr_text)
        else:
            self.goto_offset(offset)
