# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Hashing mixin for the hex editor panel."""

from __future__ import annotations

from typing import Any, Final

from PyQt6.QtWidgets import (
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QWidget,
)

from intellicrack.ui.panels.hex_editor._base import compute_hash, logger
from intellicrack.ui.panels.hex_editor._widgets import CustomCrcDialog


_PE_MIN_HEADER_SIZE: Final[int] = 0x40
_PE_LFANEW_OFFSET: Final[int] = 0x3C
_PE_CHECKSUM_RELATIVE_OFFSET: Final[int] = 0x58
_PE_CHECKSUM_FIELD_SIZE: Final[int] = 4
_PE_CHECKSUM_MASK_16: Final[int] = 0xFFFF
_PE_CHECKSUM_MASK_32: Final[int] = 0xFFFFFFFF
_PE_WORD_SHIFT: Final[int] = 16
_PE_WORD_SIZE: Final[int] = 2


class HashingMixin:
    """Mixin providing hash computation for the hex editor panel."""

    _document: Any | None
    document: Any | None
    _hex_widget: Any | None
    _hash_algo_combo: QComboBox | None
    _hash_result_label: QLabel | None
    _selection_start: int
    _selection_end: int
    _pe_checksum_status: QLabel | None

    def _on_calculate_hash(self) -> None:
        """Calculate the hash of the current document and display the result."""
        if self.document is None or self._hash_algo_combo is None or self._hash_result_label is None:
            return
        algo = self._hash_algo_combo.currentText()
        try:
            doc_len: int = self.document.length()
            raw: bytes | bytearray | list[int] = self.document.read(0, doc_len)
            data = raw if isinstance(raw, bytes) else bytes(raw)
            result = compute_hash(algo, data)
        except (ValueError, AttributeError, TypeError) as exc:
            self._hash_result_label.setText(f"Error: {exc}")
            logger.debug("hash_calculate_failed", error=str(exc))
        else:
            self._hash_result_label.setText(f"{algo}: {result}")
            logger.info("hash_calculated", algo=algo)

    def _on_custom_crc(self) -> None:
        """Open the custom CRC dialog with the current document data."""
        if self.document is None:
            return
        try:
            doc_len: int = self.document.length()
            raw: bytes | bytearray | list[int] = self.document.read(0, doc_len)
            data = raw if isinstance(raw, bytes) else bytes(raw)
        except (ValueError, AttributeError, TypeError) as exc:
            if isinstance(self, QWidget):
                QMessageBox.warning(self, "Custom CRC", f"Failed to read document data:\n{exc}")
        else:
            parent = self if isinstance(self, QWidget) else None
            dlg = CustomCrcDialog(data, parent)
            dlg.exec()

    def _create_pe_checksum_group(self) -> QGroupBox:
        """Create the PE Checksum verification/repair group box.

        Returns:
            QGroupBox: Container with verify and repair buttons and status label.
        """
        box = QGroupBox("PE Checksum")
        layout = QHBoxLayout(box)
        self._pe_checksum_status = QLabel("Not verified")
        layout.addWidget(self._pe_checksum_status)
        verify_btn = QPushButton("Verify")
        verify_btn.clicked.connect(self._on_verify_pe_checksum)
        layout.addWidget(verify_btn)
        repair_btn = QPushButton("Repair")
        repair_btn.clicked.connect(self._on_repair_pe_checksum)
        layout.addWidget(repair_btn)
        return box

    def _on_hash_selection(self) -> None:
        """Calculate the hash of the current selection range."""
        if self.document is None or self._hash_algo_combo is None or self._hash_result_label is None:
            return

        sel_start: int = getattr(self, "_selection_start", -1)
        sel_end: int = getattr(self, "_selection_end", -1)
        if sel_start < 0 or sel_end < 0 or sel_end <= sel_start:
            self._hash_result_label.setText("No selection")
            return

        algo = self._hash_algo_combo.currentText()
        try:
            raw: bytes | bytearray | list[int] = self.document.read(sel_start, sel_end - sel_start)
            data = raw if isinstance(raw, bytes) else bytes(raw)
            result = compute_hash(algo, data)
        except (ValueError, AttributeError, TypeError) as exc:
            self._hash_result_label.setText(f"Error: {exc}")
            logger.debug("hash_selection_failed", error=str(exc))
        else:
            self._hash_result_label.setText(
                f"{algo} (0x{sel_start:X}-0x{sel_end:X}): {result}",
            )

    def _on_verify_pe_checksum(self) -> None:
        """Verify the PE checksum of the current document."""
        if self.document is None:
            return

        try:
            doc_len: int = self.document.length()
            raw: bytes | bytearray | list[int] = self.document.read(0, doc_len)
            data = raw if isinstance(raw, bytes) else bytes(raw)
        except (ValueError, AttributeError, TypeError) as exc:
            if self._pe_checksum_status is not None:
                self._pe_checksum_status.setText(f"Error: {exc}")
            return

        if len(data) < _PE_MIN_HEADER_SIZE or data[:2] != b"MZ":
            if self._pe_checksum_status is not None:
                self._pe_checksum_status.setText("Not a PE file")
            return

        e_lfanew = int.from_bytes(data[_PE_LFANEW_OFFSET:_PE_MIN_HEADER_SIZE], "little")
        if e_lfanew + _PE_CHECKSUM_RELATIVE_OFFSET + _PE_CHECKSUM_FIELD_SIZE > len(data):
            if self._pe_checksum_status is not None:
                self._pe_checksum_status.setText("Invalid PE header")
            return

        checksum_offset = e_lfanew + _PE_CHECKSUM_RELATIVE_OFFSET
        stored = int.from_bytes(data[checksum_offset : checksum_offset + _PE_CHECKSUM_FIELD_SIZE], "little")
        calculated = self._compute_pe_checksum(data, checksum_offset)

        if self._pe_checksum_status is not None:
            if stored == calculated:
                self._pe_checksum_status.setText(
                    f"Valid: 0x{stored:08X}",
                )
            else:
                self._pe_checksum_status.setText(
                    f"Invalid: stored=0x{stored:08X}, expected=0x{calculated:08X}",
                )

    def _on_repair_pe_checksum(self) -> None:
        """Repair the PE checksum of the current document."""
        if self.document is None:
            return

        parent = self if isinstance(self, QWidget) else None
        reply = QMessageBox.question(
            parent,
            "Repair PE Checksum",
            "Overwrite the PE checksum field with the correct value?",
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            doc_len: int = self.document.length()
            raw: bytes | bytearray | list[int] = self.document.read(0, doc_len)
            data = raw if isinstance(raw, bytes) else bytes(raw)
        except (ValueError, AttributeError, TypeError) as exc:
            QMessageBox.warning(parent, "Repair Failed", str(exc))
            return

        if len(data) < _PE_MIN_HEADER_SIZE or data[:2] != b"MZ":
            QMessageBox.warning(parent, "Repair Failed", "Not a PE file.")
            return

        e_lfanew = int.from_bytes(data[_PE_LFANEW_OFFSET:_PE_MIN_HEADER_SIZE], "little")
        checksum_offset = e_lfanew + _PE_CHECKSUM_RELATIVE_OFFSET
        if checksum_offset + _PE_CHECKSUM_FIELD_SIZE > len(data):
            QMessageBox.warning(parent, "Repair Failed", "Invalid PE header.")
            return

        calculated = self._compute_pe_checksum(data, checksum_offset)
        checksum_bytes = calculated.to_bytes(_PE_CHECKSUM_FIELD_SIZE, "little")
        try:
            self.document.write_bytes(checksum_offset, checksum_bytes)
        except (AttributeError, ValueError) as exc:
            QMessageBox.warning(parent, "Repair Failed", str(exc))
            return

        if self._pe_checksum_status is not None:
            self._pe_checksum_status.setText(f"Repaired: 0x{calculated:08X}")

        if self._hex_widget is not None:
            update_fn = getattr(self._hex_widget, "_update_viewport", None)
            if callable(update_fn):
                update_fn()

        logger.info("pe_checksum_repaired", value=calculated)

    @staticmethod
    def _compute_pe_checksum(data: bytes, checksum_offset: int) -> int:
        """Compute the PE file checksum using the Windows algorithm.

        Sums all 16-bit words in the file, skipping the 4-byte CheckSum
        field, folding carries into the lower 16 bits, and adding the
        file length to the final result.

        Args:
            data: Complete file contents.
            checksum_offset: Byte offset of the PE CheckSum field.

        Returns:
            int: Computed PE checksum value.
        """
        checksum = 0
        size = len(data)
        skip_start = checksum_offset
        skip_end = checksum_offset + _PE_CHECKSUM_FIELD_SIZE

        i = 0
        while i < size - 1:
            if skip_start <= i < skip_end:
                i += _PE_WORD_SIZE
                continue
            word = data[i] | (data[i + 1] << 8)
            checksum += word
            checksum = (checksum & _PE_CHECKSUM_MASK_16) + (checksum >> _PE_WORD_SHIFT)
            i += _PE_WORD_SIZE

        if i < size and i not in range(skip_start, skip_end):
            checksum += data[i]
            checksum = (checksum & _PE_CHECKSUM_MASK_16) + (checksum >> _PE_WORD_SHIFT)

        checksum = (checksum & _PE_CHECKSUM_MASK_16) + (checksum >> _PE_WORD_SHIFT)
        checksum += size
        return checksum & _PE_CHECKSUM_MASK_32
