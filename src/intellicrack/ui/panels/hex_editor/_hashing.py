# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Hashing mixin for the hex editor panel."""

from __future__ import annotations

from typing import Any

from PyQt6.QtWidgets import QComboBox, QLabel, QMessageBox, QWidget

from intellicrack.ui.panels.hex_editor._base import compute_hash, logger
from intellicrack.ui.panels.hex_editor._widgets import CustomCrcDialog


class HashingMixin:
    """Mixin providing hash computation for the hex editor panel."""

    _document: Any | None
    document: Any | None
    _hash_algo_combo: QComboBox | None
    _hash_result_label: QLabel | None

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
