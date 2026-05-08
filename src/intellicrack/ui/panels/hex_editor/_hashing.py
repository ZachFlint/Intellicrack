# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Hashing mixin for the hex editor panel."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Final, cast

from PyQt6.QtWidgets import (
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui._dialogs import show_warning
from intellicrack.ui.panels.hex_editor._widgets import CustomCrcDialog


_logger = get_logger(__name__)


_PE_CHECKSUM_OFFSET: Final[int] = 0x58
_PE_CHECKSUM_LEN: Final[int] = 4


class HashingMixin:
    """Mixin providing hash computation for the hex editor panel.

    All hash and PE-checksum work is delegated to the hexcore document so that the UI thread never has to materialise the full file in
    Python. The mixin only formats the returned values for display.
    """

    _document: Any | None
    document: Any | None
    _hex_widget: Any | None
    _hash_algo_combo: QComboBox | None
    _hash_result_label: QLabel | None
    _selection_start: int
    _selection_end: int
    _pe_checksum_status: QLabel | None
    state_holder: Any | None
    file_path: Path | None
    _custom_crc_worker: Any | None

    def _notify_state_data_modified_for_hashing(self, offset: int, length: int, *, source: str) -> None:
        """Forward a byte-region mutation event to the shared state holder if attached.

        Args:
            offset: Start byte offset of the affected range.
            length: Number of bytes affected.
            source: Loop-guard identifier so the caller is filtered out.
        """
        holder = self.state_holder
        if holder is None:
            return
        notify = getattr(holder, "notify_data_modified", None)
        if not callable(notify):
            return
        notify(offset, length, source=source)

    def _resolve_custom_crc_file_path(self) -> str | None:
        """Resolve the best file source for the custom CRC streaming worker.

        Prefers the panel's ``file_path`` attribute when present and
        readable; falls back to ``document.file_path()`` when the
        document exposes one. Returns ``None`` when the document is
        purely in-memory so the worker streams via the document API.

        Returns:
            str | None: Absolute path of an existing readable file, or
                ``None`` when the worker should stream via the
                document API.
        """
        candidates: list[str] = []
        panel_path = self.file_path
        if panel_path is not None:
            try:
                candidates.append(os.fspath(panel_path))
            except TypeError:
                _logger.debug("custom_crc_panel_path_unfsable", path_type=type(panel_path).__name__)
        document = self.document
        if document is not None:
            doc_path_fn = getattr(document, "file_path", None)
            if callable(doc_path_fn):
                try:
                    doc_path: object = doc_path_fn()
                except (OSError, RuntimeError, ValueError):
                    doc_path = None
                if isinstance(doc_path, str):
                    candidates.append(doc_path)
                elif doc_path is not None:
                    try:
                        candidates.append(os.fspath(cast("os.PathLike[str]", doc_path)))
                    except TypeError:
                        _logger.debug(
                            "custom_crc_doc_path_unfsable",
                            path_type=type(doc_path).__name__,
                        )
        for path_str in candidates:
            if not path_str:
                continue
            try:
                if Path(path_str).is_file():
                    return path_str
            except OSError:
                continue
        return None

    def _on_calculate_hash(self) -> None:
        """Calculate the hash of the current document via hexcore document.compute_hash."""
        if self.document is None or self._hash_algo_combo is None or self._hash_result_label is None:
            return
        algo = self._hash_algo_combo.currentText()
        try:
            result = self.document.compute_hash(algo)
        except (RuntimeError, OSError, ValueError, AttributeError) as exc:
            self._hash_result_label.setText(f"Error: {exc}")
            _logger.exception("hash_calculate_failed")
        else:
            self._hash_result_label.setText(f"{algo}: {result}")
            _logger.info("hash_calculated", algo=algo)

    def _on_custom_crc(self) -> None:
        """Open the custom CRC dialog wired to the streaming worker.

        The dialog never copies the document body onto the UI thread.
        It receives the file path (when one is resolvable) and the
        document handle; clicking Calculate spawns a worker that
        streams the bytes through ``compute_streaming_custom_crc`` in
        bounded chunks.
        """
        document = self.document
        if document is None:
            return
        try:
            doc_len: int = document.length()
        except (RuntimeError, OSError, ValueError, AttributeError) as exc:
            if isinstance(self, QWidget):
                show_warning(self, "Custom CRC", f"Failed to read document length:\n{exc}")
            return

        parent = self if isinstance(self, QWidget) else None
        dlg = CustomCrcDialog(
            file_path=self._resolve_custom_crc_file_path(),
            document=document,
            length=doc_len,
            parent=parent,
        )
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
        """Hash the current selection range via hexcore document.compute_hash_range."""
        if self.document is None or self._hash_algo_combo is None or self._hash_result_label is None:
            return

        sel_start: int = getattr(self, "_selection_start", -1)
        sel_end: int = getattr(self, "_selection_end", -1)
        if sel_start < 0 or sel_end < 0 or sel_end <= sel_start:
            self._hash_result_label.setText("No selection")
            return

        algo = self._hash_algo_combo.currentText()
        try:
            result = self.document.compute_hash_range(sel_start, sel_end, algo)
        except (RuntimeError, OSError, ValueError, AttributeError) as exc:
            self._hash_result_label.setText(f"Error: {exc}")
            _logger.exception("hash_selection_failed")
        else:
            self._hash_result_label.setText(
                f"{algo} (0x{sel_start:X}-0x{sel_end:X}): {result}",
            )

    def _on_verify_pe_checksum(self) -> None:
        """Verify the PE checksum via hexcore document.verify_pe_checksum."""
        if self.document is None:
            return

        try:
            info = self.document.verify_pe_checksum()
        except (RuntimeError, OSError, ValueError, AttributeError) as exc:
            if self._pe_checksum_status is not None:
                self._pe_checksum_status.setText(f"Error: {exc}")
            _logger.exception("pe_checksum_verify_failed")
            return

        if self._pe_checksum_status is None:
            return

        if not isinstance(info, dict):
            self._pe_checksum_status.setText("Verification unavailable")
            return
        info_dict = cast("dict[str, Any]", info)
        if info_dict.get("valid") is False and info_dict.get("reason"):
            self._pe_checksum_status.setText(str(info_dict["reason"]))
            return

        stored = info_dict.get("stored")
        calculated = info_dict.get("calculated", info_dict.get("expected"))
        if not isinstance(stored, int) or not isinstance(calculated, int):
            self._pe_checksum_status.setText("Verification unavailable")
            return

        if stored == calculated:
            self._pe_checksum_status.setText(f"Valid: 0x{stored:08X}")
        else:
            self._pe_checksum_status.setText(
                f"Invalid: stored=0x{stored:08X}, expected=0x{calculated:08X}",
            )

    def _on_repair_pe_checksum(self) -> None:
        """Repair the PE checksum via hexcore document.repair_pe_checksum."""
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
            self.document.repair_pe_checksum()
        except (RuntimeError, OSError, ValueError, AttributeError) as exc:
            _logger.exception("pe_checksum_repair_failed")
            show_warning(parent, "Repair Failed", str(exc))
            return

        self._notify_state_data_modified_for_hashing(
            _PE_CHECKSUM_OFFSET,
            _PE_CHECKSUM_LEN,
            source="hex-editor.hashing.repair_pe_checksum",
        )

        if self._pe_checksum_status is not None:
            try:
                info = self.document.verify_pe_checksum()
            except (RuntimeError, OSError, ValueError, AttributeError) as exc:
                self._pe_checksum_status.setText(f"Repaired (verify failed: {exc})")
            else:
                if isinstance(info, dict):
                    info_dict = cast("dict[str, Any]", info)
                    calculated = info_dict.get("calculated", info_dict.get("stored"))
                    if isinstance(calculated, int):
                        self._pe_checksum_status.setText(f"Repaired: 0x{calculated:08X}")
                    else:
                        self._pe_checksum_status.setText("Repaired")
                else:
                    self._pe_checksum_status.setText("Repaired")

        if self._hex_widget is not None:
            update_fn = getattr(self._hex_widget, "_update_viewport", None)
            if callable(update_fn):
                update_fn()

        _logger.info("pe_checksum_repaired")
