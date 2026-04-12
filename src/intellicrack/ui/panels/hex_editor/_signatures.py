# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Non-YARA signature scanning mixin for the hex editor panel."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Final, cast, override

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.ui.panels.hex_editor._base import logger


_MAX_ENTRY_POINT_BYTES: Final[int] = 256
_NDB_LINE_FIELDS: Final[int] = 4
_HDB_LINE_FIELDS: Final[int] = 3


class SignatureScanWorker(QThread):
    """Background worker for scanning documents against signature databases.

    Supports DIE-style JSON databases, ClamAV .ndb/.hdb files, and
    custom JSON signature formats.

    Args:
        doc_data: Full document contents as bytes.
        db_type: Database format (``"die"``, ``"clamav"``, ``"custom"``).
        db_path: Path to the signature database file.
        parent: Parent QObject.

    Attributes:
        scan_finished: Emitted with list of match dicts on success.
        scan_error: Emitted with error message on failure.
    """

    scan_finished: pyqtSignal = pyqtSignal(list)
    scan_error: pyqtSignal = pyqtSignal(str)

    def __init__(
        self,
        doc_data: bytes,
        db_type: str,
        db_path: str,
        parent: QThread | None = None,
    ) -> None:
        super().__init__(parent)
        self._doc_data = doc_data
        self._db_type = db_type
        self._db_path = db_path

    @override
    def run(self) -> None:
        """Execute the signature scan in the background thread."""
        try:
            if self._db_type == "die":
                results = self._scan_die()
            elif self._db_type == "clamav":
                results = self._scan_clamav()
            else:
                results = self._scan_custom()
            self.scan_finished.emit(results)
        except (OSError, json.JSONDecodeError, ValueError, KeyError) as exc:
            self.scan_error.emit(str(exc))

    def _scan_die(self) -> list[dict[str, Any]]:
        """Scan using a DIE-style JSON signature database.

        Returns:
            list[dict[str, Any]]: List of match dicts with name, type,
                version, and offset keys.
        """
        db_text = Path(self._db_path).read_text(encoding="utf-8")
        db_entries: list[dict[str, Any]] = json.loads(db_text)
        results: list[dict[str, Any]] = []

        ep_bytes = self._doc_data[:_MAX_ENTRY_POINT_BYTES]

        for entry in db_entries:
            patterns: list[Any] = list(entry.get("patterns", []))
            sig_name = str(entry.get("name", "unknown"))
            sig_type = str(entry.get("type", "unknown"))
            sig_version = str(entry.get("version", ""))

            for pattern_info in patterns:
                if isinstance(pattern_info, str):
                    hex_pattern = pattern_info
                    scan_offset = "ep"
                elif isinstance(pattern_info, dict):
                    hex_pattern = str(pattern_info.get("pattern", ""))
                    scan_offset = str(pattern_info.get("offset", "ep"))
                else:
                    continue

                try:
                    pattern_bytes = bytes.fromhex(hex_pattern.replace(" ", ""))
                except ValueError:
                    continue

                if scan_offset == "ep":
                    idx = ep_bytes.find(pattern_bytes)
                    if idx >= 0:
                        results.append({
                            "name": sig_name,
                            "type": sig_type,
                            "version": sig_version,
                            "offset": idx,
                            "details": f"Entry point match at +{idx}",
                        })
                elif scan_offset == "any":
                    idx = self._doc_data.find(pattern_bytes)
                    if idx >= 0:
                        results.append({
                            "name": sig_name,
                            "type": sig_type,
                            "version": sig_version,
                            "offset": idx,
                            "details": f"Full scan match at 0x{idx:X}",
                        })
                else:
                    try:
                        fixed_offset = int(scan_offset, 0)
                    except ValueError:
                        continue
                    if fixed_offset + len(pattern_bytes) <= len(self._doc_data):
                        region = self._doc_data[fixed_offset : fixed_offset + len(pattern_bytes)]
                        if region == pattern_bytes:
                            results.append({
                                "name": sig_name,
                                "type": sig_type,
                                "version": sig_version,
                                "offset": fixed_offset,
                                "details": f"Fixed offset match at 0x{fixed_offset:X}",
                            })

        return results

    def _scan_clamav(self) -> list[dict[str, Any]]:
        """Scan using ClamAV .ndb or .hdb signature files.

        Returns:
            list[dict[str, Any]]: List of match dicts with malware_name,
                sig_type, and offset keys.
        """
        db_path = Path(self._db_path)
        suffix = db_path.suffix.lower()
        lines = db_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if suffix == ".hdb":
            return self._scan_clamav_hdb(lines)
        return self._scan_clamav_ndb(lines)

    def _scan_clamav_hdb(self, lines: list[str]) -> list[dict[str, Any]]:
        """Scan ClamAV hash-based (.hdb) signatures.

        Args:
            lines: Lines from the .hdb signature file.

        Returns:
            list[dict[str, Any]]: Match results.
        """
        file_md5 = hashlib.md5(self._doc_data).hexdigest()  # noqa: S324
        file_size = len(self._doc_data)
        results: list[dict[str, Any]] = []
        for line in lines:
            parts = line.strip().split(":")
            if len(parts) < _HDB_LINE_FIELDS:
                continue
            sig_md5 = parts[0].lower()
            sig_name = parts[2]
            try:
                sig_size = int(parts[1])
            except ValueError:
                continue
            if sig_md5 == file_md5 and sig_size == file_size:
                results.append({
                    "name": sig_name,
                    "type": "hash",
                    "version": "",
                    "offset": 0,
                    "details": f"MD5 hash match (size={file_size})",
                })
        return results

    def _scan_clamav_ndb(self, lines: list[str]) -> list[dict[str, Any]]:
        """Scan ClamAV pattern-based (.ndb) signatures.

        Args:
            lines: Lines from the .ndb signature file.

        Returns:
            list[dict[str, Any]]: Match results.
        """
        results: list[dict[str, Any]] = []
        for line in lines:
            parts = line.strip().split(":")
            if len(parts) < _NDB_LINE_FIELDS:
                continue
            sig_name = parts[0]
            sig_offset_spec = parts[2]
            sig_hex = parts[3]
            try:
                clean_hex = sig_hex.replace("*", "").replace("?", "")
                if not clean_hex:
                    continue
                pattern_bytes = bytes.fromhex(clean_hex)
            except ValueError:
                continue
            if sig_offset_spec == "*":
                idx = self._doc_data.find(pattern_bytes)
                if idx >= 0:
                    results.append({
                        "name": sig_name,
                        "type": "ndb",
                        "version": "",
                        "offset": idx,
                        "details": f"Pattern match at 0x{idx:X}",
                    })
            elif sig_offset_spec == "EP+0" and self._doc_data[: len(pattern_bytes)] == pattern_bytes:
                results.append({
                    "name": sig_name,
                    "type": "ndb",
                    "version": "",
                    "offset": 0,
                    "details": "Entry point match",
                })
            else:
                try:
                    offset_val = int(sig_offset_spec, 0)
                except ValueError:
                    continue
                end = offset_val + len(pattern_bytes)
                if end <= len(self._doc_data) and self._doc_data[offset_val:end] == pattern_bytes:
                    results.append({
                        "name": sig_name,
                        "type": "ndb",
                        "version": "",
                        "offset": offset_val,
                        "details": f"Fixed offset match at 0x{offset_val:X}",
                    })
        return results

    def _scan_custom(self) -> list[dict[str, Any]]:
        """Scan using a custom JSON signature database.

        Expected format: list of objects with name, pattern (hex), offset, type.

        Returns:
            list[dict[str, Any]]: List of match dicts.
        """
        db_text = Path(self._db_path).read_text(encoding="utf-8")
        entries: list[dict[str, str]] = json.loads(db_text)
        results: list[dict[str, Any]] = []

        for entry in entries:
            sig_name = entry.get("name", "unknown")
            hex_pattern = entry.get("pattern", "")
            offset_spec = entry.get("offset", "any")
            sig_type = entry.get("type", "unknown")

            try:
                pattern_bytes = bytes.fromhex(hex_pattern.replace(" ", ""))
            except ValueError:
                continue

            if offset_spec == "ep":
                idx = self._doc_data[:_MAX_ENTRY_POINT_BYTES].find(pattern_bytes)
                if idx >= 0:
                    results.append({
                        "name": sig_name,
                        "type": sig_type,
                        "version": "",
                        "offset": idx,
                        "details": f"Entry point match at +{idx}",
                    })
            elif offset_spec == "any":
                idx = self._doc_data.find(pattern_bytes)
                if idx >= 0:
                    results.append({
                        "name": sig_name,
                        "type": sig_type,
                        "version": "",
                        "offset": idx,
                        "details": f"Full scan match at 0x{idx:X}",
                    })
            else:
                try:
                    fixed_offset = int(offset_spec, 0)
                except ValueError:
                    continue
                end = fixed_offset + len(pattern_bytes)
                if end <= len(self._doc_data) and self._doc_data[fixed_offset:end] == pattern_bytes:
                    results.append({
                        "name": sig_name,
                        "type": sig_type,
                        "version": "",
                        "offset": fixed_offset,
                        "details": f"Fixed offset match at 0x{fixed_offset:X}",
                    })

        return results


class SignaturesMixin:
    """Mixin providing non-YARA signature scanning for the hex editor panel."""

    document: Any | None
    _hex_widget: Any | None
    _sig_db_type_combo: QComboBox | None
    _sig_db_path_label: QLabel | None
    _sig_results_tree: QTreeWidget | None
    _sig_worker: SignatureScanWorker | None
    _sig_db_path: str

    def goto_offset(self, offset: int) -> None:
        """Navigate the hex widget to a specific offset.

        Args:
            offset: Target byte offset.
        """
        hex_widget = getattr(self, "_hex_widget", None)
        if hex_widget is not None:
            goto_fn = getattr(hex_widget, "goto_offset", None)
            if callable(goto_fn):
                goto_fn(offset)

    def _create_signatures_tab(self) -> QWidget:
        """Create the Signatures side panel tab widget.

        Returns:
            QWidget: Container with database selector, scan button,
                and results tree.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(4)

        type_row = QHBoxLayout()
        type_row.addWidget(QLabel("Database:"))
        self._sig_db_type_combo = QComboBox()
        self._sig_db_type_combo.addItems(["DIE (JSON)", "ClamAV (.ndb/.hdb)", "Custom (JSON)"])
        type_row.addWidget(self._sig_db_type_combo)
        layout.addLayout(type_row)

        db_row = QHBoxLayout()
        select_btn = QPushButton("Select Database...")
        select_btn.clicked.connect(self._on_select_sig_db)
        db_row.addWidget(select_btn)
        self._sig_db_path_label = QLabel("(none)")
        db_row.addWidget(self._sig_db_path_label)
        layout.addLayout(db_row)

        scan_btn = QPushButton("Scan")
        scan_btn.clicked.connect(self._on_scan_signatures)
        layout.addWidget(scan_btn)

        self._sig_results_tree = QTreeWidget()
        self._sig_results_tree.setHeaderLabels(["Name", "Type", "Version", "Offset", "Details"])
        self._sig_results_tree.setRootIsDecorated(show=False)
        self._sig_results_tree.setAlternatingRowColors(enable=True)
        self._sig_results_tree.itemDoubleClicked.connect(self._on_sig_result_double_clicked)
        layout.addWidget(self._sig_results_tree)

        self._sig_db_path = ""
        self._sig_worker = None
        return container

    def _on_select_sig_db(self) -> None:
        """Open a file dialog to select a signature database file."""
        parent = self if isinstance(self, QWidget) else None
        file_filter = "Signature Files (*.json *.ndb *.hdb);;All Files (*)"
        result = QFileDialog.getOpenFileName(parent, "Select Signature Database", "", file_filter)
        db_path = result[0] if result else ""
        if db_path:
            self._sig_db_path = db_path
            if self._sig_db_path_label is not None:
                name = Path(db_path).name
                self._sig_db_path_label.setText(name)

    def _on_scan_signatures(self) -> None:
        """Start scanning the document against the selected signature database."""
        if self.document is None or not self._sig_db_path:
            return

        if self._sig_worker is not None and self._sig_worker.isRunning():
            return

        try:
            doc_len: int = self.document.length()
            raw: object = self.document.read(0, doc_len)
            if isinstance(raw, list):
                doc_data = bytes(cast("list[int]", raw))
            elif isinstance(raw, bytearray):
                doc_data = bytes(raw)
            elif isinstance(raw, bytes):
                doc_data = raw
            else:
                return
        except (AttributeError, ValueError) as exc:
            logger.warning("sig_scan_read_failed", error=str(exc))
            return

        type_idx = self._sig_db_type_combo.currentIndex() if self._sig_db_type_combo else 0
        db_type_map = {0: "die", 1: "clamav", 2: "custom"}
        db_type = db_type_map.get(type_idx, "custom")

        if self._sig_results_tree is not None:
            self._sig_results_tree.clear()

        worker = SignatureScanWorker(doc_data, db_type, self._sig_db_path)
        worker.scan_finished.connect(self._on_sig_scan_finished)
        worker.scan_error.connect(self._on_sig_scan_error)
        self._sig_worker = worker
        worker.start()

    def _on_sig_scan_finished(self, results: list[object]) -> None:
        """Populate the results tree with scan matches.

        Args:
            results: List of match dicts from the scan worker.
        """
        if self._sig_results_tree is None:
            return

        self._sig_results_tree.clear()
        typed_results = cast("list[dict[str, Any]]", results)
        for match in typed_results:
            offset = match.get("offset", 0)
            item = QTreeWidgetItem([
                str(match.get("name", "")),
                str(match.get("type", "")),
                str(match.get("version", "")),
                f"0x{offset:08X}" if isinstance(offset, int) else str(offset),
                str(match.get("details", "")),
            ])
            self._sig_results_tree.addTopLevelItem(item)

        logger.info("sig_scan_complete", match_count=len(typed_results))

    def _on_sig_scan_error(self, error: str) -> None:
        """Handle signature scan failure.

        Args:
            error: Error message from the scan worker.
        """
        logger.warning("sig_scan_failed", error=error)
        if self._sig_results_tree is not None:
            self._sig_results_tree.clear()

    def _on_sig_result_double_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        """Navigate to the offset of a double-clicked scan result.

        Args:
            item: The clicked tree item.
            column: The clicked column index.
        """
        _ = column
        offset_text = item.text(3)
        try:
            offset = int(offset_text, 16)
        except ValueError:
            return
        self.goto_offset(offset)
