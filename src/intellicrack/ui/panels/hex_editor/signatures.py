# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Non-YARA signature scanning mixin for the hex editor panel."""

from __future__ import annotations

import hashlib
import json
import mmap
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.core.yara_scanner import YaraScanner
from intellicrack.ui.panels.async_bridge import (
    GenericCallableWorker,
    run_bridge_coroutine_logged,
    worker_is_running,
)


if TYPE_CHECKING:
    from intellicrack.bridges.hex_editor import HexEditorBridge


_logger = get_logger(__name__)


_MAX_ENTRY_POINT_BYTES: Final[int] = 256
_NDB_LINE_FIELDS: Final[int] = 4
_HDB_LINE_FIELDS: Final[int] = 3


def read_file_for_scan(path: Path) -> bytes:
    """Read file contents using mmap for memory-efficient access.

    Args:
        path: Absolute path to the file to read.

    Returns:
        bytes: Complete file contents.
    """
    size = path.stat().st_size
    _logger.debug("sig_scan_file_read_begin", path=str(path), size=size)
    if size == 0:
        return b""
    with path.open("rb") as fh, mmap.mmap(fh.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
        return bytes(mm)


def read_document_for_scan(document: object) -> bytes:
    """Read document contents via the document API on the calling thread.

    Args:
        document: Hex-editor document object exposing ``length()`` and
            ``read(offset, length)`` methods.

    Returns:
        bytes: Complete document contents as a bytes object.

    Raises:
        TypeError: If the document does not expose the expected API.
        ValueError: If the document read returns an unexpected type.
    """
    length_fn = getattr(document, "length", None)
    read_fn = getattr(document, "read", None)
    if not callable(length_fn) or not callable(read_fn):
        msg = "Document does not expose length() and read() methods"
        _logger.warning("read_document_for_scan_raise_pending", error_type="TypeError")
        raise TypeError(msg)
    doc_len: int = cast("int", length_fn())
    raw: object = read_fn(0, doc_len)
    if isinstance(raw, list):
        return bytes(cast("list[int]", raw))
    if isinstance(raw, bytearray):
        return bytes(raw)
    if isinstance(raw, bytes):
        return raw
    msg = f"Unexpected document.read return type: {type(raw).__name__}"
    _logger.warning("read_document_for_scan_raise_pending", error_type="ValueError")
    raise ValueError(msg)


def execute_signature_scan_from_source(
    file_path: str | None,
    document: object | None,
    db_type: str,
    db_path: str,
) -> list[dict[str, Any]]:
    """Read document data on the calling thread then scan against the database.

    Intended to be executed on a worker thread so that neither the file I/O
    nor the scan computation blocks the Qt UI thread.  When ``file_path`` is
    provided and refers to an existing file, the file is read via
    :func:`read_file_for_scan` using ``mmap``.  Otherwise ``document`` is
    used as a fallback via :func:`read_document_for_scan`.

    Args:
        file_path: Absolute path to the on-disk binary, or ``None`` when the
            document is not file-backed.
        document: Hex-editor document object used as a fallback when
            ``file_path`` is ``None`` or the file does not exist.
        db_type: Database format (``"die"``, ``"clamav"``, ``"custom"``).
        db_path: Path to the signature database file.

    Returns:
        list[dict[str, Any]]: List of match dicts with ``name``, ``type``,
            ``version``, ``offset``, and ``details`` keys.

    Raises:
        ValueError: If neither a valid ``file_path`` nor a usable ``document``
            is available.
    """
    doc_data: bytes
    if file_path is not None:
        fp = Path(file_path)
        if fp.is_file():
            doc_data = read_file_for_scan(fp)
        elif document is not None:
            doc_data = read_document_for_scan(document)
        else:
            msg = f"File not found and no document fallback: {file_path}"
            raise ValueError(msg)
    elif document is not None:
        doc_data = read_document_for_scan(document)
    else:
        msg = "No file path and no document provided for signature scan"
        raise ValueError(msg)

    return execute_signature_scan(doc_data, db_type, db_path)


def execute_signature_scan(
    doc_data: bytes,
    db_type: str,
    db_path: str,
) -> list[dict[str, Any]]:
    """Scan ``doc_data`` against the selected signature database.

    Args:
        doc_data: Full document contents as bytes.
        db_type: Database format (``"die"``, ``"clamav"``, ``"custom"``).
        db_path: Path to the signature database file.

    Returns:
        list[dict[str, Any]]: List of match dicts with ``name``, ``type``,
            ``version``, ``offset``, and ``details`` keys.
    """
    if db_type == "die":
        return _scan_die(doc_data, db_path)
    if db_type == "clamav":
        return _scan_clamav(doc_data, db_path)
    if db_type == "yara":
        scanner = YaraScanner()
        rules = scanner.compile_rules([db_path])
        matches = scanner.scan_data(doc_data, rules)
        return [
            {
                "name": match.rule_name,
                "type": "YARA",
                "version": str(match.meta.get("version", "1.0")),
                "offset": match.strings[0].offset if match.strings else 0,
                "details": f"Namespace: {match.namespace}, Meta: {match.meta}, Tags: {match.tags}",
            }
            for match in matches
        ]
    return _scan_custom(doc_data, db_path)


def _scan_die(doc_data: bytes, db_path: str) -> list[dict[str, Any]]:
    """Scan using a DIE-style JSON signature database.

    Args:
        doc_data: Full document contents as bytes.
        db_path: Path to the DIE JSON database file.

    Returns:
        list[dict[str, Any]]: List of match dicts with ``name``, ``type``,
            ``version``, and ``offset`` keys.
    """
    _logger.info("sig_scan_die_read_begin", db_path=db_path, doc_size=len(doc_data))
    db_text = Path(db_path).read_text(encoding="utf-8")
    db_entries: list[dict[str, Any]] = json.loads(db_text)
    _logger.debug(
        "sig_scan_die_read_complete",
        db_path=db_path,
        entry_count=len(db_entries),
        db_size=len(db_text),
    )
    results: list[dict[str, Any]] = []

    ep_bytes = doc_data[:_MAX_ENTRY_POINT_BYTES]

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
                typed_pattern_info = cast("dict[str, object]", pattern_info)
                hex_pattern = str(typed_pattern_info.get("pattern", ""))
                scan_offset = str(typed_pattern_info.get("offset", "ep"))
            else:
                continue

            try:
                pattern_bytes = bytes.fromhex(hex_pattern.replace(" ", ""))
            except ValueError:
                _logger.warning(
                    "die_pattern_decode_failed",
                    sig_name=sig_name,
                    hex_pattern=hex_pattern,
                )
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
                idx = doc_data.find(pattern_bytes)
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
                    _logger.warning(
                        "die_offset_parse_failed",
                        sig_name=sig_name,
                        scan_offset=scan_offset,
                    )
                    continue
                if fixed_offset + len(pattern_bytes) <= len(doc_data):
                    region = doc_data[fixed_offset : fixed_offset + len(pattern_bytes)]
                    if region == pattern_bytes:
                        results.append({
                            "name": sig_name,
                            "type": sig_type,
                            "version": sig_version,
                            "offset": fixed_offset,
                            "details": f"Fixed offset match at 0x{fixed_offset:X}",
                        })

    return results


def _scan_clamav(doc_data: bytes, db_path: str) -> list[dict[str, Any]]:
    """Scan using ClamAV .ndb or .hdb signature files.

    Args:
        doc_data: Full document contents as bytes.
        db_path: Path to the ClamAV signature file.

    Returns:
        list[dict[str, Any]]: List of match dicts with ``name``, ``type``,
            and ``offset`` keys.
    """
    db_file = Path(db_path)
    suffix = db_file.suffix.lower()
    _logger.info(
        "sig_scan_clamav_read_begin",
        db_path=db_path,
        suffix=suffix,
        doc_size=len(doc_data),
    )
    lines = db_file.read_text(encoding="utf-8", errors="replace").splitlines()
    _logger.debug(
        "sig_scan_clamav_read_complete",
        db_path=db_path,
        line_count=len(lines),
    )
    if suffix == ".hdb":
        return _scan_clamav_hdb(doc_data, lines)
    return _scan_clamav_ndb(doc_data, lines)


def _scan_clamav_hdb(doc_data: bytes, lines: list[str]) -> list[dict[str, Any]]:
    """Scan ClamAV hash-based (.hdb) signatures.

    Args:
        doc_data: Full document contents as bytes.
        lines: Lines from the .hdb signature file.

    Returns:
        list[dict[str, Any]]: Match results.
    """
    file_md5 = hashlib.md5(doc_data, usedforsecurity=False).hexdigest()
    file_size = len(doc_data)
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
            _logger.warning(
                "hdb_size_parse_failed",
                sig_name=sig_name,
                sig_size=parts[1],
            )
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


def _scan_clamav_ndb(doc_data: bytes, lines: list[str]) -> list[dict[str, Any]]:
    """Scan ClamAV pattern-based (.ndb) signatures.

    Args:
        doc_data: Full document contents as bytes.
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
            if clean_hex := sig_hex.replace("*", "").replace("?", ""):
                pattern_bytes = bytes.fromhex(clean_hex)
            else:
                continue
        except ValueError:
            _logger.warning(
                "ndb_pattern_decode_failed",
                sig_name=sig_name,
                sig_hex=sig_hex,
            )
            continue
        if sig_offset_spec == "*":
            idx = doc_data.find(pattern_bytes)
            if idx >= 0:
                results.append({
                    "name": sig_name,
                    "type": "ndb",
                    "version": "",
                    "offset": idx,
                    "details": f"Pattern match at 0x{idx:X}",
                })
        elif sig_offset_spec == "EP+0" and doc_data[: len(pattern_bytes)] == pattern_bytes:
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
                _logger.warning(
                    "ndb_offset_parse_failed",
                    sig_name=sig_name,
                    sig_offset_spec=sig_offset_spec,
                )
                continue
            end = offset_val + len(pattern_bytes)
            if end <= len(doc_data) and doc_data[offset_val:end] == pattern_bytes:
                results.append({
                    "name": sig_name,
                    "type": "ndb",
                    "version": "",
                    "offset": offset_val,
                    "details": f"Fixed offset match at 0x{offset_val:X}",
                })
    return results


def _scan_custom(doc_data: bytes, db_path: str) -> list[dict[str, Any]]:
    """Scan using a custom JSON signature database.

    Expected format: list of objects with name, pattern (hex), offset, type.

    Args:
        doc_data: Full document contents as bytes.
        db_path: Path to the custom JSON signature file.

    Returns:
        list[dict[str, Any]]: List of match dicts.
    """
    _logger.info("sig_scan_custom_read_begin", db_path=db_path, doc_size=len(doc_data))
    db_text = Path(db_path).read_text(encoding="utf-8")
    entries: list[dict[str, str]] = json.loads(db_text)
    _logger.debug(
        "sig_scan_custom_read_complete",
        db_path=db_path,
        entry_count=len(entries),
        db_size=len(db_text),
    )
    results: list[dict[str, Any]] = []

    for entry in entries:
        sig_name = entry.get("name", "unknown")
        hex_pattern = entry.get("pattern", "")
        offset_spec = entry.get("offset", "any")
        sig_type = entry.get("type", "unknown")

        try:
            pattern_bytes = bytes.fromhex(hex_pattern.replace(" ", ""))
        except ValueError:
            _logger.warning(
                "custom_pattern_decode_failed",
                sig_name=sig_name,
                hex_pattern=hex_pattern,
            )
            continue

        if offset_spec == "ep":
            idx = doc_data[:_MAX_ENTRY_POINT_BYTES].find(pattern_bytes)
            if idx >= 0:
                results.append({
                    "name": sig_name,
                    "type": sig_type,
                    "version": "",
                    "offset": idx,
                    "details": f"Entry point match at +{idx}",
                })
        elif offset_spec == "any":
            idx = doc_data.find(pattern_bytes)
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
                _logger.warning(
                    "custom_offset_parse_failed",
                    sig_name=sig_name,
                    offset_spec=offset_spec,
                )
                continue
            end = fixed_offset + len(pattern_bytes)
            if end <= len(doc_data) and doc_data[fixed_offset:end] == pattern_bytes:
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
    file_path: Path | None
    _hex_widget: Any | None
    _sig_db_type_combo: QComboBox | None
    _sig_db_path_label: QLabel | None
    _sig_results_tree: QTreeWidget | None
    _sig_worker: GenericCallableWorker | None
    _sig_db_path: str
    _bridge: Any | None

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
        self._sig_db_type_combo.addItems(["DIE (JSON)", "ClamAV (.ndb/.hdb)", "Custom (JSON)", "YARA (.yar/.yara)"])
        type_row.addWidget(self._sig_db_type_combo)
        layout.addLayout(type_row)

        db_row = QHBoxLayout()
        select_btn = QPushButton("Select Database...")
        select_btn.clicked.connect(self._on_select_sig_db)
        db_row.addWidget(select_btn)
        self._sig_db_path_label = QLabel("(none)")
        self._sig_db_path_label.setWordWrap(True)
        self._sig_db_path_label.setToolTip("(none)")
        db_row.addWidget(self._sig_db_path_label, 1)
        layout.addLayout(db_row)

        scan_btn = QPushButton("Scan")
        scan_btn.clicked.connect(self._on_scan_signatures)
        layout.addWidget(scan_btn)

        self._sig_results_tree = QTreeWidget()
        self._sig_results_tree.setHeaderLabels(["Name", "Type", "Version", "Offset", "Details"])
        self._sig_results_tree.setRootIsDecorated(False)
        self._sig_results_tree.setAlternatingRowColors(True)
        results_header = self._sig_results_tree.header()
        if results_header is not None:
            results_header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
            results_header.setStretchLastSection(True)
        self._sig_results_tree.itemDoubleClicked.connect(self._on_sig_result_double_clicked)
        layout.addWidget(self._sig_results_tree)

        self._sig_db_path = ""
        self._sig_worker = None
        return container

    def _on_select_sig_db(self) -> None:
        """Open a file dialog to select a signature database file."""
        parent = self if isinstance(self, QWidget) else None
        file_filter = "Signature/YARA Files (*.json *.ndb *.hdb *.yar *.yara);;All Files (*)"
        result = QFileDialog.getOpenFileName(parent, "Select Signature Database", "", file_filter)
        db_path = result[0] if result else ""
        if db_path:
            self._sig_db_path = db_path
            if self._sig_db_path_label is not None:
                name = Path(db_path).name
                self._sig_db_path_label.setText(name)
                self._sig_db_path_label.setToolTip(db_path)

    def _on_scan_signatures(self) -> None:
        """Start scanning the document against the selected signature database.

        DIE, ClamAV, and custom-JSON databases are dispatched through the matching ``HexEditorBridge.scan_*_signatures`` method so the AI-
        callable tool and this toolbar action share a single scanner implementation (the audit's highest drift-risk item: nontrivial parsing
        logic most likely to drift between two independent copies). YARA has no bridge equivalent and continues to run via the local
        :class:`YaraScanner`-backed worker.
        """
        if self.document is None or not self._sig_db_path:
            return

        if worker_is_running(self._sig_worker):
            return

        type_idx = self._sig_db_type_combo.currentIndex() if self._sig_db_type_combo else 0
        db_type_map = {0: "die", 1: "clamav", 2: "custom", 3: "yara"}
        db_type = db_type_map.get(type_idx, "custom")

        if self._sig_results_tree is not None:
            self._sig_results_tree.clear()

        fp_str: str | None = str(self.file_path) if getattr(self, "file_path", None) is not None else None
        _logger.info(
            "sig_scan_started",
            db_type=db_type,
            db_path=self._sig_db_path,
            file_path=fp_str,
            has_document=self.document is not None,
        )

        bridge = getattr(self, "_bridge", None)
        if db_type != "yara" and bridge is not None:
            self._scan_signatures_via_bridge(bridge, db_type)
            return

        worker = GenericCallableWorker(
            execute_signature_scan_from_source,
            fp_str,
            self.document,
            db_type,
            self._sig_db_path,
        )
        _: object = worker.call_finished.connect(self._on_sig_scan_finished_obj)
        _ = worker.call_error.connect(self._on_sig_scan_error_obj)
        self._sig_worker = worker
        worker.start()

    def _scan_signatures_via_bridge(self, bridge: HexEditorBridge, db_type: str) -> None:
        """Dispatch a DIE/ClamAV/custom signature scan to the matching bridge method.

        Args:
            bridge: Attached ``HexEditorBridge`` instance.
            db_type: Selected database format (``"die"``, ``"clamav"``, or ``"custom"``).
        """
        coro = {
            "die": bridge.scan_die_signatures,
            "clamav": bridge.scan_clamav_signatures,
            "custom": bridge.scan_custom_signatures,
        }[db_type](self._sig_db_path)

        run_bridge_coroutine_logged(
            coro,
            on_success=self._on_sig_scan_bridge_success,
            on_error=self._on_sig_scan_bridge_error,
            parent=self if isinstance(self, QWidget) else None,
            event=f"hex_editor_scan_{db_type}_signatures",
            logger=_logger,
            db_type=db_type,
            db_path=self._sig_db_path,
        )

    def _on_sig_scan_bridge_success(self, result: object) -> None:
        """Render DiE/ClamAV/custom signature hits after a successful bridge scan.

        Args:
            result: Match list from ``scan_die_signatures``,
                ``scan_clamav_signatures``, or ``scan_custom_signatures``.
        """
        if not isinstance(result, list):
            _logger.warning("sig_scan_bridge_unexpected_result_type", result_type=type(result).__name__)
            return
        self._on_sig_scan_finished(cast("list[object]", result))

    def _on_sig_scan_bridge_error(self, exc: object) -> None:
        """Show the signature-scan error path when a bridge scan method fails.

        Args:
            exc: Exception raised by the signature-scan bridge method.
        """
        self._on_sig_scan_error(str(exc))

    def _on_sig_scan_finished_obj(self, results: object) -> None:
        """Accept untyped worker finished payloads into the typed scan-finished path.

        Args:
            results: Raw object emitted by ``GenericCallableWorker.call_finished``.
        """
        if isinstance(results, list):
            self._on_sig_scan_finished(cast("list[object]", results))

    def _on_sig_scan_error_obj(self, exc: object) -> None:
        """Forward worker exceptions to the typed signature scan error handler.

        Args:
            exc: Exception object emitted by ``GenericCallableWorker.call_error``.
        """
        self._on_sig_scan_error(str(exc))

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
            offset_text = f"0x{offset:08X}" if isinstance(offset, int) else str(offset)
            values = [
                str(match.get("name", "")),
                str(match.get("type", "")),
                str(match.get("version", "")),
                offset_text,
                str(match.get("details", "")),
            ]
            item = QTreeWidgetItem(values)
            for column, value in enumerate(values):
                item.setToolTip(column, value)
            self._sig_results_tree.addTopLevelItem(item)

        _logger.info("sig_scan_complete", match_count=len(typed_results))

    def _on_sig_scan_error(self, error: str) -> None:
        """Handle signature scan failure.

        Args:
            error: Error message from the scan worker.
        """
        _logger.warning("sig_scan_failed", error=error)
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
            _logger.exception("sig_result_offset_parse_failed", offset_text=offset_text)
            return
        self.goto_offset(offset)
