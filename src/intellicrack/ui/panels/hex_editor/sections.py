# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Sections/imports/exports/strings mixin for the hex editor panel."""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING, Any, Final, Protocol, cast, runtime_checkable

from PyQt6.QtWidgets import QComboBox, QLabel, QTreeWidget, QTreeWidgetItem, QWidget

from intellicrack.bridges.pe_format import detect_format
from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import GenericCallableWorker, run_bridge_coroutine_logged
from intellicrack.ui.panels.hex_editor.base import (
    PREVIEW_BYTES,
    hexpat_interpreter_available,
)


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


_logger = get_logger(__name__)


_STRINGS_MIN_LENGTH: Final[int] = 4
_STRINGS_MAX_RESULTS: Final[int] = 5000


_FORMAT_TO_TEMPLATE: Final[dict[str, tuple[str, str]]] = {
    "pe": ("PE", "IMAGE_DOS_HEADER"),
    "elf": ("ELF", "ELF_HEADER_64"),
    "macho": ("Mach-O", "MACH_HEADER_64"),
    "zip": ("ZIP", "ZIP_LOCAL_FILE_HEADER"),
}
"""Map :func:`detect_format` results to ``(display_name, template_id)`` for the templates panel."""


@runtime_checkable
class _StringsSource(Protocol):
    """Subset of the hexcore ``HexDocument`` API required by ``execute_strings_extraction``."""

    def extract_strings(
        self,
        *,
        min_length: int,
        include_ascii: bool,
        include_utf16: bool,
        max_results: int,
    ) -> object:
        """Extract string matches from the underlying document.

        Args:
            min_length: Minimum string length in codepoints to keep.
            include_ascii: Whether to include ASCII-encoded strings.
            include_utf16: Whether to include UTF-16 encoded strings.
            max_results: Upper bound on returned matches.

        Returns:
            object: Iterable of dict-like records with at minimum ``offset`` and ``text`` keys.
        """


def execute_strings_extraction(
    document: _StringsSource,
    min_length: int,
    max_results: int,
) -> object:
    """Invoke ``document.extract_strings`` with ASCII and UTF-16 enabled.

    Args:
        document: Hexcore ``HexDocument`` (or compatible) implementing
            ``extract_strings``.
        min_length: Minimum string length in characters/codepoints to keep.
        max_results: Upper bound on returned entries.

    Returns:
        object: Iterable of dict-like records as returned by
            ``HexDocument.extract_strings``.
    """
    return document.extract_strings(
        min_length=min_length,
        include_ascii=True,
        include_utf16=True,
        max_results=max_results,
    )


class SectionsMixin:
    """Mixin providing PE section/import/export/string parsing and file type detection."""

    document: Any | None
    file_path: Path | None
    sections_tree: QTreeWidget | None
    _document: Any | None
    _file_path: Path | None
    _hex_widget: Any | None
    _sections_tree: QTreeWidget | None
    _imports_tree: QTreeWidget | None
    _exports_tree: QTreeWidget | None
    _strings_tree: QTreeWidget | None
    _template_combo: QComboBox | None
    _file_info_label: QLabel | None
    _pattern_status_label: QLabel | None
    _pattern_registry: Any | None
    _strings_worker: GenericCallableWorker | None
    _bridge: HexEditorBridge | None
    _select_template: Callable[[str], None]

    def goto_offset(self, offset: int) -> None:
        """Navigate the hex widget to the given byte offset.

        Args:
            offset: Absolute byte offset within the active document.
        """

    def _populate_sections(self) -> None:
        """Populate the sections tree by routing through the hex editor bridge.

        Calls :meth:`HexEditorBridge.get_pe_sections` via :func:`run_bridge_coroutine_logged` so the parse runs on the persistent bridge
        event loop. Bridge results are rendered on the Qt main thread through the success callback.
        """
        if self.sections_tree is None:
            return

        self.sections_tree.clear()

        bridge = getattr(self, "_bridge", None)
        if bridge is None:
            _logger.warning("sections_bridge_unavailable")
            return

        parent_obj = self if isinstance(self, QWidget) else None
        run_bridge_coroutine_logged(
            bridge.get_pe_sections(),
            on_success=self._on_pe_sections_ready,
            on_error=self._on_pe_sections_failed,
            parent=parent_obj,
            event="hex_editor_get_pe_sections",
            logger=_logger,
        )

    def _on_pe_sections_ready(self, result: object) -> None:
        """Render PE section dicts into the sections tree.

        Args:
            result: ``list[dict]`` payload returned by
                :meth:`HexEditorBridge.get_pe_sections`. Each dict
                exposes ``name``, ``virtual_address``, ``virtual_size``,
                ``raw_size``, and ``raw_offset`` keys.
        """
        if self.sections_tree is None:
            return
        if not isinstance(result, list):
            _logger.warning("sections_unexpected_result_type", result_type=type(result).__name__)
            return
        sections = cast("list[dict[str, Any]]", result)
        for section in sections:
            name = str(section.get("name", ""))
            virtual_address = int(section.get("virtual_address", 0))
            virtual_size = int(section.get("virtual_size", 0))
            raw_size = int(section.get("raw_size", 0))
            item = QTreeWidgetItem(
                [
                    name,
                    f"0x{virtual_address:08X}",
                    f"0x{virtual_size:08X}",
                    f"0x{raw_size:08X}",
                ],
            )
            self.sections_tree.addTopLevelItem(item)

    @staticmethod
    def _on_pe_sections_failed(exc: object) -> None:
        """Log a PE sections parse failure raised by the bridge.

        Args:
            exc: Exception object emitted by the bridge worker.
        """
        _logger.warning("sections_parse_failed", error_type=type(exc).__name__, error=str(exc))

    def _populate_imports(self) -> None:
        """Populate the imports tree by routing through the hex editor bridge.

        Calls :meth:`HexEditorBridge.get_pe_imports` via :func:`run_bridge_coroutine_logged` so the parse runs on the persistent bridge
        event loop. Bridge results are rendered on the Qt main thread through the success callback.
        """
        if self._imports_tree is None:
            return

        self._imports_tree.clear()

        bridge = getattr(self, "_bridge", None)
        if bridge is None:
            _logger.warning("imports_bridge_unavailable")
            return

        parent_obj = self if isinstance(self, QWidget) else None
        run_bridge_coroutine_logged(
            bridge.get_pe_imports(),
            on_success=self._on_pe_imports_ready,
            on_error=self._on_pe_imports_failed,
            parent=parent_obj,
            event="hex_editor_get_pe_imports",
            logger=_logger,
        )

    def _on_pe_imports_ready(self, result: object) -> None:
        """Render PE import dicts into the imports tree.

        Args:
            result: ``list[dict]`` payload returned by
                :meth:`HexEditorBridge.get_pe_imports`. Each dict
                exposes ``dll``, ``function``, ``address``, and
                ``ordinal`` keys.
        """
        if self._imports_tree is None:
            return
        if not isinstance(result, list):
            _logger.warning("imports_unexpected_result_type", result_type=type(result).__name__)
            return
        entries = cast("list[dict[str, Any]]", result)
        for entry in entries:
            dll_name = str(entry.get("dll", "unknown"))
            function_name = str(entry.get("function", ""))
            address_val = int(entry.get("address", 0))
            address_text = f"0x{address_val:08X}" if address_val else "N/A"
            item = QTreeWidgetItem([dll_name, function_name, address_text])
            self._imports_tree.addTopLevelItem(item)

    @staticmethod
    def _on_pe_imports_failed(exc: object) -> None:
        """Log a PE imports parse failure raised by the bridge.

        Args:
            exc: Exception object emitted by the bridge worker.
        """
        _logger.warning("imports_parse_failed", error_type=type(exc).__name__, error=str(exc))

    def _populate_exports(self) -> None:
        """Populate the exports tree by routing through the hex editor bridge.

        Calls :meth:`HexEditorBridge.get_pe_exports` via :func:`run_bridge_coroutine_logged` so the parse runs on the persistent bridge
        event loop. Bridge results are rendered on the Qt main thread through the success callback.
        """
        if self._exports_tree is None:
            return

        self._exports_tree.clear()

        bridge = getattr(self, "_bridge", None)
        if bridge is None:
            _logger.warning("exports_bridge_unavailable")
            return

        parent_obj = self if isinstance(self, QWidget) else None
        run_bridge_coroutine_logged(
            bridge.get_pe_exports(),
            on_success=self._on_pe_exports_ready,
            on_error=self._on_pe_exports_failed,
            parent=parent_obj,
            event="hex_editor_get_pe_exports",
            logger=_logger,
        )

    def _on_pe_exports_ready(self, result: object) -> None:
        """Render PE export dicts into the exports tree.

        Args:
            result: ``list[dict]`` payload returned by
                :meth:`HexEditorBridge.get_pe_exports`. Each dict
                exposes ``name``, ``address``, and ``ordinal`` keys.
        """
        if self._exports_tree is None:
            return
        if not isinstance(result, list):
            _logger.warning("exports_unexpected_result_type", result_type=type(result).__name__)
            return
        entries = cast("list[dict[str, Any]]", result)
        for entry in entries:
            name = str(entry.get("name", ""))
            address_val = int(entry.get("address", 0))
            address_text = f"0x{address_val:08X}" if address_val else "N/A"
            ordinal_val = entry.get("ordinal")
            ordinal_text = str(ordinal_val) if ordinal_val is not None else "N/A"
            item = QTreeWidgetItem([name, address_text, ordinal_text])
            self._exports_tree.addTopLevelItem(item)

    @staticmethod
    def _on_pe_exports_failed(exc: object) -> None:
        """Log a PE exports parse failure raised by the bridge.

        Args:
            exc: Exception object emitted by the bridge worker.
        """
        _logger.warning("exports_parse_failed", error_type=type(exc).__name__, error=str(exc))

    def _populate_strings(self) -> None:
        """Populate the strings tab asynchronously via a ``GenericCallableWorker``.

        Dispatches the hexcore ``extract_strings`` RPC on a background thread so that very large binaries do not block the Qt event loop
        while the Rust backend streams matches back. Results are consumed on the UI thread through the worker's ``call_finished`` /
        ``call_error`` signals.
        """
        if self._strings_tree is None or self.document is None:
            return

        self._strings_tree.clear()
        pending_row = QTreeWidgetItem(["-", "-", "(scanning...)"])
        self._strings_tree.addTopLevelItem(pending_row)

        previous = getattr(self, "_strings_worker", None)
        if isinstance(previous, GenericCallableWorker) and previous.isRunning():
            previous.requestInterruption()

        _logger.info(
            "strings_extract_started",
            min_length=_STRINGS_MIN_LENGTH,
            max_results=_STRINGS_MAX_RESULTS,
        )

        worker = GenericCallableWorker(
            execute_strings_extraction,
            self.document,
            _STRINGS_MIN_LENGTH,
            _STRINGS_MAX_RESULTS,
        )
        self._strings_worker = worker
        _: object = worker.call_finished.connect(partial(self._on_strings_worker_finished, worker))
        _ = worker.call_error.connect(partial(self._on_strings_worker_error, worker))
        worker.start()

    def _on_strings_worker_finished(self, worker: GenericCallableWorker, results: object) -> None:
        """Render extraction results only if ``worker`` is still the active strings worker.

        A superseded worker's ``requestInterruption()`` request does not stop its
        already-running native extraction call, so a stale worker can still emit
        ``call_finished`` after a newer scan has replaced it. Comparing against the
        current :attr:`_strings_worker` reference discards any such stale delivery
        instead of overwriting freshly rendered results.

        Args:
            worker: The :class:`GenericCallableWorker` instance that produced
                ``results``.
            results: Iterable of dict-like records as returned by
                ``HexDocument.extract_strings``.
        """
        if worker is not self._strings_worker:
            _logger.debug("strings_extract_stale_result_discarded")
            return
        self._on_strings_ready(results)

    def _on_strings_worker_error(self, worker: GenericCallableWorker, exc: object) -> None:
        """Report an extraction failure only if ``worker`` is still the active strings worker.

        Args:
            worker: The :class:`GenericCallableWorker` instance that raised ``exc``.
            exc: Exception object emitted by ``GenericCallableWorker.call_error``.
        """
        if worker is not self._strings_worker:
            _logger.debug("strings_extract_stale_error_discarded")
            return
        self._on_strings_failed_obj(exc)

    def _on_strings_failed_obj(self, exc: object) -> None:
        """Forward worker exceptions to the typed strings-failed handler.

        Args:
            exc: Exception object emitted by ``GenericCallableWorker.call_error``.
        """
        self._on_strings_failed(str(exc))

    def _on_strings_ready(self, results: object) -> None:
        """Replace the strings tree contents with the extracted entries.

        Args:
            results: Iterable of dict-like records with ``offset`` and ``text`` keys as
                returned by ``HexDocument.extract_strings``.
        """
        if self._strings_tree is None:
            return
        self._strings_tree.clear()
        if not isinstance(results, list):
            return
        max_display_len = PREVIEW_BYTES
        for entry in cast("list[object]", results):
            if not isinstance(entry, dict):
                continue
            typed: dict[str, object] = cast("dict[str, object]", entry)
            offset_val = typed.get("offset")
            text_val = typed.get("text") or typed.get("value")
            if offset_val is None or text_val is None:
                continue
            try:
                offset_int = int(cast("Any", offset_val))
            except (TypeError, ValueError):
                continue
            text_str = str(text_val)
            display = text_str[:max_display_len]
            item = QTreeWidgetItem([
                f"0x{offset_int:08X}",
                str(len(text_str)),
                display,
            ])
            self._strings_tree.addTopLevelItem(item)

    def _on_strings_failed(self, message: str) -> None:
        """Record a failed string extraction and clear the pending-scan row.

        Args:
            message: Error message emitted by the extraction worker.
        """
        _logger.warning("strings_extract_failed", error=message)
        if self._strings_tree is not None:
            self._strings_tree.clear()
            self._strings_tree.addTopLevelItem(QTreeWidgetItem(["-", "-", f"(error: {message})"]))

    def _on_string_double_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        """Navigate to the string offset when double-clicked.

        Args:
            item: The clicked tree item.
            column: The clicked column index.
        """
        _ = column
        offset_text = item.text(0)
        try:
            offset = int(offset_text, 16)
        except ValueError:
            _logger.warning("hex_editor_string_invalid_offset", input_text=offset_text)
        else:
            self.goto_offset(offset)

    def _auto_detect_file_type(self) -> None:
        """Detect the file type from magic bytes and auto-select the template."""
        if self.document is None or self._template_combo is None:
            return

        try:
            magic_raw: object = self.document.read(0, 4)
        except (AttributeError, ValueError):
            _logger.exception("auto_detect_failed")
            return

        if isinstance(magic_raw, bytes):
            magic = magic_raw
        elif isinstance(magic_raw, bytearray):
            magic = bytes(magic_raw)
        elif isinstance(magic_raw, list):
            magic_list = cast("list[int]", magic_raw)
            magic = bytes(magic_list)
        else:
            magic = b""

        entry = _FORMAT_TO_TEMPLATE.get(detect_format(magic))
        if entry is not None:
            detected, template_name = entry
            self._select_template(template_name)
            if self._file_info_label is not None:
                current = self._file_info_label.text()
                self._file_info_label.setText(f"{current} [{detected}]")

        self._try_pattern_registry_match()

    def _try_pattern_registry_match(self) -> None:
        """Attempt to match the open file against .hexpat patterns via ``HexEditorBridge.auto_detect_pattern``.

        Routes through the bridge's own pattern registry instead of instantiating a second, GUI-local ``PatternRegistry`` so the AI-callable
        tool and the auto-detect-on-open feature share a single source of truth for pattern matching.
        """
        if self.document is None or not hexpat_interpreter_available:
            return

        bridge = getattr(self, "_bridge", None)
        if bridge is None:
            _logger.warning("pattern_auto_detect_bridge_unavailable")
            return

        run_bridge_coroutine_logged(
            bridge.auto_detect_pattern(),
            on_success=self._on_pattern_auto_detect_ready,
            on_error=self._on_pattern_auto_detect_failed,
            parent=self if isinstance(self, QWidget) else None,
            event="hex_editor_auto_detect_pattern",
            logger=_logger,
        )

    def _on_pattern_auto_detect_ready(self, result: object) -> None:
        """Render the bridge's matched-pattern names into the status label.

        Args:
            result: ``list[dict]`` payload returned by
                :meth:`HexEditorBridge.auto_detect_pattern`. Each dict
                exposes ``name``, ``description``, and ``category`` keys.
        """
        if not isinstance(result, list) or self._pattern_status_label is None:
            return
        matches = cast("list[dict[str, Any]]", result)
        if not matches:
            return
        names = ", ".join(str(m.get("name", "")) for m in matches[:3])
        self._pattern_status_label.setText(f"Detected patterns: {names}")

    @staticmethod
    def _on_pattern_auto_detect_failed(exc: object) -> None:
        """Log a pattern auto-detect failure raised by the bridge.

        Args:
            exc: Exception object emitted by the bridge worker.
        """
        _logger.warning("pattern_auto_detect_failed", error_type=type(exc).__name__, error=str(exc))
