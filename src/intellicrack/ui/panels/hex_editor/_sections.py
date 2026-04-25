# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Sections/imports/exports/strings mixin for the hex editor panel."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final, Protocol, cast, runtime_checkable

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import QComboBox, QLabel, QTreeWidget, QTreeWidgetItem

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.hex_editor._base import (
    PREVIEW_BYTES,
    DataReaderCls,
    PatternRegistryCls,
    hexpat_interpreter_available,
    pefile,
    pefile_available,
)


_logger = get_logger(__name__)


_STRINGS_MIN_LENGTH: Final[int] = 4
_STRINGS_MAX_RESULTS: Final[int] = 5000


@runtime_checkable
class _StringsSource(Protocol):
    """Subset of the hexcore ``HexDocument`` API required by ``StringsExtractionWorker``."""

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


class StringsExtractionWorker(QThread):
    """Background worker that invokes ``document.extract_strings`` off the UI thread.

    Attributes:
        strings_ready: Signal emitted with the list of string entries on success.
        strings_failed: Signal emitted with the error message on failure.
    """

    strings_ready: pyqtSignal = pyqtSignal(object)
    strings_failed: pyqtSignal = pyqtSignal(str)

    def __init__(
        self,
        document: _StringsSource,
        min_length: int,
        max_results: int,
        parent: QThread | None = None,
    ) -> None:
        """Initialise the strings extraction worker.

        Args:
            document: The hexcore ``HexDocument`` (or compatible) to invoke ``extract_strings`` on.
            min_length: Minimum string length in characters/codepoints to keep.
            max_results: Upper bound on returned entries.
            parent: Optional ``QThread`` parent for Qt ownership.
        """
        super().__init__(parent)
        self._document: _StringsSource = document
        self._min_length: int = min_length
        self._max_results: int = max_results
        _: object = self.finished.connect(self.deleteLater)

    def run(self) -> None:
        """Execute ``extract_strings`` on the worker thread and emit the result.

        Emits ``strings_ready`` with the returned iterable on success, or
        ``strings_failed`` with the stringified error message on any recognised
        hexcore / IO failure.
        """
        document = self._document
        try:
            results = document.extract_strings(
                min_length=self._min_length,
                include_ascii=True,
                include_utf16=True,
                max_results=self._max_results,
            )
        except (RuntimeError, OSError, ValueError, AttributeError) as exc:
            self.strings_failed.emit(str(exc))
            return
        self.strings_ready.emit(results)


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

    def goto_offset(self, offset: int) -> None:
        """Navigate the hex widget to the given byte offset.

        Args:
            offset: Absolute byte offset within the active document.
        """

    def _select_template(self, template_name: str) -> None:
        """Select a structure template by name for the current file type.

        Args:
            template_name: Identifier of the template to activate.
        """

    def _populate_sections(self) -> None:
        """Populate the sections tree using pefile."""
        if self.sections_tree is None or self.file_path is None:
            return

        self.sections_tree.clear()

        if not pefile_available or pefile is None:
            _logger.warning("pefile_not_available")
            return

        try:
            pe = pefile.PE(str(self.file_path), fast_load=True)
        except (AttributeError, ValueError, OSError):
            _logger.exception("sections_parse_failed", file_path=str(self.file_path))
            return

        try:
            sections = getattr(pe, "sections", None)
            if sections is not None:
                for section in sections:
                    name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
                    vaddr = f"0x{section.VirtualAddress:08X}"
                    vsize = f"0x{section.Misc_VirtualSize:08X}"
                    rawsize = f"0x{section.SizeOfRawData:08X}"
                    item = QTreeWidgetItem([name, vaddr, vsize, rawsize])
                    self.sections_tree.addTopLevelItem(item)
        except (AttributeError, ValueError):
            _logger.exception("sections_parse_failed", file_path=str(self.file_path))
        finally:
            pe.close()

    def _populate_imports(self) -> None:
        """Populate the imports tree using pefile."""
        if self._imports_tree is None or self.file_path is None:
            return

        self._imports_tree.clear()

        if not pefile_available or pefile is None:
            _logger.warning("pefile_not_available_for_imports")
            return

        try:
            pe = pefile.PE(str(self.file_path), fast_load=True)
        except (AttributeError, ValueError, OSError):
            _logger.exception("imports_parse_failed", file_path=str(self.file_path))
            return

        try:
            dir_entry: dict[str, int] = getattr(pefile, "DIRECTORY_ENTRY", {})
            pe.parse_data_directories(directories=[dir_entry.get("IMAGE_DIRECTORY_ENTRY_IMPORT", 1)])
            import_dir = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None)
            if import_dir is not None:
                for entry in import_dir:
                    dll_name = entry.dll.decode("utf-8", errors="replace") if entry.dll else "unknown"
                    for imp in entry.imports:
                        func_name = imp.name.decode("utf-8", errors="replace") if imp.name else f"Ordinal {imp.ordinal}"
                        addr = f"0x{imp.address:08X}" if imp.address else "N/A"
                        item = QTreeWidgetItem([dll_name, func_name, addr])
                        self._imports_tree.addTopLevelItem(item)
        except (AttributeError, ValueError):
            _logger.exception("imports_parse_failed", file_path=str(self.file_path))
        finally:
            pe.close()

    def _populate_exports(self) -> None:
        """Populate the exports tree using pefile."""
        if self._exports_tree is None or self.file_path is None:
            return

        self._exports_tree.clear()

        if not pefile_available or pefile is None:
            _logger.warning("pefile_not_available_for_exports")
            return

        try:
            pe = pefile.PE(str(self.file_path), fast_load=True)
        except (AttributeError, ValueError, OSError):
            _logger.exception("exports_parse_failed", file_path=str(self.file_path))
            return

        try:
            dir_entry_exp: dict[str, int] = getattr(pefile, "DIRECTORY_ENTRY", {})
            pe.parse_data_directories(directories=[dir_entry_exp.get("IMAGE_DIRECTORY_ENTRY_EXPORT", 0)])
            export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
            if export_dir is not None:
                symbols = getattr(export_dir, "symbols", None)
                if symbols is not None:
                    for exp in symbols:
                        name = exp.name.decode("utf-8", errors="replace") if exp.name else f"Ordinal {exp.ordinal}"
                        addr = f"0x{exp.address:08X}" if exp.address else "N/A"
                        ordinal = str(exp.ordinal) if exp.ordinal is not None else "N/A"
                        item = QTreeWidgetItem([name, addr, ordinal])
                        self._exports_tree.addTopLevelItem(item)
        except (AttributeError, ValueError):
            _logger.exception("exports_parse_failed", file_path=str(self.file_path))
        finally:
            pe.close()

    def _populate_strings(self) -> None:
        """Populate the strings tab asynchronously via a ``QThread`` worker.

        Dispatches the hexcore ``extract_strings`` RPC on a background thread so
        that very large binaries do not block the Qt event loop while the Rust
        backend streams matches back.  Results are consumed on the UI thread
        through the worker's ``strings_ready`` / ``strings_failed`` signals.
        """
        if self._strings_tree is None or self.document is None:
            return

        self._strings_tree.clear()
        pending_row = QTreeWidgetItem(["-", "-", "(scanning...)"])
        self._strings_tree.addTopLevelItem(pending_row)

        previous = getattr(self, "_strings_worker", None)
        if isinstance(previous, StringsExtractionWorker) and previous.isRunning():
            previous.requestInterruption()

        worker = StringsExtractionWorker(
            self.document,
            _STRINGS_MIN_LENGTH,
            _STRINGS_MAX_RESULTS,
            parent=cast("QThread | None", self if isinstance(self, QThread) else None),
        )
        self._strings_worker = worker
        _: object = worker.strings_ready.connect(self._on_strings_ready)
        _ = worker.strings_failed.connect(self._on_strings_failed)
        worker.start()

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
            pass
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

        detected = ""
        pe_magic = b"\x4d\x5a"
        elf_magic = b"\x7fELF"
        zip_magic = b"\x50\x4b\x03\x04"
        macho_magics = {
            b"\xfe\xed\xfa\xce",
            b"\xfe\xed\xfa\xcf",
            b"\xce\xfa\xed\xfe",
            b"\xcf\xfa\xed\xfe",
        }
        if len(magic) >= len(pe_magic) and magic[:2] == pe_magic:
            detected = "PE"
            self._select_template("IMAGE_DOS_HEADER")
        elif len(magic) >= len(elf_magic) and magic[:4] == elf_magic:
            detected = "ELF"
            self._select_template("ELF_HEADER_64")
        elif len(magic) >= len(elf_magic) and magic[:4] in macho_magics:
            detected = "Mach-O"
            self._select_template("MACH_HEADER_64")
        elif len(magic) >= len(zip_magic) and magic[:4] == zip_magic:
            detected = "ZIP"
            self._select_template("ZIP_LOCAL_FILE_HEADER")

        if detected and self._file_info_label is not None:
            current = self._file_info_label.text()
            self._file_info_label.setText(f"{current} [{detected}]")

        self._try_pattern_registry_match()

    def _try_pattern_registry_match(self) -> None:
        """Attempt to match the open file against .hexpat patterns via magic bytes."""
        if self.document is None or not hexpat_interpreter_available or PatternRegistryCls is None or DataReaderCls is None:
            return

        if self._pattern_registry is None:
            project_root = Path(__file__).resolve().parents[4]
            patterns_dir = project_root / "vendor" / "community-patterns" / "patterns"
            pattern_dirs: list[Path] = []
            if patterns_dir.exists():
                pattern_dirs.append(patterns_dir)
            if not pattern_dirs:
                return
            self._pattern_registry = PatternRegistryCls(pattern_dirs)

        registry = self._pattern_registry
        if registry is None:
            return

        try:
            data_reader = DataReaderCls.from_document(self.document)
            matches = registry.match_file(data_reader)
        except (AttributeError, ValueError):
            _logger.exception("pattern_registry_match_failed")
            return

        if matches and self._pattern_status_label is not None:
            names = ", ".join(m.name for m in matches[:3])
            self._pattern_status_label.setText(f"Detected patterns: {names}")
