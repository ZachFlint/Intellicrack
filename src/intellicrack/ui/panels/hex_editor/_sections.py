# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Sections/imports/exports/strings mixin for the hex editor panel."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from PyQt6.QtWidgets import QComboBox, QLabel, QTreeWidget, QTreeWidgetItem

from intellicrack.ui.panels.hex_editor._base import (
    PREVIEW_BYTES,
    PRINTABLE_MAX,
    PRINTABLE_MIN,
    DataReaderCls,
    PatternRegistryCls,
    hexpat_interpreter_available,
    logger,
    pefile,
    pefile_available,
)


class SectionsMixin:
    """Mixin providing PE section/import/export/string parsing and file type detection."""

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

    def goto_offset(self, offset: int) -> None: ...
    def _select_template(self, template_name: str) -> None: ...

    def _populate_sections(self) -> None:
        """Populate the sections tree using pefile."""
        if self._sections_tree is None or self._file_path is None:
            return

        self._sections_tree.clear()

        if not pefile_available or pefile is None:
            logger.debug("pefile_not_available")
            return

        try:
            pe = pefile.PE(str(self._file_path), fast_load=True)
        except (AttributeError, ValueError, OSError) as exc:
            logger.debug("sections_parse_failed", error=str(exc))
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
                    self._sections_tree.addTopLevelItem(item)
        except (AttributeError, ValueError) as exc:
            logger.debug("sections_parse_failed", error=str(exc))
        finally:
            pe.close()

    def _populate_imports(self) -> None:
        """Populate the imports tree using pefile."""
        if self._imports_tree is None or self._file_path is None:
            return

        self._imports_tree.clear()

        if not pefile_available or pefile is None:
            logger.debug("pefile_not_available_for_imports")
            return

        try:
            pe = pefile.PE(str(self._file_path), fast_load=True)
        except (AttributeError, ValueError, OSError) as exc:
            logger.debug("imports_parse_failed", error=str(exc))
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
        except (AttributeError, ValueError) as exc:
            logger.debug("imports_parse_failed", error=str(exc))
        finally:
            pe.close()

    def _populate_exports(self) -> None:
        """Populate the exports tree using pefile."""
        if self._exports_tree is None or self._file_path is None:
            return

        self._exports_tree.clear()

        if not pefile_available or pefile is None:
            logger.debug("pefile_not_available_for_exports")
            return

        try:
            pe = pefile.PE(str(self._file_path), fast_load=True)
        except (AttributeError, ValueError, OSError) as exc:
            logger.debug("exports_parse_failed", error=str(exc))
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
        except (AttributeError, ValueError) as exc:
            logger.debug("exports_parse_failed", error=str(exc))
        finally:
            pe.close()

    def _populate_strings(self) -> None:
        """Scan the document for printable ASCII strings and populate the strings tab."""
        if self._strings_tree is None or self._document is None:
            return

        self._strings_tree.clear()
        chunk_size = 65536
        min_string_len = 4
        max_strings = 5000
        max_display_len = PREVIEW_BYTES

        doc_len: int = self._document.length()
        string_count = 0
        current_string_start = -1
        current_chars: list[str] = []
        offset = 0

        while offset < doc_len and string_count < max_strings:
            chunk_len = min(chunk_size, doc_len - offset)
            raw = self._document.read(offset, chunk_len)
            if isinstance(raw, (list, bytearray)):
                raw = bytes(raw)

            for i, byte_val in enumerate(raw):
                abs_offset = offset + i
                if PRINTABLE_MIN <= byte_val <= PRINTABLE_MAX:
                    if current_string_start < 0:
                        current_string_start = abs_offset
                    current_chars.append(chr(byte_val))
                else:
                    if len(current_chars) >= min_string_len:
                        string_val = "".join(current_chars)
                        display = string_val[:max_display_len]
                        item = QTreeWidgetItem([
                            f"0x{current_string_start:08X}",
                            str(len(string_val)),
                            display,
                        ])
                        self._strings_tree.addTopLevelItem(item)
                        string_count += 1
                        if string_count >= max_strings:
                            break
                    current_string_start = -1
                    current_chars.clear()

            offset += chunk_len

        if len(current_chars) >= min_string_len and string_count < max_strings:
            string_val = "".join(current_chars)
            display = string_val[:max_display_len]
            item = QTreeWidgetItem([
                f"0x{current_string_start:08X}",
                str(len(string_val)),
                display,
            ])
            self._strings_tree.addTopLevelItem(item)

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
        if self._document is None or self._template_combo is None:
            return

        try:
            magic_raw: object = self._document.read(0, 4)
        except (AttributeError, ValueError) as exc:
            logger.debug("auto_detect_failed", error=str(exc))
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
        if (
            self._document is None
            or not hexpat_interpreter_available
            or PatternRegistryCls is None
            or DataReaderCls is None
        ):
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
            data_reader = DataReaderCls.from_document(self._document)
            matches = registry.match_file(data_reader)
        except (AttributeError, ValueError) as exc:
            logger.debug("pattern_registry_match_failed", error=str(exc))
            return

        if matches and self._pattern_status_label is not None:
            names = ", ".join(m.name for m in matches[:3])
            self._pattern_status_label.setText(f"Detected patterns: {names}")
