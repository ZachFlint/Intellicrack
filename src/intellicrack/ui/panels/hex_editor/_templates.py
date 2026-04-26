# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Templates mixin for the hex editor panel."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final, cast

from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QMessageBox,
    QTreeWidget,
    QTreeWidgetItem,
    QWidget,
)

from intellicrack.bridges._pe_format import (
    PE_COFF_HEADER_SIZE,
    PE_DOS_HEADER_SIZE,
    PE_DOS_LFANEW_OFFSET,
    PE_OPTIONAL_HEADER_OFFSET,
    PE_SIGNATURE,
    read_dos_e_lfanew,
    unpack_coff_header,
)
from intellicrack.core.logging import get_logger
from intellicrack.ui.resources.theme_manager import ThemeManager


_logger = get_logger(__name__)


_TEMPLATE_COLOR_DARK: Final[str] = "#44FF44"
_TEMPLATE_COLOR_LIGHT: Final[str] = "#2E7D32"
_MAGIC_MIN_LEN: Final[int] = 2
_ELF_CLASS_64: Final[int] = 2
_MAX_BOOKMARK_SECTIONS: Final[int] = 20


def _get_default_template_color() -> str:
    """Return a theme-appropriate default color for template field highlights.

    Returns:
        str: Hex color string suitable for the active theme.
    """
    if ThemeManager.get_instance().is_dark_theme():
        return _TEMPLATE_COLOR_DARK
    return _TEMPLATE_COLOR_LIGHT


class TemplatesMixin:
    """Mixin providing struct template application and display for the hex editor panel."""

    _document: Any | None
    document: Any | None
    _hex_widget: Any | None
    _template_combo: QComboBox | None
    _templates_tree: QTreeWidget | None

    def _on_apply_template(self) -> None:
        """Apply the selected struct template at the current cursor offset."""
        if self.document is None or self._template_combo is None or self._templates_tree is None:
            return

        template_name = self._template_combo.currentText()
        if not template_name:
            return

        cursor_offset = 0
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)

        try:
            result = self.document.apply_template(template_name, cursor_offset)
        except (AttributeError, ValueError):
            _logger.exception("template_apply_failed", template_name=template_name)
        else:
            self._templates_tree.clear()

            if isinstance(result, list):
                typed_fields = cast("list[dict[str, object]]", result)
                self._populate_template_tree(typed_fields)
                self._highlight_template_fields(typed_fields)

            _logger.info("template_applied", template=template_name)

    def _populate_template_tree(self, fields: list[dict[str, object]]) -> None:
        """Populate the templates tree with parsed field data.

        Supports arbitrary nesting depth by recursively building child items.

        Args:
            fields: List of field dictionaries from the template engine.
        """
        if self._templates_tree is None:
            return

        for field_data in fields:
            item = QTreeWidgetItem([
                str(field_data.get("name", "")),
                str(field_data.get("offset", "")),
                str(field_data.get("size", "")),
                str(field_data.get("display_value", "")),
            ])
            self._templates_tree.addTopLevelItem(item)
            TemplatesMixin._add_field_children(item, field_data)

    @staticmethod
    def _add_field_children(
        parent_item: QTreeWidgetItem,
        field_data: dict[str, object],
    ) -> None:
        """Recursively add child fields to a tree widget item.

        Args:
            parent_item: The parent QTreeWidgetItem to add children to.
            field_data: Field dict potentially containing a 'children' list.
        """
        children_raw = field_data.get("children")
        if not isinstance(children_raw, list):
            return
        children = cast("list[dict[str, object]]", children_raw)
        for child in children:
            child_item = QTreeWidgetItem([
                str(child.get("name", "")),
                str(child.get("offset", "")),
                str(child.get("size", "")),
                str(child.get("display_value", "")),
            ])
            parent_item.addChild(child_item)
            TemplatesMixin._add_field_children(child_item, child)

    def _highlight_template_fields(self, fields: list[dict[str, object]]) -> None:
        """Apply highlight overlays for template field regions.

        Recursively collects all descendant field regions for highlighting.

        Args:
            fields: List of field dictionaries from the template engine.
        """
        if self._hex_widget is None:
            return

        highlights: list[tuple[int, int, str]] = []
        TemplatesMixin._collect_field_highlights(fields, highlights)

        highlight_fn = getattr(self._hex_widget, "highlight_offsets", None)
        if callable(highlight_fn):
            highlight_fn(highlights, "template")

    @staticmethod
    def _collect_field_highlights(
        fields: list[dict[str, object]],
        highlights: list[tuple[int, int, str]],
    ) -> None:
        """Recursively collect highlight regions from nested field data.

        Args:
            fields: List of field dictionaries.
            highlights: Accumulator list for (offset, size, color) tuples.
        """
        for field_data in fields:
            f_offset = field_data.get("offset")
            f_size = field_data.get("size")
            if isinstance(f_offset, int) and isinstance(f_size, int):
                color_raw = field_data.get("color")
                color = str(color_raw) if isinstance(color_raw, str) else _get_default_template_color()
                highlights.append((f_offset, f_size, color))
            children_raw = field_data.get("children")
            if isinstance(children_raw, list):
                children = cast("list[dict[str, object]]", children_raw)
                TemplatesMixin._collect_field_highlights(children, highlights)

    def _populate_template_combo(self) -> None:
        """Populate the template combo box with available templates."""
        if self._template_combo is None or self.document is None:
            return

        self._template_combo.clear()
        try:
            templates: list[tuple[str, str]] = self.document.list_templates()
        except (AttributeError, ValueError, RuntimeError):
            _logger.exception("list_templates_failed")
            templates = []
        for name, _description in templates:
            self._template_combo.addItem(str(name))

    def _select_template(self, template_name: str) -> None:
        """Select a template by name in the combo box.

        Args:
            template_name: Template name to select.
        """
        if self._template_combo is None:
            return
        idx = self._template_combo.findText(template_name)
        if idx >= 0:
            self._template_combo.setCurrentIndex(idx)

    def _on_import_template(self) -> None:
        """Import a template from a JSON file and register it."""
        if self.document is None:
            return

        parent = self if isinstance(self, QWidget) else None
        result = QFileDialog.getOpenFileName(
            parent,
            "Import Template",
            "",
            "JSON Files (*.json);;All Files (*)",
        )
        file_path = result[0] if result else ""
        if not file_path:
            return

        try:
            json_str = Path(file_path).read_text(encoding="utf-8")
            name: str = self.document.register_json_template(json_str)
        except (OSError, ValueError, AttributeError) as exc:
            QMessageBox.warning(parent, "Import Template", f"Import failed:\n{exc}")
            _logger.exception("template_import_failed")
        else:
            self._populate_template_combo()
            self._select_template(name)
            _logger.info("template_imported", template_name=name)

    def _on_export_template(self) -> None:
        """Export the selected template to a JSON file."""
        if self.document is None or self._template_combo is None:
            return

        name = self._template_combo.currentText()
        if not name:
            return

        parent = self if isinstance(self, QWidget) else None
        result = QFileDialog.getSaveFileName(
            parent,
            "Export Template",
            f"{name}.json",
            "JSON Files (*.json);;All Files (*)",
        )
        save_path = result[0] if result else ""
        if not save_path:
            return

        try:
            json_str: str = self.document.export_template_json(name)
            _logger.info("file_written", path=save_path, size=len(json_str), kind="template_json")
            Path(save_path).write_text(json_str, encoding="utf-8")
        except (OSError, ValueError, AttributeError) as exc:
            QMessageBox.warning(parent, "Export Template", f"Export failed:\n{exc}")
            _logger.exception("template_export_failed")
        else:
            _logger.info("template_exported", template_name=name, path=save_path)

    def _on_remove_template(self) -> None:
        """Remove the selected template from the registry."""
        if self.document is None or self._template_combo is None:
            return

        name = self._template_combo.currentText()
        if not name:
            return

        parent = self if isinstance(self, QWidget) else None
        reply = QMessageBox.question(
            parent,
            "Remove Template",
            f"Remove template '{name}'?",
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            self.document.remove_template(name)
        except (AttributeError, ValueError):
            _logger.exception("template_remove_failed", template_name=name)
        else:
            self._populate_template_combo()
            _logger.info("template_removed", template_name=name)

    def _on_auto_bookmark_structure(self) -> None:
        """Automatically create bookmarks for PE/ELF structure regions."""
        if self.document is None:
            return

        try:
            magic_raw: object = self.document.read(0, 4)
        except (AttributeError, ValueError):
            return

        if isinstance(magic_raw, bytes):
            magic = magic_raw
        elif isinstance(magic_raw, bytearray):
            magic = bytes(magic_raw)
        elif isinstance(magic_raw, list):
            magic = bytes(cast("list[int]", magic_raw))
        else:
            return

        if len(magic) < _MAGIC_MIN_LEN:
            return

        if magic[:_MAGIC_MIN_LEN] == b"\x4d\x5a":
            self._bookmark_pe_structure()
        elif magic[:4] == b"\x7fELF":
            self._bookmark_elf_structure()
        else:
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.information(
                parent,
                "Auto Bookmark",
                "Unsupported file format (PE and ELF supported).",
            )

    def _bookmark_pe_structure(self) -> None:
        """Create colored bookmarks for PE file structure regions."""
        if self.document is None:
            return

        try:
            dos_raw: object = self.document.read(0, PE_DOS_HEADER_SIZE)
            if isinstance(dos_raw, bytes):
                dos_data = dos_raw
            elif isinstance(dos_raw, bytearray):
                dos_data = bytes(dos_raw)
            elif isinstance(dos_raw, list):
                dos_data = bytes(cast("list[int]", dos_raw))
            else:
                return
        except (AttributeError, ValueError):
            return

        self.document.add_bookmark(0, PE_DOS_HEADER_SIZE, "DOS Header", "#FF6B6B")

        if len(dos_data) < PE_DOS_LFANEW_OFFSET + 4:
            return
        e_lfanew = read_dos_e_lfanew(dos_data)

        try:
            coff_raw: object = self.document.read(e_lfanew, 4 + PE_COFF_HEADER_SIZE)
            if isinstance(coff_raw, bytes):
                coff_data = coff_raw
            elif isinstance(coff_raw, bytearray):
                coff_data = bytes(coff_raw)
            elif isinstance(coff_raw, list):
                coff_data = bytes(cast("list[int]", coff_raw))
            else:
                return
        except (AttributeError, ValueError):
            return

        if len(coff_data) < 4 + PE_COFF_HEADER_SIZE or coff_data[:4] != PE_SIGNATURE:
            return

        self.document.add_bookmark(e_lfanew, PE_OPTIONAL_HEADER_OFFSET, "PE File Header", "#4ECDC4")

        _machine, num_sections, opt_size, _characteristics = unpack_coff_header(coff_data, 4)
        if opt_size > 0:
            self.document.add_bookmark(e_lfanew + PE_OPTIONAL_HEADER_OFFSET, opt_size, "Optional Header", "#4ECDC4")

        section_offset = e_lfanew + PE_OPTIONAL_HEADER_OFFSET + opt_size

        self._bookmark_pe_sections(section_offset, num_sections)
        self._refresh_bookmarks()
        _logger.info("pe_structure_bookmarked", sections=num_sections)

    def _bookmark_pe_sections(self, section_offset: int, num_sections: int) -> None:
        """Create bookmarks for each PE section header.

        Args:
            section_offset: Byte offset of the first section header.
            num_sections: Total number of sections to bookmark.
        """
        if self.document is None:
            return
        section_colors = ["#45B7D1", "#96CEB4", "#FFEAA7", "#DDA0DD", "#98D8C8"]
        for i in range(min(num_sections, _MAX_BOOKMARK_SECTIONS)):
            sec_off = section_offset + i * 40
            try:
                sec_raw: object = self.document.read(sec_off, 8)
                if isinstance(sec_raw, bytes):
                    sec_name = sec_raw.rstrip(b"\x00").decode("ascii", errors="replace")
                elif isinstance(sec_raw, bytearray):
                    sec_name = bytes(sec_raw).rstrip(b"\x00").decode("ascii", errors="replace")
                elif isinstance(sec_raw, list):
                    sec_name = bytes(cast("list[int]", sec_raw)).rstrip(b"\x00").decode("ascii", errors="replace")
                else:
                    sec_name = f"Section {i}"
            except (AttributeError, ValueError):
                sec_name = f"Section {i}"
            color = section_colors[i % len(section_colors)]
            self.document.add_bookmark(sec_off, 40, sec_name, color)

    def _bookmark_elf_structure(self) -> None:
        """Create colored bookmarks for ELF file structure regions."""
        if self.document is None:
            return

        self.document.add_bookmark(0, 64, "ELF Header", "#FF6B6B")

        try:
            ident_raw: object = self.document.read(4, 1)
            if isinstance(ident_raw, bytes):
                ei_class = ident_raw[0]
            elif isinstance(ident_raw, bytearray):
                ei_class = bytes(ident_raw)[0]
            elif isinstance(ident_raw, list):
                ei_class = bytes(cast("list[int]", ident_raw))[0]
            else:
                return
        except (AttributeError, ValueError):
            return

        is_64 = ei_class == _ELF_CLASS_64

        if is_64:
            try:
                hdr_raw: object = self.document.read(32, 16)
                if isinstance(hdr_raw, bytes):
                    hdr = hdr_raw
                elif isinstance(hdr_raw, bytearray):
                    hdr = bytes(hdr_raw)
                elif isinstance(hdr_raw, list):
                    hdr = bytes(cast("list[int]", hdr_raw))
                else:
                    return
            except (AttributeError, ValueError):
                return

            ph_offset = int.from_bytes(hdr[0:8], "little")
            sh_offset = int.from_bytes(hdr[8:16], "little")

            try:
                count_raw: object = self.document.read(56, 4)
                if isinstance(count_raw, bytes):
                    count_data = count_raw
                elif isinstance(count_raw, bytearray):
                    count_data = bytes(count_raw)
                elif isinstance(count_raw, list):
                    count_data = bytes(cast("list[int]", count_raw))
                else:
                    return
            except (AttributeError, ValueError):
                return

            ph_count = int.from_bytes(count_data[0:2], "little")
            sh_count = int.from_bytes(count_data[2:4], "little")
        else:
            try:
                hdr_raw = self.document.read(28, 8)
                if isinstance(hdr_raw, bytes):
                    hdr = hdr_raw
                elif isinstance(hdr_raw, bytearray):
                    hdr = bytes(hdr_raw)
                elif isinstance(hdr_raw, list):
                    hdr = bytes(cast("list[int]", hdr_raw))
                else:
                    return
            except (AttributeError, ValueError):
                return

            ph_offset = int.from_bytes(hdr[0:4], "little")
            sh_offset = int.from_bytes(hdr[4:8], "little")
            ph_count = 0
            sh_count = 0

        if ph_offset > 0 and ph_count > 0:
            ph_entry_size = 56 if is_64 else 32
            self.document.add_bookmark(
                ph_offset,
                ph_entry_size * ph_count,
                "Program Headers",
                "#4ECDC4",
            )

        if sh_offset > 0 and sh_count > 0:
            sh_entry_size = 64 if is_64 else 40
            self.document.add_bookmark(
                sh_offset,
                sh_entry_size * sh_count,
                "Section Headers",
                "#45B7D1",
            )

        self._refresh_bookmarks()
        _logger.info("elf_structure_bookmarked")

    def _refresh_bookmarks(self) -> None:
        """Refresh the bookmarks display after modification.

        Delegates to the bookmarks mixin if available.
        """
        refresh_fn = getattr(self, "_refresh_bookmarks_tree", None)
        if callable(refresh_fn):
            refresh_fn()
