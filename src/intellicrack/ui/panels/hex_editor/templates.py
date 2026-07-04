# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Templates mixin for the hex editor panel."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, Final, Literal, cast

from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QMessageBox,
    QTreeWidget,
    QTreeWidgetItem,
    QWidget,
)

from intellicrack.bridges.pe_format import (
    PE_COFF_HEADER_SIZE,
    PE_DOS_HEADER_SIZE,
    PE_DOS_LFANEW_OFFSET,
    PE_OPTIONAL_HEADER_OFFSET,
    PE_SIGNATURE,
    read_dos_e_lfanew,
    unpack_coff_header,
)
from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged
from intellicrack.ui.resources.theme_manager import ThemeManager


_logger = get_logger(__name__)


_TEMPLATE_COLOR_DARK: Final[str] = "#44FF44"
_TEMPLATE_COLOR_LIGHT: Final[str] = "#2E7D32"
_MAGIC_MIN_LEN: Final[int] = 2
_ELF_CLASS_64: Final[int] = 2
_MAX_BOOKMARK_SECTIONS: Final[int] = 20

NotificationLevel = Literal["info", "warning"]
UserNotifier = Callable[[str, str, "NotificationLevel"], None]


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
    state_holder: Any | None
    _user_notifier: UserNotifier | None
    _bridge: Any | None

    def _notify_user(self, title: str, message: str, level: NotificationLevel) -> None:
        """Surface a user-facing notification through the injected reporter or a dialog.

        When a non-modal ``_user_notifier`` reporter is attached (for headless
        orchestration, the bridge layer, or tests), the notification is routed
        to it so the registry / bookmark mutation logic can run to completion
        without blocking on a modal dialog. Otherwise the panel falls back to
        the standard modal :class:`QMessageBox`.

        Args:
            title: Dialog / notification title.
            message: Human-readable notification body.
            level: ``"info"`` or ``"warning"`` notification severity.
        """
        notifier = getattr(self, "_user_notifier", None)
        if callable(notifier):
            notifier(title, message, level)
            return
        parent = self if isinstance(self, QWidget) else None
        if level == "warning":
            QMessageBox.warning(parent, title, message)
        else:
            QMessageBox.information(parent, title, message)

    def _notify_state_template_registered(self, template_name: str, *, source: str) -> None:
        """Forward template-registration to the shared state holder if attached.

        Args:
            template_name: Name of the registered template.
            source: Loop-guard identifier so the caller is filtered out.
        """
        holder = self.state_holder
        if holder is None:
            return
        notify = getattr(holder, "notify_template_registered", None)
        if not callable(notify):
            return
        notify(template_name, source=source)

    def _notify_state_template_removed(self, template_name: str, *, source: str) -> None:
        """Forward template-removal to the shared state holder if attached.

        Args:
            template_name: Name of the removed template.
            source: Loop-guard identifier so the caller is filtered out.
        """
        holder = self.state_holder
        if holder is None:
            return
        notify = getattr(holder, "notify_template_removed", None)
        if not callable(notify):
            return
        notify(template_name, source=source)

    def _notify_state_data_modified(self, offset: int, length: int, *, source: str) -> None:
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

    def _notify_state_pattern_executed(
        self,
        pattern_name: str,
        field_count: int,
        *,
        source: str,
    ) -> None:
        """Forward a pattern-execution event to the shared state holder if attached.

        Args:
            pattern_name: Name of the executed pattern or template.
            field_count: Number of top-level fields produced by the execution.
            source: Loop-guard identifier so the caller is filtered out.
        """
        holder = self.state_holder
        if holder is None:
            return
        notify = getattr(holder, "notify_pattern_executed", None)
        if not callable(notify):
            return
        notify(pattern_name, field_count, source=source)

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

            field_count = 0
            if isinstance(result, list):
                typed_fields = cast("list[dict[str, object]]", result)
                field_count = len(typed_fields)
                self._populate_template_tree(typed_fields)
                self._highlight_template_fields(typed_fields)

            self._notify_state_template_registered(
                template_name,
                source="hex-editor.templates.apply.register",
            )
            self._notify_state_pattern_executed(
                template_name,
                field_count,
                source="hex-editor.templates.apply",
            )

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
        """Populate the template combo box with available templates.

        Routes through :meth:`HexEditorBridge.list_templates_detailed` instead of the document's plain ``list_templates()`` so the combo is
        populated from the same richer (name, description, category, field_count) metadata the AI-callable tool sees, even though only the
        name is currently rendered into the widget.
        """
        if self._template_combo is None or self.document is None:
            return

        bridge = self._bridge
        if bridge is None:
            _logger.warning("template_combo_bridge_unavailable")
            self._populate_template_combo_fallback()
            return

        run_bridge_coroutine_logged(
            bridge.list_templates_detailed(),
            on_success=self._on_templates_detailed_ready,
            on_error=self._on_templates_detailed_failed,
            parent=self if isinstance(self, QWidget) else None,
            event="hex_editor_list_templates_detailed",
            logger=_logger,
        )

    def _populate_template_combo_fallback(self) -> None:
        """Populate the template combo directly from the document when no bridge is attached."""
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

    def _on_templates_detailed_ready(self, result: object) -> None:
        """Render the bridge's detailed template metadata into the combo box.

        Args:
            result: ``list[dict]`` payload returned by
                :meth:`HexEditorBridge.list_templates_detailed`. Each
                dict exposes ``name``, ``description``, ``category``,
                and ``field_count`` keys.
        """
        if self._template_combo is None:
            return
        if not isinstance(result, list):
            _logger.warning("templates_detailed_unexpected_result_type", result_type=type(result).__name__)
            return
        typed_result = cast("list[dict[str, Any]]", result)
        self._template_combo.clear()
        for entry in typed_result:
            self._template_combo.addItem(str(entry.get("name", "")))

    @staticmethod
    def _on_templates_detailed_failed(exc: object) -> None:
        """Log a detailed-template listing failure raised by the bridge.

        Args:
            exc: Exception raised by
                :meth:`HexEditorBridge.list_templates_detailed`.
        """
        _logger.warning("templates_detailed_failed", error=str(exc))

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

        self._import_template_from_path(file_path)

    def _import_template_from_path(self, file_path: str) -> None:
        """Register a JSON template from ``file_path`` on the active document.

        Holds the non-interactive half of :meth:`_on_import_template` so the
        registration, combo refresh and ``TEMPLATE_REGISTERED`` notification
        can be exercised independently of the file-selection dialog.

        Args:
            file_path: Filesystem path to the JSON template definition.
        """
        if self.document is None:
            return

        try:
            json_str = Path(file_path).read_text(encoding="utf-8")
            name: str = self.document.register_json_template(json_str)
        except (OSError, ValueError, AttributeError) as exc:
            self._notify_user("Import Template", f"Import failed:\n{exc}", "warning")
            _logger.exception("template_import_failed")
        else:
            self._populate_template_combo()
            self._select_template(name)
            self._notify_state_template_registered(name, source="hex-editor.templates.import")
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
            _logger.info(
                "template_export_write_begin",
                path=save_path,
                size=len(json_str),
                kind="template_json",
                template_name=name,
            )
            Path(save_path).write_text(json_str, encoding="utf-8")
        except (OSError, ValueError, AttributeError) as exc:
            QMessageBox.warning(parent, "Export Template", f"Export failed:\n{exc}")
            _logger.exception("template_export_failed", template_name=name, path=save_path)
        else:
            _logger.info(
                "file_written",
                path=save_path,
                size=len(json_str),
                kind="template_json",
            )
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

        self._remove_template_named(name)

    def _remove_template_named(self, name: str) -> None:
        """Remove ``name`` from the active document's template registry.

        Holds the non-interactive half of :meth:`_on_remove_template` so the
        deletion, combo refresh and ``TEMPLATE_REMOVED`` notification can be
        exercised independently of the confirmation dialog.

        Args:
            name: Name of the template to remove from the registry.
        """
        if self.document is None:
            return
        try:
            self.document.remove_template(name)
        except (AttributeError, ValueError):
            _logger.exception("template_remove_failed", template_name=name)
        else:
            self._populate_template_combo()
            self._notify_state_template_removed(name, source="hex-editor.templates.remove")
            _logger.info("template_removed", template_name=name)

    def _on_auto_bookmark_structure(self) -> None:
        """Automatically create bookmarks for PE/ELF/Mach-O structure regions.

        Routes through :meth:`HexEditorBridge.generate_structure_bookmarks`
        so the AI-callable tool and the toolbar action share a single
        detection-and-bookmark implementation (which also covers Mach-O,
        not handled by the local fallback). Falls back to the local
        PE/ELF-only walk when no bridge is attached, matching the local
        implementation's format support and error handling exactly.
        """
        if self.document is None:
            return

        bridge = getattr(self, "_bridge", None)
        if bridge is not None:
            run_bridge_coroutine_logged(
                bridge.generate_structure_bookmarks(),
                on_success=self._on_structure_bookmarks_ready,
                on_error=self._on_structure_bookmarks_failed,
                parent=self if isinstance(self, QWidget) else None,
                event="hex_editor_generate_structure_bookmarks",
                logger=_logger,
                level="info",
            )
            return

        self._auto_bookmark_structure_local()
        self._refresh_bookmarks()

    def _on_structure_bookmarks_ready(self, result: object) -> None:
        """Refresh the bookmarks tree after the bridge created structure bookmarks.

        The bridge itself calls ``document.add_bookmark`` for each
        detected region, so this handler only needs to refresh the
        GUI's bookmarks tree and surface the "unsupported format"
        notice when the bridge detected neither PE, ELF, nor Mach-O
        structure.

        Args:
            result: ``list[dict]`` payload returned by
                :meth:`HexEditorBridge.generate_structure_bookmarks`.
        """
        if not isinstance(result, list):
            _logger.warning("structure_bookmarks_unexpected_result_type", result_type=type(result).__name__)
            return
        typed_result = cast("list[dict[str, Any]]", result)
        if not typed_result:
            self._notify_user(
                "Auto Bookmark",
                "Unsupported file format (PE, ELF, and Mach-O supported).",
                "info",
            )
            return
        self._refresh_bookmarks()
        _logger.info("structure_bookmarked", bookmark_count=len(typed_result))

    @staticmethod
    def _on_structure_bookmarks_failed(exc: object) -> None:
        """Log a structure-bookmark generation failure raised by the bridge.

        Args:
            exc: Exception raised by
                :meth:`HexEditorBridge.generate_structure_bookmarks`.
        """
        _logger.warning("structure_bookmarks_failed", error=str(exc))

    def _auto_bookmark_structure_local(self) -> None:
        """Create PE/ELF structure bookmarks directly against the document.

        Local fallback used only when no bridge is attached to this mixin (e.g. headless / test harnesses that drive the document directly),
        preserving the exact PE/ELF detection and bookmark regions the panel has always produced.
        """
        document = self.document
        if document is None:
            return

        try:
            magic_raw: object = document.read(0, 4)
        except (AttributeError, ValueError) as exc:
            _logger.warning(
                "auto_bookmark_magic_read_failed",
                exc_type=type(exc).__name__,
                error=str(exc),
            )
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
            self._notify_user(
                "Auto Bookmark",
                "Unsupported file format (PE and ELF supported).",
                "info",
            )

    def _read_document_bytes(self, offset: int, length: int) -> bytes | None:
        """Read ``length`` bytes from the document at ``offset`` as ``bytes``.

        Args:
            offset: Byte offset to read from.
            length: Number of bytes to request.

        Returns:
            bytes | None: Decoded byte payload, or ``None`` if the document is
                missing or returned an unsupported payload type.
        """
        document: Any = self.document
        if document is None:
            return None
        raw: object = document.read(offset, length)
        if isinstance(raw, bytes):
            return raw
        if isinstance(raw, bytearray):
            return bytes(raw)
        return bytes(cast("list[int]", raw)) if isinstance(raw, list) else None

    def _bookmark_pe_structure(self) -> None:
        """Create colored bookmarks for PE file structure regions."""
        if self.document is None:
            return

        try:
            dos_data = self._read_document_bytes(0, PE_DOS_HEADER_SIZE)
        except (AttributeError, ValueError) as exc:
            _logger.warning(
                "pe_bookmark_dos_header_read_failed",
                exc_type=type(exc).__name__,
                error=str(exc),
            )
            return
        if dos_data is None:
            return

        self.document.add_bookmark(0, PE_DOS_HEADER_SIZE, "DOS Header", "#FF6B6B")
        self._notify_state_data_modified(0, PE_DOS_HEADER_SIZE, source="hex-editor.templates.auto-bookmark.pe")

        if len(dos_data) < PE_DOS_LFANEW_OFFSET + 4:
            return
        e_lfanew = read_dos_e_lfanew(dos_data)

        try:
            coff_data = self._read_document_bytes(e_lfanew, 4 + PE_COFF_HEADER_SIZE)
        except (AttributeError, ValueError) as exc:
            _logger.warning(
                "pe_bookmark_coff_header_read_failed",
                e_lfanew=e_lfanew,
                exc_type=type(exc).__name__,
                error=str(exc),
            )
            return
        if coff_data is None:
            return

        if len(coff_data) < 4 + PE_COFF_HEADER_SIZE or coff_data[:4] != PE_SIGNATURE:
            return

        self.document.add_bookmark(e_lfanew, PE_OPTIONAL_HEADER_OFFSET, "PE File Header", "#4ECDC4")
        self._notify_state_data_modified(
            e_lfanew,
            PE_OPTIONAL_HEADER_OFFSET,
            source="hex-editor.templates.auto-bookmark.pe",
        )

        _machine, num_sections, opt_size, _characteristics = unpack_coff_header(coff_data, 4)
        if opt_size > 0:
            self.document.add_bookmark(e_lfanew + PE_OPTIONAL_HEADER_OFFSET, opt_size, "Optional Header", "#4ECDC4")
            self._notify_state_data_modified(
                e_lfanew + PE_OPTIONAL_HEADER_OFFSET,
                opt_size,
                source="hex-editor.templates.auto-bookmark.pe",
            )

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
                sec_bytes = self._read_document_bytes(sec_off, 8)
            except (AttributeError, ValueError) as exc:
                _logger.warning(
                    "pe_bookmark_section_read_failed",
                    section_index=i,
                    section_offset=sec_off,
                    exc_type=type(exc).__name__,
                    error=str(exc),
                )
                sec_bytes = None
            sec_name = sec_bytes.rstrip(b"\x00").decode("ascii", errors="replace") if sec_bytes is not None else f"Section {i}"
            color = section_colors[i % len(section_colors)]
            self.document.add_bookmark(sec_off, 40, sec_name, color)
            self._notify_state_data_modified(sec_off, 40, source="hex-editor.templates.auto-bookmark.pe")

    def _bookmark_elf_structure(self) -> None:
        """Create colored bookmarks for ELF file structure regions."""
        if self.document is None:
            return

        self.document.add_bookmark(0, 64, "ELF Header", "#FF6B6B")
        self._notify_state_data_modified(0, 64, source="hex-editor.templates.auto-bookmark.elf")

        try:
            ident_bytes = self._read_document_bytes(4, 1)
        except (AttributeError, ValueError) as exc:
            _logger.warning(
                "elf_bookmark_ei_class_read_failed",
                exc_type=type(exc).__name__,
                error=str(exc),
            )
            return
        if ident_bytes is None:
            return
        ei_class = ident_bytes[0]

        is_64 = ei_class == _ELF_CLASS_64

        if is_64:
            try:
                hdr = self._read_document_bytes(32, 16)
            except (AttributeError, ValueError) as exc:
                _logger.warning(
                    "elf64_bookmark_header_read_failed",
                    exc_type=type(exc).__name__,
                    error=str(exc),
                )
                return
            if hdr is None:
                return

            ph_offset = int.from_bytes(hdr[:8], "little")
            sh_offset = int.from_bytes(hdr[8:16], "little")

            try:
                count_data = self._read_document_bytes(56, 4)
            except (AttributeError, ValueError) as exc:
                _logger.warning(
                    "elf64_bookmark_header_counts_read_failed",
                    exc_type=type(exc).__name__,
                    error=str(exc),
                )
                return
            if count_data is None:
                return

            ph_count = int.from_bytes(count_data[:2], "little")
            sh_count = int.from_bytes(count_data[2:4], "little")
        else:
            try:
                hdr = self._read_document_bytes(28, 8)
            except (AttributeError, ValueError) as exc:
                _logger.warning(
                    "elf32_bookmark_header_read_failed",
                    exc_type=type(exc).__name__,
                    error=str(exc),
                )
                return
            if hdr is None:
                return

            ph_offset = int.from_bytes(hdr[:4], "little")
            sh_offset = int.from_bytes(hdr[4:8], "little")
            ph_count = 0
            sh_count = 0

        if ph_offset > 0 and ph_count > 0:
            ph_entry_size = 56 if is_64 else 32
            ph_total = ph_entry_size * ph_count
            self.document.add_bookmark(ph_offset, ph_total, "Program Headers", "#4ECDC4")
            self._notify_state_data_modified(ph_offset, ph_total, source="hex-editor.templates.auto-bookmark.elf")

        if sh_offset > 0 and sh_count > 0:
            sh_entry_size = 64 if is_64 else 40
            sh_total = sh_entry_size * sh_count
            self.document.add_bookmark(sh_offset, sh_total, "Section Headers", "#45B7D1")
            self._notify_state_data_modified(sh_offset, sh_total, source="hex-editor.templates.auto-bookmark.elf")

        self._refresh_bookmarks()
        _logger.info("elf_structure_bookmarked")

    def _refresh_bookmarks(self) -> None:
        """Refresh the bookmarks display after modification.

        Delegates to the bookmarks mixin if available.
        """
        refresh_fn = getattr(self, "_refresh_bookmarks_tree", None)
        if callable(refresh_fn):
            refresh_fn()
