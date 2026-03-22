# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Templates mixin for the hex editor panel."""

from __future__ import annotations

from typing import Any, cast

from PyQt6.QtWidgets import QComboBox, QTreeWidget, QTreeWidgetItem

from intellicrack.ui.panels.hex_editor._base import logger


class TemplatesMixin:
    """Mixin providing struct template application and display for the hex editor panel."""

    _document: Any | None
    _hex_widget: Any | None
    _template_combo: QComboBox | None
    _templates_tree: QTreeWidget | None

    def _on_apply_template(self) -> None:
        """Apply the selected struct template at the current cursor offset."""
        if self._document is None or self._template_combo is None or self._templates_tree is None:
            return

        template_name = self._template_combo.currentText()
        if not template_name:
            return

        cursor_offset = 0
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)

        try:
            result = self._document.apply_template(template_name, cursor_offset)
        except (AttributeError, ValueError) as exc:
            logger.debug("template_apply_failed", error=str(exc))
        else:
            self._templates_tree.clear()

            if isinstance(result, list):
                typed_fields = cast("list[dict[str, object]]", result)
                self._populate_template_tree(typed_fields)
                self._highlight_template_fields(typed_fields)

            logger.info("template_applied", template=template_name)

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
            highlight_fn(highlights)

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
                color = str(color_raw) if isinstance(color_raw, str) else "#44FF44"
                highlights.append((f_offset, f_size, color))
            children_raw = field_data.get("children")
            if isinstance(children_raw, list):
                children = cast("list[dict[str, object]]", children_raw)
                TemplatesMixin._collect_field_highlights(children, highlights)

    def _populate_template_combo(self) -> None:
        """Populate the template combo box with available templates."""
        if self._template_combo is None or self._document is None:
            return

        self._template_combo.clear()
        templates = self._document.list_templates()
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
