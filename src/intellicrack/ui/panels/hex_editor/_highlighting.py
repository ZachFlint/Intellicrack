# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Highlight rule management mixin for the hex editor panel."""

from __future__ import annotations

import uuid
from typing import Any, Final

from PyQt6.QtWidgets import (
    QColorDialog,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from intellicrack.ui.panels.hex_editor._base import logger
from intellicrack.ui.panels.hex_editor_widget import HighlightRule


_DEFAULT_HIGHLIGHT_COLOR: Final[str] = "#FFFF00"
_BYTE_MAX: Final[int] = 255


class HighlightingMixin:
    """Mixin providing highlight rule management for the hex editor panel."""

    document: Any | None
    _hex_widget: Any | None
    _highlight_condition_combo: QComboBox | None
    _highlight_color_edit: QLineEdit | None
    _highlight_params_stack: QStackedWidget | None
    _highlight_byte_value_spin: QSpinBox | None
    _highlight_range_min_spin: QSpinBox | None
    _highlight_range_max_spin: QSpinBox | None
    _highlight_pattern_edit: QLineEdit | None
    _highlight_rules_list: QListWidget | None
    _active_highlight_ids: list[str]

    def _create_highlighting_controls(self) -> QGroupBox:
        """Create the highlight rules management group box.

        Returns:
            QGroupBox: Container with condition type selector, parameter
                inputs, color picker, rule list, and control buttons.
        """
        box = QGroupBox("Highlight Rules")
        layout = QVBoxLayout(box)
        layout.setSpacing(4)

        cond_row = QHBoxLayout()
        cond_row.addWidget(QLabel("Condition:"))
        self._highlight_condition_combo = QComboBox()
        self._highlight_condition_combo.addItems(["Byte Value", "Byte Range", "Pattern"])
        self._highlight_condition_combo.currentIndexChanged.connect(
            self._on_highlight_condition_changed,
        )
        cond_row.addWidget(self._highlight_condition_combo)
        layout.addLayout(cond_row)

        self._highlight_params_stack = QStackedWidget()

        byte_value_page = QWidget()
        bv_layout = QHBoxLayout(byte_value_page)
        bv_layout.setContentsMargins(0, 0, 0, 0)
        bv_layout.addWidget(QLabel("Value:"))
        self._highlight_byte_value_spin = QSpinBox()
        self._highlight_byte_value_spin.setRange(0, _BYTE_MAX)
        bv_layout.addWidget(self._highlight_byte_value_spin)
        bv_layout.addStretch()
        self._highlight_params_stack.addWidget(byte_value_page)

        byte_range_page = QWidget()
        br_layout = QHBoxLayout(byte_range_page)
        br_layout.setContentsMargins(0, 0, 0, 0)
        br_layout.addWidget(QLabel("Min:"))
        self._highlight_range_min_spin = QSpinBox()
        self._highlight_range_min_spin.setRange(0, _BYTE_MAX)
        br_layout.addWidget(self._highlight_range_min_spin)
        br_layout.addWidget(QLabel("Max:"))
        self._highlight_range_max_spin = QSpinBox()
        self._highlight_range_max_spin.setRange(0, _BYTE_MAX)
        self._highlight_range_max_spin.setValue(_BYTE_MAX)
        br_layout.addWidget(self._highlight_range_max_spin)
        br_layout.addStretch()
        self._highlight_params_stack.addWidget(byte_range_page)

        pattern_page = QWidget()
        pp_layout = QHBoxLayout(pattern_page)
        pp_layout.setContentsMargins(0, 0, 0, 0)
        pp_layout.addWidget(QLabel("Hex:"))
        self._highlight_pattern_edit = QLineEdit()
        self._highlight_pattern_edit.setToolTip("Hex pattern (e.g. 4D5A)")
        pp_layout.addWidget(self._highlight_pattern_edit)
        self._highlight_params_stack.addWidget(pattern_page)

        layout.addWidget(self._highlight_params_stack)

        color_row = QHBoxLayout()
        color_row.addWidget(QLabel("Color:"))
        self._highlight_color_edit = QLineEdit(_DEFAULT_HIGHLIGHT_COLOR)
        self._highlight_color_edit.setMaximumWidth(80)
        color_row.addWidget(self._highlight_color_edit)
        pick_btn = QPushButton("Pick...")
        pick_btn.clicked.connect(self._on_pick_highlight_color)
        color_row.addWidget(pick_btn)
        color_row.addStretch()
        layout.addLayout(color_row)

        add_btn = QPushButton("Add Rule")
        add_btn.clicked.connect(self._on_add_highlight_rule)
        layout.addWidget(add_btn)

        self._highlight_rules_list = QListWidget()
        layout.addWidget(self._highlight_rules_list)

        btn_row = QHBoxLayout()
        rm_btn = QPushButton("Remove Selected")
        rm_btn.clicked.connect(self._on_remove_highlight_rule)
        btn_row.addWidget(rm_btn)
        clear_btn = QPushButton("Clear All")
        clear_btn.clicked.connect(self._on_clear_highlight_rules)
        btn_row.addWidget(clear_btn)
        layout.addLayout(btn_row)

        self._active_highlight_ids = []
        return box

    def _on_highlight_condition_changed(self, index: int) -> None:
        """Switch the parameter input page for the selected condition type.

        Args:
            index: Index of the selected condition type.
        """
        if self._highlight_params_stack is not None:
            self._highlight_params_stack.setCurrentIndex(index)

    def _on_pick_highlight_color(self) -> None:
        """Open a color dialog and set the selected color."""
        parent = self if isinstance(self, QWidget) else None
        color = QColorDialog.getColor(parent=parent)
        if color.isValid() and self._highlight_color_edit is not None:
            self._highlight_color_edit.setText(color.name())

    def _on_add_highlight_rule(self) -> None:
        """Create a highlight rule from the current form values and apply it."""
        if self._highlight_condition_combo is None or self._hex_widget is None:
            return

        condition_idx = self._highlight_condition_combo.currentIndex()
        color = self._highlight_color_edit.text().strip() if self._highlight_color_edit else _DEFAULT_HIGHLIGHT_COLOR
        rule_id = str(uuid.uuid4())[:8]

        condition_type: str
        params: dict[str, Any]

        if condition_idx == 0:
            value = self._highlight_byte_value_spin.value() if self._highlight_byte_value_spin else 0
            condition_type = "byte_value"
            params = {"value": value}
            label = f"[{rule_id}] Byte == 0x{value:02X}  ({color})"
        elif condition_idx == 1:
            min_val = self._highlight_range_min_spin.value() if self._highlight_range_min_spin else 0
            max_val = self._highlight_range_max_spin.value() if self._highlight_range_max_spin else _BYTE_MAX
            condition_type = "byte_range"
            params = {"min": min_val, "max": max_val}
            label = f"[{rule_id}] Byte 0x{min_val:02X}-0x{max_val:02X}  ({color})"
        else:
            pattern = self._highlight_pattern_edit.text().strip() if self._highlight_pattern_edit else ""
            if not pattern:
                parent = self if isinstance(self, QWidget) else None
                QMessageBox.warning(parent, "Highlight", "Pattern cannot be empty.")
                return
            condition_type = "pattern"
            params = {"pattern": pattern}
            label = f"[{rule_id}] Pattern {pattern}  ({color})"

        add_rule_fn = getattr(self._hex_widget, "add_highlight_rule", None)
        if callable(add_rule_fn):
            try:
                rule = HighlightRule(
                    rule_id=rule_id,
                    condition_type=condition_type,
                    condition_params=params,
                    color=color,
                    priority=len(self._active_highlight_ids),
                )
                add_rule_fn(rule)
            except (ImportError, TypeError, AttributeError) as exc:
                logger.debug("highlight_rule_add_failed", error=str(exc))
                return

        self._active_highlight_ids.append(rule_id)
        if self._highlight_rules_list is not None:
            item = QListWidgetItem(label)
            self._highlight_rules_list.addItem(item)

        update_fn = getattr(self._hex_widget, "update", None)
        if callable(update_fn):
            update_fn()

        logger.debug("highlight_rule_added", rule_id=rule_id, condition_type=condition_type)

    def _on_remove_highlight_rule(self) -> None:
        """Remove the selected highlight rule."""
        if self._highlight_rules_list is None or self._hex_widget is None:
            return

        row = self._highlight_rules_list.currentRow()
        if row < 0 or row >= len(self._active_highlight_ids):
            return

        remove_fn = getattr(self._hex_widget, "remove_highlight_rule", None)
        if callable(remove_fn):
            try:
                remove_fn(row)
            except (IndexError, TypeError, AttributeError) as exc:
                logger.debug("highlight_rule_remove_failed", row=row, error=str(exc))

        self._active_highlight_ids.pop(row)
        self._highlight_rules_list.takeItem(row)

        update_fn = getattr(self._hex_widget, "update", None)
        if callable(update_fn):
            update_fn()

    def _on_clear_highlight_rules(self) -> None:
        """Remove all active highlight rules."""
        if self._hex_widget is None:
            return

        clear_fn = getattr(self._hex_widget, "clear_highlight_rules", None)
        if callable(clear_fn):
            clear_fn()
        else:
            rules_attr = getattr(self._hex_widget, "_highlight_rules", None)
            if isinstance(rules_attr, list):
                rules_attr.clear()

        self._active_highlight_ids.clear()
        if self._highlight_rules_list is not None:
            self._highlight_rules_list.clear()

        update_fn = getattr(self._hex_widget, "update", None)
        if callable(update_fn):
            update_fn()
