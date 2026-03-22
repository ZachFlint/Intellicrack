# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Transforms mixin for the hex editor panel."""

from __future__ import annotations

from typing import Any, cast

from PyQt6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from intellicrack.ui.panels.hex_editor._base import (
    DESCRIPTION_TRUNCATE_LEN,
    HEX_ROW_WIDTH,
    PREVIEW_BYTES,
    PRINTABLE_MAX,
    PRINTABLE_MIN,
    get_all_transform_nodes_fn,
    logger,
)


class TransformsMixin:
    """Mixin providing data transforms and pipeline execution for the hex editor panel."""

    _document: Any | None
    _hex_widget: Any | None
    _transform_node_combo: QComboBox | None
    _transform_params_form: QFormLayout | None
    _transform_params_widget: QWidget | None
    _transform_preview_pane: QPlainTextEdit | None
    _transform_pipeline_list: QListWidget | None
    _transform_pipeline: list[tuple[str, dict[str, str]]]
    _transform_nodes_cache: list[Any]

    def _on_data_changed(self) -> None: ...

    def _create_transforms_tab(self) -> QWidget:
        """Create the Transforms side panel tab widget.

        Returns:
            QWidget: Container widget with transform selector, parameters,
                preview pane, and pipeline controls.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(2, 2, 2, 2)

        self._transform_nodes_cache = get_all_transform_nodes_fn() if get_all_transform_nodes_fn is not None else []

        node_row = QHBoxLayout()
        node_row.addWidget(QLabel("Transform:"))
        self._transform_node_combo = QComboBox()
        for node in self._transform_nodes_cache:
            label = f"{node.name} [{node.category}]" if node.category else node.name
            self._transform_node_combo.addItem(label)
        self._transform_node_combo.currentIndexChanged.connect(self._on_transform_node_changed)
        node_row.addWidget(self._transform_node_combo)
        node_row.addStretch()
        layout.addLayout(node_row)

        self._transform_params_widget = QWidget()
        self._transform_params_form = QFormLayout(self._transform_params_widget)
        self._transform_params_form.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._transform_params_widget)

        action_row = QHBoxLayout()
        preview_btn = QPushButton("Preview")
        preview_btn.clicked.connect(self._on_transform_preview)
        action_row.addWidget(preview_btn)
        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self._on_transform_apply)
        action_row.addWidget(apply_btn)
        action_row.addStretch()
        layout.addLayout(action_row)

        self._transform_preview_pane = QPlainTextEdit()
        self._transform_preview_pane.setReadOnly(True)
        preview_font = self._transform_preview_pane.font()
        preview_font.setFamily("Consolas")
        preview_font.setPointSize(9)
        self._transform_preview_pane.setFont(preview_font)
        self._transform_preview_pane.setMaximumHeight(120)
        layout.addWidget(self._transform_preview_pane)

        layout.addWidget(QLabel("Pipeline:"))

        self._transform_pipeline_list = QListWidget()
        self._transform_pipeline_list.setMaximumHeight(100)
        layout.addWidget(self._transform_pipeline_list)

        pipeline_btn_row = QHBoxLayout()
        add_step_btn = QPushButton("Add Step")
        add_step_btn.clicked.connect(self._on_pipeline_add_step)
        pipeline_btn_row.addWidget(add_step_btn)
        remove_step_btn = QPushButton("Remove Step")
        remove_step_btn.clicked.connect(self._on_pipeline_remove_step)
        pipeline_btn_row.addWidget(remove_step_btn)
        move_up_btn = QPushButton("Move Up")
        move_up_btn.clicked.connect(self._on_pipeline_move_up)
        pipeline_btn_row.addWidget(move_up_btn)
        move_down_btn = QPushButton("Move Down")
        move_down_btn.clicked.connect(self._on_pipeline_move_down)
        pipeline_btn_row.addWidget(move_down_btn)
        layout.addLayout(pipeline_btn_row)

        execute_btn = QPushButton("Execute Pipeline")
        execute_btn.clicked.connect(self._on_pipeline_execute)
        layout.addWidget(execute_btn)

        layout.addStretch()

        self._on_transform_node_changed(0)

        return container

    def _on_transform_node_changed(self, index: int) -> None:
        """Rebuild the parameter form when the selected transform changes.

        Args:
            index: Index of the newly selected transform in the combo box.
        """
        if self._transform_params_form is None or self._transform_params_widget is None:
            return

        while self._transform_params_form.rowCount() > 0:
            self._transform_params_form.removeRow(0)

        if not self._transform_nodes_cache or index < 0 or index >= len(self._transform_nodes_cache):
            return

        node = self._transform_nodes_cache[index]

        node_param_specs: dict[str, list[str]] = {
            "xor": ["key"],
            "rot": ["amount"],
            "add": ["value"],
            "sub": ["value"],
            "rc4": ["key"],
            "base64_encode": [],
            "base64_decode": [],
            "zlib_compress": [],
            "zlib_decompress": [],
            "reverse": [],
            "hex_encode": [],
            "hex_decode": [],
            "regex_replace": ["pattern", "replacement"],
            "custom_expression": ["expression"],
            "repeat": ["count"],
            "truncate": ["length"],
            "pad": ["length", "byte"],
        }

        param_names = node_param_specs.get(node.name, [])

        if not param_names and node.description:
            self._transform_params_form.addRow(
                QLabel(
                    node.description[:DESCRIPTION_TRUNCATE_LEN]
                    if len(node.description) > DESCRIPTION_TRUNCATE_LEN
                    else node.description
                )
            )

        for param_name in param_names:
            param_edit = QLineEdit()
            param_edit.setObjectName(f"transform_param_{param_name}")
            param_edit.setToolTip(f"Value for '{param_name}' parameter")
            self._transform_params_form.addRow(QLabel(f"{param_name}:"), param_edit)

    def _collect_transform_params(self) -> dict[str, str]:
        """Collect current parameter values from the transform params form.

        Returns:
            dict[str, str]: Mapping of parameter names to their string values.
        """
        params: dict[str, str] = {}
        if self._transform_params_form is None:
            return params
        for row in range(self._transform_params_form.rowCount()):
            label_item = self._transform_params_form.itemAt(row, QFormLayout.ItemRole.LabelRole)
            field_item = self._transform_params_form.itemAt(row, QFormLayout.ItemRole.FieldRole)
            if label_item is None or field_item is None:
                continue
            label_widget = label_item.widget()
            field_widget = field_item.widget()
            if not isinstance(label_widget, QLabel) or not isinstance(field_widget, QLineEdit):
                continue
            label_text = label_widget.text().rstrip(":")
            params[label_text] = field_widget.text()
        return params

    def _run_single_transform(self, data: bytes) -> bytes | None:
        """Apply the currently selected single transform to data.

        Args:
            data: Input bytes to transform.

        Returns:
            bytes | None: Transformed bytes, or None on failure.
        """
        if self._transform_node_combo is None or not self._transform_nodes_cache:
            return None
        idx = self._transform_node_combo.currentIndex()
        if idx < 0 or idx >= len(self._transform_nodes_cache):
            return None
        node = self._transform_nodes_cache[idx]
        raw_params = self._collect_transform_params()
        try:
            return node.process(data, raw_params)
        except (ValueError, TypeError, KeyError) as exc:
            logger.debug("transform_single_failed", error=str(exc))
            return None

    def _on_transform_preview(self) -> None:
        """Apply the selected transform to the cursor region and show a hex dump preview."""
        if self._document is None or self._transform_preview_pane is None:
            return

        cursor_offset = 0
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)

        preview_len = PREVIEW_BYTES
        try:
            doc_len: int = self._document.length()
            read_len = min(preview_len, doc_len - cursor_offset)
            if read_len <= 0:
                return
            raw: object = self._document.read(cursor_offset, read_len)
            if isinstance(raw, (list, bytearray)):
                data = bytes(cast("list[int]", raw) if isinstance(raw, list) else raw)
            elif isinstance(raw, bytes):
                data = raw
            else:
                return
        except (AttributeError, ValueError) as exc:
            logger.debug("transform_preview_read_failed", error=str(exc))
            return

        result = self._run_single_transform(data)
        if result is None:
            return

        lines: list[str] = []
        for row_start in range(0, min(len(result), PREVIEW_BYTES), HEX_ROW_WIDTH):
            chunk = result[row_start : row_start + HEX_ROW_WIDTH]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if PRINTABLE_MIN <= b <= PRINTABLE_MAX else "." for b in chunk)
            lines.append(f"{cursor_offset + row_start:08X}  {hex_part:<48}  {ascii_part}")

        self._transform_preview_pane.setPlainText("\n".join(lines))

    def _on_transform_apply(self) -> None:
        """Apply the selected transform to the current selection or cursor region and write to document."""
        if self._document is None:
            return

        cursor_offset = 0
        apply_len = PREVIEW_BYTES
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)
            sel_start: int = getattr(self._hex_widget, "_selection_start", -1)
            sel_end: int = getattr(self._hex_widget, "_selection_end", -1)
            if sel_start >= 0 and sel_end >= 0 and sel_end > sel_start:
                cursor_offset = sel_start
                apply_len = sel_end - sel_start

        try:
            doc_len: int = self._document.length()
            read_len = min(apply_len, doc_len - cursor_offset)
            if read_len <= 0:
                return
            raw: object = self._document.read(cursor_offset, read_len)
            if isinstance(raw, (list, bytearray)):
                data = bytes(cast("list[int]", raw) if isinstance(raw, list) else raw)
            elif isinstance(raw, bytes):
                data = raw
            else:
                return
        except (AttributeError, ValueError) as exc:
            logger.debug("transform_apply_read_failed", error=str(exc))
            return

        result = self._run_single_transform(data)
        if result is None:
            return

        write_len = min(len(result), read_len)
        try:
            self._document.write_bytes(cursor_offset, result[:write_len])
        except (AttributeError, ValueError) as exc:
            logger.debug("transform_apply_write_failed", error=str(exc))
        else:
            if self._hex_widget is not None:
                update_fn = getattr(self._hex_widget, "_update_viewport", None)
                if callable(update_fn):
                    update_fn()
            self._on_data_changed()
            logger.debug("transform_applied", offset=cursor_offset, length=write_len)

    def _on_pipeline_add_step(self) -> None:
        """Add the currently selected transform as a new pipeline step."""
        if self._transform_node_combo is None or not self._transform_nodes_cache:
            return
        idx = self._transform_node_combo.currentIndex()
        if idx < 0 or idx >= len(self._transform_nodes_cache):
            return
        node = self._transform_nodes_cache[idx]
        params = self._collect_transform_params()
        self._transform_pipeline.append((node.name, params))
        if self._transform_pipeline_list is not None:
            param_summary = ", ".join(f"{k}={v}" for k, v in params.items() if v)
            label = f"{node.name}({param_summary})" if param_summary else node.name
            self._transform_pipeline_list.addItem(label)

    def _on_pipeline_remove_step(self) -> None:
        """Remove the selected step from the pipeline."""
        if self._transform_pipeline_list is None:
            return
        row = self._transform_pipeline_list.currentRow()
        if row < 0 or row >= len(self._transform_pipeline):
            return
        self._transform_pipeline.pop(row)
        self._transform_pipeline_list.takeItem(row)

    def _on_pipeline_move_up(self) -> None:
        """Move the selected pipeline step one position earlier."""
        if self._transform_pipeline_list is None:
            return
        row = self._transform_pipeline_list.currentRow()
        if row <= 0 or row >= len(self._transform_pipeline):
            return
        self._transform_pipeline[row - 1], self._transform_pipeline[row] = (
            self._transform_pipeline[row],
            self._transform_pipeline[row - 1],
        )
        item = self._transform_pipeline_list.takeItem(row)
        self._transform_pipeline_list.insertItem(row - 1, item)
        self._transform_pipeline_list.setCurrentRow(row - 1)

    def _on_pipeline_move_down(self) -> None:
        """Move the selected pipeline step one position later."""
        if self._transform_pipeline_list is None:
            return
        row = self._transform_pipeline_list.currentRow()
        if row < 0 or row >= len(self._transform_pipeline) - 1:
            return
        self._transform_pipeline[row], self._transform_pipeline[row + 1] = (
            self._transform_pipeline[row + 1],
            self._transform_pipeline[row],
        )
        item = self._transform_pipeline_list.takeItem(row)
        self._transform_pipeline_list.insertItem(row + 1, item)
        self._transform_pipeline_list.setCurrentRow(row + 1)

    def _on_pipeline_execute(self) -> None:
        """Execute all pipeline steps on the current document region and write results."""
        if self._document is None or not self._transform_pipeline:
            return

        if get_all_transform_nodes_fn is None:
            logger.debug("transform_pipeline_unavailable")
            return

        all_nodes = {n.name: n for n in get_all_transform_nodes_fn()}

        cursor_offset = 0
        apply_len = 65536
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)
            sel_start: int = getattr(self._hex_widget, "_selection_start", -1)
            sel_end: int = getattr(self._hex_widget, "_selection_end", -1)
            if sel_start >= 0 and sel_end >= 0 and sel_end > sel_start:
                cursor_offset = sel_start
                apply_len = sel_end - sel_start

        try:
            doc_len: int = self._document.length()
            read_len = min(apply_len, doc_len - cursor_offset)
            if read_len <= 0:
                return
            raw: object = self._document.read(cursor_offset, read_len)
            if isinstance(raw, (list, bytearray)):
                data = bytes(cast("list[int]", raw) if isinstance(raw, list) else raw)
            elif isinstance(raw, bytes):
                data = raw
            else:
                return
        except (AttributeError, ValueError) as exc:
            logger.debug("pipeline_read_failed", error=str(exc))
            return

        result = data
        for node_name, params in self._transform_pipeline:
            node = all_nodes.get(node_name)
            if node is None:
                logger.debug("pipeline_node_not_found", node_name=node_name)
                continue
            try:
                result = node.process(result, params)
            except (ValueError, TypeError, KeyError) as exc:
                logger.debug("pipeline_step_failed", node_name=node_name, error=str(exc))
                return

        write_len = min(len(result), read_len)
        try:
            self._document.write_bytes(cursor_offset, result[:write_len])
        except (AttributeError, ValueError) as exc:
            logger.debug("pipeline_write_failed", error=str(exc))
        else:
            if self._hex_widget is not None:
                update_fn = getattr(self._hex_widget, "_update_viewport", None)
                if callable(update_fn):
                    update_fn()
            self._on_data_changed()
            logger.debug("pipeline_executed", offset=cursor_offset, length=write_len)
