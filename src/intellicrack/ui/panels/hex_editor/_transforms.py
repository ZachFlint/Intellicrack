# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Transforms mixin for the hex editor panel."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Final, cast

from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine
from intellicrack.ui.panels.hex_editor._base import (
    DESCRIPTION_TRUNCATE_LEN,
    HEX_ROW_WIDTH,
    PREVIEW_BYTES,
    PRINTABLE_MAX,
    PRINTABLE_MIN,
    get_all_transform_nodes_fn,
)


_logger = get_logger(__name__)


_LAYOUT_MARGIN: Final[int] = 2
_ZERO_MARGIN: Final[int] = 0
_PREVIEW_MAX_HEIGHT: Final[int] = 120
_PIPELINE_MAX_HEIGHT: Final[int] = 100
_PIPELINE_DEFAULT_LEN: Final[int] = 65536
_BYTE_MASK: Final[int] = 0xFF
_BITS_PER_BYTE: Final[int] = 8
_TRANSFORM_TUPLE_ARITY: Final[int] = 3

_ARITHMETIC_OP_MAP: Final[dict[str, str]] = {
    "XOR": "xor",
    "AND": "and",
    "OR": "or",
    "NOT": "not",
    "Shift Left": "shl",
    "Shift Right": "shr",
    "Rotate Left": "rol",
    "Rotate Right": "ror",
}

_TransformPipeline_cls: Any = None
_pipeline_available: bool = False
try:
    from intellicrack.core.transform_pipeline import (
        TransformPipeline as _TransformPipeline_cls,
    )

    _pipeline_available = True
except ImportError:
    _logger.debug("transform_pipeline_class_import_unavailable")


@dataclass(frozen=True)
class TransformDescriptor:
    """Describes a single transform node exposed by hexcore ``list_transforms``.

    Attributes:
        name: Machine-readable node identifier passed back to ``transform_data``.
        category: Human-readable category grouping (e.g. ``xor``, ``compress``).
        description: Free-form description shown in the UI.
    """

    name: str
    category: str
    description: str


def _load_transform_descriptors(document: object) -> list[TransformDescriptor]:
    """Build the transform catalogue for the UI.

    Prefers the hexcore ``document.list_transforms()`` RPC when a document is
    available, and falls back to the in-process
    ``intellicrack.core.transform_pipeline.get_all_transform_nodes`` for the
    no-document case (e.g. before a file has been opened) so the combo box is
    populated on first paint.

    Args:
        document: Active hexcore document, or ``None`` when no file is open.

    Returns:
        list[TransformDescriptor]: Available transforms, in the order returned
            by the underlying source.
    """
    if document is not None:
        list_fn = getattr(document, "list_transforms", None)
        if callable(list_fn):
            try:
                raw: object = list_fn()
            except (RuntimeError, OSError, ValueError, AttributeError):
                _logger.exception("transform_list_from_document_failed")
            else:
                if isinstance(raw, list):
                    descriptors: list[TransformDescriptor] = []
                    for entry in cast("list[object]", raw):
                        if isinstance(entry, tuple) and len(cast("tuple[object, ...]", entry)) >= _TRANSFORM_TUPLE_ARITY:
                            tup = cast("tuple[object, object, object]", entry)
                            descriptors.append(
                                TransformDescriptor(
                                    name=str(tup[0]),
                                    category=str(tup[1]),
                                    description=str(tup[2]),
                                ),
                            )
                        elif isinstance(entry, dict):
                            typed = cast("dict[str, object]", entry)
                            descriptors.append(
                                TransformDescriptor(
                                    name=str(typed.get("name", "")),
                                    category=str(typed.get("category", "")),
                                    description=str(typed.get("description", "")),
                                ),
                            )
                    if descriptors:
                        return descriptors

    if get_all_transform_nodes_fn is None:
        return []
    nodes_raw: object = get_all_transform_nodes_fn()
    if not isinstance(nodes_raw, list):
        return []
    fallback: list[TransformDescriptor] = []
    for node in cast("list[object]", nodes_raw):
        name = getattr(node, "name", None)
        if not isinstance(name, str):
            continue
        fallback.append(
            TransformDescriptor(
                name=name,
                category=str(getattr(node, "category", "") or ""),
                description=str(getattr(node, "description", "") or ""),
            ),
        )
    return fallback


class TransformsMixin:
    """Mixin providing data transforms and pipeline execution for the hex editor panel."""

    _document: Any | None
    document: Any | None
    _hex_widget: Any | None
    _transform_node_combo: QComboBox | None
    _transform_params_form: QFormLayout | None
    _transform_params_widget: QWidget | None
    _transform_preview_pane: QPlainTextEdit | None
    _transform_pipeline_list: QListWidget | None
    _transform_pipeline: Any
    _transform_nodes_cache: list[TransformDescriptor]
    _bridge: Any | None
    state_holder: Any | None
    _selection_start: int
    _selection_end: int

    def _on_data_changed(self) -> None:
        """Handle document data-change signals by refreshing derived views."""
        if self._transform_preview_pane is not None:
            self._transform_preview_pane.clear()
        self._transform_nodes_cache = _load_transform_descriptors(self.document)
        if self._hex_widget is not None:
            update_fn = getattr(self._hex_widget, "_update_viewport", None)
            if callable(update_fn):
                update_fn()

    def _create_transforms_tab(self) -> QWidget:
        """Create the Transforms side panel tab widget.

        Returns:
            QWidget: Container widget with transform selector, parameters,
                preview pane, and pipeline controls.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_LAYOUT_MARGIN, _LAYOUT_MARGIN, _LAYOUT_MARGIN, _LAYOUT_MARGIN)

        self._transform_nodes_cache = _load_transform_descriptors(self.document)

        if _pipeline_available and _TransformPipeline_cls is not None:
            self._transform_pipeline = _TransformPipeline_cls()
        else:
            self._transform_pipeline = None

        layout.addLayout(self._create_node_selector_row())
        layout.addWidget(self._create_params_section())
        layout.addLayout(self._create_action_row())
        layout.addWidget(self._create_preview_pane())
        layout.addWidget(QLabel("Pipeline:"))
        layout.addWidget(self._create_pipeline_list())
        layout.addLayout(self._create_pipeline_btn_row())

        execute_btn = QPushButton("Execute Pipeline")
        execute_btn.clicked.connect(self._on_pipeline_execute)
        layout.addWidget(execute_btn)

        layout.addWidget(self._create_block_ops_group())
        layout.addWidget(self._create_arithmetic_group())
        layout.addStretch()

        self._on_transform_node_changed(0)

        return container

    def _create_node_selector_row(self) -> QHBoxLayout:
        """Build the transform node selector row.

        Returns:
            QHBoxLayout: Row containing the Transform label and combo box.
        """
        node_row = QHBoxLayout()
        node_row.addWidget(QLabel("Transform:"))
        self._transform_node_combo = QComboBox()
        for node in self._transform_nodes_cache:
            label = f"{node.name} [{node.category}]" if node.category else node.name
            self._transform_node_combo.addItem(label)
        self._transform_node_combo.currentIndexChanged.connect(self._on_transform_node_changed)
        node_row.addWidget(self._transform_node_combo)
        node_row.addStretch()
        return node_row

    def _create_params_section(self) -> QWidget:
        """Build the transform parameters form widget.

        Returns:
            QWidget: Widget containing the parameter form layout.
        """
        self._transform_params_widget = QWidget()
        self._transform_params_form = QFormLayout(self._transform_params_widget)
        self._transform_params_form.setContentsMargins(_ZERO_MARGIN, _ZERO_MARGIN, _ZERO_MARGIN, _ZERO_MARGIN)
        return self._transform_params_widget

    def _create_action_row(self) -> QHBoxLayout:
        """Build the Preview/Apply action button row.

        Returns:
            QHBoxLayout: Row containing Preview and Apply buttons.
        """
        action_row = QHBoxLayout()
        preview_btn = QPushButton("Preview")
        preview_btn.clicked.connect(self._on_transform_preview)
        action_row.addWidget(preview_btn)
        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self._on_transform_apply)
        action_row.addWidget(apply_btn)
        action_row.addStretch()
        return action_row

    def _create_preview_pane(self) -> QPlainTextEdit:
        """Build the transform preview plain-text pane.

        Returns:
            QPlainTextEdit: Read-only monospace preview pane.
        """
        self._transform_preview_pane = QPlainTextEdit()
        self._transform_preview_pane.setReadOnly(True)
        preview_font = self._transform_preview_pane.font()
        preview_font.setFamily("Consolas")
        preview_font.setPointSize(9)
        self._transform_preview_pane.setFont(preview_font)
        self._transform_preview_pane.setMaximumHeight(_PREVIEW_MAX_HEIGHT)
        return self._transform_preview_pane

    def _create_pipeline_list(self) -> QListWidget:
        """Build the pipeline step list widget.

        Returns:
            QListWidget: List widget showing current pipeline steps.
        """
        self._transform_pipeline_list = QListWidget()
        self._transform_pipeline_list.setMaximumHeight(_PIPELINE_MAX_HEIGHT)
        return self._transform_pipeline_list

    def _create_pipeline_btn_row(self) -> QHBoxLayout:
        """Build the pipeline management button row.

        Returns:
            QHBoxLayout: Row containing Add, Remove, Move Up, Move Down buttons.
        """
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
        return pipeline_btn_row

    def _create_block_ops_group(self) -> QGroupBox:
        """Create the Block Operations group box.

        Returns:
            QGroupBox: Group containing Fill, Copy, Move, and Swap buttons.
        """
        block_box = QGroupBox("Block Operations")
        block_layout = QHBoxLayout(block_box)
        for label, slot in [
            ("Fill", self._on_block_fill),
            ("Copy", self._on_block_copy),
            ("Move", self._on_block_move),
            ("Swap", self._on_block_swap),
        ]:
            btn = QPushButton(label)
            btn.clicked.connect(slot)
            block_layout.addWidget(btn)
        return block_box

    def _create_arithmetic_group(self) -> QGroupBox:
        """Create the Quick Arithmetic group box.

        Returns:
            QGroupBox: Group with operator selector, key/mask input, and apply button.
        """
        arith_box = QGroupBox("Quick Arithmetic")
        arith_layout = QVBoxLayout(arith_box)
        arith_top = QHBoxLayout()
        self._arith_op_combo = QComboBox()
        self._arith_op_combo.addItems([
            "XOR",
            "AND",
            "OR",
            "NOT",
            "Shift Left",
            "Shift Right",
            "Rotate Left",
            "Rotate Right",
        ])
        arith_top.addWidget(self._arith_op_combo)
        arith_layout.addLayout(arith_top)
        arith_key_row = QHBoxLayout()
        arith_key_row.addWidget(QLabel("Key/Mask:"))
        self._arith_key_edit = QLineEdit()
        self._arith_key_edit.setToolTip("Hex key or mask (e.g. FF or DEADBEEF)")
        arith_key_row.addWidget(self._arith_key_edit)
        arith_layout.addLayout(arith_key_row)
        arith_count_row = QHBoxLayout()
        arith_count_row.addWidget(QLabel("Count:"))
        self._arith_count_spin = QSpinBox()
        self._arith_count_spin.setRange(1, 64)
        self._arith_count_spin.setValue(1)
        arith_count_row.addWidget(self._arith_count_spin)
        arith_count_row.addStretch()
        arith_layout.addLayout(arith_count_row)
        arith_apply_btn = QPushButton("Apply to Selection")
        arith_apply_btn.clicked.connect(self._on_apply_arithmetic)
        arith_layout.addWidget(arith_apply_btn)
        return arith_box

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
                    node.description[:DESCRIPTION_TRUNCATE_LEN] if len(node.description) > DESCRIPTION_TRUNCATE_LEN else node.description,
                ),
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

    def _run_single_transform(self, offset: int, length: int) -> bytes | None:
        """Apply the currently selected single transform via hexcore transform_data.

        Args:
            offset: Absolute byte offset within the document.
            length: Number of bytes to transform.

        Returns:
            bytes | None: Transformed bytes returned by hexcore, or None on failure.
        """
        if self.document is None or self._transform_node_combo is None or not self._transform_nodes_cache:
            return None
        idx = self._transform_node_combo.currentIndex()
        if idx < 0 or idx >= len(self._transform_nodes_cache):
            return None
        node = self._transform_nodes_cache[idx]
        node_name = getattr(node, "name", None)
        if not isinstance(node_name, str):
            return None
        raw_params = self._collect_transform_params()
        encoded_params: dict[str, bytes] = {key: str(value).encode("utf-8") for key, value in raw_params.items()}
        try:
            result = self.document.transform_data(node_name, offset, length, encoded_params)
        except (RuntimeError, OSError, ValueError, TypeError, KeyError, AttributeError):
            _logger.exception("transform_single_failed", node_name=node_name)
            return None
        if isinstance(result, bytes):
            return result
        if isinstance(result, bytearray):
            return bytes(result)
        return bytes(cast("list[int]", result)) if isinstance(result, list) else None

    def _on_transform_preview(self) -> None:
        """Apply the selected transform to the cursor region and show a hex dump preview."""
        if self.document is None or self._transform_preview_pane is None:
            return

        cursor_offset = 0
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)

        try:
            doc_len: int = self.document.length()
        except (AttributeError, ValueError):
            _logger.exception("transform_preview_len_failed")
            return
        read_len = min(PREVIEW_BYTES, doc_len - cursor_offset)
        if read_len <= 0:
            return

        result = self._run_single_transform(cursor_offset, read_len)
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
        if self.document is None:
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
            doc_len: int = self.document.length()
        except (AttributeError, ValueError):
            _logger.exception("transform_apply_len_failed")
            return
        read_len = min(apply_len, doc_len - cursor_offset)
        if read_len <= 0:
            return

        result = self._run_single_transform(cursor_offset, read_len)
        if result is None:
            return

        write_len = min(len(result), read_len)
        if len(result) > read_len:
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.warning(
                parent,
                "Transform Truncated",
                f"Transform output ({len(result)} bytes) exceeds input region ({read_len} bytes). Output will be truncated to fit.",
            )
        write_payload = result[:write_len]
        _logger.info(
            "file_written",
            path="<document>",
            offset=cursor_offset,
            size=write_len,
            data_size=write_len,
            data_sha256=hashlib.sha256(write_payload).hexdigest()[:12],
            kind="transform_apply",
        )
        try:
            self.document.write_bytes(cursor_offset, write_payload)
        except (AttributeError, ValueError):
            _logger.exception("transform_apply_write_failed", offset=cursor_offset, length=write_len)
        else:
            if self._hex_widget is not None:
                update_fn = getattr(self._hex_widget, "_update_viewport", None)
                if callable(update_fn):
                    update_fn()
            state_holder = getattr(self, "state_holder", None)
            if state_holder is not None:
                state_holder.notify_data_modified(cursor_offset, write_len, source="hex-editor.transforms.apply")
            self._on_data_changed()
            _logger.info("transform_applied", offset=cursor_offset, length=write_len)

    def _pipeline_step_count(self) -> int:
        """Return the number of steps in the current pipeline.

        Returns:
            int: Number of pipeline steps.
        """
        if self._transform_pipeline is None:
            return 0
        steps: list[Any] = getattr(self._transform_pipeline, "steps", [])
        return len(steps)

    def _refresh_pipeline_list(self) -> None:
        """Rebuild the pipeline QListWidget from the TransformPipeline steps."""
        if self._transform_pipeline_list is None:
            return
        self._transform_pipeline_list.clear()
        if self._transform_pipeline is None:
            return
        steps: list[Any] = getattr(self._transform_pipeline, "steps", [])
        for step in steps:
            node_name: str = step.node.name if hasattr(step, "node") else str(step)
            params: dict[str, Any] = step.params if hasattr(step, "params") else {}
            param_summary = ", ".join(f"{k}={v}" for k, v in params.items() if v)
            label = f"{node_name}({param_summary})" if param_summary else node_name
            self._transform_pipeline_list.addItem(label)

    def _on_pipeline_add_step(self) -> None:
        """Add the currently selected transform as a new pipeline step."""
        if self._transform_node_combo is None or not self._transform_nodes_cache:
            return
        if self._transform_pipeline is None:
            return
        idx = self._transform_node_combo.currentIndex()
        if idx < 0 or idx >= len(self._transform_nodes_cache):
            return
        node = self._transform_nodes_cache[idx]
        params = self._collect_transform_params()
        add_step_fn: Any = getattr(self._transform_pipeline, "add_step", None)
        if callable(add_step_fn):
            add_step_fn(node, params)
        self._refresh_pipeline_list()

    def _on_pipeline_remove_step(self) -> None:
        """Remove the selected step from the pipeline."""
        if self._transform_pipeline_list is None or self._transform_pipeline is None:
            return
        row = self._transform_pipeline_list.currentRow()
        if row < 0 or row >= self._pipeline_step_count():
            return
        remove_fn: Any = getattr(self._transform_pipeline, "remove_step", None)
        if callable(remove_fn):
            remove_fn(row)
        self._refresh_pipeline_list()

    def _on_pipeline_move_up(self) -> None:
        """Move the selected pipeline step one position earlier."""
        if self._transform_pipeline_list is None or self._transform_pipeline is None:
            return
        row = self._transform_pipeline_list.currentRow()
        if row <= 0 or row >= self._pipeline_step_count():
            return
        move_fn: Any = getattr(self._transform_pipeline, "move_step", None)
        if callable(move_fn):
            move_fn(row, row - 1)
        self._refresh_pipeline_list()
        self._transform_pipeline_list.setCurrentRow(row - 1)

    def _on_pipeline_move_down(self) -> None:
        """Move the selected pipeline step one position later."""
        if self._transform_pipeline_list is None or self._transform_pipeline is None:
            return
        row = self._transform_pipeline_list.currentRow()
        if row < 0 or row >= self._pipeline_step_count() - 1:
            return
        move_fn: Any = getattr(self._transform_pipeline, "move_step", None)
        if callable(move_fn):
            move_fn(row, row + 1)
        self._refresh_pipeline_list()
        self._transform_pipeline_list.setCurrentRow(row + 1)

    def _resolve_pipeline_region(self) -> tuple[int, int]:
        """Resolve the cursor offset and apply length for pipeline execution.

        Returns:
            tuple[int, int]: ``(cursor_offset, apply_len)`` derived from the current
                hex widget selection if any, otherwise the cursor position with the
                default pipeline window length.
        """
        cursor_offset = 0
        apply_len = _PIPELINE_DEFAULT_LEN
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)
            sel_start: int = getattr(self._hex_widget, "_selection_start", -1)
            sel_end: int = getattr(self._hex_widget, "_selection_end", -1)
            if sel_start >= 0 and sel_end >= 0 and sel_end > sel_start:
                cursor_offset = sel_start
                apply_len = sel_end - sel_start
        return cursor_offset, apply_len

    def _read_pipeline_input(self, cursor_offset: int, apply_len: int) -> tuple[bytes, int] | None:
        """Read the input region for the pipeline.

        Args:
            cursor_offset: Document offset at which to read.
            apply_len: Maximum number of bytes to read.

        Returns:
            tuple[bytes, int] | None: ``(data, read_len)`` on success, or ``None`` if
                the document is empty, the read returned an unexpected type, or an
                attribute/value error was raised while reading.
        """
        if self.document is None:
            return None
        try:
            doc_len: int = self.document.length()
            read_len = min(apply_len, doc_len - cursor_offset)
            if read_len <= 0:
                return None
            raw: object = self.document.read(cursor_offset, read_len)
        except (AttributeError, ValueError):
            _logger.exception("pipeline_read_failed")
            return None
        if isinstance(raw, (list, bytearray)):
            return bytes(cast("list[int]", raw) if isinstance(raw, list) else raw), read_len
        return (raw, read_len) if isinstance(raw, bytes) else None

    def _write_pipeline_output(self, cursor_offset: int, result: bytes, read_len: int) -> None:
        """Write pipeline output back to the document.

        Truncates ``result`` to ``read_len`` when the output exceeds the input region
        size and surfaces a warning dialog. Updates the hex widget viewport and emits
        a ``notify_data_modified`` signal to the session state holder.

        Args:
            cursor_offset: Document offset at which to begin writing.
            result: Pipeline output bytes to write.
            read_len: Length of the original input region, used to bound the write.
        """
        if self.document is None:
            return
        parent = self if isinstance(self, QWidget) else None
        write_len = min(len(result), read_len)
        if len(result) > read_len:
            QMessageBox.warning(
                parent,
                "Pipeline Truncated",
                f"Pipeline output ({len(result)} bytes) exceeds input region ({read_len} bytes). Output will be truncated to fit.",
            )
        write_payload = result[:write_len]
        _logger.info(
            "file_written",
            path="<document>",
            offset=cursor_offset,
            size=write_len,
            data_size=write_len,
            data_sha256=hashlib.sha256(write_payload).hexdigest()[:12],
            kind="pipeline_apply",
        )
        try:
            self.document.write_bytes(cursor_offset, write_payload)
        except (AttributeError, ValueError):
            _logger.exception("pipeline_write_failed", offset=cursor_offset, length=write_len)
            return
        if self._hex_widget is not None:
            update_fn = getattr(self._hex_widget, "_update_viewport", None)
            if callable(update_fn):
                update_fn()
        state_holder = getattr(self, "state_holder", None)
        if state_holder is not None:
            state_holder.notify_data_modified(cursor_offset, write_len, source="hex-editor.transforms.pipeline")
        self._on_data_changed()
        _logger.info("pipeline_executed", offset=cursor_offset, length=write_len)

    def _on_pipeline_execute(self) -> None:
        """Execute all pipeline steps on the current document region and write results."""
        if self.document is None or self._transform_pipeline is None:
            return
        if self._pipeline_step_count() == 0:
            return

        cursor_offset, apply_len = self._resolve_pipeline_region()
        read_result = self._read_pipeline_input(cursor_offset, apply_len)
        if read_result is None:
            return
        data, read_len = read_result

        execute_fn: Any = getattr(self._transform_pipeline, "execute", None)
        if not callable(execute_fn):
            _logger.warning("pipeline_execute_not_available")
            return

        try:
            raw_result: object = execute_fn(data)
            result: bytes = raw_result if isinstance(raw_result, bytes) else bytes(cast("list[int]", raw_result))
        except (ValueError, TypeError, KeyError) as exc:
            _logger.exception("pipeline_execution_failed")
            QMessageBox.warning(
                self if isinstance(self, QWidget) else None,
                "Pipeline Failed",
                f"Pipeline execution failed at a step:\n{exc}",
            )
            return

        self._write_pipeline_output(cursor_offset, result, read_len)

    def _on_block_fill(self) -> None:
        """Fill a block via hexcore document.fill_block."""
        if self.document is None:
            return
        parent = self if isinstance(self, QWidget) else None
        dlg = _BlockFillDialog(self._hex_widget, parent)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        offset, length, pattern = dlg.get_values()
        if not pattern:
            return
        _logger.info("block_fill_invoke", offset=offset, length=length, pattern_size=len(pattern))
        try:
            self.document.fill_block(offset, length, bytes(pattern))
        except (RuntimeError, OSError, ValueError, AttributeError):
            _logger.exception("block_fill_failed", offset=offset, length=length)
            return
        state_holder = getattr(self, "state_holder", None)
        if state_holder is not None:
            state_holder.notify_data_modified(offset, length, source="hex-editor.transforms.fill")
        self._refresh_widget()
        _logger.info("block_fill_complete", offset=offset, length=length)

    def _on_block_copy(self) -> None:
        """Copy a block via hexcore document.copy_block."""
        if self.document is None:
            return
        parent = self if isinstance(self, QWidget) else None
        dlg = _BlockCopyMoveDialog("Copy Block", parent)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        src, length, dst = dlg.get_values()
        try:
            self.document.copy_block(src, length, dst)
        except (RuntimeError, OSError, ValueError, AttributeError):
            _logger.exception("block_copy_failed", src=src, length=length, dst=dst)
            return
        state_holder = getattr(self, "state_holder", None)
        if state_holder is not None:
            state_holder.notify_data_modified(dst, length, source="hex-editor.transforms.copy")
        self._refresh_widget()

    def _on_block_move(self) -> None:
        """Move a block via hexcore document.move_block."""
        if self.document is None:
            return
        parent = self if isinstance(self, QWidget) else None
        dlg = _BlockCopyMoveDialog("Move Block", parent)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        src, length, dst = dlg.get_values()
        try:
            self.document.move_block(src, length, dst)
        except (RuntimeError, OSError, ValueError, AttributeError):
            _logger.exception("block_move_failed", src=src, length=length, dst=dst)
            return
        state_holder = getattr(self, "state_holder", None)
        if state_holder is not None:
            state_holder.notify_data_modified(0, length, source="hex-editor.transforms.move")
        self._refresh_widget()

    def _on_block_swap(self) -> None:
        """Swap two blocks via hexcore document.swap_blocks."""
        if self.document is None:
            return
        parent = self if isinstance(self, QWidget) else None
        dlg = _BlockSwapDialog(parent)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        off_a, len_a, off_b, len_b = dlg.get_values()
        try:
            self.document.swap_blocks(off_a, len_a, off_b, len_b)
        except (RuntimeError, OSError, ValueError, AttributeError):
            _logger.exception("block_swap_failed", off_a=off_a, len_a=len_a, off_b=off_b, len_b=len_b)
            return
        state_holder = getattr(self, "state_holder", None)
        if state_holder is not None:
            total_len = len_a + len_b
            state_holder.notify_data_modified(min(off_a, off_b), total_len, source="hex-editor.transforms.swap")
        self._refresh_widget()

    def _on_apply_arithmetic(self) -> None:
        """Apply the selected arithmetic operation to the current selection via the bridge.

        Routes the operation through
        :meth:`HexEditorBridge.apply_arithmetic_to_selection`, which performs the
        native hexcore transform (``xor_repeating``/``mask_and``/``bit_shift_left``
        etc.) and updates the shared document in-place.  The bridge's own
        selection state is first synchronised to the widget's selection before
        dispatch.
        """
        if self.document is None or self._hex_widget is None:
            return
        if self._bridge is None:
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.warning(
                parent,
                "Arithmetic",
                "Hex editor bridge is not available; cannot apply arithmetic operation.",
            )
            return

        sel_start: int = getattr(self, "_selection_start", -1)
        sel_end: int = getattr(self, "_selection_end", -1)
        if sel_start < 0 or sel_end < 0 or sel_end <= sel_start:
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.information(parent, "Arithmetic", "Select a region first.")
            return

        op_combo: QComboBox | None = getattr(self, "_arith_op_combo", None)
        key_edit: QLineEdit | None = getattr(self, "_arith_key_edit", None)
        count_spin: QSpinBox | None = getattr(self, "_arith_count_spin", None)
        if op_combo is None:
            return

        op_label = op_combo.currentText()
        op_short = _ARITHMETIC_OP_MAP.get(op_label)
        if op_short is None:
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.warning(parent, "Arithmetic", f"Unsupported operation: {op_label}")
            return
        key_hex = key_edit.text().strip() if key_edit else ""
        if key_hex:
            try:
                bytes.fromhex(key_hex.replace(" ", ""))
            except ValueError:
                parent = self if isinstance(self, QWidget) else None
                QMessageBox.warning(parent, "Arithmetic", "Invalid hex key.")
                return
        count = count_spin.value() if count_spin else 1

        bridge = self._bridge
        bridge_end = sel_end - 1
        try:
            run_bridge_coroutine(bridge.select_range(sel_start, bridge_end))
            run_bridge_coroutine(
                bridge.apply_arithmetic_to_selection(op_short, key_hex=key_hex, count=count),
            )
        except (RuntimeError, OSError, ValueError, TypeError, AttributeError) as exc:
            _logger.exception(
                "arithmetic_bridge_failed",
                operation=op_short,
                selection_start=sel_start,
                selection_end=bridge_end,
            )
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.warning(parent, "Arithmetic", f"Arithmetic operation failed: {exc}")
            return
        self._refresh_widget()

    def _refresh_widget(self) -> None:
        """Refresh the hex widget viewport and trigger data changed."""
        if self._hex_widget is not None:
            update_fn = getattr(self._hex_widget, "_update_viewport", None)
            if callable(update_fn):
                update_fn()
        self._on_data_changed()


class _BlockFillDialog(QDialog):
    """Dialog for configuring block fill parameters."""

    def __init__(self, hex_widget: object, parent: QWidget | None = None) -> None:
        """Initialize the _BlockFillDialog with fill parameters.

        Args:
            hex_widget: The hex editor widget for pre-filling cursor/selection values.
            parent: Parent widget.
        """
        super().__init__(parent)
        self.setWindowTitle("Fill Block")
        layout = QVBoxLayout(self)
        form = QFormLayout()

        cursor = int(getattr(hex_widget, "_cursor_offset", 0)) if hex_widget else 0
        sel_start = int(getattr(hex_widget, "_selection_start", -1)) if hex_widget else -1
        sel_end = int(getattr(hex_widget, "_selection_end", -1)) if hex_widget else -1
        default_len = max(sel_end - sel_start, 1) if sel_start >= 0 and sel_end > sel_start else 16

        self._offset_edit = QLineEdit(f"0x{cursor:X}")
        form.addRow("Offset (hex):", self._offset_edit)
        self._length_edit = QLineEdit(str(default_len))
        form.addRow("Length:", self._length_edit)
        self._pattern_edit = QLineEdit("00")
        self._pattern_edit.setToolTip("Hex pattern to fill with (e.g. 00 or DEADBEEF)")
        form.addRow("Pattern (hex):", self._pattern_edit)
        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_values(self) -> tuple[int, int, bytes]:
        """Extract the dialog values.

        Returns:
            tuple[int, int, bytes]: Offset, length, and pattern bytes.
        """
        offset = int(self._offset_edit.text().strip(), 0)
        length = int(self._length_edit.text().strip(), 0)
        pattern = bytes.fromhex(self._pattern_edit.text().strip())
        return offset, length, pattern


class _BlockCopyMoveDialog(QDialog):
    """Dialog for configuring block copy or move parameters."""

    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        """Initialize the _BlockCopyMoveDialog with window title.

        Args:
            title: Dialog window title.
            parent: Parent widget.
        """
        super().__init__(parent)
        self.setWindowTitle(title)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self._src_edit = QLineEdit("0x0")
        form.addRow("Source offset (hex):", self._src_edit)
        self._len_edit = QLineEdit("16")
        form.addRow("Length:", self._len_edit)
        self._dst_edit = QLineEdit("0x0")
        form.addRow("Destination offset (hex):", self._dst_edit)
        layout.addLayout(form)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_values(self) -> tuple[int, int, int]:
        """Extract the dialog values.

        Returns:
            tuple[int, int, int]: Source offset, length, destination offset.
        """
        src = int(self._src_edit.text().strip(), 0)
        length = int(self._len_edit.text().strip(), 0)
        dst = int(self._dst_edit.text().strip(), 0)
        return src, length, dst


class _BlockSwapDialog(QDialog):
    """Dialog for configuring block swap parameters."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the _BlockSwapDialog.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self.setWindowTitle("Swap Blocks")
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self._off_a_edit = QLineEdit("0x0")
        form.addRow("Block A offset (hex):", self._off_a_edit)
        self._len_a_edit = QLineEdit("16")
        form.addRow("Block A length:", self._len_a_edit)
        self._off_b_edit = QLineEdit("0x0")
        form.addRow("Block B offset (hex):", self._off_b_edit)
        self._len_b_edit = QLineEdit("16")
        form.addRow("Block B length:", self._len_b_edit)
        layout.addLayout(form)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_values(self) -> tuple[int, int, int, int]:
        """Extract the dialog values.

        Returns:
            tuple[int, int, int, int]: Offset A, length A, offset B, length B.
        """
        off_a = int(self._off_a_edit.text().strip(), 0)
        len_a = int(self._len_a_edit.text().strip(), 0)
        off_b = int(self._off_b_edit.text().strip(), 0)
        len_b = int(self._len_b_edit.text().strip(), 0)
        return off_a, len_a, off_b, len_b
