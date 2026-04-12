# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Data inspector mixin for the hex editor panel."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from PyQt6.QtWidgets import (
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from intellicrack.ui.panels.hex_editor._base import ENCODING_ENTRIES, logger


if TYPE_CHECKING:
    from collections.abc import Callable


_BIT_COUNT: int = 8
_BIT_BUTTON_WIDTH: int = 28
_DECODE_DEFAULT_LEN: int = 64
_DECODE_MAX_LEN: int = 4096


class DataInspectorMixin:
    """Mixin providing data inspector functionality for the hex editor panel."""

    _data_inspector_tree: QTreeWidget | None
    _document: Any | None
    document: Any | None
    _hex_widget: Any | None
    _bit_buttons: list[QPushButton]
    _bit_editor_offset: int
    _decode_output: QPlainTextEdit | None
    _decode_combo: QComboBox | None
    _decode_length_spin: QSpinBox | None
    _encode_input: QLineEdit | None
    _encode_output: QLabel | None
    _encode_combo: QComboBox | None

    def _update_data_inspector(self, offset: int) -> None:
        """Update the data inspector tree for the given offset.

        Args:
            offset: Byte offset to inspect.
        """
        if self._data_inspector_tree is None or self.document is None:
            return

        self._data_inspector_tree.clear()
        try:
            result = self.document.inspect_at(offset)
            if not isinstance(result, dict):
                return
            typed_result = cast("dict[str, object]", result)

            display_order = [
                "int8",
                "uint8",
                "ascii_char",
                "utf8_char",
                "int16_le",
                "uint16_le",
                "int16_be",
                "uint16_be",
                "int32_le",
                "uint32_le",
                "int32_be",
                "uint32_be",
                "float32_le",
                "float32_be",
                "int64_le",
                "uint64_le",
                "int64_be",
                "uint64_be",
                "float64_le",
                "float64_be",
                "unix_timestamp",
                "dos_date",
                "dos_time",
                "filetime",
            ]

            for key in display_order:
                if key in typed_result:
                    item = QTreeWidgetItem([key, str(typed_result[key])])
                    self._data_inspector_tree.addTopLevelItem(item)

            for key, val in sorted(typed_result.items()):
                if key not in display_order:
                    item = QTreeWidgetItem([key, str(val)])
                    self._data_inspector_tree.addTopLevelItem(item)

        except (AttributeError, ValueError, TypeError) as exc:
            logger.debug("inspector_update_failed", error=str(exc))

        self._update_bit_buttons(offset)

    def _create_bit_editor_group(self) -> QGroupBox:
        """Create the bit-level editor group box with 8 toggle buttons.

        Returns:
            QGroupBox: Container with 8 bit toggle buttons (MSB to LSB).
        """
        box = QGroupBox("Bit Editor")
        layout = QHBoxLayout(box)
        layout.setSpacing(2)
        self._bit_buttons = []
        self._bit_editor_offset = 0
        for i in range(_BIT_COUNT):
            btn = QPushButton("0")
            btn.setFixedWidth(_BIT_BUTTON_WIDTH)
            btn.setCheckable(True)
            bit_index = 7 - i

            def _make_bit_handler(bi: int) -> Callable[..., None]:
                def _handler(*args: object) -> None:
                    checked = bool(args[0]) if args else False
                    self._on_bit_toggled(bi, checked=checked)

                return _handler

            btn.clicked.connect(_make_bit_handler(bit_index))
            self._bit_buttons.append(btn)
            layout.addWidget(btn)
        layout.addStretch()
        return box

    def _update_bit_buttons(self, offset: int) -> None:
        """Refresh bit button states from the byte at the given offset.

        Args:
            offset: Byte offset to read.
        """
        if not hasattr(self, "_bit_buttons") or self.document is None:
            return

        self._bit_editor_offset = offset
        try:
            raw = self.document.read(offset, 1)
            if isinstance(raw, bytes) and len(raw) > 0:
                byte_val: int = raw[0]
            elif isinstance(raw, list):
                int_list = cast("list[int]", raw)
                if not int_list:
                    return
                byte_val = int(int_list[0])
            elif isinstance(raw, bytearray) and len(raw) > 0:
                byte_val = raw[0]
            else:
                return
        except (AttributeError, ValueError):
            return

        for i, btn in enumerate(self._bit_buttons):
            bit_idx = 7 - i
            is_set = bool(byte_val & (1 << bit_idx))
            btn.setChecked(is_set)
            btn.setText("1" if is_set else "0")

    def _on_bit_toggled(self, bit_index: int, *, checked: bool) -> None:
        """Handle a bit toggle button click.

        Args:
            bit_index: Bit position (0=LSB, 7=MSB).
            checked: Whether the button is now checked.
        """
        if self.document is None:
            return

        offset = self._bit_editor_offset if hasattr(self, "_bit_editor_offset") else 0
        try:
            raw = self.document.read(offset, 1)
            if isinstance(raw, bytes) and len(raw) > 0:
                byte_val: int = raw[0]
            elif isinstance(raw, list):
                int_list = cast("list[int]", raw)
                if not int_list:
                    return
                byte_val = int(int_list[0])
            elif isinstance(raw, bytearray) and len(raw) > 0:
                byte_val = raw[0]
            else:
                return
        except (AttributeError, ValueError):
            return

        byte_val = byte_val | (1 << bit_index) if checked else byte_val & (~(1 << bit_index) & 0xFF)

        try:
            new_bytes = byte_val.to_bytes(1, "little")
            self.document.write_bytes(offset, new_bytes)
        except (AttributeError, ValueError):
            return

        btn_idx = 7 - bit_index
        if 0 <= btn_idx < len(self._bit_buttons):
            self._bit_buttons[btn_idx].setText("1" if checked else "0")

        if self._hex_widget is not None:
            update_fn = getattr(self._hex_widget, "_update_viewport", None)
            if callable(update_fn):
                update_fn()

    def _create_text_decode_group(self) -> QGroupBox:
        """Create the text decode/encode group box.

        Returns:
            QGroupBox: Container with decode and encode controls.
        """
        box = QGroupBox("Text Decode/Encode")
        layout = QVBoxLayout(box)
        layout.setSpacing(4)

        decode_row = QHBoxLayout()
        self._decode_combo = QComboBox()
        for entry in ENCODING_ENTRIES:
            if not entry.startswith("---"):
                self._decode_combo.addItem(entry)
        decode_row.addWidget(self._decode_combo)
        self._decode_length_spin = QSpinBox()
        self._decode_length_spin.setRange(1, _DECODE_MAX_LEN)
        self._decode_length_spin.setValue(_DECODE_DEFAULT_LEN)
        self._decode_length_spin.setSuffix(" bytes")
        decode_row.addWidget(self._decode_length_spin)
        decode_btn = QPushButton("Decode at Cursor")
        decode_btn.clicked.connect(self._on_decode_text)
        decode_row.addWidget(decode_btn)
        layout.addLayout(decode_row)

        self._decode_output = QPlainTextEdit()
        self._decode_output.setReadOnly(True)
        self._decode_output.setMaximumHeight(80)
        layout.addWidget(self._decode_output)

        encode_row = QHBoxLayout()
        self._encode_input = QLineEdit()
        self._encode_input.setToolTip("Text to encode")
        encode_row.addWidget(self._encode_input)
        self._encode_combo = QComboBox()
        for entry in ENCODING_ENTRIES:
            if not entry.startswith("---"):
                self._encode_combo.addItem(entry)
        encode_row.addWidget(self._encode_combo)
        encode_btn = QPushButton("Encode")
        encode_btn.clicked.connect(self._on_encode_text)
        encode_row.addWidget(encode_btn)
        layout.addLayout(encode_row)

        self._encode_output = QLabel("")
        self._encode_output.setWordWrap(on=True)
        layout.addWidget(self._encode_output)

        return box

    def _on_decode_text(self) -> None:
        """Decode bytes at the cursor position as text in the selected encoding."""
        if self.document is None or self._decode_output is None:
            return

        cursor_offset = 0
        if self._hex_widget is not None:
            cursor_offset = int(getattr(self._hex_widget, "_cursor_offset", 0))

        encoding = self._decode_combo.currentText().lower().replace("-", "") if self._decode_combo else "utf8"
        length = self._decode_length_spin.value() if self._decode_length_spin else _DECODE_DEFAULT_LEN

        try:
            raw = self.document.read(cursor_offset, length)
            if isinstance(raw, bytes):
                data = raw
            elif isinstance(raw, bytearray):
                data = bytes(raw)
            elif isinstance(raw, list):
                data = bytes(cast("list[int]", raw))
            else:
                return
            decoded = data.decode(encoding, errors="replace")
            self._decode_output.setPlainText(decoded)
        except (AttributeError, ValueError, LookupError) as exc:
            self._decode_output.setPlainText(f"Error: {exc}")

    def _on_encode_text(self) -> None:
        """Encode text input to hex in the selected encoding."""
        if self._encode_input is None or self._encode_output is None:
            return

        text = self._encode_input.text()
        if not text:
            return

        encoding = self._encode_combo.currentText().lower().replace("-", "") if self._encode_combo else "utf8"

        try:
            encoded = text.encode(encoding, errors="replace")
            hex_str = " ".join(f"{b:02X}" for b in encoded)
            self._encode_output.setText(hex_str)
        except (LookupError, ValueError) as exc:
            self._encode_output.setText(f"Error: {exc}")
