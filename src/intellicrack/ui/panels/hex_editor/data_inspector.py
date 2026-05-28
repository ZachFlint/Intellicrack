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

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine
from intellicrack.ui.panels.hex_editor.base import hexcore, hexcore_available


_logger = get_logger(__name__)


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
    state_holder: Any | None
    _bridge: Any | None
    _hex_widget: Any | None
    _bit_buttons: list[QPushButton]
    _bit_editor_offset: int
    _decode_output: QPlainTextEdit | None
    _decode_combo: QComboBox | None
    _decode_length_spin: QSpinBox | None
    _encode_input: QLineEdit | None
    _encode_output: QLabel | None
    _encode_combo: QComboBox | None

    def _populate_data_inspector(self, tree: QTreeWidget, offset: int) -> None:
        """Inspect ``offset`` and populate ``tree`` with the decoded fields.

        Args:
            tree: Inspector tree widget to fill.
            offset: Byte offset to inspect.
        """
        document: Any = self.document
        if document is None:
            return
        result = document.inspect_at(offset)
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
                tree.addTopLevelItem(item)

        for key, val in sorted(typed_result.items()):
            if key not in display_order:
                item = QTreeWidgetItem([key, str(val)])
                tree.addTopLevelItem(item)

    def _update_data_inspector(self, offset: int) -> None:
        """Update the data inspector tree for the given offset.

        Args:
            offset: Byte offset to inspect.
        """
        if self._data_inspector_tree is None or self.document is None:
            return

        self._data_inspector_tree.clear()
        try:
            self._populate_data_inspector(self._data_inspector_tree, offset)
        except (AttributeError, ValueError, TypeError):
            _logger.exception("inspector_update_failed")

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

        Uses ``document.get_bit`` for each bit so the GUI reflects the
        authoritative state from the hexcore backend without performing
        its own read-modify arithmetic.

        Args:
            offset: Byte offset to read.
        """
        if not hasattr(self, "_bit_buttons") or self.document is None:
            return

        self._bit_editor_offset = offset
        for i, btn in enumerate(self._bit_buttons):
            bit_idx = 7 - i
            try:
                is_set = bool(self.document.get_bit(offset, bit_idx))
            except (AttributeError, ValueError, OverflowError):
                _logger.exception("bit_read_failed", offset=offset, bit=bit_idx)
                btn.setChecked(False)
                btn.setText("?")
                btn.setEnabled(False)
                continue
            btn.setEnabled(True)
            btn.setChecked(is_set)
            btn.setText("1" if is_set else "0")

    def _on_bit_toggled(self, bit_index: int, *, checked: bool) -> None:
        """Handle a bit toggle button click.

        Delegates the single-bit write to ``document.set_bit`` so the
        hexcore backend performs the read-modify-write atomically and
        records it in the undo history. The button is re-synced from
        ``document.get_bit`` after the write to avoid drift if the
        backend clamps or rejects the value.

        Args:
            bit_index: Bit position (0=LSB, 7=MSB).
            checked: Whether the button is now checked.
        """
        if self.document is None:
            return

        offset = self._bit_editor_offset if hasattr(self, "_bit_editor_offset") else 0
        _logger.info("bit_write_requested", offset=offset, bit=bit_index, checked=checked)
        try:
            self.document.set_bit(offset, bit_index, checked)
        except (AttributeError, ValueError, OverflowError):
            _logger.exception("bit_write_failed", offset=offset, bit=bit_index)
            return

        state_holder = getattr(self, "state_holder", None)
        if state_holder is not None:
            notify = getattr(state_holder, "notify_data_modified", None)
            if callable(notify):
                notify(offset, 1, source="hex-editor.data_inspector.bit")

        btn_idx = 7 - bit_index
        if 0 <= btn_idx < len(self._bit_buttons):
            try:
                is_set = bool(self.document.get_bit(offset, bit_index))
            except (AttributeError, ValueError, OverflowError):
                is_set = checked
            self._bit_buttons[btn_idx].setChecked(is_set)
            self._bit_buttons[btn_idx].setText("1" if is_set else "0")

        if self._hex_widget is not None:
            update_fn = getattr(self._hex_widget, "_update_viewport", None)
            if callable(update_fn):
                update_fn()

    @staticmethod
    def _populate_encoding_combo(combo: QComboBox) -> None:
        """Populate an encoding combo from the hexcore encoding registry.

        Each entry uses the human-readable description as the display
        label and stores the hexcore codec name as the item's user data,
        so the decode/encode handlers can pass the untransformed codec
        name to the backend.

        Args:
            combo: The combo box to populate.
        """
        combo.clear()
        encodings: list[tuple[str, str]] = []
        if hexcore_available and hexcore is not None:
            try:
                encodings = list(hexcore.HexDocument.list_encodings())
            except (AttributeError, TypeError, ValueError):
                _logger.exception("list_encodings_failed")
                encodings = []
        if not encodings:
            encodings = [("utf-8", "UTF-8"), ("ascii", "ASCII (7-bit)")]
        for name, description in encodings:
            combo.addItem(description, userData=name)

    @staticmethod
    def _selected_encoding(combo: QComboBox | None) -> str:
        """Return the hexcore codec name for the combo's current selection.

        Args:
            combo: The encoding combo box, or ``None`` if not initialized.

        Returns:
            str: The hexcore codec name, defaulting to ``"utf-8"``.
        """
        if combo is None:
            return "utf-8"
        data = combo.currentData()
        return data if isinstance(data, str) and data else "utf-8"

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
        self._populate_encoding_combo(self._decode_combo)
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
        self._populate_encoding_combo(self._encode_combo)
        encode_row.addWidget(self._encode_combo)
        encode_btn = QPushButton("Encode")
        encode_btn.clicked.connect(self._on_encode_text)
        encode_row.addWidget(encode_btn)
        layout.addLayout(encode_row)

        self._encode_output = QLabel("")
        self._encode_output.setWordWrap(True)
        layout.addWidget(self._encode_output)

        return box

    def _on_decode_text(self) -> None:
        """Decode bytes at the cursor position using the hexcore backend.

        Calls ``document.decode_text`` so the Rust codec registry handles EBCDIC, Shift-JIS, and other encodings that lack a Python stdlib
        codec. The hexcore name is read from the combo's user data.
        """
        if self.document is None or self._decode_output is None:
            return

        cursor_offset = 0
        if self._hex_widget is not None:
            cursor_offset = int(getattr(self._hex_widget, "_cursor_offset", 0))

        encoding = self._selected_encoding(self._decode_combo)
        length = self._decode_length_spin.value() if self._decode_length_spin else _DECODE_DEFAULT_LEN

        doc_len = 0
        try:
            doc_len = int(self.document.length())
        except (AttributeError, TypeError, ValueError) as exc:
            _logger.warning(
                "decode_text_doc_length_unavailable",
                error_type=type(exc).__name__,
                error=str(exc),
            )
            doc_len = 0
        if doc_len > 0:
            length = max(0, min(length, doc_len - cursor_offset))
        if length <= 0:
            self._decode_output.setPlainText("")
            _logger.debug(
                "decode_text_zero_length",
                cursor_offset=cursor_offset,
                doc_len=doc_len,
            )
            return

        _logger.info(
            "decode_text_started",
            encoding=encoding,
            offset=cursor_offset,
            length=length,
            doc_len=doc_len,
        )

        try:
            decoded = self.document.decode_text(cursor_offset, length, encoding)
        except (AttributeError, ValueError, OverflowError) as exc:
            _logger.warning(
                "decode_text_failed",
                encoding=encoding,
                offset=cursor_offset,
                length=length,
                error_type=type(exc).__name__,
                error=str(exc),
            )
            self._decode_output.setPlainText(f"Error: {exc}")
        else:
            self._decode_output.setPlainText(str(decoded))

    def _on_encode_text(self) -> None:
        """Encode text input to hex using the bridge's encode_text path.

        Routes the encode operation through the bridge so the Rust codec registry handles encodings that lack a Python stdlib codec (e.g.
        EBCDIC). When no document is open the status label is set to "No document open" and no bytes are produced.
        """
        if self._encode_input is None or self._encode_output is None:
            return

        text = self._encode_input.text()
        if not text:
            return

        if self.document is None:
            self._encode_output.setText("No document open")
            return

        bridge = getattr(self, "_bridge", None)
        if bridge is None:
            self._encode_output.setText("Error: hex editor bridge not available")
            return

        encoding = self._selected_encoding(self._encode_combo)

        _logger.info(
            "encode_text_started",
            encoding=encoding,
            text_length=len(text),
        )

        try:
            hex_str = run_bridge_coroutine(bridge.encode_text(text, encoding))
        except (AttributeError, ValueError, OverflowError, RuntimeError) as exc:
            _logger.exception(
                "encode_text_bridge_failed",
                encoding=encoding,
                text_length=len(text),
                error_type=type(exc).__name__,
            )
            self._encode_output.setText(f"Error: {exc}")
            return

        if hex_str is None:
            self._encode_output.setText("Error: encode operation did not return a result")
            return

        spaced = " ".join(str(hex_str)[i : i + 2].upper() for i in range(0, len(str(hex_str)), 2))
        self._encode_output.setText(spaced)
