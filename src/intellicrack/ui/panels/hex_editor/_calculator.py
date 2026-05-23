# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Base conversion calculator mixin for the hex editor panel."""

from __future__ import annotations

import struct
from typing import Final

from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger


_logger = get_logger(__name__)


_TREE_COL_COUNT: Final[int] = 2
_IEEE_FLOAT32_BYTES: Final[int] = 4
_IEEE_FLOAT64_BYTES: Final[int] = 8
_BITS_PER_BYTE: Final[int] = 8
_MAX_UINT64: Final[int] = (1 << 64) - 1


class CalculatorMixin:
    """Mixin providing a base conversion calculator tab for the hex editor panel."""

    _side_tabs: QTabWidget | None
    _calc_input: QLineEdit | None
    _calc_signed_check: QCheckBox | None
    _calc_endian_combo: QComboBox | None
    _calc_results_tree: QTreeWidget | None
    _calc_float32_label: QLabel | None
    _calc_float64_label: QLabel | None

    def _create_calculator_tab(self) -> QWidget:
        """Create the base conversion calculator side panel tab.

        Returns:
            QWidget: Container widget with input, convert button,
                endianness controls, results tree, and IEEE 754 display.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(4)

        self._calc_input = QLineEdit()
        self._calc_input.setToolTip("Enter decimal, 0xHex, 0bBinary, 0oOctal")
        self._calc_input.returnPressed.connect(self._on_convert)
        layout.addWidget(self._calc_input)

        opts_row = QHBoxLayout()
        self._calc_signed_check = QCheckBox("Signed")
        opts_row.addWidget(self._calc_signed_check)
        self._calc_endian_combo = QComboBox()
        self._calc_endian_combo.addItems(["Little Endian", "Big Endian"])
        opts_row.addWidget(self._calc_endian_combo)
        convert_btn = QPushButton("Convert")
        convert_btn.clicked.connect(self._on_convert)
        opts_row.addWidget(convert_btn)
        opts_row.addStretch()
        layout.addLayout(opts_row)

        self._calc_results_tree = QTreeWidget()
        self._calc_results_tree.setHeaderLabels(["Representation", "Value"])
        self._calc_results_tree.setColumnCount(_TREE_COL_COUNT)
        self._calc_results_tree.setRootIsDecorated(show=False)
        self._calc_results_tree.setAlternatingRowColors(enable=True)
        layout.addWidget(self._calc_results_tree)

        ieee_box = QGroupBox("IEEE 754")
        ieee_layout = QVBoxLayout(ieee_box)
        self._calc_float32_label = QLabel("float32: --")
        self._calc_float32_label.setWordWrap(on=True)
        ieee_layout.addWidget(self._calc_float32_label)
        self._calc_float64_label = QLabel("float64: --")
        self._calc_float64_label.setWordWrap(on=True)
        ieee_layout.addWidget(self._calc_float64_label)
        layout.addWidget(ieee_box)

        layout.addStretch()
        return container

    def _on_convert(self) -> None:
        """Parse the input value and populate all base/type representations."""
        if self._calc_input is None or self._calc_results_tree is None:
            return

        text = self._calc_input.text().strip()
        if not text:
            return

        self._calc_results_tree.clear()

        try:
            value = self._parse_input_value(text)
        except ValueError as exc:
            _logger.debug("calc_input_parse_failed", text=text, error=str(exc))
            self._calc_results_tree.addTopLevelItem(
                QTreeWidgetItem(["Error", str(exc)]),
            )
            return

        big_endian = self._calc_endian_combo is not None and self._calc_endian_combo.currentText() == "Big Endian"
        byte_order = ">" if big_endian else "<"
        order_label = "BE" if big_endian else "LE"

        self._add_result("Decimal", str(value))
        self._add_result("Hex", f"0x{value & _MAX_UINT64:X}")
        self._add_result("Octal", f"0o{value & _MAX_UINT64:o}")
        self._add_result("Binary", f"0b{value & _MAX_UINT64:b}")

        int_formats: list[tuple[str, str, int]] = [
            ("int8", "b", 1),
            ("uint8", "B", 1),
            (f"int16_{order_label}", f"{byte_order}h", 2),
            (f"uint16_{order_label}", f"{byte_order}H", 2),
            (f"int32_{order_label}", f"{byte_order}i", 4),
            (f"uint32_{order_label}", f"{byte_order}I", 4),
            (f"int64_{order_label}", f"{byte_order}q", 8),
            (f"uint64_{order_label}", f"{byte_order}Q", 8),
        ]

        for label, fmt, size in int_formats:
            try:
                mask = (1 << (size * _BITS_PER_BYTE)) - 1
                packed = struct.pack(fmt, value & mask if fmt[-1].isupper() else self._to_signed(value, size))
                unpacked = struct.unpack(fmt, packed)[0]
                self._add_result(label, str(unpacked))
            except (struct.error, OverflowError) as exc:
                _logger.debug("calc_int_overflow", label=label, value=value, error=str(exc))
                self._add_result(label, "overflow")

        for label, fmt in [(f"float32_{order_label}", f"{byte_order}f"), (f"float64_{order_label}", f"{byte_order}d")]:
            size = _IEEE_FLOAT32_BYTES if "32" in label else _IEEE_FLOAT64_BYTES
            mask = (1 << (size * _BITS_PER_BYTE)) - 1
            try:
                packed = struct.pack(f"{byte_order}{'I' if size == _IEEE_FLOAT32_BYTES else 'Q'}", value & mask)
                float_val = struct.unpack(fmt, packed)[0]
                self._add_result(label, f"{float_val}")
            except (struct.error, OverflowError) as exc:
                _logger.debug("calc_float_pack_failed", label=label, error=str(exc))
                self._add_result(label, "N/A")

        self._update_ieee754_display(value, byte_order)

    def _add_result(self, label: str, value: str) -> None:
        """Add a row to the results tree.

        Args:
            label: Representation name.
            value: Converted value string.
        """
        if self._calc_results_tree is not None:
            self._calc_results_tree.addTopLevelItem(QTreeWidgetItem([label, value]))

    @staticmethod
    def _parse_input_value(text: str) -> int:
        """Parse an input string as an integer in auto-detected base.

        Args:
            text: Input string, optionally prefixed with 0x, 0b, or 0o.

        Returns:
            int: Parsed integer value.

        Raises:
            ValueError: If the string is empty.
        """
        lower = text.lower().strip()
        if not lower:
            msg = f"Cannot parse empty input: {text!r}"
            raise ValueError(msg)
        if lower.startswith("0x"):
            return int(lower, 16)
        if lower.startswith("0b"):
            return int(lower, 2)
        if lower.startswith("0o"):
            return int(lower, 8)
        return int(text, 10)

    @staticmethod
    def _to_signed(value: int, size: int) -> int:
        """Convert an unsigned integer to its signed representation.

        Args:
            value: Unsigned integer value.
            size: Byte width of the target type.

        Returns:
            int: Signed integer that fits in the given byte width.
        """
        mask = (1 << (size * _BITS_PER_BYTE)) - 1
        val = value & mask
        sign_bit = 1 << (size * _BITS_PER_BYTE - 1)
        if val & sign_bit:
            return val - (1 << (size * _BITS_PER_BYTE))
        return val

    def _update_ieee754_display(self, value: int, byte_order: str) -> None:
        """Update the IEEE 754 bit-layout labels.

        Args:
            value: Raw integer value to interpret as float bits.
            byte_order: Struct byte-order character ('>' or '<').
        """
        if self._calc_float32_label is not None:
            bits32 = value & 0xFFFFFFFF
            sign = (bits32 >> 31) & 1
            exp = (bits32 >> 23) & 0xFF
            mantissa = bits32 & 0x7FFFFF
            try:
                packed = struct.pack(f"{byte_order}I", bits32)
                fval = struct.unpack(f"{byte_order}f", packed)[0]
                self._calc_float32_label.setText(
                    f"float32: {fval}  [S={sign} E={exp} M=0x{mantissa:06X}]",
                )
            except struct.error as exc:
                _logger.debug("calc_ieee754_pack_failed", label="float32", error=str(exc))
                self._calc_float32_label.setText("float32: N/A")

        if self._calc_float64_label is not None:
            bits64 = value & 0xFFFFFFFFFFFFFFFF
            sign = (bits64 >> 63) & 1
            exp = (bits64 >> 52) & 0x7FF
            mantissa = bits64 & 0xFFFFFFFFFFFFF
            try:
                packed = struct.pack(f"{byte_order}Q", bits64)
                fval = struct.unpack(f"{byte_order}d", packed)[0]
                self._calc_float64_label.setText(
                    f"float64: {fval}  [S={sign} E={exp} M=0x{mantissa:013X}]",
                )
            except struct.error as exc:
                _logger.debug("calc_ieee754_pack_failed", label="float64", error=str(exc))
                self._calc_float64_label.setText("float64: N/A")
