# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Base conversion calculator mixin for the hex editor panel."""

from __future__ import annotations

import struct
from typing import Any, Final, cast

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
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged


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
    _bridge: Any | None

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
        self._calc_results_tree.setRootIsDecorated(False)
        self._calc_results_tree.setAlternatingRowColors(True)
        layout.addWidget(self._calc_results_tree)

        ieee_box = QGroupBox("IEEE 754")
        ieee_layout = QVBoxLayout(ieee_box)
        self._calc_float32_label = QLabel("float32: --")
        self._calc_float32_label.setWordWrap(True)
        ieee_layout.addWidget(self._calc_float32_label)
        self._calc_float64_label = QLabel("float64: --")
        self._calc_float64_label.setWordWrap(True)
        ieee_layout.addWidget(self._calc_float64_label)
        layout.addWidget(ieee_box)

        layout.addStretch()
        return container

    def _on_convert(self) -> None:
        """Parse the input value and populate all base/type representations.

        Dispatches to :meth:`HexEditorBridge.base_convert` so the value parsing and canonical decimal/hex/octal/binary/little-endian
        representations come from the same code path the AI-callable tool uses. The big-endian sized-integer and IEEE 754 views (not
        produced by the bridge, which is little-endian only) are derived locally from the bridge's returned decimal value once it is back on
        the Qt main thread. Falls back to an entirely local, synchronous computation when no bridge is attached (e.g. headless / test
        harnesses that drive the calculator tab directly).
        """
        if self._calc_input is None or self._calc_results_tree is None:
            return

        text = self._calc_input.text().strip()
        if not text:
            return

        self._calc_results_tree.clear()
        big_endian = self._calc_endian_combo is not None and self._calc_endian_combo.currentText() == "Big Endian"
        signed_only = self._calc_signed_check is not None and self._calc_signed_check.isChecked()

        bridge = getattr(self, "_bridge", None)
        if bridge is None:
            self._convert_local(text, big_endian=big_endian, signed_only=signed_only)
            return

        run_bridge_coroutine_logged(
            bridge.base_convert(text, from_base="auto"),
            on_success=lambda result: self._on_convert_success(result, big_endian=big_endian, signed_only=signed_only),
            on_error=self._on_convert_error,
            parent=self if isinstance(self, QWidget) else None,
            event="hex_editor_base_convert",
            logger=_logger,
            input_value=text,
        )

    def _convert_local(self, text: str, *, big_endian: bool, signed_only: bool) -> None:
        """Parse ``text`` and populate representations without the bridge.

        Local fallback used only when no bridge is attached to this
        mixin, preserving the exact parsing and rendering behaviour the
        panel has always produced.

        Args:
            text: Raw input string, optionally prefixed with 0x, 0b, or 0o.
            big_endian: Whether the endianness combo was set to "Big Endian".
            signed_only: Whether the "Signed" checkbox is checked. When
                ``True`` only signed sized-integer representations are
                shown; when ``False`` both signed and unsigned ones are
                shown.
        """
        try:
            value = self._parse_input_value(text)
        except ValueError as exc:
            _logger.warning("calc_input_parse_failed", text=text, error=str(exc))
            self._add_result("Error", str(exc))
            return

        byte_order = ">" if big_endian else "<"
        order_label = "BE" if big_endian else "LE"

        self._add_result("Decimal", str(value))
        self._add_result("Hex", f"0x{value & _MAX_UINT64:X}")
        self._add_result("Octal", f"0o{value & _MAX_UINT64:o}")
        self._add_result("Binary", f"0b{value & _MAX_UINT64:b}")

        self._add_sized_int_results(value, byte_order, order_label, signed_only=signed_only)
        self._add_float_results(value, byte_order, order_label)
        self._update_ieee754_display(value, byte_order)

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
        return int(lower, 8) if lower.startswith("0o") else int(text, 10)

    def _on_convert_success(self, result: object, *, big_endian: bool, signed_only: bool) -> None:
        """Render the bridge's base-conversion representations into the results tree.

        Args:
            result: ``dict[str, str]`` payload returned by
                :meth:`HexEditorBridge.base_convert`, keyed by
                representation name (``decimal``, ``hex``, ``octal``,
                ``binary``, ``uint8``, ``int8``, ``uint16_le``,
                ``int16_le``, ``uint32_le``, ``int32_le``, ``uint64_le``,
                ``int64_le``, ``float32_le``, ``float64_le``).
            big_endian: Whether the endianness combo was set to "Big
                Endian" when the request was dispatched; controls
                whether the locally-derived big-endian sized-integer
                and IEEE 754 rows are shown instead of the bridge's
                little-endian ones.
            signed_only: Whether the "Signed" checkbox was checked when
                the request was dispatched. When ``True`` only signed
                sized-integer representations are shown; when ``False``
                both signed and unsigned representations are shown.
        """
        if self._calc_results_tree is None:
            return
        if not isinstance(result, dict):
            _logger.warning("base_convert_unexpected_result_type", result_type=type(result).__name__)
            return
        typed_result = cast("dict[str, str]", result)

        self._calc_results_tree.clear()
        self._add_result("Decimal", typed_result.get("decimal", ""))
        self._add_result("Hex", typed_result.get("hex", ""))
        self._add_result("Octal", typed_result.get("octal", ""))
        self._add_result("Binary", typed_result.get("binary", ""))

        try:
            value = int(typed_result.get("decimal", "0"))
        except ValueError:
            _logger.warning("base_convert_decimal_parse_failed", decimal=typed_result.get("decimal"))
            return

        byte_order = ">" if big_endian else "<"
        order_label = "BE" if big_endian else "LE"

        if big_endian:
            self._add_sized_int_results(value, byte_order, order_label, signed_only=signed_only)
            self._add_float_results(value, byte_order, order_label)
        else:
            self._add_result("int8", typed_result.get("int8", "overflow"))
            if not signed_only:
                self._add_result("uint8", typed_result.get("uint8", "overflow"))
            self._add_result("int16_LE", typed_result.get("int16_le", "overflow"))
            if not signed_only:
                self._add_result("uint16_LE", typed_result.get("uint16_le", "overflow"))
            self._add_result("int32_LE", typed_result.get("int32_le", "overflow"))
            if not signed_only:
                self._add_result("uint32_LE", typed_result.get("uint32_le", "overflow"))
            self._add_result("int64_LE", typed_result.get("int64_le", "overflow"))
            if not signed_only:
                self._add_result("uint64_LE", typed_result.get("uint64_le", "overflow"))
            self._add_result("float32_LE", typed_result.get("float32_le", "N/A"))
            self._add_result("float64_LE", typed_result.get("float64_le", "N/A"))

        self._update_ieee754_display(value, byte_order)

    def _on_convert_error(self, exc: object) -> None:
        """Render a base-conversion failure raised by the bridge.

        Args:
            exc: Exception raised by :meth:`HexEditorBridge.base_convert`,
                typically :class:`ValueError` for an unparsable input.
        """
        _logger.warning("base_convert_failed", error=str(exc))
        if self._calc_results_tree is not None:
            self._calc_results_tree.clear()
            self._calc_results_tree.addTopLevelItem(
                QTreeWidgetItem(["Error", str(exc)]),
            )

    def _add_sized_int_results(self, value: int, byte_order: str, order_label: str, *, signed_only: bool) -> None:
        """Add signed/unsigned 8-64 bit representations for the given byte order.

        Args:
            value: Parsed integer value.
            byte_order: Struct byte-order character ('>' or '<').
            order_label: Display suffix for the byte order ('BE' or 'LE').
            signed_only: Whether the "Signed" checkbox is checked. When
                ``True`` only signed representations are added; when
                ``False`` both signed and unsigned representations are
                added.
        """
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
        if signed_only:
            int_formats = [(label, fmt, size) for label, fmt, size in int_formats if fmt[-1].islower()]

        for label, fmt, size in int_formats:
            try:
                mask = (1 << (size * _BITS_PER_BYTE)) - 1
                packed = struct.pack(fmt, value & mask if fmt[-1].isupper() else self._to_signed(value, size))
                unpacked = struct.unpack(fmt, packed)[0]
                self._add_result(label, str(unpacked))
            except (struct.error, OverflowError) as exc:
                _logger.warning("calc_int_overflow", label=label, value=value, error=str(exc))
                self._add_result(label, "overflow")

    def _add_float_results(self, value: int, byte_order: str, order_label: str) -> None:
        """Add IEEE 754 float32/float64 representations for the given byte order.

        Args:
            value: Parsed integer value whose bit pattern is reinterpreted as a float.
            byte_order: Struct byte-order character ('>' or '<').
            order_label: Display suffix for the byte order ('BE' or 'LE').
        """
        for label, fmt in [(f"float32_{order_label}", f"{byte_order}f"), (f"float64_{order_label}", f"{byte_order}d")]:
            size = _IEEE_FLOAT32_BYTES if "32" in label else _IEEE_FLOAT64_BYTES
            mask = (1 << (size * _BITS_PER_BYTE)) - 1
            try:
                packed = struct.pack(f"{byte_order}{'I' if size == _IEEE_FLOAT32_BYTES else 'Q'}", value & mask)
                float_val = struct.unpack(fmt, packed)[0]
                self._add_result(label, f"{float_val}")
            except (struct.error, OverflowError) as exc:
                _logger.warning("calc_float_pack_failed", label=label, error=str(exc))
                self._add_result(label, "N/A")

    def _add_result(self, label: str, value: str) -> None:
        """Add a row to the results tree.

        Args:
            label: Representation name.
            value: Converted value string.
        """
        if self._calc_results_tree is not None:
            self._calc_results_tree.addTopLevelItem(QTreeWidgetItem([label, value]))

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
        return val - (1 << (size * _BITS_PER_BYTE)) if val & sign_bit else val

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
                _logger.warning("calc_ieee754_pack_failed", label="float32", error=str(exc))
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
                _logger.warning("calc_ieee754_pack_failed", label="float64", error=str(exc))
                self._calc_float64_label.setText("float64: N/A")
