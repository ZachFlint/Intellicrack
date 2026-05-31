# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-logic coverage for ``hex_editor.calculator.CalculatorMixin``.

The audit (shard 13) flagged ``calculator.py`` as entirely untested. The
calculator is a pure-logic unit: it parses a number in an auto-detected base
and renders every integer/float representation through :mod:`struct`. These
tests drive the real :class:`CalculatorMixin` UI (a genuine
``QTreeWidget``/``QLineEdit`` built by ``_create_calculator_tab``) end to end
and assert the actual computed base conversions, signed-width wrapping, and
IEEE-754 bit layouts against independent ``struct`` references — no fakes
stand in for the conversion logic under test.
"""

from __future__ import annotations

import struct

import pytest
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QLabel,
    QLineEdit,
    QTabWidget,
    QTreeWidget,
    QWidget,
)

from intellicrack.ui.panels.hex_editor.calculator import CalculatorMixin


pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Provide a shared QApplication for the calculator tests.

    Returns:
        QApplication: The Qt application instance.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        return existing
    return QApplication([])


class _CalculatorHost(CalculatorMixin):
    """Concrete host that builds the real calculator tab for testing.

    Attributes:
        side_tabs: Unused tab container required by the mixin annotations.
        container: The calculator tab widget, retained so its child controls
            are not garbage collected during the test.
    """

    side_tabs: QTabWidget
    container: QWidget

    def __init__(self, *, big_endian: bool = False, signed: bool = False) -> None:
        """Build the real calculator tab and configure endianness/sign.

        Args:
            big_endian: Whether to select big-endian byte order.
            signed: Whether to tick the signed checkbox.
        """
        self.side_tabs = QTabWidget()
        setattr(self, "_side_tabs", self.side_tabs)
        setattr(self, "_calc_input", None)
        setattr(self, "_calc_signed_check", None)
        setattr(self, "_calc_endian_combo", None)
        setattr(self, "_calc_results_tree", None)
        setattr(self, "_calc_float32_label", None)
        setattr(self, "_calc_float64_label", None)
        self.container = self._create_calculator_tab()
        combo = self.endian_combo
        combo.setCurrentText("Big Endian" if big_endian else "Little Endian")
        self.signed_check.setChecked(signed)

    @property
    def input_edit(self) -> QLineEdit:
        """Expose the input line edit for tests.

        Returns:
            QLineEdit: The calculator input field.
        """
        edit = getattr(self, "_calc_input", None)
        assert isinstance(edit, QLineEdit)
        return edit

    @property
    def endian_combo(self) -> QComboBox:
        """Expose the endianness combo box for tests.

        Returns:
            QComboBox: The endianness selector.
        """
        combo = getattr(self, "_calc_endian_combo", None)
        assert isinstance(combo, QComboBox)
        return combo

    @property
    def signed_check(self) -> QCheckBox:
        """Expose the signed checkbox for tests.

        Returns:
            QCheckBox: The signed-mode checkbox.
        """
        check = getattr(self, "_calc_signed_check", None)
        assert isinstance(check, QCheckBox)
        return check

    @property
    def results_tree(self) -> QTreeWidget:
        """Expose the results tree for tests.

        Returns:
            QTreeWidget: The results tree.
        """
        tree = getattr(self, "_calc_results_tree", None)
        assert isinstance(tree, QTreeWidget)
        return tree

    @property
    def float32_label(self) -> QLabel:
        """Expose the float32 IEEE-754 label for tests.

        Returns:
            QLabel: The float32 display label.
        """
        label = getattr(self, "_calc_float32_label", None)
        assert isinstance(label, QLabel)
        return label

    def convert(self, text: str) -> dict[str, str]:
        """Run a conversion and return the results tree as a label->value map.

        Args:
            text: Input value string to convert.

        Returns:
            dict[str, str]: Mapping of representation label to computed value.
        """
        self.input_edit.setText(text)
        self._on_convert()
        tree = self.results_tree
        result: dict[str, str] = {}
        for row in range(tree.topLevelItemCount()):
            item = tree.topLevelItem(row)
            assert item is not None
            result[item.text(0)] = item.text(1)
        return result


class TestBaseConversions:
    """Auto-base parsing must produce correct hex/octal/binary representations."""

    def test_decimal_input_all_bases(self, qapp: QApplication) -> None:
        """Verify a decimal input renders matching hex/octal/binary values.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        host = _CalculatorHost()
        results = host.convert("255")
        assert results["Decimal"] == "255"
        assert results["Hex"] == "0xFF"
        assert results["Octal"] == "0o377"
        assert results["Binary"] == "0b11111111"

    def test_hex_input_parsed(self, qapp: QApplication) -> None:
        """Verify a 0x-prefixed input is parsed as hexadecimal.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        host = _CalculatorHost()
        results = host.convert("0xDEAD")
        assert results["Decimal"] == str(0xDEAD)
        assert results["Hex"] == "0xDEAD"

    def test_binary_and_octal_inputs(self, qapp: QApplication) -> None:
        """Verify 0b and 0o prefixed inputs parse in the right base.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        host = _CalculatorHost()
        assert host.convert("0b1010")["Decimal"] == "10"
        assert host.convert("0o17")["Decimal"] == "15"

    def test_invalid_input_reports_error(self, qapp: QApplication) -> None:
        """Verify a non-numeric input produces an Error row, not a crash.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        host = _CalculatorHost()
        results = host.convert("not_a_number")
        assert "Error" in results


class TestIntegerTypeRepresentations:
    """Integer width interpretations must match independent struct references."""

    def test_signed_wraparound_little_endian(self, qapp: QApplication) -> None:
        """Verify 0xFF interpreted as int8 wraps to -1 and uint8 stays 255.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        host = _CalculatorHost()
        results = host.convert("0xFF")
        assert results["int8"] == "-1"
        assert results["uint8"] == "255"

    def test_int32_matches_struct(self, qapp: QApplication) -> None:
        """Verify int32_LE/uint32_LE reproduce a struct round-trip.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        host = _CalculatorHost()
        value = 0xCAFEBABE
        results = host.convert(hex(value))
        packed = struct.pack("<I", value & 0xFFFFFFFF)
        assert results["uint32_LE"] == str(struct.unpack("<I", packed)[0])
        assert results["int32_LE"] == str(struct.unpack("<i", packed)[0])

    def test_endianness_labels_track_selection(self, qapp: QApplication) -> None:
        """Verify the order label reflects the selected byte order.

        The calculator packs and unpacks with the same byte order, so the
        integer value round-trips identically; the distinguishing, observable
        effect of the endianness selection is the ``_LE`` / ``_BE`` suffix on
        the representation labels.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        value = 0x01020304
        le_results = _CalculatorHost(big_endian=False).convert(hex(value))
        be_results = _CalculatorHost(big_endian=True).convert(hex(value))
        assert "uint32_LE" in le_results
        assert "uint32_BE" in be_results
        assert "uint32_BE" not in le_results
        assert "uint32_LE" not in be_results
        assert le_results["uint32_LE"] == str(struct.unpack("<I", struct.pack("<I", value))[0])
        assert be_results["uint32_BE"] == str(struct.unpack(">I", struct.pack(">I", value))[0])


class TestIeee754Display:
    """IEEE-754 bit-layout labels must decode the raw integer correctly."""

    def test_float32_one_point_zero(self, qapp: QApplication) -> None:
        """Verify the float32 label decodes the IEEE-754 bit pattern for 1.0.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        host = _CalculatorHost()
        bits = struct.unpack("<I", struct.pack("<f", 1.0))[0]
        host.convert(hex(bits))
        text = host.float32_label.text()
        assert "1.0" in text
        assert "E=127" in text
