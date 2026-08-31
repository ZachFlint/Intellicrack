# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for the hex editor base conversion calculator mixin.

The audit (shard 13, ``calculator.py`` listed under ``NOT TESTED``) flagged the
binary calculator as untested real functionality: base conversions, signed/
unsigned integer reinterpretation across every fixed width, IEEE-754 float
decoding, and endianness handling.

These tests drive the real :class:`CalculatorMixin` against a real Qt widget
tree. They assert the actual computed representations - decimal/hex/octal/
binary strings, signed two's-complement values, and IEEE-754 float bit layouts
- against values independently derived with :mod:`struct`, never against a value
the test injected into the widget.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication, QWidget

from intellicrack.ui.panels.hex_editor.calculator import CalculatorMixin


if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication]:
    """Provide a process-wide ``QApplication`` for Qt widget construction.

    Yields:
        QApplication: Qt application instance shared across tests.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


class _CalculatorHarness(CalculatorMixin, QWidget):
    """Minimal host widget that builds the real calculator tab.

    Uses the production :meth:`CalculatorMixin._create_calculator_tab` so the
    real widgets, signal wiring, and :meth:`_on_convert` slot are exercised.
    """

    def __init__(self) -> None:
        """Build the real calculator tab and retain it as a child widget."""
        super().__init__()
        self._tab: QWidget = self._create_calculator_tab()

    def convert(self, text: str, *, big_endian: bool = False) -> dict[str, str]:
        """Drive the real conversion slot and return the rendered rows.

        Args:
            text: Input string to feed the calculator.
            big_endian: When ``True`` selects the big-endian interpretation.

        Returns:
            dict[str, str]: Mapping of representation label to value string.
        """
        if self._calc_endian_combo is not None:
            self._calc_endian_combo.setCurrentText("Big Endian" if big_endian else "Little Endian")
        if self._calc_input is not None:
            self._calc_input.setText(text)
        self._on_convert()
        return self._results()

    def float32_text(self) -> str:
        """Return the rendered IEEE-754 float32 label text.

        Returns:
            str: The float32 label contents.
        """
        return self._calc_float32_label.text() if self._calc_float32_label is not None else ""

    def float64_text(self) -> str:
        """Return the rendered IEEE-754 float64 label text.

        Returns:
            str: The float64 label contents.
        """
        return self._calc_float64_label.text() if self._calc_float64_label is not None else ""

    def _results(self) -> dict[str, str]:
        """Read every rendered representation row out of the results tree.

        Returns:
            dict[str, str]: Mapping of representation label to value string.
        """
        out: dict[str, str] = {}
        tree = self._calc_results_tree
        if tree is None:
            return out
        for i in range(tree.topLevelItemCount()):
            item = tree.topLevelItem(i)
            if item is not None:
                out[item.text(0)] = item.text(1)
        return out


def _build(qapp: QApplication) -> _CalculatorHarness:
    """Construct a calculator harness.

    Args:
        qapp: Live Qt application (kept alive for widget construction).

    Returns:
        _CalculatorHarness: Ready-to-drive calculator harness.
    """
    del qapp
    return _CalculatorHarness()


@pytest.mark.usefixtures("qapp")
class TestBaseConversion:
    """The calculator must produce correct base representations of real values."""

    @staticmethod
    def test_decimal_input_round_trips_through_all_bases(qapp: QApplication) -> None:
        """A decimal input renders matching hex, octal, and binary strings.

        Args:
            qapp: Qt application fixture.
        """
        rows = _build(qapp).convert("3735928559")
        assert rows["Decimal"] == "3735928559"
        assert rows["Hex"] == "0xDEADBEEF"
        assert rows["Octal"] == f"0o{3735928559:o}"
        assert rows["Binary"] == f"0b{3735928559:b}"

    @staticmethod
    def test_hex_prefixed_input_is_auto_detected(qapp: QApplication) -> None:
        """A ``0x``-prefixed input is parsed as hexadecimal.

        Args:
            qapp: Qt application fixture.
        """
        rows = _build(qapp).convert("0xCAFEBABE")
        assert rows["Decimal"] == str(0xCAFEBABE)
        assert rows["Hex"] == "0xCAFEBABE"

    @staticmethod
    def test_binary_and_octal_prefixes_are_auto_detected(qapp: QApplication) -> None:
        """``0b`` and ``0o`` prefixes select binary and octal parsing.

        Args:
            qapp: Qt application fixture.
        """
        harness = _build(qapp)
        assert harness.convert("0b101010")["Decimal"] == "42"
        assert harness.convert("0o755")["Decimal"] == str(0o755)

    @staticmethod
    def test_invalid_input_renders_error_row(qapp: QApplication) -> None:
        """Unparseable input produces an ``Error`` row, not a crash.

        Args:
            qapp: Qt application fixture.
        """
        rows = _build(qapp).convert("not_a_number")
        assert "Error" in rows
        assert "Decimal" not in rows


@pytest.mark.usefixtures("qapp")
class TestIntegerReinterpretation:
    """Signed and unsigned integer rows must match independent struct decoding."""

    @staticmethod
    def test_signed_eight_bit_two_complement(qapp: QApplication) -> None:
        """0xFF renders as int8 -1 and uint8 255 (real two's complement).

        Args:
            qapp: Qt application fixture.
        """
        rows = _build(qapp).convert("0xFF")
        assert rows["int8"] == "-1"
        assert rows["uint8"] == "255"

    @staticmethod
    def test_signed_thirty_two_bit_matches_struct(qapp: QApplication) -> None:
        """int32 reinterpretation matches an independent struct decode.

        Args:
            qapp: Qt application fixture.
        """
        rows = _build(qapp).convert("0xFFFFFFFE", big_endian=False)
        expected = struct.unpack("<i", struct.pack("<I", 0xFFFFFFFE))[0]
        assert rows["int32_LE"] == str(expected)
        assert expected == -2


@pytest.mark.usefixtures("qapp")
class TestIeee754Decoding:
    """IEEE-754 float rows must match struct float decoding of the bit pattern."""

    @staticmethod
    def test_float32_one_point_zero_bit_pattern(qapp: QApplication) -> None:
        """0x3F800000 decodes to float32 1.0 with correct sign/exp/mantissa.

        Args:
            qapp: Qt application fixture.
        """
        harness = _build(qapp)
        rows = harness.convert("0x3F800000", big_endian=True)

        expected = struct.unpack(">f", struct.pack(">I", 0x3F800000))[0]
        assert rows["float32_BE"] == str(expected)
        assert abs(expected - 1.0) < 1e-9

        label = harness.float32_text()
        assert "S=0" in label
        assert "E=127" in label
        assert "M=0x000000" in label

    @staticmethod
    def test_float64_known_bit_pattern(qapp: QApplication) -> None:
        """A 64-bit pattern decodes to the struct-defined double value.

        Args:
            qapp: Qt application fixture.
        """
        harness = _build(qapp)
        bits = 0x400921FB54442D18
        rows = harness.convert(f"0x{bits:016X}", big_endian=True)

        expected = struct.unpack(">d", struct.pack(">Q", bits))[0]
        assert rows["float64_BE"] == str(expected)
        assert "float64:" in harness.float64_text()
