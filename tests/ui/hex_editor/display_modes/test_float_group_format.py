# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Gate for the float display modes of ``HexEditorWidget._format_group``.

``float32`` and ``float64`` render an IEEE-754 value from raw bytes, and each has
three outcomes: a finite number, ``NaN``, and a signed infinity. The gates feed
real ``struct.pack`` byte patterns through the real widget in each mode and read
the rendered text back, so a branch that stops returning its own text - or falls
through into the next display mode's handling and prints a hex byte instead -
fails an assertion. Padding is stripped before comparing: the width of the cell
is layout, the value it carries is what is gated here.
"""

from __future__ import annotations

import math
import struct
from typing import TYPE_CHECKING, Final

from intellicrack.ui.panels.hex_editor_widget import HexEditorWidget


if TYPE_CHECKING:
    from pytestqt.qtbot import QtBot


_FLOAT32_SIZE: Final[int] = 4
_FLOAT64_SIZE: Final[int] = 8
_FINITE_VALUE: Final[float] = 1.5
_NEGATIVE_FINITE_VALUE: Final[float] = -2.25
_FLOAT_REL_TOL: Final[float] = 1e-6


class _ExposedHexEditorWidget(HexEditorWidget):
    """``HexEditorWidget`` exposing its group formatter without private access."""

    def format_group(self, group_bytes: bytes, padded_size: int) -> str:
        """Forward to :meth:`HexEditorWidget._format_group`.

        Args:
            group_bytes: Bytes of the group to render.
            padded_size: Expected group size in bytes for the current mode.

        Returns:
            str: The text the widget renders for the group.
        """
        return self._format_group(group_bytes, padded_size)


def _widget_in_mode(qtbot: QtBot, mode: str) -> _ExposedHexEditorWidget:
    """Build a real hex editor widget set to one display mode.

    Args:
        qtbot: pytest-qt fixture owning the widget's lifetime.
        mode: Display mode name to select.

    Returns:
        _ExposedHexEditorWidget: Widget whose formatter is ready to call.
    """
    widget = _ExposedHexEditorWidget()
    qtbot.addWidget(widget)
    widget.set_display_mode(mode)
    return widget


class TestFloat32Display:
    """``float32`` mode renders finite values, NaN and both infinities."""

    def test_finite_values_render_their_decimal_value(self, qtbot: QtBot) -> None:
        """A finite float32 is printed as the number it encodes."""
        widget = _widget_in_mode(qtbot, "float32")

        for value in (_FINITE_VALUE, _NEGATIVE_FINITE_VALUE):
            text = widget.format_group(struct.pack("<f", value), _FLOAT32_SIZE).strip()

            assert math.isclose(float(text), value, rel_tol=_FLOAT_REL_TOL), f"float32 {value!r} rendered as {text!r}"

    def test_nan_renders_as_nan(self, qtbot: QtBot) -> None:
        """A float32 NaN payload is printed as ``NaN``."""
        widget = _widget_in_mode(qtbot, "float32")

        text = widget.format_group(struct.pack("<f", math.nan), _FLOAT32_SIZE).strip()

        assert text == "NaN", f"float32 NaN rendered as {text!r}"

    def test_infinities_render_with_their_sign(self, qtbot: QtBot) -> None:
        """Positive and negative float32 infinity are told apart."""
        widget = _widget_in_mode(qtbot, "float32")

        positive = widget.format_group(struct.pack("<f", math.inf), _FLOAT32_SIZE).strip()
        negative = widget.format_group(struct.pack("<f", -math.inf), _FLOAT32_SIZE).strip()

        assert positive == "Inf", f"float32 +infinity rendered as {positive!r}"
        assert negative == "-Inf", f"float32 -infinity rendered as {negative!r}"


class TestFloat64Display:
    """``float64`` mode renders finite values, NaN and both infinities."""

    def test_finite_values_render_their_decimal_value(self, qtbot: QtBot) -> None:
        """A finite float64 is printed as the number it encodes."""
        widget = _widget_in_mode(qtbot, "float64")

        for value in (_FINITE_VALUE, _NEGATIVE_FINITE_VALUE):
            text = widget.format_group(struct.pack("<d", value), _FLOAT64_SIZE).strip()

            assert math.isclose(float(text), value, rel_tol=_FLOAT_REL_TOL), f"float64 {value!r} rendered as {text!r}"

    def test_nan_renders_as_nan(self, qtbot: QtBot) -> None:
        """A float64 NaN payload is printed as ``NaN``."""
        widget = _widget_in_mode(qtbot, "float64")

        text = widget.format_group(struct.pack("<d", math.nan), _FLOAT64_SIZE).strip()

        assert text == "NaN", f"float64 NaN rendered as {text!r}"

    def test_infinities_render_with_their_sign(self, qtbot: QtBot) -> None:
        """Positive and negative float64 infinity are told apart."""
        widget = _widget_in_mode(qtbot, "float64")

        positive = widget.format_group(struct.pack("<d", math.inf), _FLOAT64_SIZE).strip()
        negative = widget.format_group(struct.pack("<d", -math.inf), _FLOAT64_SIZE).strip()

        assert positive == "Inf", f"float64 +infinity rendered as {positive!r}"
        assert negative == "-Inf", f"float64 -infinity rendered as {negative!r}"
