# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Rendered-pixel gates for the ``SandboxConfigDialog`` availability status frame.

The status frame is styled purely by the ``toolResult`` dynamic property, so
the only honest check is to apply a real theme, drive the dialog into each
state and read pixels back from the painted frame:

* the neutral state (probe still running) must paint the base fill, a 1px
  border on every edge and rounded corners;
* the available and unavailable states must paint that same fill, the same
  1px border on the top edge and rounded corners, plus a 3px left bar in the
  theme's success or error colour.

Each assertion fails against a stylesheet in which the success/error rules
carry only ``border-left`` (the frame then renders as a bare left bar on the
unstyled dialog background).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, NamedTuple

import pytest
from PyQt6.QtWidgets import QApplication, QFrame

from intellicrack.ui.resources.theme_manager import ThemeManager
from intellicrack.ui.sandbox_config import SandboxConfigDialog


if TYPE_CHECKING:
    from PyQt6.QtGui import QImage
    from pytestqt.qtbot import QtBot


class _StatusFramePalette(NamedTuple):
    """Colours the theme promises for the status frame.

    Attributes:
        fill: Interior background of the frame.
        border: 1px border colour on the top, right and bottom edges.
        success: Left bar colour for the available state.
        error: Left bar colour for the unavailable state.
    """

    fill: str
    border: str
    success: str
    error: str


_THEME_PALETTES: Final[dict[str, _StatusFramePalette]] = {
    "dark": _StatusFramePalette(fill="#252526", border="#3e3e42", success="#4caf50", error="#f44336"),
    "light": _StatusFramePalette(fill="#f7f8fa", border="#c2c8d0", success="#2e7d32", error="#c62828"),
    "dark2": _StatusFramePalette(fill="#1b1e24", border="#30353d", success="#3fb950", error="#f85149"),
    "light2": _StatusFramePalette(fill="#f6f8fb", border="#d0d5dd", success="#2c8a37", error="#cf2b2b"),
}

_STATES: Final[tuple[str, ...]] = ("neutral", "success", "error")


def _skip_availability_probe(self: SandboxConfigDialog) -> None:
    """Replace the dialog's availability probe so the test controls the state.

    Args:
        self: Dialog whose probe would otherwise start a PowerShell worker.
    """
    del self


def _render_status_frame(
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
    theme: str,
    state: str,
) -> QImage:
    """Build the dialog under a real theme, drive it into a state and paint the frame.

    Args:
        qtbot: pytest-qt bot used to own and pump the dialog.
        monkeypatch: Fixture used to disable the live availability probe.
        theme: Theme name passed to ``ThemeManager.apply_theme``.
        state: ``"neutral"`` leaves the dialog as constructed, ``"success"``
            calls ``_set_available`` and ``"error"`` calls ``_set_unavailable``.

    Returns:
        QImage: The status frame as painted by Qt.
    """
    monkeypatch.setattr(SandboxConfigDialog, "_start_availability_check", _skip_availability_probe)
    assert ThemeManager.get_instance().apply_theme(theme)
    dialog = SandboxConfigDialog()
    qtbot.addWidget(dialog)
    if state == "success":
        dialog._set_available()
    elif state == "error":
        dialog._set_unavailable("probe reported a failure")
    dialog.show()
    qtbot.waitExposed(dialog)
    QApplication.processEvents()
    frame: QFrame = dialog._status_frame
    return frame.grab().toImage()


def _hex_at(image: QImage, x: int, y: int) -> str:
    """Return the colour of one pixel as a lowercase ``#rrggbb`` string.

    Args:
        image: Painted image to sample.
        x: Pixel column.
        y: Pixel row.

    Returns:
        str: Lowercase ``#rrggbb`` colour of the pixel.
    """
    return image.pixelColor(x, y).name().lower()


@pytest.mark.parametrize("theme", sorted(_THEME_PALETTES))
@pytest.mark.parametrize("state", _STATES)
def test_status_frame_paints_fill_border_and_state_bar(
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
    theme: str,
    state: str,
) -> None:
    """The frame paints its fill, its border and, once resolved, the coloured left bar.

    Args:
        qtbot: pytest-qt bot used to own and pump the dialog.
        monkeypatch: Fixture used to disable the live availability probe.
        theme: Theme under test.
        state: Dialog state under test.
    """
    palette = _THEME_PALETTES[theme]
    image = _render_status_frame(qtbot, monkeypatch, theme, state)
    width, height = image.width(), image.height()
    mid = height // 2

    assert _hex_at(image, width - 6, mid) == palette.fill, "interior must carry the base fill"
    assert _hex_at(image, width // 2, 0) == palette.border, "top edge must carry the 1px base border"
    assert _hex_at(image, width // 2, height - 1) == palette.border, "bottom edge must carry the 1px base border"
    assert _hex_at(image, width - 1, mid) == palette.border, "right edge must carry the 1px base border"

    expected_left = {"neutral": palette.border, "success": palette.success, "error": palette.error}[state]
    assert _hex_at(image, 0, mid) == expected_left

    if state == "neutral":
        assert _hex_at(image, 1, mid) == palette.fill, "neutral border is 1px wide, so x=1 is interior"
    else:
        assert _hex_at(image, 1, mid) == expected_left, "state bar is 3px wide"
        assert _hex_at(image, 2, mid) == expected_left, "state bar is 3px wide"
        assert _hex_at(image, 3, mid) == palette.fill, "bar must end after 3px"

    corner = _hex_at(image, 0, 0)
    assert corner not in {palette.border, palette.success, palette.error}, "4px radius must round the corner"


def test_status_frame_property_tracks_dialog_state(qtbot: QtBot, monkeypatch: pytest.MonkeyPatch) -> None:
    """The ``toolResult`` property is neutral at construction and follows each state change.

    Args:
        qtbot: pytest-qt bot used to own the dialog.
        monkeypatch: Fixture used to disable the live availability probe.
    """
    monkeypatch.setattr(SandboxConfigDialog, "_start_availability_check", _skip_availability_probe)
    dialog = SandboxConfigDialog()
    qtbot.addWidget(dialog)

    assert dialog._status_frame.property("toolResult") == "true"
    dialog._set_available()
    assert dialog._status_frame.property("toolResult") == "success"
    dialog._set_unavailable("probe reported a failure")
    assert dialog._status_frame.property("toolResult") == "error"
    dialog._set_available()
    assert dialog._status_frame.property("toolResult") == "success"


@pytest.mark.parametrize("theme", sorted(_THEME_PALETTES))
def test_status_frame_changes_appearance_between_states(
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
    theme: str,
) -> None:
    """Repolishing on a state change actually repaints the frame's left bar.

    Args:
        qtbot: pytest-qt bot used to own and pump the dialog.
        monkeypatch: Fixture used to disable the live availability probe.
        theme: Theme under test.
    """
    monkeypatch.setattr(SandboxConfigDialog, "_start_availability_check", _skip_availability_probe)
    palette = _THEME_PALETTES[theme]
    assert ThemeManager.get_instance().apply_theme(theme)
    dialog = SandboxConfigDialog()
    qtbot.addWidget(dialog)
    dialog.show()
    qtbot.waitExposed(dialog)

    def left_bar() -> str:
        QApplication.processEvents()
        image = dialog._status_frame.grab().toImage()
        return _hex_at(image, 0, image.height() // 2)

    assert left_bar() == palette.border
    dialog._set_available()
    assert left_bar() == palette.success
    dialog._set_unavailable("probe reported a failure")
    assert left_bar() == palette.error
