# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for GUI audit finding D04 (bit-editor button labels).

Prior to the fix, ``DataInspectorMixin._create_bit_editor_group`` sized
each of the 8 bit-toggle buttons with ``setFixedWidth(28)``. The
application-wide stylesheet (:mod:`intellicrack.ui.resources.theme_manager`)
styles every ``QPushButton`` with ``padding: 6px 16px`` -- 32px of
horizontal padding alone -- so the 28px button left a negative content
area and Qt clipped the ``"0"``/``"1"`` label entirely, rendering blank
buttons.

The fix (``DataInspectorMixin._compute_bit_button_width``) probes the
application's live ``QStyle`` with throwaway buttons -- covering every
label the bit editor can show, in both the unchecked and checked states
-- and takes the widest reported ``sizeHint``, floored at 40px, so the
label always has positive room to render regardless of font, DPI, or
independent stylesheet changes (such as the checked-state border added
separately for this same finding). This test drives the real
:class:`DataInspectorMixin` bit-editor group under the real application
stylesheet and a real ``intellicrack_hexcore`` document, toggles a bit
through the same click path a user would use, and asserts both that the
button's label matches the document's authoritative bit value and that
the label physically fits inside the button's style-computed content
rect. Reverting the fix (widths back to 28px) makes the fit assertion
fail because the stylesheet's padding alone exceeds 28px.
"""

from __future__ import annotations

import os


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt6.QtWidgets import (
    QApplication,
    QGroupBox,
    QPushButton,
    QStyle,
    QStyleOptionButton,
    QWidget,
)

from intellicrack.ui.panels.hex_editor.data_inspector import DataInspectorMixin
from intellicrack.ui.resources.theme_manager import THEME_DARK, ThemeManager


hexcore = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)

pytestmark = pytest.mark.integration


class _BitEditorHarness(DataInspectorMixin, QWidget):
    """Minimal widget exposing :class:`DataInspectorMixin` for the D04 gate.

    Wires only the instance attributes the bit-editor code path reads:
    a real hexcore document, no bridge (so writes take the synchronous
    ``document.set_bit`` fallback), and no state holder or hex widget.
    """

    def __init__(self, document: object) -> None:
        """Initialise the harness with a real hexcore document attached.

        Args:
            document: A real ``intellicrack_hexcore.HexDocument`` instance.
        """
        super().__init__()
        self.document = document
        self._document = document
        self.state_holder = None
        self._bridge = None
        self._hex_widget = None
        self._bit_editor_offset = 0
        self._bit_buttons: list[QPushButton] = []


def _bit_button_content_width(btn: QPushButton) -> int:
    """Return the style-computed interior width available for the button's label.

    Uses ``QStyle.subElementRect(SE_PushButtonContents, ...)`` rather than
    :meth:`QWidget.contentsRect`, because the latter always reports the
    full widget rect and never reflects the stylesheet's ``padding``.
    ``subElementRect`` is the same query Qt itself uses to lay out and
    clip the button's label, so it is the correct oracle for "does the
    label actually fit".

    Args:
        btn: The bit-toggle button to measure.

    Returns:
        int: Width in pixels available for the label after the active
        stylesheet's padding is subtracted. Negative when the padding
        alone exceeds the button's fixed width.
    """
    opt = QStyleOptionButton()
    btn.initStyleOption(opt)
    style = btn.style()
    assert style is not None, "a constructed QPushButton must always have a style"
    return style.subElementRect(QStyle.SubElement.SE_PushButtonContents, opt, btn).width()


@pytest.fixture(scope="module", autouse=True)
def _apply_production_dark_theme() -> None:
    """Apply the real production dark-theme stylesheet for this module's tests.

    D04 is a collision between the bit-button width and the application's
    real ``QPushButton { padding: 6px 16px; }`` rule, so the gate must run
    under that real stylesheet rather than an unstyled default ``QStyle``.
    ``THEME_DARK`` is also the application's own default theme, so no
    teardown restoration is needed.
    """
    ThemeManager.get_instance().apply_theme(THEME_DARK)


def test_bit_toggle_label_matches_document_and_fits_button(qapp: QApplication) -> None:
    """A toggled bit button must show the document's bit value, fully visible.

    Toggles bit 3 of a single zero byte on through the real click path
    (:meth:`DataInspectorMixin._on_bit_toggled`, the same handler wired to
    ``QPushButton.clicked`` in ``_create_bit_editor_group``), then asserts:

    * The button's text equals ``"1"`` -- the authoritative bit value read
      back from the real hexcore document via ``get_bit``, not a locally
      recomputed value.
    * ``fontMetrics().horizontalAdvance(text) <= `` the button's
      style-computed content width, i.e. the label has positive room to
      render instead of being clipped to nothing.

    Args:
        qapp: The shared offscreen ``QApplication`` fixture.
    """
    document = hexcore.HexDocument.open_bytes(bytes([0x00]))
    harness = _BitEditorHarness(document)
    group: QGroupBox = harness._create_bit_editor_group()
    assert group is not None

    buttons = harness._bit_buttons
    assert len(buttons) == 8, f"bit editor must expose exactly 8 toggle buttons; got {len(buttons)}"

    bit_index = 3
    btn_idx = 7 - bit_index
    btn = buttons[btn_idx]

    btn.click()
    qapp.processEvents()

    expected_bit = bool(document.get_bit(0, bit_index))
    assert expected_bit is True, "toggling an initially-clear bit via click() must set it"
    expected_text = "1" if expected_bit else "0"
    assert btn.text() == expected_text, f"button text must mirror the document's authoritative bit value; got {btn.text()!r}, expected {expected_text!r}"

    content_width = _bit_button_content_width(btn)
    label_width = btn.fontMetrics().horizontalAdvance(btn.text())
    assert label_width <= content_width, (
        f"label {btn.text()!r} (width {label_width}px) must fit inside the button's "
        f"style-computed content rect (width {content_width}px) under the real "
        f"application stylesheet -- a button too narrow for its own padding renders "
        f"a blank label"
    )


def test_all_bit_buttons_labels_fit_after_sync(qapp: QApplication) -> None:
    """Every one of the 8 bit buttons must show a visible label after a resync.

    Uses a non-trivial byte (``0b10110101``) so both ``"0"`` and ``"1"``
    labels are exercised across the row, then asserts every button's label
    fits its style-computed content rect.

    Args:
        qapp: The shared offscreen ``QApplication`` fixture.
    """
    document = hexcore.HexDocument.open_bytes(bytes([0b10110101]))
    harness = _BitEditorHarness(document)
    group: QGroupBox = harness._create_bit_editor_group()
    assert group is not None
    qapp.processEvents()

    harness._update_bit_buttons(0)

    for i, btn in enumerate(harness._bit_buttons):
        bit_idx = 7 - i
        expected_bit = bool((0b10110101 >> bit_idx) & 1)
        expected_text = "1" if expected_bit else "0"
        assert btn.text() == expected_text, f"bit {bit_idx}: expected label {expected_text!r}, got {btn.text()!r}"

        content_width = _bit_button_content_width(btn)
        label_width = btn.fontMetrics().horizontalAdvance(btn.text())
        assert label_width <= content_width, (
            f"bit {bit_idx} label {btn.text()!r} (width {label_width}px) must fit inside "
            f"the button's content rect (width {content_width}px); got a non-positive or "
            f"too-narrow content rect, indicating the button is too narrow for the "
            f"stylesheet's own padding"
        )
