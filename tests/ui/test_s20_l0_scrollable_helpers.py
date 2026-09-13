# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for the shared S20-D14/D16 scroll-wrapper contract in ``base_panel``.

Every other S20 domain's panel leans on :func:`make_scrollable` and
:meth:`AnalysisPanelBase._wrap_content` to turn clipping into scrolling. The
guarantee those helpers must hold is that when wrapped content's real
minimum width exceeds the viewport, the wrapper grows a *horizontal*
scrollbar (not just a vertical one) instead of letting Qt silently shrink
the content's controls below their natural size. This test builds a real
wide control cluster, wraps it with the shared helper, squeezes the
viewport narrower than the content's minimum, and asserts the content kept
its full width and the horizontal scrollbar actually engaged.
"""

from __future__ import annotations

import pytest
from PyQt6.QtWidgets import QApplication, QHBoxLayout, QPushButton, QWidget

from intellicrack.ui.panels.base_panel import make_control_row, make_scrollable


_NARROW_VIEWPORT_WIDTH: int = 150
_VIEWPORT_HEIGHT: int = 200
_WIDE_BUTTON_COUNT: int = 12
_WIDE_BUTTON_LABEL: str = "A Reasonably Long Button Label"


def _build_wide_content() -> QWidget:
    """Build a plain widget whose natural minimum width is far above ``_NARROW_VIEWPORT_WIDTH``.

    Returns:
        QWidget: A widget hosting a row of wide, real ``QPushButton`` controls.
    """
    inner = QWidget()
    layout = QHBoxLayout(inner)
    for i in range(_WIDE_BUTTON_COUNT):
        layout.addWidget(QPushButton(f"{_WIDE_BUTTON_LABEL} {i}"))
    return inner


@pytest.mark.usefixtures("qapp")
def test_make_scrollable_grows_a_horizontal_scrollbar_when_content_is_wider_than_viewport(
    qapp: QApplication,
) -> None:
    """A viewport narrower than the wrapped content's minimum width must engage horizontal scrolling.

    Args:
        qapp: Shared QApplication fixture required for Qt widget construction.
    """
    _ = qapp
    content = _build_wide_content()
    assert content.minimumSizeHint().width() > _NARROW_VIEWPORT_WIDTH, "test premise: content is naturally wider than the narrow viewport"

    scroll = make_scrollable(content)
    try:
        scroll.show()
        scroll.resize(_NARROW_VIEWPORT_WIDTH, _VIEWPORT_HEIGHT)
        QApplication.processEvents()

        # Re-measured after the widget is shown and polished: a style's font
        # metrics can settle to a slightly different value than an unpolished,
        # never-shown widget reports, so the real guarantee under test is that
        # the content's rendered width tracks ITS OWN current minimum, not a
        # value captured before the widget ever had a chance to lay out.
        current_min_width = content.minimumSizeHint().width()
        assert content.width() >= current_min_width, (
            f"content was squeezed to {content.width()}px, narrower than its own minimum {current_min_width}px "
            "-- make_scrollable must not let the viewport shrink content below its natural size"
        )
        h_bar = scroll.horizontalScrollBar()
        assert h_bar is not None
        assert h_bar.maximum() > 0, "expected a horizontal scrollbar range once content exceeds the viewport width"
    finally:
        scroll.deleteLater()


@pytest.mark.usefixtures("qapp")
def test_make_control_row_keeps_full_button_labels_instead_of_eliding_them(
    qapp: QApplication,
) -> None:
    """A dense control row wrapped by ``make_control_row`` must keep buttons at their natural width.

    Before this contract, a plain ``QHBoxLayout`` let Qt shrink every control
    below its natural width in a narrow panel, eliding button captions down
    to unreadable fragments.

    Args:
        qapp: Shared QApplication fixture required for Qt widget construction.
    """
    _ = qapp
    row = QHBoxLayout()
    buttons = [QPushButton(f"{_WIDE_BUTTON_LABEL} {i}") for i in range(_WIDE_BUTTON_COUNT)]
    for button in buttons:
        row.addWidget(button)

    scroll = make_control_row(row)
    try:
        scroll.show()
        scroll.resize(_NARROW_VIEWPORT_WIDTH, scroll.height())
        QApplication.processEvents()

        for button in buttons:
            assert button.width() >= button.sizeHint().width(), (
                f"button {button.text()!r} was squeezed to {button.width()}px below its natural "
                f"{button.sizeHint().width()}px width in a narrow control row"
            )
    finally:
        scroll.deleteLater()
