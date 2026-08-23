# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for defect A4/S12-D10.

The light-theme toggle used to restyle window chrome (menu bar, toolbar) but
left content viewports -- the disassembly table, the chat scroll area, and
the chat message bubbles' markdown text browsers -- rendering with the
background they were first polished with, because none of them subscribe to
``ThemeManager.theme_changed`` and instead depend entirely on the global
stylesheet restyling an already-polished widget.

A direct pixel or ``QPalette`` comparison cannot distinguish a fixed build
from a broken one under Qt's offscreen platform plugin (used by this test
suite's sandbox): under that platform, re-querying a widget's resolved
palette or rendering it to an image both already reflect the live
application stylesheet regardless of whether the widget was ever
unpolished/repolished, so such an assertion stays green even with the fix
reverted. This module instead asserts the fix's actual mechanism -- that
``ThemeManager._repolish_chrome`` calls ``style().unpolish()`` then
``style().polish()`` on the live content-viewport widgets during a runtime
toggle -- via a duck-typed recording stand-in installed as
``QApplication.style()``, mirroring the approach already established in
``tests/ui/test_theme_manager.py`` for the menu bar/toolbar regression.
"""

from __future__ import annotations

import pytest
from PyQt6.QtWidgets import (
    QApplication,
    QFrame,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.types import Message
from intellicrack.ui.chat import ChatPanel
from intellicrack.ui.resources.theme_manager import THEME_DARK, THEME_LIGHT, ThemeManager


@pytest.fixture
def theme_manager() -> ThemeManager:
    """Provide a fresh ThemeManager instance for each test.

    Returns:
        ThemeManager: A fresh singleton instance.
    """
    ThemeManager.reset_instance()
    return ThemeManager.get_instance()


class _RecordingStyleStandIn:
    """Duck-typed stand-in for ``QApplication.style()`` that records ``polish``/``unpolish`` calls.

    ``QStyle.polish``/``unpolish`` are C++ virtuals with inconsistently-named
    PyQt6-stub overloads that a real ``QStyle`` subclass cannot satisfy for
    all of them at once, so this stand-in avoids subclassing ``QStyle``
    entirely: ``ThemeManager._repolish_chrome`` only ever calls
    ``style().unpolish(widget)`` and ``style().polish(widget)`` via plain
    duck typing on whatever ``QApplication.style()`` returns, so a plain,
    precisely-typed Python object serves exactly as well as a real
    ``QStyle`` for observing those two calls. It is installed only by
    reassigning the ``style`` attribute on the live ``QApplication``
    instance for the narrow, fully synchronous duration of a single
    ``ThemeManager.apply_theme`` call, then immediately restored.
    """

    def __init__(self) -> None:
        """Initialize the stand-in with empty call-history lists."""
        self.polished: list[QWidget] = []
        self.unpolished: list[QWidget] = []

    def polish(self, widget: QWidget) -> None:
        """Record a ``polish(widget)`` call.

        Args:
            widget: The widget being polished.
        """
        self.polished.append(widget)

    def unpolish(self, widget: QWidget) -> None:
        """Record an ``unpolish(widget)`` call.

        Args:
            widget: The widget being unpolished.
        """
        self.unpolished.append(widget)


def _build_disassembly_style_table() -> QTableWidget:
    """Build a real ``QTableWidget`` shaped like the disassembly view's table.

    Mirrors ``DisassemblyMixin``'s construction of ``_disasm_table`` in
    ``intellicrack.ui.panels.hex_editor.disassembly``: four address/bytes/
    mnemonic/operands columns, alternating row colors, and no per-item
    colors set on any cell, so its rendering depends entirely on the global
    stylesheet restyling an already-polished ``QAbstractItemView`` viewport.

    Returns:
        QTableWidget: A populated, disassembly-shaped table.
    """
    table = QTableWidget(0, 4)
    table.setHorizontalHeaderLabels(["Address", "Hex Bytes", "Mnemonic", "Operands"])
    table.setAlternatingRowColors(True)
    row = table.rowCount()
    table.insertRow(row)
    table.setItem(row, 0, QTableWidgetItem("0x00401000"))
    table.setItem(row, 1, QTableWidgetItem("55 8B EC"))
    table.setItem(row, 2, QTableWidgetItem("push"))
    table.setItem(row, 3, QTableWidgetItem("ebp"))
    return table


class TestContentViewportRuntimeRepolish:
    """Regression gate: a live theme toggle must repolish content viewports.

    Reproduces defect A4/S12-D10, where Settings -> Toggle Theme left the
    disassembly table, the chat scroll area, and chat message bubbles'
    markdown text browsers rendering the previous theme's colors after a
    runtime dark -> light toggle.
    """

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_runtime_toggle_repolishes_disassembly_table_and_chat_viewports(
        theme_manager: ThemeManager,
    ) -> None:
        """A runtime dark->light toggle unpolishes and repolishes content viewports.

        Builds a real disassembly-shaped ``QTableWidget`` and a real
        ``ChatPanel`` (with one message added, so a genuine message-bubble
        ``QFrame`` and its ``QTextBrowser`` exist), applies the dark theme
        to establish an initial polish, then toggles to the light theme
        while a recording stand-in is installed as ``QApplication.style()``.

        Falsifiable: reverting ``ThemeManager._repolish_chrome`` to only
        handle ``QMenuBar``/``QToolBar`` (i.e. dropping the
        ``QAbstractScrollArea`` and role-propertied ``QFrame`` handling,
        along with the per-widget ``viewport()`` repolish) leaves every
        assertion below failing: none of the content-viewport widgets, nor
        their viewports, ever appear in ``stand_in.unpolished`` /
        ``stand_in.polished``, because the stand-in style is never consulted
        for them at all without that code path (confirmed by reverting it
        locally and rerunning this test).

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        app = QApplication.instance()
        assert isinstance(app, QApplication)

        table = _build_disassembly_style_table()
        chat_panel = ChatPanel()
        chat_panel.add_message(Message(role="user", content="Hello from the light-theme regression test."))

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.addWidget(table)
        layout.addWidget(chat_panel)
        container.resize(500, 500)
        container.show()
        QApplication.processEvents()

        try:
            assert theme_manager.apply_theme(THEME_DARK)
            QApplication.processEvents()

            scroll_area = chat_panel.findChild(QScrollArea, "chat_scroll_area")
            assert scroll_area is not None, "ChatPanel did not expose its #chat_scroll_area QScrollArea"

            text_browsers = chat_panel.findChildren(QTextBrowser)
            assert text_browsers, "expected the chat message bubble to contain a QTextBrowser"

            role_frames = [frame for frame in chat_panel.findChildren(QFrame) if frame.property("role") is not None]
            assert role_frames, "expected the chat message bubble to carry a 'role' dynamic property"

            table_viewport = table.viewport()
            scroll_viewport = scroll_area.viewport()
            browser_viewport = text_browsers[0].viewport()
            assert table_viewport is not None
            assert scroll_viewport is not None
            assert browser_viewport is not None

            stand_in = _RecordingStyleStandIn()
            original_style_method = app.style
            setattr(app, "style", lambda: stand_in)
            try:
                assert theme_manager.apply_theme(THEME_LIGHT)
            finally:
                setattr(app, "style", original_style_method)
            QApplication.processEvents()

            checks: list[tuple[QWidget, str]] = [
                (table, "disassembly table"),
                (table_viewport, "disassembly table viewport"),
                (scroll_area, "chat scroll area"),
                (scroll_viewport, "chat scroll area viewport"),
                (text_browsers[0], "chat message QTextBrowser"),
                (browser_viewport, "chat message QTextBrowser viewport"),
                (role_frames[0], "chat message bubble (role-propertied QFrame)"),
            ]
            for widget, label in checks:
                assert widget in stand_in.unpolished, f"{label} was not unpolished during the runtime theme toggle"
                assert widget in stand_in.polished, f"{label} was not repolished during the runtime theme toggle"
        finally:
            container.close()
            theme_manager.apply_theme(THEME_DARK)
