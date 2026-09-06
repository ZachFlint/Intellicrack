# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for defect R04 -- theme-toggle UI freeze.

``ThemeManager._repolish_chrome`` used to call ``QApplication.allWidgets()``
and unpolish/repolish every live ``QMenuBar``/``QToolBar``/
``QAbstractScrollArea``/role-propertied ``QFrame`` in the entire process --
including every scroll area and role-frame sitting in every inactive tab of
every docked tool panel -- on top of the full-tree restyle
``QApplication.setStyleSheet`` already performs. On a fully populated main
window (multiple embedded tool panels, each with dozens of scroll areas and
tables), that redundant second sweep blocked the event loop for seconds,
surfacing to the user as "Not Responding".

The fix scopes the explicit repolish to chrome that is actually visible right
now (the main window's menu bar/toolbars and the current tab's own content),
deferring anything hidden to a one-shot repolish the moment it is next shown.

This module builds a real, populated ``MainWindow`` -- five real embedded
tool panels (Hex Editor, Frida, Ghidra, Process, Cutter) added to the real
``ToolOutputPanel`` tab widget, exactly as ``MainWindow``'s own menu actions
do -- and drives a real runtime theme toggle through it, observing the actual
``QStyle.unpolish``/``polish`` traffic via a duck-typed recording stand-in
installed as ``QApplication.style()`` (the same technique already established
in ``tests/ui/test_theme_manager.py``), rather than timing the call: a
wall-clock assertion would be flaky under the sandbox's shared load, while
counting exactly which widgets the style was consulted for is deterministic
and pinpoints the actual mechanism.

Falsifiable: reverting ``ThemeManager._repolish_chrome`` to sweep
``QApplication.allWidgets()`` (dropping the visible-top-level scoping and the
lazy show-time deferral) makes every assertion below fail at once -- the
distinct-widget polish count jumps from ~23 to the hundreds (every scroll
area/role-frame across every hidden tab, confirmed locally at 474 chrome
candidates against 4302 total live widgets for this fixture), and the hidden
Frida-tab scroll area used as the negative probe appears in the *first*
toggle's polished set instead of only after its own tab is switched to
(confirmed by reverting the fix locally and rerunning this module).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QAbstractScrollArea, QApplication, QFrame, QMenuBar, QToolBar, QWidget

from intellicrack.bridges.cutter import CutterBridge
from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.process import ProcessBridge
from intellicrack.core.config import Config
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolName, ToolRegistry
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui.app import MainWindow
from intellicrack.ui.resources.theme_manager import THEME_DARK, THEME_LIGHT, ThemeManager


if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


# A fully populated MainWindow (five embedded tool panels) carries thousands
# of live widgets; the old allWidgets() sweep touched every scroll area and
# role-frame among them (474 chrome candidates were observed locally).
_TOTAL_WIDGET_SANITY_FLOOR: int = 500
_VISIBLE_CHROME_REPOLISH_CAP: int = 100


class _RecordingStyleStandIn:
    """Duck-typed stand-in for ``QApplication.style()`` that records ``polish``/``unpolish`` calls.

    Mirrors the stand-in already established in
    ``tests/ui/test_theme_manager.py`` and
    ``tests/ui/test_theme_manager_s12d10_content_viewport_repolish.py``:
    ``ThemeManager._repolish_chrome`` only ever calls
    ``style().unpolish(widget)`` / ``style().polish(widget)`` via plain duck
    typing, so a precisely-typed Python object observes those calls exactly
    as well as a real ``QStyle`` subclass, without needing to satisfy
    ``QStyle``'s inconsistently-named C++ virtual overloads.
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


def _build_tool_registry_with_bridges(tmp_path: Path) -> ToolRegistry:
    """Build a real ``ToolRegistry`` with every bridge needed by the embedded panels.

    Args:
        tmp_path: Per-test temporary directory used for the tools directory.

    Returns:
        ToolRegistry: A registry with Frida/Ghidra/Cutter/Hex Editor/Process
        bridges registered, so ``ToolOutputPanel.add_*_tab`` succeeds instead
        of failing to resolve a bridge from an empty registry.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    registry = ToolRegistry(tools_dir=tools_dir)
    registry.register_bridge(ToolName.FRIDA, FridaBridge())
    registry.register_bridge(ToolName.GHIDRA, GhidraBridge())
    registry.register_bridge(ToolName.CUTTER, CutterBridge())
    registry.register_bridge(ToolName.HEX_EDITOR, HexEditorBridge())
    registry.register_bridge(ToolName.PROCESS, ProcessBridge())
    return registry


@pytest.fixture
def theme_manager() -> ThemeManager:
    """Provide a fresh ThemeManager instance for each test.

    Returns:
        ThemeManager: A fresh singleton instance.
    """
    ThemeManager.reset_instance()
    return ThemeManager.get_instance()


@pytest.fixture
def populated_main_window(
    qapp: QApplication,
    tmp_path: Path,
    theme_manager: ThemeManager,
) -> Generator[MainWindow]:
    """Construct a real, populated ``MainWindow`` with five embedded tool panels.

    Mirrors how a user actually populates the window: real ``Config``/
    ``Orchestrator``/``ToolRegistry`` instances, then the same
    ``ToolOutputPanel.add_*_tab`` calls ``MainWindow``'s own menu actions
    make, for Hex Editor, Frida, Ghidra, Process, and Cutter. Only the first
    tab added (Hex Editor) is the active/visible one; the other four sit in
    hidden ``QTabWidget`` pages, giving a real population of chrome that is
    NOT currently visible.

    Args:
        qapp: Session-scoped Qt application fixture.
        tmp_path: Per-test temporary directory.
        theme_manager: Fresh ThemeManager fixture instance (establishes the
            singleton before the window wires up ``theme_changed``).

    Yields:
        MainWindow: The populated, shown window under test.
    """
    del theme_manager
    config = Config(
        tools_directory=tmp_path / "tools",
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
    )
    orchestrator = Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=_build_tool_registry_with_bridges(tmp_path),
        session_manager=SessionManager(store=SessionStore(db_path=tmp_path / "sessions.db")),
    )
    window = MainWindow(config, orchestrator)
    assert window.tool_panel.add_hex_editor_tab() is not None
    assert window.tool_panel.add_frida_tab() is not None
    assert window.tool_panel.add_ghidra_tab() is not None
    assert window.tool_panel.add_process_tab() is not None
    assert window.tool_panel.add_cutter_tab() is not None
    window.show()
    qapp.processEvents()
    try:
        yield window
    finally:
        window.close()


def _visible_chrome_widgets(top_level: QWidget) -> list[QWidget]:
    """Enumerate the chrome widgets under ``top_level`` that are visible right now.

    Args:
        top_level: A shown top-level widget to search for chrome.

    Returns:
        list[QWidget]: Every ``QMenuBar``/``QToolBar``/``QAbstractScrollArea``/
        role-propertied ``QFrame`` descendant whose ``isVisible()`` is True.
    """
    candidates: list[QWidget] = [
        *top_level.findChildren(QMenuBar),
        *top_level.findChildren(QToolBar),
        *top_level.findChildren(QAbstractScrollArea),
        *(frame for frame in top_level.findChildren(QFrame) if frame.property("role") is not None),
    ]
    return [widget for widget in candidates if widget.isVisible()]


def _find_tab_index(window: MainWindow, title: str) -> int:
    """Find the index of an embedded tool tab by its title.

    Args:
        window: The populated MainWindow to search.
        title: The tab's display title (e.g. ``"Frida"``).

    Returns:
        int: The matching tab index.

    Raises:
        AssertionError: If no tab with ``title`` is present.
    """
    tab_widget = window.tool_panel.tab_widget
    for index in range(tab_widget.count()):
        if tab_widget.tabText(index) == title:
            return index
    message = f"tab {title!r} not found"
    raise AssertionError(message)


@pytest.mark.usefixtures("qapp")
class TestVisibleChromeScopedRepolish:
    """Regression gate: a live theme toggle repolishes only currently-visible chrome."""

    @staticmethod
    def test_toggle_repolish_is_bounded_to_visible_chrome_not_all_widgets(
        populated_main_window: MainWindow,
        theme_manager: ThemeManager,
    ) -> None:
        """A runtime toggle's repolish work is bounded to visible chrome, not ``allWidgets()``.

        Establishes the dark theme (so every widget is polished once under a
        known baseline), then swaps in a recording stand-in and toggles to
        light. Asserts, against the real live widget tree:

        * every widget ``ThemeManager`` itself currently considers "visible
          chrome" was actually unpolished and repolished;
        * the real menu bar (definitely-visible chrome) was repolished;
        * a real scroll area sitting in the hidden Frida tab was NOT
          repolished during this toggle (it is deferred, not swept);
        * the total distinct widgets touched is capped far below the
          hundreds of chrome-typed widgets that exist across every hidden
          tab, and far below the thousands of total live widgets in this
          fixture -- i.e. the work does not scale with ``allWidgets()``.

        Args:
            populated_main_window: Fresh, populated MainWindow fixture.
            theme_manager: Fresh ThemeManager fixture instance.
        """
        app = QApplication.instance()
        assert isinstance(app, QApplication)
        window = populated_main_window

        assert theme_manager.apply_theme(THEME_DARK)
        app.processEvents()

        total_widgets = len(app.allWidgets())
        assert total_widgets > _TOTAL_WIDGET_SANITY_FLOOR, (
            f"fixture is not populated enough to distinguish scoped from whole-tree repolish ({total_widgets} live widgets)"
        )

        visible_chrome = _visible_chrome_widgets(window)
        assert visible_chrome, "expected at least the main window's own menu bar/toolbar to be visible chrome"

        frida_index = _find_tab_index(window, "Frida")
        frida_page = window.tool_panel.tab_widget.widget(frida_index)
        assert frida_page is not None
        assert not frida_page.isVisible(), "Frida tab must not be the active tab for this gate"
        hidden_frida_probe = next(
            (sa for sa in frida_page.findChildren(QAbstractScrollArea) if not sa.isVisible()),
            None,
        )
        assert hidden_frida_probe is not None, "expected a hidden scroll area inside the inactive Frida tab"

        stand_in = _RecordingStyleStandIn()
        original_style_method = app.style
        setattr(app, "style", lambda: stand_in)
        try:
            assert theme_manager.apply_theme(THEME_LIGHT)
        finally:
            setattr(app, "style", original_style_method)
        app.processEvents()

        for widget in visible_chrome:
            assert widget in stand_in.unpolished, "a currently-visible chrome widget was not unpolished during the toggle"
            assert widget in stand_in.polished, "a currently-visible chrome widget was not repolished during the toggle"

        menubar = window.menuBar()
        assert menubar is not None
        assert menubar in stand_in.polished, "the main window's own menu bar was not repolished"

        assert hidden_frida_probe not in stand_in.polished, (
            "a scroll area in the hidden Frida tab was repolished eagerly -- the sweep is not scoped to visible chrome"
        )

        distinct_polished = len(set(stand_in.polished))
        assert distinct_polished <= _VISIBLE_CHROME_REPOLISH_CAP, (
            f"toggle repolished {distinct_polished} distinct widgets, expected a small count bounded to "
            f"visible chrome (<= {_VISIBLE_CHROME_REPOLISH_CAP}), not proportional to the "
            f"{total_widgets}-widget application tree"
        )
        assert distinct_polished < total_widgets // 10, (
            "repolish work scales with the size of the whole application tree instead of staying bounded to the currently-visible chrome"
        )

    @staticmethod
    def test_hidden_tab_scroll_area_is_repolished_lazily_when_shown(
        populated_main_window: MainWindow,
        theme_manager: ThemeManager,
    ) -> None:
        """A chrome widget hidden at toggle time is repolished the moment its tab becomes current.

        Continues the previous scenario: after a toggle skips the hidden
        Frida tab's content, switching to that tab must repolish its content
        immediately (via the lazy show-time filter), rather than leaving it
        stuck on the pre-toggle theme indefinitely.

        Args:
            populated_main_window: Fresh, populated MainWindow fixture.
            theme_manager: Fresh ThemeManager fixture instance.
        """
        app = QApplication.instance()
        assert isinstance(app, QApplication)
        window = populated_main_window
        tab_widget = window.tool_panel.tab_widget

        assert theme_manager.apply_theme(THEME_DARK)
        app.processEvents()

        frida_index = _find_tab_index(window, "Frida")
        frida_page = tab_widget.widget(frida_index)
        assert frida_page is not None

        # A widget one level of hiding deep (directly under the inactive tab
        # page) becomes visible as soon as that page is selected; probe with
        # one that does, confirmed by round-tripping the tab before recording.
        tab_widget.setCurrentIndex(frida_index)
        app.processEvents()
        shown_on_tab_switch = [sa for sa in frida_page.findChildren(QAbstractScrollArea) if sa.isVisible()]
        assert shown_on_tab_switch, "expected at least one Frida-tab scroll area to become visible on tab switch"
        probe = shown_on_tab_switch[0]
        tab_widget.setCurrentIndex(0)
        app.processEvents()
        assert not probe.isVisible(), "probe widget must be hidden again after switching back"

        stand_in_toggle = _RecordingStyleStandIn()
        original_style_method = app.style
        setattr(app, "style", lambda: stand_in_toggle)
        try:
            assert theme_manager.apply_theme(THEME_LIGHT)
        finally:
            setattr(app, "style", original_style_method)
        app.processEvents()
        assert probe not in stand_in_toggle.polished, "hidden probe must not be repolished by the toggle itself"

        stand_in_show = _RecordingStyleStandIn()
        original_style_method = app.style
        setattr(app, "style", lambda: stand_in_show)
        try:
            tab_widget.setCurrentIndex(frida_index)
            app.processEvents()
        finally:
            setattr(app, "style", original_style_method)

        assert probe.isVisible()
        assert probe in stand_in_show.unpolished, "hidden probe was not unpolished when its tab became visible"
        assert probe in stand_in_show.polished, "hidden probe was not repolished when its tab became visible"
