# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the layout/DPI foundation fixes (D38, D08, D03, D02, D27).

Covers the shared toolbar-height derivation used by every docked analysis
panel and the main window toolbar (D38/D08/D03 -- a fixed 32px/40px toolbar
clips styled ``QPushButton``/``QLineEdit`` children), the docked-tab splitter
floor that must leave the handle movable and the right dock column on-screen
instead of pinning to a tab's raw, unbounded ``minimumSizeHint`` (D02), and
the early splash pixmap composition that must fill its frame edge-to-edge
instead of pillarboxing (D27).

Drives a real ``MainWindow`` with real embedded Frida/Hex Editor bridges (no
mocked geometry, no stubbed Qt objects) -- the same fixture wiring used by
``test_main_window_resizable.py``.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QPoint
from PyQt6.QtGui import QColor

from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.core.types import ToolName
from intellicrack.main import _EARLY_SPLASH_BG, _build_early_splash_pixmap
from intellicrack.ui.app import MainWindow
from intellicrack.ui.panels.base_panel import compute_toolbar_height

from .conftest import NoOpSandboxManager


if TYPE_CHECKING:
    from collections.abc import Generator

    from PyQt6.QtWidgets import QApplication, QToolBar, QWidget

    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator


_REALISTIC_WIDTH = 900
_REALISTIC_HEIGHT = 700
_SPLASH_WIDTH = 600
_SPLASH_HEIGHT = 400
# Sampled every few rows rather than every row: cheap, and a genuinely
# pillarboxed edge column is uniform background across every sampled row too.
_SPLASH_ROW_STRIDE = 5


@pytest.fixture
def window(
    qapp: QApplication,
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[MainWindow]:
    """Build, show, and tear down a real MainWindow with Frida/Hex Editor bridges wired.

    Registers real bridge instances on the orchestrator's tool registry before
    construction so ``ToolOutputPanel.add_frida_tab``/``add_hex_editor_tab``
    (which resolve their bridge through that registry once a real
    ``MainWindow`` has wired it) succeed instead of raising ``ToolError``.

    Args:
        qapp: QApplication instance required by Qt widgets.
        real_config: Real Config instance.
        real_orchestrator: Real Orchestrator instance.
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        MainWindow: A shown MainWindow with both bridges available.
    """
    monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)
    real_orchestrator.tool_registry.register_bridge(ToolName.FRIDA, FridaBridge())
    real_orchestrator.tool_registry.register_bridge(ToolName.HEX_EDITOR, HexEditorBridge())
    win = MainWindow(real_config, real_orchestrator)
    win.show()
    qapp.processEvents()
    try:
        yield win
    finally:
        win.close()
        qapp.processEvents()


def _toolbar_child_widgets(toolbar: QToolBar) -> list[QWidget]:
    """Collect the real widgets a toolbar's actions carry.

    Args:
        toolbar: The toolbar to inspect.

    Returns:
        list[QWidget]: Every non-``None`` widget bound to one of the
        toolbar's current actions (skips plain ``QAction`` separators, which
        carry no widget).
    """
    widgets: list[QWidget] = []
    for action in toolbar.actions():
        widget = toolbar.widgetForAction(action)
        if widget is not None:
            widgets.append(widget)
    return widgets


class TestToolbarHeightFitsStyledControls:
    """D38/D08/D03: every toolbar must be tall enough for its styled controls.

    A fixed 32px (base_panel) or 40px toolbar height clips the bottom of a
    styled ``QPushButton`` (min-height 24px + 12px vertical padding) once the
    8px of ``QToolBar`` chrome padding is added -- 44px minimum. Two
    independent signals catch a regression to either hardcoded height: the
    toolbar's real height must equal what :func:`compute_toolbar_height`
    derives (fails immediately if a literal constant is restored, regardless
    of what any individual control's rendered ``sizeHint`` happens to be in
    the test environment), and no child's ``sizeHint`` may exceed the
    toolbar's actual height (fails if the toolbar is simply too short for
    the controls it holds).
    """

    @staticmethod
    def test_docked_panel_toolbars_match_derived_height_and_fit_children(
        window: MainWindow,
        qapp: QApplication,
    ) -> None:
        """Each docked analysis-panel toolbar uses the shared derivation and clips nothing.

        Args:
            window: The MainWindow fixture.
            qapp: QApplication instance for event pumping.
        """
        tool_panel = window.tool_panel
        tool_panel.add_frida_tab()
        tool_panel.add_hex_editor_tab()
        qapp.processEvents()

        checked_tabs = 0
        for index in range(tool_panel.tab_widget.count()):
            panel = tool_panel.tab_widget.widget(index)
            toolbar = getattr(panel, "_toolbar", None)
            if toolbar is None:
                continue
            checked_tabs += 1
            tab_name = tool_panel.tab_widget.tabText(index)

            assert toolbar.height() == compute_toolbar_height(panel), (
                f"{tab_name!r} toolbar height {toolbar.height()} does not match the "
                f"font-metric derivation {compute_toolbar_height(panel)} -- a hardcoded "
                f"height constant may have been restored"
            )

            widgets = _toolbar_child_widgets(toolbar)
            assert widgets, f"{tab_name!r} toolbar has no widgets to check"
            for widget in widgets:
                assert widget.sizeHint().height() <= toolbar.height(), (
                    f"{type(widget).__name__} in {tab_name!r} toolbar needs "
                    f"{widget.sizeHint().height()}px but the toolbar is only "
                    f"{toolbar.height()}px tall"
                )

        assert checked_tabs >= 2, f"expected at least 2 docked panel toolbars, checked {checked_tabs}"

    @staticmethod
    def test_main_toolbar_matches_derived_height_and_fits_children(window: MainWindow) -> None:
        """The main window toolbar uses the same shared derivation and clips nothing.

        Args:
            window: The MainWindow fixture.
        """
        toolbar = window._toolbar

        assert toolbar.height() == compute_toolbar_height(window), (
            f"main toolbar height {toolbar.height()} does not match the font-metric "
            f"derivation {compute_toolbar_height(window)} -- a hardcoded height "
            f"constant may have been restored"
        )

        widgets = _toolbar_child_widgets(toolbar)
        assert widgets, "main toolbar has no widgets to check"
        for widget in widgets:
            assert widget.sizeHint().height() <= toolbar.height(), (
                f"{type(widget).__name__} in the main toolbar needs "
                f"{widget.sizeHint().height()}px but the toolbar is only "
                f"{toolbar.height()}px tall"
            )


class TestDockedSplitterStaysUsable:
    """D02: the docked left/right column split must never freeze the handle or push content off-screen.

    Pinning the left column's floor to a docked tab's raw, unbounded
    ``minimumSizeHint`` (the Hex Editor's real content -- disassembly,
    registers, hex grid -- comfortably exceeds 1000px) starves the splitter
    of any slack once the window is a realistic size: the handle stops
    responding to ``setSizes`` and the right dock column has nowhere left to
    go. All three checks below are driven through the real, embedded Hex
    Editor panel and the real ``QSplitter``, not a stand-in widget.
    """

    @staticmethod
    def test_handle_moves_and_right_panel_stays_onscreen(window: MainWindow, qapp: QApplication) -> None:
        """At a realistic window width, the handle can move and the right column never spills off-window.

        Args:
            window: The MainWindow fixture.
            qapp: QApplication instance for event pumping.
        """
        tool_panel = window.tool_panel
        tool_panel.add_hex_editor_tab()
        hex_index = next(i for i in range(tool_panel.tab_widget.count()) if tool_panel.tab_widget.tabText(i) == "Hex Editor")
        tool_panel.tab_widget.setCurrentIndex(hex_index)
        qapp.processEvents()

        window.resize(_REALISTIC_WIDTH, _REALISTIC_HEIGHT)
        qapp.processEvents()

        splitter = tool_panel.main_splitter
        sizes_before = splitter.sizes()
        assert sum(sizes_before) <= splitter.width(), f"splitter sizes {sizes_before} sum past its own width {splitter.width()}"

        requested = [max(1, sizes_before[0] - 100), sizes_before[1] + 100]
        splitter.setSizes(requested)
        qapp.processEvents()
        sizes_after = splitter.sizes()
        assert sizes_after != sizes_before, (
            f"splitter handle did not move: sizes stayed {sizes_before} after setSizes({requested}) -- "
            f"the left column's floor is starving the splitter of slack"
        )

        right_panel = tool_panel.right_panel
        # .x() is parent-relative (the splitter's coordinate space), not
        # window-relative, so mapTo is required to compare against
        # window.width() meaningfully.
        right_top_left_in_window = right_panel.mapTo(window, QPoint(0, 0))
        right_edge = right_top_left_in_window.x() + right_panel.width()
        assert right_edge <= window.width(), (
            f"right panel's right edge ({right_edge}) spills past the window's own width ({window.width()})"
        )


class TestEarlySplashFillsFrame:
    """D27: the early splash pixmap must fill its frame edge-to-edge, not pillarbox.

    ``KeepAspectRatio`` scales the source image to fit *inside* the target
    frame, leaving solid-background bars on the two sides that do not match
    the frame's aspect ratio. The fix scales to *cover* the frame
    (``KeepAspectRatioByExpanding``) and center-crops, so real image content
    -- not background fill -- reaches both edge columns.
    """

    @staticmethod
    def test_edge_columns_are_not_uniformly_background(qapp: QApplication) -> None:
        """Neither edge column of the composed pixmap is solid background top-to-bottom.

        Args:
            qapp: QApplication instance (a ``QPixmap`` requires one to exist).
        """
        del qapp
        splash_path = Path(__file__).resolve().parents[2] / "src" / "intellicrack" / "assets" / "splash.png"
        assert splash_path.exists(), f"splash asset missing at {splash_path}"

        pixmap = _build_early_splash_pixmap(splash_path, _SPLASH_WIDTH, _SPLASH_HEIGHT)
        image = pixmap.toImage()
        background = QColor(_EARLY_SPLASH_BG)

        def _column_is_uniform_background(x: int) -> bool:
            """Report whether every sampled row of column ``x`` is the plain background colour.

            Args:
                x: Pixel column to sample.

            Returns:
                bool: True if every sampled row at ``x`` equals ``background``.
            """
            return all(image.pixelColor(x, y) == background for y in range(0, _SPLASH_HEIGHT, _SPLASH_ROW_STRIDE))

        assert not _column_is_uniform_background(0), "left edge column is solid background -- image is pillarboxed"
        assert not _column_is_uniform_background(_SPLASH_WIDTH - 1), "right edge column is solid background -- image is pillarboxed"
