"""Tests for DetachedPanelWindow from intellicrack.ui.panel_dock.

Verifies construction, property accessors, signal emission on
re-dock and close, widget attribute configuration, and window
title formatting.
"""

from __future__ import annotations

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QToolBar, QWidget

from intellicrack.ui.panel_dock import DetachedPanelWindow

from .conftest import SignalRecorder


_TITLE: str = "Test Panel"
_TITLE_ALT: str = "Another Panel"


@pytest.mark.usefixtures("qapp")
class TestDetachedPanelWindowConstruction:
    """Tests for DetachedPanelWindow construction and layout."""

    @staticmethod
    def test_construction() -> None:
        """Verify window creates with panel as central widget and toolbar with re-dock button."""
        panel = QWidget()
        window = DetachedPanelWindow(panel, _TITLE)

        assert window.centralWidget() is panel

        toolbar_found = False
        for child in window.children():
            if isinstance(child, QToolBar):
                toolbar_found = True
                actions_and_widgets = [child.widgetForAction(a) for a in child.actions()]
                redock_labels = [
                    w.text()
                    for w in actions_and_widgets
                    if w is not None and hasattr(w, "text")
                ]
                assert "Re-dock" in redock_labels
                break

        assert toolbar_found

    @staticmethod
    def test_panel_property() -> None:
        """Verify .panel returns the widget passed to constructor."""
        panel = QWidget()
        window = DetachedPanelWindow(panel, _TITLE)

        assert window.panel is panel

    @staticmethod
    def test_panel_title_property() -> None:
        """Verify .panel_title returns the title string."""
        panel = QWidget()
        window = DetachedPanelWindow(panel, _TITLE)

        assert window.panel_title == _TITLE

    @staticmethod
    def test_panel_title_property_alternate() -> None:
        """Verify .panel_title returns the correct title for a different string."""
        panel = QWidget()
        window = DetachedPanelWindow(panel, _TITLE_ALT)

        assert window.panel_title == _TITLE_ALT


@pytest.mark.usefixtures("qapp")
class TestDetachedPanelWindowSignals:
    """Tests for DetachedPanelWindow signal emission."""

    @staticmethod
    def test_redock_emits_signal() -> None:
        """Verify _on_redock() emits reattach_requested with (panel, title)."""
        panel = QWidget()
        window = DetachedPanelWindow(panel, _TITLE)
        recorder = SignalRecorder()
        window.reattach_requested.connect(recorder)

        window._on_redock()

        recorder.verify_single_call(panel, _TITLE)

    @staticmethod
    def test_close_emits_reattach() -> None:
        """Verify closeEvent(None) emits reattach_requested signal."""
        panel = QWidget()
        window = DetachedPanelWindow(panel, _TITLE)
        recorder = SignalRecorder()
        window.reattach_requested.connect(recorder)

        window.closeEvent(None)

        recorder.verify_single_call(panel, _TITLE)


@pytest.mark.usefixtures("qapp")
class TestDetachedPanelWindowAttributes:
    """Tests for DetachedPanelWindow widget attributes and title format."""

    @staticmethod
    def test_wa_delete_on_close_disabled() -> None:
        """Verify WA_DeleteOnClose is False via testAttribute()."""
        panel = QWidget()
        window = DetachedPanelWindow(panel, _TITLE)

        assert window.testAttribute(Qt.WidgetAttribute.WA_DeleteOnClose) is False

    @staticmethod
    def test_window_title_format() -> None:
        """Verify window title is 'Intellicrack - {title}'."""
        panel = QWidget()
        window = DetachedPanelWindow(panel, _TITLE)

        assert window.windowTitle() == f"Intellicrack - {_TITLE}"

    @staticmethod
    def test_window_title_format_alternate() -> None:
        """Verify window title format works with different titles."""
        panel = QWidget()
        window = DetachedPanelWindow(panel, _TITLE_ALT)

        assert window.windowTitle() == f"Intellicrack - {_TITLE_ALT}"
