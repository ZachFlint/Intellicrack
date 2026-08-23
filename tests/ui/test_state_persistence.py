# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for ToolOutputPanel window state persistence.

Verifies tab state capture (names, active index, splitter sizes),
state restoration, unsaved-changes detection, hex editor save
delegation, and detached window state tracking.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtCore import QSettings
from PyQt6.QtWidgets import QWidget

from intellicrack.ui.tools import ToolOutputPanel


if TYPE_CHECKING:
    from collections.abc import Generator


_SETTINGS_ORG: str = "IntellicrackTest"
_SETTINGS_APP: str = "TestStateP"
_TAB_A: str = "TabA"
_TAB_B: str = "TabB"


@pytest.fixture
def clean_settings() -> Generator[QSettings]:
    """Provide a QSettings instance and clear it on teardown.

    Yields:
        QSettings: Temporary settings store for testing.
    """
    settings = QSettings(_SETTINGS_ORG, _SETTINGS_APP)
    yield settings
    settings.clear()
    settings.sync()


@pytest.mark.usefixtures("qapp")
class TestSaveTabState:
    """Tests for save_tab_state capturing tab layout."""

    @staticmethod
    def test_save_tab_state_captures_names() -> None:
        """Verify tab_names in saved state matches added tab titles."""
        panel = ToolOutputPanel()
        widget_a = QWidget()
        widget_b = QWidget()
        panel.tab_widget.addTab(widget_a, _TAB_A)
        panel.tab_widget.addTab(widget_b, _TAB_B)

        state = panel.save_tab_state()
        tab_names = state["tab_names"]

        assert isinstance(tab_names, list)
        assert _TAB_A in tab_names
        assert _TAB_B in tab_names

    @staticmethod
    def test_save_tab_state_captures_active() -> None:
        """Verify active_index reflects the currently selected tab."""
        panel = ToolOutputPanel()
        widget_a = QWidget()
        widget_b = QWidget()
        panel.tab_widget.addTab(widget_a, _TAB_A)
        panel.tab_widget.addTab(widget_b, _TAB_B)
        panel.tab_widget.setCurrentIndex(1)

        state = panel.save_tab_state()

        assert state["active_index"] == 1

    @staticmethod
    def test_save_tab_state_captures_splitter() -> None:
        """Verify splitter_sizes is a list of two integers."""
        panel = ToolOutputPanel()

        state = panel.save_tab_state()
        splitter_sizes = state["splitter_sizes"]

        assert isinstance(splitter_sizes, list)
        typed_sizes = cast("list[int]", splitter_sizes)
        assert len(typed_sizes) == 2
        assert isinstance(typed_sizes[0], int)
        assert isinstance(typed_sizes[1], int)


@pytest.mark.usefixtures("qapp")
class TestRestoreTabState:
    """Tests for restore_tab_state restoring layout."""

    @staticmethod
    def test_restore_tab_state_sets_active() -> None:
        """Verify active index is restored from saved state dict."""
        panel = ToolOutputPanel()
        widget_a = QWidget()
        widget_b = QWidget()
        widget_c = QWidget()
        panel.tab_widget.addTab(widget_a, _TAB_A)
        panel.tab_widget.addTab(widget_b, _TAB_B)
        panel.tab_widget.addTab(widget_c, "Extra")
        panel.tab_widget.setCurrentIndex(2)

        state: dict[str, object] = {
            "tab_names": [],
            "active_index": 1,
            "splitter_sizes": [500, 300],
        }

        panel.restore_tab_state(state)

        assert panel.tab_widget.currentIndex() == 1

    @staticmethod
    def test_restore_tab_state_sets_splitter() -> None:
        """Verify splitter sizes are restored from saved state dict."""
        panel = ToolOutputPanel()
        default_sizes = list(panel.main_splitter.sizes())

        state: dict[str, object] = {
            "tab_names": [],
            "active_index": 0,
            "splitter_sizes": [400, 400],
        }

        panel.restore_tab_state(state)

        sizes = panel.main_splitter.sizes()
        assert len(sizes) == 2
        assert abs(sizes[0] - sizes[1]) <= 1
        assert sizes != default_sizes or default_sizes == [400, 400]

    @staticmethod
    def test_restore_tab_state_tab_openers_keys() -> None:
        """Verify restore_tab_state opens each registered panel with the correct title.

        Each key in tab_openers must map to a tab whose tabText equals that key exactly.
        Passing the keys through tab_names drives the real opener; asserting idx >= 0
        confirms the tab was actually created, and tabText(idx) == key confirms the
        title was preserved faithfully.
        """
        panel = ToolOutputPanel()
        registered_keys: list[str] = [
            "Hex Editor",
            "Frida",
            "Ghidra",
            "Cutter",
            "Process",
            "Sandbox",
            "Analysis",
            "Scripts",
            "Stack",
        ]

        state: dict[str, object] = {
            "tab_names": registered_keys,
            "active_index": 0,
            "splitter_sizes": [600, 200],
        }
        panel.restore_tab_state(state)

        for key in registered_keys:
            idx = panel.find_tab_by_title(key)
            assert idx >= 0, f"Tab '{key}' was not opened by restore_tab_state (index={idx})"
            assert panel.tab_widget.tabText(idx) == key, f"tabText({idx}) is {panel.tab_widget.tabText(idx)!r}, expected {key!r}"

        assert panel.tab_widget.count() >= len(registered_keys)


@pytest.mark.usefixtures("qapp")
class TestUnsavedChanges:
    """Tests for unsaved changes and hex editor save methods."""

    @staticmethod
    def test_has_unsaved_changes_no_editor() -> None:
        """Verify fresh panel with no hex editor returns False."""
        panel = ToolOutputPanel()

        assert panel.has_unsaved_changes() is False

    @staticmethod
    def test_save_hex_editor_no_editor() -> None:
        """Verify fresh panel with no hex editor returns False on save."""
        panel = ToolOutputPanel()

        assert panel.save_hex_editor() is False


@pytest.mark.usefixtures("qapp")
class TestDetachedState:
    """Tests for detached tab state tracking."""

    @staticmethod
    def test_detached_state_persisted() -> None:
        """Verify detached tab title appears in get_detached_state."""
        panel = ToolOutputPanel()
        widget = QWidget()
        panel.tab_widget.addTab(widget, _TAB_A)

        tab_index = panel.tab_widget.indexOf(widget)
        panel.detach_tab(tab_index)

        detached = panel.get_detached_state()
        assert _TAB_A in detached

    @staticmethod
    def test_detached_state_empty_initially() -> None:
        """Verify get_detached_state returns empty list on fresh panel."""
        panel = ToolOutputPanel()

        assert panel.get_detached_state() == []

    @staticmethod
    def test_detached_state_multiple(clean_settings: QSettings) -> None:
        """Verify multiple detached tabs all appear in state.

        Args:
            clean_settings: QSettings fixture for test isolation.
        """
        _ = clean_settings
        panel = ToolOutputPanel()
        widget_a = QWidget()
        widget_b = QWidget()
        panel.tab_widget.addTab(widget_a, _TAB_A)
        panel.tab_widget.addTab(widget_b, _TAB_B)

        panel.detach_tab(1)
        panel.detach_tab(0)

        detached = panel.get_detached_state()
        assert _TAB_A in detached
        assert _TAB_B in detached
