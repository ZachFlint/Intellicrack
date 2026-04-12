# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for embedded tools UI integration in MainWindow.

Tests the menu actions, toolbar buttons, and handlers for x64dbg,
Cutter, and HxD embedded tool integration.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication, QMessageBox, QPushButton

from intellicrack.ui.app import MainWindow

from .conftest import CallRecorder, DialogRecorder, NoOpSandboxManager


if TYPE_CHECKING:
    from collections.abc import Generator

    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator

_EXPECTED_MENU_ACTION_COUNT: int = 6


@pytest.fixture
def patched_window(
    qapp: QApplication,
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[MainWindow]:
    """Create a MainWindow with SandboxManager patched out.

    Args:
        qapp: QApplication instance required by Qt widgets.
        real_config: Real Config instance.
        real_orchestrator: Real Orchestrator instance.
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        Generator[MainWindow]:: MainWindow instance.
    """
    _ = qapp
    monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)
    window = MainWindow(real_config, real_orchestrator)
    yield window
    window.close()


class TestEmbeddedToolsMenuIntegration:
    """Tests for embedded tools menu items in MainWindow."""

    @staticmethod
    def test_embedded_tools_menu_exists(
        patched_window: MainWindow,
    ) -> None:
        """Verify Embedded Tools submenu is created in Tools menu.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
        """
        window = patched_window
        menubar = window.menuBar()
        assert menubar is not None, "Menu bar not found"

        tools_menu = next(
            (action.menu() for action in menubar.actions() if action.text() == "&Tools"),
            None,
        )
        assert tools_menu is not None, "Tools menu not found"

        embedded_menu = next(
            (action.menu() for action in tools_menu.actions() if action.text() == "&Embedded Tools"),
            None,
        )
        assert embedded_menu is not None, "Embedded Tools submenu not found"

    @staticmethod
    def test_embedded_tools_menu_actions_count(
        patched_window: MainWindow,
    ) -> None:
        """Verify all 6 menu actions exist in Embedded Tools submenu.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
        """
        window = patched_window
        menubar = window.menuBar()
        assert menubar is not None

        tools_menu = next(
            (action.menu() for action in menubar.actions() if action.text() == "&Tools"),
            None,
        )
        embedded_menu = None
        if tools_menu is not None:
            for action in tools_menu.actions():
                if action.text() == "&Embedded Tools":
                    embedded_menu = action.menu()
                    break

        assert embedded_menu is not None

        action_texts = [a.text() for a in embedded_menu.actions() if not a.isSeparator()]
        expected_actions = [
            "Open x64dbg Debugger",
            "Open Cutter Analysis",
            "Open HxD Hex Editor",
            "Debug Current Binary...",
            "Analyze Current Binary...",
            "Hex Edit Current Binary...",
        ]

        for expected in expected_actions:
            assert expected in action_texts, f"Missing action: {expected}"


class TestToolbarButtonsIntegration:
    """Tests for embedded tools toolbar buttons."""

    @staticmethod
    def test_toolbar_has_tool_buttons(
        patched_window: MainWindow,
    ) -> None:
        """Verify x64dbg, Cutter, and HxD buttons exist in toolbar.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
        """
        window = patched_window
        assert hasattr(window, "_x64dbg_btn"), "x64dbg button not found"
        assert hasattr(window, "_cutter_btn"), "Cutter button not found"
        assert hasattr(window, "_hxd_btn"), "HxD button not found"

        x64dbg_btn: object = window.x64dbg_btn
        cutter_btn: object = window.cutter_btn
        hxd_btn: object = window.hxd_btn

        assert isinstance(x64dbg_btn, QPushButton)
        assert isinstance(cutter_btn, QPushButton)
        assert isinstance(hxd_btn, QPushButton)

        assert x64dbg_btn.text() == "x64dbg"
        assert cutter_btn.text() == "Cutter"
        assert hxd_btn.text() == "HxD"

    @staticmethod
    def test_toolbar_button_tooltips(
        patched_window: MainWindow,
    ) -> None:
        """Verify toolbar buttons have correct tooltips.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
        """
        window = patched_window

        x64dbg_btn: object = window.x64dbg_btn
        cutter_btn: object = window.cutter_btn
        hxd_btn: object = window.hxd_btn

        assert isinstance(x64dbg_btn, QPushButton)
        assert isinstance(cutter_btn, QPushButton)
        assert isinstance(hxd_btn, QPushButton)

        assert "x64dbg" in x64dbg_btn.toolTip()
        assert "Cutter" in cutter_btn.toolTip()
        assert "HxD" in hxd_btn.toolTip()


class TestEmbeddedToolHandlers:
    """Tests for embedded tool handler methods."""

    @staticmethod
    def test_on_open_x64dbg_calls_add_tab(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify _on_open_x64dbg calls add_x64dbg_tab.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        recorder = CallRecorder(result=None)
        monkeypatch.setattr(window.tool_panel, "add_x64dbg_tab", recorder)
        monkeypatch.setattr(window, "_show_tool_error", CallRecorder())

        window.on_open_x64dbg()

        assert recorder.times_called >= 1

    @staticmethod
    def test_on_open_x64dbg_handles_none_widget(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify _on_open_x64dbg shows error when widget creation fails.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        tab_recorder = CallRecorder(result=None)
        error_recorder = CallRecorder()
        monkeypatch.setattr(window.tool_panel, "add_x64dbg_tab", tab_recorder)
        monkeypatch.setattr(window, "_show_tool_error", error_recorder)

        window.on_open_x64dbg()

        assert error_recorder.times_called >= 1
        assert "x64dbg" in str(error_recorder.calls[0])

    @staticmethod
    def test_on_open_cutter_calls_add_tab(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify _on_open_cutter calls add_cutter_tab.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        recorder = CallRecorder(result=None)
        monkeypatch.setattr(window.tool_panel, "add_cutter_tab", recorder)
        monkeypatch.setattr(window, "_show_tool_error", CallRecorder())

        window.on_open_cutter()

        assert recorder.times_called >= 1

    @staticmethod
    def test_on_open_hxd_calls_add_tab(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify _on_open_hxd calls add_hxd_tab.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        recorder = CallRecorder(result=None)
        monkeypatch.setattr(window.tool_panel, "add_hxd_tab", recorder)
        monkeypatch.setattr(window, "_show_tool_error", CallRecorder())

        window.on_open_hxd()

        assert recorder.times_called >= 1


class TestCurrentBinaryHandlers:
    """Tests for current binary operation handlers."""

    @staticmethod
    def test_debug_current_binary_without_binary_shows_warning(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify warning shown when no binary is loaded for debug.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        window.current_binary = None
        recorder = CallRecorder()
        monkeypatch.setattr(window, "_show_no_binary_warning", recorder)

        window.on_debug_current_binary()
        assert recorder.times_called == 1
        assert recorder.calls[0][0] == ("debug",)

    @staticmethod
    def test_analyze_current_binary_without_binary_shows_warning(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify warning shown when no binary is loaded for analysis.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        window.current_binary = None
        recorder = CallRecorder()
        monkeypatch.setattr(window, "_show_no_binary_warning", recorder)

        window.on_analyze_current_binary()
        assert recorder.times_called == 1
        assert recorder.calls[0][0] == ("analyze",)

    @staticmethod
    def test_hex_edit_current_binary_without_binary_shows_warning(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify warning shown when no binary is loaded for hex edit.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        window.current_binary = None
        recorder = CallRecorder()
        monkeypatch.setattr(window, "_show_no_binary_warning", recorder)

        window.on_hex_edit_current_binary()
        assert recorder.times_called == 1
        assert recorder.calls[0][0] == ("hex edit",)

    @staticmethod
    def test_debug_current_binary_with_binary_calls_open_in_x64dbg(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify binary is passed to x64dbg when loaded.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        test_path = Path("/test/binary.exe")
        window.current_binary = test_path
        recorder = CallRecorder(result=True)
        monkeypatch.setattr(window.tool_panel, "open_in_x64dbg", recorder)

        window.on_debug_current_binary()

        assert recorder.times_called == 1
        assert recorder.calls[0][0] == (test_path,)

    @staticmethod
    def test_analyze_current_binary_with_binary_calls_open_in_cutter(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify binary is passed to Cutter when loaded.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        test_path = Path("/test/binary.exe")
        window.current_binary = test_path
        recorder = CallRecorder(result=True)
        monkeypatch.setattr(window.tool_panel, "open_in_cutter", recorder)

        window.on_analyze_current_binary()

        assert recorder.times_called == 1
        assert recorder.calls[0][0] == (test_path,)

    @staticmethod
    def test_hex_edit_current_binary_with_binary_calls_open_in_hxd(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify binary is passed to HxD when loaded.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        test_path = Path("/test/binary.exe")
        window.current_binary = test_path
        recorder = CallRecorder(result=True)
        monkeypatch.setattr(window.tool_panel, "open_in_hxd", recorder)

        window.on_hex_edit_current_binary()

        assert recorder.times_called == 1
        assert recorder.calls[0][0] == (test_path,)


class TestCurrentBinaryTracking:
    """Tests for current binary tracking in MainWindow."""

    @staticmethod
    def test_current_binary_initialized_to_none(
        patched_window: MainWindow,
    ) -> None:
        """Verify _current_binary starts as None.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
        """
        current_binary: object = patched_window.current_binary
        assert current_binary is None

    @staticmethod
    def test_load_binary_sets_current_binary(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify _load_binary updates _current_binary.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        test_path = Path("/test/sample.exe")
        run_async_recorder = CallRecorder()
        monkeypatch.setattr(window, "_run_async", run_async_recorder)

        window.load_binary(test_path)

        current_binary: object = window.current_binary
        assert current_binary == test_path


class TestErrorDialogs:
    """Tests for error and warning dialog display."""

    @staticmethod
    def test_show_tool_error_displays_warning(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify _show_tool_error displays QMessageBox warning.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        recorder = DialogRecorder()
        monkeypatch.setattr(QMessageBox, "warning", staticmethod(recorder))

        window = patched_window
        window.show_tool_error("TestTool", "Test error message")

        assert len(recorder.calls) >= 1
        assert "TestTool" in str(recorder.calls[0])
        assert "Test error message" in str(recorder.calls[0])

    @staticmethod
    def test_show_no_binary_warning_displays_info(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify _show_no_binary_warning displays QMessageBox information.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        recorder = DialogRecorder()
        monkeypatch.setattr(QMessageBox, "information", staticmethod(recorder))

        window = patched_window
        window.show_no_binary_warning("test action")

        assert len(recorder.calls) >= 1
        assert "test action" in str(recorder.calls[0])
