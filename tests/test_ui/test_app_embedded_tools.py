"""Tests for embedded tools UI integration in MainWindow.

Tests the menu actions, toolbar buttons, and handlers for x64dbg,
Cutter, and HxD embedded tool integration.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from PyQt6.QtWidgets import QApplication, QMessageBox, QPushButton


if TYPE_CHECKING:
    from collections.abc import Generator

    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator
    from intellicrack.ui.app import MainWindow


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication]:
    """Provide QApplication for tests."""
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


@pytest.fixture
def mock_orchestrator() -> MagicMock:
    """Create a mock orchestrator for MainWindow."""
    orchestrator = MagicMock()
    orchestrator.set_message_callback = MagicMock()
    orchestrator.set_tool_call_callback = MagicMock()
    orchestrator.set_tool_result_callback = MagicMock()
    orchestrator.set_stream_callback = MagicMock()
    orchestrator.set_async_confirmation_callback = MagicMock()
    orchestrator._config = MagicMock()
    orchestrator.shutdown = AsyncMock()
    return orchestrator


@pytest.fixture
def mock_config() -> MagicMock:
    """Create a mock config for MainWindow."""
    config = MagicMock()
    config.tools_directory = Path("tools")
    return config


def _create_window(
    mock_config: MagicMock,
    mock_orchestrator: MagicMock,
) -> MainWindow:
    """Create a MainWindow instance with mock dependencies.

    Args:
        mock_config: Mock configuration object.
        mock_orchestrator: Mock orchestrator object.

    Returns:
        A new MainWindow instance.
    """
    from intellicrack.ui.app import MainWindow as _MainWindow

    return _MainWindow(
        cast("Config", mock_config),
        cast("Orchestrator", mock_orchestrator),
    )


class TestEmbeddedToolsMenuIntegration:
    """Tests for embedded tools menu items in MainWindow."""

    def test_embedded_tools_menu_exists(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify Embedded Tools submenu is created in Tools menu."""
        del qapp
        with patch("intellicrack.ui.app.SandboxManager"):
            window = _create_window(mock_config, mock_orchestrator)
            try:
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
            finally:
                window.close()

    def test_embedded_tools_menu_actions_count(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify all 6 menu actions exist in Embedded Tools submenu."""
        del qapp
        with patch("intellicrack.ui.app.SandboxManager"):
            window = _create_window(mock_config, mock_orchestrator)
            try:
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
            finally:
                window.close()


class TestToolbarButtonsIntegration:
    """Tests for embedded tools toolbar buttons."""

    def test_toolbar_has_tool_buttons(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify x64dbg, Cutter, and HxD buttons exist in toolbar."""
        del qapp
        with patch("intellicrack.ui.app.SandboxManager"):
            window = _create_window(mock_config, mock_orchestrator)
            try:
                assert hasattr(window, "_x64dbg_btn"), "x64dbg button not found"
                assert hasattr(window, "_cutter_btn"), "Cutter button not found"
                assert hasattr(window, "_hxd_btn"), "HxD button not found"

                x64dbg_btn: object = window._x64dbg_btn
                cutter_btn: object = window._cutter_btn
                hxd_btn: object = window._hxd_btn

                assert isinstance(x64dbg_btn, QPushButton)
                assert isinstance(cutter_btn, QPushButton)
                assert isinstance(hxd_btn, QPushButton)

                assert x64dbg_btn.text() == "x64dbg"
                assert cutter_btn.text() == "Cutter"
                assert hxd_btn.text() == "HxD"
            finally:
                window.close()

    def test_toolbar_button_tooltips(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify toolbar buttons have correct tooltips."""
        del qapp
        with patch("intellicrack.ui.app.SandboxManager"):
            window = _create_window(mock_config, mock_orchestrator)
            try:
                x64dbg_btn: object = window._x64dbg_btn
                cutter_btn: object = window._cutter_btn
                hxd_btn: object = window._hxd_btn

                assert isinstance(x64dbg_btn, QPushButton)
                assert isinstance(cutter_btn, QPushButton)
                assert isinstance(hxd_btn, QPushButton)

                assert "x64dbg" in x64dbg_btn.toolTip()
                assert "Cutter" in cutter_btn.toolTip()
                assert "HxD" in hxd_btn.toolTip()
            finally:
                window.close()


class TestEmbeddedToolHandlers:
    """Tests for embedded tool handler methods."""

    def test_on_open_x64dbg_creates_widget(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify _on_open_x64dbg calls add_x64dbg_tab."""
        del qapp
        with patch("intellicrack.ui.app.SandboxManager"):
            window = _create_window(mock_config, mock_orchestrator)
            try:
                mock_widget = MagicMock()
                mock_widget.start_tool.return_value = True
                tool_panel: object = window._tool_panel
                mock_add_tab = MagicMock(return_value=mock_widget)
                tool_panel.add_x64dbg_tab = mock_add_tab

                open_x64dbg: object = window._on_open_x64dbg
                assert callable(open_x64dbg)
                open_x64dbg()

                mock_add_tab.assert_called_once_with(is_64bit=True)
                mock_widget.start_tool.assert_called_once()
            finally:
                window.close()

    def test_on_open_x64dbg_handles_none_widget(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify _on_open_x64dbg shows error when widget creation fails."""
        del qapp
        with patch("intellicrack.ui.app.SandboxManager"):
            window = _create_window(mock_config, mock_orchestrator)
            try:
                tool_panel: object = window._tool_panel
                tool_panel.add_x64dbg_tab = MagicMock(return_value=None)

                with patch.object(window, "_show_tool_error") as mock_error:
                    open_x64dbg: object = window._on_open_x64dbg
                    assert callable(open_x64dbg)
                    open_x64dbg()
                    mock_error.assert_called_once()
                    call_args = mock_error.call_args
                    assert call_args is not None
                    assert "x64dbg" in str(call_args[0][0])
            finally:
                window.close()

    def test_on_open_cutter_creates_widget(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify _on_open_cutter calls add_cutter_tab."""
        del qapp
        with patch("intellicrack.ui.app.SandboxManager"):
            window = _create_window(mock_config, mock_orchestrator)
            try:
                mock_widget = MagicMock()
                mock_widget.start_tool.return_value = True
                tool_panel: object = window._tool_panel
                mock_add_tab = MagicMock(return_value=mock_widget)
                tool_panel.add_cutter_tab = mock_add_tab

                open_cutter: object = window._on_open_cutter
                assert callable(open_cutter)
                open_cutter()

                mock_add_tab.assert_called_once()
                mock_widget.start_tool.assert_called_once()
            finally:
                window.close()

    def test_on_open_hxd_creates_widget(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify _on_open_hxd calls add_hxd_tab."""
        del qapp
        with patch("intellicrack.ui.app.SandboxManager"):
            window = _create_window(mock_config, mock_orchestrator)
            try:
                mock_widget = MagicMock()
                mock_widget.start_tool.return_value = True
                tool_panel: object = window._tool_panel
                mock_add_tab = MagicMock(return_value=mock_widget)
                tool_panel.add_hxd_tab = mock_add_tab

                open_hxd: object = window._on_open_hxd
                assert callable(open_hxd)
                open_hxd()

                mock_add_tab.assert_called_once()
                mock_widget.start_tool.assert_called_once()
            finally:
                window.close()


class TestCurrentBinaryHandlers:
    """Tests for current binary operation handlers."""

    def test_debug_current_binary_without_binary_shows_warning(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify warning shown when no binary is loaded for debug."""
        del qapp
        with patch("intellicrack.ui.app.SandboxManager"):
            window = _create_window(mock_config, mock_orchestrator)
            try:
                window._current_binary = None

                with patch.object(window, "_show_no_binary_warning") as mock_warn:
                    on_debug: object = window._on_debug_current_binary
                    assert callable(on_debug)
                    on_debug()
                    mock_warn.assert_called_once_with("debug")
            finally:
                window.close()

    def test_analyze_current_binary_without_binary_shows_warning(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify warning shown when no binary is loaded for analysis."""
        del qapp
        with patch("intellicrack.ui.app.SandboxManager"):
            window = _create_window(mock_config, mock_orchestrator)
            try:
                window._current_binary = None

                with patch.object(window, "_show_no_binary_warning") as mock_warn:
                    on_analyze: object = window._on_analyze_current_binary
                    assert callable(on_analyze)
                    on_analyze()
                    mock_warn.assert_called_once_with("analyze")
            finally:
                window.close()

    def test_hex_edit_current_binary_without_binary_shows_warning(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify warning shown when no binary is loaded for hex edit."""
        del qapp
        with patch("intellicrack.ui.app.SandboxManager"):
            window = _create_window(mock_config, mock_orchestrator)
            try:
                window._current_binary = None

                with patch.object(window, "_show_no_binary_warning") as mock_warn:
                    on_hex_edit: object = window._on_hex_edit_current_binary
                    assert callable(on_hex_edit)
                    on_hex_edit()
                    mock_warn.assert_called_once_with("hex edit")
            finally:
                window.close()

    def test_debug_current_binary_with_binary_calls_open_in_x64dbg(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify binary is passed to x64dbg when loaded."""
        del qapp
        with patch("intellicrack.ui.app.SandboxManager"):
            window = _create_window(mock_config, mock_orchestrator)
            try:
                test_path = Path("/test/binary.exe")
                window._current_binary = test_path
                tool_panel: object = window._tool_panel
                mock_open = MagicMock(return_value=True)
                tool_panel.open_in_x64dbg = mock_open

                on_debug: object = window._on_debug_current_binary
                assert callable(on_debug)
                on_debug()

                mock_open.assert_called_once_with(test_path)
            finally:
                window.close()

    def test_analyze_current_binary_with_binary_calls_open_in_cutter(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify binary is passed to Cutter when loaded."""
        del qapp
        with patch("intellicrack.ui.app.SandboxManager"):
            window = _create_window(mock_config, mock_orchestrator)
            try:
                test_path = Path("/test/binary.exe")
                window._current_binary = test_path
                tool_panel: object = window._tool_panel
                mock_open = MagicMock(return_value=True)
                tool_panel.open_in_cutter = mock_open

                on_analyze: object = window._on_analyze_current_binary
                assert callable(on_analyze)
                on_analyze()

                mock_open.assert_called_once_with(test_path)
            finally:
                window.close()

    def test_hex_edit_current_binary_with_binary_calls_open_in_hxd(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify binary is passed to HxD when loaded."""
        del qapp
        with patch("intellicrack.ui.app.SandboxManager"):
            window = _create_window(mock_config, mock_orchestrator)
            try:
                test_path = Path("/test/binary.exe")
                window._current_binary = test_path
                tool_panel: object = window._tool_panel
                mock_open = MagicMock(return_value=True)
                tool_panel.open_in_hxd = mock_open

                on_hex_edit: object = window._on_hex_edit_current_binary
                assert callable(on_hex_edit)
                on_hex_edit()

                mock_open.assert_called_once_with(test_path)
            finally:
                window.close()


class TestCurrentBinaryTracking:
    """Tests for current binary tracking in MainWindow."""

    def test_current_binary_initialized_to_none(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify _current_binary starts as None."""
        del qapp
        with patch("intellicrack.ui.app.SandboxManager"):
            window = _create_window(mock_config, mock_orchestrator)
            try:
                current_binary: object = window._current_binary
                assert current_binary is None
            finally:
                window.close()

    def test_load_binary_sets_current_binary(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify _load_binary updates _current_binary."""
        del qapp
        with patch("intellicrack.ui.app.SandboxManager"):
            window = _create_window(mock_config, mock_orchestrator)
            try:
                test_path = Path("/test/sample.exe")

                with patch.object(window, "_run_async"):
                    load_binary: object = window._load_binary
                    assert callable(load_binary)
                    load_binary(test_path)

                current_binary: object = window._current_binary
                assert current_binary == test_path
            finally:
                window.close()


class TestErrorDialogs:
    """Tests for error and warning dialog display."""

    def test_show_tool_error_displays_warning(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify _show_tool_error displays QMessageBox warning."""
        del qapp
        with patch("intellicrack.ui.app.SandboxManager"):
            window = _create_window(mock_config, mock_orchestrator)
            try:
                with patch.object(QMessageBox, "warning") as mock_warning:
                    show_error: object = window._show_tool_error
                    assert callable(show_error)
                    show_error("TestTool", "Test error message")

                    mock_warning.assert_called_once()
                    call_args = mock_warning.call_args
                    assert call_args is not None
                    assert "TestTool" in str(call_args[0][1])
                    assert "Test error message" in str(call_args[0][2])
            finally:
                window.close()

    def test_show_no_binary_warning_displays_info(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify _show_no_binary_warning displays QMessageBox information."""
        del qapp
        with patch("intellicrack.ui.app.SandboxManager"):
            window = _create_window(mock_config, mock_orchestrator)
            try:
                with patch.object(QMessageBox, "information") as mock_info:
                    show_warning: object = window._show_no_binary_warning
                    assert callable(show_warning)
                    show_warning("test action")

                    mock_info.assert_called_once()
                    call_args = mock_info.call_args
                    assert call_args is not None
                    assert "test action" in str(call_args[0][2])
            finally:
                window.close()
