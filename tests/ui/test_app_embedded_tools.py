# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for embedded tools UI integration in MainWindow.

Tests the menu actions, toolbar buttons, and handlers for x64dbg
and Cutter embedded tool integration.
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


class FakeToolWidget:
    """Minimal concrete stand-in for any ToolWidget protocol.

    Tracks calls to ``start_tool`` so tests can assert the production
    handler actually invoked it after successfully obtaining a widget.
    Does NOT inherit from QWidget — it is returned by a monkeypatched
    ``add_*_tab`` method so Qt never inspects its type.

    Construction takes no arguments.
    """

    def __init__(self) -> None:
        """Initialise with an empty call-history list."""
        self.start_tool_calls: int = 0

    def start_tool(self) -> bool:
        """Record an invocation and return success.

        Returns:
            bool: Always True (success).
        """
        self.start_tool_calls += 1
        return True

    def debug_file(self, file_path: Path) -> bool:
        """Stub implementation of the x64dbg debug-file protocol method.

        Args:
            file_path: Ignored path argument.

        Returns:
            bool: Always True (success).
        """
        del file_path
        return True

    def analyze_binary(self, file_path: Path) -> bool:
        """Stub implementation of the Cutter analyze-binary protocol method.

        Args:
            file_path: Ignored path argument.

        Returns:
            bool: Always True (success).
        """
        del file_path
        return True

    def load_file(self, file_path: Path | str) -> bool:
        """Stub implementation of the hex-editor load-file protocol method.

        Args:
            file_path: Ignored path argument.

        Returns:
            bool: Always True (success).
        """
        del file_path
        return True


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
        MainWindow:: MainWindow instance.
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
            "Open Hex Editor",
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
        """Verify x64dbg and Cutter buttons exist in toolbar.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
        """
        window = patched_window
        assert hasattr(window, "x64dbg_btn"), "x64dbg button not found"
        assert hasattr(window, "cutter_btn"), "Cutter button not found"

        x64dbg_btn: object = window.x64dbg_btn
        cutter_btn: object = window.cutter_btn

        assert isinstance(x64dbg_btn, QPushButton)
        assert isinstance(cutter_btn, QPushButton)

        assert x64dbg_btn.text() == "x64dbg"
        assert cutter_btn.text() == "Cutter"

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

        assert isinstance(x64dbg_btn, QPushButton)
        assert isinstance(cutter_btn, QPushButton)

        assert "x64dbg" in x64dbg_btn.toolTip()
        assert "Cutter" in cutter_btn.toolTip()


class TestEmbeddedToolHandlers:
    """Tests for embedded tool handler methods.

    Each handler has two distinct code states that must be exercised:
    the success path (add_*_tab returns a real widget, start_tool is called)
    and the error path (add_*_tab returns None, _show_tool_error is called
    with exact positional arguments).
    """

    @staticmethod
    def test_on_open_x64dbg_success_calls_start_tool(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify _on_open_x64dbg calls start_tool when add_x64dbg_tab succeeds.

        The production handler (``_open_x64dbg_impl``) must call
        ``widget.start_tool()`` after receiving a non-None widget.  If that
        call is removed or guarded incorrectly this test goes red.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        fake_widget = FakeToolWidget()

        def _return_fake_widget(**_kwargs: object) -> FakeToolWidget:
            return fake_widget

        monkeypatch.setattr(window.tool_panel, "add_x64dbg_tab", _return_fake_widget)
        run_bridge_recorder = CallRecorder()
        monkeypatch.setattr(
            "intellicrack.ui.app.run_bridge_coroutine_logged",
            run_bridge_recorder,
        )

        window.on_open_x64dbg()

        assert fake_widget.start_tool_calls == 1, (
            f"Expected start_tool() to be called exactly once on the widget returned by add_x64dbg_tab; got {fake_widget.start_tool_calls}"
        )

    @staticmethod
    def test_on_open_x64dbg_none_widget_shows_exact_error(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify _on_open_x64dbg calls _show_tool_error with exact args when widget is None.

        The production code at ``_open_x64dbg_impl`` calls
        ``_show_tool_error("x64dbg", "Failed to initialize x64dbg panel")`` when
        ``add_x64dbg_tab`` returns ``None``.  This test asserts the exact
        positional arguments so capitalisation or message changes are caught.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        monkeypatch.setattr(window.tool_panel, "add_x64dbg_tab", lambda **_kw: None)
        run_bridge_recorder = CallRecorder()
        monkeypatch.setattr(
            "intellicrack.ui.app.run_bridge_coroutine_logged",
            run_bridge_recorder,
        )
        error_recorder = CallRecorder()
        monkeypatch.setattr(window, "_show_tool_error", error_recorder)

        window.on_open_x64dbg()

        assert error_recorder.times_called == 1, f"Expected _show_tool_error called once; got {error_recorder.times_called}"
        args, kwargs = error_recorder.calls[0]
        assert args == ("x64dbg", "Failed to initialize x64dbg panel"), f"Unexpected _show_tool_error arguments: {args!r}, {kwargs!r}"

    @staticmethod
    def test_on_open_cutter_success_calls_start_tool(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify _on_open_cutter calls start_tool when add_cutter_tab succeeds.

        The production handler must call ``widget.start_tool()`` on the returned
        widget.  If that call is removed this test goes red.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        fake_widget = FakeToolWidget()
        monkeypatch.setattr(window.tool_panel, "add_cutter_tab", lambda: fake_widget)

        window.on_open_cutter()

        assert fake_widget.start_tool_calls == 1, f"Expected start_tool() called once; got {fake_widget.start_tool_calls}"

    @staticmethod
    def test_on_open_cutter_none_widget_shows_exact_error(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify _on_open_cutter shows exact error message when widget creation fails.

        The production code calls ``_show_tool_error("Cutter", "Failed to initialize Cutter panel")``
        when ``add_cutter_tab`` returns ``None``.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        monkeypatch.setattr(window.tool_panel, "add_cutter_tab", lambda: None)
        error_recorder = CallRecorder()
        monkeypatch.setattr(window, "_show_tool_error", error_recorder)

        window.on_open_cutter()

        assert error_recorder.times_called == 1, f"Expected _show_tool_error called once; got {error_recorder.times_called}"
        args, kwargs = error_recorder.calls[0]
        assert args == ("Cutter", "Failed to initialize Cutter panel"), f"Unexpected _show_tool_error arguments: {args!r}, {kwargs!r}"

    @staticmethod
    def test_on_open_hex_editor_success_calls_start_tool(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify _on_open_hex_editor calls start_tool when add_hex_editor_tab succeeds.

        The production handler must call ``widget.start_tool()`` on the returned
        widget.  If that call is removed this test goes red.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        fake_widget = FakeToolWidget()
        monkeypatch.setattr(window.tool_panel, "add_hex_editor_tab", lambda: fake_widget)

        window._on_open_hex_editor()

        assert fake_widget.start_tool_calls == 1, f"Expected start_tool() called once; got {fake_widget.start_tool_calls}"

    @staticmethod
    def test_on_open_hex_editor_none_widget_shows_exact_error(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify _on_open_hex_editor shows exact error message when widget creation fails.

        The production code calls ``_show_tool_error("Hex Editor", "Failed to initialize hex editor panel")``
        when ``add_hex_editor_tab`` returns ``None``.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        monkeypatch.setattr(window.tool_panel, "add_hex_editor_tab", lambda: None)
        error_recorder = CallRecorder()
        monkeypatch.setattr(window, "_show_tool_error", error_recorder)

        window._on_open_hex_editor()

        assert error_recorder.times_called == 1, f"Expected _show_tool_error called once; got {error_recorder.times_called}"
        args, kwargs = error_recorder.calls[0]
        assert args == ("Hex Editor", "Failed to initialize hex editor panel"), (
            f"Unexpected _show_tool_error arguments: {args!r}, {kwargs!r}"
        )


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

        window._on_debug_current_binary()
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

        window._on_analyze_current_binary()
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

        window._on_hex_edit_current_binary()
        assert recorder.times_called == 1
        assert recorder.calls[0][0] == ("hex edit",)

    @staticmethod
    def test_debug_current_binary_success_passes_exact_path(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify exact path is forwarded to open_in_x64dbg when binary is loaded.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        test_path = Path("/test/binary.exe")
        window.current_binary = test_path
        recorder = CallRecorder(result=True)
        monkeypatch.setattr(window.tool_panel, "open_in_x64dbg", recorder)

        window._on_debug_current_binary()

        assert recorder.times_called == 1
        args, kwargs = recorder.calls[0]
        assert args == (test_path,), f"Expected path {test_path!r} as sole positional arg; got {args!r}"
        assert kwargs == {}, f"Expected no keyword args; got {kwargs!r}"

    @staticmethod
    def test_debug_current_binary_failure_shows_exact_error(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify _show_tool_error is called with exact args when open_in_x64dbg fails.

        The production code at line 3082-3083 calls
        ``_show_tool_error("x64dbg", "Failed to open binary in x64dbg")``
        when ``open_in_x64dbg`` returns ``False``.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        test_path = Path("/test/binary.exe")
        window.current_binary = test_path
        monkeypatch.setattr(window.tool_panel, "open_in_x64dbg", CallRecorder(result=False))
        error_recorder = CallRecorder()
        monkeypatch.setattr(window, "_show_tool_error", error_recorder)

        window._on_debug_current_binary()

        assert error_recorder.times_called == 1, f"Expected _show_tool_error called once; got {error_recorder.times_called}"
        args, kwargs = error_recorder.calls[0]
        assert args == ("x64dbg", "Failed to open binary in x64dbg"), f"Unexpected _show_tool_error arguments: {args!r}, {kwargs!r}"

    @staticmethod
    def test_analyze_current_binary_success_passes_exact_path(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify exact path is forwarded to open_in_cutter when binary is loaded.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        test_path = Path("/test/binary.exe")
        window.current_binary = test_path
        recorder = CallRecorder(result=True)
        monkeypatch.setattr(window.tool_panel, "open_in_cutter", recorder)

        window._on_analyze_current_binary()

        assert recorder.times_called == 1
        args, kwargs = recorder.calls[0]
        assert args == (test_path,), f"Expected path {test_path!r} as sole positional arg; got {args!r}"
        assert kwargs == {}, f"Expected no keyword args; got {kwargs!r}"

    @staticmethod
    def test_analyze_current_binary_failure_shows_exact_error(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify _show_tool_error is called with exact args when open_in_cutter fails.

        The production code calls ``_show_tool_error("Cutter", "Failed to open binary in Cutter")``
        when ``open_in_cutter`` returns ``False``.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        test_path = Path("/test/binary.exe")
        window.current_binary = test_path
        monkeypatch.setattr(window.tool_panel, "open_in_cutter", CallRecorder(result=False))
        error_recorder = CallRecorder()
        monkeypatch.setattr(window, "_show_tool_error", error_recorder)

        window._on_analyze_current_binary()

        assert error_recorder.times_called == 1, f"Expected _show_tool_error called once; got {error_recorder.times_called}"
        args, kwargs = error_recorder.calls[0]
        assert args == ("Cutter", "Failed to open binary in Cutter"), f"Unexpected _show_tool_error arguments: {args!r}, {kwargs!r}"

    @staticmethod
    def test_hex_edit_current_binary_success_passes_exact_path(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify exact path is forwarded to open_in_hex_editor when binary is loaded.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        test_path = Path("/test/binary.exe")
        window.current_binary = test_path
        recorder = CallRecorder(result=True)
        monkeypatch.setattr(window.tool_panel, "open_in_hex_editor", recorder)

        window._on_hex_edit_current_binary()

        assert recorder.times_called == 1
        args, kwargs = recorder.calls[0]
        assert args == (test_path,), f"Expected path {test_path!r} as sole positional arg; got {args!r}"
        assert kwargs == {}, f"Expected no keyword args; got {kwargs!r}"

    @staticmethod
    def test_hex_edit_current_binary_failure_shows_exact_error(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify _show_tool_error is called with exact args when open_in_hex_editor fails.

        The production code calls ``_show_tool_error("Hex Editor", "Failed to open binary in hex editor")``
        when ``open_in_hex_editor`` returns ``False``.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        test_path = Path("/test/binary.exe")
        window.current_binary = test_path
        monkeypatch.setattr(window.tool_panel, "open_in_hex_editor", CallRecorder(result=False))
        error_recorder = CallRecorder()
        monkeypatch.setattr(window, "_show_tool_error", error_recorder)

        window._on_hex_edit_current_binary()

        assert error_recorder.times_called == 1, f"Expected _show_tool_error called once; got {error_recorder.times_called}"
        args, kwargs = error_recorder.calls[0]
        assert args == ("Hex Editor", "Failed to open binary in hex editor"), f"Unexpected _show_tool_error arguments: {args!r}, {kwargs!r}"


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
    def test_load_binary_sets_current_binary_and_enables_buttons(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify _load_binary sets current_binary, updates label, enables buttons, and calls hex editor.

        The production code at ``_load_binary`` must:
        1. Set ``current_binary`` to the supplied path.
        2. Update ``_binary_label`` to show the filename.
        3. Enable every button in ``_binary_dependent_buttons``.
        4. Call ``tool_panel.open_in_hex_editor`` with the string path.

        If any of these side-effects are removed, the corresponding assertion fails.

        Args:
            patched_window: MainWindow fixture with SandboxManager patched out.
            monkeypatch: Pytest monkeypatch fixture used to replace attributes during the test.
        """
        window = patched_window
        test_path = Path("/test/sample.exe")

        run_async_recorder = CallRecorder()
        monkeypatch.setattr(window, "_run_async", run_async_recorder)

        hex_editor_recorder = CallRecorder(result=True)
        monkeypatch.setattr(window.tool_panel, "open_in_hex_editor", hex_editor_recorder)

        for button in window._binary_dependent_buttons:
            button.setEnabled(False)

        window._load_binary(test_path)

        assert window.current_binary == test_path, f"current_binary expected {test_path!r}, got {window.current_binary!r}"

        binary_label_text: str = window._binary_label.text()
        assert binary_label_text == f"Binary: {test_path.name}", (
            f"Binary label expected 'Binary: {test_path.name}', got {binary_label_text!r}"
        )

        for button in window._binary_dependent_buttons:
            assert button.isEnabled(), f"Button '{button.text()}' expected enabled after _load_binary but was disabled"

        assert hex_editor_recorder.times_called == 1, f"Expected open_in_hex_editor called once; got {hex_editor_recorder.times_called}"
        hex_args, hex_kwargs = hex_editor_recorder.calls[0]
        assert hex_args == (str(test_path),), f"open_in_hex_editor expected str path {str(test_path)!r}; got {hex_args!r}"
        assert hex_kwargs == {}, f"Expected no keyword args to open_in_hex_editor; got {hex_kwargs!r}"


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
        window._show_tool_error("TestTool", "Test error message")

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
        window._show_no_binary_warning("test action")

        assert len(recorder.calls) >= 1
        assert "test action" in str(recorder.calls[0])
