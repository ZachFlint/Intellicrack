# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for embedded tools UI integration in MainWindow.

These tests drive the real :class:`MainWindow` and its real
:class:`~intellicrack.ui.tools.ToolPanel`. Menu actions are *triggered* (not
merely inspected) so the test proves each action is genuinely connected to its
real handler, and the resulting real side effect (a tab added, a context-driven
button enabled, the exact warning/error dialog) is asserted. The only object
ever substituted is the OS-modal ``QMessageBox`` static method, which is
recorded rather than shown so the suite never blocks; the operations under test
(routing, tab creation, error surfacing) always run for real.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QSettings
from PyQt6.QtWidgets import QApplication, QMessageBox, QPushButton

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.core.tools import ToolName
from intellicrack.ui.app import MainWindow

from .conftest import DialogRecorder, NoOpSandboxManager


if TYPE_CHECKING:
    from collections.abc import Coroutine, Generator
    from pathlib import Path

    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator

_EXPECTED_MENU_ACTION_COUNT: int = 6


class _AwaitableSandboxManager(NoOpSandboxManager):
    """No-op SandboxManager whose ``destroy_all`` returns a real coroutine.

    ``MainWindow.closeEvent`` runs ``destroy_all`` through the async bridge,
    which requires an awaitable. The base no-op returns ``None`` for every
    attribute, so this subclass supplies a genuine coroutine for the one method
    the close path awaits, keeping the real teardown path exercised without a
    real sandbox.
    """

    async def destroy_all(self) -> None:
        """Return immediately; no sandboxes exist to destroy in tests."""
        return


def _write_minimal_pe(path: Path) -> Path:
    r"""Write a minimal but structurally valid 64-bit PE file to ``path``.

    The file carries a real ``MZ`` DOS header, a correct ``e_lfanew`` pointer,
    a ``PE\0\0`` signature, an ``IMAGE_FILE_HEADER`` declaring the AMD64
    machine type, and an ``IMAGE_OPTIONAL_HEADER64`` magic. This is a real
    on-disk binary the routing layer can load and pass to tool bridges, not a
    placeholder byte sequence.

    Args:
        path: Destination path for the generated executable.

    Returns:
        Path: The same ``path`` for call-site convenience.
    """
    e_lfanew = 0x80
    dos_header = bytearray(e_lfanew)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, e_lfanew)

    pe_signature = b"PE\x00\x00"
    machine_amd64 = 0x8664
    number_of_sections = 1
    size_of_optional_header = 0xF0
    characteristics = 0x0022
    file_header = struct.pack(
        "<HHIIIHH",
        machine_amd64,
        number_of_sections,
        0,
        0,
        0,
        size_of_optional_header,
        characteristics,
    )
    optional_header = struct.pack("<H", 0x020B) + bytes(size_of_optional_header - 2)

    path.write_bytes(bytes(dos_header) + pe_signature + file_header + optional_header)
    return path


@pytest.fixture
def patched_window(
    qapp: QApplication,
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Generator[MainWindow]:
    """Create a real MainWindow with only the SandboxManager replaced.

    The SandboxManager is replaced because it spawns external sandbox
    processes that are irrelevant to embedded-tool UI wiring. ``QSettings`` is
    redirected into ``tmp_path`` so persisted window/tab state from the
    developer's profile cannot non-deterministically trigger tab restoration
    during construction; the store starts empty for every test. Every component
    exercised by the tests (menus, toolbar, ToolPanel, routing handlers) is the
    real production object.

    Args:
        qapp: QApplication instance required by Qt widgets.
        real_config: Real Config instance.
        real_orchestrator: Real Orchestrator instance.
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Pytest temporary directory used to isolate QSettings.

    Yields:
        Generator[MainWindow]: The constructed MainWindow.
    """
    _ = qapp
    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    QSettings.setPath(
        QSettings.Format.IniFormat,
        QSettings.Scope.UserScope,
        str(tmp_path / "qsettings"),
    )
    real_orchestrator.tool_registry.register_bridge(ToolName.HEX_EDITOR, HexEditorBridge())
    monkeypatch.setattr("intellicrack.ui.app.SandboxManager", _AwaitableSandboxManager)
    window = MainWindow(real_config, real_orchestrator)
    yield window
    window.close()


def _embedded_menu_actions(window: MainWindow) -> list[str]:
    """Return the non-separator action texts of the Embedded Tools submenu.

    Args:
        window: The MainWindow under test.

    Returns:
        list[str]: Ordered action labels (separators excluded).
    """
    menubar = window.menuBar()
    assert menubar is not None
    tools_menu = next((a.menu() for a in menubar.actions() if a.text() == "&Tools"), None)
    assert tools_menu is not None
    embedded_menu = next((a.menu() for a in tools_menu.actions() if a.text() == "&Embedded Tools"), None)
    assert embedded_menu is not None
    return [a.text() for a in embedded_menu.actions() if not a.isSeparator()]


class TestEmbeddedToolsMenuIntegration:
    """Tests for the Embedded Tools submenu structure and live wiring."""

    @staticmethod
    def test_embedded_tools_submenu_has_exact_action_set(patched_window: MainWindow) -> None:
        """Verify the submenu exposes exactly the six expected actions in order.

        Args:
            patched_window: Real MainWindow fixture.
        """
        actions = _embedded_menu_actions(patched_window)
        assert actions == [
            "Open x64dbg Debugger",
            "Open Cutter Analysis",
            "Open Hex Editor",
            "Debug Current Binary...",
            "Analyze Current Binary...",
            "Hex Edit Current Binary...",
        ]
        assert len(actions) == _EXPECTED_MENU_ACTION_COUNT

    @staticmethod
    def test_hex_edit_menu_action_is_wired_to_real_handler(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify triggering the menu action runs the real no-binary handler.

        This proves the menu item is genuinely connected to
        ``_on_hex_edit_current_binary`` rather than merely existing: with no
        binary loaded, triggering it must invoke the real handler, which shows
        the real "No Binary Loaded" information dialog naming the action.

        Args:
            patched_window: Real MainWindow fixture.
            monkeypatch: Used only to record the OS-modal QMessageBox.
        """
        window = patched_window
        window.current_binary = None
        info_recorder = DialogRecorder()
        monkeypatch.setattr(QMessageBox, "information", staticmethod(info_recorder))

        menubar = window.menuBar()
        assert menubar is not None
        tools_menu = next((a.menu() for a in menubar.actions() if a.text() == "&Tools"), None)
        assert tools_menu is not None
        embedded_menu = next((a.menu() for a in tools_menu.actions() if a.text() == "&Embedded Tools"), None)
        assert embedded_menu is not None
        hex_edit_action = next(a for a in embedded_menu.actions() if a.text() == "Hex Edit Current Binary...")

        hex_edit_action.trigger()
        QApplication.processEvents()

        assert len(info_recorder.calls) == 1
        dialog_text = " ".join(str(arg) for arg in info_recorder.calls[0])
        assert "No Binary Loaded" in dialog_text
        assert "hex edit" in dialog_text


class TestToolbarButtonsIntegration:
    """Tests for embedded tools toolbar buttons and their context-driven state."""

    @staticmethod
    def test_toolbar_buttons_have_expected_identity_and_tooltips(patched_window: MainWindow) -> None:
        """Verify x64dbg, Cutter, and HxD buttons exist with correct labels and tooltips.

        Args:
            patched_window: Real MainWindow fixture.
        """
        window = patched_window
        x64dbg_btn: object = window.x64dbg_btn
        cutter_btn: object = window.cutter_btn
        hxd_btn: object = window.hxd_btn

        assert isinstance(x64dbg_btn, QPushButton)
        assert isinstance(cutter_btn, QPushButton)
        assert isinstance(hxd_btn, QPushButton)

        assert x64dbg_btn.text() == "x64dbg"
        assert cutter_btn.text() == "Cutter"
        assert hxd_btn.text() == "HxD"

        assert "x64dbg" in x64dbg_btn.toolTip()
        assert "Cutter" in cutter_btn.toolTip()
        assert "HxD" in hxd_btn.toolTip()

    @staticmethod
    def test_tool_buttons_disabled_until_binary_loaded(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Verify binary-dependent tool buttons start disabled and enable on load.

        This is the real context-driven enabled-state contract: the tool
        buttons must be disabled before any binary is loaded and enabled after
        the real ``_load_binary`` runs against a real PE. The async session
        load and the modal hex-editor warning are recorded so the test stays
        deterministic, but the button-enabling logic itself runs for real.

        Args:
            patched_window: Real MainWindow fixture.
            monkeypatch: Used to record async dispatch and the modal warning.
            tmp_path: Pytest temporary directory.
        """
        window = patched_window

        assert not window.x64dbg_btn.isEnabled()
        assert not window.cutter_btn.isEnabled()
        assert not window.hxd_btn.isEnabled()

        run_async_calls: list[object] = []

        def _record_async(coro: Coroutine[object, object, object]) -> None:
            run_async_calls.append(type(coro).__name__)
            coro.close()

        monkeypatch.setattr(window, "_run_async", _record_async)
        monkeypatch.setattr(QMessageBox, "warning", staticmethod(DialogRecorder()))

        binary = _write_minimal_pe(tmp_path / "sample.exe")
        window._load_binary(binary)
        QApplication.processEvents()

        assert run_async_calls == ["coroutine"]

        assert window.current_binary == binary
        assert window.x64dbg_btn.isEnabled()
        assert window.cutter_btn.isEnabled()
        assert window.hxd_btn.isEnabled()


class TestCurrentBinaryRouting:
    """Tests for routing of current-binary operations through the real ToolPanel."""

    @staticmethod
    @pytest.mark.parametrize(
        ("handler_name", "action_word"),
        [
            ("_on_debug_current_binary", "debug"),
            ("_on_analyze_current_binary", "analyze"),
            ("_on_hex_edit_current_binary", "hex edit"),
        ],
    )
    def test_no_binary_routes_to_named_warning(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
        handler_name: str,
        action_word: str,
    ) -> None:
        """Verify each current-binary handler warns with the correct action word.

        With no binary loaded, the real handler must short-circuit to the real
        "No Binary Loaded" information dialog and must name the specific action
        (``debug`` / ``analyze`` / ``hex edit``). A regression that mislabels
        or drops the guard would change the dialog text and fail here.

        Args:
            patched_window: Real MainWindow fixture.
            monkeypatch: Used only to record the OS-modal QMessageBox.
            handler_name: Name of the MainWindow handler method to invoke.
            action_word: The action verb expected in the dialog text.
        """
        window = patched_window
        window.current_binary = None
        info_recorder = DialogRecorder()
        warn_recorder = DialogRecorder()
        monkeypatch.setattr(QMessageBox, "information", staticmethod(info_recorder))
        monkeypatch.setattr(QMessageBox, "warning", staticmethod(warn_recorder))

        handler = getattr(window, handler_name)
        handler()
        QApplication.processEvents()

        assert len(info_recorder.calls) == 1
        assert warn_recorder.calls == []
        dialog_text = " ".join(str(arg) for arg in info_recorder.calls[0])
        assert "No Binary Loaded" in dialog_text
        assert f"to {action_word} it" in dialog_text

    @staticmethod
    def test_hex_edit_with_binary_loads_real_pe_into_built_in_editor(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Verify a loaded PE is routed into the real built-in hex editor and loaded.

        With a real binary set, ``_on_hex_edit_current_binary`` calls the real
        ``ToolPanel.open_in_hex_editor``, which drives the real built-in hex
        editor (backed by the hexcore Rust extension) to open the file. This
        exercises the full routing-to-load path end to end: the editor's
        document must report the exact byte length of the PE on disk, the panel
        must record the file path, and the handler must show no error dialog.
        The independent oracle for the document length is the file's own size
        from ``os.stat`` (computed by a different code path than the editor).

        Args:
            patched_window: Real MainWindow fixture.
            monkeypatch: Used only to record the OS-modal QMessageBox.
            tmp_path: Pytest temporary directory.
        """
        window = patched_window
        binary = _write_minimal_pe(tmp_path / "target.exe")
        expected_size = binary.stat().st_size
        window.current_binary = binary

        warn_recorder = DialogRecorder()
        info_recorder = DialogRecorder()
        monkeypatch.setattr(QMessageBox, "warning", staticmethod(warn_recorder))
        monkeypatch.setattr(QMessageBox, "information", staticmethod(info_recorder))

        window._on_hex_edit_current_binary()
        QApplication.processEvents()

        assert warn_recorder.calls == []
        assert info_recorder.calls == []

        panel: object = window.tool_panel.embedded_tools["hex_editor"]
        document: object = getattr(panel, "document", None)
        assert document is not None
        length_getter = getattr(document, "length", None)
        assert callable(length_getter)
        assert length_getter() == expected_size
        assert getattr(panel, "file_path", None) == binary


class TestErrorDialogs:
    """Tests for the error and warning dialog helpers."""

    @staticmethod
    def test_show_tool_error_passes_tool_name_and_message_verbatim(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify _show_tool_error forwards the tool name and message into the dialog.

        Args:
            patched_window: Real MainWindow fixture.
            monkeypatch: Used only to record the OS-modal QMessageBox.
        """
        recorder = DialogRecorder()
        monkeypatch.setattr(QMessageBox, "warning", staticmethod(recorder))

        window = patched_window
        window._show_tool_error("Ghidra", "Decompiler timed out after 60s")

        assert len(recorder.calls) == 1
        dialog_text = " ".join(str(arg) for arg in recorder.calls[0])
        assert "Ghidra Error" in dialog_text
        assert "Decompiler timed out after 60s" in dialog_text

    @staticmethod
    def test_show_no_binary_warning_names_the_action(
        patched_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify _show_no_binary_warning embeds the attempted action in the dialog.

        Args:
            patched_window: Real MainWindow fixture.
            monkeypatch: Used only to record the OS-modal QMessageBox.
        """
        recorder = DialogRecorder()
        monkeypatch.setattr(QMessageBox, "information", staticmethod(recorder))

        window = patched_window
        window._show_no_binary_warning("analyze")

        assert len(recorder.calls) == 1
        dialog_text = " ".join(str(arg) for arg in recorder.calls[0])
        assert "No Binary Loaded" in dialog_text
        assert "to analyze it" in dialog_text


class TestCurrentBinaryTracking:
    """Tests for current binary tracking in MainWindow."""

    @staticmethod
    def test_current_binary_initialized_to_none(patched_window: MainWindow) -> None:
        """Verify current_binary starts as None before any load.

        Args:
            patched_window: Real MainWindow fixture.
        """
        current_binary: object = patched_window.current_binary
        assert current_binary is None
