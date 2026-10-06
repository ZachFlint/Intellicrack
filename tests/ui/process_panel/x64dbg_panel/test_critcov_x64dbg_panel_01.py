# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the desktop window lookup, embed/mirror polling and debug-control slots of the x64dbg panel.

Every test drives a real ``X64DbgPanel``. Bridge-backed slots run against ``ScriptedBridge``, a subclass of the real ``X64DbgBridge`` that
replaces only the two methods crossing the process boundary to the debugger (``_send_pipe_command`` and ``_send_command``); the coroutine each
slot builds is the production bridge method, so the console text and button state the panel shows come from the real error and success
paths. Expected console text follows the panel's documented message prefixes, and the commands the bridge would send are derived from the
x64dbg command syntax documented in the bridge docstrings. Window lookup is exercised against real top-level windows the test creates in
its own process with their own ctypes prototypes, and the hidden-desktop child process is a plain Python interpreter that never creates a
window. Lines that need x64dbg or a window living on another desktop are not exercised.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import os
import sys
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QFileDialog, QSpacerItem, QTableWidgetItem, QWidget

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core import win32_desktop_process as desktop_module
from intellicrack.core.types import ToolError
from intellicrack.core.win32_desktop_process import HiddenDesktop, spawn_on_hidden_desktop
from intellicrack.ui.panels import x64dbg_panel as panel_module
from intellicrack.ui.panels.async_bridge import bridge_workers_for, drain_bridge_workers_for, worker_is_running
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel, find_window_by_pid_on_desktop


if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Iterator, Mapping

    from PyQt6.QtWidgets import QApplication
    from pytestqt.qtbot import QtBot

    from intellicrack.bridges.x64dbg import PipeCommandResult
    from intellicrack.core.win32_desktop_process import DesktopProcess


_Dynamic = Any

_WAIT_MS: int = 20_000
_DRAIN_MS: int = 5_000
_SETTLE_ROUNDS: int = 10
_CHILD_WAIT_S: float = 10.0
_DEAD_PID: int = 3_999_996
_CODE_ADDRESS: int = 0x401000
_CHILD_SOURCE: str = "import time\ntime.sleep(60)\n"

_WINDOW_WIDTH: int = 320
_WINDOW_HEIGHT: int = 200
_WS_OVERLAPPEDWINDOW: int = 0x00CF0000
_GARBAGE_HWND: int = 0xDEADBEEF
_WINDOW_TITLE: str = "CritcovX64dbgPanelWindow"

_EMBED_MAX_RETRIES: int = getattr(panel_module, "_EMBED_MAX_RETRIES")
_resolve_hwnd: Callable[[int], int | None] = cast("Callable[[int], int | None]", getattr(panel_module, "_resolve_debugger_window_hwnd"))
_hex_width: Callable[[dict[str, int], str], int | None] = cast(
    "Callable[[dict[str, int], str], int | None]",
    getattr(panel_module, "_extended_register_hex_width"),
)

_NO_BRIDGE_SLOTS: list[str] = [
    "_on_run",
    "_on_pause",
    "_on_stop",
    "_on_restart",
    "_on_step_into",
    "_on_step_over",
    "_on_step_out",
    "_on_step_into_user_code",
    "_on_step_into_system_code",
    "_on_step_extended",
    "_on_step_count",
    "_on_animate_start",
    "_on_animate_stop",
    "_on_set_default_breakpoint_type",
]
_FAILING_DISPATCH: list[tuple[str, str | None, str]] = [
    ("_on_run", "_run_btn", "[-] Run failed:"),
    ("_on_pause", "_pause_btn", "[-] Pause failed:"),
    ("_on_stop", "_stop_btn", "[-] Stop failed:"),
    ("_on_restart", "_restart_btn", "[-] Restart failed:"),
    ("_on_step_into", "_step_into_btn", "[-] Step into failed:"),
    ("_on_step_over", "_step_over_btn", "[-] Step over failed:"),
    ("_on_step_out", "_step_out_btn", "[-] Step out failed:"),
    ("_on_step_into_user_code", None, "[-] Step user failed:"),
    ("_on_step_into_system_code", None, "[-] Step system failed:"),
    ("_on_step_extended", "_step_ext_btn", "[-] Step Ext failed:"),
    ("_on_animate_start", "_animate_start_btn", "[-] Animate start failed:"),
    ("_on_animate_stop", "_animate_stop_btn", "[-] Animate stop failed:"),
]
_ERROR_HANDLERS: list[tuple[str, str, str]] = [
    ("_on_attach_error", "_attach_btn", "[-] Attach failed: boom"),
    ("_on_run_error", "_run_btn", "[-] Run failed: boom"),
    ("_on_pause_error", "_pause_btn", "[-] Pause failed: boom"),
    ("_on_stop_error", "_stop_btn", "[-] Stop failed: boom"),
    ("_on_restart_error", "_restart_btn", "[-] Restart failed: boom"),
    ("_on_step_extended_error", "_step_ext_btn", "[-] Step Ext failed: boom"),
    ("_on_step_count_error", "_step_count_btn", "[-] Step N failed: boom"),
    ("_on_animate_start_error", "_animate_start_btn", "[-] Animate start failed: boom"),
    ("_on_animate_stop_error", "_animate_stop_btn", "[-] Animate stop failed: boom"),
    ("_on_bp_add_error", "_add_bp_btn", "[-] Failed to set breakpoint: boom"),
    ("_on_range_bp_add_error", "_add_range_bp_btn", "[-] Failed to set memory range breakpoint: boom"),
    ("_on_bp_remove_error", "_remove_bp_btn", "[-] Failed to remove breakpoint: boom"),
]
_BP_ACTIONS: list[tuple[str, str, str]] = [
    ("_on_remove_breakpoint", "_remove_bp_btn", "[-] Failed to remove breakpoint:"),
    ("_on_enable_breakpoint", "_enable_bp_btn", "[-] Failed to enable breakpoint:"),
    ("_on_disable_breakpoint", "_disable_bp_btn", "[-] Failed to disable breakpoint:"),
]


class ScriptedBridge(X64DbgBridge):
    """Real ``X64DbgBridge`` whose debugger transport answers from a script.

    Only ``_send_pipe_command`` and ``_send_command`` are replaced. A pipe command with no scripted reply fails with ``ToolError``, and
    console commands are recorded and fail with ``ToolError`` unless ``fail_commands`` is cleared. The plugin is marked deployed so the
    panel enables its debug controls.
    """

    def __init__(self, replies: Mapping[str, PipeCommandResult] | None = None, *, fail_commands: bool = True) -> None:
        """Create the bridge with its scripted pipe replies.

        Args:
            replies: Reply returned for each RPC name; absent names fail.
            fail_commands: Whether console commands fail instead of succeeding.
        """
        super().__init__()
        self.replies: dict[str, PipeCommandResult] = dict(replies or {})
        self.fail_commands: bool = fail_commands
        self.sent_commands: list[str] = []
        self._plugin_deployed = True

    async def _send_pipe_command(
        self,
        command: str,
        params: dict[str, Any] | None = None,
    ) -> PipeCommandResult:
        """Return the scripted reply for ``command``.

        Args:
            command: RPC name requested by the production code.
            params: RPC parameters requested by the production code.

        Returns:
            PipeCommandResult: The scripted reply.

        Raises:
            ToolError: When no reply is scripted for ``command``.
        """
        del params
        await asyncio.sleep(0)
        if command in self.replies:
            return self.replies[command]
        msg = f"no scripted reply for {command}"
        raise ToolError(msg, tool_name="x64dbg")

    async def _send_command(self, command: str) -> str:
        """Record the console command instead of sending it.

        Args:
            command: Console command text built by the production code.

        Returns:
            str: Always an empty command output.

        Raises:
            ToolError: When ``fail_commands`` is set.
        """
        await asyncio.sleep(0)
        self.sent_commands.append(command)
        if self.fail_commands:
            msg = "x64dbg not running"
            raise ToolError(msg, tool_name="x64dbg")
        return ""


class _WindowApi:
    """Independent ctypes bindings the tests use to create real top-level windows in this process."""

    def __init__(self) -> None:
        """Load ``user32`` and ``kernel32`` and declare the prototypes from the Windows SDK."""
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        self.create_window = user32.CreateWindowExW
        self.create_window.restype = wintypes.HWND
        self.create_window.argtypes = [
            wintypes.DWORD,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.HWND,
            wintypes.HANDLE,
            wintypes.HANDLE,
            wintypes.LPVOID,
        ]
        self.destroy_window = user32.DestroyWindow
        self.destroy_window.restype = wintypes.BOOL
        self.destroy_window.argtypes = [wintypes.HWND]
        self.is_window_visible = user32.IsWindowVisible
        self.is_window_visible.restype = wintypes.BOOL
        self.is_window_visible.argtypes = [wintypes.HWND]
        self.get_thread_desktop = user32.GetThreadDesktop
        self.get_thread_desktop.restype = wintypes.HANDLE
        self.get_thread_desktop.argtypes = [wintypes.DWORD]
        self.get_current_thread_id = kernel32.GetCurrentThreadId
        self.get_current_thread_id.restype = wintypes.DWORD
        self.get_current_thread_id.argtypes = []

    def thread_desktop(self) -> int:
        """Return the handle of the desktop the calling thread runs on.

        Returns:
            int: The desktop handle; it is owned by the thread and must not be closed.
        """
        handle = self.get_thread_desktop(self.get_current_thread_id())
        assert handle
        return int(handle)


@contextlib.contextmanager
def _window(api: _WindowApi, title: str) -> Generator[int]:
    """Create a real, never-shown top-level window in this process and destroy it afterwards.

    Args:
        api: Window bindings.
        title: Window caption.

    Yields:
        int: The window handle.
    """
    hwnd = api.create_window(
        0,
        "Static",
        title,
        _WS_OVERLAPPEDWINDOW,
        0,
        0,
        _WINDOW_WIDTH,
        _WINDOW_HEIGHT,
        None,
        None,
        None,
        None,
    )
    assert hwnd
    try:
        assert not api.is_window_visible(hwnd)
        yield int(hwnd)
    finally:
        api.destroy_window(hwnd)


@contextlib.contextmanager
def _registered_desktop(pid: int, hdesk: int) -> Generator[None]:
    """Register ``hdesk`` as the desktop of ``pid`` in the process-to-desktop registry.

    Args:
        pid: Process id to register.
        hdesk: Desktop handle the process is said to run on.

    Yields:
        None: Control while the registration is in place.
    """
    registry: dict[int, int] = getattr(desktop_module, "_pid_desktop_handles")
    registry[pid] = hdesk
    try:
        yield
    finally:
        registry.pop(pid, None)


def _priv(obj: object, name: str) -> _Dynamic:
    """Read a private attribute or method of a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.

    Returns:
        _Dynamic: The attribute value.
    """
    return getattr(obj, name)


def _set_priv(obj: object, name: str, value: object) -> None:
    """Assign a private data attribute on a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.
        value: Value to store.
    """
    setattr(obj, name, value)


def _invoke(obj: object, name: str, *args: object) -> _Dynamic:
    """Call a private method of a product object.

    Args:
        obj: Object that owns the method.
        name: Method name.
        *args: Positional arguments for the method.

    Returns:
        _Dynamic: The method result.
    """
    return getattr(obj, name)(*args)


def _console(panel: X64DbgPanel) -> str:
    """Read the panel console text.

    Args:
        panel: Panel under test.

    Returns:
        str: The full console text.
    """
    return str(_priv(panel, "_console_output").toPlainText())


def _status(panel: X64DbgPanel) -> str:
    """Read the panel toolbar status text.

    Args:
        panel: Panel under test.

    Returns:
        str: The status label text.
    """
    label = panel.status_label
    assert label is not None
    return label.text()


def _wait_console(qtbot: QtBot, panel: X64DbgPanel, fragment: str) -> None:
    """Spin the event loop until the console contains ``fragment``.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        panel: Panel under test.
        fragment: Text that must appear in the console.
    """
    qtbot.waitUntil(lambda: fragment in _console(panel), timeout=_WAIT_MS)


def _settle(panel: X64DbgPanel, qapp: QApplication) -> None:
    """Join every bridge worker the panel owns and deliver its results.

    Args:
        panel: Panel whose workers are joined.
        qapp: Application whose queued events are delivered.
    """
    for _ in range(_SETTLE_ROUNDS):
        drain_bridge_workers_for(panel, _DRAIN_MS)
        qapp.processEvents()
        if not any(worker_is_running(worker) for worker in bridge_workers_for(panel)):
            break


def _select_bp_row(panel: X64DbgPanel, text: str | None) -> None:
    """Create one breakpoint table row and make it current.

    Args:
        panel: Panel under test.
        text: Text of the address cell, or ``None`` to leave the cell empty.
    """
    table = _priv(panel, "_bp_table")
    table.setRowCount(1)
    if text is not None:
        table.setItem(0, 0, QTableWidgetItem(text))
    table.setCurrentCell(0, 0)


def _chooser(chosen: str) -> Callable[..., tuple[str, str]]:
    """Build a stand-in for ``QFileDialog.getOpenFileName`` that picks ``chosen``.

    Args:
        chosen: Path the stand-in returns.

    Returns:
        Callable[..., tuple[str, str]]: The stand-in.
    """

    def _pick(*_args: object, **_kwargs: object) -> tuple[str, str]:
        """Return the chosen path with an empty filter.

        Args:
            *_args: Ignored dialog arguments.
            **_kwargs: Ignored dialog keyword arguments.

        Returns:
            tuple[str, str]: The chosen path and an empty selected filter.
        """
        return (chosen, "")

    return _pick


@pytest.fixture
def panel(qapp: QApplication) -> Iterator[X64DbgPanel]:
    """Build a real panel and join everything it started on teardown.

    Args:
        qapp: Shared offscreen application.

    Yields:
        X64DbgPanel: The panel under test.
    """
    widget = X64DbgPanel()
    try:
        yield widget
    finally:
        _invoke(widget, "_stop_embed_timer")
        _invoke(widget, "_stop_mirror_timer")
        _settle(widget, qapp)
        widget.close()
        qapp.processEvents()


@pytest.fixture
def bridge(panel: X64DbgPanel) -> ScriptedBridge:
    """Attach a scripted bridge whose debugger commands all fail to the panel.

    Args:
        panel: Panel under test.

    Returns:
        ScriptedBridge: The attached bridge.
    """
    scripted = ScriptedBridge()
    panel.set_bridge(scripted)
    return scripted


@pytest.fixture
def own_windows() -> _WindowApi:
    """Provide the window bindings.

    Returns:
        _WindowApi: Freshly declared bindings.
    """
    return _WindowApi()


@pytest.fixture
def hidden_child() -> Iterator[DesktopProcess]:
    """Run a window-less Python child on a hidden desktop and reap it afterwards.

    Yields:
        DesktopProcess: The running child.
    """
    process = spawn_on_hidden_desktop(Path(sys.executable), ["-c", _CHILD_SOURCE])
    try:
        yield process
    finally:
        try:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=_CHILD_WAIT_S)
        finally:
            process.close()


def test_mxcsr_width_is_eight_hex_digits_independent_of_the_table() -> None:
    """MXCSR is a 32-bit register, so it is eight hex digits whatever the width table says."""
    assert _hex_width({}, "mxcsr") == 8
    assert _hex_width({"mxcsr": 99}, "  MXCSR ") == 8


def test_desktop_finder_ignores_invisible_windows(own_windows: _WindowApi) -> None:
    """A titled window of the requested process that is not visible is skipped.

    Args:
        own_windows: Window bindings.
    """
    with _window(own_windows, _WINDOW_TITLE):
        assert find_window_by_pid_on_desktop(own_windows.thread_desktop(), os.getpid()) is None


def test_desktop_finder_reports_nothing_on_an_empty_desktop() -> None:
    """A freshly created desktop holds no window of this process."""
    with HiddenDesktop() as desktop:
        assert find_window_by_pid_on_desktop(desktop.handle, os.getpid()) is None


def test_resolver_falls_back_to_the_default_desktop_for_an_unregistered_pid() -> None:
    """A pid with no registered desktop is looked up on the calling thread's desktop and not found."""
    assert _resolve_hwnd(_DEAD_PID) is None


def test_resolver_falls_back_when_the_registered_desktop_has_no_window() -> None:
    """A registered desktop without the process's window falls back to the default desktop, which has none."""
    with HiddenDesktop() as desktop, _registered_desktop(os.getpid(), desktop.handle):
        assert _resolve_hwnd(os.getpid()) is None


def test_start_mirror_capture_builds_the_mirror_view_for_a_window_it_cannot_capture(panel: X64DbgPanel) -> None:
    """The mirror view is installed even when the first capture of the handle fails.

    A garbage handle makes ``GetWindowRect`` fail, so the capture yields no frame and the label stays empty.

    Args:
        panel: Panel under test.
    """
    host_layout = panel.embed_host.layout()
    assert host_layout is not None
    status_label = _priv(panel, "_embed_status_label")
    assert host_layout.count() == 1

    _invoke(panel, "_start_mirror_capture", _GARBAGE_HWND, 4321)

    assert _priv(panel, "_mirror_hwnd") == _GARBAGE_HWND
    label = _priv(panel, "_mirror_label")
    assert label is not None
    assert host_layout.count() == 1
    item = host_layout.itemAt(0)
    assert item is not None
    assert item.widget() is label
    assert status_label.parent() is None
    assert (label.minimumWidth(), label.minimumHeight()) == (200, 150)
    timer = _priv(panel, "_mirror_timer")
    assert timer is not None
    assert timer.isActive()
    assert timer.interval() == 250
    assert label.pixmap().isNull()
    assert _priv(panel, "_main_tabs").currentWidget() is panel.embed_host


def test_poll_tick_keeps_polling_within_the_retry_budget(panel: X64DbgPanel) -> None:
    """A tick that finds no window leaves the poll timer running.

    Args:
        panel: Panel under test.
    """
    timer = QTimer(panel)
    timer.setInterval(60_000)
    timer.start()
    _set_priv(panel, "_embed_timer", timer)
    try:
        _invoke(panel, "_poll_embed_tick", _DEAD_PID)

        assert _priv(panel, "_embed_attempts") == 1
        assert _priv(panel, "_embed_timer") is timer
        assert timer.isActive()
    finally:
        timer.stop()


def test_poll_tick_stops_the_timer_when_the_retry_budget_is_spent(panel: X64DbgPanel) -> None:
    """The tick that exhausts the retry budget stops and discards the poll timer.

    Args:
        panel: Panel under test.
    """
    timer = QTimer(panel)
    timer.setInterval(60_000)
    timer.start()
    _set_priv(panel, "_embed_timer", timer)
    _set_priv(panel, "_embed_attempts", _EMBED_MAX_RETRIES - 1)
    try:
        _invoke(panel, "_poll_embed_tick", _DEAD_PID)

        assert _priv(panel, "_embed_attempts") == _EMBED_MAX_RETRIES
        assert _priv(panel, "_embed_timer") is None
        assert not timer.isActive()
    finally:
        timer.stop()


def test_start_mirror_capture_does_nothing_once_the_embed_was_cancelled(panel: X64DbgPanel) -> None:
    """A cancelled embed never starts a mirror.

    Args:
        panel: Panel under test.
    """
    _set_priv(panel, "_embed_cancelled", value=True)

    _invoke(panel, "_start_mirror_capture", 0x1234, 4321)

    assert _priv(panel, "_mirror_label") is None
    assert _priv(panel, "_mirror_timer") is None
    assert _priv(panel, "_mirror_hwnd") is None


def test_embed_window_ready_replaces_the_placeholder_with_the_container(panel: X64DbgPanel) -> None:
    """The embed host ends up holding only the container, and the tab switches to it.

    Args:
        panel: Panel under test.
    """
    host_layout = panel.embed_host.layout()
    assert host_layout is not None
    host_layout.addItem(QSpacerItem(0, 0))
    status_label = _priv(panel, "_embed_status_label")
    container = QWidget()
    assert _priv(panel, "_main_tabs").currentIndex() == 0

    _invoke(panel, "_embed_window_ready", container, 4321)

    assert host_layout.count() == 1
    item = host_layout.itemAt(0)
    assert item is not None
    assert item.widget() is container
    assert status_label.parent() is None
    assert panel.embedded_container is container
    assert _priv(panel, "_main_tabs").currentWidget() is panel.embed_host


def test_cleanup_releases_the_embedded_container(panel: X64DbgPanel) -> None:
    """Teardown detaches the embedded window container and forgets it.

    Args:
        panel: Panel under test.
    """
    container = QWidget(panel.embed_host)
    panel.embedded_container = container

    _invoke(panel, "_cleanup")

    assert panel.embedded_container is None
    assert container.parent() is None


def test_reset_debug_views_releases_the_embedded_container_and_restores_the_placeholder(panel: X64DbgPanel) -> None:
    """Stopping a session drops the embedded window and shows the placeholder again.

    Args:
        panel: Panel under test.
    """
    host_layout = panel.embed_host.layout()
    assert host_layout is not None
    container = QWidget()
    host_layout.addWidget(container)
    host_layout.addItem(QSpacerItem(0, 0))
    panel.embedded_container = container

    _invoke(panel, "_reset_debug_views")

    assert panel.embedded_container is None
    assert container.parent() is None
    assert host_layout.count() == 1
    item = host_layout.itemAt(0)
    assert item is not None
    assert item.widget() is _priv(panel, "_embed_status_label")


def test_try_embed_without_a_bridge_starts_nothing(panel: X64DbgPanel) -> None:
    """With no bridge there is no debugger window to poll for.

    Args:
        panel: Panel under test.
    """
    _invoke(panel, "_try_embed_debugger_window")

    assert _priv(panel, "_embed_timer") is None


def test_try_embed_without_a_debugger_process_starts_nothing(panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """A bridge that tracks no debugger process starts no poll timer.

    Args:
        panel: Panel under test.
        bridge: Attached bridge with no debugger process.
    """
    assert bridge.debugger_pid is None

    _invoke(panel, "_try_embed_debugger_window")

    assert _priv(panel, "_embed_timer") is None


@pytest.mark.spawns_process
def test_try_embed_polls_for_the_window_of_the_debugger_process(
    panel: X64DbgPanel,
    bridge: ScriptedBridge,
    hidden_child: DesktopProcess,
    qtbot: QtBot,
) -> None:
    """A tracked debugger process gets a running poll timer whose ticks look for its window.

    Args:
        panel: Panel under test.
        bridge: Attached bridge.
        hidden_child: Window-less child standing in as the debugger process.
        qtbot: pytest-qt fixture used to spin the event loop.
    """
    _set_priv(bridge, "_process", hidden_child)
    try:
        assert bridge.debugger_pid == hidden_child.pid
        _set_priv(panel, "_embed_cancelled", value=True)
        _set_priv(panel, "_embed_attempts", 7)

        _invoke(panel, "_try_embed_debugger_window")

        timer = _priv(panel, "_embed_timer")
        assert timer is not None
        assert timer.isActive()
        assert timer.interval() == 500
        assert _priv(panel, "_embed_cancelled") is False
        assert _priv(panel, "_embed_attempts") == 0

        qtbot.waitUntil(lambda: _priv(panel, "_embed_attempts") >= 1, timeout=_WAIT_MS)
        assert _priv(panel, "_mirror_label") is None
        assert panel.embedded_container is None
    finally:
        _invoke(panel, "_stop_embed_timer")
        _set_priv(bridge, "_process", None)


def test_set_bridge_unregisters_the_callback_from_the_previous_bridge(panel: X64DbgPanel) -> None:
    """Replacing the bridge moves the panel's event callback to the new bridge.

    Args:
        panel: Panel under test.
    """
    first = ScriptedBridge()
    second = ScriptedBridge()
    callback = _priv(panel, "_on_debug_event")

    panel.set_bridge(first)
    assert first.event_callbacks == [callback]
    panel.set_bridge(second)

    assert first.event_callbacks == []
    assert second.event_callbacks == [callback]
    assert panel.get_bridge() is second


def test_toggling_the_64bit_checkbox_updates_the_panel_architecture(panel: X64DbgPanel) -> None:
    """Unchecking and rechecking the toolbar checkbox switches the panel architecture flag.

    Args:
        panel: Panel under test.
    """
    toggle = _priv(panel, "_64bit_toggle")
    assert _priv(panel, "_is_64bit") is True

    toggle.setChecked(False)
    assert _priv(panel, "_is_64bit") is False
    toggle.setChecked(True)
    assert _priv(panel, "_is_64bit") is True


def test_debug_file_without_a_bridge_refuses(panel: X64DbgPanel, tmp_path: Path) -> None:
    """Loading a file with no bridge reports failure and leaves the load button enabled.

    Args:
        panel: Panel under test.
        tmp_path: Per-test directory.
    """
    assert panel.debug_file(tmp_path / "target.exe") is False

    assert _priv(panel, "_load_btn").isEnabled()
    assert bridge_workers_for(panel) == []


def test_load_dialog_cancel_loads_nothing(panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """Cancelling the file dialog starts no load.

    Args:
        panel: Panel under test.
        bridge: Attached bridge.
    """
    _invoke(panel, "_on_load")

    assert _priv(panel, "_load_btn").isEnabled()
    assert bridge_workers_for(panel) == []
    assert bridge.sent_commands == []


def test_load_dialog_choice_of_a_missing_file_reports_the_failure(
    panel: X64DbgPanel,
    bridge: ScriptedBridge,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    qtbot: QtBot,
) -> None:
    """Choosing a file that does not exist ends in a load-failed status and a re-enabled button.

    Args:
        panel: Panel under test.
        bridge: Attached bridge.
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Per-test directory.
        qtbot: pytest-qt fixture used to spin the event loop.
    """
    missing = tmp_path / "missing.exe"
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _chooser(str(missing)))

    _invoke(panel, "_on_load")

    assert not _priv(panel, "_load_btn").isEnabled()
    qtbot.waitUntil(lambda: _status(panel).startswith("Load failed:"), timeout=_WAIT_MS)
    assert "File not found" in _status(panel)
    assert _priv(panel, "_load_btn").isEnabled()
    assert bridge.sent_commands == []


def test_load_success_updates_status_and_architecture(panel: X64DbgPanel) -> None:
    """A finished load shows the file name and adopts the bridge's architecture.

    Args:
        panel: Panel under test.
    """
    scripted = ScriptedBridge()
    scripted.is_64bit = False
    panel.set_bridge(scripted)
    _priv(panel, "_load_btn").setEnabled(False)

    _invoke(panel, "_on_load_success", Path("target.exe"))

    assert _status(panel) == "Loaded: target.exe"
    assert _priv(panel, "_load_btn").isEnabled()
    assert _priv(panel, "_is_64bit") is False
    assert not _priv(panel, "_64bit_toggle").isChecked()


def test_load_success_without_a_bridge_keeps_the_controls_consistent(panel: X64DbgPanel) -> None:
    """A finished load with no bridge re-enables the button and finds no debugger window to embed.

    Args:
        panel: Panel under test.
    """
    _priv(panel, "_load_btn").setEnabled(False)

    _invoke(panel, "_on_load_success", Path("target.exe"))

    assert _priv(panel, "_load_btn").isEnabled()
    assert _priv(panel, "_embed_timer") is None
    assert _status(panel) == "No bridge configured"


def test_load_failure_reports_the_error(panel: X64DbgPanel) -> None:
    """A failed load shows the error and re-enables the load button.

    Args:
        panel: Panel under test.
    """
    _priv(panel, "_load_btn").setEnabled(False)

    _invoke(panel, "_on_load_error", Path("target.exe"), ToolError("boom"))

    assert _status(panel) == "Load failed: boom"
    assert _priv(panel, "_load_btn").isEnabled()


def test_sync_64bit_toggle_ignores_a_missing_bridge(panel: X64DbgPanel) -> None:
    """Without a bridge the checkbox keeps its state.

    Args:
        panel: Panel under test.
    """
    _invoke(panel, "_sync_64bit_toggle")

    assert _priv(panel, "_is_64bit") is True
    assert _priv(panel, "_64bit_toggle").isChecked()


def test_attach_requires_a_bridge(panel: X64DbgPanel) -> None:
    """Attaching with no bridge says so on the console.

    Args:
        panel: Panel under test.
    """
    _invoke(panel, "_on_attach")

    assert _console(panel) == "[!] No bridge configured"


@pytest.mark.parametrize(
    ("text", "expected"),
    [("", "[!] Enter a PID"), ("  ", "[!] Enter a PID"), ("abc", "[!] Invalid PID: abc")],
)
def test_attach_rejects_unusable_pid_text(panel: X64DbgPanel, bridge: ScriptedBridge, text: str, expected: str) -> None:
    """A blank or non-numeric PID is reported without dispatching anything.

    Args:
        panel: Panel under test.
        bridge: Attached bridge.
        text: Text typed into the PID field.
        expected: Console line the panel must show.
    """
    _priv(panel, "_pid_input").setText(text)

    _invoke(panel, "_on_attach")

    assert _console(panel) == expected
    assert _priv(panel, "_attach_btn").isEnabled()
    assert bridge_workers_for(panel) == []
    assert bridge.sent_commands == []


def test_attach_to_an_unopenable_pid_reports_the_failure(panel: X64DbgPanel, bridge: ScriptedBridge, qtbot: QtBot) -> None:
    """Attaching to a pid whose architecture cannot be read ends in an attach-failed line and a re-enabled button.

    Args:
        panel: Panel under test.
        bridge: Attached bridge.
        qtbot: pytest-qt fixture used to spin the event loop.
    """
    _priv(panel, "_pid_input").setText(f" {_DEAD_PID} ")

    _invoke(panel, "_on_attach")

    assert not _priv(panel, "_attach_btn").isEnabled()
    _wait_console(qtbot, panel, "[-] Attach failed:")
    assert f"pid {_DEAD_PID}" in _console(panel)
    assert _priv(panel, "_attach_btn").isEnabled()
    assert bridge.attached_pid is None


def test_attach_success_reports_the_pid_and_adopts_the_architecture(panel: X64DbgPanel) -> None:
    """A finished attach shows the pid and adopts the bridge's architecture.

    Args:
        panel: Panel under test.
    """
    scripted = ScriptedBridge()
    scripted.is_64bit = False
    panel.set_bridge(scripted)
    _priv(panel, "_attach_btn").setEnabled(False)

    _invoke(panel, "_on_attach_success", 1234)

    assert _status(panel) == "Attached: PID 1234"
    assert _console(panel) == "[+] Attached to PID 1234"
    assert _priv(panel, "_attach_btn").isEnabled()
    assert _priv(panel, "_is_64bit") is False
    assert not _priv(panel, "_64bit_toggle").isChecked()


@pytest.mark.parametrize("slot", _NO_BRIDGE_SLOTS)
def test_slots_do_nothing_without_a_bridge(panel: X64DbgPanel, slot: str) -> None:
    """Every debug-control slot is inert when no bridge is set.

    Args:
        panel: Panel under test.
        slot: Name of the slot under test.
    """
    before = _console(panel)

    _invoke(panel, slot)

    assert _console(panel) == before
    assert bridge_workers_for(panel) == []


@pytest.mark.parametrize("slot", ["_on_add_breakpoint", "_on_add_range_breakpoint"])
def test_breakpoint_adds_say_when_no_bridge_is_set(panel: X64DbgPanel, slot: str) -> None:
    """Adding a breakpoint without a bridge says so on the console.

    Args:
        panel: Panel under test.
        slot: Name of the slot under test.
    """
    _invoke(panel, slot)

    assert _console(panel) == "[!] No bridge configured"
    assert bridge_workers_for(panel) == []


@pytest.mark.parametrize(("slot", "button", "fragment"), _FAILING_DISPATCH)
def test_failing_bridge_calls_end_in_the_error_handler(
    panel: X64DbgPanel,
    bridge: ScriptedBridge,
    qtbot: QtBot,
    slot: str,
    button: str | None,
    fragment: str,
) -> None:
    """A bridge call that fails shows its failure line and re-enables the control.

    Args:
        panel: Panel under test.
        bridge: Attached bridge whose debugger calls fail.
        qtbot: pytest-qt fixture used to spin the event loop.
        slot: Name of the slot under test.
        button: Attribute name of the control the slot disables while the call runs, if any.
        fragment: Console text the failure must produce.
    """
    del bridge

    _invoke(panel, slot)

    if button is not None:
        assert not _priv(panel, button).isEnabled()
    _wait_console(qtbot, panel, fragment)
    if button is not None:
        assert _priv(panel, button).isEnabled()


def test_step_failures_re_enable_every_step_button(panel: X64DbgPanel, bridge: ScriptedBridge, qtbot: QtBot) -> None:
    """A failed step re-enables all three plain step buttons.

    Args:
        panel: Panel under test.
        bridge: Attached bridge whose debugger calls fail.
        qtbot: pytest-qt fixture used to spin the event loop.
    """
    del bridge
    for name in ("_step_into_btn", "_step_over_btn", "_step_out_btn"):
        _priv(panel, name).setEnabled(False)

    _invoke(panel, "_on_step_over")
    _wait_console(qtbot, panel, "[-] Step over failed:")

    for name in ("_step_into_btn", "_step_over_btn", "_step_out_btn"):
        assert _priv(panel, name).isEnabled()


def test_extended_step_sends_the_selected_direction_and_mode(panel: X64DbgPanel, bridge: ScriptedBridge, qtbot: QtBot) -> None:
    """The extended step sends the x64dbg command for the chosen direction and exception mode.

    Args:
        panel: Panel under test.
        bridge: Attached bridge whose debugger calls fail.
        qtbot: pytest-qt fixture used to spin the event loop.
    """
    _priv(panel, "_step_ext_type_combo").setCurrentIndex(1)
    _priv(panel, "_step_ext_mode_combo").setCurrentIndex(1)

    _invoke(panel, "_on_step_extended")
    _wait_console(qtbot, panel, "[-] Step Ext failed:")

    assert bridge.sent_commands == ["seStepOver 1"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [("", "[!] Invalid step count: "), ("0", "[!] Step count must be positive"), ("-3", "[!] Step count must be positive")],
)
def test_step_count_rejects_unusable_counts(panel: X64DbgPanel, bridge: ScriptedBridge, text: str, expected: str) -> None:
    """A blank, zero or negative step count is reported without dispatching anything.

    Args:
        panel: Panel under test.
        bridge: Attached bridge.
        text: Text typed into the step count field.
        expected: Console line the panel must show.
    """
    _priv(panel, "_step_count_input").setText(text)

    _invoke(panel, "_on_step_count")

    assert _console(panel) == expected
    assert bridge_workers_for(panel) == []
    assert bridge.sent_commands == []


def test_step_count_sends_the_requested_number_of_steps(panel: X64DbgPanel, bridge: ScriptedBridge, qtbot: QtBot) -> None:
    """The step count reaches x64dbg as the budget of a conditional trace into.

    Args:
        panel: Panel under test.
        bridge: Attached bridge whose debugger calls fail.
        qtbot: pytest-qt fixture used to spin the event loop.
    """
    _priv(panel, "_step_count_input").setText("3")

    _invoke(panel, "_on_step_count")
    assert not _priv(panel, "_step_count_btn").isEnabled()
    _wait_console(qtbot, panel, "[-] Step N failed:")

    assert bridge.sent_commands == ["TraceIntoConditional 0, 3"]
    assert _priv(panel, "_step_count_btn").isEnabled()


def test_animate_start_runs_a_bounded_conditional_trace(panel: X64DbgPanel, bridge: ScriptedBridge, qtbot: QtBot) -> None:
    """Animation starts as an effectively unbounded conditional trace into.

    Args:
        panel: Panel under test.
        bridge: Attached bridge whose debugger calls fail.
        qtbot: pytest-qt fixture used to spin the event loop.
    """
    _invoke(panel, "_on_animate_start")
    _wait_console(qtbot, panel, "[-] Animate start failed:")

    assert bridge.sent_commands == ["TraceIntoConditional 0, 1000000000"]


@pytest.mark.parametrize(
    ("slot", "rpc", "button", "line", "status"),
    [
        ("_on_run", "run", "_run_btn", "[+] Execution continued", "Running"),
        ("_on_stop", "stop", "_stop_btn", "[+] Debugging stopped", "Stopped"),
    ],
)
def test_successful_bridge_calls_end_in_the_success_handler(
    panel: X64DbgPanel,
    qtbot: QtBot,
    slot: str,
    rpc: str,
    button: str,
    line: str,
    status: str,
) -> None:
    """A bridge call that succeeds shows its success line and status and re-enables the control.

    Args:
        panel: Panel under test.
        qtbot: pytest-qt fixture used to spin the event loop.
        slot: Name of the slot under test.
        rpc: Pipe command the bridge answers.
        button: Attribute name of the control the slot disables while the call runs.
        line: Console line the success must produce.
        status: Status text the success must produce.
    """
    panel.set_bridge(ScriptedBridge({rpc: None}))

    _invoke(panel, slot)
    assert not _priv(panel, button).isEnabled()
    _wait_console(qtbot, panel, line)

    assert _status(panel) == status
    assert _priv(panel, button).isEnabled()


def test_pause_success_handler_reports_the_paused_state(panel: X64DbgPanel) -> None:
    """The pause success handler shows its status and console line and re-enables the pause button.

    Args:
        panel: Panel under test.
    """
    _priv(panel, "_pause_btn").setEnabled(False)

    _invoke(panel, "_on_pause_success")

    assert _status(panel) == "Paused"
    assert _console(panel) == "[+] Execution paused"
    assert _priv(panel, "_pause_btn").isEnabled()


@pytest.mark.parametrize(("handler", "button", "line"), _ERROR_HANDLERS)
def test_error_handlers_show_the_failure_and_re_enable_their_control(
    panel: X64DbgPanel,
    handler: str,
    button: str,
    line: str,
) -> None:
    """Each failure handler writes one console line and re-enables the control that started the call.

    Args:
        panel: Panel under test.
        handler: Name of the handler under test.
        button: Attribute name of the control the handler re-enables.
        line: Console line the handler must write.
    """
    _priv(panel, button).setEnabled(False)

    _invoke(panel, handler, ToolError("boom"))

    assert _console(panel) == line
    assert _priv(panel, button).isEnabled()


@pytest.mark.parametrize(
    ("result", "status", "line"),
    [
        (None, "Restarted", "[+] Debuggee restarted (unverified)"),
        ({"path": "C:\\target.exe", "verified": True}, "Restarted: C:\\target.exe", "[+] Debuggee restarted"),
    ],
)
def test_restart_success_reports_the_result(panel: X64DbgPanel, result: object, status: str, line: str) -> None:
    """A finished restart shows the restarted path when the bridge reports one.

    Args:
        panel: Panel under test.
        result: Result the bridge produced.
        status: Status text the panel must show.
        line: Console line the panel must write.
    """
    panel.set_bridge(ScriptedBridge())
    _priv(panel, "_restart_btn").setEnabled(False)

    _invoke(panel, "_on_restart_success", result)

    assert _status(panel) == status
    assert _console(panel) == line
    assert _priv(panel, "_restart_btn").isEnabled()


def test_step_success_reports_the_new_instruction_pointer(panel: X64DbgPanel) -> None:
    """A finished step prints the new instruction pointer in hex.

    Args:
        panel: Panel under test.
    """
    for name in ("_step_into_btn", "_step_over_btn", "_step_out_btn"):
        _priv(panel, name).setEnabled(False)

    _invoke(panel, "_on_step_success", "into", 0x7FF612341000)

    assert _console(panel) == "[+] Step into -> 0x7FF612341000"
    for name in ("_step_into_btn", "_step_over_btn", "_step_out_btn"):
        assert _priv(panel, name).isEnabled()


def test_step_success_without_an_address_prints_nothing(panel: X64DbgPanel) -> None:
    """A step that reports no address writes no console line but still re-enables the buttons.

    Args:
        panel: Panel under test.
    """
    _priv(panel, "_step_out_btn").setEnabled(False)

    _invoke(panel, "_on_step_success", "out", None)

    assert not _console(panel)
    assert _priv(panel, "_step_out_btn").isEnabled()


def test_step_error_names_the_direction_and_re_enables_every_step_button(panel: X64DbgPanel) -> None:
    """A failed step names its direction and re-enables all three step buttons.

    Args:
        panel: Panel under test.
    """
    for name in ("_step_into_btn", "_step_over_btn", "_step_out_btn"):
        _priv(panel, name).setEnabled(False)

    _invoke(panel, "_on_step_error", "out", ToolError("boom"))

    assert _console(panel) == "[-] Step out failed: boom"
    for name in ("_step_into_btn", "_step_over_btn", "_step_out_btn"):
        assert _priv(panel, name).isEnabled()


def test_extended_step_success_prints_the_address_only_when_one_is_reported(panel: X64DbgPanel) -> None:
    """The extended step prints an integer result in hex and stays quiet otherwise.

    Args:
        panel: Panel under test.
    """
    _priv(panel, "_step_ext_btn").setEnabled(False)

    _invoke(panel, "_on_step_extended_success", None)
    assert not _console(panel)
    assert _priv(panel, "_step_ext_btn").isEnabled()

    _invoke(panel, "_on_step_extended_success", _CODE_ADDRESS)
    assert _console(panel) == "[+] Step Ext -> 0x401000"


@pytest.mark.parametrize(
    ("result", "line"),
    [
        (None, "[+] Stepped 0 time(s) (unverified)"),
        ({"count": 5, "verified": True}, "[+] Stepped 5 time(s)"),
    ],
)
def test_step_count_success_reports_the_steps_taken(panel: X64DbgPanel, result: object, line: str) -> None:
    """A finished Step N shows how many steps ran and whether the debugger confirmed it.

    Args:
        panel: Panel under test.
        result: Result the bridge produced.
        line: Console line the panel must write.
    """
    _priv(panel, "_step_count_btn").setEnabled(False)

    _invoke(panel, "_on_step_count_success", result)

    assert _console(panel) == line
    assert _priv(panel, "_step_count_btn").isEnabled()


@pytest.mark.parametrize("text", ["zz", "0xZZ"])
def test_add_breakpoint_rejects_unparsable_addresses(panel: X64DbgPanel, bridge: ScriptedBridge, text: str) -> None:
    """A malformed breakpoint address is reported without dispatching anything.

    Args:
        panel: Panel under test.
        bridge: Attached bridge.
        text: Text typed into the address field.
    """
    _priv(panel, "_bp_addr_input").setText(text)

    _invoke(panel, "_on_add_breakpoint")

    assert _console(panel) == f"[!] Invalid address: {text}"
    assert _priv(panel, "_add_bp_btn").isEnabled()
    assert bridge_workers_for(panel) == []
    assert bridge.sent_commands == []


def test_add_breakpoint_with_a_blank_address_does_nothing(panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """A blank address field adds no breakpoint and prints nothing.

    Args:
        panel: Panel under test.
        bridge: Attached bridge.
    """
    _invoke(panel, "_on_add_breakpoint")

    assert not _console(panel)
    assert bridge_workers_for(panel) == []
    assert bridge.sent_commands == []


def test_add_breakpoint_failure_re_enables_the_button(panel: X64DbgPanel, bridge: ScriptedBridge, qtbot: QtBot) -> None:
    """A breakpoint the debugger rejects shows the failure and re-enables the add button.

    Args:
        panel: Panel under test.
        bridge: Attached bridge whose debugger calls fail.
        qtbot: pytest-qt fixture used to spin the event loop.
    """
    del bridge
    _priv(panel, "_bp_addr_input").setText("0x401000")

    _invoke(panel, "_on_add_breakpoint")
    assert not _priv(panel, "_add_bp_btn").isEnabled()
    _wait_console(qtbot, panel, "[-] Failed to set breakpoint:")

    assert _priv(panel, "_add_bp_btn").isEnabled()


def test_range_breakpoint_with_a_blank_address_does_nothing(panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """A blank address field adds no range breakpoint and prints nothing.

    Args:
        panel: Panel under test.
        bridge: Attached bridge.
    """
    _invoke(panel, "_on_add_range_breakpoint")

    assert not _console(panel)
    assert bridge_workers_for(panel) == []
    assert bridge.sent_commands == []


def test_range_breakpoint_rejects_an_unparsable_address(panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """A malformed range start is reported without dispatching anything.

    Args:
        panel: Panel under test.
        bridge: Attached bridge.
    """
    _priv(panel, "_bp_addr_input").setText("zz")

    _invoke(panel, "_on_add_range_breakpoint")

    assert _console(panel) == "[!] Invalid address: zz"
    assert bridge_workers_for(panel) == []
    assert bridge.sent_commands == []


def test_range_breakpoint_with_a_blank_size_does_nothing(panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """A blank size field adds no range breakpoint and prints nothing.

    Args:
        panel: Panel under test.
        bridge: Attached bridge.
    """
    _priv(panel, "_bp_addr_input").setText("0x401000")

    _invoke(panel, "_on_add_range_breakpoint")

    assert not _console(panel)
    assert bridge_workers_for(panel) == []
    assert bridge.sent_commands == []


def test_range_breakpoint_sends_the_selected_access_and_size(panel: X64DbgPanel, bridge: ScriptedBridge, qtbot: QtBot) -> None:
    """A rejected range breakpoint shows the failure; the command carries the chosen access and size.

    Args:
        panel: Panel under test.
        bridge: Attached bridge whose debugger calls fail.
        qtbot: pytest-qt fixture used to spin the event loop.
    """
    _priv(panel, "_bp_addr_input").setText("0x401000")
    _priv(panel, "_bp_range_size_input").setText("0x1000")
    _priv(panel, "_bp_range_access_combo").setCurrentIndex(1)
    _priv(panel, "_bp_range_singleshot_check").setChecked(True)

    _invoke(panel, "_on_add_range_breakpoint")
    assert not _priv(panel, "_add_range_bp_btn").isEnabled()
    _wait_console(qtbot, panel, "[-] Failed to set memory range breakpoint:")

    assert bridge.sent_commands == ["SetMemoryRangeBPX 0x401000, 0x1000, wss"]
    assert _priv(panel, "_add_range_bp_btn").isEnabled()


@pytest.mark.parametrize(("slot", "button", "fragment"), _BP_ACTIONS)
def test_breakpoint_actions_need_a_selected_row(
    panel: X64DbgPanel,
    bridge: ScriptedBridge,
    slot: str,
    button: str,
    fragment: str,
) -> None:
    """Removing, enabling or disabling with no selected row does nothing.

    Args:
        panel: Panel under test.
        bridge: Attached bridge.
        slot: Name of the slot under test.
        button: Attribute name of the control the slot disables while the call runs.
        fragment: Failure text the slot would produce.
    """
    del fragment
    assert _priv(panel, "_bp_table").currentRow() == -1

    _invoke(panel, slot)

    assert _priv(panel, button).isEnabled()
    assert bridge_workers_for(panel) == []
    assert bridge.sent_commands == []


@pytest.mark.parametrize(("slot", "button", "fragment"), _BP_ACTIONS)
def test_breakpoint_actions_need_an_address_cell(
    panel: X64DbgPanel,
    bridge: ScriptedBridge,
    slot: str,
    button: str,
    fragment: str,
) -> None:
    """A selected row whose address cell is empty is ignored.

    Args:
        panel: Panel under test.
        bridge: Attached bridge.
        slot: Name of the slot under test.
        button: Attribute name of the control the slot disables while the call runs.
        fragment: Failure text the slot would produce.
    """
    del fragment
    _select_bp_row(panel, None)

    _invoke(panel, slot)

    assert _priv(panel, button).isEnabled()
    assert bridge_workers_for(panel) == []
    assert bridge.sent_commands == []


@pytest.mark.parametrize(("slot", "button", "fragment"), _BP_ACTIONS)
def test_breakpoint_actions_ignore_an_unparsable_address_cell(
    panel: X64DbgPanel,
    bridge: ScriptedBridge,
    slot: str,
    button: str,
    fragment: str,
) -> None:
    """A selected row whose address cell is not hexadecimal is ignored.

    Args:
        panel: Panel under test.
        bridge: Attached bridge.
        slot: Name of the slot under test.
        button: Attribute name of the control the slot disables while the call runs.
        fragment: Failure text the slot would produce.
    """
    del fragment
    _select_bp_row(panel, "not-hex")

    _invoke(panel, slot)

    assert _priv(panel, button).isEnabled()
    assert bridge_workers_for(panel) == []
    assert bridge.sent_commands == []


@pytest.mark.parametrize(("slot", "button", "fragment"), _BP_ACTIONS)
def test_breakpoint_actions_need_a_bridge(panel: X64DbgPanel, slot: str, button: str, fragment: str) -> None:
    """With a valid selected row but no bridge, nothing is dispatched.

    Args:
        panel: Panel under test.
        slot: Name of the slot under test.
        button: Attribute name of the control the slot disables while the call runs.
        fragment: Failure text the slot would produce.
    """
    del fragment
    _select_bp_row(panel, "0x401000")

    _invoke(panel, slot)

    assert _priv(panel, button).isEnabled()
    assert bridge_workers_for(panel) == []
    assert not _console(panel)


@pytest.mark.parametrize(("slot", "button", "fragment"), _BP_ACTIONS)
def test_breakpoint_action_failures_re_enable_the_controls(
    panel: X64DbgPanel,
    bridge: ScriptedBridge,
    qtbot: QtBot,
    slot: str,
    button: str,
    fragment: str,
) -> None:
    """A removal, enable or disable the debugger rejects shows the failure and re-enables the control.

    Args:
        panel: Panel under test.
        bridge: Attached bridge whose debugger calls fail.
        qtbot: pytest-qt fixture used to spin the event loop.
        slot: Name of the slot under test.
        button: Attribute name of the control the slot disables while the call runs.
        fragment: Failure text the slot must produce.
    """
    del bridge
    _select_bp_row(panel, "0x401000")

    _invoke(panel, slot)
    assert not _priv(panel, button).isEnabled()
    _wait_console(qtbot, panel, fragment)

    assert _priv(panel, button).isEnabled()


def test_breakpoint_removal_success_reports_the_address(panel: X64DbgPanel, qtbot: QtBot) -> None:
    """A removal the debugger accepts reports the address and re-enables the remove button.

    Args:
        panel: Panel under test.
        qtbot: pytest-qt fixture used to spin the event loop.
    """
    panel.set_bridge(ScriptedBridge({"bp_remove": None}))
    _select_bp_row(panel, "0x401000")

    _invoke(panel, "_on_remove_breakpoint")
    _wait_console(qtbot, panel, "[+] Breakpoint removed at 0x401000")

    assert _priv(panel, "_remove_bp_btn").isEnabled()


def test_breakpoint_removed_handler_reports_the_address(panel: X64DbgPanel) -> None:
    """The removal success handler writes the address and re-enables the remove button.

    Args:
        panel: Panel under test.
    """
    _priv(panel, "_remove_bp_btn").setEnabled(False)

    _invoke(panel, "_on_bp_removed", _CODE_ADDRESS)

    assert _console(panel) == "[+] Breakpoint removed at 0x401000"
    assert _priv(panel, "_remove_bp_btn").isEnabled()


def test_breakpoint_toggle_done_handler_reports_the_action(panel: X64DbgPanel) -> None:
    """The enable/disable success handler writes the action and re-enables both buttons.

    Args:
        panel: Panel under test.
    """
    _priv(panel, "_enable_bp_btn").setEnabled(False)
    _priv(panel, "_disable_bp_btn").setEnabled(False)

    _invoke(panel, "_on_bp_toggle_done", "enabled", _CODE_ADDRESS)

    assert _console(panel) == "[+] Breakpoint enabled at 0x401000"
    assert _priv(panel, "_enable_bp_btn").isEnabled()
    assert _priv(panel, "_disable_bp_btn").isEnabled()
