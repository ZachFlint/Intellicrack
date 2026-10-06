# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the Frida panel's device, attach, script, hook, process, thread and Stalker slots.

Every test builds a real ``FridaPanel``. Most of them hand it a real ``FridaBridge`` that has never been initialized or attached, so each
bridge call that needs a device or a session fails with the bridge's own ``ToolError`` and travels through the real asynchronous worker back to the
panel's error handler. Result handlers are fed the real dataclasses the bridge returns. The tests that need a live Frida session attach to a
child process that the test itself starts and stops. Expected console text, button states and table cells come from the panel's documented
behavior and from independent oracles (the Frida device manager, the child's own report of its thread id and hand-computed hexadecimal formatting).
"""

from __future__ import annotations

import asyncio
import sys
from typing import TYPE_CHECKING, Final, cast

import frida
import pytest
from PyQt6.QtCore import QSignalBlocker, QTimer
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QInputDialog,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
)

from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.core.subprocess_compat import DEVNULL, PIPE, Popen
from intellicrack.core.types import (
    FridaApplicationInfo,
    FridaDeviceInfo,
    FridaProcessEntry,
    HookInfo,
    StalkerEvent,
    StalkerTrace,
    ThreadInfo,
    ToolError,
)
from intellicrack.ui.panels.async_bridge import bridge_workers_for, drain_bridge_workers_for
from intellicrack.ui.panels.frida_panel import FridaPanel


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator

    from pytestqt.qtbot import QtBot


pytestmark = [pytest.mark.usefixtures("qapp"), pytest.mark.spawns_process]

_WAIT_MS: Final[int] = 20_000
_WAIT_S: Final[float] = 20.0
_NOT_ATTACHED: Final[str] = "not attached to a process"
_NO_DEVICE: Final[str] = "no Frida device available"
_NO_BRIDGE: Final[str] = "[!] No Frida bridge available"
_IDLE_TIP: Final[str] = "Run the script editor contents against the attached process"
_BLOCKED_TIP: Final[str] = "A persistent script is already loaded - stop it to run a new one"
_TARGET_READY: Final[bytes] = b"critcov-ready"
_TARGET_SOURCE: Final[str] = "import sys\nsys.stdout.write('critcov-ready\\n')\nsys.stdout.flush()\nsys.stdin.read()\n"
_THREAD_TARGET_SOURCE: Final[str] = (
    "import sys, threading\nsys.stdout.write('critcov-ready %d\\n' % threading.get_native_id())\nsys.stdout.flush()\nsys.stdin.read()\n"
)
_REMOTE_HOST: Final[str] = "127.0.0.1:59997"
_HOOK_ADDRESS: Final[int] = 0x401000
_COL_ADDRESS: Final[int] = 0
_COL_MODULE: Final[int] = 1
_COL_FUNCTION: Final[int] = 2
_COL_STATUS: Final[int] = 3


def _get[T](obj: object, name: str, typ: type[T]) -> T:
    """Read an attribute of a product object and check its type.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name, including a leading underscore for private members.
        typ: Expected type of the attribute.

    Returns:
        T: The attribute value.
    """
    value: object = getattr(obj, name)
    assert isinstance(value, typ)
    return value


def _put(obj: object, name: str, value: object) -> None:
    """Assign a private data attribute on a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.
        value: Value to store.
    """
    setattr(obj, name, value)


def _call(obj: object, name: str, *args: object, **kwargs: object) -> object:
    """Invoke a (possibly private) method of a product object by name.

    Args:
        obj: Object or class that owns the method.
        name: Method name.
        *args: Positional arguments for the method.
        **kwargs: Keyword arguments for the method.

    Returns:
        object: The method's return value.
    """
    method: object = getattr(obj, name)
    assert callable(method)
    result: object = method(*args, **kwargs)
    return result


def _console(panel: FridaPanel) -> str:
    """Return the panel's console text.

    Args:
        panel: Panel under test.

    Returns:
        str: Plain text of the console output.
    """
    return _get(panel, "_console", QPlainTextEdit).toPlainText()


def _button(panel: FridaPanel, name: str) -> QPushButton:
    """Return one of the panel's push buttons.

    Args:
        panel: Panel under test.
        name: Attribute name of the button.

    Returns:
        QPushButton: The button.
    """
    return _get(panel, name, QPushButton)


def _action(panel: FridaPanel, name: str) -> QAction:
    """Return one of the panel's toolbar menu actions.

    Args:
        panel: Panel under test.
        name: Attribute name of the action.

    Returns:
        QAction: The action.
    """
    return _get(panel, name, QAction)


def _table(panel: FridaPanel, name: str) -> QTableWidget:
    """Return one of the panel's tables.

    Args:
        panel: Panel under test.
        name: Attribute name of the table.

    Returns:
        QTableWidget: The table.
    """
    return _get(panel, name, QTableWidget)


def _cells(table: QTableWidget, row: int) -> list[str | None]:
    """Read the text of every cell in one table row.

    Args:
        table: Table to read.
        row: Row index.

    Returns:
        list[str | None]: Cell texts, with ``None`` for a cell that has no item.
    """
    cells: list[str | None] = []
    for column in range(table.columnCount()):
        item = table.item(row, column)
        cells.append(None if item is None else item.text())
    return cells


def _column(table: QTableWidget, column: int) -> list[str]:
    """Read the text of one table column across every row.

    Args:
        table: Table to read.
        column: Column index.

    Returns:
        list[str]: The texts of the column's cells, top to bottom.
    """
    texts: list[str] = []
    for row in range(table.rowCount()):
        item = table.item(row, column)
        assert item is not None
        texts.append(item.text())
    return texts


def _hook_ids(panel: FridaPanel) -> list[str]:
    """Return a copy of the panel's hook id list.

    Args:
        panel: Panel under test.

    Returns:
        list[str]: Hook ids and pending keys, one per hooks-table row.
    """
    return list(cast("list[str]", _get(panel, "_hook_ids", list)))


def _wait(qtbot: QtBot, predicate: Callable[[], bool]) -> None:
    """Spin the event loop until a condition holds.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        predicate: Condition to wait for.
    """
    qtbot.waitUntil(predicate, timeout=_WAIT_MS)


def _wait_console(qtbot: QtBot, panel: FridaPanel, text: str) -> None:
    """Spin the event loop until the console contains some text.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        panel: Panel under test.
        text: Text that must appear in the console.
    """
    _wait(qtbot, lambda: text in _console(panel))


def _settle(panel: FridaPanel) -> None:
    """Join the panel's in-flight bridge workers and deliver their results.

    Args:
        panel: Panel whose workers are joined.
    """
    drain_bridge_workers_for(panel, _WAIT_MS)
    QApplication.processEvents()
    drain_bridge_workers_for(panel, _WAIT_MS)
    QApplication.processEvents()


def _text_answer(value: str, *, accepted: bool) -> Callable[..., tuple[str, bool]]:
    """Build a replacement for ``QInputDialog.getText`` that answers immediately.

    Args:
        value: Text the replacement reports as entered.
        accepted: Whether the replacement reports the dialog as accepted.

    Returns:
        Callable[..., tuple[str, bool]]: A function ignoring its arguments and returning the chosen answer.
    """

    def _impl(*args: object, **kwargs: object) -> tuple[str, bool]:
        """Return the chosen answer.

        Args:
            *args: Ignored positional arguments.
            **kwargs: Ignored keyword arguments.

        Returns:
            tuple[str, bool]: The chosen text and acceptance flag.
        """
        del args, kwargs
        return (value, accepted)

    return _impl


def _hook(hook_id: str, target: str, address: int | None = _HOOK_ADDRESS, trampoline: int | None = None) -> HookInfo:
    """Build the ``HookInfo`` a bridge install call resolves to.

    Args:
        hook_id: Hook identifier.
        target: Target string the hook was installed on.
        address: Resolved address.
        trampoline: Original-function trampoline, when installed with ``replaceFast``.

    Returns:
        HookInfo: The hook description.
    """
    return HookInfo(id=hook_id, target=target, address=address, script_id=hook_id, active=True, original_trampoline=trampoline)


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run a coroutine to completion on a private event loop and join its executor threads.

    Args:
        coro: Coroutine to execute.

    Returns:
        T: The coroutine's return value.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            loop.run_until_complete(loop.shutdown_default_executor())
        finally:
            loop.close()


def _stop_target(proc: Popen[bytes]) -> None:
    """Terminate a child process, wait for it and close its pipes.

    Args:
        proc: The child process to stop.
    """
    try:
        if proc.poll() is None:
            proc.terminate()
        proc.wait(timeout=_WAIT_S)
    finally:
        for stream in (proc.stdin, proc.stdout):
            if stream is not None:
                stream.close()


def _start_target() -> Popen[bytes]:
    """Start a Python child that reports readiness on stdout and then blocks on stdin.

    Returns:
        Popen[bytes]: The ready child process.
    """
    proc = Popen([sys.executable, "-c", _TARGET_SOURCE], stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
    ready = b""
    try:
        stdout = proc.stdout
        assert stdout is not None
        ready = stdout.readline().strip()
    finally:
        if ready != _TARGET_READY:
            _stop_target(proc)
    assert ready == _TARGET_READY
    return proc


def _start_thread_reporting_target() -> tuple[Popen[bytes], int]:
    """Start a Python child that reports its main thread's native id, then blocks on stdin.

    Returns:
        tuple[Popen[bytes], int]: The ready child process and the native id of its main thread, which stays alive while the child blocks.
    """
    proc = Popen([sys.executable, "-c", _THREAD_TARGET_SOURCE], stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
    parts: list[bytes] = []
    try:
        stdout = proc.stdout
        assert stdout is not None
        parts = stdout.readline().split()
    finally:
        if len(parts) != 2 or parts[0] != _TARGET_READY:
            _stop_target(proc)
    assert len(parts) == 2
    assert parts[0] == _TARGET_READY
    return proc, int(parts[1])


def _remote_present(host: str) -> bool:
    """Report whether the Frida device manager lists the remote device added for ``host``.

    Args:
        host: The ``host:port`` the remote device was added with.

    Returns:
        bool: True when a device with Frida's ``socket@host`` id exists.
    """
    expected = f"socket@{host}"
    return any(device.id == expected for device in frida.get_device_manager().enumerate_devices())


@pytest.fixture
def panel(qtbot: QtBot) -> Generator[FridaPanel]:
    """Provide a real panel with no bridge and stop its timer and workers on teardown.

    Args:
        qtbot: pytest-qt fixture that owns the widget.

    Yields:
        FridaPanel: A freshly built panel.
    """
    widget = FridaPanel()
    qtbot.addWidget(widget)
    try:
        yield widget
    finally:
        _get(widget, "_console_drain_timer", QTimer).stop()
        drain_bridge_workers_for(widget, _WAIT_MS)
        QApplication.processEvents()


@pytest.fixture
def bridge_panel(panel: FridaPanel) -> FridaPanel:
    """Provide a panel that owns a real bridge which was never initialized or attached.

    Args:
        panel: Panel without a bridge.

    Returns:
        FridaPanel: The same panel with the bridge installed.
    """
    panel.set_bridge(FridaBridge())
    return panel


@pytest.fixture
def target() -> Generator[Popen[bytes]]:
    """Start a child process for Frida to attach to and stop it afterwards.

    Yields:
        Popen[bytes]: The running child process.
    """
    proc = _start_target()
    try:
        yield proc
    finally:
        _stop_target(proc)


@pytest.fixture
def device_bridge() -> Generator[FridaBridge]:
    """Initialize a bridge on the local Frida device without attaching and shut it down afterwards.

    Yields:
        FridaBridge: A connected bridge with no session.
    """
    bridge = FridaBridge()
    _run(bridge.initialize())
    try:
        yield bridge
    finally:
        _run(bridge.shutdown())


@pytest.fixture
def attached_bridge(device_bridge: FridaBridge, target: Popen[bytes]) -> FridaBridge:
    """Attach the initialized bridge to the child process.

    Args:
        device_bridge: Initialized bridge.
        target: Child process to attach to.

    Returns:
        FridaBridge: The bridge with a live session on the child.
    """
    _run(device_bridge.attach(target.pid))
    assert device_bridge.state.process_attached
    return device_bridge


def test_get_bridge_returns_the_installed_bridge(panel: FridaPanel) -> None:
    """``get_bridge`` is ``None`` until a bridge is installed and then returns that very bridge.

    Args:
        panel: Panel without a bridge.
    """
    assert panel.get_bridge() is None
    bridge = FridaBridge()
    panel.set_bridge(bridge)
    assert panel.get_bridge() is bridge


def test_live_devices_checkbox_without_bridge_unchecks_itself(panel: FridaPanel) -> None:
    """Ticking "Live" with no bridge must leave the box unticked.

    Args:
        panel: Panel without a bridge.
    """
    box = _get(panel, "_live_devices_cb", QCheckBox)
    box.setChecked(True)
    assert not box.isChecked()


def test_notify_lost_checkbox_without_bridge_unchecks_itself(panel: FridaPanel) -> None:
    """Ticking "Notify Lost" with no bridge must leave the box unticked.

    Args:
        panel: Panel without a bridge.
    """
    box = _get(panel, "_device_lost_cb", QCheckBox)
    box.setChecked(True)
    assert not box.isChecked()


def test_live_devices_checkbox_enables_and_disables_change_notifications(qtbot: QtBot, bridge_panel: FridaPanel) -> None:
    """The "Live" box registers the device-list handler on tick and removes it on untick.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridge_panel: Panel with an unattached bridge.
    """
    bridge = bridge_panel.get_bridge()
    assert bridge is not None
    box = _get(bridge_panel, "_live_devices_cb", QCheckBox)
    try:
        box.setChecked(True)
        _wait(qtbot, lambda: _get(bridge, "_device_change_notifications_enabled", bool))
        assert box.isChecked()
        box.setChecked(False)
        _wait(qtbot, lambda: not _get(bridge, "_device_change_notifications_enabled", bool))
    finally:
        _settle(bridge_panel)
        _run(bridge.disable_device_change_notifications())


def test_notify_lost_checkbox_enables_and_disables_lost_notifications(
    qtbot: QtBot,
    panel: FridaPanel,
    device_bridge: FridaBridge,
) -> None:
    """The "Notify Lost" box registers the device-lost handler on tick and removes it on untick.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        panel: Panel without a bridge.
        device_bridge: Bridge connected to the local device.
    """
    panel.set_bridge(device_bridge)
    box = _get(panel, "_device_lost_cb", QCheckBox)
    try:
        box.setChecked(True)
        _wait(qtbot, lambda: _get(device_bridge, "_device_lost_notifications_enabled", bool))
        box.setChecked(False)
        _wait(qtbot, lambda: not _get(device_bridge, "_device_lost_notifications_enabled", bool))
    finally:
        _settle(panel)


@pytest.mark.parametrize(
    ("fd", "stream"),
    [(1, "stdout"), (2, "stderr")],
)
def test_process_output_message_names_the_stream(panel: FridaPanel, fd: int, stream: str) -> None:
    """A spawned process's captured output is printed with its pid and stream name.

    Args:
        panel: Panel without a bridge.
        fd: POSIX stream number carried by the message.
        stream: Stream name the console must show.
    """
    payload = {"type": "process_output", "pid": 4242, "fd": fd, "data": "hello"}
    _call(panel, "_on_frida_message", {"type": "send", "payload": payload})
    assert _console(panel) == f"[pid 4242 {stream}] hello"


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"type": "other"}, "[send] {'type': 'other'}"),
        ("plain text", "[send] plain text"),
    ],
)
def test_send_message_without_special_type_is_echoed_only(panel: FridaPanel, payload: object, expected: str) -> None:
    """A ``send`` payload that is not a device notification only appears in the console.

    Args:
        panel: Panel without a bridge.
        payload: Payload of the ``send`` message.
        expected: Console text expected.
    """
    _call(panel, "_on_frida_message", {"type": "send", "payload": payload})
    assert _console(panel) == expected
    assert panel.status_label is not None
    assert panel.status_label.text() == "Not attached"


def test_unknown_message_type_is_printed_with_its_type(panel: FridaPanel) -> None:
    """A message of an unrecognized type is printed as ``[type] message``.

    Args:
        panel: Panel without a bridge.
    """
    _call(panel, "_on_frida_message", {"type": "weird", "n": 1})
    assert _console(panel) == "[weird] {'type': 'weird', 'n': 1}"


def test_device_lost_message_updates_status_and_unticks_the_box(panel: FridaPanel) -> None:
    """A ``device_lost`` notification sets the status label and unticks "Notify Lost".

    Args:
        panel: Panel without a bridge.
    """
    box = _get(panel, "_device_lost_cb", QCheckBox)
    with QSignalBlocker(box):
        box.setChecked(True)
    _call(panel, "_on_frida_message", {"type": "send", "payload": {"type": "device_lost"}})
    assert panel.status_label is not None
    assert panel.status_label.text() == "Device lost"
    assert not box.isChecked()
    assert _console(panel) == "[send] {'type': 'device_lost'}"


def test_device_list_changed_message_refreshes_the_device_combo(qtbot: QtBot, bridge_panel: FridaPanel) -> None:
    """A ``device_list_changed`` notification repopulates the device combo from Frida's own device list.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridge_panel: Panel with an unattached bridge.
    """
    combo = _get(bridge_panel, "_device_combo", QComboBox)
    assert [combo.itemText(i) for i in range(combo.count())] == ["local"]
    expected = sorted(f"{device.name} ({device.type})" for device in frida.enumerate_devices())
    _call(bridge_panel, "_on_frida_message", {"type": "send", "payload": {"type": "device_list_changed"}})
    _wait(qtbot, lambda: sorted(combo.itemText(i) for i in range(combo.count())) == expected)


def test_attach_with_blank_target_asks_for_a_target(bridge_panel: FridaPanel) -> None:
    """Attach with an empty target field prints a hint and leaves the Attach button enabled.

    Args:
        bridge_panel: Panel with an unattached bridge.
    """
    _get(bridge_panel, "_target_input", QLineEdit).setText("   ")
    _call(bridge_panel, "_on_attach")
    assert _console(bridge_panel) == "[!] Enter a PID or process name"
    assert _button(bridge_panel, "_attach_btn").isEnabled()
    assert not bridge_workers_for(bridge_panel)


def test_attach_failure_reenables_the_attach_button(qtbot: QtBot, bridge_panel: FridaPanel) -> None:
    """A failed attach reports the error and re-enables the Attach button.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridge_panel: Panel with an unattached bridge.
    """
    attach = _button(bridge_panel, "_attach_btn")
    _get(bridge_panel, "_target_input", QLineEdit).setText("4242")
    _call(bridge_panel, "_on_attach")
    assert not attach.isEnabled()
    _wait_console(qtbot, bridge_panel, "[-] Attach failed: ")
    _wait(qtbot, attach.isEnabled)
    assert _get(bridge_panel, "_attached_pid", object) is None


def test_attach_by_name_success_without_bridge_keeps_pid_unknown(qtbot: QtBot, panel: FridaPanel) -> None:
    """A name-based attach success with no bridge reports the name and leaves the pid unset.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        panel: Panel without a bridge.
    """
    with qtbot.waitSignal(panel.tool_started, timeout=_WAIT_MS):
        _call(panel, "_on_attach_name_success", "notepad.exe")
    assert _get(panel, "_attached_pid", object) is None
    assert _console(panel) == "[+] Attached to 'notepad.exe'"
    assert panel.status_label is not None
    assert panel.status_label.text() == "Attached"
    assert not _button(panel, "_attach_btn").isEnabled()
    assert _button(panel, "_detach_btn").isEnabled()


def test_detach_without_bridge_changes_nothing(panel: FridaPanel) -> None:
    """Detach with no bridge returns without touching the buttons.

    Args:
        panel: Panel without a bridge.
    """
    detach = _button(panel, "_detach_btn")
    detach.setEnabled(True)
    _call(panel, "_on_detach")
    assert detach.isEnabled()
    assert not _console(panel)


def test_detach_without_session_resets_the_panel_state(qtbot: QtBot, bridge_panel: FridaPanel) -> None:
    """Detaching when the bridge holds no session still resets every attach-related control.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridge_panel: Panel with an unattached bridge.
    """
    _put(bridge_panel, "_attached_pid", 4321)
    _put(bridge_panel, "_active_script_id", "abcd1234")
    run = _button(bridge_panel, "run_btn")
    stop = _button(bridge_panel, "_stop_btn")
    stop_all = _action(bridge_panel, "_stop_all_btn")
    attach = _button(bridge_panel, "_attach_btn")
    detach = _button(bridge_panel, "_detach_btn")
    run.setEnabled(False)
    run.setToolTip(_BLOCKED_TIP)
    stop.setEnabled(True)
    stop_all.setEnabled(True)
    attach.setEnabled(False)
    detach.setEnabled(True)
    with qtbot.waitSignal(bridge_panel.tool_closed, timeout=_WAIT_MS):
        _call(bridge_panel, "_on_detach")
    assert not detach.isEnabled()
    assert attach.isEnabled()
    assert run.isEnabled()
    assert run.toolTip() == _IDLE_TIP
    assert not stop.isEnabled()
    assert not stop_all.isEnabled()
    assert _get(bridge_panel, "_attached_pid", object) is None
    assert _get(bridge_panel, "_active_script_id", object) is None
    assert _console(bridge_panel) == "[+] Detached"
    assert bridge_panel.status_label is not None
    assert bridge_panel.status_label.text() == "Not attached"


def test_detach_error_resets_the_panel_state(qtbot: QtBot, panel: FridaPanel) -> None:
    """A detach error is reported and still returns the panel to the not-attached state.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        panel: Panel without a bridge.
    """
    _put(panel, "_attached_pid", 4321)
    _button(panel, "_attach_btn").setEnabled(False)
    _button(panel, "_detach_btn").setEnabled(True)
    with qtbot.waitSignal(panel.tool_closed, timeout=_WAIT_MS):
        _call(panel, "_on_detach_error", ToolError("detach boom"))
    assert _console(panel) == "[-] Detach failed: detach boom"
    assert _get(panel, "_attached_pid", object) is None
    assert panel.status_label is not None
    assert panel.status_label.text() == "Not attached"
    assert _button(panel, "_attach_btn").isEnabled()
    assert not _button(panel, "_detach_btn").isEnabled()


def test_stop_tool_detaches_the_attached_session(qtbot: QtBot, panel: FridaPanel, attached_bridge: FridaBridge) -> None:
    """Stopping the tool detaches a live session and forgets the attached pid.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        panel: Panel without a bridge.
        attached_bridge: Bridge attached to the child process.
    """
    panel.set_bridge(attached_bridge)
    _put(panel, "_attached_pid", 1234)
    with qtbot.waitSignal(panel.tool_closed, timeout=_WAIT_MS):
        assert panel.stop_tool()
    assert not attached_bridge.state.process_attached
    assert _get(attached_bridge, "_session", object) is None
    assert _get(panel, "_attached_pid", object) is None


def test_run_script_without_bridge_reports_it(panel: FridaPanel) -> None:
    """Run Script with no bridge prints a message and keeps the button enabled.

    Args:
        panel: Panel without a bridge.
    """
    _call(panel, "_on_run_script")
    assert _console(panel) == _NO_BRIDGE
    assert _button(panel, "run_btn").isEnabled()


def test_run_script_with_blank_editor_reports_it(bridge_panel: FridaPanel) -> None:
    """Run Script with only whitespace in the editor prints a message and dispatches nothing.

    Args:
        bridge_panel: Panel with an unattached bridge.
    """
    _get(bridge_panel, "_script_editor", QPlainTextEdit).setPlainText("  \n\t ")
    _call(bridge_panel, "_on_run_script")
    assert _console(bridge_panel) == "[!] Script is empty"
    assert _button(bridge_panel, "run_btn").isEnabled()
    assert not bridge_workers_for(bridge_panel)


@pytest.mark.parametrize("oneshot", [False, True])
def test_run_script_without_session_reports_the_failure(qtbot: QtBot, bridge_panel: FridaPanel, *, oneshot: bool) -> None:
    """Run Script on an unattached bridge disables the button, then reports the failure and restores the idle state.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridge_panel: Panel with an unattached bridge.
        oneshot: Whether the One-shot box is ticked.
    """
    run = _button(bridge_panel, "run_btn")
    stop = _button(bridge_panel, "_stop_btn")
    _get(bridge_panel, "_oneshot_script_cb", QCheckBox).setChecked(oneshot)
    _put(bridge_panel, "_active_script_id", "stale")
    stop.setEnabled(True)
    _call(bridge_panel, "_on_run_script")
    assert not run.isEnabled()
    _wait_console(qtbot, bridge_panel, f"[-] Script execution failed: {_NOT_ATTACHED}")
    assert run.isEnabled()
    assert run.toolTip() == _IDLE_TIP
    assert not stop.isEnabled()
    assert _get(bridge_panel, "_active_script_id", object) is None


def test_persistent_script_runs_and_stops_on_a_live_session(qtbot: QtBot, panel: FridaPanel, attached_bridge: FridaBridge) -> None:
    """A persistent script loads into the target, blocks Run, and Stop unloads it.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        panel: Panel without a bridge.
        attached_bridge: Bridge attached to the child process.
    """
    panel.set_bridge(attached_bridge)
    _get(panel, "_script_editor", QPlainTextEdit).setPlainText("var critcovPanelMarker = 1;")
    run = _button(panel, "run_btn")
    stop = _button(panel, "_stop_btn")
    try:
        _call(panel, "_on_run_script")
        assert not run.isEnabled()
        _wait(qtbot, lambda: _get(panel, "_active_script_id", object) is not None)
        script_id = _get(panel, "_active_script_id", str)
        assert list(cast("dict[str, object]", _get(attached_bridge, "_scripts", dict))) == [script_id]
        assert run.toolTip() == _BLOCKED_TIP
        assert stop.isEnabled()
        _call(panel, "_on_stop_script")
        assert not stop.isEnabled()
        _wait(qtbot, lambda: _get(panel, "_active_script_id", object) is None)
        _wait_console(qtbot, panel, "[+] Script stopped")
        assert run.isEnabled()
        assert run.toolTip() == _IDLE_TIP
        assert not _action(panel, "_stop_all_btn").isEnabled()
        assert not _get(attached_bridge, "_scripts", dict)
    finally:
        _settle(panel)


def test_oneshot_script_returns_its_result_on_a_live_session(qtbot: QtBot, panel: FridaPanel, attached_bridge: FridaBridge) -> None:
    """A one-shot script runs once in the target and prints the payload it sent.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        panel: Panel without a bridge.
        attached_bridge: Bridge attached to the child process.
    """
    panel.set_bridge(attached_bridge)
    _get(panel, "_script_editor", QPlainTextEdit).setPlainText("send({ok: true});")
    _get(panel, "_oneshot_script_cb", QCheckBox).setChecked(True)
    run = _button(panel, "run_btn")
    try:
        _call(panel, "_on_run_script")
        assert not run.isEnabled()
        _wait_console(qtbot, panel, "[+] Script result: {'ok': True}")
        assert run.isEnabled()
        assert _get(panel, "_active_script_id", object) is None
        assert not _get(attached_bridge, "_scripts", dict)
    finally:
        _settle(panel)


def test_stop_script_without_bridge_changes_nothing(panel: FridaPanel) -> None:
    """Stop with no bridge returns without touching the buttons.

    Args:
        panel: Panel without a bridge.
    """
    stop = _button(panel, "_stop_btn")
    stop.setEnabled(True)
    _call(panel, "_on_stop_script")
    assert stop.isEnabled()
    assert not _console(panel)


def test_stop_script_without_a_handle_restores_the_idle_state(bridge_panel: FridaPanel) -> None:
    """Stop with no persistent script handle explains it and returns the buttons to idle.

    Args:
        bridge_panel: Panel with an unattached bridge.
    """
    run = _button(bridge_panel, "run_btn")
    stop = _button(bridge_panel, "_stop_btn")
    run.setEnabled(False)
    run.setToolTip(_BLOCKED_TIP)
    stop.setEnabled(True)
    _call(bridge_panel, "_on_stop_script")
    assert _console(bridge_panel) == "[!] No persistent script handle to stop"
    assert not stop.isEnabled()
    assert run.isEnabled()
    assert run.toolTip() == _IDLE_TIP
    assert not bridge_workers_for(bridge_panel)


def test_stop_script_error_reenables_stop(panel: FridaPanel) -> None:
    """A failed stop prints the error and lets the user try again.

    Args:
        panel: Panel without a bridge.
    """
    stop = _button(panel, "_stop_btn")
    stop.setEnabled(False)
    _call(panel, "_on_stop_script_error", ToolError("unload boom"))
    assert _console(panel) == "[-] Stop failed: unload boom"
    assert stop.isEnabled()


def test_stop_all_scripts_without_bridge_reports_it(panel: FridaPanel) -> None:
    """Stop All Scripts with no bridge prints a message.

    Args:
        panel: Panel without a bridge.
    """
    _call(panel, "_on_stop_all_scripts")
    assert _console(panel) == _NO_BRIDGE


@pytest.mark.parametrize(("script_id", "expect_enabled"), [(None, False), ("s1", True)])
def test_stop_all_scripts_error_reenables_buttons_only_with_an_active_script(
    panel: FridaPanel,
    script_id: str | None,
    *,
    expect_enabled: bool,
) -> None:
    """After a failed Stop All, the stop buttons are enabled only while a script handle is held.

    Args:
        panel: Panel without a bridge.
        script_id: Active persistent script id, or ``None``.
        expect_enabled: Whether the stop buttons must end up enabled.
    """
    _put(panel, "_active_script_id", script_id)
    _button(panel, "_stop_btn").setEnabled(not expect_enabled)
    _action(panel, "_stop_all_btn").setEnabled(not expect_enabled)
    _call(panel, "_on_stop_all_scripts_error", ToolError("sweep boom"))
    assert _console(panel) == "[-] Stop all failed: sweep boom"
    assert _button(panel, "_stop_btn").isEnabled() is expect_enabled
    assert _action(panel, "_stop_all_btn").isEnabled() is expect_enabled


def test_clear_console_empties_the_console(panel: FridaPanel) -> None:
    """Clear Console removes every line of output.

    Args:
        panel: Panel without a bridge.
    """
    panel.log_message("first")
    panel.log_message("second")
    assert _console(panel) == "first\nsecond"
    _call(panel, "_on_clear_console")
    assert not _console(panel)


def test_add_hook_without_bridge_reports_it(panel: FridaPanel) -> None:
    """Add Hook with no bridge prints a message and adds no row.

    Args:
        panel: Panel without a bridge.
    """
    _call(panel, "_on_add_hook")
    assert _console(panel) == "[!] No Frida bridge - cannot add hook"
    assert _table(panel, "_hooks_table").rowCount() == 0


@pytest.mark.parametrize(("text", "accepted"), [("0x401000", False), ("   ", True)])
def test_add_hook_dialog_without_a_target_adds_nothing(
    monkeypatch: pytest.MonkeyPatch,
    bridge_panel: FridaPanel,
    text: str,
    *,
    accepted: bool,
) -> None:
    """A cancelled dialog, or an accepted blank one, adds no hook row and dispatches nothing.

    Args:
        monkeypatch: Pytest monkeypatch fixture that answers the dialog.
        bridge_panel: Panel with an unattached bridge.
        text: Text the dialog reports.
        accepted: Whether the dialog reports acceptance.
    """
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(_text_answer(text, accepted=accepted)))
    _call(bridge_panel, "_on_add_hook")
    assert _table(bridge_panel, "_hooks_table").rowCount() == 0
    assert _hook_ids(bridge_panel) == []
    assert _button(bridge_panel, "_add_hook_btn").isEnabled()
    assert not bridge_workers_for(bridge_panel)


def test_find_hook_row_ignores_an_empty_key(panel: FridaPanel) -> None:
    """An empty key never matches a row, even when a row was added without a hook id.

    Args:
        panel: Panel without a bridge.
    """
    panel.add_hook_entry("0x401000", "kernel32.dll", "Sleep")
    assert _hook_ids(panel) == [""]
    assert _call(panel, "_find_hook_row", "") == -1


def test_remove_pending_row_with_unknown_key_keeps_every_row(panel: FridaPanel) -> None:
    """Removing a pending row that does not exist leaves the table and the id list untouched.

    Args:
        panel: Panel without a bridge.
    """
    panel.add_hook_entry("0x401000", "kernel32.dll", "Sleep", hook_id="h1")
    panel.add_hook_entry("0x402000", "kernel32.dll", "Wait", hook_id="h2")
    _call(panel, "_remove_pending_hook_row", "__pending_hook_9__")
    assert _table(panel, "_hooks_table").rowCount() == 2
    assert _hook_ids(panel) == ["h1", "h2"]


def test_apply_install_result_tolerates_a_row_without_cells(panel: FridaPanel) -> None:
    """Writing an install result into a row that has no cell items still records the hook id.

    Args:
        panel: Panel without a bridge.
    """
    table = _table(panel, "_hooks_table")
    table.insertRow(0)
    cast("list[str]", _get(panel, "_hook_ids", list)).append("pending-key")
    outcome = _call(panel, "_apply_hook_install_result", "pending-key", "kernel32.dll!Sleep", _hook("hk-1", "kernel32.dll!Sleep"))
    assert outcome == (True, "0x401000", "hk-1")
    assert _cells(table, 0) == [None, None, None, None]
    assert _hook_ids(panel) == ["hk-1"]


def test_hook_installed_after_its_row_vanished_still_reports_success(qtbot: QtBot, panel: FridaPanel) -> None:
    """A hook that finishes installing after its row was removed is reported as installed with a refreshed row.

    Args:
        qtbot: pytest-qt fixture used to catch the ``hook_added`` signal.
        panel: Panel without a bridge.
    """
    add = _button(panel, "_add_hook_btn")
    add.setEnabled(False)
    with qtbot.waitSignal(panel.hook_added, timeout=_WAIT_MS) as blocker:
        _call(panel, "_on_hook_installed", "__pending_hook_77__", "kernel32.dll!Sleep", _hook("hk-9", "kernel32.dll!Sleep", 0x7FF600001000))
    assert cast("list[object] | None", blocker.args) == ["0x7FF600001000"]
    assert _console(panel) == "[+] Hook installed: kernel32.dll!Sleep at 0x7FF600001000 (row refreshed)"
    assert add.isEnabled()
    assert _table(panel, "_hooks_table").rowCount() == 0
    assert _hook_ids(panel) == []


@pytest.mark.parametrize(
    ("handler", "extra", "expected"),
    [
        ("_on_intercept_return_installed", (5,), "[+] Intercept return installed for kernel32.dll!Sleep -> 5 at 0x401000"),
        ("_on_replace_function_installed", (), "[+] Function replaced: kernel32.dll!Sleep at 0x401000"),
        ("_on_replace_function_fast_installed", (), "[+] Function replaced (fast): kernel32.dll!Sleep at 0x401000"),
    ],
)
def test_install_result_without_a_row_is_reported_and_adds_none(
    panel: FridaPanel,
    handler: str,
    extra: tuple[int, ...],
    expected: str,
) -> None:
    """The Intercept Ret and Replace Fn handlers still report success when their pending row is gone.

    Args:
        panel: Panel without a bridge.
        handler: Name of the success handler under test.
        extra: Handler arguments between the target and the result.
        expected: Console text expected.
    """
    target_text = "kernel32.dll!Sleep"
    _call(panel, handler, "__pending_hook_5__", target_text, *extra, _hook("hk-3", target_text))
    assert _console(panel) == expected
    assert _table(panel, "_hooks_table").rowCount() == 0
    assert _hook_ids(panel) == []


def test_replace_fast_install_fills_its_pending_row_and_shows_the_trampoline(panel: FridaPanel) -> None:
    """A fast replacement fills its pending row and prints the original trampoline address.

    Args:
        panel: Panel without a bridge.
    """
    target_text = "kernel32.dll!GetTickCount"
    _call(panel, "_insert_pending_hook_row", "__pending_hook_0__", target_text)
    _call(panel, "_on_replace_function_fast_installed", "__pending_hook_0__", target_text, _hook("hk-fast", target_text, trampoline=0xBEEF))
    table = _table(panel, "_hooks_table")
    assert _cells(table, 0) == ["0x401000", "kernel32.dll", "GetTickCount", "Active"]
    assert _hook_ids(panel) == ["hk-fast"]
    assert _console(panel).splitlines() == [
        "[+] Function replaced (fast): kernel32.dll!GetTickCount at 0x401000",
        "[+] Original trampoline: 0xBEEF",
    ]


@pytest.mark.parametrize(
    ("handler", "label"),
    [
        ("_on_replace_function_error", "Replace function failed"),
        ("_on_replace_function_fast_error", "Replace function (fast) failed"),
    ],
)
def test_replace_install_error_removes_the_pending_row(panel: FridaPanel, handler: str, label: str) -> None:
    """A failed replacement removes its pending row and prints the error.

    Args:
        panel: Panel without a bridge.
        handler: Name of the error handler under test.
        label: Console label the handler uses.
    """
    panel.add_hook_entry("0x402000", "kernel32.dll", "Wait", hook_id="h-keep")
    _call(panel, "_insert_pending_hook_row", "__pending_hook_1__", "kernel32.dll!Sleep")
    assert _hook_ids(panel) == ["h-keep", "__pending_hook_1__"]
    _call(panel, handler, "__pending_hook_1__", ToolError("replace boom"))
    assert _console(panel) == f"[-] {label}: replace boom"
    assert _table(panel, "_hooks_table").rowCount() == 1
    assert _hook_ids(panel) == ["h-keep"]


def test_remove_hook_without_selection_does_nothing(bridge_panel: FridaPanel) -> None:
    """Remove with no selected row leaves the table and the Remove button alone.

    Args:
        bridge_panel: Panel with an unattached bridge.
    """
    bridge_panel.add_hook_entry("0x401000", "kernel32.dll", "Sleep", hook_id="h1")
    table = _table(bridge_panel, "_hooks_table")
    table.setCurrentCell(-1, -1)
    assert table.currentRow() == -1
    _call(bridge_panel, "_on_remove_hook")
    assert table.rowCount() == 1
    assert _hook_ids(bridge_panel) == ["h1"]
    assert _button(bridge_panel, "_remove_hook_btn").isEnabled()
    assert not bridge_workers_for(bridge_panel)


def test_remove_hook_for_a_row_without_a_tracked_id_drops_the_row(panel: FridaPanel) -> None:
    """Removing a row that has no entry in the id list removes the row and does not fail.

    Args:
        panel: Panel without a bridge.
    """
    table = _table(panel, "_hooks_table")
    table.insertRow(0)
    table.setItem(0, _COL_FUNCTION, QTableWidgetItem("Sleep"))
    table.setCurrentCell(0, _COL_FUNCTION)
    assert _hook_ids(panel) == []
    _call(panel, "_on_remove_hook")
    assert table.rowCount() == 0
    assert _hook_ids(panel) == []


def test_hook_removed_for_an_unknown_id_keeps_the_rows(panel: FridaPanel) -> None:
    """A removal confirmation for an id that is not in the table keeps every row and re-enables Remove.

    Args:
        panel: Panel without a bridge.
    """
    panel.add_hook_entry("0x401000", "kernel32.dll", "Sleep", hook_id="h1")
    remove = _button(panel, "_remove_hook_btn")
    remove.setEnabled(False)
    _call(panel, "_on_hook_removed", "zzz")
    assert _console(panel) == "[+] Removed hook zzz"
    assert _table(panel, "_hooks_table").rowCount() == 1
    assert _hook_ids(panel) == ["h1"]
    assert remove.isEnabled()


def test_hook_remove_error_reenables_remove(panel: FridaPanel) -> None:
    """A failed hook removal prints the error and re-enables Remove.

    Args:
        panel: Panel without a bridge.
    """
    remove = _button(panel, "_remove_hook_btn")
    remove.setEnabled(False)
    _call(panel, "_on_hook_remove_error", "h1", ToolError("remove boom"))
    assert _console(panel) == "[-] Failed to remove hook: remove boom"
    assert remove.isEnabled()


def test_rename_shortcut_opens_an_editor_on_the_function_cell(panel: FridaPanel) -> None:
    """The F2 handler starts editing the selected hook's function name.

    Args:
        panel: Panel without a bridge.
    """
    panel.add_hook_entry("0x401000", "kernel32.dll", "CreateFileW", hook_id="h1")
    table = _table(panel, "_hooks_table")
    table.setCurrentCell(0, _COL_STATUS)
    _call(panel, "_on_hook_rename_shortcut")
    assert [editor.text() for editor in table.findChildren(QLineEdit)] == ["CreateFileW"]


def test_rename_shortcut_without_a_row_or_a_cell_opens_no_editor(panel: FridaPanel) -> None:
    """The F2 handler opens no editor when nothing is selected or the selected row has no function cell.

    Args:
        panel: Panel without a bridge.
    """
    table = _table(panel, "_hooks_table")
    assert table.currentRow() == -1
    _call(panel, "_on_hook_rename_shortcut")
    assert table.findChildren(QLineEdit) == []
    table.insertRow(0)
    table.setCurrentCell(0, 0)
    assert table.currentRow() == 0
    _call(panel, "_on_hook_rename_shortcut")
    assert table.findChildren(QLineEdit) == []


@pytest.mark.parametrize(
    ("user_data", "text", "expected"),
    [
        (None, "usb", ("usb", None)),
        (None, "anything else", ("local", None)),
        ({"type": "", "id": ""}, "usb", ("usb", None)),
        ({"type": "remote", "id": ""}, "remote:10.1.1.1:5", ("remote", "10.1.1.1:5")),
        ({"type": "remote", "id": "   "}, "local", ("local", None)),
        ({"type": "remote", "id": "socket"}, "x", ("enumerated", "socket")),
        ({"type": "REMOTE", "id": "socket@10.0.0.9:27042"}, "x", ("remote", "10.0.0.9:27042")),
        ({"type": "usb", "id": "abc"}, "x", ("usb", None)),
        ("not a mapping", "remote:", ("remote", None)),
    ],
)
def test_resolve_device_selection(user_data: object, text: str, expected: tuple[str, str | None]) -> None:
    """The device type and host come from the combo item's data first and from its text only as a fallback.

    Args:
        user_data: The selected combo item's data.
        text: The selected combo item's text.
        expected: Bridge device type and host expected.
    """
    assert _call(FridaPanel, "_resolve_device_selection", user_data, text) == expected


def test_device_combo_change_without_bridge_does_nothing(panel: FridaPanel) -> None:
    """Selecting another device with no bridge prints nothing and dispatches nothing.

    Args:
        panel: Panel without a bridge.
    """
    combo = _get(panel, "_device_combo", QComboBox)
    combo.addItem("usb")
    combo.setCurrentIndex(1)
    assert combo.currentText() == "usb"
    assert not _console(panel)
    assert not bridge_workers_for(panel)


def test_add_remote_device_without_bridge_reports_it(panel: FridaPanel) -> None:
    """Add Remote Device with no bridge prints a message.

    Args:
        panel: Panel without a bridge.
    """
    _call(panel, "_on_add_remote_device")
    assert _console(panel) == _NO_BRIDGE


@pytest.mark.parametrize(
    ("text", "accepted", "expected"),
    [("", False, ""), ("  ", True, "[!] Remote host:port is required")],
)
def test_add_remote_device_without_an_address_connects_nothing(
    monkeypatch: pytest.MonkeyPatch,
    bridge_panel: FridaPanel,
    text: str,
    expected: str,
    *,
    accepted: bool,
) -> None:
    """A cancelled dialog is silent and an accepted blank one asks for an address; neither connects.

    Args:
        monkeypatch: Pytest monkeypatch fixture that answers the dialog.
        bridge_panel: Panel with an unattached bridge.
        text: Text the dialog reports.
        expected: Console text expected.
        accepted: Whether the dialog reports acceptance.
    """
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(_text_answer(text, accepted=accepted)))
    _call(bridge_panel, "_on_add_remote_device")
    assert _console(bridge_panel) == expected
    assert not bridge_workers_for(bridge_panel)


def test_remote_device_added_twice_selects_the_existing_entry(panel: FridaPanel) -> None:
    """Adding a remote device whose entry exists selects that entry instead of duplicating it.

    Args:
        panel: Panel without a bridge.
    """
    combo = _get(panel, "_device_combo", QComboBox)
    with QSignalBlocker(combo):
        combo.addItem(f"remote:{_REMOTE_HOST}")
        combo.addItem("remote:10.0.0.1:1")
        combo.setCurrentIndex(2)
    _call(panel, "_on_remote_device_added", _REMOTE_HOST, FridaDeviceInfo(id=f"socket@{_REMOTE_HOST}", name="Remote", device_type="remote"))
    assert [combo.itemText(i) for i in range(combo.count())] == ["local", f"remote:{_REMOTE_HOST}", "remote:10.0.0.1:1"]
    assert combo.currentIndex() == 1
    assert _console(panel) == "[+] Connected to device: Remote"


def test_remove_remote_device_without_bridge_reports_it(panel: FridaPanel) -> None:
    """Remove Remote Device with no bridge prints a message.

    Args:
        panel: Panel without a bridge.
    """
    _call(panel, "_on_remove_remote_device")
    assert _console(panel) == _NO_BRIDGE


@pytest.mark.parametrize("entry", ["remote:10.0.0.1:1", "local"])
def test_remove_remote_device_needs_a_remote_selection(bridge_panel: FridaPanel, entry: str) -> None:
    """Removing with a selection that carries no remote device data, or a non-remote device, only prints a hint.

    Args:
        bridge_panel: Panel with an unattached bridge.
        entry: Combo entry to select; one without data, or the built-in local one.
    """
    combo = _get(bridge_panel, "_device_combo", QComboBox)
    with QSignalBlocker(combo):
        if entry != "local":
            combo.addItem(entry)
        combo.setCurrentIndex(combo.findText(entry))
    _call(bridge_panel, "_on_remove_remote_device")
    assert _console(bridge_panel) == "[!] Select a remote device in the Device list to remove it"
    assert not bridge_workers_for(bridge_panel)


@pytest.mark.parametrize("host", ["10.0.0.1:1", "10.9.9.9:9"])
def test_remote_device_removed_drops_its_entry_and_selects_the_first(panel: FridaPanel, host: str) -> None:
    """The removed remote device's entry leaves the combo, if present, and the first entry becomes current.

    Args:
        panel: Panel without a bridge.
        host: Host reported as removed; the first value has an entry, the second has none.
    """
    combo = _get(panel, "_device_combo", QComboBox)
    with QSignalBlocker(combo):
        combo.addItem("remote:10.0.0.1:1")
        combo.setCurrentIndex(1)
    _call(panel, "_on_remote_device_removed", host)
    remaining = [combo.itemText(i) for i in range(combo.count())]
    assert remaining == (["local"] if host == "10.0.0.1:1" else ["local", "remote:10.0.0.1:1"])
    assert combo.currentIndex() == 0
    assert _console(panel) == f"[+] Removed remote device: {host}"


def _entry_index(combo: QComboBox, device_id: str) -> int:
    """Find the combo entry whose data carries a device id.

    Args:
        combo: Device combo to search.
        device_id: Frida device id to look for.

    Returns:
        int: Index of the entry, or ``-1`` when there is none.
    """
    for index in range(combo.count()):
        data: object = combo.itemData(index)
        if isinstance(data, dict) and cast("dict[str, object]", data).get("id") == device_id:
            return index
    return -1


def _add_remote_through_the_panel(qtbot: QtBot, panel: FridaPanel, monkeypatch: pytest.MonkeyPatch) -> None:
    """Add the loopback remote device by driving the panel's Add Remote Device handler.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        panel: Panel that owns a bridge.
        monkeypatch: Pytest monkeypatch fixture that answers the dialog.
    """
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(_text_answer(_REMOTE_HOST, accepted=True)))
    _call(panel, "_on_add_remote_device")
    _wait_console(qtbot, panel, "[+] Connected to device: ")
    assert _remote_present(_REMOTE_HOST)


def _forget_remote() -> None:
    """Remove the loopback remote device from the Frida device manager if it is still there."""
    if _remote_present(_REMOTE_HOST):
        frida.get_device_manager().remove_remote_device(_REMOTE_HOST)


def test_remove_remote_device_right_after_adding_it_removes_it(
    qtbot: QtBot,
    bridge_panel: FridaPanel,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Add Remote Device followed by Remove Remote Device must remove the device that was just added.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridge_panel: Panel with an unattached bridge.
        monkeypatch: Pytest monkeypatch fixture that answers the dialog.
    """
    try:
        _add_remote_through_the_panel(qtbot, bridge_panel, monkeypatch)
        combo = _get(bridge_panel, "_device_combo", QComboBox)
        assert combo.currentText() == f"remote:{_REMOTE_HOST}"
        _call(bridge_panel, "_on_remove_remote_device")
        _settle(bridge_panel)
        assert not _remote_present(_REMOTE_HOST), _console(bridge_panel)
    finally:
        _settle(bridge_panel)
        _forget_remote()


def test_remove_remote_device_after_refreshing_the_list_removes_it(
    qtbot: QtBot,
    bridge_panel: FridaPanel,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After the device list is refreshed, removing the selected remote device must remove it from Frida.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridge_panel: Panel with an unattached bridge.
        monkeypatch: Pytest monkeypatch fixture that answers the dialog.
    """
    expected_id = f"socket@{_REMOTE_HOST}"
    combo = _get(bridge_panel, "_device_combo", QComboBox)
    try:
        _add_remote_through_the_panel(qtbot, bridge_panel, monkeypatch)
        _call(bridge_panel, "refresh_devices")
        _wait(qtbot, lambda: _entry_index(combo, expected_id) >= 0)
        with QSignalBlocker(combo):
            combo.setCurrentIndex(_entry_index(combo, expected_id))
        _call(bridge_panel, "_on_remove_remote_device")
        _settle(bridge_panel)
        assert not _remote_present(_REMOTE_HOST), _console(bridge_panel)
    finally:
        _settle(bridge_panel)
        _forget_remote()


def test_refresh_processes_without_bridge_reports_it(panel: FridaPanel) -> None:
    """Refresh with no bridge prints a message.

    Args:
        panel: Panel without a bridge.
    """
    _call(panel, "_on_refresh_processes")
    assert _console(panel) == _NO_BRIDGE


def test_populate_process_table_replaces_rows_and_ignores_a_non_list(panel: FridaPanel) -> None:
    """The process table shows the enumerated pids and names, and a non-list result clears it.

    Args:
        panel: Panel without a bridge.
    """
    table = _table(panel, "_process_table")
    refresh = _button(panel, "_refresh_procs_btn")
    refresh.setEnabled(False)
    _call(panel, "_populate_process_table", [FridaProcessEntry(pid=4, name="System"), FridaProcessEntry(pid=812, name="svc.exe")])
    assert _column(table, 0) == ["4", "812"]
    assert _column(table, 1) == ["System", "svc.exe"]
    assert refresh.isEnabled()
    refresh.setEnabled(False)
    _call(panel, "_populate_process_table", "not a list")
    assert table.rowCount() == 0
    assert refresh.isEnabled()


def test_process_double_click_without_a_row_does_nothing(bridge_panel: FridaPanel) -> None:
    """Double-clicking with no current row leaves the target field and console alone.

    Args:
        bridge_panel: Panel with an unattached bridge.
    """
    _call(bridge_panel, "_on_process_double_click")
    assert not _get(bridge_panel, "_target_input", QLineEdit).text()
    assert not _console(bridge_panel)


def test_process_double_click_on_a_row_without_a_pid_cell_does_nothing(bridge_panel: FridaPanel) -> None:
    """A current row with no pid cell never reaches the attach handler.

    Args:
        bridge_panel: Panel with an unattached bridge.
    """
    table = _table(bridge_panel, "_process_table")
    table.insertRow(0)
    table.setCurrentCell(0, 0)
    assert table.currentRow() == 0
    _call(bridge_panel, "_on_process_double_click")
    assert not _get(bridge_panel, "_target_input", QLineEdit).text()
    assert not _console(bridge_panel)


def test_process_double_click_copies_the_pid_and_attaches(panel: FridaPanel) -> None:
    """Double-clicking a process copies its pid into the target field and starts an attach.

    Args:
        panel: Panel without a bridge.
    """
    _call(panel, "_populate_process_table", [FridaProcessEntry(pid=4242, name="victim.exe")])
    _table(panel, "_process_table").setCurrentCell(0, 0)
    _call(panel, "_on_process_double_click")
    assert _get(panel, "_target_input", QLineEdit).text() == "4242"
    assert _console(panel) == _NO_BRIDGE


def test_kill_process_without_bridge_reports_it(panel: FridaPanel) -> None:
    """Kill Selected with no bridge prints a message.

    Args:
        panel: Panel without a bridge.
    """
    _call(panel, "_on_kill_process")
    assert _console(panel) == _NO_BRIDGE


def test_kill_process_without_a_selection_asks_for_one(bridge_panel: FridaPanel) -> None:
    """Kill Selected with no current row asks the user to select a process.

    Args:
        bridge_panel: Panel with an unattached bridge.
    """
    _call(bridge_panel, "_on_kill_process")
    assert _console(bridge_panel) == "[!] Select a process to kill"
    assert _button(bridge_panel, "_kill_process_btn").isEnabled()


@pytest.mark.parametrize("cell_text", [None, "abc"])
def test_kill_process_ignores_a_row_without_a_numeric_pid(bridge_panel: FridaPanel, cell_text: str | None) -> None:
    """A selected row with no pid cell, or a non-numeric one, is not killed and dispatches nothing.

    Args:
        bridge_panel: Panel with an unattached bridge.
        cell_text: Text of the pid cell, or ``None`` for no cell.
    """
    table = _table(bridge_panel, "_process_table")
    table.insertRow(0)
    if cell_text is not None:
        table.setItem(0, 0, QTableWidgetItem(cell_text))
    table.setCurrentCell(0, 0)
    _call(bridge_panel, "_on_kill_process")
    assert not _console(bridge_panel)
    assert _button(bridge_panel, "_kill_process_btn").isEnabled()
    assert not bridge_workers_for(bridge_panel)


def test_kill_process_failure_is_reported_and_reenables_the_button(qtbot: QtBot, bridge_panel: FridaPanel) -> None:
    """A kill that fails because the bridge has no device is reported and the button is re-enabled.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridge_panel: Panel with an unattached bridge.
    """
    kill = _button(bridge_panel, "_kill_process_btn")
    _call(bridge_panel, "_populate_process_table", [FridaProcessEntry(pid=4242, name="victim.exe")])
    _table(bridge_panel, "_process_table").setCurrentCell(0, 0)
    _call(bridge_panel, "_on_kill_process")
    assert not kill.isEnabled()
    _wait_console(qtbot, bridge_panel, f"[-] Kill PID 4242 failed: {_NO_DEVICE}")
    assert kill.isEnabled()


def test_kill_process_terminates_the_child_and_refreshes_the_table(
    qtbot: QtBot,
    panel: FridaPanel,
    device_bridge: FridaBridge,
    target: Popen[bytes],
) -> None:
    """Kill Selected ends the selected child process and refreshes the table without it.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        panel: Panel without a bridge.
        device_bridge: Bridge connected to the local device.
        target: Child process to kill.
    """
    panel.set_bridge(device_bridge)
    table = _table(panel, "_process_table")
    kill = _button(panel, "_kill_process_btn")
    _call(panel, "_populate_process_table", [FridaProcessEntry(pid=target.pid, name="python.exe")])
    table.setCurrentCell(0, 0)
    try:
        _call(panel, "_on_kill_process")
        assert not kill.isEnabled()
        _wait_console(qtbot, panel, f"[+] Killed PID {target.pid}")
        assert kill.isEnabled()
        _wait(qtbot, lambda: table.rowCount() > 1 and _button(panel, "_refresh_procs_btn").isEnabled())
        assert target.wait(timeout=_WAIT_S) is not None
    finally:
        _settle(panel)


def test_refresh_applications_without_bridge_reports_it(panel: FridaPanel) -> None:
    """Refresh on the Applications tab with no bridge prints a message.

    Args:
        panel: Panel without a bridge.
    """
    _call(panel, "_on_refresh_applications")
    assert _console(panel) == _NO_BRIDGE


def test_populate_application_table_shows_pids_only_for_running_apps(panel: FridaPanel) -> None:
    """Applications show their pid when running and a blank cell otherwise; a non-list result clears the table.

    Args:
        panel: Panel without a bridge.
    """
    table = _table(panel, "_application_table")
    refresh = _button(panel, "_refresh_apps_btn")
    refresh.setEnabled(False)
    _call(
        panel,
        "_populate_application_table",
        [
            FridaApplicationInfo(identifier="com.example.run", name="Runner", pid=77),
            FridaApplicationInfo(identifier="com.example.idle", name="Idle", pid=0),
        ],
    )
    assert _column(table, 0) == ["com.example.run", "com.example.idle"]
    assert _column(table, 1) == ["Runner", "Idle"]
    assert _column(table, 2) == ["77", ""]
    assert refresh.isEnabled()
    _call(panel, "_populate_application_table", None)
    assert table.rowCount() == 0


def test_frontmost_application_without_bridge_reports_it(panel: FridaPanel) -> None:
    """Frontmost with no bridge prints a message and leaves the button enabled.

    Args:
        panel: Panel without a bridge.
    """
    _call(panel, "_on_get_frontmost_application")
    assert _console(panel) == _NO_BRIDGE
    assert _button(panel, "_frontmost_btn").isEnabled()


def test_frontmost_application_failure_is_reported_and_reenables_the_button(qtbot: QtBot, bridge_panel: FridaPanel) -> None:
    """A frontmost query that fails because the bridge has no device is reported and the button is re-enabled.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridge_panel: Panel with an unattached bridge.
    """
    button = _button(bridge_panel, "_frontmost_btn")
    _call(bridge_panel, "_on_get_frontmost_application")
    assert not button.isEnabled()
    _wait_console(qtbot, bridge_panel, f"[-] Get frontmost application failed: {_NO_DEVICE}")
    assert button.isEnabled()


def test_frontmost_application_result_names_the_application(panel: FridaPanel) -> None:
    """A frontmost application is printed with its name, identifier and pid.

    Args:
        panel: Panel without a bridge.
    """
    button = _button(panel, "_frontmost_btn")
    button.setEnabled(False)
    _call(panel, "_on_frontmost_application_result", FridaApplicationInfo(identifier="com.example.calc", name="Calc", pid=12))
    assert _console(panel) == "[+] Frontmost: Calc (com.example.calc), pid 12"
    assert button.isEnabled()


def test_frontmost_application_result_without_an_application(panel: FridaPanel) -> None:
    """No frontmost application is reported as such.

    Args:
        panel: Panel without a bridge.
    """
    _call(panel, "_on_frontmost_application_result", None)
    assert _console(panel) == "[*] No frontmost application"


def test_application_double_click_without_a_row_does_nothing(bridge_panel: FridaPanel) -> None:
    """Double-clicking with no current application row leaves the target field and console alone.

    Args:
        bridge_panel: Panel with an unattached bridge.
    """
    _call(bridge_panel, "_on_application_double_click")
    assert not _get(bridge_panel, "_target_input", QLineEdit).text()
    assert not _console(bridge_panel)


def test_refresh_threads_without_bridge_reports_it(panel: FridaPanel) -> None:
    """Refresh on the Threads tab with no bridge prints a message.

    Args:
        panel: Panel without a bridge.
    """
    _call(panel, "_on_refresh_threads")
    assert _console(panel) == _NO_BRIDGE
    assert _button(panel, "_refresh_threads_btn").isEnabled()


def test_refresh_threads_failure_is_reported_and_reenables_the_button(qtbot: QtBot, bridge_panel: FridaPanel) -> None:
    """A thread refresh on an unattached bridge is reported and the button is re-enabled.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridge_panel: Panel with an unattached bridge.
    """
    button = _button(bridge_panel, "_refresh_threads_btn")
    _call(bridge_panel, "_on_refresh_threads")
    assert not button.isEnabled()
    _wait_console(qtbot, bridge_panel, f"[-] Thread enumeration failed: {_NOT_ATTACHED}")
    assert button.isEnabled()


def _thread_infos() -> list[ThreadInfo]:
    """Build two thread descriptions as the bridge reports them.

    Returns:
        list[ThreadInfo]: A running and a waiting thread whose start address is unknown and whose program counter is known.
    """
    return [
        ThreadInfo(tid=111, start_address=0, current_pc=0x7FF6AA001000, state="running"),
        ThreadInfo(tid=222, start_address=0, current_pc=0x7FF6AA002000, state="waiting"),
    ]


def test_populate_threads_table_lists_each_thread(panel: FridaPanel) -> None:
    """The threads table shows one row per thread with its id and state, and a non-list result clears it.

    Args:
        panel: Panel without a bridge.
    """
    table = _table(panel, "_threads_table")
    refresh = _button(panel, "_refresh_threads_btn")
    refresh.setEnabled(False)
    _call(panel, "_populate_threads_table", _thread_infos())
    assert _column(table, 0) == ["111", "222"]
    assert _column(table, 1) == ["running", "waiting"]
    assert refresh.isEnabled()
    _call(panel, "_populate_threads_table", "not a list")
    assert table.rowCount() == 0


def test_threads_table_pc_column_shows_the_current_program_counter(panel: FridaPanel) -> None:
    """The PC column must show each thread's current program counter.

    Args:
        panel: Panel without a bridge.
    """
    _call(panel, "_populate_threads_table", _thread_infos())
    assert _column(_table(panel, "_threads_table"), 2) == ["0x7FF6AA001000", "0x7FF6AA002000"]


def test_threads_of_a_live_session_include_the_targets_main_thread(
    qtbot: QtBot,
    panel: FridaPanel,
    device_bridge: FridaBridge,
) -> None:
    """Refreshing threads on a live session lists the child's main thread and a state for every row.

    The child reports its main thread's native id on its ready line and keeps that thread blocked on stdin for the whole test, so the id
    must be in the table; no two whole thread snapshots are compared.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        panel: Panel without a bridge.
        device_bridge: Bridge connected to the local device.
    """
    proc, main_tid = _start_thread_reporting_target()
    try:
        _run(device_bridge.attach(proc.pid))
        panel.set_bridge(device_bridge)
        table = _table(panel, "_threads_table")
        button = _button(panel, "_refresh_threads_btn")
        try:
            _call(panel, "_on_refresh_threads")
            assert not button.isEnabled()
            _wait(qtbot, lambda: button.isEnabled() and table.rowCount() > 0)
            tids = _column(table, 0)
            assert str(main_tid) in tids
            assert all(text.isdigit() for text in tids)
            assert all(_column(table, 1))
        finally:
            _settle(panel)
    finally:
        _run(device_bridge.detach())
        _stop_target(proc)


@pytest.mark.parametrize(
    ("checked", "expected"),
    [
        ((True, False, False, False, False), "call"),
        ((False, False, False, False, False), "call"),
        ((True, True, True, True, True), "call,ret,exec,block,compile"),
        ((False, True, False, True, False), "ret,block"),
        ((False, False, True, False, True), "exec,compile"),
    ],
)
def test_stalker_events_string_follows_the_ticked_boxes(
    panel: FridaPanel,
    checked: tuple[bool, bool, bool, bool, bool],
    expected: str,
) -> None:
    """The events string lists the ticked event types in order and falls back to ``call`` when none is ticked.

    Args:
        panel: Panel without a bridge.
        checked: Tick state of the call, ret, exec, block and compile boxes.
        expected: Events string expected.
    """
    for name, state in zip(("call", "ret", "exec", "block", "compile"), checked, strict=True):
        _get(panel, f"_stalker_{name}_cb", QCheckBox).setChecked(state)
    assert _call(panel, "_get_stalker_events_string") == expected


def test_stalker_start_without_bridge_reports_it(panel: FridaPanel) -> None:
    """Start Trace with no bridge prints a message.

    Args:
        panel: Panel without a bridge.
    """
    _call(panel, "_on_stalker_start")
    assert _console(panel) == _NO_BRIDGE


@pytest.mark.parametrize("handler", ["_on_stalker_start", "_on_stalker_stop"])
def test_stalker_invalid_thread_id_is_rejected(bridge_panel: FridaPanel, handler: str) -> None:
    """A thread id that is not a number is reported and nothing is dispatched.

    Args:
        bridge_panel: Panel with an unattached bridge.
        handler: Start or stop handler under test.
    """
    tid_input = _get(bridge_panel, "_stalker_tid_input", QLineEdit)
    tid_input.setText("abc")
    assert tid_input.text() == "abc"
    _call(bridge_panel, handler)
    assert _console(bridge_panel) == "[-] Invalid thread ID: abc"
    assert not bridge_workers_for(bridge_panel)
    assert _button(bridge_panel, "_stalker_start_btn").isEnabled()


def test_stalker_stop_with_an_invalid_thread_id_reenables_stop_and_flush(bridge_panel: FridaPanel) -> None:
    """After rejecting a bad thread id on Stop, the Stop and Flush buttons are usable again.

    Args:
        bridge_panel: Panel with an unattached bridge.
    """
    _get(bridge_panel, "_stalker_tid_input", QLineEdit).setText("abc")
    assert not _button(bridge_panel, "_stalker_stop_btn").isEnabled()
    assert not _button(bridge_panel, "_stalker_flush_btn").isEnabled()
    _call(bridge_panel, "_on_stalker_stop")
    assert _button(bridge_panel, "_stalker_stop_btn").isEnabled()
    assert _button(bridge_panel, "_stalker_flush_btn").isEnabled()


@pytest.mark.parametrize(
    ("tid", "extra_event", "limit", "transform", "expected"),
    [
        ("", None, 10000, "", "[*] Starting Stalker trace (tid=current, events=call, limit=10000)"),
        ("4242", "ret", 500, "", "[*] Starting Stalker trace (tid=4242, events=call,ret, limit=500)"),
        ("", None, 10000, "iterator.keep();", "[*] Starting Stalker trace with transform (tid=current, events=call, limit=10000)"),
    ],
)
def test_stalker_start_announces_the_trace_and_reports_a_start_failure(
    qtbot: QtBot,
    bridge_panel: FridaPanel,
    tid: str,
    extra_event: str | None,
    limit: int,
    transform: str,
    expected: str,
) -> None:
    """Start Trace announces its settings, disables Start, and on failure reports it and re-enables Start.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridge_panel: Panel with an unattached bridge.
        tid: Text of the thread id field.
        extra_event: Additional event box to tick besides ``call``.
        limit: Value of the limit spin box.
        transform: Text of the transform editor.
        expected: First console line expected.
    """
    _get(bridge_panel, "_stalker_tid_input", QLineEdit).setText(tid)
    if extra_event is not None:
        _get(bridge_panel, f"_stalker_{extra_event}_cb", QCheckBox).setChecked(True)
    _get(bridge_panel, "_stalker_limit_spin", QSpinBox).setValue(limit)
    _get(bridge_panel, "_stalker_transform_input", QPlainTextEdit).setPlainText(transform)
    start = _button(bridge_panel, "_stalker_start_btn")
    _call(bridge_panel, "_on_stalker_start")
    assert not start.isEnabled()
    assert _console(bridge_panel).splitlines()[0] == expected
    _wait_console(qtbot, bridge_panel, f"[-] Stalker start failed: {_NOT_ATTACHED}")
    assert start.isEnabled()
    assert not _button(bridge_panel, "_stalker_stop_btn").isEnabled()


def test_stalker_started_enables_stop_and_flush(panel: FridaPanel) -> None:
    """A started trace is announced with its id and swaps Start for Stop and Flush.

    Args:
        panel: Panel without a bridge.
    """
    _call(panel, "_on_stalker_started", "trace-1")
    assert _console(panel) == "[+] Stalker tracing started (trace_id=trace-1)"
    assert not _button(panel, "_stalker_start_btn").isEnabled()
    assert _button(panel, "_stalker_stop_btn").isEnabled()
    assert _button(panel, "_stalker_flush_btn").isEnabled()


def test_stalker_stop_without_bridge_changes_nothing(panel: FridaPanel) -> None:
    """Stop Trace with no bridge returns silently.

    Args:
        panel: Panel without a bridge.
    """
    stop = _button(panel, "_stalker_stop_btn")
    stop.setEnabled(True)
    _call(panel, "_on_stalker_stop")
    assert stop.isEnabled()
    assert not _console(panel)


def test_stalker_stop_failure_is_reported_and_restores_start(qtbot: QtBot, bridge_panel: FridaPanel) -> None:
    """A failed Stop Trace is reported, and afterwards only Start is enabled.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridge_panel: Panel with an unattached bridge.
    """
    start = _button(bridge_panel, "_stalker_start_btn")
    stop = _button(bridge_panel, "_stalker_stop_btn")
    flush = _button(bridge_panel, "_stalker_flush_btn")
    start.setEnabled(False)
    stop.setEnabled(True)
    flush.setEnabled(True)
    _call(bridge_panel, "_on_stalker_stop")
    assert not stop.isEnabled()
    assert not flush.isEnabled()
    _wait_console(qtbot, bridge_panel, f"[-] Stalker stop failed: {_NOT_ATTACHED}")
    assert start.isEnabled()
    assert not stop.isEnabled()
    assert not flush.isEnabled()


def test_stalker_stopped_prints_the_events_up_to_the_display_limit(panel: FridaPanel) -> None:
    """A finished trace prints a summary, at most the display limit of events, and a count of the rest.

    Args:
        panel: Panel without a bridge.
    """
    _get(panel, "_stalker_display_limit_spin", QSpinBox).setValue(10)
    events = [
        StalkerEvent(event_type="call", from_address=0x401000, to_address=0x402000, depth=1),
        StalkerEvent(event_type="ret", from_address=0x402010, to_address=None, depth=0),
        *[StalkerEvent(event_type="exec", from_address=0x500000 + i, to_address=None, depth=2) for i in range(2, 12)],
    ]
    _button(panel, "_stalker_start_btn").setEnabled(False)
    _button(panel, "_stalker_stop_btn").setEnabled(True)
    _button(panel, "_stalker_flush_btn").setEnabled(True)
    _call(panel, "_on_stalker_stopped", StalkerTrace(thread_id=4242, events=events, event_count=12, duration_ms=12.34))
    assert _console(panel).splitlines() == [
        "[+] Stalker trace complete: 12 events in 12.3ms",
        "  [call] 0x401000 -> 0x402000 (depth=1)",
        "  [ret] 0x402010 (depth=0)",
        *[f"  [exec] 0x{0x500000 + i:X} (depth=2)" for i in range(2, 10)],
        "  ... and 2 more events",
    ]
    assert _button(panel, "_stalker_start_btn").isEnabled()
    assert not _button(panel, "_stalker_stop_btn").isEnabled()
    assert not _button(panel, "_stalker_flush_btn").isEnabled()


def test_stalker_stopped_without_events_prints_only_the_summary(panel: FridaPanel) -> None:
    """A finished trace with no events prints only its summary line.

    Args:
        panel: Panel without a bridge.
    """
    _call(panel, "_on_stalker_stopped", StalkerTrace(thread_id=0, events=[], event_count=0, duration_ms=0.04))
    assert _console(panel) == "[+] Stalker trace complete: 0 events in 0.0ms"
