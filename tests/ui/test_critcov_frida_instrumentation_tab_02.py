# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Coverage for the script-messaging, cancellable, precompiled-script and snapshot controls of the Frida instrumentation tab.

Every test drives a real widget (``ScriptMessagingControls``, ``CancellableControls``, ``PrecompiledScriptControls`` or
``ScriptSnapshotControls``) against a real ``FridaBridge``. Guard-clause and error paths use a bridge that was never attached, whose
refusals (``script not found``, ``not attached to a process``) are the bridge's own documented errors. Success paths attach a real bridge
to a child Python process that the test spawns and wait for its ready marker, then drive the buttons and check the effect inside the
child: a posted message reaches the script's ``recv`` handler, an eternalized or terminated script leaves the bridge registry, a debugger
port accepts a TCP connection, and compiled or snapshotted scripts run and send their payload. Results of the asynchronous bridge calls
are awaited with ``qtbot.waitUntil`` on widget state, never with a fixed sleep.
"""

from __future__ import annotations

import asyncio
import queue
import socket
import sys
import time
from typing import TYPE_CHECKING, Final, cast

import pytest
from PyQt6.QtWidgets import QLabel, QLineEdit, QPlainTextEdit, QPushButton, QSpinBox

from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.core.subprocess_compat import DEVNULL, PIPE, Popen
from intellicrack.ui.panels.async_bridge import bridge_workers_for, drain_bridge_workers, drain_bridge_workers_for
from intellicrack.ui.panels.frida_instrumentation_tab import (
    CancellableControls,
    PrecompiledScriptControls,
    ScriptMessagingControls,
    ScriptSnapshotControls,
)


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator

    import frida
    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")

_WAIT_S: Final[float] = 20.0
_WAIT_MS: Final[int] = 20_000
_TARGET_READY: Final[bytes] = b"critcov-ready"
_TARGET_SOURCE: Final[str] = "import sys\nsys.stdout.write('critcov-ready\\n')\nsys.stdout.flush()\nsys.stdin.read()\n"
_NOT_ATTACHED: Final[str] = "not attached to a process"
_SCRIPT_NOT_FOUND: Final[str] = "script not found"
_MESSAGING_SLOTS: Final[tuple[tuple[str, str, str], ...]] = (
    ("_on_post_message", "_post_message_btn", "Post message"),
    ("_on_eternalize_script", "_eternalize_btn", "Eternalize"),
    ("_on_enable_script_debugger", "_enable_debugger_btn", "Enable debugger"),
    ("_on_disable_script_debugger", "_disable_debugger_btn", "Disable debugger"),
    ("_on_terminate_script", "_terminate_btn", "Terminate"),
)
_MESSAGING_IDS: Final[list[str]] = [slot for slot, _, _ in _MESSAGING_SLOTS]
_MESSAGING_DONE_CASES: Final[tuple[tuple[str, tuple[object, ...], str, str], ...]] = (
    ("_on_post_message_done", (True,), "_post_message_btn", "Message posted"),
    ("_on_post_message_done", (False,), "_post_message_btn", "Post message reported failure"),
    ("_on_eternalize_script_done", ("abc", True), "_eternalize_btn", "Script abc eternalized"),
    ("_on_eternalize_script_done", ("abc", False), "_eternalize_btn", "Eternalize reported failure"),
    ("_on_enable_script_debugger_done", ("abc", 4242, True), "_enable_debugger_btn", "Debugger enabled for abc on port 4242"),
    ("_on_enable_script_debugger_done", ("abc", 4242, False), "_enable_debugger_btn", "Enable debugger reported failure"),
    ("_on_disable_script_debugger_done", ("abc", True), "_disable_debugger_btn", "Debugger disabled for abc"),
    ("_on_disable_script_debugger_done", ("abc", False), "_disable_debugger_btn", "Disable debugger reported failure"),
)
_TERMINATE_OK: Final[tuple[object, ...]] = ("abc", True)
_TERMINATE_FAILED: Final[tuple[object, ...]] = ("abc", False)
_MESSAGING_DONE_IDS: Final[list[str]] = [
    "post_ok",
    "post_failure",
    "eternalize_ok",
    "eternalize_failure",
    "enable_ok",
    "enable_failure",
    "disable_ok",
    "disable_failure",
]


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


def priv[T](obj: object, name: str, typ: type[T]) -> T:
    """Read a private attribute with a known static type.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name, including its leading underscore.
        typ: Static type of the attribute, used only for typing.

    Returns:
        T: The attribute value.
    """
    del typ
    value: T = getattr(obj, name)
    return value


def invoke(obj: object, name: str, *args: object) -> None:
    """Call a private method of a product object by name.

    Args:
        obj: Object that owns the method.
        name: Method name.
        *args: Positional arguments forwarded to the method.
    """
    method = cast("Callable[..., object]", getattr(obj, name))
    method(*args)


def _status(widget: object) -> str:
    """Read the text of a control's status label.

    Args:
        widget: Control whose ``_status_label`` is read.

    Returns:
        str: The label text.
    """
    return priv(widget, "_status_label", QLabel).text()


def _button(widget: object, name: str) -> QPushButton:
    """Look up one of a control's buttons.

    Args:
        widget: Control that owns the button.
        name: Attribute name of the button.

    Returns:
        QPushButton: The button.
    """
    return priv(widget, name, QPushButton)


def _free_port() -> int:
    """Pick a TCP port on the loopback interface that nothing is listening on.

    Returns:
        int: A port number the operating system just handed out.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
    return port


def _port_accepts(port: int) -> bool:
    """Report whether a TCP connection to the loopback port succeeds.

    Args:
        port: Port to connect to.

    Returns:
        bool: True when the connection was accepted.
    """
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def _await_payload(messages: queue.Queue[dict[str, object]], kind: str, timeout_s: float = _WAIT_S) -> dict[str, object]:
    """Wait for a dispatched ``send`` message whose payload has the given ``type``.

    Args:
        messages: Queue fed by the bridge message handler.
        kind: Payload ``type`` value to wait for.
        timeout_s: Seconds to wait before failing the test.

    Returns:
        dict[str, object]: The matching payload.
    """
    deadline = time.monotonic() + timeout_s
    seen: list[dict[str, object]] = []
    while (remaining := deadline - time.monotonic()) > 0:
        try:
            message = messages.get(timeout=remaining)
        except queue.Empty:
            break
        payload = message.get("payload")
        if isinstance(payload, dict):
            entry = cast("dict[str, object]", payload)
            if entry.get("type") == kind:
                return entry
        seen.append(message)
    pytest.fail(f"no {kind!r} payload within {timeout_s}s; saw {seen!r}")


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


def _loaded_script(bridge: FridaBridge, source: str) -> str:
    """Load a persistent script into the bridge's session.

    Args:
        bridge: Attached bridge that will own the script.
        source: JavaScript source of the script.

    Returns:
        str: The bridge's identifier for the loaded script.
    """
    return _run(bridge.execute_persistent_script(source))


def _registered_scripts(bridge: FridaBridge) -> dict[str, object]:
    """Read the bridge's registry of loaded scripts.

    Args:
        bridge: Bridge to inspect.

    Returns:
        dict[str, object]: Script identifiers mapped to their Frida script handles.
    """
    return cast("dict[str, object]", priv(bridge, "_scripts", dict))


@pytest.fixture
def messaging() -> Generator[ScriptMessagingControls]:
    """Build a real script-messaging control and release it afterwards.

    Yields:
        ScriptMessagingControls: A control with no bridge set.
    """
    controls = ScriptMessagingControls()
    try:
        yield controls
    finally:
        drain_bridge_workers_for(controls)
        controls.deleteLater()


@pytest.fixture
def cancellable() -> Generator[CancellableControls]:
    """Build a real cancellable-token control and release it afterwards.

    Yields:
        CancellableControls: A control with no bridge set.
    """
    controls = CancellableControls()
    try:
        yield controls
    finally:
        drain_bridge_workers_for(controls)
        controls.deleteLater()


@pytest.fixture
def precompiled() -> Generator[PrecompiledScriptControls]:
    """Build a real precompiled-script control and release it afterwards.

    Yields:
        PrecompiledScriptControls: A control with no bridge set.
    """
    controls = PrecompiledScriptControls()
    try:
        yield controls
    finally:
        drain_bridge_workers_for(controls)
        controls.deleteLater()


@pytest.fixture
def snapshot() -> Generator[ScriptSnapshotControls]:
    """Build a real script-snapshot control and release it afterwards.

    Yields:
        ScriptSnapshotControls: A control with no bridge set.
    """
    controls = ScriptSnapshotControls()
    try:
        yield controls
    finally:
        drain_bridge_workers_for(controls)
        controls.deleteLater()


@pytest.fixture
def unattached_bridge() -> FridaBridge:
    """Provide a real bridge that has no device and no session.

    Returns:
        FridaBridge: A bridge whose session-bound operations refuse to run.
    """
    return FridaBridge()


@pytest.fixture
def target_process() -> Generator[Popen[bytes]]:
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
def attached_bridge(target_process: Popen[bytes]) -> Generator[FridaBridge]:
    """Initialize a bridge, attach it to the child process and shut it down afterwards.

    Args:
        target_process: The running child process.

    Yields:
        FridaBridge: A bridge attached to ``target_process``.
    """
    bridge = FridaBridge()
    _run(bridge.initialize())
    try:
        _run(bridge.attach(target_process.pid))
        yield bridge
    finally:
        drain_bridge_workers()
        _run(bridge.shutdown())


@pytest.mark.parametrize(("slot", "button", "operation"), _MESSAGING_SLOTS, ids=_MESSAGING_IDS)
def test_messaging_slot_without_bridge_reports_no_bridge(
    messaging: ScriptMessagingControls,
    slot: str,
    button: str,
    operation: str,
) -> None:
    """Every script-messaging slot refuses to run when no bridge was set, before reading any input.

    Args:
        messaging: Control with no bridge.
        slot: Name of the slot under test.
        button: Name of the button that triggers the slot.
        operation: Human-readable operation name (unused here).
    """
    del operation
    priv(messaging, "_script_id_input", QLineEdit).setText("abc")
    priv(messaging, "_post_message_input", QPlainTextEdit).setPlainText('{"a": 1}')

    invoke(messaging, slot)

    assert _status(messaging) == "No bridge available"
    assert _button(messaging, button).isEnabled() is True
    assert bridge_workers_for(messaging) == []


@pytest.mark.parametrize(("slot", "button", "operation"), _MESSAGING_SLOTS, ids=_MESSAGING_IDS)
def test_messaging_slot_without_script_id_asks_for_one(
    messaging: ScriptMessagingControls,
    unattached_bridge: FridaBridge,
    slot: str,
    button: str,
    operation: str,
) -> None:
    """A blank (whitespace-only) script ID is rejected before anything is dispatched.

    Args:
        messaging: Control under test.
        unattached_bridge: Bridge that would answer any dispatched call with an error.
        slot: Name of the slot under test.
        button: Name of the button that triggers the slot.
        operation: Human-readable operation name (unused here).
    """
    del operation
    messaging.set_bridge(unattached_bridge)
    priv(messaging, "_script_id_input", QLineEdit).setText("   ")
    priv(messaging, "_post_message_input", QPlainTextEdit).setPlainText('{"a": 1}')

    invoke(messaging, slot)

    assert _status(messaging) == "Enter a script ID"
    assert _button(messaging, button).isEnabled() is True
    assert bridge_workers_for(messaging) == []


@pytest.mark.parametrize(("slot", "button", "operation"), _MESSAGING_SLOTS, ids=_MESSAGING_IDS)
def test_messaging_slot_failure_reenables_button_and_shows_bridge_error(
    messaging: ScriptMessagingControls,
    unattached_bridge: FridaBridge,
    qtbot: QtBot,
    slot: str,
    button: str,
    operation: str,
) -> None:
    """A script ID the bridge does not know comes back as the bridge's own error and re-enables the button.

    Args:
        messaging: Control under test.
        unattached_bridge: Bridge with no scripts, which raises ``script not found``.
        qtbot: Pytest-qt fixture used to pump events while waiting.
        slot: Name of the slot under test.
        button: Name of the button that triggers the slot.
        operation: Human-readable operation name shown in the failure text.
    """
    messaging.set_bridge(unattached_bridge)
    priv(messaging, "_script_id_input", QLineEdit).setText("ghost")
    priv(messaging, "_post_message_input", QPlainTextEdit).setPlainText('{"a": 1}')
    target = _button(messaging, button)

    invoke(messaging, slot)

    assert target.isEnabled() is False
    qtbot.waitUntil(target.isEnabled, timeout=_WAIT_MS)
    assert _status(messaging) == f"{operation} failed: {_SCRIPT_NOT_FOUND}"


def test_post_message_without_message_asks_for_json(messaging: ScriptMessagingControls, unattached_bridge: FridaBridge) -> None:
    """A blank message is rejected before the JSON check and before any dispatch.

    Args:
        messaging: Control under test.
        unattached_bridge: Bridge that would answer a dispatched call with an error.
    """
    messaging.set_bridge(unattached_bridge)
    priv(messaging, "_script_id_input", QLineEdit).setText("abc")
    priv(messaging, "_post_message_input", QPlainTextEdit).setPlainText("  \n ")

    invoke(messaging, "_on_post_message")

    assert _status(messaging) == "Enter a JSON message"
    assert _button(messaging, "_post_message_btn").isEnabled() is True
    assert bridge_workers_for(messaging) == []


def test_post_message_rejects_invalid_json_before_dispatch(messaging: ScriptMessagingControls, unattached_bridge: FridaBridge) -> None:
    """A message that is not valid JSON is rejected in the widget and never reaches the bridge.

    Args:
        messaging: Control under test.
        unattached_bridge: Bridge that would answer a dispatched call with an error.
    """
    messaging.set_bridge(unattached_bridge)
    priv(messaging, "_script_id_input", QLineEdit).setText("abc")
    priv(messaging, "_post_message_input", QPlainTextEdit).setPlainText("{not json")

    invoke(messaging, "_on_post_message")

    assert _status(messaging) == "Message must be valid JSON"
    assert _button(messaging, "_post_message_btn").isEnabled() is True
    assert bridge_workers_for(messaging) == []


@pytest.mark.parametrize(
    ("handler", "args", "button", "expected"),
    _MESSAGING_DONE_CASES,
    ids=_MESSAGING_DONE_IDS,
)
def test_messaging_done_handler_reenables_button_and_reports_outcome(
    messaging: ScriptMessagingControls,
    handler: str,
    args: tuple[object, ...],
    button: str,
    expected: str,
) -> None:
    """Each success handler shows a message that matches the boolean the bridge returned and re-enables its button.

    Args:
        messaging: Control under test.
        handler: Name of the result handler.
        args: Arguments in the shape the dispatch lambdas pass (script ID, port, result flag).
        button: Name of the button the handler must re-enable.
        expected: Status text expected for the given result.
    """
    target = _button(messaging, button)
    target.setEnabled(False)

    invoke(messaging, handler, *args)

    assert target.isEnabled() is True
    assert _status(messaging) == expected


def test_terminate_done_with_success_clears_the_script_id(messaging: ScriptMessagingControls) -> None:
    """A terminated script no longer exists, so the script-ID field is emptied.

    Args:
        messaging: Control under test.
    """
    id_input = priv(messaging, "_script_id_input", QLineEdit)
    id_input.setText("abc")
    _button(messaging, "_terminate_btn").setEnabled(False)

    invoke(messaging, "_on_terminate_script_done", *_TERMINATE_OK)

    assert not id_input.text()
    assert _status(messaging) == "Script abc terminated"
    assert _button(messaging, "_terminate_btn").isEnabled() is True


def test_terminate_done_with_failure_keeps_the_script_id(messaging: ScriptMessagingControls) -> None:
    """A failed termination leaves the script ID in place so the operator can retry.

    Args:
        messaging: Control under test.
    """
    id_input = priv(messaging, "_script_id_input", QLineEdit)
    id_input.setText("abc")
    _button(messaging, "_terminate_btn").setEnabled(False)

    invoke(messaging, "_on_terminate_script_done", *_TERMINATE_FAILED)

    assert id_input.text() == "abc"
    assert _status(messaging) == "Terminate reported failure"
    assert _button(messaging, "_terminate_btn").isEnabled() is True


@pytest.mark.spawns_process
def test_post_message_delivers_the_json_to_the_script(
    messaging: ScriptMessagingControls,
    attached_bridge: FridaBridge,
    qtbot: QtBot,
) -> None:
    """The Post Message button delivers its JSON to the script's ``recv`` handler and reports success.

    Args:
        messaging: Control under test.
        attached_bridge: Bridge attached to a child process.
        qtbot: Pytest-qt fixture used to pump events while waiting.
    """
    received: queue.Queue[dict[str, object]] = queue.Queue()
    attached_bridge.set_message_handler(received.put)
    script_id = _loaded_script(
        attached_bridge,
        "recv(function (message) { send({ type: 'critcov_echo', got: message.value }); });",
    )
    messaging.set_bridge(attached_bridge)
    priv(messaging, "_script_id_input", QLineEdit).setText(script_id)
    priv(messaging, "_post_message_input", QPlainTextEdit).setPlainText('{"value": 5}')
    button = _button(messaging, "_post_message_btn")

    invoke(messaging, "_on_post_message")

    assert button.isEnabled() is False
    qtbot.waitUntil(button.isEnabled, timeout=_WAIT_MS)
    assert _status(messaging) == "Message posted"
    assert _await_payload(received, "critcov_echo") == {"type": "critcov_echo", "got": 5}


@pytest.mark.spawns_process
def test_eternalize_script_releases_the_script_from_the_bridge(
    messaging: ScriptMessagingControls,
    attached_bridge: FridaBridge,
    qtbot: QtBot,
) -> None:
    """The Eternalize button hands the script over to the target and the bridge forgets it.

    Args:
        messaging: Control under test.
        attached_bridge: Bridge attached to a child process.
        qtbot: Pytest-qt fixture used to pump events while waiting.
    """
    script_id = _loaded_script(attached_bridge, "var critcovEternal = 1;")
    assert script_id in _registered_scripts(attached_bridge)
    messaging.set_bridge(attached_bridge)
    priv(messaging, "_script_id_input", QLineEdit).setText(script_id)
    button = _button(messaging, "_eternalize_btn")

    invoke(messaging, "_on_eternalize_script")

    assert button.isEnabled() is False
    qtbot.waitUntil(button.isEnabled, timeout=_WAIT_MS)
    assert _status(messaging) == f"Script {script_id} eternalized"
    assert script_id not in _registered_scripts(attached_bridge)


@pytest.mark.spawns_process
def test_terminate_script_removes_the_script_and_clears_the_field(
    messaging: ScriptMessagingControls,
    attached_bridge: FridaBridge,
    qtbot: QtBot,
) -> None:
    """The Terminate button stops the script, the bridge forgets it and the ID field empties.

    Args:
        messaging: Control under test.
        attached_bridge: Bridge attached to a child process.
        qtbot: Pytest-qt fixture used to pump events while waiting.
    """
    script_id = _loaded_script(attached_bridge, "var critcovTerminate = 1;")
    messaging.set_bridge(attached_bridge)
    id_input = priv(messaging, "_script_id_input", QLineEdit)
    id_input.setText(script_id)
    button = _button(messaging, "_terminate_btn")

    invoke(messaging, "_on_terminate_script")

    assert button.isEnabled() is False
    qtbot.waitUntil(button.isEnabled, timeout=_WAIT_MS)
    assert _status(messaging) == f"Script {script_id} terminated"
    assert not id_input.text()
    assert script_id not in _registered_scripts(attached_bridge)


@pytest.mark.spawns_process
def test_enable_script_debugger_opens_the_chosen_port(
    messaging: ScriptMessagingControls,
    attached_bridge: FridaBridge,
    qtbot: QtBot,
) -> None:
    """The Enable Debugger button opens an inspector listener on the port from the spin box.

    Args:
        messaging: Control under test.
        attached_bridge: Bridge attached to a child process.
        qtbot: Pytest-qt fixture used to pump events while waiting.
    """
    script_id = _loaded_script(attached_bridge, "var critcovDebug = 1;")
    port = _free_port()
    messaging.set_bridge(attached_bridge)
    priv(messaging, "_script_id_input", QLineEdit).setText(script_id)
    priv(messaging, "_debugger_port_input", QSpinBox).setValue(port)
    button = _button(messaging, "_enable_debugger_btn")

    try:
        invoke(messaging, "_on_enable_script_debugger")

        assert button.isEnabled() is False
        qtbot.waitUntil(button.isEnabled, timeout=_WAIT_MS)
        assert _status(messaging) == f"Debugger enabled for {script_id} on port {port}"
        qtbot.waitUntil(lambda: _port_accepts(port), timeout=_WAIT_MS)
    finally:
        _run(attached_bridge.disable_script_debugger(script_id))


@pytest.mark.spawns_process
def test_disable_script_debugger_closes_the_port(
    messaging: ScriptMessagingControls,
    attached_bridge: FridaBridge,
    qtbot: QtBot,
) -> None:
    """The Disable Debugger button closes an inspector listener that was open.

    Args:
        messaging: Control under test.
        attached_bridge: Bridge attached to a child process.
        qtbot: Pytest-qt fixture used to pump events while waiting.
    """
    script_id = _loaded_script(attached_bridge, "var critcovDebugOff = 1;")
    port = _free_port()
    assert _run(attached_bridge.enable_script_debugger(script_id, port)) is True
    qtbot.waitUntil(lambda: _port_accepts(port), timeout=_WAIT_MS)
    messaging.set_bridge(attached_bridge)
    priv(messaging, "_script_id_input", QLineEdit).setText(script_id)
    button = _button(messaging, "_disable_debugger_btn")

    invoke(messaging, "_on_disable_script_debugger")

    assert button.isEnabled() is False
    qtbot.waitUntil(button.isEnabled, timeout=_WAIT_MS)
    assert _status(messaging) == f"Debugger disabled for {script_id}"
    qtbot.waitUntil(lambda: not _port_accepts(port), timeout=_WAIT_MS)


@pytest.mark.parametrize("slot", ["_on_create_cancellable", "_on_cancel"])
def test_cancellable_slot_without_bridge_reports_no_bridge(cancellable: CancellableControls, slot: str) -> None:
    """Creating or cancelling a token with no bridge set reports it and changes nothing.

    Args:
        cancellable: Control with no bridge.
        slot: Name of the slot under test.
    """
    invoke(cancellable, slot)

    assert _status(cancellable) == "No bridge available"
    assert _button(cancellable, "_create_btn").isEnabled() is True
    assert cancellable.last_cancellable_id() is None
    assert bridge_workers_for(cancellable) == []


def test_cancel_without_a_created_token_reports_nothing_to_cancel(
    cancellable: CancellableControls,
    unattached_bridge: FridaBridge,
) -> None:
    """Cancelling before any token was created is rejected before the bridge is called.

    Args:
        cancellable: Control under test.
        unattached_bridge: Real bridge with no tokens.
    """
    cancellable.set_bridge(unattached_bridge)

    invoke(cancellable, "_on_cancel")

    assert _status(cancellable) == "No cancellable to cancel"
    assert bridge_workers_for(cancellable) == []


def test_create_cancellable_registers_a_real_token_in_the_bridge(
    cancellable: CancellableControls,
    unattached_bridge: FridaBridge,
    qtbot: QtBot,
) -> None:
    """Create Cancellable stores the bridge's new token ID in the widget and enables Cancel.

    Args:
        cancellable: Control under test.
        unattached_bridge: Real bridge, which needs no session to mint a token.
        qtbot: Pytest-qt fixture used to pump events while waiting.
    """
    cancellable.set_bridge(unattached_bridge)
    create = _button(cancellable, "_create_btn")
    cancel = _button(cancellable, "_cancel_btn")
    assert cancel.isEnabled() is False

    invoke(cancellable, "_on_create_cancellable")

    assert create.isEnabled() is False
    qtbot.waitUntil(create.isEnabled, timeout=_WAIT_MS)
    tokens = cast("dict[str, frida.Cancellable]", priv(unattached_bridge, "_cancellables", dict))
    token_id = cancellable.last_cancellable_id()
    assert token_id is not None
    assert list(tokens) == [token_id]
    assert tokens[token_id].is_cancelled is False
    assert priv(cancellable, "_cancellable_id_input", QLineEdit).text() == token_id
    assert cancel.isEnabled() is True
    assert _status(cancellable) == f"Created {token_id}"


def test_cancel_triggers_the_token_and_clears_the_widget(
    cancellable: CancellableControls,
    unattached_bridge: FridaBridge,
    qtbot: QtBot,
) -> None:
    """Cancel triggers the real token, drops it from the bridge and resets the widget.

    Args:
        cancellable: Control under test.
        unattached_bridge: Real bridge holding the token.
        qtbot: Pytest-qt fixture used to pump events while waiting.
    """
    cancellable.set_bridge(unattached_bridge)
    create = _button(cancellable, "_create_btn")
    invoke(cancellable, "_on_create_cancellable")
    qtbot.waitUntil(create.isEnabled, timeout=_WAIT_MS)
    token_id = cancellable.last_cancellable_id()
    assert token_id is not None
    tokens = cast("dict[str, frida.Cancellable]", priv(unattached_bridge, "_cancellables", dict))
    token = tokens[token_id]
    assert token.is_cancelled is False

    invoke(cancellable, "_on_cancel")

    assert _button(cancellable, "_cancel_btn").isEnabled() is False
    qtbot.waitUntil(lambda: _status(cancellable) == f"Cancelled {token_id}", timeout=_WAIT_MS)
    assert token.is_cancelled is True
    assert token_id not in tokens
    assert cancellable.last_cancellable_id() is None
    assert not priv(cancellable, "_cancellable_id_input", QLineEdit).text()


def test_cancel_of_a_token_the_bridge_no_longer_has_reports_not_found(
    cancellable: CancellableControls,
    unattached_bridge: FridaBridge,
    qtbot: QtBot,
) -> None:
    """A token already cancelled elsewhere is reported as not found and stays selected in the widget.

    Args:
        cancellable: Control under test.
        unattached_bridge: Real bridge holding the token.
        qtbot: Pytest-qt fixture used to pump events while waiting.
    """
    cancellable.set_bridge(unattached_bridge)
    create = _button(cancellable, "_create_btn")
    invoke(cancellable, "_on_create_cancellable")
    qtbot.waitUntil(create.isEnabled, timeout=_WAIT_MS)
    token_id = cancellable.last_cancellable_id()
    assert token_id is not None
    assert _run(unattached_bridge.cancel(token_id)) is True

    invoke(cancellable, "_on_cancel")

    qtbot.waitUntil(lambda: _status(cancellable) == f"Cancellable {token_id} was not found", timeout=_WAIT_MS)
    assert cancellable.last_cancellable_id() == token_id
    assert priv(cancellable, "_cancellable_id_input", QLineEdit).text() == token_id


def test_create_cancellable_error_reenables_the_button(cancellable: CancellableControls) -> None:
    """A failed token creation shows the error and re-enables Create Cancellable.

    Args:
        cancellable: Control under test.
    """
    create = _button(cancellable, "_create_btn")
    create.setEnabled(False)

    invoke(cancellable, "_on_create_cancellable_error", RuntimeError("boom"))

    assert create.isEnabled() is True
    assert _status(cancellable) == "Create failed: boom"
    assert cancellable.last_cancellable_id() is None


def test_cancel_error_reenables_the_cancel_button(cancellable: CancellableControls) -> None:
    """A failed cancellation shows the error with the token ID and re-enables Cancel.

    Args:
        cancellable: Control under test.
    """
    cancel = _button(cancellable, "_cancel_btn")
    assert cancel.isEnabled() is False

    invoke(cancellable, "_on_cancel_error", "tok1", RuntimeError("boom"))

    assert cancel.isEnabled() is True
    assert _status(cancellable) == "Cancel failed: boom"


@pytest.mark.parametrize("slot", ["_on_compile_script", "_on_load_compiled_script"])
def test_precompiled_slot_without_bridge_reports_no_bridge(precompiled: PrecompiledScriptControls, slot: str) -> None:
    """Compile and Load Compiled Script refuse to run when no bridge was set.

    Args:
        precompiled: Control with no bridge.
        slot: Name of the slot under test.
    """
    priv(precompiled, "_source_input", QPlainTextEdit).setPlainText("var x = 1;")
    priv(precompiled, "_bytecode_input", QLineEdit).setText("00")

    invoke(precompiled, slot)

    assert _status(precompiled) == "No bridge available"
    assert _button(precompiled, "_compile_btn").isEnabled() is True
    assert _button(precompiled, "_load_compiled_btn").isEnabled() is True
    assert bridge_workers_for(precompiled) == []


def test_compile_without_source_asks_for_source(precompiled: PrecompiledScriptControls, unattached_bridge: FridaBridge) -> None:
    """Compile with only whitespace in the source box is rejected before dispatch.

    Args:
        precompiled: Control under test.
        unattached_bridge: Bridge that would answer a dispatched call with an error.
    """
    precompiled.set_bridge(unattached_bridge)
    priv(precompiled, "_source_input", QPlainTextEdit).setPlainText("  \n ")

    invoke(precompiled, "_on_compile_script")

    assert _status(precompiled) == "Enter script source to compile"
    assert _button(precompiled, "_compile_btn").isEnabled() is True
    assert bridge_workers_for(precompiled) == []


def test_load_compiled_without_bytecode_asks_for_bytecode(
    precompiled: PrecompiledScriptControls,
    unattached_bridge: FridaBridge,
) -> None:
    """Load Compiled Script with a blank bytecode field is rejected before dispatch.

    Args:
        precompiled: Control under test.
        unattached_bridge: Bridge that would answer a dispatched call with an error.
    """
    precompiled.set_bridge(unattached_bridge)
    priv(precompiled, "_bytecode_input", QLineEdit).setText("   ")

    invoke(precompiled, "_on_load_compiled_script")

    assert _status(precompiled) == "Enter (or compile) bytecode to load"
    assert _button(precompiled, "_load_compiled_btn").isEnabled() is True
    assert bridge_workers_for(precompiled) == []


@pytest.mark.parametrize(
    ("slot", "button", "operation"),
    [
        ("_on_compile_script", "_compile_btn", "Compile"),
        ("_on_load_compiled_script", "_load_compiled_btn", "Load compiled script"),
    ],
    ids=["compile", "load_compiled"],
)
def test_precompiled_failure_reenables_button_and_shows_bridge_error(
    precompiled: PrecompiledScriptControls,
    unattached_bridge: FridaBridge,
    qtbot: QtBot,
    slot: str,
    button: str,
    operation: str,
) -> None:
    """A bridge that is not attached refuses the call and the widget shows that refusal.

    Args:
        precompiled: Control under test.
        unattached_bridge: Bridge with no session.
        qtbot: Pytest-qt fixture used to pump events while waiting.
        slot: Name of the slot under test.
        button: Name of the button that triggers the slot.
        operation: Human-readable operation name shown in the failure text.
    """
    precompiled.set_bridge(unattached_bridge)
    priv(precompiled, "_source_input", QPlainTextEdit).setPlainText("var x = 1;")
    priv(precompiled, "_bytecode_input", QLineEdit).setText("00")
    target = _button(precompiled, button)

    invoke(precompiled, slot)

    assert target.isEnabled() is False
    qtbot.waitUntil(target.isEnabled, timeout=_WAIT_MS)
    assert _status(precompiled) == f"{operation} failed: {_NOT_ATTACHED}"


@pytest.mark.spawns_process
def test_compile_fills_the_bytecode_field_with_real_bytecode(
    precompiled: PrecompiledScriptControls,
    attached_bridge: FridaBridge,
    qtbot: QtBot,
) -> None:
    """Compile puts valid hex bytecode in the field and reports the number of bytes it holds.

    Args:
        precompiled: Control under test.
        attached_bridge: Bridge attached to a child process.
        qtbot: Pytest-qt fixture used to pump events while waiting.
    """
    precompiled.set_bridge(attached_bridge)
    priv(precompiled, "_source_input", QPlainTextEdit).setPlainText("send({ type: 'critcov_compiled', value: 11 });")
    button = _button(precompiled, "_compile_btn")

    invoke(precompiled, "_on_compile_script")

    assert button.isEnabled() is False
    qtbot.waitUntil(button.isEnabled, timeout=_WAIT_MS)
    text = priv(precompiled, "_bytecode_input", QLineEdit).text()
    data = bytes.fromhex(text)
    assert len(data) > 0
    assert _status(precompiled) == f"Compiled {len(data)} bytes"


@pytest.mark.spawns_process
def test_load_compiled_script_runs_the_bytecode(
    precompiled: PrecompiledScriptControls,
    attached_bridge: FridaBridge,
    qtbot: QtBot,
) -> None:
    """Load Compiled Script registers a script from compiled bytecode and the script sends its payload.

    Args:
        precompiled: Control under test.
        attached_bridge: Bridge attached to a child process.
        qtbot: Pytest-qt fixture used to pump events while waiting.
    """
    received: queue.Queue[dict[str, object]] = queue.Queue()
    attached_bridge.set_message_handler(received.put)
    bytecode_hex = _run(attached_bridge.compile_script("send({ type: 'critcov_loaded', value: 13 });"))
    precompiled.set_bridge(attached_bridge)
    priv(precompiled, "_bytecode_input", QLineEdit).setText(bytecode_hex)
    button = _button(precompiled, "_load_compiled_btn")

    invoke(precompiled, "_on_load_compiled_script")

    assert button.isEnabled() is False
    qtbot.waitUntil(button.isEnabled, timeout=_WAIT_MS)
    registered = list(_registered_scripts(attached_bridge))
    assert len(registered) == 1
    assert _status(precompiled) == f"Loaded script {registered[0]}"
    assert _await_payload(received, "critcov_loaded") == {"type": "critcov_loaded", "value": 13}


@pytest.mark.parametrize("slot", ["_on_snapshot_script", "_on_load_script_with_snapshot"])
def test_snapshot_slot_without_bridge_reports_no_bridge(snapshot: ScriptSnapshotControls, slot: str) -> None:
    """Create Snapshot and Load With Snapshot refuse to run when no bridge was set.

    Args:
        snapshot: Control with no bridge.
        slot: Name of the slot under test.
    """
    priv(snapshot, "_embed_script_input", QPlainTextEdit).setPlainText("var x = 1;")
    priv(snapshot, "_snapshot_source_input", QPlainTextEdit).setPlainText("var y = 2;")
    priv(snapshot, "_snapshot_input", QLineEdit).setText("00")

    invoke(snapshot, slot)

    assert _status(snapshot) == "No bridge available"
    assert _button(snapshot, "_snapshot_btn").isEnabled() is True
    assert _button(snapshot, "_load_with_snapshot_btn").isEnabled() is True
    assert bridge_workers_for(snapshot) == []


def test_snapshot_without_embed_script_asks_for_one(snapshot: ScriptSnapshotControls, unattached_bridge: FridaBridge) -> None:
    """Create Snapshot with a blank embed script is rejected before dispatch.

    Args:
        snapshot: Control under test.
        unattached_bridge: Bridge that would answer a dispatched call with an error.
    """
    snapshot.set_bridge(unattached_bridge)
    priv(snapshot, "_embed_script_input", QPlainTextEdit).setPlainText("  \n ")

    invoke(snapshot, "_on_snapshot_script")

    assert _status(snapshot) == "Enter an embed script to snapshot"
    assert _button(snapshot, "_snapshot_btn").isEnabled() is True
    assert bridge_workers_for(snapshot) == []


def test_load_with_snapshot_without_source_asks_for_source(snapshot: ScriptSnapshotControls, unattached_bridge: FridaBridge) -> None:
    """Load With Snapshot with a blank source is rejected before the snapshot field is read.

    Args:
        snapshot: Control under test.
        unattached_bridge: Bridge that would answer a dispatched call with an error.
    """
    snapshot.set_bridge(unattached_bridge)
    priv(snapshot, "_snapshot_source_input", QPlainTextEdit).setPlainText("  ")
    priv(snapshot, "_snapshot_input", QLineEdit).setText("00")

    invoke(snapshot, "_on_load_script_with_snapshot")

    assert _status(snapshot) == "Enter script source to run with the snapshot"
    assert _button(snapshot, "_load_with_snapshot_btn").isEnabled() is True
    assert bridge_workers_for(snapshot) == []


def test_load_with_snapshot_without_snapshot_asks_for_one(snapshot: ScriptSnapshotControls, unattached_bridge: FridaBridge) -> None:
    """Load With Snapshot with source but a blank snapshot field is rejected before dispatch.

    Args:
        snapshot: Control under test.
        unattached_bridge: Bridge that would answer a dispatched call with an error.
    """
    snapshot.set_bridge(unattached_bridge)
    priv(snapshot, "_snapshot_source_input", QPlainTextEdit).setPlainText("var y = 2;")
    priv(snapshot, "_snapshot_input", QLineEdit).setText("   ")

    invoke(snapshot, "_on_load_script_with_snapshot")

    assert _status(snapshot) == "Enter (or create) a snapshot to load"
    assert _button(snapshot, "_load_with_snapshot_btn").isEnabled() is True
    assert bridge_workers_for(snapshot) == []


@pytest.mark.parametrize(
    ("slot", "button", "operation"),
    [
        ("_on_snapshot_script", "_snapshot_btn", "Create snapshot"),
        ("_on_load_script_with_snapshot", "_load_with_snapshot_btn", "Load with snapshot"),
    ],
    ids=["snapshot", "load_with_snapshot"],
)
def test_snapshot_failure_reenables_button_and_shows_bridge_error(
    snapshot: ScriptSnapshotControls,
    unattached_bridge: FridaBridge,
    qtbot: QtBot,
    slot: str,
    button: str,
    operation: str,
) -> None:
    """A bridge that is not attached refuses the call and the widget shows that refusal.

    Args:
        snapshot: Control under test.
        unattached_bridge: Bridge with no session.
        qtbot: Pytest-qt fixture used to pump events while waiting.
        slot: Name of the slot under test.
        button: Name of the button that triggers the slot.
        operation: Human-readable operation name shown in the failure text.
    """
    snapshot.set_bridge(unattached_bridge)
    priv(snapshot, "_embed_script_input", QPlainTextEdit).setPlainText("var x = 1;")
    priv(snapshot, "_warmup_script_input", QLineEdit).setText("var warm = 1;")
    priv(snapshot, "_snapshot_source_input", QPlainTextEdit).setPlainText("var y = 2;")
    priv(snapshot, "_snapshot_input", QLineEdit).setText("00")
    target = _button(snapshot, button)

    invoke(snapshot, slot)

    assert target.isEnabled() is False
    qtbot.waitUntil(target.isEnabled, timeout=_WAIT_MS)
    assert _status(snapshot) == f"{operation} failed: {_NOT_ATTACHED}"


@pytest.mark.spawns_process
def test_snapshot_with_warmup_fills_the_snapshot_field(
    snapshot: ScriptSnapshotControls,
    attached_bridge: FridaBridge,
    qtbot: QtBot,
) -> None:
    """Create Snapshot with a warmup script stores valid hex snapshot bytes and reports their count.

    Args:
        snapshot: Control under test.
        attached_bridge: Bridge attached to a child process.
        qtbot: Pytest-qt fixture used to pump events while waiting.
    """
    snapshot.set_bridge(attached_bridge)
    priv(snapshot, "_embed_script_input", QPlainTextEdit).setPlainText("var critcovWarm = 'critcov-warm';")
    priv(snapshot, "_warmup_script_input", QLineEdit).setText("var critcovWarmup = 1;")
    button = _button(snapshot, "_snapshot_btn")

    invoke(snapshot, "_on_snapshot_script")

    assert button.isEnabled() is False
    qtbot.waitUntil(button.isEnabled, timeout=_WAIT_MS)
    text = priv(snapshot, "_snapshot_input", QLineEdit).text()
    data = bytes.fromhex(text)
    assert len(data) > 0
    assert _status(snapshot) == f"Snapshot captured ({len(data)} bytes)"


@pytest.mark.spawns_process
def test_snapshot_then_load_with_snapshot_runs_a_warm_started_script(
    snapshot: ScriptSnapshotControls,
    attached_bridge: FridaBridge,
    qtbot: QtBot,
) -> None:
    """A snapshot made through the widget warm-starts a script, which sees the global the snapshot defined.

    Args:
        snapshot: Control under test.
        attached_bridge: Bridge attached to a child process.
        qtbot: Pytest-qt fixture used to pump events while waiting.
    """
    received: queue.Queue[dict[str, object]] = queue.Queue()
    attached_bridge.set_message_handler(received.put)
    snapshot.set_bridge(attached_bridge)
    priv(snapshot, "_embed_script_input", QPlainTextEdit).setPlainText("var critcovWarm = 'critcov-warm';")
    make = _button(snapshot, "_snapshot_btn")
    invoke(snapshot, "_on_snapshot_script")
    qtbot.waitUntil(make.isEnabled, timeout=_WAIT_MS)
    assert priv(snapshot, "_snapshot_input", QLineEdit).text()
    priv(snapshot, "_snapshot_source_input", QPlainTextEdit).setPlainText(
        "send({ type: 'critcov_snapshot', seen: critcovWarm });",
    )
    load = _button(snapshot, "_load_with_snapshot_btn")

    invoke(snapshot, "_on_load_script_with_snapshot")

    assert load.isEnabled() is False
    qtbot.waitUntil(load.isEnabled, timeout=_WAIT_MS)
    registered = list(_registered_scripts(attached_bridge))
    assert len(registered) == 1
    assert _status(snapshot) == f"Loaded script {registered[0]}"
    assert _await_payload(received, "critcov_snapshot") == {"type": "critcov_snapshot", "seen": "critcov-warm"}
