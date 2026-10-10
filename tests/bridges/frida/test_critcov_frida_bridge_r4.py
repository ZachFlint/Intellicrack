# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Fourth-pass critical-coverage tests for the Frida bridge: device removal, device switching and canceled attaches.

Every test drives the real Frida runtime against a child process that the test
itself starts (a Python interpreter blocked on stdin, a uniquely named copy of
``cmd.exe``, or a private ``notepad.exe``), never against the pytest process.
The cases cover the removal of a remote device that is not the bridge's current
device, the removal of one that was never added, the release of a session that
will not detach (a frozen target) while a remote device is removed or the
device is switched, and an attach by name under a cancellation token that was
already canceled.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import sys
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import frida
import pytest
from structlog.testing import capture_logs

from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.core.subprocess_compat import DEVNULL, PIPE, Popen
from intellicrack.core.types import FridaDeviceInfo, ToolError
from tests._helpers.frida_targets import (
    resume_process,
    run_bounded,
    suspend_process,
    wait_for_stdout_line,
)
from tests._helpers.process_cleanup import kill_pid_tree


if TYPE_CHECKING:
    from collections.abc import Generator


pytestmark = pytest.mark.spawns_process

_WAIT_S: Final[float] = 30.0
_FROZEN_CALL_S: Final[float] = 45.0
_TARGET_READY: Final[bytes] = b"critcov-ready"
_TARGET_SOURCE: Final[str] = "import sys\nsys.stdout.write('critcov-ready\\n')\nsys.stdout.flush()\nsys.stdin.read()\n"
_UNKNOWN_HOST: Final[str] = "127.0.0.1:59981"
_CURRENT_HOST: Final[str] = "127.0.0.1:59982"
_OTHER_HOST: Final[str] = "127.0.0.1:59983"
_FROZEN_HOST: Final[str] = "127.0.0.1:59984"
_DEVICE_FAILED: Final[str] = "failed to initialize Frida device"
_ENUMERATE_POLL_S: Final[float] = 0.1


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


def put(obj: object, name: str, *, value: object) -> None:
    """Set a private data attribute on an object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name, including its leading underscore.
        value: Value to store.
    """
    setattr(obj, name, value)


def _device_ids() -> list[str]:
    """List the ids of the devices the Frida device manager currently knows.

    Returns:
        list[str]: The device ids.
    """
    return [device.id for device in frida.get_device_manager().enumerate_devices()]


def _forget_remote(host: str) -> None:
    """Remove a remote device from the Frida device manager if it is still there.

    Args:
        host: The ``host:port`` the device was added with.
    """
    with contextlib.suppress(frida.InvalidArgumentError):
        frida.get_device_manager().remove_remote_device(host)


def _end_process(proc: Popen[bytes]) -> None:
    """Kill a child process and its descendants, wait for it and close its pipes.

    Args:
        proc: The child process to end.
    """
    try:
        kill_pid_tree(proc.pid)
        proc.wait(timeout=_WAIT_S)
    finally:
        for stream in (proc.stdin, proc.stdout):
            if stream is not None:
                stream.close()


@pytest.fixture
def python_target() -> Generator[Popen[bytes]]:
    """Start a Python child that reports readiness on stdout and blocks on stdin, and end it afterwards.

    Yields:
        Popen[bytes]: The ready child process.
    """
    proc = Popen([sys.executable, "-c", _TARGET_SOURCE], stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
    try:
        wait_for_stdout_line(proc, _TARGET_READY)
        yield proc
    finally:
        _end_process(proc)


@pytest.fixture
def idle_bridge() -> Generator[FridaBridge]:
    """Initialize a bridge on the local Frida device without attaching and shut it down afterwards.

    Yields:
        FridaBridge: A connected bridge with no session.
    """
    bridge = FridaBridge()
    run_bounded(bridge.initialize())
    try:
        yield bridge
    finally:
        run_bounded(bridge.shutdown())


@pytest.fixture
def attached_bridge(python_target: Popen[bytes], idle_bridge: FridaBridge) -> FridaBridge:
    """Attach the idle bridge to the Python child.

    Args:
        python_target: The running child process.
        idle_bridge: Initialized bridge without a session.

    Returns:
        FridaBridge: The bridge attached to ``python_target``.
    """
    run_bounded(idle_bridge.attach(python_target.pid))
    return idle_bridge


@pytest.fixture
def named_target(tmp_path: Path) -> Generator[tuple[Popen[bytes], str]]:
    """Start a copy of ``cmd.exe`` under a name no other process has, once Frida lists it, and end it afterwards.

    Args:
        tmp_path: Directory that holds the renamed copy.

    Yields:
        tuple[Popen[bytes], str]: The child process and the image name it runs under.
    """
    name = f"critcovr4{uuid.uuid4().hex[:8]}.exe"
    copy = tmp_path / name
    shutil.copy2(Path(os.environ["SYSTEMROOT"]) / "System32" / "cmd.exe", copy)
    proc = Popen([str(copy), "/c", "pause"], stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL)
    try:
        device = frida.get_local_device()
        deadline = time.monotonic() + _WAIT_S
        while not any(entry.pid == proc.pid and entry.name == name for entry in device.enumerate_processes()):
            if time.monotonic() >= deadline:
                pytest.fail(f"Frida did not list {name} (pid {proc.pid}) within {_WAIT_S:g}s", pytrace=False)
            time.sleep(_ENUMERATE_POLL_S)
        yield proc, name
    finally:
        _end_process(proc)


def test_remove_remote_device_that_was_never_added_fails_with_frida_reason(idle_bridge: FridaBridge) -> None:
    """Removing an endpoint the device manager does not know raises the device error with Frida's reason, and keeps the current device.

    Args:
        idle_bridge: Initialized bridge without a session.
    """
    original = priv(idle_bridge, "_device", object)
    assert f"socket@{_UNKNOWN_HOST}" not in _device_ids()

    with capture_logs() as logs, pytest.raises(ToolError) as excinfo:
        run_bounded(idle_bridge.remove_remote_device(_UNKNOWN_HOST))

    assert excinfo.value.message == _DEVICE_FAILED
    assert excinfo.value.details == {
        "frida_error": "device not found",
        "frida_error_type": "InvalidArgumentError",
        "host": _UNKNOWN_HOST,
    }
    assert isinstance(excinfo.value.__cause__, frida.InvalidArgumentError)
    assert priv(idle_bridge, "_device", object) is original
    assert any(entry["event"] == "remote_device_remove_failed" and entry["host"] == _UNKNOWN_HOST for entry in logs)
    assert not any(entry["event"] == "remote_device_removed" for entry in logs)


def test_remove_remote_device_other_than_the_local_current_one_keeps_device_and_session(attached_bridge: FridaBridge) -> None:
    """Removing a remote endpoint while the bridge works on the local device removes only that endpoint.

    Args:
        attached_bridge: Bridge attached to the Python child through the local device.
    """
    local = priv(attached_bridge, "_device", object)
    session = priv(attached_bridge, "_session", object)
    try:
        frida.get_device_manager().add_remote_device(_OTHER_HOST)
        assert f"socket@{_OTHER_HOST}" in _device_ids()

        run_bounded(attached_bridge.remove_remote_device(_OTHER_HOST))

        assert f"socket@{_OTHER_HOST}" not in _device_ids()
        assert priv(attached_bridge, "_device", object) is local
        assert priv(attached_bridge, "_session", object) is session
        assert attached_bridge.state.process_attached is True
    finally:
        _forget_remote(_OTHER_HOST)


def test_remove_remote_device_other_than_the_current_remote_one_keeps_device_and_session(attached_bridge: FridaBridge) -> None:
    """Removing one remote endpoint while the bridge works on a different remote device keeps that device and its session.

    Args:
        attached_bridge: Bridge attached to the Python child; its current device is replaced by a remote one.
    """
    session = priv(attached_bridge, "_session", object)
    try:
        current = frida.get_device_manager().add_remote_device(_CURRENT_HOST)
        frida.get_device_manager().add_remote_device(_OTHER_HOST)
        put(attached_bridge, "_device", value=current)

        run_bounded(attached_bridge.remove_remote_device(_OTHER_HOST))

        assert f"socket@{_OTHER_HOST}" not in _device_ids()
        assert f"socket@{_CURRENT_HOST}" in _device_ids()
        assert priv(attached_bridge, "_device", object) is current
        assert priv(attached_bridge, "_session", object) is session
        assert attached_bridge.state.process_attached is True
    finally:
        _forget_remote(_OTHER_HOST)
        _forget_remote(_CURRENT_HOST)
        put(attached_bridge, "_device", value=frida.get_local_device())


def test_remove_remote_device_whose_session_will_not_detach_still_forgets_device_and_session(
    frida_notepad: Popen[bytes],
    notepad_bridge: FridaBridge,
) -> None:
    """A session that cannot be detached because its target is frozen is logged, and the removal still drops the device and the session.

    Args:
        frida_notepad: The private notepad the bridge is attached to; it is frozen during the removal and resumed afterwards.
        notepad_bridge: Bridge attached to ``frida_notepad``.
    """
    try:
        remote = frida.get_device_manager().add_remote_device(_FROZEN_HOST)
        put(notepad_bridge, "_device", value=remote)
        handle = suspend_process(frida_notepad.pid)
        try:
            with capture_logs() as logs:
                run_bounded(notepad_bridge.remove_remote_device(_FROZEN_HOST), timeout=_FROZEN_CALL_S)
        finally:
            resume_process(handle)

        events = [str(entry["event"]) for entry in logs]
        assert "session_release_before_device_removal_failed" in events
        assert "remote_device_removed" in events
        assert events.index("session_release_before_device_removal_failed") < events.index("remote_device_removed")
        assert f"socket@{_FROZEN_HOST}" not in _device_ids()
        assert priv(notepad_bridge, "_device", object) is None
        assert priv(notepad_bridge, "_session", object) is None
        assert notepad_bridge.state.process_attached is False
    finally:
        _forget_remote(_FROZEN_HOST)


def test_connect_device_whose_current_session_will_not_detach_still_switches_the_device(
    frida_notepad: Popen[bytes],
    notepad_bridge: FridaBridge,
) -> None:
    """A session that cannot be detached because its target is frozen is logged, and the switch to the local device still happens.

    Args:
        frida_notepad: The private notepad the bridge is attached to; it is frozen during the switch and resumed afterwards.
        notepad_bridge: Bridge attached to ``frida_notepad``.
    """
    handle = suspend_process(frida_notepad.pid)
    try:
        with capture_logs() as logs:
            info = run_bounded(notepad_bridge.connect_device("local"), timeout=_FROZEN_CALL_S)
    finally:
        resume_process(handle)

    events = [str(entry["event"]) for entry in logs]
    assert "session_release_before_device_switch_failed" in events
    assert "device_connected" in events
    assert events.index("session_release_before_device_switch_failed") < events.index("device_connected")
    assert isinstance(info, FridaDeviceInfo)
    assert (info.id, info.device_type) == ("local", "local")
    assert priv(notepad_bridge, "_session", object) is None
    assert notepad_bridge.state.process_attached is False


def test_attach_by_name_with_a_canceled_token_raises_a_tool_error_and_attaches_nothing(
    idle_bridge: FridaBridge,
    named_target: tuple[Popen[bytes], str],
) -> None:
    """Canceling the attach token before the attach ends the call with a tool error and leaves the bridge detached (suspected defect, red until fixed).

    Args:
        idle_bridge: Initialized bridge without a session.
        named_target: A running child and the unique image name Frida lists it under.
    """
    _, name = named_target
    token_id = run_bounded(idle_bridge.create_cancellable())
    tokens = cast("dict[str, frida.Cancellable]", priv(idle_bridge, "_cancellables", object))
    tokens[token_id].cancel()

    with pytest.raises(ToolError):
        run_bounded(idle_bridge.attach_by_name(name, cancellable_id=token_id))

    assert priv(idle_bridge, "_session", object) is None
    assert idle_bridge.state.process_attached is False
