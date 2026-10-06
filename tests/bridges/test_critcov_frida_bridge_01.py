# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Critical-coverage tests for the Frida bridge session, memory, scan and script paths.

Every test drives the real Frida runtime against a child process that the test
itself starts (a Python interpreter blocked on stdin, or a process the bridge
spawns), never against the pytest process. The tests cover the error paths and
teardown paths of ``FridaBridge``: attach/detach/kill failures, shutdown of every
kind of registered resource, memory access that faults inside the target, scan
chunk failures, script compilation and snapshot failures, and the message
callbacks that Frida invokes from its own thread.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import os
import queue
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import frida
import psutil
import pytest
from frida import ScriptMessage

from intellicrack.bridges.base import MemorySearchResult
from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.core.subprocess_compat import DEVNULL, PIPE, Popen
from intellicrack.core.types import ModuleInfo, ToolError


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator


pytestmark = pytest.mark.spawns_process

_WAIT_S: Final[float] = 20.0
_ABSENT_PID: Final[int] = 0x7FFFFFFE
_NOT_ATTACHED: Final[str] = "not attached to a process"
_TARGET_READY: Final[bytes] = b"critcov-ready"
_TARGET_SOURCE: Final[str] = "import sys\nsys.stdout.write('critcov-ready\\n')\nsys.stdout.flush()\nsys.stdin.read()\n"
_SLEEPER_SOURCE: Final[str] = "import time\ntime.sleep(120)\n"
_CMD_EXE: Final[Path] = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "cmd.exe"
_TYPED_VALUE_TYPES: Final[tuple[str, ...]] = (
    "cstring",
    "double",
    "float",
    "pointer",
    "s16",
    "s32",
    "s64",
    "s8",
    "u16",
    "u32",
    "u64",
    "u8",
    "utf8",
)
_UNATTACHED_CALLS: Final[tuple[tuple[str, tuple[object, ...]], ...]] = (
    ("read_memory", (0, 1)),
    ("write_memory", (0, b"a")),
    ("copy_memory", (0, 0, 1)),
    ("read_typed_value", (0, "u8")),
    ("write_typed_value", (0, "u8", 1)),
    ("get_memory_regions", ()),
    ("enumerate_module_ranges", ("kernel32.dll",)),
    ("scan_memory", (b"a",)),
    ("enumerate_modules", ()),
    ("enumerate_exports", ("kernel32.dll",)),
    ("hook_function", ("0x1",)),
    ("execute_persistent_script", ("var x = 1;",)),
    ("compile_script", ("var x = 1;",)),
    ("load_compiled_script", ("00",)),
    ("snapshot_script", ("var x = 1;",)),
    ("load_script_with_snapshot", ("var x = 1;", "00")),
    ("call_function", (0,)),
    ("_execute_script_and_wait", ("var x = 1;",)),
    ("enumerate_imports", ("kernel32.dll",)),
    ("enumerate_module_sections", ("kernel32.dll",)),
    ("enumerate_module_dependencies", ("kernel32.dll",)),
    ("enumerate_threads", ()),
)


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


def sync_method(obj: object, name: str) -> Callable[..., object]:
    """Look up a (possibly private) synchronous method by name.

    Args:
        obj: Object or class that owns the method.
        name: Method name.

    Returns:
        Callable[..., object]: The bound method or plain function.
    """
    return cast("Callable[..., object]", getattr(obj, name))


def async_method(obj: object, name: str) -> Callable[..., Coroutine[object, object, object]]:
    """Look up a (possibly private) coroutine method by name.

    Args:
        obj: Object or class that owns the method.
        name: Method name.

    Returns:
        Callable[..., Coroutine[object, object, object]]: The bound coroutine method or plain coroutine function.
    """
    return cast("Callable[..., Coroutine[object, object, object]]", getattr(obj, name))


def _ignore_signal(event: object) -> None:
    """Accept a Frida device signal and do nothing with it.

    Args:
        event: The signal payload delivered by Frida.
    """
    del event


def _send(payload: object) -> ScriptMessage:
    """Build a Frida ``send`` message carrying ``payload``.

    Args:
        payload: Value delivered as the message payload.

    Returns:
        ScriptMessage: A ``send`` script message.
    """
    return {"type": "send", "payload": payload}


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


def _wait_for_exit(pid: int) -> None:
    """Wait until the process ``pid`` no longer runs.

    Args:
        pid: Identifier of the process expected to terminate.
    """
    with contextlib.suppress(psutil.NoSuchProcess):
        psutil.Process(pid).wait(timeout=_WAIT_S)


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


def _drain(messages: queue.Queue[dict[str, object]]) -> list[dict[str, object]]:
    """Remove and return every message currently queued.

    Args:
        messages: Queue fed by the bridge message handler.

    Returns:
        list[dict[str, object]]: The queued messages in arrival order.
    """
    drained: list[dict[str, object]] = []
    while True:
        try:
            drained.append(messages.get_nowait())
        except queue.Empty:
            return drained


def _loaded_script(bridge: FridaBridge) -> tuple[str, frida.Script]:
    """Load an inert persistent script and return its identifier and handle.

    Args:
        bridge: Attached bridge that will own the script.

    Returns:
        tuple[str, frida.Script]: The script identifier and the live Frida script.
    """
    script_id = _run(bridge.execute_persistent_script("var critcovIdle = 1;"))
    scripts = cast("dict[str, frida.Script]", priv(bridge, "_scripts", object))
    return script_id, scripts[script_id]


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
def idle_bridge() -> Generator[FridaBridge]:
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
def attached_bridge(target_process: Popen[bytes], idle_bridge: FridaBridge) -> FridaBridge:
    """Attach the idle bridge to the child process.

    Args:
        target_process: The running child process.
        idle_bridge: Initialized bridge without a session.

    Returns:
        FridaBridge: The bridge attached to ``target_process``.
    """
    _run(idle_bridge.attach(target_process.pid))
    return idle_bridge


@pytest.mark.parametrize(("method", "args"), _UNATTACHED_CALLS, ids=[name for name, _ in _UNATTACHED_CALLS])
def test_operation_without_session_raises_not_attached(method: str, args: tuple[object, ...]) -> None:
    """Every session-bound operation refuses to run before the bridge has attached to a process.

    Args:
        method: Name of the bridge method under test.
        args: Positional arguments for the call.
    """
    bridge = FridaBridge()
    with pytest.raises(ToolError) as excinfo:
        _run(async_method(bridge, method)(*args))
    assert excinfo.value.message == _NOT_ATTACHED


def test_kill_without_device_raises_no_device() -> None:
    """Killing a process through a bridge that never initialized reports the missing device."""
    with pytest.raises(ToolError) as excinfo:
        _run(FridaBridge().kill(1))
    assert excinfo.value.message == "no Frida device available"


def test_attach_absent_pid_reports_process_not_found(idle_bridge: FridaBridge) -> None:
    """Attaching to a pid that does not exist raises a process-not-found error and records it in the state.

    Args:
        idle_bridge: Initialized bridge without a session.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(idle_bridge.attach(_ABSENT_PID))
    assert excinfo.value.message == "process not found"
    assert excinfo.value.details["pid"] == _ABSENT_PID
    assert excinfo.value.details["frida_error_type"] == "ProcessNotFoundError"
    assert idle_bridge.state.last_error == excinfo.value.details["frida_error"]
    assert idle_bridge.state.process_attached is False


def test_spawn_rejects_unknown_stdio_mode(idle_bridge: FridaBridge) -> None:
    """Spawning with a stdio mode other than inherit or pipe is refused before anything starts.

    Args:
        idle_bridge: Initialized bridge without a session.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(idle_bridge.spawn(Path(sys.executable), stdio="bogus"))
    assert excinfo.value.message == "failed to attach to process"
    assert excinfo.value.details == {"reason": "invalid stdio mode: bogus"}
    assert priv(idle_bridge, "_spawned_pid", object) is None


def test_spawn_with_pipe_stdio_captures_output_and_reuses_the_handler(idle_bridge: FridaBridge) -> None:
    """A pipe-stdio spawn delivers the child's stdout as process_output messages through one shared handler.

    Args:
        idle_bridge: Initialized bridge without a session.
    """
    messages: queue.Queue[dict[str, object]] = queue.Queue()
    idle_bridge.set_message_handler(messages.put)
    marker = "CRITCOV_PIPE_MARKER"

    pid = _run(idle_bridge.spawn(_CMD_EXE, ["/c", f"echo {marker}"], stdio="pipe"))
    first_handler = priv(idle_bridge, "_output_handler", object)
    assert first_handler is not None
    device = priv(idle_bridge, "_device", frida.Device)
    sync_method(idle_bridge, "_ensure_output_handler_registered")(device)
    assert priv(idle_bridge, "_output_handler", object) is first_handler

    _run(idle_bridge.resume())
    captured = ""
    while marker not in captured:
        payload = _await_payload(messages, "process_output")
        if payload["pid"] == pid and payload["fd"] == 1:
            captured += str(payload["data"])
    assert captured.strip() == marker


def test_output_handler_forwards_chunk_as_process_output_message(idle_bridge: FridaBridge) -> None:
    """The registered output handler turns a stdio chunk into a decoded process_output message.

    Args:
        idle_bridge: Initialized bridge without a session.
    """
    messages: queue.Queue[dict[str, object]] = queue.Queue()
    idle_bridge.set_message_handler(messages.put)
    sync_method(idle_bridge, "_ensure_output_handler_registered")(priv(idle_bridge, "_device", frida.Device))
    handler = cast("Callable[[int, int, bytes], None]", priv(idle_bridge, "_output_handler", object))

    handler(4321, 2, b"warn\xff")

    assert _drain(messages) == [
        {"type": "send", "payload": {"type": "process_output", "pid": 4321, "fd": 2, "data": "warn\ufffd"}},
    ]


def test_detach_output_handler_survives_handler_already_removed(idle_bridge: FridaBridge) -> None:
    """Detaching the output handler clears the record even when Frida no longer knows the handler.

    Args:
        idle_bridge: Initialized bridge without a session.
    """
    device = priv(idle_bridge, "_device", frida.Device)
    sync_method(idle_bridge, "_ensure_output_handler_registered")(device)
    handler = cast("Callable[[int, int, bytes], None]", priv(idle_bridge, "_output_handler", object))
    device.off("output", handler)

    sync_method(idle_bridge, "_detach_output_handler")()

    assert priv(idle_bridge, "_output_handler", object) is None


_GATING_FAMILIES: Final[tuple[tuple[str, str, str, str, str, str], ...]] = (
    (
        "spawn",
        "_register_spawn_gating_handlers",
        "_detach_spawn_gating_handlers",
        "_spawn_added_handler",
        "_spawn_removed_handler",
        "spawn",
    ),
    (
        "child",
        "_register_session_child_gating_handlers",
        "_detach_session_child_gating_handlers",
        "_child_added_handler",
        "_child_removed_handler",
        "child",
    ),
)


@pytest.mark.parametrize(
    ("register", "detach", "added_attr", "removed_attr", "signal_stem"),
    [family[1:] for family in _GATING_FAMILIES],
    ids=[family[0] for family in _GATING_FAMILIES],
)
def test_detach_gating_handlers_ignores_handlers_already_removed(
    idle_bridge: FridaBridge,
    register: str,
    detach: str,
    added_attr: str,
    removed_attr: str,
    signal_stem: str,
) -> None:
    """Detaching gating handlers forgets both records even when Frida has already dropped them.

    Args:
        idle_bridge: Initialized bridge without a session.
        register: Name of the bridge method that registers the handler pair.
        detach: Name of the bridge method that detaches the handler pair.
        added_attr: Attribute that records the added-signal handler.
        removed_attr: Attribute that records the removed-signal handler.
        signal_stem: Frida signal family, ``spawn`` or ``child``.
    """
    device = priv(idle_bridge, "_device", frida.Device)
    sync_method(idle_bridge, register)(device, _ignore_signal, _ignore_signal)
    assert priv(idle_bridge, added_attr, object) is _ignore_signal
    assert priv(idle_bridge, removed_attr, object) is _ignore_signal
    sync_method(device, "off")(f"{signal_stem}-added", _ignore_signal)
    sync_method(device, "off")(f"{signal_stem}-removed", _ignore_signal)

    sync_method(idle_bridge, detach)()

    assert priv(idle_bridge, added_attr, object) is None
    assert priv(idle_bridge, removed_attr, object) is None


@pytest.mark.parametrize(
    ("detach", "added_attr", "removed_attr"),
    [family[2:5] for family in _GATING_FAMILIES],
    ids=[family[0] for family in _GATING_FAMILIES],
)
def test_detach_gating_handlers_with_nothing_registered_is_a_no_op(
    idle_bridge: FridaBridge,
    detach: str,
    added_attr: str,
    removed_attr: str,
) -> None:
    """Detaching gating handlers that were never registered leaves both records empty.

    Args:
        idle_bridge: Initialized bridge without a session.
        detach: Name of the bridge method that detaches the handler pair.
        added_attr: Attribute that records the added-signal handler.
        removed_attr: Attribute that records the removed-signal handler.
    """
    sync_method(idle_bridge, detach)()

    assert priv(idle_bridge, added_attr, object) is None
    assert priv(idle_bridge, removed_attr, object) is None


def test_detach_spawn_gating_handlers_after_shutdown_clears_records(idle_bridge: FridaBridge) -> None:
    """Detaching spawn-gating handlers after the device was released still forgets the recorded handlers.

    Args:
        idle_bridge: Initialized bridge without a session.
    """
    sync_method(idle_bridge, "_register_spawn_gating_handlers")(
        priv(idle_bridge, "_device", frida.Device),
        _ignore_signal,
        _ignore_signal,
    )
    _run(idle_bridge.shutdown())
    assert priv(idle_bridge, "_device", object) is None
    assert priv(idle_bridge, "_spawn_added_handler", object) is _ignore_signal

    sync_method(idle_bridge, "_detach_spawn_gating_handlers")()

    assert priv(idle_bridge, "_spawn_added_handler", object) is None
    assert priv(idle_bridge, "_spawn_removed_handler", object) is None


def test_target_exit_resets_state_and_publishes_session_detached(target_process: Popen[bytes], attached_bridge: FridaBridge) -> None:
    """When the target dies Frida's detached signal resets the bridge and publishes a session_detached message.

    Args:
        target_process: The attached child process.
        attached_bridge: Bridge attached to the child.
    """
    pid = target_process.pid
    messages: queue.Queue[dict[str, object]] = queue.Queue()
    attached_bridge.set_message_handler(messages.put)

    target_process.terminate()
    target_process.wait(timeout=_WAIT_S)

    payload = _await_payload(messages, "session_detached")
    assert payload["pid"] == pid
    assert payload["reason"] == "process-terminated"
    assert attached_bridge.state.process_attached is False
    assert attached_bridge.state.target_pid is None
    assert attached_bridge.state.last_error == "session detached: process-terminated"
    assert priv(attached_bridge, "_session", object) is None
    assert priv(attached_bridge, "_pid", object) is None


def test_requested_detach_does_not_publish_session_detached(target_process: Popen[bytes], attached_bridge: FridaBridge) -> None:
    """A detach requested by the application neither sets an error nor publishes a session_detached message.

    Args:
        target_process: The attached child process.
        attached_bridge: Bridge attached to the child.
    """
    messages: queue.Queue[dict[str, object]] = queue.Queue()
    attached_bridge.set_message_handler(messages.put)

    _run(attached_bridge.detach())
    _run(attached_bridge.attach(target_process.pid))
    assert _run(attached_bridge.enumerate_modules())

    published = [
        message["payload"]
        for message in _drain(messages)
        if isinstance(message.get("payload"), dict) and cast("dict[str, object]", message["payload"]).get("type") == "session_detached"
    ]
    assert published == []
    assert attached_bridge.state.last_error is None


def test_detach_unloads_scripts_and_kills_the_spawned_process(idle_bridge: FridaBridge) -> None:
    """Detaching from a spawned process unloads its scripts, kills the process and clears the spawn record.

    Args:
        idle_bridge: Initialized bridge without a session.
    """
    pid = _run(idle_bridge.spawn(Path(sys.executable), ["-c", _SLEEPER_SOURCE]))
    assert priv(idle_bridge, "_spawned_pid", object) == pid
    _script_id, script = _loaded_script(idle_bridge)

    _run(idle_bridge.detach())

    assert script.is_destroyed
    assert cast("dict[str, frida.Script]", priv(idle_bridge, "_scripts", object)) == {}
    assert priv(idle_bridge, "_spawned_pid", object) is None
    assert priv(idle_bridge, "_session", object) is None
    assert idle_bridge.state.process_attached is False
    assert idle_bridge.state.target_pid is None
    _wait_for_exit(pid)


def test_perform_detach_without_session_returns_immediately(idle_bridge: FridaBridge) -> None:
    """The detach worker does nothing and leaves the state untouched when no session exists.

    Args:
        idle_bridge: Initialized bridge without a session.
    """
    assert _run(async_method(idle_bridge, "_perform_detach")(kill_spawned=True)) is None
    assert idle_bridge.state.connected is True
    assert idle_bridge.state.process_attached is False


def test_shutdown_releases_every_registered_resource(attached_bridge: FridaBridge, tmp_path: Path) -> None:
    """Shutdown unloads stalker, probe, exception-handler, allocation and plain scripts and disables file monitors.

    Args:
        attached_bridge: Bridge attached to the child.
        tmp_path: Directory watched by the file monitor.
    """
    tick = _run(attached_bridge.find_export_by_name("GetTickCount", "kernel32.dll"))
    assert tick is not None
    _run(attached_bridge.stalker_follow(events="call", limit=100))
    _run(attached_bridge.stalker_add_call_probe(tick, "send({ type: 'critcov_probe' });"))
    _run(attached_bridge.set_exception_handler())
    _run(attached_bridge.monitor_path(str(tmp_path)))
    _run(attached_bridge.allocate_memory(64))
    _run(attached_bridge.execute_persistent_script("var critcovPlain = 1;"))
    scripts = dict(cast("dict[str, frida.Script]", priv(attached_bridge, "_scripts", object)))
    assert len(scripts) == 5
    assert not any(script.is_destroyed for script in scripts.values())

    _run(attached_bridge.shutdown())

    assert all(script.is_destroyed for script in scripts.values())
    assert cast("dict[str, frida.Script]", priv(attached_bridge, "_scripts", object)) == {}
    assert cast("dict[int, str]", priv(attached_bridge, "_stalker_scripts", object)) == {}
    assert cast("dict[str, str]", priv(attached_bridge, "_call_probes", object)) == {}
    assert cast("dict[int, str]", priv(attached_bridge, "_alloc_scripts", object)) == {}
    assert cast("dict[str, object]", priv(attached_bridge, "_file_monitors", object)) == {}
    assert priv(attached_bridge, "_exception_handler_script", object) is None
    assert priv(attached_bridge, "_session", object) is None
    assert priv(attached_bridge, "_device", object) is None


def test_shutdown_disables_session_child_gating(attached_bridge: FridaBridge) -> None:
    """Shutdown turns session child gating off and forgets its handlers.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    _run(attached_bridge.enable_session_child_gating())
    assert priv(attached_bridge, "_session_child_gating_enabled", bool) is True
    assert priv(attached_bridge, "_child_added_handler", object) is not None

    _run(attached_bridge.shutdown())

    assert priv(attached_bridge, "_session_child_gating_enabled", bool) is False
    assert priv(attached_bridge, "_child_added_handler", object) is None
    assert priv(attached_bridge, "_child_removed_handler", object) is None


def test_shutdown_tolerates_file_monitor_already_disabled(idle_bridge: FridaBridge, tmp_path: Path) -> None:
    """Shutdown clears the monitor registry even when a monitor was already disabled directly.

    Args:
        idle_bridge: Initialized bridge without a session.
        tmp_path: Directory watched by the file monitor.
    """
    monitor_id = _run(idle_bridge.monitor_path(str(tmp_path)))
    monitors = cast("dict[str, frida.FileMonitor]", priv(idle_bridge, "_file_monitors", object))
    monitors[monitor_id].disable()

    _run(idle_bridge.shutdown())

    assert cast("dict[str, frida.FileMonitor]", priv(idle_bridge, "_file_monitors", object)) == {}


def test_shutdown_tolerates_spawned_process_that_already_died(idle_bridge: FridaBridge) -> None:
    """Shutdown forgets a spawned pid whose process was already killed and unregisters it.

    Args:
        idle_bridge: Initialized bridge without a session.
    """
    messages: queue.Queue[dict[str, object]] = queue.Queue()
    idle_bridge.set_message_handler(messages.put)
    pid = _run(idle_bridge.spawn(Path(sys.executable), ["-c", _SLEEPER_SOURCE]))
    assert _run(idle_bridge.kill(pid)) is True
    assert _await_payload(messages, "session_detached")["pid"] == pid

    _run(idle_bridge.shutdown())

    assert priv(idle_bridge, "_spawned_pid", object) is None
    _wait_for_exit(pid)


def test_read_memory_rejects_negative_size(attached_bridge: FridaBridge) -> None:
    """A negative read size is refused with a reason before any script runs.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    base = _run(attached_bridge.find_base_address("kernel32.dll"))
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.read_memory(base, -1))
    assert excinfo.value.message == "memory read failed"
    assert excinfo.value.details == {"reason": "size must be non-negative"}


def test_copy_memory_rejects_negative_size(attached_bridge: FridaBridge) -> None:
    """A negative copy size is refused with a reason before any script runs.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    base = _run(attached_bridge.find_base_address("kernel32.dll"))
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.copy_memory(base, base, -1))
    assert excinfo.value.message == "memory write failed"
    assert excinfo.value.details == {"reason": "size must be non-negative"}


def test_read_memory_of_zero_bytes_returns_empty_bytes(attached_bridge: FridaBridge) -> None:
    """Reading zero bytes is a valid, non-negative request and yields an empty byte string.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    base = _run(attached_bridge.find_base_address("kernel32.dll"))
    assert _run(attached_bridge.read_memory(base, 0)) == b""


@pytest.mark.parametrize(
    ("method", "args", "message"),
    [
        ("read_memory", (0, 4), "memory read failed"),
        ("write_memory", (0, b"\x01"), "memory write failed"),
        ("copy_memory", (0, 0, 4), "memory write failed"),
        ("read_typed_value", (0, "u8"), "memory read failed"),
        ("write_typed_value", (0, "u8", 1), "memory write failed"),
    ],
    ids=["read", "write", "copy", "typed_read", "typed_write"],
)
def test_access_to_unmapped_address_raises_and_target_survives(
    attached_bridge: FridaBridge,
    method: str,
    args: tuple[object, ...],
    message: str,
) -> None:
    """Memory access that faults inside the target is reported as a tool error and the session stays usable.

    Args:
        attached_bridge: Bridge attached to the child.
        method: Name of the bridge method under test.
        args: Positional arguments targeting the null page.
        message: Expected error message.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(async_method(attached_bridge, method)(*args))
    assert excinfo.value.message == message
    assert _run(attached_bridge.enumerate_modules())


def test_read_typed_value_rejects_unsupported_type(attached_bridge: FridaBridge) -> None:
    """Reading with a value type outside the supported set lists the allowed types.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    base = _run(attached_bridge.find_base_address("kernel32.dll"))
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.read_typed_value(base, "u128"))
    assert excinfo.value.message == "memory read failed"
    assert excinfo.value.details["reason"] == "unsupported value_type: u128"
    assert excinfo.value.details["allowed"] == list(_TYPED_VALUE_TYPES)


def test_write_typed_value_rejects_unsupported_type(attached_bridge: FridaBridge) -> None:
    """Writing with a value type outside the supported set lists the allowed types.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    base = _run(attached_bridge.find_base_address("kernel32.dll"))
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.write_typed_value(base, "u128", 1))
    assert excinfo.value.message == "memory write failed"
    assert excinfo.value.details["reason"] == "unsupported value_type: u128"
    assert excinfo.value.details["allowed"] == list(_TYPED_VALUE_TYPES)


@pytest.mark.parametrize(
    ("value_type", "value", "expected"),
    [
        ("pointer", "0x20", "writePointer(ptr('0x20'))"),
        ("pointer", "32", "writePointer(ptr('0x20'))"),
        ("pointer", 255, "writePointer(ptr('0xff'))"),
    ],
    ids=["hex_string", "decimal_string", "int"],
)
def test_build_typed_write_call_normalizes_pointer_values(value_type: str, value: float | str, expected: str) -> None:
    """Pointer values given as hex strings, decimal strings or integers all become one hex pointer literal.

    Args:
        value_type: Typed-value name.
        value: Value to encode.
        expected: Expected JavaScript call fragment.
    """
    assert sync_method(FridaBridge(), "_build_typed_write_call")(value_type, value) == expected


@pytest.mark.parametrize(
    ("value_type", "value", "reason"),
    [
        ("pointer", 1.5, "pointer value must be an int or hex string"),
        ("utf8", 5, "utf8 value must be a string"),
        ("u64", "7", "u64 value must be an int"),
        ("s64", 1.5, "s64 value must be an int"),
        ("float", "x", "float value must be a number"),
        ("double", "x", "double value must be a number"),
    ],
    ids=["pointer", "utf8", "u64", "s64", "float", "double"],
)
def test_build_typed_write_call_rejects_wrongly_shaped_values(value_type: str, value: float | str, reason: str) -> None:
    """A value whose Python type does not fit the requested typed write is refused with a reason.

    Args:
        value_type: Typed-value name.
        value: Value of the wrong shape.
        reason: Expected failure reason.
    """
    with pytest.raises(ToolError) as excinfo:
        sync_method(FridaBridge(), "_build_typed_write_call")(value_type, value)
    assert excinfo.value.message == "memory write failed"
    assert excinfo.value.details == {"reason": reason}


def test_write_typed_pointer_from_strings_round_trips_through_memory(attached_bridge: FridaBridge) -> None:
    """Hex-string and decimal-string pointer writes land as little-endian 64-bit values.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    address = _run(attached_bridge.allocate_memory(16))

    assert _run(attached_bridge.write_typed_value(address, "pointer", "0x1122334455667788")) is True
    assert _run(attached_bridge.read_memory(address, 8)) == (0x1122334455667788).to_bytes(8, "little")
    assert _run(attached_bridge.read_typed_value(address, "pointer")) == 0x1122334455667788

    assert _run(attached_bridge.write_typed_value(address, "pointer", "4096")) is True
    assert _run(attached_bridge.read_memory(address, 8)) == (4096).to_bytes(8, "little")


def test_scan_memory_limited_to_a_module_finds_its_header_with_file_context(attached_bridge: FridaBridge) -> None:
    """A module-scoped scan finds the DOS header only inside that module and returns the following bytes as context.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    modules: list[ModuleInfo] = _run(attached_bridge.enumerate_modules())
    kernel32 = next(module for module in modules if module.name.lower() == "kernel32.dll")
    on_disk_header = kernel32.path.read_bytes()[:20]

    matches: list[MemorySearchResult] = _run(attached_bridge.scan_memory("4D 5A ?? ??", module_name="kernel32.dll"))

    assert all(kernel32.base_address <= match.address < kernel32.base_address + kernel32.size for match in matches)
    at_base = [match for match in matches if match.address == kernel32.base_address]
    assert len(at_base) == 1
    assert at_base[0].matched_bytes == "4d 5a ?? ??"
    assert base64.b64decode(at_base[0].context_after) == on_disk_header[4:20]
    assert len(base64.b64decode(at_base[0].context_before)) in {0, 16}


def test_scan_memory_limited_to_an_unknown_module_finds_nothing(attached_bridge: FridaBridge) -> None:
    """A scan scoped to a module that is not loaded has no ranges to scan and returns no matches.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    assert _run(attached_bridge.scan_memory(b"MZ", module_name="critcov_not_loaded.dll")) == []


def test_scan_ranges_chunked_requires_a_loaded_scan_agent(attached_bridge: FridaBridge) -> None:
    """Chunked scanning fails with script-not-found when the agent script id is unknown.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(async_method(attached_bridge, "_scan_ranges_chunked")("ghost", [(0x1000, 16)], "00"))
    assert excinfo.value.message == "script not found"


def test_scan_one_chunk_gives_up_on_an_agent_that_never_answers(attached_bridge: FridaBridge) -> None:
    """A chunk whose agent never resolves is abandoned after the chunk timeout and yields no matches.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    scan_one = async_method(FridaBridge, "_scan_one_chunk")

    async def scenario() -> object:
        """Run one chunk scan against an agent whose RPC never resolves.

        Returns:
            object: The chunk scan result.
        """
        script_id = await attached_bridge.execute_persistent_script(
            "rpc.exports = { scanChunk: function () { return new Promise(function () {}); } };",
        )
        scripts = cast("dict[str, frida.Script]", priv(attached_bridge, "_scripts", object))
        try:
            return await scan_one(scripts[script_id], 0x1000, 16, "00")
        finally:
            await attached_bridge.unload_script(script_id)

    assert _run(scenario()) == []


def test_scan_one_chunk_returns_matches_then_nothing_once_the_script_is_gone(attached_bridge: FridaBridge) -> None:
    """A chunk scan returns the agent's matches while it lives and an empty list after the script was destroyed.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    scan_one = async_method(FridaBridge, "_scan_one_chunk")
    script_id = _run(
        attached_bridge.execute_persistent_script("rpc.exports = { scanChunk: function () { return [{ address: '0x10', size: 2 }]; } };"),
    )
    script = cast("dict[str, frida.Script]", priv(attached_bridge, "_scripts", object))[script_id]

    assert _run(scan_one(script, 0x1000, 16, "00")) == [{"address": "0x10", "size": 2}]

    script.unload()

    assert _run(scan_one(script, 0x1000, 16, "00")) == []


def test_scan_one_chunk_ignores_a_non_list_agent_result(attached_bridge: FridaBridge) -> None:
    """A scan agent that answers with something other than a list contributes no matches.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    script_id = _run(attached_bridge.execute_persistent_script("rpc.exports = { scanChunk: function () { return 5; } };"))
    script = cast("dict[str, frida.Script]", priv(attached_bridge, "_scripts", object))[script_id]

    assert _run(async_method(FridaBridge, "_scan_one_chunk")(script, 0x1000, 16, "00")) == []


def test_build_scan_results_ignores_non_list_and_non_dict_data(idle_bridge: FridaBridge) -> None:
    """Scan data that is not a list of match dictionaries produces no results.

    Args:
        idle_bridge: Initialized bridge without a session.
    """
    build = async_method(idle_bridge, "_build_scan_results")

    assert _run(build(scan_data=None, hex_pattern="aa", pattern_len=1)) == []
    assert _run(build(scan_data=[1, "x", None], hex_pattern="aa", pattern_len=1)) == []


def test_build_scan_results_uses_empty_context_when_pages_are_unreadable(attached_bridge: FridaBridge) -> None:
    """A match at the start of the null page has no readable bytes around it, so both contexts are empty strings.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    results = _run(
        async_method(attached_bridge, "_build_scan_results")(
            scan_data=[{"address": "0x0", "size": 2}],
            hex_pattern="aa bb",
            pattern_len=2,
        ),
    )

    assert results == [MemorySearchResult(address=0, matched_bytes="aa bb", context_before="", context_after="")]


def test_hook_function_with_malformed_target_raises_hook_failed(attached_bridge: FridaBridge) -> None:
    """A target that makes the hook script fail to compile is reported as a hook failure and registers nothing.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.hook_function("0xZZ"))
    assert excinfo.value.message == "hook installation failed"
    assert _run(attached_bridge.get_hooks()) == []


def test_remove_hook_with_unknown_id_returns_false(attached_bridge: FridaBridge) -> None:
    """Removing a hook that was never installed reports False and changes nothing.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    assert _run(attached_bridge.remove_hook("deadbeef")) is False
    assert _run(attached_bridge.get_hooks()) == []


def test_persistent_script_messages_reach_the_message_handler(attached_bridge: FridaBridge) -> None:
    """A persistent script's send() payload is dispatched to the registered message handler.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    messages: queue.Queue[dict[str, object]] = queue.Queue()
    attached_bridge.set_message_handler(messages.put)

    script_id = _run(attached_bridge.execute_persistent_script("send({ type: 'critcov_persistent', value: 7 });"))

    assert _await_payload(messages, "critcov_persistent") == {"type": "critcov_persistent", "value": 7}
    assert _run(attached_bridge.unload_script(script_id)) is True


def test_compiled_script_round_trip_delivers_its_message(attached_bridge: FridaBridge) -> None:
    """A script compiled to bytecode and loaded from that bytecode runs and dispatches its message.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    messages: queue.Queue[dict[str, object]] = queue.Queue()
    attached_bridge.set_message_handler(messages.put)

    bytecode_hex = _run(attached_bridge.compile_script("send({ type: 'critcov_compiled', value: 11 });"))
    assert len(bytes.fromhex(bytecode_hex)) > 0
    script_id = _run(attached_bridge.load_compiled_script(bytecode_hex))

    assert _await_payload(messages, "critcov_compiled") == {"type": "critcov_compiled", "value": 11}
    assert _run(attached_bridge.unload_script(script_id)) is True


def test_compile_script_rejects_invalid_source(attached_bridge: FridaBridge) -> None:
    """Compiling source with a syntax error reports a precompilation failure carrying Frida's own error.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.compile_script("function ("))
    cause = excinfo.value.__cause__
    assert cause is not None
    assert excinfo.value.message == "script precompilation failed"
    assert excinfo.value.details["frida_error"] == str(cause)
    assert excinfo.value.details["frida_error_type"] == type(cause).__name__


def test_load_compiled_script_rejects_non_hex_bytecode(attached_bridge: FridaBridge) -> None:
    """Bytecode that is not valid hex is refused before Frida is involved.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.load_compiled_script("not-hex"))
    assert excinfo.value.message == "script precompilation failed"
    assert excinfo.value.details == {"reason": "invalid hex bytecode"}


def test_load_compiled_script_rejects_corrupt_bytecode(attached_bridge: FridaBridge) -> None:
    """Hex that is not real script bytecode makes Frida refuse the script and the bridge reports it.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.load_compiled_script("000102"))
    assert excinfo.value.message == "script precompilation failed"
    assert excinfo.value.__cause__ is not None
    assert excinfo.value.details["frida_error"] == str(excinfo.value.__cause__)


def test_snapshot_round_trip_preserves_warmed_state_and_dispatches(attached_bridge: FridaBridge) -> None:
    """A script started from a snapshot sees the global the snapshot script defined and dispatches its message.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    messages: queue.Queue[dict[str, object]] = queue.Queue()
    attached_bridge.set_message_handler(messages.put)

    snapshot_hex = _run(attached_bridge.snapshot_script("var critcovWarm = 'critcov-warm';"))
    assert len(bytes.fromhex(snapshot_hex)) > 0
    script_id = _run(
        attached_bridge.load_script_with_snapshot("send({ type: 'critcov_snapshot', seen: critcovWarm });", snapshot_hex),
    )

    assert _await_payload(messages, "critcov_snapshot") == {"type": "critcov_snapshot", "seen": "critcov-warm"}
    assert _run(attached_bridge.unload_script(script_id)) is True


def test_snapshot_script_rejects_invalid_source(attached_bridge: FridaBridge) -> None:
    """Snapshotting source with a syntax error reports a script failure carrying Frida's own error.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.snapshot_script("var ("))
    assert excinfo.value.message == "script execution failed"
    assert excinfo.value.__cause__ is not None
    assert excinfo.value.details["frida_error"] == str(excinfo.value.__cause__)


def test_load_script_with_snapshot_rejects_non_hex_snapshot(attached_bridge: FridaBridge) -> None:
    """A snapshot that is not valid hex is refused before Frida is involved.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.load_script_with_snapshot("var x = 1;", "not-hex"))
    assert excinfo.value.message == "script execution failed"
    assert excinfo.value.details == {"reason": "invalid hex snapshot"}


def test_load_script_with_snapshot_rejects_invalid_source(attached_bridge: FridaBridge) -> None:
    """A valid snapshot combined with source that fails to compile is reported as a script failure.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    snapshot_hex = _run(attached_bridge.snapshot_script("var critcovWarm = 1;"))
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.load_script_with_snapshot("var (", snapshot_hex))
    assert excinfo.value.message == "script execution failed"
    assert excinfo.value.__cause__ is not None
    assert excinfo.value.details["frida_error"] == str(excinfo.value.__cause__)


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"return_type": "bogus"}, "invalid return type: bogus"),
        ({"calling_convention": "cdecl"}, "invalid calling convention: cdecl"),
        ({"args": [1], "arg_types": ["bogus"]}, "invalid arg type: bogus"),
    ],
    ids=["return_type", "calling_convention", "arg_type"],
)
def test_call_function_rejects_invalid_type_names(attached_bridge: FridaBridge, kwargs: dict[str, object], reason: str) -> None:
    """Native type names and calling conventions outside the supported sets are refused with a reason.

    Args:
        attached_bridge: Bridge attached to the child.
        kwargs: Keyword arguments carrying one invalid name.
        reason: Expected failure reason.
    """
    base = _run(attached_bridge.find_base_address("kernel32.dll"))
    with pytest.raises(ToolError) as excinfo:
        _run(async_method(attached_bridge, "call_function")(base, **kwargs))
    assert excinfo.value.message == "function call failed"
    assert excinfo.value.details == {"reason": reason}


def test_call_function_void_with_explicit_convention_returns_zero(attached_bridge: FridaBridge) -> None:
    """Calling a void function with an explicit Windows x64 convention runs it and reports zero.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    sleep_address = _run(attached_bridge.find_export_by_name("Sleep", "kernel32.dll"))
    assert sleep_address is not None

    assert _run(attached_bridge.call_function(sleep_address, [0], return_type="void", calling_convention="win64")) == 0


def test_call_function_double_return_is_truncated_to_an_integer(attached_bridge: FridaBridge) -> None:
    """Calling atof on the text 2.5 returns the double 2.5, which the bridge reports as the integer 2.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    atof_address = _run(attached_bridge.find_export_by_name("atof", "ucrtbase.dll"))
    assert atof_address is not None
    text = _run(attached_bridge.allocate_memory(32))
    assert _run(attached_bridge.write_memory(text, b"2.5\x00")) == 4

    assert _run(attached_bridge.call_function(atof_address, [text], return_type="double")) == 2


def test_execute_script_and_wait_reports_script_errors(attached_bridge: FridaBridge) -> None:
    """A script that throws yields an error entry carrying Frida's description of the failure.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    result = _run(async_method(attached_bridge, "_execute_script_and_wait")("throw new Error('critcov-boom');"))

    assert isinstance(result, dict)
    outcome = cast("dict[str, object]", result)
    assert "critcov-boom" in str(outcome["error"])
    assert outcome["__error_description"] == outcome["error"]


@pytest.mark.parametrize(
    ("script", "expected"),
    [
        ("send('hello');", {"payload": "hello"}),
        ("send(42);", {"payload": 42}),
        ("send([1, 2]);", {"payload": [1, 2]}),
        ("send({ type: 'critcov_object', value: 3 });", {"type": "critcov_object", "value": 3}),
        (
            "send({ type: 'critcov_bin' }, new Uint8Array([1, 2, 3]).buffer);",
            {"type": "critcov_bin", "__binary": [1, 2, 3]},
        ),
    ],
    ids=["string", "number", "array", "object", "binary"],
)
def test_execute_script_and_wait_collects_the_first_send_payload(
    attached_bridge: FridaBridge,
    script: str,
    expected: dict[str, object],
) -> None:
    """The first send() of a script becomes the result, with non-object payloads under one key and binary data as a list.

    Args:
        attached_bridge: Bridge attached to the child.
        script: JavaScript source to execute.
        expected: Expected result mapping.
    """
    assert _run(async_method(attached_bridge, "_execute_script_and_wait")(script)) == expected


def test_console_log_output_reaches_the_message_handler(attached_bridge: FridaBridge) -> None:
    """console.log output of a one-shot script is forwarded to the registered message handler.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    messages: queue.Queue[dict[str, object]] = queue.Queue()
    attached_bridge.set_message_handler(messages.put)

    result = _run(async_method(attached_bridge, "_execute_script_and_wait")("console.log('critcov-log-line'); send({ done: true });"))

    assert result == {"done": True}
    logged = [message for message in _drain(messages) if message.get("type") == "log" and message.get("payload") == "critcov-log-line"]
    assert len(logged) == 1


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (frida.InvalidOperationError("script has been destroyed"), True),
        (frida.TransportError("Session DETACHED"), True),
        (frida.TransportError("connection closed"), False),
        (frida.InvalidOperationError("unable to load"), False),
    ],
    ids=["destroyed", "detached_any_case", "closed", "other"],
)
def test_is_already_unloaded_error_matches_destroy_and_detach_markers(*, error: Exception, expected: bool) -> None:
    """Only Frida errors that mention a destroyed script or detached session count as already unloaded.

    Args:
        error: Frida exception to classify.
        expected: Whether the exception means the script is already gone.
    """
    assert sync_method(FridaBridge, "_is_already_unloaded_error")(error) is expected


def test_set_event_threadsafe_skips_an_event_whose_loop_is_closed() -> None:
    """Signalling an event bound to a closed loop is dropped instead of raising or setting the event."""
    event = asyncio.Event()
    loop = asyncio.new_event_loop()

    async def bind_to_loop() -> None:
        """Bind the event to the loop by waiting on it with a short timeout."""
        await asyncio.wait_for(event.wait(), timeout=0.01)

    try:
        with pytest.raises(TimeoutError):
            loop.run_until_complete(bind_to_loop())
    finally:
        loop.close()

    sync_method(FridaBridge, "_set_event_threadsafe")(event)

    assert not event.is_set()


def test_removing_one_call_probe_keeps_the_other_probes_script(attached_bridge: FridaBridge) -> None:
    """Removing one call probe unloads only its own script and leaves the other probe registered and loaded.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    tick = _run(attached_bridge.find_export_by_name("GetTickCount", "kernel32.dll"))
    assert tick is not None
    first = _run(attached_bridge.stalker_add_call_probe(tick, "send({ type: 'critcov_probe_a' });"))
    second = _run(attached_bridge.stalker_add_call_probe(tick, "send({ type: 'critcov_probe_b' });"))
    probes = dict(cast("dict[str, str]", priv(attached_bridge, "_call_probes", object)))
    scripts = cast("dict[str, frida.Script]", priv(attached_bridge, "_scripts", object))
    first_script = scripts[probes[first]]
    second_script = scripts[probes[second]]

    assert _run(attached_bridge.stalker_remove_call_probe(first)) is True

    assert first_script.is_destroyed
    assert not second_script.is_destroyed
    assert cast("dict[str, str]", priv(attached_bridge, "_call_probes", object)) == {second: probes[second]}
    assert probes[first] not in scripts
    assert probes[second] in scripts
    assert _run(attached_bridge.stalker_remove_call_probe(second)) is True
    assert second_script.is_destroyed


def test_unloading_the_exception_handler_script_clears_its_registration(attached_bridge: FridaBridge) -> None:
    """Unloading the exception-handler script forgets it, so installing a handler again creates a new script.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    first = _run(attached_bridge.set_exception_handler())
    assert priv(attached_bridge, "_exception_handler_script", object) == first

    assert _run(attached_bridge.unload_script(first)) is True
    assert priv(attached_bridge, "_exception_handler_script", object) is None

    second = _run(attached_bridge.set_exception_handler())
    assert second != first
    assert priv(attached_bridge, "_exception_handler_script", object) == second


def test_unload_script_with_unknown_id_changes_nothing(attached_bridge: FridaBridge) -> None:
    """Unloading an identifier that is not registered leaves every loaded script alone.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    script_id, script = _loaded_script(attached_bridge)

    _run(async_method(attached_bridge, "_unload_script")("ghost"))

    assert not script.is_destroyed
    assert script_id in cast("dict[str, frida.Script]", priv(attached_bridge, "_scripts", object))


def test_unload_stalker_script_with_unknown_script_id_is_a_no_op(attached_bridge: FridaBridge) -> None:
    """Tearing down a stalker script that is not registered touches no other script.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    _script_id, script = _loaded_script(attached_bridge)

    _run(async_method(attached_bridge, "_unload_stalker_script")(7, "ghost"))

    assert not script.is_destroyed


def test_unload_stalker_script_survives_a_script_that_is_already_destroyed(attached_bridge: FridaBridge) -> None:
    """Tearing down a stalker script whose Frida script is already destroyed still removes the registration.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    script_id, script = _loaded_script(attached_bridge)
    script.unload()

    _run(async_method(attached_bridge, "_unload_stalker_script")(7, script_id))

    assert script_id not in cast("dict[str, frida.Script]", priv(attached_bridge, "_scripts", object))


def test_resolve_install_address_returns_the_acknowledged_address(attached_bridge: FridaBridge) -> None:
    """Install-message parsing skips unrelated messages and returns the address from the success acknowledgement.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    _script_id, script = _loaded_script(attached_bridge)
    messages: list[ScriptMessage] = [
        cast("ScriptMessage", {"type": "log", "level": "info", "payload": "noise"}),
        _send("plain text"),
        _send({"type": "hooked", "address": 5}),
        _send({"type": "progress"}),
        _send({"type": "hooked", "address": "0x7ff600001000"}),
    ]

    address = _run(
        async_method(FridaBridge, "_resolve_install_address")(
            script=script,
            messages=messages,
            target="critcov",
            success_type="hooked",
            error_type="hook_error",
            error_constant="hook installation failed",
            log_prefix="hook",
        ),
    )

    assert address == 0x7FF600001000
    assert not script.is_destroyed


def test_resolve_install_address_error_payload_unloads_script_and_raises(attached_bridge: FridaBridge) -> None:
    """A script-side install error payload destroys the script and is raised with the script's message.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    _script_id, script = _loaded_script(attached_bridge)

    with pytest.raises(ToolError) as excinfo:
        _run(
            async_method(FridaBridge, "_resolve_install_address")(
                script=script,
                messages=[_send({"type": "hook_error", "error": "boom"})],
                target="critcov",
                success_type="hooked",
                error_type="hook_error",
                error_constant="hook installation failed",
                log_prefix="hook",
            ),
        )

    assert excinfo.value.message == "hook installation failed"
    assert excinfo.value.details == {"error": "boom"}
    assert script.is_destroyed


def test_resolve_install_address_without_acknowledgement_unloads_script_and_raises(attached_bridge: FridaBridge) -> None:
    """Install messages that never acknowledge success destroy the script and raise the failure constant.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    _script_id, script = _loaded_script(attached_bridge)

    with pytest.raises(ToolError) as excinfo:
        _run(
            async_method(FridaBridge, "_resolve_install_address")(
                script=script,
                messages=[_send({"type": "progress"})],
                target="critcov",
                success_type="hooked",
                error_type="hook_error",
                error_constant="hook installation failed",
                log_prefix="hook",
            ),
        )

    assert excinfo.value.message == "hook installation failed"
    assert excinfo.value.details == {}
    assert script.is_destroyed


def test_install_waiter_wakes_only_for_terminal_payloads(idle_bridge: FridaBridge) -> None:
    """The install waiter buffers and forwards every message but wakes only for a terminal payload type.

    Args:
        idle_bridge: Initialized bridge without a session.
    """
    forwarded: list[dict[str, object]] = []
    idle_bridge.set_message_handler(forwarded.append)
    messages, on_message, installed = cast(
        "tuple[list[ScriptMessage], Callable[[ScriptMessage, bytes | None], None], asyncio.Event]",
        sync_method(idle_bridge, "_make_install_waiter")({"hooked"}),
    )

    for noise in (
        _send({"type": "progress"}),
        _send("plain text"),
        cast("ScriptMessage", {"type": "log", "level": "info", "payload": "noise"}),
    ):
        on_message(noise, None)
        assert not installed.is_set()

    on_message(_send({"type": "hooked", "address": "0x1"}), None)

    assert installed.is_set()
    assert len(messages) == 4
    assert len(forwarded) == 4


def test_install_waiter_wakes_for_an_error_message(idle_bridge: FridaBridge) -> None:
    """The install waiter wakes as soon as the script reports an error.

    Args:
        idle_bridge: Initialized bridge without a session.
    """
    messages, on_message, installed = cast(
        "tuple[list[ScriptMessage], Callable[[ScriptMessage, bytes | None], None], asyncio.Event]",
        sync_method(idle_bridge, "_make_install_waiter")({"hooked"}),
    )

    on_message({"type": "error", "description": "boom"}, None)

    assert installed.is_set()
    assert messages == [{"type": "error", "description": "boom"}]
