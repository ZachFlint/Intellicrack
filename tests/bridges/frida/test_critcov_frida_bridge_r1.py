# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Second-pass critical-coverage tests for the Frida bridge.

Every test drives the real Frida runtime against a child process that the test
itself starts (a Python interpreter blocked on stdin), never against the pytest
process. The tests cover what the first pass left: shutdown phases that depend
on bookkeeping, failures of a session whose target is gone, the message and
signal callbacks that the bridge records and that are therefore invoked here on
the test thread, and the removal of a remote device.
"""

from __future__ import annotations

import asyncio
import contextlib
import queue
import sys
import threading
import time
from typing import TYPE_CHECKING, Final, cast

import frida
import pytest

from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.core.subprocess_compat import DEVNULL, PIPE, Popen
from intellicrack.core.types import ChildProcessInfo, ToolError


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator

    from frida import ScriptMessage


pytestmark = pytest.mark.spawns_process

_WAIT_S: Final[float] = 20.0
_ACK_TIMEOUT_MS: Final[float] = 4500.0
_REMOTE_HOST: Final[str] = "127.0.0.1:59999"
_TARGET_READY: Final[bytes] = b"critcov-ready"
_TARGET_SOURCE: Final[str] = "import sys\nsys.stdout.write('critcov-ready\\n')\nsys.stdout.flush()\nsys.stdin.read()\n"
_SCRIPT_KINDS: Final[tuple[str, ...]] = ("persistent", "compiled", "snapshot", "exception", "probe", "socket")
_STALKER_KINDS: Final[tuple[str, ...]] = ("plain", "transform")
_BATCH_FROM: Final[int] = 0x7FFC00001000
_BATCH_TO: Final[int] = 0x7FFC00002000
_NOISE_MESSAGES: Final[tuple[dict[str, object], ...]] = (
    {"type": "send", "payload": "critcov-plain"},
    {"type": "send", "payload": {"type": "stalker_batch", "events": None, "marker": "no-list"}},
    {"type": "send", "payload": {"type": "stalker_done", "count": 1, "marker": "other"}},
    {"type": "send", "payload": {"type": "stalker_started", "tid": 0}},
    {"type": "error", "description": "critcov-boom", "stack": "", "fileName": "", "lineNumber": 1, "columnNumber": 1},
    {"type": "log", "level": "info", "payload": "critcov-log"},
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


def put(obj: object, name: str, *, value: object) -> None:
    """Set a private data attribute on an object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name, including its leading underscore.
        value: Value to store.
    """
    setattr(obj, name, value)


def sync_method(obj: object, name: str) -> Callable[..., object]:
    """Look up a (possibly private) synchronous method by name.

    Args:
        obj: Object or class that owns the method.
        name: Method name.

    Returns:
        Callable[..., object]: The bound method or plain function.
    """
    return cast("Callable[..., object]", getattr(obj, name))


def _ignore_signal(event: object) -> None:
    """Accept a Frida device signal and do nothing with it.

    Args:
        event: The signal payload delivered by Frida.
    """
    del event


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


def _loaded_script(bridge: FridaBridge, source: str = "var critcovIdle = 1;") -> tuple[str, frida.Script]:
    """Load a persistent script and return its identifier and handle.

    Args:
        bridge: Attached bridge that will own the script.
        source: JavaScript source of the script.

    Returns:
        tuple[str, frida.Script]: The script identifier and the live Frida script.
    """
    script_id = _run(bridge.execute_persistent_script(source))
    scripts = cast("dict[str, frida.Script]", priv(bridge, "_scripts", object))
    return script_id, scripts[script_id]


def _message_handlers(script: frida.Script) -> list[Callable[[ScriptMessage, bytes | None], None]]:
    """Return the message callbacks that were registered on a Frida script.

    Args:
        script: Script whose registered ``message`` callbacks are read.

    Returns:
        list[Callable[[ScriptMessage, bytes | None], None]]: The live registration list, in registration order.
    """
    return cast("list[Callable[[ScriptMessage, bytes | None], None]]", priv(script, "_message_handlers", list))


def _wait_for_registrations(handlers: list[Callable[[ScriptMessage, bytes | None], None]], count: int) -> None:
    """Block until a script's callback list holds at least ``count`` entries or the wait limit passes.

    Args:
        handlers: The live callback registration list of a script.
        count: Number of registrations to wait for.
    """
    deadline = time.monotonic() + _WAIT_S
    while len(handlers) < count and time.monotonic() < deadline:
        time.sleep(0.001)


def _stale_session(bridge: FridaBridge, target: Popen[bytes]) -> frida.Session:
    """End the bridge's target, wait for Frida to detach, and hand the dead session back to the bridge.

    Args:
        bridge: Bridge attached to ``target``.
        target: The attached child process, which is terminated.

    Returns:
        frida.Session: The detached session, stored again as the bridge's current session.
    """
    session = priv(bridge, "_session", frida.Session)
    gone = threading.Event()

    def on_gone(reason: str, crash: object) -> None:
        """Record that Frida reported the session as detached.

        Args:
            reason: Frida-reported detach reason.
            crash: Crash details, unused.
        """
        del reason, crash
        gone.set()

    session.on("detached", on_gone)
    target.terminate()
    target.wait(timeout=_WAIT_S)
    assert gone.wait(_WAIT_S)
    deadline = time.monotonic() + _WAIT_S
    while priv(bridge, "_session", object) is not None and time.monotonic() < deadline:
        time.sleep(0.01)
    assert priv(bridge, "_session", object) is None
    assert session.is_detached
    put(bridge, "_session", value=session)
    return session


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


def test_shutdown_tolerates_stalker_registrations_that_share_one_script(attached_bridge: FridaBridge) -> None:
    """Two thread registrations of one script are torn down together without a lookup failure for the second.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    script_id, script = _loaded_script(attached_bridge)
    registry = cast("dict[int, str]", priv(attached_bridge, "_stalker_scripts", object))
    registry[1] = script_id
    registry[2] = script_id

    _run(attached_bridge.shutdown())

    assert script.is_destroyed
    assert registry == {}
    assert cast("dict[str, frida.Script]", priv(attached_bridge, "_scripts", object)) == {}


def test_shutdown_disables_device_wide_spawn_gating_and_forgets_its_handlers(idle_bridge: FridaBridge) -> None:
    """Shutdown of a bridge that enabled spawn gating turns the flag off and drops both signal handlers.

    Args:
        idle_bridge: Initialized bridge without a session.
    """
    sync_method(idle_bridge, "_register_spawn_gating_handlers")(
        priv(idle_bridge, "_device", frida.Device),
        _ignore_signal,
        _ignore_signal,
    )
    put(idle_bridge, "_child_gating_enabled", value=True)

    _run(idle_bridge.shutdown())

    assert priv(idle_bridge, "_child_gating_enabled", bool) is False
    assert priv(idle_bridge, "_spawn_added_handler", object) is None
    assert priv(idle_bridge, "_spawn_removed_handler", object) is None


def test_shutdown_after_the_target_died_resets_session_child_gating(
    target_process: Popen[bytes],
    attached_bridge: FridaBridge,
) -> None:
    """Shutdown of a bridge whose gated session is already detached still resets the gating state and the session.

    Args:
        target_process: The attached child process.
        attached_bridge: Bridge attached to the child.
    """
    _run(attached_bridge.enable_session_child_gating())
    _stale_session(attached_bridge, target_process)
    put(attached_bridge, "_session_child_gating_enabled", value=True)

    _run(attached_bridge.shutdown())

    assert priv(attached_bridge, "_session_child_gating_enabled", bool) is False
    assert priv(attached_bridge, "_child_added_handler", object) is None
    assert priv(attached_bridge, "_session", object) is None


def test_enable_session_child_gating_on_a_detached_session_reports_gating_failure(
    target_process: Popen[bytes],
    attached_bridge: FridaBridge,
) -> None:
    """Enabling session child gating on a detached session fails with Frida's error as the reason and leaves no handlers.

    Args:
        target_process: The attached child process.
        attached_bridge: Bridge attached to the child.
    """
    _stale_session(attached_bridge, target_process)

    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.enable_session_child_gating())

    cause = excinfo.value.__cause__
    assert cause is not None
    assert excinfo.value.message == "child gating operation failed"
    assert excinfo.value.details == {"reason": str(cause) or type(cause).__name__}
    assert priv(attached_bridge, "_session_child_gating_enabled", bool) is False
    assert priv(attached_bridge, "_child_added_handler", object) is None
    assert priv(attached_bridge, "_child_removed_handler", object) is None


def test_disable_session_child_gating_on_a_detached_session_reports_gating_failure(
    target_process: Popen[bytes],
    attached_bridge: FridaBridge,
) -> None:
    """Disabling session child gating on a detached session raises a tool error chained to Frida's error.

    Args:
        target_process: The attached child process.
        attached_bridge: Bridge attached to the child.
    """
    _stale_session(attached_bridge, target_process)
    put(attached_bridge, "_session_child_gating_enabled", value=True)

    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.disable_session_child_gating())

    assert excinfo.value.message == "child gating operation failed"
    assert excinfo.value.__cause__ is not None
    assert priv(attached_bridge, "_session_child_gating_enabled", bool) is True


def test_set_exception_handler_on_a_detached_session_registers_nothing(
    target_process: Popen[bytes],
    attached_bridge: FridaBridge,
) -> None:
    """Installing the exception handler on a detached session is reported as a failure and registers no script.

    Args:
        target_process: The attached child process.
        attached_bridge: Bridge attached to the child.
    """
    _stale_session(attached_bridge, target_process)

    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.set_exception_handler())

    assert excinfo.value.message == "exception handler setup failed"
    assert excinfo.value.__cause__ is not None
    assert priv(attached_bridge, "_exception_handler_script", object) is None
    assert cast("dict[str, object]", priv(attached_bridge, "_scripts", object)) == {}


def test_session_child_handlers_track_each_pending_child_once_and_forget_it_on_removal(attached_bridge: FridaBridge) -> None:
    """The recorded child-added handler tracks a pid once however often it fires and the removed handler forgets it.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    messages: queue.Queue[dict[str, object]] = queue.Queue()
    attached_bridge.set_message_handler(messages.put)
    _run(attached_bridge.enable_session_child_gating())
    added = cast("Callable[[object], None]", priv(attached_bridge, "_child_added_handler", object))
    removed = cast("Callable[[object], None]", priv(attached_bridge, "_child_removed_handler", object))
    child = ChildProcessInfo(
        pid=4242,
        parent_pid=7,
        origin="spawn",
        identifier=None,
        path="C:\\critcov\\child.exe",
        argv=["child.exe", "-x"],
    )

    added(child)
    added(child)

    tracked = cast("list[ChildProcessInfo]", priv(attached_bridge, "_session_gated_children", object))
    assert [(c.pid, c.parent_pid, c.origin, c.identifier, c.path, c.argv) for c in tracked] == [
        (4242, 7, "spawn", None, "C:\\critcov\\child.exe", ["child.exe", "-x"]),
    ]
    first: dict[str, object] = {"type": "send", "payload": {"type": "session_child_added", "pid": 4242}}
    assert _drain(messages).count(first) == 2

    removed(child)

    assert cast("list[ChildProcessInfo]", priv(attached_bridge, "_session_gated_children", object)) == []
    assert _await_payload(messages, "session_child_removed") == {"type": "session_child_removed", "pid": 4242}


def test_device_list_change_handler_publishes_a_device_list_changed_message(idle_bridge: FridaBridge) -> None:
    """The recorded device-manager handler turns a change notification into a device_list_changed message.

    Args:
        idle_bridge: Initialized bridge without a session.
    """
    messages: queue.Queue[dict[str, object]] = queue.Queue()
    idle_bridge.set_message_handler(messages.put)
    _run(idle_bridge.enable_device_change_notifications())
    handler = cast("Callable[[], None]", priv(idle_bridge, "_device_manager_changed_handler", object))

    handler()

    assert _await_payload(messages, "device_list_changed") == {"type": "device_list_changed"}


async def _install_script(bridge: FridaBridge, kind: str) -> str:
    """Install one kind of retained script on the bridge and return its registry identifier.

    Args:
        bridge: Attached bridge.
        kind: One of the names in ``_SCRIPT_KINDS``.

    Returns:
        str: Identifier of the script in the bridge's script registry.
    """
    if kind == "persistent":
        return await bridge.execute_persistent_script("var critcovIdle = 1;")
    if kind == "compiled":
        return await bridge.load_compiled_script(await bridge.compile_script("var critcovIdle = 1;"))
    if kind == "snapshot":
        snapshot = await bridge.snapshot_script("var critcovWarm = 1;")
        return await bridge.load_script_with_snapshot("var critcovIdle = 1;", snapshot)
    if kind == "exception":
        return await bridge.set_exception_handler()
    if kind == "probe":
        tick = await bridge.find_export_by_name("GetTickCount", "kernel32.dll")
        assert tick is not None
        probe_id = await bridge.stalker_add_call_probe(tick, "send({ type: 'critcov_probe' });")
        return cast("dict[str, str]", priv(bridge, "_call_probes", object))[probe_id]
    return await bridge.socket_listen(0)


@pytest.mark.parametrize("kind", _SCRIPT_KINDS, ids=list(_SCRIPT_KINDS))
def test_retained_script_message_callback_forwards_messages_to_the_message_handler(attached_bridge: FridaBridge, kind: str) -> None:
    """The message callback the bridge registered on a retained script dispatches a message and ignores its binary data.

    Args:
        attached_bridge: Bridge attached to the child.
        kind: Kind of retained script that is installed.
    """
    messages: queue.Queue[dict[str, object]] = queue.Queue()
    attached_bridge.set_message_handler(messages.put)
    script_id = _run(_install_script(attached_bridge, kind))
    script = cast("dict[str, frida.Script]", priv(attached_bridge, "_scripts", object))[script_id]
    callback = _message_handlers(script)[0]
    message = cast("ScriptMessage", {"type": "send", "payload": {"type": "critcov_direct", "kind": kind}})

    callback(message, b"ignored")

    assert _await_payload(messages, "critcov_direct") == {"type": "critcov_direct", "kind": kind}


def _start_trace(bridge: FridaBridge, kind: str) -> str:
    """Start a Stalker trace of the requested kind on the default thread.

    Args:
        bridge: Attached bridge.
        kind: ``plain`` for ``stalker_follow`` or ``transform`` for ``stalker_follow_with_transform``.

    Returns:
        str: Identifier of the trace script.
    """
    if kind == "plain":
        return _run(bridge.stalker_follow(events="call", limit=100))
    return _run(bridge.stalker_follow_with_transform(events="call", limit=100, transform_code="iterator.keep();"))


def _as_dispatched(message: dict[str, object]) -> dict[str, object]:
    """Copy a message the way the bridge copies it before dispatching.

    Args:
        message: Message handed to a callback.

    Returns:
        dict[str, object]: A shallow copy.
    """
    return dict(message)


@pytest.mark.parametrize("kind", _STALKER_KINDS, ids=list(_STALKER_KINDS))
def test_stalker_trace_callback_stores_batches_and_forwards_every_message(attached_bridge: FridaBridge, kind: str) -> None:
    """The trace callback stores the events of a batch against the thread and forwards each message, whatever its shape.

    Args:
        attached_bridge: Bridge attached to the child.
        kind: Which Stalker trace flavor is started.
    """
    messages: queue.Queue[dict[str, object]] = queue.Queue()
    attached_bridge.set_message_handler(messages.put)
    script_id = _start_trace(attached_bridge, kind)
    script = cast("dict[str, frida.Script]", priv(attached_bridge, "_scripts", object))[script_id]
    callback = _message_handlers(script)[0]
    batch: dict[str, object] = {
        "type": "send",
        "payload": {
            "type": "stalker_batch",
            "tid": 0,
            "events": [{"type": "call", "from": hex(_BATCH_FROM), "to": hex(_BATCH_TO), "depth": 1}, "junk"],
        },
    }

    for message in (batch, *_NOISE_MESSAGES):
        callback(cast("ScriptMessage", message), None)

    seen = _drain(messages)
    assert all(_as_dispatched(message) in seen for message in (batch, *_NOISE_MESSAGES))
    trace = _run(attached_bridge.stalker_unfollow())
    mine = [event for event in trace.events if event.from_address == _BATCH_FROM]
    assert [(event.event_type, event.to_address, event.depth) for event in mine] == [("call", _BATCH_TO, 1)]


def test_call_summary_callback_accumulates_numeric_counts_and_forwards_every_message(attached_bridge: FridaBridge) -> None:
    """The call-summary callback adds up numeric counts per target across messages, skips other values and forwards messages.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    messages: queue.Queue[dict[str, object]] = queue.Queue()
    attached_bridge.set_message_handler(messages.put)
    script_id = _run(attached_bridge.stalker_follow_call_summary())
    script = cast("dict[str, frida.Script]", priv(attached_bridge, "_scripts", object))[script_id]
    callback = _message_handlers(script)[0]
    summaries: tuple[dict[str, object], ...] = (
        {"type": "send", "payload": {"type": "stalker_call_summary", "tid": 0, "summary": {"0x1000": 3, "0x2000": 2.0, "bad": "x"}}},
        {"type": "send", "payload": {"type": "stalker_call_summary", "tid": 0, "summary": {"0x1000": 4}}},
        {"type": "send", "payload": {"type": "stalker_call_summary", "tid": 0, "summary": ["not", "a", "dict"]}},
        {"type": "send", "payload": {"type": "stalker_summary_started", "tid": 0}},
    )

    for message in (*summaries, *_NOISE_MESSAGES):
        callback(cast("ScriptMessage", message), None)

    seen = _drain(messages)
    assert all(_as_dispatched(message) in seen for message in (*summaries, *_NOISE_MESSAGES))
    summary = _run(attached_bridge.stalker_unfollow_call_summary())
    assert summary.counts["0x1000"] == 7
    assert summary.counts["0x2000"] == 2
    assert "bad" not in summary.counts


@pytest.mark.parametrize(
    "acknowledgement",
    [
        {"type": "send", "payload": {"type": "stalker_summary_unfollowed"}},
        {"type": "send", "payload": {"type": "stalker_summary_unfollow_error"}},
        {"type": "error", "description": "critcov-ack-error", "stack": "", "fileName": "", "lineNumber": 1, "columnNumber": 1},
    ],
    ids=["unfollowed", "unfollow_error", "script_error"],
)
def test_unfollow_acknowledgement_callback_releases_the_wait_for_an_acknowledging_message(
    attached_bridge: FridaBridge,
    acknowledgement: dict[str, object],
) -> None:
    """Only an unfollow acknowledgement or an error message ends the wait for a script that never answers by itself.

    Args:
        attached_bridge: Bridge attached to the child.
        acknowledgement: The message that is expected to end the wait.
    """
    script_id, script = _loaded_script(attached_bridge, "var critcovSilent = 1;")
    registry = cast("dict[int, str]", priv(attached_bridge, "_stalker_summary_scripts", object))
    registry[9] = script_id
    handlers = _message_handlers(script)
    ignored: tuple[dict[str, object], ...] = (
        {"type": "send", "payload": "critcov-plain"},
        {"type": "send", "payload": {"type": "critcov_other"}},
        {"type": "log", "level": "info", "payload": "critcov-log"},
    )

    async def scenario() -> float:
        """Run the unfollow while feeding the temporary acknowledgement callback.

        Returns:
            float: Duration in milliseconds that the unfollow reported.
        """
        unfollow = asyncio.ensure_future(attached_bridge.stalker_unfollow_call_summary(9))
        await asyncio.to_thread(_wait_for_registrations, handlers, 2)
        assert len(handlers) == 2
        callback = handlers[1]
        for message in ignored:
            callback(cast("ScriptMessage", message), None)
        assert not unfollow.done()
        callback(cast("ScriptMessage", acknowledgement), None)
        return (await unfollow).duration_ms

    assert _run(scenario()) < _ACK_TIMEOUT_MS
    assert script.is_destroyed
    assert registry == {}


def test_remove_remote_device_forgets_the_removed_device_as_the_current_one(idle_bridge: FridaBridge) -> None:
    """Removing the remote endpoint the bridge is connected to leaves the bridge without a current device.

    Args:
        idle_bridge: Initialized bridge without a session.
    """
    try:
        info = _run(idle_bridge.connect_device("remote", _REMOTE_HOST))
        assert info.device_type == "remote"

        _run(idle_bridge.remove_remote_device(_REMOTE_HOST))

        assert priv(idle_bridge, "_device", object) is None
    finally:
        with contextlib.suppress(Exception):
            frida.get_device_manager().remove_remote_device(_REMOTE_HOST)


def test_remove_remote_device_detaches_the_session_of_the_removed_device(attached_bridge: FridaBridge) -> None:
    """Removing the remote endpoint the bridge is connected to also releases the session it holds.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    try:
        remote = frida.get_device_manager().add_remote_device(_REMOTE_HOST)
        put(attached_bridge, "_device", value=remote)

        _run(attached_bridge.remove_remote_device(_REMOTE_HOST))

        assert priv(attached_bridge, "_device", object) is None
        assert priv(attached_bridge, "_session", object) is None
        assert attached_bridge.state.process_attached is False
    finally:
        with contextlib.suppress(Exception):
            frida.get_device_manager().remove_remote_device(_REMOTE_HOST)


@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("read_typed_value", (0, "u8")),
        ("write_typed_value", (0, "u8", 1)),
        ("copy_memory", (0, 0, 4)),
    ],
    ids=["typed_read", "typed_write", "copy"],
)
def test_failed_memory_access_error_names_the_reason(attached_bridge: FridaBridge, method: str, args: tuple[object, ...]) -> None:
    """A memory access that faults in the target reports Frida's description of the fault in the error details.

    Args:
        attached_bridge: Bridge attached to the child.
        method: Name of the bridge method under test.
        args: Positional arguments targeting the null page.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(cast("Callable[..., Coroutine[object, object, object]]", getattr(attached_bridge, method))(*args))

    reason = excinfo.value.details.get("reason")
    assert isinstance(reason, str)
    assert reason


def test_protection_query_of_the_null_page_reports_no_access(attached_bridge: FridaBridge) -> None:
    """A protection query for the unmapped null page reports the no-access triplet.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    assert _run(attached_bridge.query_memory_protection(0)) == "---"
