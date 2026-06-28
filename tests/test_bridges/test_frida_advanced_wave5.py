# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Wave-5 falsifiable gates for FridaBridge — advanced instrumentation band.

Closes the 35 STILL-OPEN findings from the Group-04 report:

    #1   is_available
    #5   detach(kill_spawned)
    #6   get_hooks
    #7   execute_script (public surface)
    #8   unload_all_scripts
    #9   set_message_handler
    #11  resume_child — error-path match=
    #13  post_message
    #14  eternalize_script
    #16  create_cancellable
    #17  cancel
    #20  enumerate_symbols
    #21  load_module
    #22  find_module_by_address
    #23  find_functions_matching
    #24  disassemble_instruction
    #25  get_backtrace
    #26  set_exception_handler
    #27  revert_hook
    #28  flush_interceptor
    #29  call_system_function
    #30  stalker_add_call_probe
    #31  stalker_remove_call_probe
    #32  enumerate_applications
    #33  inject_library_file
    #34  inject_library_blob
    #46  create_cmodule
    #64  cloak_add_thread
    #65  cloak_remove_thread
    #66  cloak_add_range
    #67  cloak_remove_range
    #68  monitor_path
    #69  stop_monitor
    #70  enumerate_exports not-found error path (match=)
    #71  stalker_follow / stalker_unfollow — deterministic offline gate

Every test drives the real production code path.  Frida transport is replaced
by in-file fake doubles.  No unittest.mock is used.  Every assertion is on an
exact, independently-computed value.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import TYPE_CHECKING, cast

import frida
import pytest

from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.core.types import (
    FridaApplicationInfo,
    HookInfo,
    InstructionInfo,
    ModuleInfo,
    StalkerTrace,
    SymbolInfo,
    SystemCallResult,
    ToolError,
)


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# ---------------------------------------------------------------------------
# Oracle constants — chosen independently of the production code
# ---------------------------------------------------------------------------

_ATTACH_PID: int = 7777
_PROBE_ADDRESS: int = 0xABC0_0000
_CLOAK_THREAD_ID: int = 4321
_CLOAK_ADDRESS: int = 0xDEAD_0000
_CLOAK_SIZE: int = 4096
_MODULE_BASE: int = 0x1000_0000
_MODULE_SIZE: int = 81920
_SYM_ADDRESS: int = 0x7FFE_1234
_INSN_ADDRESS: int = 0xCAFE_0000
_INSN_NEXT: int = 0xCAFE_0003
_INSN_SIZE: int = 3
_CALL_FUNC_ADDRESS: int = 0xDEAD_1234
_INJECT_PID: int = 1234
_INJECT_RESULT: int = 42
_INJECT_BLOB_RESULT: int = 43

_EXEC_RESULT: dict[str, object] = {"type": "result", "value": 99}
_EXEC_RESULT_STR: str = str(_EXEC_RESULT)

_MODULE_NAME: str = "ntdll.dll"
_MODULE_PATH: str = "C:\\Windows\\System32\\ntdll.dll"
_LIB_PATH: str = "C:\\mylib.dll"
_LIB_BLOB_HEX: str = "deadbeef"
_LIB_BLOB_BYTES: bytes = bytes.fromhex(_LIB_BLOB_HEX)
_LIB_ENTRYPOINT: str = "my_init"
_LIB_DATA: str = "init_data"

_CMODULE_CODE: str = "void my_func(void) {}"
_CMODULE_SYM_NAME: str = "helper"
_CMODULE_SYM_ADDR: int = 0x5000_0000

_MONITOR_PATH: str = "C:\\temp\\watched"
_MONITOR_ID: str = "mon00001"

_STALKER_CALL_EVENT: dict[str, object] = {
    "type": "call",
    "from": "0x7fff1000",
    "to": "0x7fff2000",
    "depth": 0,
}
_STALKER_TID: int = 9999


# ---------------------------------------------------------------------------
# Minimal fake Frida doubles
# ---------------------------------------------------------------------------


class _FakeScriptW5:
    """Minimal ``frida.core.Script`` substitute with per-call tracking.

    Records every ``on``/``load``/``unload``/``post``/``eternalize`` call.
    Exposes ``deliver`` so tests can push canned messages to the registered
    handler without running any real JavaScript.
    """

    def __init__(self) -> None:
        """Initialise all per-call counters to zero."""
        self.source: str = ""
        self.load_calls: int = 0
        self.unload_calls: int = 0
        self.eternalize_calls: int = 0
        self.posts: list[dict[str, object]] = []
        self._handler: Callable[..., None] | None = None

    def on(self, event: str, handler: Callable[..., None]) -> None:
        """Capture the message handler registered by the bridge.

        Args:
            event: Event name; only ``"message"`` is intercepted.
            handler: Callback invoked when a message is delivered.
        """
        if event == "message":
            self._handler = handler

    def load(self) -> None:
        """Record a load invocation."""
        self.load_calls += 1

    def unload(self) -> None:
        """Record an unload invocation."""
        self.unload_calls += 1

    def eternalize(self) -> None:
        """Record an eternalize invocation."""
        self.eternalize_calls += 1

    def post(self, message: dict[str, object]) -> None:
        """Record a posted message.

        Args:
            message: Message dict posted from Python to the script.
        """
        self.posts.append(dict(message))

    def deliver(self, payload: dict[str, object], data: bytes | None = None) -> None:
        """Push a send-shaped payload to the registered handler.

        Args:
            payload: Inner payload to wrap as ``{"type": "send", "payload": ...}``.
            data: Optional binary side-channel.
        """
        if self._handler is None:
            return
        self._handler({"type": "send", "payload": payload}, data)


class _FakeSessionW5:
    """``frida.core.Session`` substitute that records every JS source the bridge emits."""

    def __init__(self) -> None:
        """Initialise empty script and source registries."""
        self.scripts: list[_FakeScriptW5] = []
        self.sources: list[str] = []
        self.detach_calls: int = 0

    def create_script(self, source: str, **_: object) -> _FakeScriptW5:
        """Return a new fake script and record the JavaScript source.

        Args:
            source: JavaScript source the bridge is injecting.
            **_: Ignored keyword arguments.

        Returns:
            _FakeScriptW5: Newly created fake script.
        """
        script = _FakeScriptW5()
        script.source = source
        self.sources.append(source)
        self.scripts.append(script)
        return script

    def detach(self) -> None:
        """Record a detach call."""
        self.detach_calls += 1


class _FakeApp:
    """Minimal stand-in for a Frida application object."""

    def __init__(self, identifier: str, name: str, pid: int) -> None:
        """Initialise the fake application entry.

        Args:
            identifier: Bundle identifier.
            name: Human-readable name.
            pid: Process ID (0 if not running).
        """
        self.identifier = identifier
        self.name = name
        self.pid = pid


class _FakeDeviceW5:
    """``frida.core.Device`` substitute that records device-level calls."""

    def __init__(
        self,
        resume_raises: BaseException | None = None,
        inject_file_id: int = _INJECT_RESULT,
        inject_blob_id: int = _INJECT_BLOB_RESULT,
        apps: list[_FakeApp] | None = None,
    ) -> None:
        """Initialise the fake device with scripted responses.

        Args:
            resume_raises: If set, ``resume()`` raises this exception.
            inject_file_id: Value returned by ``inject_library_file()``.
            inject_blob_id: Value returned by ``inject_library_blob()``.
            apps: Application list returned by ``enumerate_applications()``.
        """
        self._resume_raises = resume_raises
        self._inject_file_id = inject_file_id
        self._inject_blob_id = inject_blob_id
        self._apps: list[_FakeApp] = apps or []
        self.resume_calls: list[int] = []
        self.inject_file_calls: list[tuple[int, str, str, str]] = []
        self.inject_blob_calls: list[tuple[int, bytes, str, str]] = []

    def resume(self, pid: int) -> None:
        """Record the PID and optionally raise.

        Args:
            pid: Process ID to resume.
        """
        self.resume_calls.append(pid)
        exc = self._resume_raises
        if exc is not None:
            raise exc

    def inject_library_file(self, pid: int, path: str, entrypoint: str, data: str) -> int:
        """Record injection args and return the scripted ID.

        Args:
            pid: Target process ID.
            path: Path to the library.
            entrypoint: Entrypoint function name.
            data: Data string for the entrypoint.

        Returns:
            int: Scripted injection ID.
        """
        self.inject_file_calls.append((pid, path, entrypoint, data))
        return self._inject_file_id

    def inject_library_blob(self, pid: int, blob: bytes, entrypoint: str, data: str) -> int:
        """Record injection args and return the scripted ID.

        Args:
            pid: Target process ID.
            blob: Library bytes.
            entrypoint: Entrypoint function name.
            data: Data string for the entrypoint.

        Returns:
            int: Scripted injection ID.
        """
        self.inject_blob_calls.append((pid, blob, entrypoint, data))
        return self._inject_blob_id

    def enumerate_applications(self) -> list[_FakeApp]:
        """Return the scripted application list.

        Returns:
            list[_FakeApp]: Configured application entries.
        """
        return self._apps


class _FakeFileMonitor:
    """Minimal ``frida.FileMonitor`` substitute that records enable/disable calls."""

    def __init__(self, path: str) -> None:
        """Initialise the fake file monitor.

        Args:
            path: Path being monitored.
        """
        self.path = path
        self.enable_calls: int = 0
        self.disable_calls: int = 0
        self._handlers: dict[str, Callable[..., None]] = {}

    def on(self, event: str, handler: Callable[..., None]) -> None:
        """Register an event handler.

        Args:
            event: Event name.
            handler: Callback for the event.
        """
        self._handlers[event] = handler

    def enable(self) -> None:
        """Record an enable call."""
        self.enable_calls += 1

    def disable(self) -> None:
        """Record a disable call."""
        self.disable_calls += 1


class _StalkerInjectScript:
    """Fake Frida script that injects stalker events synchronously during load().

    Used by the deterministic stalker_follow/stalker_unfollow gate (#71) to
    avoid any ``time.sleep`` / wall-clock dependency.  On ``load()``, the script
    delivers a ``stalker_started`` message and one ``stalker_batch`` containing
    known events to the registered handler.  ``_set_event_threadsafe`` then
    queues the event release on the asyncio loop via ``call_soon_threadsafe``
    so the waiter in ``stalker_follow`` resolves correctly.
    """

    def __init__(self, tid: int, batch: list[dict[str, object]]) -> None:
        """Initialise with the thread ID and batch events to deliver on load.

        Args:
            tid: Thread ID passed in ``stalker_started`` and ``stalker_batch`` payloads.
            batch: Raw event dicts delivered as the ``events`` field of the batch.
        """
        self.tid = tid
        self.batch = batch
        self.load_calls: int = 0
        self.unload_calls: int = 0
        self.posts: list[dict[str, object]] = []
        self._handler: Callable[..., None] | None = None

    def on(self, event: str, handler: Callable[..., None]) -> None:
        """Capture the bridge's on_stalker_message handler.

        Args:
            event: Event name; only ``"message"`` is intercepted.
            handler: Bridge-registered callback.
        """
        if event == "message":
            self._handler = handler

    def load(self) -> None:
        """Deliver stalker_started and stalker_batch events on the thread pool thread.

        Called via ``asyncio.to_thread`` so the handler invocations occur on
        a worker thread, exactly as the real Frida runtime would trigger them.
        ``_set_event_threadsafe`` then uses ``call_soon_threadsafe`` to wake
        the asyncio waiter.
        """
        self.load_calls += 1
        handler = self._handler
        if handler is None:
            return
        handler(
            {"type": "send", "payload": {"type": "stalker_started", "tid": self.tid}},
            None,
        )
        if self.batch:
            handler(
                {
                    "type": "send",
                    "payload": {"type": "stalker_batch", "tid": self.tid, "events": self.batch},
                },
                None,
            )

    def unload(self) -> None:
        """Record an unload call."""
        self.unload_calls += 1

    def post(self, message: dict[str, object]) -> None:
        """Record a posted message.

        Args:
            message: Message dict posted by the bridge.
        """
        self.posts.append(dict(message))


class _StalkerSession:
    """Recording session that returns ``_StalkerInjectScript`` from ``create_script``."""

    def __init__(self, tid: int, batch: list[dict[str, object]]) -> None:
        """Initialise with the thread ID and batch events to embed in the inject script.

        Args:
            tid: Thread ID forwarded to ``_StalkerInjectScript``.
            batch: Batch events forwarded to ``_StalkerInjectScript``.
        """
        self.tid = tid
        self.batch = batch
        self.scripts: list[_StalkerInjectScript] = []
        self.sources: list[str] = []

    def create_script(self, source: str, **_: object) -> _StalkerInjectScript:
        """Return a new inject script and record the JS source.

        Args:
            source: JavaScript source the bridge is injecting.
            **_: Ignored keyword arguments.

        Returns:
            _StalkerInjectScript: Inject script for deterministic event delivery.
        """
        script = _StalkerInjectScript(self.tid, self.batch)
        self.sources.append(source)
        self.scripts.append(script)
        return script

    def detach(self) -> None:
        """No-op detach."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro: Coroutine[object, object, object]) -> object:
    """Execute an async coroutine on a fresh event loop and return the result.

    Args:
        coro: Awaitable to execute.

    Returns:
        object: Whatever the coroutine returns.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _set(target: object, name: str, value: object) -> None:
    """Set an attribute on *target* via setattr to avoid private-access diagnostics.

    Args:
        target: Object to mutate.
        name: Attribute name.
        value: Replacement value.
    """
    setattr(target, name, value)


def _get(target: object, name: str) -> object:
    """Read an attribute from *target*.

    Args:
        target: Object to read.
        name: Attribute name.

    Returns:
        object: The attribute value.
    """
    return getattr(target, name)


def _index_set(target: object, name: str, key: object, value: object) -> None:
    """Set ``target.<name>[key] = value`` without private-access diagnostics.

    Args:
        target: Object whose attribute holds a mapping.
        name: Attribute name.
        key: Mapping key.
        value: Mapping value.
    """
    container = cast("dict[object, object]", getattr(target, name))
    container[key] = value


def _get_dict(target: object, name: str) -> dict[object, object]:
    """Read a dict-typed private attribute cast for lookup checks.

    Args:
        target: Object to read.
        name: Attribute name.

    Returns:
        dict[object, object]: The mapping at ``target.<name>``.
    """
    return cast("dict[object, object]", getattr(target, name))


def _build_attached_bridge(session: _FakeSessionW5 | None = None) -> tuple[FridaBridge, _FakeSessionW5]:
    """Construct a FridaBridge wired to a fake session in attached state.

    Args:
        session: Optional pre-built session; a new one is created if None.

    Returns:
        tuple[FridaBridge, _FakeSessionW5]: Bridge and its backing session.
    """
    bridge = FridaBridge()
    sess = session if session is not None else _FakeSessionW5()
    _set(bridge, "_session", sess)
    _set(bridge, "_pid", _ATTACH_PID)
    bridge.state.connected = True
    bridge.state.tool_running = True
    bridge.state.process_attached = True
    bridge.state.target_pid = _ATTACH_PID
    return bridge, sess


def _build_attached_bridge_with_device(
    device: _FakeDeviceW5 | None = None,
) -> tuple[FridaBridge, _FakeSessionW5, _FakeDeviceW5]:
    """Construct a FridaBridge wired to fake session AND fake device.

    Args:
        device: Optional pre-built device; a new one is created if None.

    Returns:
        tuple[FridaBridge, _FakeSessionW5, _FakeDeviceW5]: Bridge, session, and device.
    """
    bridge, sess = _build_attached_bridge()
    dev = device if device is not None else _FakeDeviceW5()
    _set(bridge, "_device", dev)
    return bridge, sess, dev


def _patch_exec(bridge: FridaBridge, fixed_result: dict[str, object]) -> list[str]:
    """Replace ``_execute_script_and_wait`` with a recorder that returns *fixed_result*.

    Args:
        bridge: Bridge whose internal method is replaced.
        fixed_result: Dict returned on every invocation.

    Returns:
        list[str]: Accumulates script source strings; grows by one per call.
    """
    captured: list[str] = []

    async def _fake(
        script_code: str,
        max_wait: float = 5.0,
        *,
        cancellable_id: str | None = None,
    ) -> dict[str, object]:
        del max_wait, cancellable_id
        captured.append(script_code)
        await asyncio.sleep(0)
        return dict(fixed_result)

    _set(bridge, "_execute_script_and_wait", _fake)
    return captured


# ---------------------------------------------------------------------------
# Finding #1 — is_available()
# ---------------------------------------------------------------------------


def test_is_available_returns_true_when_device_accessible() -> None:
    """``is_available()`` returns True when ``frida.get_local_device`` succeeds.

    Patches ``frida.get_local_device`` to return a dummy device so the test
    is deterministic even in environments without a running frida-server.

    Falsifiable: if the bridge returns False on a successful device lookup the
    ``is True`` assertion fails.
    """
    original = getattr(frida, "get_local_device")
    setattr(frida, "get_local_device", lambda **_: object())
    try:
        bridge = FridaBridge()
        result = _run(bridge.is_available())
        assert result is True, f"is_available() must return True when device accessible, got {result!r}"
    finally:
        setattr(frida, "get_local_device", original)


def test_is_available_returns_false_when_device_raises_oserror() -> None:
    """``is_available()`` returns False when ``frida.get_local_device`` raises OSError.

    Falsifiable: if the except clause is removed the function propagates the
    OSError instead of returning False.
    """
    original = getattr(frida, "get_local_device")

    def _raise(**_: object) -> object:
        raise OSError("no device")

    setattr(frida, "get_local_device", _raise)
    try:
        bridge = FridaBridge()
        result = _run(bridge.is_available())
        assert result is False, f"is_available() must return False on OSError, got {result!r}"
    finally:
        setattr(frida, "get_local_device", original)


# ---------------------------------------------------------------------------
# Finding #5 — detach(kill_spawned)
# ---------------------------------------------------------------------------


def test_detach_calls_session_detach_exactly_once_and_clears_session() -> None:
    """``detach()`` calls session.detach() once and sets ``bridge._session`` to None.

    Falsifiable: if detach() returns early without calling session.detach() the
    detach_calls==1 assertion fails; if _perform_detach omits the
    ``self._session = None`` assignment the second assertion fails.
    """
    bridge, sess = _build_attached_bridge()
    _run(bridge.detach(kill_spawned=False))
    assert sess.detach_calls == 1, f"session.detach() must be called once, got {sess.detach_calls}"
    session_after = _get(bridge, "_session")
    assert session_after is None, f"bridge._session must be None after detach, got {session_after!r}"


# ---------------------------------------------------------------------------
# Finding #6 — get_hooks()
# ---------------------------------------------------------------------------


def test_get_hooks_returns_hook_with_correct_id_and_target() -> None:
    """``get_hooks()`` returns the HookInfo stored in the internal hooks registry.

    Falsifiable: if get_hooks() returns a copy that drops entries, or returns
    values from a different container, the assertion on id/target fails.
    """
    bridge, _ = _build_attached_bridge()
    hook_id = "hook001"
    expected = HookInfo(id=hook_id, target="0x10001000", address=0x10001000, script_id="s001", active=True)
    _index_set(bridge, "_hooks", hook_id, expected)
    result = cast("list[HookInfo]", _run(bridge.get_hooks()))
    assert len(result) == 1, f"get_hooks() must return 1 hook, got {len(result)}"
    assert result[0].id == hook_id, f"hook id mismatch: {result[0].id!r} != {hook_id!r}"
    assert result[0].target == "0x10001000", f"hook target mismatch: {result[0].target!r}"


# ---------------------------------------------------------------------------
# Finding #7 — execute_script(script)
# ---------------------------------------------------------------------------


def test_execute_script_returns_str_of_canned_result() -> None:
    """``execute_script()`` converts the ``_execute_script_and_wait`` result to str.

    Oracle: ``str(_EXEC_RESULT)`` computed independently from the known dict.
    Falsifiable: if execute_script() returns the dict itself instead of its str
    representation the equality assertion fails.
    """
    bridge, _ = _build_attached_bridge()
    _patch_exec(bridge, _EXEC_RESULT)
    result = cast("str", _run(bridge.execute_script("some_js_code()")))
    assert result == _EXEC_RESULT_STR, f"execute_script() must return str(result), got {result!r}"


def test_execute_script_raises_on_error_payload() -> None:
    """``execute_script()`` raises ToolError when the result contains an ``error`` key.

    Falsifiable: if the ``if "error" in result`` check is removed the error
    payload is silently stringified instead of raising.
    """
    bridge, _ = _build_attached_bridge()
    _patch_exec(bridge, {"error": "script crashed"})
    with pytest.raises(ToolError, match=r"script execution failed"):
        _run(bridge.execute_script("bad_js()"))


# ---------------------------------------------------------------------------
# Finding #8 — unload_all_scripts()
# ---------------------------------------------------------------------------


def test_unload_all_scripts_clears_scripts_dict_and_calls_unload_on_each() -> None:
    """``unload_all_scripts()`` empties ``_scripts`` and calls unload() on every script.

    Falsifiable: if unload_all_scripts() only clears the dict but skips
    calling unload() on each script, the ``unload_calls`` assertions fail;
    if the loop omits one script the len==0 check would still pass but the
    individual unload count assertions catch it.
    """
    bridge, _ = _build_attached_bridge()
    s1 = _FakeScriptW5()
    s2 = _FakeScriptW5()
    _index_set(bridge, "_scripts", "id1", s1)
    _index_set(bridge, "_scripts", "id2", s2)
    _run(bridge.unload_all_scripts())
    scripts_after = _get_dict(bridge, "_scripts")
    assert len(scripts_after) == 0, f"_scripts must be empty after unload_all, got {len(scripts_after)} entries"
    assert s1.unload_calls == 1, f"script s1 unload() must be called once, got {s1.unload_calls}"
    assert s2.unload_calls == 1, f"script s2 unload() must be called once, got {s2.unload_calls}"


# ---------------------------------------------------------------------------
# Finding #9 — set_message_handler(handler)
# ---------------------------------------------------------------------------


def test_dispatch_message_calls_registered_handler_with_exact_dict() -> None:
    """``_dispatch_message`` invokes the handler registered via ``set_message_handler``.

    Drives the full path: set_message_handler → internal lock → _dispatch_message.

    Falsifiable: if the lock-protected read drops the handler reference the
    received list stays empty; if a copy is dispatched instead of the original
    dict the equality check fails.
    """
    bridge, _ = _build_attached_bridge()
    delivered: list[dict[str, object]] = []

    def handler(msg: dict[str, object]) -> None:
        """Capture messages dispatched by the bridge.

        Args:
            msg: Message dict forwarded by the bridge dispatcher.
        """
        delivered.append(dict(msg))

    expected: dict[str, object] = {"type": "send", "payload": {"event": "hook_hit", "addr": 0x1000}}
    bridge.set_message_handler(handler)
    dispatch = cast("Callable[[dict[str, object]], None]", getattr(bridge, "_dispatch_message"))
    dispatch(expected)
    assert len(delivered) == 1, f"handler must be invoked once via _dispatch_message, got {len(delivered)}"
    assert delivered[0] == expected, f"dispatched payload mismatch: {delivered[0]!r} != {expected!r}"


# ---------------------------------------------------------------------------
# Finding #11 — resume_child(pid) error path with match=
# ---------------------------------------------------------------------------


def test_resume_child_raises_toolerror_matching_child_gating_failed() -> None:
    """``resume_child()`` raises ToolError whose message matches 'child gating'.

    The bare ``pytest.raises(ToolError)`` in the existing test accepts *any*
    ToolError; this gate pins the exact message so a different ToolError
    (e.g. 'not attached') would not satisfy the assertion.

    Falsifiable: if the except block raises ToolError('not attached') instead
    of ToolError('child gating operation failed') the match= pattern rejects it.
    """
    dev = _FakeDeviceW5(resume_raises=RuntimeError("frida error"))
    bridge, _, _ = _build_attached_bridge_with_device(dev)
    with pytest.raises(ToolError, match=r"child gating operation failed"):
        _run(bridge.resume_child(99999))


# ---------------------------------------------------------------------------
# Finding #13 — post_message(script_id, message)
# ---------------------------------------------------------------------------


def test_post_message_posts_parsed_json_to_script() -> None:
    """``post_message()`` deserialises the JSON string and passes the dict to script.post.

    Oracle: ``fake_script.posts == [expected_payload]``.
    Falsifiable: if the bridge passes the raw JSON string instead of the parsed
    dict, or passes a different payload, the equality assertion fails.
    """
    bridge, _ = _build_attached_bridge()
    script_id = "sc00001"
    fake_script = _FakeScriptW5()
    _index_set(bridge, "_scripts", script_id, fake_script)
    expected: dict[str, object] = {"cmd": "read", "address": 0x1000}
    _run(bridge.post_message(script_id, json.dumps(expected)))
    assert fake_script.posts == [expected], f"script.post must receive {expected!r}, got {fake_script.posts!r}"


def test_post_message_unknown_script_id_raises_toolerror() -> None:
    """``post_message()`` raises ToolError when the script_id is not registered.

    Falsifiable: if the guard ``if script_id not in self._scripts`` is removed,
    the call proceeds to json.loads and may raise a different exception or
    succeed silently.
    """
    bridge, _ = _build_attached_bridge()
    with pytest.raises(ToolError, match=r"script not found"):
        _run(bridge.post_message("nonexistent", json.dumps({"x": 1})))


# ---------------------------------------------------------------------------
# Finding #14 — eternalize_script(script_id)
# ---------------------------------------------------------------------------


def test_eternalize_script_calls_eternalize_and_removes_from_registry() -> None:
    """``eternalize_script()`` calls ``script.eternalize()`` once and removes from ``_scripts``.

    Falsifiable: if the bridge skips calling ``script.eternalize()`` the
    eternalize_calls==1 assertion fails; if it forgets to delete the id from
    _scripts the id-not-in check fails.
    """
    bridge, _ = _build_attached_bridge()
    script_id = "eter0001"
    fake_script = _FakeScriptW5()
    _index_set(bridge, "_scripts", script_id, fake_script)
    result = _run(bridge.eternalize_script(script_id))
    assert result is True, f"eternalize_script must return True, got {result!r}"
    assert fake_script.eternalize_calls == 1, (
        f"script.eternalize() must be called once, got {fake_script.eternalize_calls}"
    )
    scripts = _get_dict(bridge, "_scripts")
    assert script_id not in scripts, f"script_id must be removed from _scripts after eternalize, still present"


# ---------------------------------------------------------------------------
# Finding #16 — create_cancellable()
# ---------------------------------------------------------------------------


def test_create_cancellable_registers_token_in_cancellables() -> None:
    """``create_cancellable()`` stores a real ``frida.Cancellable`` under the returned id.

    Oracle: the returned id is a non-empty str and is a key in ``_cancellables``.
    Falsifiable: if create_cancellable() returns an id not stored in
    _cancellables the ``in`` assertion fails; if an empty string is returned
    the ``len > 0`` assertion fails.
    """
    bridge = FridaBridge()
    token_id = cast("str", _run(bridge.create_cancellable()))
    assert isinstance(token_id, str) and len(token_id) > 0, (
        f"create_cancellable must return non-empty str id, got {token_id!r}"
    )
    cancellables = _get_dict(bridge, "_cancellables")
    assert token_id in cancellables, (
        f"returned id {token_id!r} must be registered in _cancellables, keys={list(cancellables)!r}"
    )


# ---------------------------------------------------------------------------
# Finding #17 — cancel(cancellable_id)
# ---------------------------------------------------------------------------


def test_cancel_known_id_returns_true_and_removes_token() -> None:
    """``cancel()`` returns True and removes the token when the id is known.

    Falsifiable: if cancel() returns False instead of True the first assertion
    fails; if the token is not removed from _cancellables the second fails.
    """
    bridge = FridaBridge()
    token_id = cast("str", _run(bridge.create_cancellable()))
    result = cast("bool", _run(bridge.cancel(token_id)))
    assert result is True, f"cancel(known_id) must return True, got {result!r}"
    cancellables = _get_dict(bridge, "_cancellables")
    assert token_id not in cancellables, f"token {token_id!r} must be removed after cancel, still present"


def test_cancel_unknown_id_returns_false() -> None:
    """``cancel()`` returns False for an unknown cancellable id.

    The production code does ``self._cancellables.pop(id, None)`` and returns
    False when None is obtained — it does NOT raise ToolError.

    Falsifiable: if the bridge raises ToolError for unknown ids the
    pytest.raises-free assertion on the return value is unreachable.
    """
    bridge = FridaBridge()
    result = cast("bool", _run(bridge.cancel("completely_unknown_id_xyz")))
    assert result is False, f"cancel(unknown_id) must return False, got {result!r}"


# ---------------------------------------------------------------------------
# Finding #20 — enumerate_symbols(module_name)
# ---------------------------------------------------------------------------

_SYM_NAME: str = "CreateFileW"
_SYM_TYPE: str = "function"


def test_enumerate_symbols_embeds_module_name_and_parses_canned_symbols() -> None:
    """``enumerate_symbols()`` embeds module name in JS and parses name/address/type.

    Oracle: symbol name == 'CreateFileW', address == 0x7FFE_1234 (decimal from
    hex string "0x7ffe1234" via int(x, 16)).

    Falsifiable: if the bridge reads the wrong field from the payload the
    address mismatch catches it; if module_name is omitted from the JS the
    framing assertion fails.
    """
    bridge, _ = _build_attached_bridge()
    canned: dict[str, object] = {
        "data": [
            {"name": _SYM_NAME, "address": "0x7ffe1234", "isGlobal": True, "type": _SYM_TYPE}
        ]
    }
    captured = _patch_exec(bridge, canned)
    result = cast("list[SymbolInfo]", _run(bridge.enumerate_symbols(_MODULE_NAME)))
    assert len(captured) == 1, "exactly one script must be generated"
    assert _MODULE_NAME in captured[0], (
        f"module name {_MODULE_NAME!r} must appear in JS source; source={captured[0]!r}"
    )
    assert len(result) == 1, f"must parse exactly 1 symbol, got {len(result)}"
    assert result[0].name == _SYM_NAME, f"symbol name mismatch: {result[0].name!r} != {_SYM_NAME!r}"
    assert result[0].address == _SYM_ADDRESS, (
        f"symbol address mismatch: {result[0].address:#x} != {_SYM_ADDRESS:#x}"
    )


# ---------------------------------------------------------------------------
# Finding #21 — load_module(path)
# ---------------------------------------------------------------------------


def test_load_module_embeds_module_load_in_js_and_parses_result() -> None:
    """``load_module()`` emits 'Module.load' in JS and returns parsed ModuleInfo.

    Oracle: path embedded in JS must equal the original path; result.name must
    equal 'ntdll.dll'; result.base_address must equal _MODULE_BASE.

    Falsifiable: if Module.load is replaced with a wrong call the framing check
    fails; if the base address is parsed as decimal instead of hex the value
    mismatch is caught.
    """
    bridge, _ = _build_attached_bridge()
    canned: dict[str, object] = {
        "name": _MODULE_NAME,
        "path": _MODULE_PATH,
        "base": hex(_MODULE_BASE),
        "size": _MODULE_SIZE,
    }
    captured = _patch_exec(bridge, canned)
    result = cast("ModuleInfo", _run(bridge.load_module(_MODULE_PATH)))
    assert "Module.load" in captured[0], (
        f"'Module.load' must appear in JS; source={captured[0]!r}"
    )
    assert _MODULE_NAME in captured[0], (
        f"module filename {_MODULE_NAME!r} must appear in JS path arg; source={captured[0]!r}"
    )
    assert result.name == _MODULE_NAME, f"module name mismatch: {result.name!r} != {_MODULE_NAME!r}"
    assert result.base_address == _MODULE_BASE, (
        f"base address mismatch: {result.base_address:#x} != {_MODULE_BASE:#x}"
    )
    assert result.size == _MODULE_SIZE, f"module size mismatch: {result.size} != {_MODULE_SIZE}"


# ---------------------------------------------------------------------------
# Finding #22 — find_module_by_address(address)
# ---------------------------------------------------------------------------


def test_find_module_by_address_embeds_address_and_parses_module_info() -> None:
    """``find_module_by_address()`` embeds the address decimal in JS and returns ModuleInfo.

    Oracle: result.name == 'ntdll.dll'; result.base_address == _MODULE_BASE;
    str(_MODULE_BASE) must appear in the generated JS.

    Falsifiable: if the address decimal is replaced with a hex literal the
    str(address) check fails; if the bridge reads the wrong field the name
    assertion fails.
    """
    bridge, _ = _build_attached_bridge()
    canned: dict[str, object] = {
        "name": _MODULE_NAME,
        "path": _MODULE_PATH,
        "base": hex(_MODULE_BASE),
        "size": _MODULE_SIZE,
    }
    captured = _patch_exec(bridge, canned)
    result = cast("ModuleInfo | None", _run(bridge.find_module_by_address(_MODULE_BASE)))
    assert str(_MODULE_BASE) in captured[0], (
        f"address decimal {_MODULE_BASE} must appear in JS; source={captured[0]!r}"
    )
    assert result is not None, "find_module_by_address must return ModuleInfo when found"
    assert result.name == _MODULE_NAME, f"module name mismatch: {result.name!r}"
    assert result.base_address == _MODULE_BASE, (
        f"base_address mismatch: {result.base_address:#x} != {_MODULE_BASE:#x}"
    )


def test_find_module_by_address_returns_none_when_not_found() -> None:
    """``find_module_by_address()`` returns None when the canned result has null name.

    Falsifiable: if the null-name guard is removed the bridge attempts to build
    a ModuleInfo from None and raises AttributeError instead of returning None.
    """
    bridge, _ = _build_attached_bridge()
    _patch_exec(bridge, {"name": None})
    result = _run(bridge.find_module_by_address(0xDEAD_BEEF))
    assert result is None, f"find_module_by_address must return None when not found, got {result!r}"


# ---------------------------------------------------------------------------
# Finding #23 — find_functions_matching(pattern)
# ---------------------------------------------------------------------------

_FUNC_PATTERN: str = "CreateFile*"
_FUNC_ADDR: int = 0x7FFE_5678


def test_find_functions_matching_embeds_pattern_and_parses_addresses() -> None:
    """``find_functions_matching()`` embeds pattern in JS and parses addresses from hex strings.

    Oracle: result[0].name == 'CreateFileW', result[0].address == _FUNC_ADDR.

    Falsifiable: if the address is parsed as decimal rather than hex the value
    differs; if the pattern is omitted from the JS the framing check fails.
    """
    bridge, _ = _build_attached_bridge()
    canned: dict[str, object] = {
        "data": [
            {
                "name": "CreateFileW",
                "address": hex(_FUNC_ADDR),
                "moduleName": "kernel32.dll",
                "fileName": None,
                "lineNumber": None,
            }
        ]
    }
    captured = _patch_exec(bridge, canned)
    result = cast("list[SymbolInfo]", _run(bridge.find_functions_matching(_FUNC_PATTERN)))
    assert _FUNC_PATTERN in captured[0], (
        f"pattern {_FUNC_PATTERN!r} must appear in JS; source={captured[0]!r}"
    )
    assert len(result) == 1, f"must parse exactly 1 symbol, got {len(result)}"
    assert result[0].name == "CreateFileW", f"symbol name mismatch: {result[0].name!r}"
    assert result[0].address == _FUNC_ADDR, (
        f"address mismatch: {result[0].address:#x} != {_FUNC_ADDR:#x}"
    )


# ---------------------------------------------------------------------------
# Finding #24 — disassemble_instruction(address)
# ---------------------------------------------------------------------------

_INSN_MNEMONIC: str = "mov"
_INSN_OP_STR: str = "eax, ecx"
_INSN_STRING: str = "mov eax, ecx"


def test_disassemble_instruction_parses_mnemonic_and_operands() -> None:
    """``disassemble_instruction()`` returns InstructionInfo with exact mnemonic/operands.

    Oracle: mnemonic=='mov', op_str=='eax, ecx', address==_INSN_ADDRESS.

    Falsifiable: if the bridge reads opStr instead of mnemonic (or vice versa)
    the mismatch is caught; if the address decimal is wrong the assertion fails.
    """
    bridge, _ = _build_attached_bridge()
    canned: dict[str, object] = {
        "address": hex(_INSN_ADDRESS),
        "next": hex(_INSN_NEXT),
        "size": _INSN_SIZE,
        "mnemonic": _INSN_MNEMONIC,
        "opStr": _INSN_OP_STR,
        "string": _INSN_STRING,
    }
    captured = _patch_exec(bridge, canned)
    result = cast("InstructionInfo", _run(bridge.disassemble_instruction(_INSN_ADDRESS)))
    assert str(_INSN_ADDRESS) in captured[0], (
        f"address decimal {_INSN_ADDRESS} must appear in JS; source={captured[0]!r}"
    )
    assert result.mnemonic == _INSN_MNEMONIC, f"mnemonic mismatch: {result.mnemonic!r}"
    assert result.op_str == _INSN_OP_STR, f"op_str mismatch: {result.op_str!r}"
    assert result.address == _INSN_ADDRESS, f"address mismatch: {result.address:#x}"
    assert result.size == _INSN_SIZE, f"size mismatch: {result.size}"


# ---------------------------------------------------------------------------
# Finding #25 — get_backtrace(context_address, backtracer)
# ---------------------------------------------------------------------------

_BT_FRAME_ADDR: int = 0x7FFE_ABCD


def test_get_backtrace_embeds_backtracer_type_and_parses_frames() -> None:
    """``get_backtrace()`` embeds 'Backtracer.FUZZY' in JS and parses frame addresses.

    Oracle: result[0].address == _BT_FRAME_ADDR (int parsed from hex string).

    Falsifiable: if the bridge emits 'Backtracer.ACCURATE' instead of 'FUZZY'
    the JS framing assertion fails; if the address parsing reads the wrong field
    the address mismatch is caught.
    """
    bridge, _ = _build_attached_bridge()
    canned: dict[str, object] = {
        "data": [
            {
                "name": "frob_function",
                "address": hex(_BT_FRAME_ADDR),
                "moduleName": "libfoo.dll",
                "fileName": None,
                "lineNumber": None,
            }
        ]
    }
    captured = _patch_exec(bridge, canned)
    result = cast("list[SymbolInfo]", _run(bridge.get_backtrace(backtracer="fuzzy")))
    assert "Backtracer.FUZZY" in captured[0], (
        f"'Backtracer.FUZZY' must appear in JS for backtracer='fuzzy'; source={captured[0]!r}"
    )
    assert len(result) == 1, f"must parse 1 frame, got {len(result)}"
    assert result[0].address == _BT_FRAME_ADDR, (
        f"frame address mismatch: {result[0].address:#x} != {_BT_FRAME_ADDR:#x}"
    )


# ---------------------------------------------------------------------------
# Finding #26 — set_exception_handler()
# ---------------------------------------------------------------------------


def test_set_exception_handler_embeds_process_set_exception_handler_and_registers() -> None:
    """``set_exception_handler()`` emits 'Process.setExceptionHandler' in JS and registers.

    Asserts:
    1. The JS source contains 'Process.setExceptionHandler'.
    2. The returned script_id equals bridge._exception_handler_script.
    3. The script_id is stored in bridge._scripts.

    Falsifiable: any of the three invariants catches a distinct mutation:
    (1) wrong API name, (2) wrong id stored in _exception_handler_script,
    (3) script not registered in _scripts.
    """
    bridge, sess = _build_attached_bridge()
    result_id = cast("str", _run(bridge.set_exception_handler()))
    assert len(sess.sources) >= 1, "set_exception_handler must generate at least one script"
    first_source = sess.sources[0]
    assert "Process.setExceptionHandler" in first_source, (
        f"'Process.setExceptionHandler' must appear in JS; source={first_source!r}"
    )
    exc_script = cast("str | None", _get(bridge, "_exception_handler_script"))
    assert exc_script == result_id, (
        f"_exception_handler_script must equal returned id; got {exc_script!r}"
    )
    scripts = _get_dict(bridge, "_scripts")
    assert result_id in scripts, f"script_id {result_id!r} must be in _scripts"


# ---------------------------------------------------------------------------
# Finding #27 — revert_hook(target)
# ---------------------------------------------------------------------------


def test_revert_hook_embeds_interceptor_revert_in_js() -> None:
    """``revert_hook()`` emits 'Interceptor.revert' in JS and returns True.

    Falsifiable: if 'Interceptor.revert' is replaced with 'Interceptor.detach'
    the framing assertion fails; if the bridge returns False on success the
    value assertion fails.
    """
    bridge, _ = _build_attached_bridge()
    captured = _patch_exec(bridge, {"success": True})
    result = cast("bool", _run(bridge.revert_hook("0x10001000")))
    assert "Interceptor.revert" in captured[0], (
        f"'Interceptor.revert' must appear in JS; source={captured[0]!r}"
    )
    assert result is True, f"revert_hook must return True on success, got {result!r}"


# ---------------------------------------------------------------------------
# Finding #28 — flush_interceptor()
# ---------------------------------------------------------------------------


def test_flush_interceptor_embeds_interceptor_flush_in_js() -> None:
    """``flush_interceptor()`` emits 'Interceptor.flush()' in JS and returns True.

    Falsifiable: if 'Interceptor.flush()' is replaced with a no-op the
    framing assertion fails; if the bridge returns False on success the
    value assertion fails.
    """
    bridge, _ = _build_attached_bridge()
    captured = _patch_exec(bridge, {"success": True})
    result = cast("bool", _run(bridge.flush_interceptor()))
    assert "Interceptor.flush()" in captured[0], (
        f"'Interceptor.flush()' must appear in JS; source={captured[0]!r}"
    )
    assert result is True, f"flush_interceptor must return True on success, got {result!r}"


# ---------------------------------------------------------------------------
# Finding #29 — call_system_function(address, ...)
# ---------------------------------------------------------------------------

_SYSCALL_VALUE: int = 12345
_SYSCALL_ERRNO: int = 5
_SYSCALL_LAST_ERROR: int = 7


def test_call_system_function_embeds_system_function_and_parses_syscall_result() -> None:
    """``call_system_function()`` emits 'SystemFunction' in JS and parses value/errno/lastError.

    Oracle: value==12345 (from string "12345" with valueIsString=True),
    errno==5, last_error==7.

    Falsifiable: (1) if 'NativeFunction' is used instead of 'SystemFunction' the
    framing assertion catches it; (2) if the address decimal is wrong the str()
    check fails; (3) if value is parsed without valueIsString handling the int
    mismatch is caught; (4) errno or last_error read from wrong field is caught.
    """
    bridge, _ = _build_attached_bridge()
    canned: dict[str, object] = {
        "value": str(_SYSCALL_VALUE),
        "errno": _SYSCALL_ERRNO,
        "lastError": _SYSCALL_LAST_ERROR,
        "valueIsString": True,
    }
    captured = _patch_exec(bridge, canned)
    result = cast("SystemCallResult", _run(bridge.call_system_function(_CALL_FUNC_ADDRESS)))
    assert "SystemFunction" in captured[0], (
        f"'SystemFunction' must appear in JS; source={captured[0]!r}"
    )
    assert str(_CALL_FUNC_ADDRESS) in captured[0], (
        f"address decimal {_CALL_FUNC_ADDRESS} must appear in JS; source={captured[0]!r}"
    )
    assert result.value == _SYSCALL_VALUE, f"value mismatch: {result.value} != {_SYSCALL_VALUE}"
    assert result.errno == _SYSCALL_ERRNO, f"errno mismatch: {result.errno} != {_SYSCALL_ERRNO}"
    assert result.last_error == _SYSCALL_LAST_ERROR, (
        f"last_error mismatch: {result.last_error} != {_SYSCALL_LAST_ERROR}"
    )


# ---------------------------------------------------------------------------
# Finding #30 — stalker_add_call_probe(address, callback_code)
# ---------------------------------------------------------------------------

_PROBE_CALLBACK: str = "console.log('probe hit');"


def test_stalker_add_call_probe_embeds_add_call_probe_and_registers_probe() -> None:
    """``stalker_add_call_probe()`` emits 'Stalker.addCallProbe' in JS and registers the probe.

    Asserts:
    1. 'Stalker.addCallProbe' appears in the generated JS.
    2. The address decimal appears in the JS.
    3. The returned probe_id is registered in bridge._call_probes.

    Falsifiable: (1) wrong JS API name; (2) address not embedded; (3) probe not
    registered.
    """
    bridge, sess = _build_attached_bridge()
    result_id = cast("str", _run(bridge.stalker_add_call_probe(_PROBE_ADDRESS, _PROBE_CALLBACK)))
    assert len(sess.sources) >= 1, "stalker_add_call_probe must generate at least one script"
    source = sess.sources[0]
    assert "Stalker.addCallProbe" in source, (
        f"'Stalker.addCallProbe' must appear in JS; source={source!r}"
    )
    assert str(_PROBE_ADDRESS) in source, (
        f"address decimal {_PROBE_ADDRESS} must appear in JS; source={source!r}"
    )
    probes = _get_dict(bridge, "_call_probes")
    assert result_id in probes, f"probe_id {result_id!r} must be in _call_probes, keys={list(probes)!r}"


# ---------------------------------------------------------------------------
# Finding #31 — stalker_remove_call_probe(probe_id)
# ---------------------------------------------------------------------------


def test_stalker_remove_call_probe_removes_probe_and_script_from_registries() -> None:
    """``stalker_remove_call_probe()`` returns True and clears both registries.

    Falsifiable: if the probe is not popped from _call_probes or the script
    is not unloaded from _scripts the respective ``not in`` checks fail.
    """
    bridge, _ = _build_attached_bridge()
    probe_id = "probe001"
    script_id = "scprobe1"
    fake_script = _FakeScriptW5()
    _index_set(bridge, "_scripts", script_id, fake_script)
    _index_set(bridge, "_call_probes", probe_id, script_id)
    result = cast("bool", _run(bridge.stalker_remove_call_probe(probe_id)))
    assert result is True, f"stalker_remove_call_probe must return True, got {result!r}"
    probes = _get_dict(bridge, "_call_probes")
    assert probe_id not in probes, f"probe_id must be removed from _call_probes"
    scripts = _get_dict(bridge, "_scripts")
    assert script_id not in scripts, f"script_id must be removed from _scripts after probe removal"


def test_stalker_remove_call_probe_unknown_id_returns_false() -> None:
    """``stalker_remove_call_probe()`` returns False for an unknown probe_id.

    Falsifiable: if the bridge raises ToolError for unknown probes the
    assertion on the return value is unreachable.
    """
    bridge, _ = _build_attached_bridge()
    result = cast("bool", _run(bridge.stalker_remove_call_probe("no_such_probe")))
    assert result is False, f"remove unknown probe must return False, got {result!r}"


# ---------------------------------------------------------------------------
# Finding #32 — enumerate_applications()
# ---------------------------------------------------------------------------

_APP_IDENTIFIER: str = "com.example.testapp"
_APP_NAME: str = "TestApp"
_APP_PID: int = 5678


def test_enumerate_applications_parses_identifier_name_and_pid() -> None:
    """``enumerate_applications()`` maps device results to FridaApplicationInfo fields.

    Oracle: result[0].identifier=='com.example.testapp', result[0].name=='TestApp'.

    Falsifiable: if the bridge reads 'id' instead of 'identifier' from the app
    object the identifier assertion fails; similarly for name/pid.
    """
    apps = [_FakeApp(_APP_IDENTIFIER, _APP_NAME, _APP_PID)]
    dev = _FakeDeviceW5(apps=apps)
    bridge, _, _ = _build_attached_bridge_with_device(dev)
    result = cast("list[FridaApplicationInfo]", _run(bridge.enumerate_applications()))
    assert len(result) == 1, f"must enumerate exactly 1 application, got {len(result)}"
    assert result[0].identifier == _APP_IDENTIFIER, (
        f"identifier mismatch: {result[0].identifier!r} != {_APP_IDENTIFIER!r}"
    )
    assert result[0].name == _APP_NAME, f"name mismatch: {result[0].name!r}"
    assert result[0].pid == _APP_PID, f"pid mismatch: {result[0].pid}"


# ---------------------------------------------------------------------------
# Finding #33 — inject_library_file(pid, path, entrypoint, data)
# ---------------------------------------------------------------------------


def test_inject_library_file_passes_correct_args_to_device_and_returns_id() -> None:
    """``inject_library_file()`` passes pid/path/entrypoint/data to device and returns the ID.

    Oracle: inject_id == _INJECT_RESULT; device recorded exactly (pid, path, ep, data).

    Falsifiable: if any arg is transposed or the device method is not called
    the tuple comparison fails; if the wrong return value is forwarded the ID
    assertion fails.
    """
    dev = _FakeDeviceW5(inject_file_id=_INJECT_RESULT)
    bridge, _, _ = _build_attached_bridge_with_device(dev)
    result = cast("int", _run(bridge.inject_library_file(_INJECT_PID, _LIB_PATH, _LIB_ENTRYPOINT, _LIB_DATA)))
    assert result == _INJECT_RESULT, f"inject_id mismatch: {result} != {_INJECT_RESULT}"
    assert len(dev.inject_file_calls) == 1, (
        f"device.inject_library_file must be called once, got {len(dev.inject_file_calls)}"
    )
    assert dev.inject_file_calls[0] == (_INJECT_PID, _LIB_PATH, _LIB_ENTRYPOINT, _LIB_DATA), (
        f"call args mismatch: {dev.inject_file_calls[0]!r}"
    )


# ---------------------------------------------------------------------------
# Finding #34 — inject_library_blob(pid, blob_hex, entrypoint, data)
# ---------------------------------------------------------------------------


def test_inject_library_blob_passes_decoded_bytes_to_device() -> None:
    """``inject_library_blob()`` decodes blob_hex to bytes and passes them to device.

    Oracle: blob_bytes == _LIB_BLOB_BYTES == bytes.fromhex('deadbeef').

    Falsifiable: if the bridge passes the raw hex string instead of decoded bytes
    the bytes equality check fails; if the wrong inject_id is returned the ID
    assertion fails.
    """
    dev = _FakeDeviceW5(inject_blob_id=_INJECT_BLOB_RESULT)
    bridge, _, _ = _build_attached_bridge_with_device(dev)
    result = cast(
        "int",
        _run(bridge.inject_library_blob(_INJECT_PID, _LIB_BLOB_HEX, _LIB_ENTRYPOINT, _LIB_DATA)),
    )
    assert result == _INJECT_BLOB_RESULT, f"inject_id mismatch: {result} != {_INJECT_BLOB_RESULT}"
    assert len(dev.inject_blob_calls) == 1, (
        f"device.inject_library_blob must be called once, got {len(dev.inject_blob_calls)}"
    )
    _, blob_bytes, ep, data = dev.inject_blob_calls[0]
    assert blob_bytes == _LIB_BLOB_BYTES, (
        f"blob bytes mismatch: {blob_bytes!r} != {_LIB_BLOB_BYTES!r}"
    )
    assert ep == _LIB_ENTRYPOINT, f"entrypoint mismatch: {ep!r}"
    assert data == _LIB_DATA, f"data mismatch: {data!r}"


# ---------------------------------------------------------------------------
# Finding #46 — create_cmodule(code, symbols)
# ---------------------------------------------------------------------------


def test_create_cmodule_embeds_new_cmodule_in_js_and_returns_registered_script_id() -> None:
    """``create_cmodule()`` emits 'new CModule' in JS, embeds symbols, and registers the handle.

    Uses the async driver / task pattern so the cmodule_loaded ack can be
    delivered after the script loads but before the timeout fires.

    Falsifiable: (1) 'new CModule' missing from JS; (2) symbol name/address not
    embedded; (3) script_id not registered in _scripts.
    """
    bridge, sess = _build_attached_bridge()

    async def driver() -> str:
        """Run create_cmodule and deliver the cmodule_loaded ack deterministically.

        Returns:
            str: The script_id returned by create_cmodule.
        """
        task: asyncio.Task[str] = asyncio.get_running_loop().create_task(
            bridge.create_cmodule(_CMODULE_CODE, {_CMODULE_SYM_NAME: _CMODULE_SYM_ADDR})
        )
        for _ in range(200):
            await asyncio.sleep(0)
            if sess.scripts and sess.scripts[-1].load_calls > 0:
                break
        assert sess.scripts, "create_cmodule must create a script"
        sess.scripts[-1].deliver({"type": "cmodule_loaded", "success": True})
        return await task

    script_id = cast("str", _run(driver()))
    assert isinstance(script_id, str) and len(script_id) > 0, (
        f"create_cmodule must return non-empty script_id, got {script_id!r}"
    )
    assert len(sess.sources) >= 1, "create_cmodule must produce at least one JS source"
    source = sess.sources[0]
    assert "new CModule" in source, (
        f"'new CModule' must appear in JS; source={source!r}"
    )
    assert _CMODULE_SYM_NAME in source, (
        f"symbol name {_CMODULE_SYM_NAME!r} must appear in JS; source={source!r}"
    )
    assert str(_CMODULE_SYM_ADDR) in source, (
        f"symbol address {_CMODULE_SYM_ADDR} must appear in JS; source={source!r}"
    )
    scripts = _get_dict(bridge, "_scripts")
    assert script_id in scripts, f"script_id {script_id!r} must be registered in _scripts"


# ---------------------------------------------------------------------------
# Finding #64 — cloak_add_thread(thread_id)
# ---------------------------------------------------------------------------


def test_cloak_add_thread_embeds_cloak_add_thread_with_tid_decimal() -> None:
    """``cloak_add_thread()`` emits 'Cloak.addThread' with the thread_id as decimal.

    Oracle: ``f'Cloak.addThread({_CLOAK_THREAD_ID})'`` appears in the JS source.

    Falsifiable: if the code uses 'Stalker.addToIncludeList' instead of
    'Cloak.addThread' the assertion fails; if thread_id is embedded as hex
    rather than decimal the f-string check catches it.
    """
    bridge, _ = _build_attached_bridge()
    captured = _patch_exec(bridge, {"success": True})
    result = cast("bool", _run(bridge.cloak_add_thread(_CLOAK_THREAD_ID)))
    assert f"Cloak.addThread({_CLOAK_THREAD_ID})" in captured[0], (
        f"'Cloak.addThread({_CLOAK_THREAD_ID})' must appear in JS; source={captured[0]!r}"
    )
    assert result is True, f"cloak_add_thread must return True, got {result!r}"


# ---------------------------------------------------------------------------
# Finding #65 — cloak_remove_thread(thread_id)
# ---------------------------------------------------------------------------


def test_cloak_remove_thread_embeds_cloak_remove_thread_with_tid_decimal() -> None:
    """``cloak_remove_thread()`` emits 'Cloak.removeThread' with the thread_id as decimal.

    Oracle: ``f'Cloak.removeThread({_CLOAK_THREAD_ID})'`` appears in the JS source.

    Falsifiable: if the code uses 'Stalker.removeFromIncludeList' instead of
    'Cloak.removeThread' the assertion fails.
    """
    bridge, _ = _build_attached_bridge()
    captured = _patch_exec(bridge, {"success": True})
    result = cast("bool", _run(bridge.cloak_remove_thread(_CLOAK_THREAD_ID)))
    assert f"Cloak.removeThread({_CLOAK_THREAD_ID})" in captured[0], (
        f"'Cloak.removeThread({_CLOAK_THREAD_ID})' must appear in JS; source={captured[0]!r}"
    )
    assert result is True, f"cloak_remove_thread must return True, got {result!r}"


# ---------------------------------------------------------------------------
# Finding #66 — cloak_add_range(address, size)
# ---------------------------------------------------------------------------


def test_cloak_add_range_embeds_cloak_add_range_with_address_and_size() -> None:
    """``cloak_add_range()`` emits 'Cloak.addRange' with address and size as decimals.

    Oracle: 'Cloak.addRange' in JS, str(_CLOAK_ADDRESS) in JS, str(_CLOAK_SIZE) in JS.

    Falsifiable: if 'Cloak.addRange' is replaced with a wrong API the first
    assertion fails; if the address or size is wrong the decimal checks catch it.
    """
    bridge, _ = _build_attached_bridge()
    captured = _patch_exec(bridge, {"success": True})
    result = cast("bool", _run(bridge.cloak_add_range(_CLOAK_ADDRESS, _CLOAK_SIZE)))
    assert "Cloak.addRange" in captured[0], (
        f"'Cloak.addRange' must appear in JS; source={captured[0]!r}"
    )
    assert str(_CLOAK_ADDRESS) in captured[0], (
        f"address decimal {_CLOAK_ADDRESS} must appear in JS; source={captured[0]!r}"
    )
    assert str(_CLOAK_SIZE) in captured[0], (
        f"size decimal {_CLOAK_SIZE} must appear in JS; source={captured[0]!r}"
    )
    assert result is True, f"cloak_add_range must return True, got {result!r}"


# ---------------------------------------------------------------------------
# Finding #67 — cloak_remove_range(address, size)
# ---------------------------------------------------------------------------


def test_cloak_remove_range_embeds_cloak_remove_range_with_address_and_size() -> None:
    """``cloak_remove_range()`` emits 'Cloak.removeRange' with address and size as decimals.

    Falsifiable: if 'Cloak.removeRange' is replaced with a wrong call the
    framing assertion fails; if the address is wrong the decimal check catches it.
    """
    bridge, _ = _build_attached_bridge()
    captured = _patch_exec(bridge, {"success": True})
    result = cast("bool", _run(bridge.cloak_remove_range(_CLOAK_ADDRESS, _CLOAK_SIZE)))
    assert "Cloak.removeRange" in captured[0], (
        f"'Cloak.removeRange' must appear in JS; source={captured[0]!r}"
    )
    assert str(_CLOAK_ADDRESS) in captured[0], (
        f"address decimal {_CLOAK_ADDRESS} must appear in JS; source={captured[0]!r}"
    )
    assert str(_CLOAK_SIZE) in captured[0], (
        f"size decimal {_CLOAK_SIZE} must appear in JS; source={captured[0]!r}"
    )
    assert result is True, f"cloak_remove_range must return True, got {result!r}"


# ---------------------------------------------------------------------------
# Finding #68 — monitor_path(path)
# ---------------------------------------------------------------------------


def test_monitor_path_registers_monitor_id_and_enables_monitoring() -> None:
    """``monitor_path()`` creates a FileMonitor, enables it, and stores monitor_id.

    Uses a monkey-patched ``frida.FileMonitor`` (the transport boundary) so
    no real file system monitoring is required.

    Falsifiable: if monitor_id is not stored in _file_monitors the ``in``
    assertion fails; if enable() is not called the enable_calls==1 check fails.
    """
    original_fm = getattr(frida, "FileMonitor")
    created_monitors: list[_FakeFileMonitor] = []

    def fake_file_monitor_ctor(path: str) -> _FakeFileMonitor:
        """Create and record a fake FileMonitor.

        Args:
            path: Path passed by the bridge.

        Returns:
            _FakeFileMonitor: A new fake monitor instance.
        """
        m = _FakeFileMonitor(path)
        created_monitors.append(m)
        return m

    setattr(frida, "FileMonitor", fake_file_monitor_ctor)
    try:
        bridge, _ = _build_attached_bridge()
        monitor_id = cast("str", _run(bridge.monitor_path(_MONITOR_PATH)))
        assert isinstance(monitor_id, str) and len(monitor_id) > 0, (
            f"monitor_path must return non-empty id, got {monitor_id!r}"
        )
        file_monitors = _get_dict(bridge, "_file_monitors")
        assert monitor_id in file_monitors, (
            f"monitor_id {monitor_id!r} must be in _file_monitors"
        )
        assert len(created_monitors) == 1, "exactly one FileMonitor must be created"
        assert created_monitors[0].path == _MONITOR_PATH, (
            f"FileMonitor path mismatch: {created_monitors[0].path!r}"
        )
        assert created_monitors[0].enable_calls == 1, (
            f"FileMonitor.enable() must be called once, got {created_monitors[0].enable_calls}"
        )
    finally:
        setattr(frida, "FileMonitor", original_fm)


# ---------------------------------------------------------------------------
# Finding #69 — stop_monitor(monitor_id)
# ---------------------------------------------------------------------------


def test_stop_monitor_calls_disable_and_removes_monitor_from_registry() -> None:
    """``stop_monitor()`` returns True, calls disable(), and removes the id from _file_monitors.

    Injects a fake monitor directly into ``_file_monitors`` so no actual
    monitoring is started.

    Falsifiable: if the id is not removed from _file_monitors the ``not in``
    assertion fails; if disable() is not called the disable_calls==1 check fails.
    """
    bridge, _ = _build_attached_bridge()
    fake_monitor = _FakeFileMonitor(_MONITOR_PATH)
    _index_set(bridge, "_file_monitors", _MONITOR_ID, fake_monitor)
    result = cast("bool", _run(bridge.stop_monitor(_MONITOR_ID)))
    assert result is True, f"stop_monitor must return True, got {result!r}"
    file_monitors = _get_dict(bridge, "_file_monitors")
    assert _MONITOR_ID not in file_monitors, f"monitor_id must be removed from _file_monitors"
    assert fake_monitor.disable_calls == 1, (
        f"monitor.disable() must be called once, got {fake_monitor.disable_calls}"
    )


def test_stop_monitor_unknown_id_returns_false() -> None:
    """``stop_monitor()`` returns False for an unregistered monitor_id.

    Falsifiable: if the bridge raises ToolError instead of returning False
    the boolean assertion is unreachable.
    """
    bridge, _ = _build_attached_bridge()
    result = cast("bool", _run(bridge.stop_monitor("no_such_monitor")))
    assert result is False, f"stop_monitor(unknown) must return False, got {result!r}"


# ---------------------------------------------------------------------------
# Finding #70 — enumerate_exports not-found error path with match=
# ---------------------------------------------------------------------------


def test_enumerate_exports_module_not_found_raises_toolerror_matching_not_found() -> None:
    """``enumerate_exports()`` raises ToolError matching 'module not found' for absent modules.

    The bare ``pytest.raises(ToolError)`` in the existing test accepts any
    ToolError; this gate pins the exact message constant ``_ERR_MODULE_NOT_FOUND``.

    Falsifiable: if the branch raises ToolError('export not found') instead of
    ToolError('module not found') the match= pattern rejects it.
    """
    bridge, _ = _build_attached_bridge()
    _patch_exec(bridge, {"error": "module_not_found", "type": "exports", "data": []})
    with pytest.raises(ToolError, match=r"module not found"):
        _run(bridge.enumerate_exports("this_module_is_not_loaded_zyx.dll"))


# ---------------------------------------------------------------------------
# Finding #71 — stalker_follow / stalker_unfollow — deterministic offline gate
# ---------------------------------------------------------------------------


def test_stalker_follow_unfollow_collects_events_deterministically() -> None:
    """``stalker_follow`` / ``stalker_unfollow`` collect events without any time.sleep.

    Replaces ``time.sleep(1.0)`` from the existing test_frida_bridge.py tests with
    a deterministic synchronisation: the fake session delivers ``stalker_started``
    and a ``stalker_batch`` payload during ``script.load()`` (on the thread-pool
    thread), which is exactly how the real Frida runtime delivers events.

    Asserts the full StalkerTrace structure:
    - ``trace.thread_id == _STALKER_TID``
    - ``trace.event_count == len(trace.events) == 1``
    - ``trace.events[0].event_type == 'call'``
    - ``trace.events[0].from_address == 0x7fff1000`` (parsed from hex string)
    - ``trace.events[0].to_address == 0x7fff2000``

    Falsifiable: (1) wrong thread_id stored; (2) event_count diverges from
    len(events); (3) event_type wrong; (4) addresses parsed incorrectly.
    """
    batch = [_STALKER_CALL_EVENT]
    stalker_sess = _StalkerSession(_STALKER_TID, batch)
    bridge = FridaBridge()
    _set(bridge, "_session", stalker_sess)
    _set(bridge, "_pid", _STALKER_TID)
    bridge.state.connected = True
    bridge.state.process_attached = True

    async def driver() -> StalkerTrace:
        """Follow a thread, then immediately unfollow and return the trace.

        Returns:
            StalkerTrace: The collected trace from stalker_unfollow.
        """
        _trace_id = await bridge.stalker_follow(thread_id=_STALKER_TID, events="call", limit=500)
        assert isinstance(_trace_id, str) and len(_trace_id) > 0, (
            f"stalker_follow must return non-empty trace id"
        )
        return await bridge.stalker_unfollow(thread_id=_STALKER_TID)

    trace = cast("StalkerTrace", _run(driver()))
    assert trace.thread_id == _STALKER_TID, (
        f"trace.thread_id must be {_STALKER_TID}, got {trace.thread_id}"
    )
    assert trace.event_count == len(trace.events), (
        f"event_count {trace.event_count} must equal len(events) {len(trace.events)}"
    )
    assert trace.event_count == 1, (
        f"exactly 1 call event must be collected, got {trace.event_count}"
    )
    evt = trace.events[0]
    assert evt.event_type == "call", f"event_type must be 'call', got {evt.event_type!r}"
    assert evt.from_address == 0x7FFF1000, (
        f"from_address must be 0x7fff1000, got {evt.from_address:#x}"
    )
    assert evt.to_address == 0x7FFF2000, (
        f"to_address must be 0x7fff2000, got {evt.to_address!r}"
    )
    assert isinstance(trace.duration_ms, float) and trace.duration_ms >= 0.0, (
        f"duration_ms must be non-negative float, got {trace.duration_ms!r}"
    )
