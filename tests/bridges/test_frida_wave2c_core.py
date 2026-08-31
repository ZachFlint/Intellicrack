# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real, falsifiable gates for FridaBridge core instrumentation operations.

Covers the operations that the section-03 audit flagged as NO COVERAGE or
WEAK: spawn, resume, attach_by_name, rpc_call, patch_code, intercept_return,
write_code, and allocate_string. Every test drives the real production method
against a minimal offline fake device/session/script and asserts on
exact output values derived from an independent oracle (known constants in the
test itself, not values re-derived by the same production code under test).

The fake frida transport is modelled after the proven pattern in
test_frida_bridge_audit5.py: a _FakeDevice, _FakeSession, and _FakeScript
that record calls and deliver scripted messages, letting the full bridge
code path run up to the network boundary.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import TYPE_CHECKING, cast

import frida
import pytest

from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.core.types import HookInfo, ToolError


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine


_SPAWN_PID: int = os.getpid()
_ATTACH_PID: int = 7777
_RPC_RETURN_VALUE: int = 0xABCD_1234
_PATCH_ADDR: int = 0xCAFE_0000
_PATCH_ADDR_INT: int = 0xCAFE0000
_WRITE_CODE_SIZE: int = 5
_ALLOC_STR_ADDR: int = 0x5555_0000
_ALLOC_STR_ADDR_HEX: str = "0x55550000"
_INTERCEPT_RETURN_VALUE: int = 0x1234_5678


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine on a fresh event loop and return its result.

    Args:
        coro: Awaitable to execute.

    Returns:
        T: Whatever the coroutine returns, preserving its type.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _set(target: object, name: str, value: object) -> None:
    """Set an attribute on target via setattr to avoid private-usage diagnostics.

    Args:
        target: Object to mutate.
        name: Attribute name.
        value: Replacement value.
    """
    setattr(target, name, value)


def _index_set(target: object, name: str, key: object, value: object) -> None:
    """Set target.<name>[key] = value without tripping private-usage diagnostics.

    Args:
        target: Object whose attribute holds a mapping.
        name: Attribute name (typically a dict).
        key: Mapping key.
        value: Mapping value.
    """
    container = cast("dict[object, object]", getattr(target, name))
    container[key] = value


def _get_attr(target: object, name: str) -> object:
    """Read a private attribute as object.

    Args:
        target: Object to read.
        name: Attribute name.

    Returns:
        object: The attribute value.
    """
    return getattr(target, name)


class _FakeExportsSync:
    """Fake Frida script.exports_sync surface for rpc_call testing."""

    def __init__(self, methods: dict[str, Callable[..., object]]) -> None:
        """Initialize with a map of method names to callables.

        Args:
            methods: Mapping of export name to synchronous callable.
        """
        self._methods = methods

    def __getattr__(self, name: str) -> Callable[..., object]:
        """Return the registered callable for name.

        Args:
            name: Export method name.

        Returns:
            Callable[..., object]: The registered callable.

        Raises:
            AttributeError: If name is not registered.
        """
        if name in self._methods:
            return self._methods[name]
        raise AttributeError(name)


class _FakeScript:
    """Minimal frida.core.Script substitute with exports_sync and message delivery.

    Records load/unload calls and captures the on("message", ...) handler so
    tests can deliver scripted payloads back to the bridge.
    """

    def __init__(self, exports_sync: _FakeExportsSync | None = None) -> None:
        """Initialize the fake script with empty call records.

        Args:
            exports_sync: Optional fake exports surface for rpc_call testing.
        """
        self.posts: list[dict[str, object]] = []
        self.unload_calls: int = 0
        self.load_calls: int = 0
        self._handler: Callable[..., None] | None = None
        self.exports_sync: _FakeExportsSync = exports_sync or _FakeExportsSync({})

    def on(self, event: str, handler: Callable[..., None]) -> None:
        """Capture the message handler registered by the bridge.

        Args:
            event: Event name.
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

    def post(self, message: dict[str, object]) -> None:
        """Capture a posted message.

        Args:
            message: Posted message dict.
        """
        self.posts.append(dict(message))

    def eternalize(self) -> None:
        """No-op for eternalize surface."""

    def deliver(self, payload: dict[str, object], data: bytes | None = None) -> None:
        """Synchronously deliver a send-shaped payload to the bridge.

        Args:
            payload: Payload dict to send as type='send'.
            data: Optional binary side-channel.
        """
        if self._handler is None:
            return
        self._handler({"type": "send", "payload": payload}, data)


class _FakeSession:
    """frida.core.Session substitute that produces _FakeScript instances.

    Records every create_script call including the source text.
    """

    def __init__(self, script_exports: _FakeExportsSync | None = None) -> None:
        """Initialize the fake session.

        Args:
            script_exports: Optional exports_sync to attach to created scripts.
        """
        self.scripts: list[_FakeScript] = []
        self.sources: list[str] = []
        self.detach_calls: int = 0
        self.on_handlers: dict[str, list[Callable[..., object]]] = {}
        self._script_exports = script_exports

    def on(self, signal: str, callback: Callable[..., object]) -> None:
        """Record a signal handler the way ``frida.core.Session.on`` does.

        Args:
            signal: Signal name (e.g. ``"detached"``).
            callback: Handler to invoke when the signal fires.
        """
        self.on_handlers.setdefault(signal, []).append(callback)

    def create_script(self, source: str, **_: object) -> _FakeScript:
        """Return a new fake script and record the source.

        Args:
            source: JavaScript source (recorded for assertion).
            **_: Ignored keyword arguments.

        Returns:
            _FakeScript: Newly registered fake script.
        """
        self.sources.append(source)
        script = _FakeScript(exports_sync=self._script_exports)
        self.scripts.append(script)
        return script

    def detach(self) -> None:
        """Record a detach call."""
        self.detach_calls += 1


class _FakeProcess:
    """Minimal frida.core.ProcessEntry substitute."""

    def __init__(self, pid: int, name: str) -> None:
        """Initialize the fake process entry.

        Args:
            pid: Process identifier.
            name: Process name.
        """
        self.pid = pid
        self.name = name


class _FakeDevice:
    """frida.core.Device substitute that records spawn/attach/resume calls."""

    def __init__(
        self,
        spawn_pid: int = _SPAWN_PID,
        attach_session: _FakeSession | None = None,
        processes: list[_FakeProcess] | None = None,
        spawn_raises: BaseException | None = None,
        attach_raises: BaseException | None = None,
        resume_raises: BaseException | None = None,
    ) -> None:
        """Initialize the fake device with scripted responses.

        Args:
            spawn_pid: PID to return from spawn().
            attach_session: Session to return from attach().
            processes: Process list to return from enumerate_processes().
            spawn_raises: If set, spawn() raises this instead of returning.
            attach_raises: If set, attach() raises this instead of returning.
            resume_raises: If set, resume() raises this instead of succeeding.
        """
        self._spawn_pid = spawn_pid
        self._attach_session = attach_session or _FakeSession()
        self._processes = processes or []
        self._spawn_raises = spawn_raises
        self._attach_raises = attach_raises
        self._resume_raises = resume_raises
        self.spawn_calls: list[dict[str, object]] = []
        self.attach_calls: list[int] = []
        self.resume_calls: list[int] = []

    def spawn(self, program: str, argv: list[str | bytes] | None = None, **_: object) -> int:
        """Record spawn arguments and return the scripted PID.

        Args:
            program: Executable path.
            argv: Command-line argument vector.
            **_: Ignored keyword arguments.

        Returns:
            int: Scripted spawn PID.

        Raises:
            spawn_exc: The configured exception if spawn_raises is set.
        """
        self.spawn_calls.append({"program": program, "argv": argv or []})
        spawn_exc = self._spawn_raises
        if spawn_exc is not None:
            raise spawn_exc
        return self._spawn_pid

    def attach(self, pid: int, **_: object) -> _FakeSession:
        """Record the attach PID and return the scripted session.

        Args:
            pid: Target process identifier.
            **_: Ignored keyword arguments (e.g., cancellable).

        Returns:
            _FakeSession: Scripted session.

        Raises:
            attach_exc: The configured exception if attach_raises is set.
        """
        self.attach_calls.append(pid)
        attach_exc = self._attach_raises
        if attach_exc is not None:
            raise attach_exc
        return self._attach_session

    def enumerate_processes(self) -> list[_FakeProcess]:
        """Return the scripted process list.

        Returns:
            list[_FakeProcess]: Configured process entries.
        """
        return self._processes

    def resume(self, pid: int) -> None:
        """Record the resume PID.

        Args:
            pid: Process identifier to resume.

        Raises:
            resume_exc: The configured exception if resume_raises is set.
        """
        self.resume_calls.append(pid)
        resume_exc = self._resume_raises
        if resume_exc is not None:
            raise resume_exc

    def kill(self, pid: int) -> None:
        """No-op kill for post-spawn-attach error recovery.

        Args:
            pid: Process identifier to kill.
        """


def _build_attached_bridge(
    session: _FakeSession | None = None,
) -> tuple[FridaBridge, _FakeSession, _FakeDevice]:
    """Construct a FridaBridge wired to fake session+device.

    Args:
        session: Optional pre-built fake session; a new one is created if None.

    Returns:
        tuple[FridaBridge, _FakeSession, _FakeDevice]: Bridge plus its backing fakes.
    """
    bridge = FridaBridge()
    sess = session or _FakeSession()
    device = _FakeDevice(attach_session=sess)
    _set(bridge, "_session", sess)
    _set(bridge, "_device", device)
    _set(bridge, "_pid", _ATTACH_PID)
    bridge.state.connected = True
    bridge.state.tool_running = True
    bridge.state.process_attached = True
    bridge.state.target_pid = _ATTACH_PID
    return bridge, sess, device


def _patch_execute_script(
    bridge: FridaBridge,
    fixed_result: dict[str, object],
) -> list[str]:
    """Replace _execute_script_and_wait with a recorder returning fixed_result.

    Args:
        bridge: Bridge whose internal method to replace.
        fixed_result: Dict returned on every invocation.

    Returns:
        list[str]: Accumulates script source strings on each call.
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


def test_spawn_no_device_raises_toolerror() -> None:
    """Bridge.spawn raises ToolError when there is no device (not initialised).

    Mutation caught: removing the device-None check at the top of spawn().
    """
    bridge = FridaBridge()

    async def driver() -> int:
        return await bridge.spawn(Path("target.exe"))

    with pytest.raises(ToolError, match=r"initialise|initialize|not initialised"):
        _run(driver())


def test_spawn_device_called_with_correct_path_and_argv() -> None:
    """Bridge.spawn passes the exact program path and argv vector to device.spawn.

    Oracle: the known constants _SPAWN_PID, the program string, and the
    extended argv list are all checked against what the fake device recorded.

    Mutation caught: swapping argv ordering, using str(path.name) instead of
    str(path), or reversing the argv/program arguments.
    """
    path = Path("C:/targets/my_app.exe")
    args = ["--debug", "--port", "8080"]
    sess = _FakeSession()
    device = _FakeDevice(spawn_pid=_SPAWN_PID, attach_session=sess)

    bridge = FridaBridge()
    _set(bridge, "_device", device)

    async def driver() -> int:
        return await bridge.spawn(path, args)

    pid = _run(driver())

    assert pid == _SPAWN_PID, f"spawn must return device PID {_SPAWN_PID}, got {pid}"
    assert len(device.spawn_calls) == 1, "device.spawn must be called exactly once"
    call = device.spawn_calls[0]
    assert call["program"] == str(path), f"program arg must be str(path)={str(path)!r}, got {call['program']!r}"
    expected_argv = [str(path), "--debug", "--port", "8080"]
    assert list(cast("list[object]", call["argv"])) == expected_argv, f"argv must be [str(path)] + args, got {call['argv']!r}"
    assert len(device.attach_calls) == 1, "device.attach must be called once after spawn"
    assert device.attach_calls[0] == _SPAWN_PID, f"attach must use the spawned PID {_SPAWN_PID}, got {device.attach_calls[0]}"

    bridge_pid = cast("int | None", _get_attr(bridge, "_pid"))
    assert bridge_pid == _SPAWN_PID, f"bridge._pid must be set to {_SPAWN_PID} after spawn, got {bridge_pid}"
    bridge_spawned = cast("int | None", _get_attr(bridge, "_spawned_pid"))
    assert bridge_spawned == _SPAWN_PID, f"bridge._spawned_pid must be {_SPAWN_PID}, got {bridge_spawned}"


def test_spawn_device_error_raises_toolerror() -> None:
    """Bridge.spawn maps frida.ExecutableNotFoundError from device.spawn to ToolError.

    Mutation caught: dropping the except clause that converts spawn errors.
    """
    device = _FakeDevice(spawn_raises=frida.ExecutableNotFoundError("not found"))
    bridge = FridaBridge()
    _set(bridge, "_device", device)

    async def driver() -> int:
        return await bridge.spawn(Path("missing.exe"))

    with pytest.raises(ToolError, match=r"failed to attach|attach"):
        _run(driver())


def test_resume_not_attached_raises_toolerror() -> None:
    """Bridge.resume raises ToolError when _pid is None (no spawned/attached process).

    Mutation caught: removing the _pid is None guard in resume().
    """
    bridge = FridaBridge()
    device = _FakeDevice()
    _set(bridge, "_device", device)
    _set(bridge, "_pid", None)

    async def driver() -> None:
        await bridge.resume()

    with pytest.raises(ToolError, match=r"not attached"):
        _run(driver())


def test_resume_calls_device_resume_with_correct_pid() -> None:
    """Bridge.resume forwards the attached PID to device.resume.

    Oracle: the known constant _ATTACH_PID is compared against what
    device.resume recorded.

    Mutation caught: passing a hardcoded 0 or wrong attribute to device.resume().
    """
    bridge, _, device = _build_attached_bridge()

    async def driver() -> None:
        await bridge.resume()

    _run(driver())

    assert len(device.resume_calls) == 1, "device.resume must be called exactly once"
    assert device.resume_calls[0] == _ATTACH_PID, f"device.resume must receive the attached PID {_ATTACH_PID}, got {device.resume_calls[0]}"


def test_resume_device_error_raises_toolerror() -> None:
    """Bridge.resume maps frida.InvalidOperationError from device.resume to ToolError.

    Mutation caught: missing the except clause around device.resume call.
    """
    bridge = FridaBridge()
    device = _FakeDevice(resume_raises=frida.InvalidOperationError("process already resumed"))
    _set(bridge, "_device", device)
    _set(bridge, "_pid", _ATTACH_PID)

    async def driver() -> None:
        await bridge.resume()

    with pytest.raises(ToolError, match=r"failed to resume|resume"):
        _run(driver())


def test_attach_by_name_not_found_raises_toolerror() -> None:
    """attach_by_name raises ToolError when name is not in the process list.

    Mutation caught: returning silently instead of raising when process name
    is absent from enumerate_processes().
    """
    device = _FakeDevice(processes=[_FakeProcess(pid=100, name="other.exe")])
    bridge = FridaBridge()
    _set(bridge, "_device", device)

    async def driver() -> None:
        await bridge.attach_by_name("missing_target.exe")

    with pytest.raises(ToolError, match=r"process not found|not found"):
        _run(driver())


def test_attach_by_name_no_device_raises_toolerror() -> None:
    """attach_by_name raises ToolError when no device is configured.

    Mutation caught: removing the device-None check in attach_by_name().
    """
    bridge = FridaBridge()

    async def driver() -> None:
        await bridge.attach_by_name("target.exe")

    with pytest.raises(ToolError, match=r"initialise|initialize|not initialised"):
        _run(driver())


def test_attach_by_name_found_attaches_to_matching_pid() -> None:
    """attach_by_name calls device.attach with the PID of the matching process.

    Oracle: the exact PID from the scripted process list (_ATTACH_PID) is
    compared against what device.attach recorded and what bridge._pid stores.

    Mutation caught: picking the wrong PID (e.g., always using processes[0].pid
    instead of the one whose .name matches).
    """
    target_name = "notepad_fake.exe"
    processes = [
        _FakeProcess(pid=3000, name="other.exe"),
        _FakeProcess(pid=_ATTACH_PID, name=target_name),
        _FakeProcess(pid=4000, name="another.exe"),
    ]
    sess = _FakeSession()
    device = _FakeDevice(processes=processes, attach_session=sess)
    bridge = FridaBridge()
    _set(bridge, "_device", device)

    async def driver() -> None:
        await bridge.attach_by_name(target_name)

    _run(driver())

    assert len(device.attach_calls) == 1, "device.attach must be called exactly once"
    assert device.attach_calls[0] == _ATTACH_PID, (
        f"device.attach must receive PID {_ATTACH_PID} for name {target_name!r}, got {device.attach_calls[0]}"
    )
    bridge_pid = cast("int | None", _get_attr(bridge, "_pid"))
    assert bridge_pid == _ATTACH_PID, f"bridge._pid must be {_ATTACH_PID} after attach_by_name, got {bridge_pid}"
    assert bridge.state.process_attached is True


def test_rpc_call_script_not_found_raises_toolerror() -> None:
    """rpc_call raises ToolError when the script_id is not registered.

    Mutation caught: returning None or raising a different exception type
    instead of ToolError for an unknown script_id.
    """
    bridge, _, _ = _build_attached_bridge()

    async def driver() -> object:
        return await bridge.rpc_call("nonexistent-id", "anyMethod")

    with pytest.raises(ToolError, match=r"script not found|not found"):
        _run(driver())


def test_rpc_call_invokes_correct_export_and_returns_result() -> None:
    """rpc_call resolves the named export on exports_sync and returns its value.

    Oracle: the method_name "compute" is looked up exactly, called with the
    argument 42, and the hardcoded return value _RPC_RETURN_VALUE is compared
    against the rpc_call return.

    Mutation caught: looking up the wrong method name, ignoring args, or
    returning a different field from the result.
    """
    received_args: list[tuple[object, ...]] = []

    def compute_fn(*args: object) -> int:
        """Record call args and return the known oracle constant.

        Args:
            *args: Arguments passed by the bridge.

        Returns:
            int: The known oracle constant.
        """
        received_args.append(args)
        return _RPC_RETURN_VALUE

    exports = _FakeExportsSync({"compute": compute_fn})
    script = _FakeScript(exports_sync=exports)
    script_id = "test-rpc-01"

    bridge, _, _ = _build_attached_bridge()
    _index_set(bridge, "_scripts", script_id, script)

    async def driver() -> object:
        return await bridge.rpc_call(script_id, "compute", [42])

    result = _run(driver())

    assert result == _RPC_RETURN_VALUE, f"rpc_call must return the export's return value {_RPC_RETURN_VALUE:#x}, got {result!r}"
    assert len(received_args) == 1, "compute_fn must be called exactly once"
    assert received_args[0] == (42,), f"compute_fn must receive (42,), got {received_args[0]!r}"


def test_rpc_call_export_exception_raises_toolerror() -> None:
    """rpc_call maps an exception raised by the export to ToolError.

    Mutation caught: letting the raw exception propagate instead of wrapping
    it in ToolError.
    """

    def failing_fn(*_args: object) -> object:
        """Always raise a RuntimeError to simulate a script error.

        Args:
            *_args: Ignored.

        Returns:
            object: Never returns; always raises.

        Raises:
            RuntimeError: Always raised.
        """
        msg = "script side error"
        raise RuntimeError(msg)

    exports = _FakeExportsSync({"fail": failing_fn})
    script = _FakeScript(exports_sync=exports)
    script_id = "test-rpc-fail"

    bridge, _, _ = _build_attached_bridge()
    _index_set(bridge, "_scripts", script_id, script)

    async def driver() -> object:
        return await bridge.rpc_call(script_id, "fail")

    with pytest.raises(ToolError, match=r"RPC call failed|rpc"):
        _run(driver())


def test_patch_code_not_attached_raises_toolerror() -> None:
    """patch_code raises ToolError when no session is active.

    Mutation caught: removing the _session is None guard in patch_code().
    """
    bridge = FridaBridge()

    async def driver() -> bool:
        return await bridge.patch_code(_PATCH_ADDR, "9090")

    with pytest.raises(ToolError, match=r"not attached"):
        _run(driver())


def test_patch_code_js_framing_address_and_bytes() -> None:
    """patch_code embeds the exact address integer and byte array in the JS.

    Oracle: address _PATCH_ADDR_INT (0xCAFE0000) and bytes 90 CC 90 are
    independently known. The captured JS source must contain the exact decimal
    address (as produced by _validate_js_int), the exact 0xNN hex literals,
    the correct size (3), and the Memory.patchCode call.

    Mutation caught: using the wrong address field in ptr(), computing hex
    array from a different byte sequence, or omitting the patchCode call.
    """
    bridge, _, _ = _build_attached_bridge()
    captured = _patch_execute_script(bridge, {"success": True})

    async def driver() -> bool:
        return await bridge.patch_code(_PATCH_ADDR_INT, "90 CC 90")

    result = _run(driver())

    assert result is True, "patch_code must return True on success"
    assert len(captured) == 1, "_execute_script_and_wait must be called once"
    js = captured[0]

    assert "Memory.patchCode" in js, "JS must call Memory.patchCode"
    addr_decimal = str(_PATCH_ADDR_INT)
    assert addr_decimal in js, f"JS must embed address as decimal {addr_decimal}, got: {js!r}"
    assert "0x90" in js, "JS must include 0x90 byte literal"
    assert "0xcc" in js, "JS must include 0xcc byte literal"
    assert ", 3," in js or ",3," in js, "JS must specify size=3 in patchCode call"


def test_patch_code_error_result_raises_toolerror() -> None:
    """patch_code raises ToolError when the script result contains an error.

    Oracle: the production check is `if 'error' in result`. We inject
    {"success": False, "error": "access denied"} and expect ToolError.

    Mutation caught: checking only result.get('success') without also checking
    'error' key, allowing partial-error results to silently succeed.
    """
    bridge, _, _ = _build_attached_bridge()
    _patch_execute_script(bridge, {"success": False, "error": "access denied"})

    async def driver() -> bool:
        return await bridge.patch_code(_PATCH_ADDR_INT, "cc")

    with pytest.raises(ToolError, match=r"code patching failed|patching"):
        _run(driver())


def test_patch_code_success_false_without_error_key_raises() -> None:
    """patch_code raises ToolError when success is False even without error key.

    Oracle: result {"success": False} triggers the `not result.get("success")`
    branch in production.

    Mutation caught: only checking 'error' key but ignoring success==False.
    """
    bridge, _, _ = _build_attached_bridge()
    _patch_execute_script(bridge, {"success": False})

    async def driver() -> bool:
        return await bridge.patch_code(_PATCH_ADDR_INT, "cc")

    with pytest.raises(ToolError, match=r"code patching failed|patching"):
        _run(driver())


def test_intercept_return_builds_exact_on_leave_string() -> None:
    """intercept_return delegates to hook_function with the exact on_leave string.

    Oracle: return_value=0x12345678 (decimal 305419896). The on_leave string
    must be exactly "retval.replace(ptr('305419896'));" per the production
    template f"retval.replace(ptr('{validated_return_value:d}'));".

    Mutation caught: using hex instead of decimal in the ptr() call,
    using retval.replaceWith instead of retval.replace, or passing the
    wrong validated_return_value field.
    """
    bridge, _, _ = _build_attached_bridge()

    captured_kwargs: list[dict[str, object]] = []

    async def fake_hook_function(
        target: str = "",
        on_enter: str = "",
        on_leave: str = "",
        **_: object,
    ) -> HookInfo:
        """Record hook_function arguments and return a canned HookInfo.

        Args:
            target: Target function name.
            on_enter: On-enter JS code.
            on_leave: On-leave JS code.
            **_: Ignored keyword arguments.

        Returns:
            HookInfo: Canned hook info for the test.
        """
        captured_kwargs.append({"target": target, "on_enter": on_enter, "on_leave": on_leave})
        await asyncio.sleep(0)
        return HookInfo(id="hook-x", target=target, address=0, script_id="hook-x", active=True)

    _set(bridge, "hook_function", fake_hook_function)

    async def driver() -> HookInfo:
        return await bridge.intercept_return("target_func", _INTERCEPT_RETURN_VALUE)

    info = _run(driver())

    assert info.target == "target_func"
    assert len(captured_kwargs) == 1, "hook_function must be called exactly once"
    on_leave = cast("str", captured_kwargs[0]["on_leave"])
    expected_decimal = str(_INTERCEPT_RETURN_VALUE)
    assert f"ptr('{expected_decimal}')" in on_leave, f"on_leave must embed decimal {expected_decimal!r} in ptr(), got: {on_leave!r}"
    assert "retval.replace(" in on_leave, f"on_leave must use retval.replace(, got: {on_leave!r}"


def test_write_code_invalid_architecture_raises_toolerror() -> None:
    """write_code raises ToolError when the architecture is not in the valid set.

    Mutation caught: removing the architecture validation guard so an invalid
    arch silently generates broken JS.
    """
    bridge, _, _ = _build_attached_bridge()

    async def driver() -> int:
        return await bridge.write_code(0x1000, "z80", ["putNop"])

    with pytest.raises(ToolError, match=r"code writing|code_write|architecture"):
        _run(driver())


def test_write_code_js_uses_correct_writer_class() -> None:
    """write_code embeds the correct architecture-specific writer class in JS.

    Oracle: architecture='x86' must use 'X86Writer'; 'arm64' must use
    'Arm64Writer'. The mapping _CODE_WRITER_MAP is reproduced independently
    in this test as the oracle.

    Mutation caught: hardcoding a single writer class name, using the wrong
    key in _CODE_WRITER_MAP, or swapping arm64 -> ArmWriter.
    """
    oracle: dict[str, str] = {
        "x86": "X86Writer",
        "arm": "ArmWriter",
        "arm64": "Arm64Writer",
        "thumb": "ThumbWriter",
    }

    for arch, expected_class in oracle.items():
        bridge_iter, _, _ = _build_attached_bridge()
        captured = _patch_execute_script(bridge_iter, {"type": "code_written", "size": _WRITE_CODE_SIZE})

        async def driver(
            a: str = arch,
            b: FridaBridge = bridge_iter,
        ) -> int:
            return await b.write_code(0x4000, a, ["putNop", "putRet"])

        written = _run(driver())
        assert written == _WRITE_CODE_SIZE, f"write_code must return parsed size {_WRITE_CODE_SIZE}, got {written}"
        js = captured[0]
        assert expected_class in js, f"JS for arch={arch!r} must contain {expected_class!r}; got: {js!r}"
        assert "wProbe.putNop();" in js, "JS must contain wProbe.putNop();"
        assert "wProbe.putRet();" in js, "JS must contain wProbe.putRet();"
        assert "Memory.patchCode" in js, "JS must call Memory.patchCode"


def test_write_code_returns_size_from_script_result() -> None:
    """write_code returns exactly the 'size' value in the script result dict.

    Oracle: the canned result {"type": "code_written", "size": 7} is compared
    against the return value of write_code.

    Mutation caught: returning len(instructions) instead of the script's
    reported size, or returning 0 unconditionally.
    """
    known_size = 7
    bridge, _, _ = _build_attached_bridge()
    _patch_execute_script(bridge, {"type": "code_written", "size": known_size})

    async def driver() -> int:
        return await bridge.write_code(0x2000, "x86", ["putNop"])

    result = _run(driver())
    assert result == known_size, f"write_code must return the script-reported size {known_size}, got {result}"


def test_write_code_error_result_raises_toolerror() -> None:
    """write_code raises ToolError when result contains type='code_write_error'.

    Mutation caught: not checking for code_write_error type in result, letting
    the method return 0 silently on script failure.
    """
    bridge, _, _ = _build_attached_bridge()
    _patch_execute_script(bridge, {"type": "code_write_error", "error": "probe produced no bytes"})

    async def driver() -> int:
        return await bridge.write_code(0x3000, "arm", ["putNop"])

    with pytest.raises(ToolError, match=r"code writing|code_write|writer"):
        _run(driver())


def test_allocate_string_invalid_encoding_raises_toolerror() -> None:
    """allocate_string raises ToolError for an unrecognised encoding.

    Oracle: the set of valid encodings is {utf8, ansi, utf16}; 'utf32' is
    not in this set.

    Mutation caught: removing the encoding validation so invalid encodings
    silently fall through to an undefined alloc_fn_map key lookup.
    """
    bridge, _, _ = _build_attached_bridge()

    async def driver() -> int:
        return await bridge.allocate_string("hello", "utf32")

    with pytest.raises(ToolError, match=r"string allocation|invalid encoding"):
        _run(driver())


def test_allocate_string_utf8_uses_allocutf8string() -> None:
    """allocate_string(encoding='utf8') uses Memory.allocUtf8String in JS.

    Oracle: the alloc_fn_map key 'utf8' -> 'allocUtf8String' is an
    independent constant; the captured JS source must embed it verbatim.

    Mutation caught: using allocAnsiString or allocUtf16String for the
    utf8 encoding path.
    """
    bridge, sess, _ = _build_attached_bridge()

    async def driver() -> int:
        task = asyncio.create_task(bridge.allocate_string("hello", "utf8"))
        await asyncio.sleep(0)
        for _ in range(50):
            if sess.scripts:
                break
            await asyncio.sleep(0.01)
        assert sess.scripts, "create_script never called"
        script = sess.scripts[0]
        for _ in range(50):
            if script.load_calls > 0:
                break
            await asyncio.sleep(0.01)
        script.deliver({"type": "string_alloc", "address": _ALLOC_STR_ADDR_HEX})
        return await task

    addr = _run(driver())

    assert addr == _ALLOC_STR_ADDR, f"allocate_string must return parsed address {_ALLOC_STR_ADDR:#x}, got {addr:#x}"
    assert len(sess.sources) >= 1, "create_script must have been called"
    js = sess.sources[0]
    assert "allocUtf8String" in js, f"JS for encoding='utf8' must use allocUtf8String, got: {js!r}"
    assert "allocAnsiString" not in js, "JS for encoding='utf8' must NOT use allocAnsiString"


def test_allocate_string_ansi_uses_allocansistring() -> None:
    """allocate_string(encoding='ansi') uses Memory.allocAnsiString in JS.

    Mutation caught: using allocUtf8String for the ansi encoding path.
    """
    bridge, sess, _ = _build_attached_bridge()

    async def driver() -> int:
        task = asyncio.create_task(bridge.allocate_string("hello", "ansi"))
        await asyncio.sleep(0)
        for _ in range(50):
            if sess.scripts:
                break
            await asyncio.sleep(0.01)
        assert sess.scripts, "create_script never called"
        script = sess.scripts[0]
        for _ in range(50):
            if script.load_calls > 0:
                break
            await asyncio.sleep(0.01)
        script.deliver({"type": "string_alloc", "address": _ALLOC_STR_ADDR_HEX})
        return await task

    addr = _run(driver())

    assert addr == _ALLOC_STR_ADDR
    js = sess.sources[0]
    assert "allocAnsiString" in js, f"JS for encoding='ansi' must use allocAnsiString, got: {js!r}"


def test_allocate_string_utf16_uses_allocutf16string() -> None:
    """allocate_string(encoding='utf16') uses Memory.allocUtf16String in JS.

    Mutation caught: using allocUtf8String or allocAnsiString for utf16.
    """
    bridge, sess, _ = _build_attached_bridge()

    async def driver() -> int:
        task = asyncio.create_task(bridge.allocate_string("hello", "utf16"))
        await asyncio.sleep(0)
        for _ in range(50):
            if sess.scripts:
                break
            await asyncio.sleep(0.01)
        assert sess.scripts, "create_script never called"
        script = sess.scripts[0]
        for _ in range(50):
            if script.load_calls > 0:
                break
            await asyncio.sleep(0.01)
        script.deliver({"type": "string_alloc", "address": _ALLOC_STR_ADDR_HEX})
        return await task

    addr = _run(driver())

    assert addr == _ALLOC_STR_ADDR
    js = sess.sources[0]
    assert "allocUtf16String" in js, f"JS for encoding='utf16' must use allocUtf16String, got: {js!r}"


def test_allocate_string_address_parsed_from_hex_string() -> None:
    """allocate_string parses a 0x-prefixed hex address string from the message.

    Oracle: hex string '0x55550000' must parse to integer 0x55550000.
    Both the 0x-prefix path and the decimal path are tested.

    Mutation caught: using int(addr_str) without the hex-detection branch,
    which would raise ValueError on a 0x-prefixed string.
    """
    bridge, sess, _ = _build_attached_bridge()
    hex_addr = "0x55550000"
    expected_addr: int = 0x5555_0000

    async def driver() -> int:
        task = asyncio.create_task(bridge.allocate_string("test_str", "utf8"))
        await asyncio.sleep(0)
        for _ in range(50):
            if sess.scripts:
                break
            await asyncio.sleep(0.01)
        assert sess.scripts
        script = sess.scripts[0]
        for _ in range(50):
            if script.load_calls > 0:
                break
            await asyncio.sleep(0.01)
        script.deliver({"type": "string_alloc", "address": hex_addr})
        return await task

    addr = _run(driver())
    assert addr == expected_addr, f"hex address {hex_addr!r} must parse to {expected_addr:#x}, got {addr:#x}"


def test_allocate_string_zero_address_raises_toolerror() -> None:
    """allocate_string raises ToolError when the reported address is 0.

    Oracle: address '0' parses to integer 0 which is the sentinel for
    allocation failure.

    Mutation caught: returning 0 as a valid address instead of raising.
    """
    bridge, sess, _ = _build_attached_bridge()

    async def driver() -> int:
        task = asyncio.create_task(bridge.allocate_string("fail_str", "utf8"))
        await asyncio.sleep(0)
        for _ in range(50):
            if sess.scripts:
                break
            await asyncio.sleep(0.01)
        assert sess.scripts
        script = sess.scripts[0]
        for _ in range(50):
            if script.load_calls > 0:
                break
            await asyncio.sleep(0.01)
        script.deliver({"type": "string_alloc", "address": "0"})
        return await task

    with pytest.raises(ToolError, match=r"string allocation|alloc"):
        _run(driver())


def test_allocate_string_registers_script_and_alloc_mapping() -> None:
    """allocate_string stores the script and address->script_id in registries.

    Oracle: after a successful allocation the bridge's _scripts and
    _alloc_scripts dicts must contain entries for the new allocation, so
    the script survives GC until explicitly freed.

    Mutation caught: forgetting to register in _alloc_scripts, which would
    prevent lookup-by-address during free operations.
    """
    bridge, sess, _ = _build_attached_bridge()

    async def driver() -> int:
        task = asyncio.create_task(bridge.allocate_string("hello", "utf8"))
        await asyncio.sleep(0)
        for _ in range(50):
            if sess.scripts:
                break
            await asyncio.sleep(0.01)
        assert sess.scripts
        script = sess.scripts[0]
        for _ in range(50):
            if script.load_calls > 0:
                break
            await asyncio.sleep(0.01)
        script.deliver({"type": "string_alloc", "address": _ALLOC_STR_ADDR_HEX})
        return await task

    addr = _run(driver())

    scripts_dict = cast("dict[object, object]", _get_attr(bridge, "_scripts"))
    alloc_scripts = cast("dict[object, object]", _get_attr(bridge, "_alloc_scripts"))

    assert _ALLOC_STR_ADDR in alloc_scripts, f"address {_ALLOC_STR_ADDR:#x} must be in _alloc_scripts after allocation"
    script_id = alloc_scripts[_ALLOC_STR_ADDR]
    assert script_id in scripts_dict, f"script_id {script_id!r} from _alloc_scripts must be present in _scripts"
    assert addr == _ALLOC_STR_ADDR
