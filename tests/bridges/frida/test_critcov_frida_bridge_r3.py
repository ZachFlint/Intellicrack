# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Third-pass critical-coverage tests for the Frida bridge, written from measurements in the real container.

Every test drives the real Frida runtime against a child process that the test
itself starts (a Python interpreter blocked on stdin), never against the pytest
process. The cases cover the error replies that a real target does produce for
inputs the bridge accepts (an unsigned-integer violation in Stalker, a negative
Cloak argument, an allocation that cannot be satisfied, a string that cannot be
converted), an install reply that arrives after the wait limit, the failure of
the TypeScript compiler and of its temporary-file cleanup, a file monitor whose
path cannot be encoded, and a remote device with no server behind it.
"""

from __future__ import annotations

import asyncio
import ctypes
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import uuid
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import frida
import pytest
from structlog.testing import capture_logs

from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.core.subprocess_compat import DEVNULL, PIPE, Popen
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator


pytestmark = pytest.mark.spawns_process

_WAIT_S: Final[float] = 20.0
_STALL_S: Final[float] = 5.5
_KILL_AFTER_S: Final[float] = 0.3
_SILENT_WAIT_S: Final[float] = 1.5
_TARGET_READY: Final[bytes] = b"critcov-ready"
_TARGET_SOURCE: Final[str] = "import sys\nsys.stdout.write('critcov-ready\\n')\nsys.stdout.flush()\nsys.stdin.read()\n"
_UNSIGNED_REASON: Final[str] = "Error: expected an unsigned integer"
_STALKER_FAILED: Final[str] = "Stalker tracing operation failed"
_HOOK_FAILED: Final[str] = "hook installation failed"
_REMOTE_REFUSED: Final[str] = "unable to connect to remote frida-server"
_TS_SOURCE: Final[str] = "const a: number = 1; console.log(a);"
_GENERIC_READ: Final[int] = 0x80000000
_SHARE_READ_WRITE: Final[int] = 0x3
_OPEN_EXISTING: Final[int] = 3
_INVALID_HANDLE: Final[int] = ctypes.c_void_p(-1).value or 0
_ERROR_CASES: Final[tuple[tuple[str, Callable[[FridaBridge], Coroutine[object, object, object]], str, dict[str, object] | None], ...]] = (
    ("query_protection_of_a_negative_address", lambda b: b.query_memory_protection(-1), "memory read failed", None),
    ("protect_a_two_gigabyte_range", lambda b: b.protect_memory(0x10000, 2**31, "rwx"), "memory protection change failed", None),
    ("stalker_exclude_negative_size", lambda b: b.stalker_exclude(0x10000, -1), _STALKER_FAILED, {"reason": _UNSIGNED_REASON}),
    (
        "stalker_invalidate_negative_thread",
        lambda b: b.stalker_invalidate(0x10000, -1),
        _STALKER_FAILED,
        {"reason": _UNSIGNED_REASON},
    ),
    ("cloak_add_negative_thread", lambda b: b.cloak_add_thread(-1), _HOOK_FAILED, None),
    ("cloak_remove_negative_thread", lambda b: b.cloak_remove_thread(-1), _HOOK_FAILED, None),
    ("cloak_add_negative_range", lambda b: b.cloak_add_range(0x10000, -1), _HOOK_FAILED, None),
    ("cloak_remove_negative_range", lambda b: b.cloak_remove_range(0x10000, -1), _HOOK_FAILED, None),
    ("allocate_two_gigabytes", lambda b: b.allocate_memory(2**31), "memory allocation failed", None),
    ("allocate_lone_surrogate_ansi", lambda b: b.allocate_string("\ud800", "ansi"), "string allocation failed", None),
    ("allocate_lone_surrogate_utf16", lambda b: b.allocate_string("\ud800", "utf16"), "string allocation failed", None),
)
_STALKER_FAILURES: Final[tuple[tuple[str, Callable[[FridaBridge], Coroutine[object, object, object]]], ...]] = (
    ("follow", lambda b: b.stalker_follow(-1, "call", 10)),
    ("call_summary", lambda b: b.stalker_follow_call_summary(-1)),
    ("transform", lambda b: b.stalker_follow_with_transform(-1, "call", 10, transform_code="iterator.keep();")),
)
_LATE_REPLIES: Final[tuple[tuple[str, Callable[[FridaBridge], Coroutine[object, object, object]], frozenset[str], str], ...]] = (
    (
        "hook_function",
        lambda b: b.hook_function("kernel32.dll!GetTickCount"),
        frozenset({"hooked", "hook_error"}),
        _HOOK_FAILED,
    ),
    (
        "replace_function",
        lambda b: b.replace_function("kernel32.dll!GetTickCount", "function () { return 0; }"),
        frozenset({"replaced", "replace_error"}),
        "function replacement failed",
    ),
    (
        "replace_function_fast",
        lambda b: b.replace_function_fast("kernel32.dll!GetTickCount", "function () { return 0; }"),
        frozenset({"replaced_fast", "replace_fast_error"}),
        "function replacement failed",
    ),
)
_DEAD_REMOTE_CALLS: Final[tuple[tuple[str, Callable[[FridaBridge], Coroutine[object, object, object]]], ...]] = (
    ("attach_by_name", lambda b: b.attach_by_name("critcov-none.exe")),
    ("attach", lambda b: b.attach(4321)),
    ("kill", lambda b: b.kill(4321)),
    ("spawn", lambda b: b.spawn(Path(sys.executable))),
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


def async_method(obj: object, name: str) -> Callable[..., Coroutine[object, object, object]]:
    """Look up a (possibly private) coroutine method by name.

    Args:
        obj: Object or class that owns the method.
        name: Method name.

    Returns:
        Callable[..., Coroutine[object, object, object]]: The bound coroutine method.
    """
    return cast("Callable[..., Coroutine[object, object, object]]", getattr(obj, name))


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


def _lock_first_typescript_file(directory: Path, locked: list[int], stop: threading.Event) -> None:
    """Open the first ``.ts`` file that appears in a directory in a way that forbids deleting it.

    Args:
        directory: Directory to watch.
        locked: List that receives the handle once the file is held.
        stop: Event that ends the watch.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel32.CreateFileW
    create.restype = ctypes.c_void_p
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    while not stop.is_set():
        for found in directory.glob("*.ts"):
            handle = create(str(found), _GENERIC_READ, _SHARE_READ_WRITE, None, _OPEN_EXISTING, 0, None)
            if handle in {None, _INVALID_HANDLE}:
                continue
            locked.append(int(handle))
            return
        time.sleep(0.001)


def _close_handle(handle: int) -> None:
    """Close a Win32 handle.

    Args:
        handle: The handle to close.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle(handle)


class _StallingHandler:
    """A bridge message handler that holds Frida's callback thread when a chosen reply arrives."""

    def __init__(self, stall_types: frozenset[str]) -> None:
        """Remember which payload types to hold.

        Args:
            stall_types: Payload ``type`` values whose delivery is held for ``_STALL_S`` seconds.
        """
        self.stall_types = stall_types
        self.stalled = threading.Event()
        self.finished = threading.Event()
        self.release = threading.Event()

    def __call__(self, message: dict[str, object]) -> None:
        """Hold the callback thread for a chosen payload type and let every other message pass.

        Args:
            message: The message the bridge dispatches.
        """
        payload = message.get("payload")
        if isinstance(payload, dict) and cast("dict[str, object]", payload).get("type") in self.stall_types:
            self.stalled.set()
            self.release.wait(_STALL_S)
            self.finished.set()


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
        put(bridge, "_device", value=frida.get_local_device())
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


@pytest.fixture
def dead_remote_host() -> Generator[str]:
    """Provide a ``host:port`` on loopback where nothing listens and forget the remote device afterwards.

    Yields:
        str: The endpoint, to be added as a remote device by the test.
    """
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    host = f"127.0.0.1:{port}"
    try:
        yield host
    finally:
        frida.get_device_manager().remove_remote_device(host)


@pytest.mark.parametrize(
    ("call", "message", "details"),
    [pytest.param(case[1], case[2], case[3], id=case[0]) for case in _ERROR_CASES],
)
def test_script_error_replies_become_tool_errors_and_leave_nothing_registered(
    attached_bridge: FridaBridge,
    call: Callable[[FridaBridge], Coroutine[object, object, object]],
    message: str,
    details: dict[str, object] | None,
) -> None:
    """An input the bridge accepts but the Frida runtime refuses surfaces as the operation's own tool error.

    Args:
        attached_bridge: Bridge attached to the child.
        call: The bridge call under test, with the offending argument.
        message: The tool error message the operation is documented to raise.
        details: The exact details expected, or None when none are carried.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(call(attached_bridge))

    assert excinfo.value.message == message
    if details is not None:
        assert excinfo.value.details == details
    assert cast("dict[str, object]", priv(attached_bridge, "_scripts", object)) == {}
    assert cast("dict[int, str]", priv(attached_bridge, "_alloc_scripts", object)) == {}


def test_query_protection_failure_names_the_reason_pd079(attached_bridge: FridaBridge) -> None:
    """A protection query that Frida refuses carries the script's error text (logged defect PD-079, red until fixed).

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.query_memory_protection(-1))

    reason = (excinfo.value.details or {}).get("reason")
    assert isinstance(reason, str)
    assert reason


@pytest.mark.parametrize(("call"), [pytest.param(case[1], id=case[0]) for case in _STALKER_FAILURES])
def test_stalker_follow_variants_report_the_script_error_and_register_no_trace(
    attached_bridge: FridaBridge,
    call: Callable[[FridaBridge], Coroutine[object, object, object]],
) -> None:
    """A thread id that Stalker cannot take as an unsigned integer fails the start with Frida's own description.

    Args:
        attached_bridge: Bridge attached to the child.
        call: The Stalker start call under test, given thread id -1.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(call(attached_bridge))

    assert excinfo.value.message == _STALKER_FAILED
    assert excinfo.value.details == {"reason": _UNSIGNED_REASON}
    assert cast("dict[str, object]", priv(attached_bridge, "_scripts", object)) == {}
    assert cast("dict[int, str]", priv(attached_bridge, "_stalker_scripts", object)) == {}
    assert cast("dict[int, str]", priv(attached_bridge, "_stalker_summary_scripts", object)) == {}


def test_enumerating_the_imports_of_a_missing_module_names_the_module(attached_bridge: FridaBridge) -> None:
    """A module that is not loaded is reported with its name rather than as a generic import failure.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.enumerate_imports("critcov_missing.dll"))

    assert excinfo.value.message == "module not found"
    assert excinfo.value.details == {"module": "critcov_missing.dll"}


@pytest.mark.parametrize(
    ("call", "stall_types", "message"),
    [pytest.param(case[1], case[2], case[3], id=case[0]) for case in _LATE_REPLIES],
)
def test_install_reply_delivered_after_the_wait_limit_fails_the_install_and_unloads_the_script(
    attached_bridge: FridaBridge,
    call: Callable[[FridaBridge], Coroutine[object, object, object]],
    stall_types: frozenset[str],
    message: str,
) -> None:
    """A hook or replacement whose acknowledgement is held past the five-second limit is reported as failed and not kept.

    Args:
        attached_bridge: Bridge attached to the child.
        call: The install call under test.
        stall_types: Acknowledgement payload types whose delivery the handler holds.
        message: The tool error message the install is documented to raise.
    """
    handler = _StallingHandler(stall_types)
    attached_bridge.set_message_handler(handler)
    started = time.monotonic()
    try:
        with pytest.raises(ToolError) as excinfo:
            _run(call(attached_bridge))
        elapsed = time.monotonic() - started
    finally:
        handler.release.set()
        assert handler.finished.wait(_WAIT_S)

    assert handler.stalled.is_set()
    assert excinfo.value.message == message
    assert isinstance(excinfo.value.__cause__, TimeoutError)
    assert elapsed >= 5.0
    assert cast("dict[str, object]", priv(attached_bridge, "_scripts", object)) == {}
    assert cast("dict[str, object]", priv(attached_bridge, "_hooks", object)) == {}


def test_silent_script_whose_target_dies_during_the_wait_times_out_and_tolerates_the_failed_unload(
    target_process: Popen[bytes],
    attached_bridge: FridaBridge,
) -> None:
    """A script that never answers fails with the wait limit even though its unload fails because the target is gone.

    Args:
        target_process: The attached child process, which a timer ends during the wait.
        attached_bridge: Bridge attached to the child.
    """
    execute = async_method(attached_bridge, "_execute_script_and_wait")
    killer = threading.Timer(_KILL_AFTER_S, target_process.terminate)
    killer.start()
    try:
        with capture_logs() as logs, pytest.raises(ToolError) as excinfo:
            _run(execute("recv(function () {});", max_wait=_SILENT_WAIT_S))
    finally:
        killer.join()

    assert excinfo.value.message == "script execution failed"
    assert excinfo.value.details == {"reason": "script execution timed out", "max_wait": _SILENT_WAIT_S}
    assert any(entry["event"] == "frida_script_unload_tolerated" and entry["timed_out"] is True for entry in logs)


def test_typescript_build_that_frida_rejects_reports_a_compilation_failure(tmp_path: Path) -> None:
    """A project root that does not contain the entry file makes the Frida compiler raise, which is reported as a tool error.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    not_a_directory = tmp_path / "root_is_a_file.txt"
    not_a_directory.write_text("critcov")
    bridge = FridaBridge()
    try:
        with pytest.raises(ToolError) as excinfo:
            _run(bridge.compile_typescript(_TS_SOURCE, str(not_a_directory)))
    finally:
        _run(bridge.shutdown())

    assert excinfo.value.message == "TypeScript compilation failed"
    cause = excinfo.value.__cause__
    assert isinstance(cause, frida.InvalidArgumentError)
    assert "entrypoint must be inside the project root" in str(cause)


def test_typescript_temp_file_that_cannot_be_deleted_is_logged_and_the_build_still_returns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When another handle forbids deleting the temporary source, the compiled output is still returned and the failure is logged.

    Args:
        tmp_path: Pytest-provided temporary directory.
        monkeypatch: Pytest fixture used to point the temporary directory at ``tmp_path``.
    """
    watch_dir = tmp_path / "ts"
    watch_dir.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(watch_dir))
    bridge = FridaBridge()
    locked: list[int] = []
    stop = threading.Event()
    watcher = threading.Thread(target=_lock_first_typescript_file, args=(watch_dir, locked, stop), daemon=True)
    watcher.start()
    try:
        with capture_logs() as logs:
            compiled = _run(bridge.compile_typescript(_TS_SOURCE))
        leftovers = list(watch_dir.glob("*.ts"))
    finally:
        stop.set()
        watcher.join(_WAIT_S)
        for handle in locked:
            _close_handle(handle)
        _run(bridge.shutdown())

    assert len(locked) == 1
    assert "var a = 1;" in compiled
    assert [entry for entry in logs if entry["event"] == "typescript_tempfile_cleanup_failed"]
    assert len(leftovers) == 1


def test_monitor_path_with_an_embedded_null_is_rejected_and_registers_no_monitor() -> None:
    """A path that cannot be handed to the file monitor fails the setup with the monitor error and keeps nothing."""
    bridge = FridaBridge()

    with pytest.raises(ToolError) as excinfo:
        _run(bridge.monitor_path("critcov\x00path"))

    assert excinfo.value.message == "file monitoring failed"
    assert isinstance(excinfo.value.__cause__, TypeError)
    assert cast("dict[str, object]", priv(bridge, "_file_monitors", object)) == {}


def test_pending_children_of_a_remote_device_without_a_server_are_reported_as_a_gating_failure(
    idle_bridge: FridaBridge,
    dead_remote_host: str,
) -> None:
    """Asking a remote device with nothing behind it for its pending spawns fails with Frida's error type in the details.

    Args:
        idle_bridge: Initialized bridge without a session.
        dead_remote_host: Loopback endpoint where nothing listens.
    """
    _run(idle_bridge.connect_device("remote", dead_remote_host))

    with pytest.raises(ToolError) as excinfo:
        _run(idle_bridge.get_pending_children())

    assert excinfo.value.message == "child gating operation failed"
    assert excinfo.value.details == {
        "frida_error": _REMOTE_REFUSED,
        "frida_error_type": "ServerNotRunningError",
    }
    assert isinstance(excinfo.value.__cause__, frida.ServerNotRunningError)


def test_pending_session_children_of_a_remote_device_without_a_server_are_reported_as_a_gating_failure(
    attached_bridge: FridaBridge,
    dead_remote_host: str,
) -> None:
    """The session-scoped pending-children query reports the same refusal when the bridge's device is a dead remote one.

    Args:
        attached_bridge: Bridge attached to the child.
        dead_remote_host: Loopback endpoint where nothing listens.
    """
    put(attached_bridge, "_device", value=frida.get_device_manager().add_remote_device(dead_remote_host))

    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.get_pending_session_children())

    assert excinfo.value.message == "child gating operation failed"
    assert excinfo.value.details == {
        "frida_error": _REMOTE_REFUSED,
        "frida_error_type": "ServerNotRunningError",
    }
    assert isinstance(excinfo.value.__cause__, frida.ServerNotRunningError)


def test_frontmost_application_of_a_remote_device_without_a_server_is_reported_as_an_enumeration_failure(
    idle_bridge: FridaBridge,
    dead_remote_host: str,
) -> None:
    """Asking a remote device with nothing behind it for its frontmost application fails with Frida's error type in the details.

    Args:
        idle_bridge: Initialized bridge without a session.
        dead_remote_host: Loopback endpoint where nothing listens.
    """
    _run(idle_bridge.connect_device("remote", dead_remote_host))

    with pytest.raises(ToolError) as excinfo:
        _run(idle_bridge.get_frontmost_application())

    assert excinfo.value.message == "enumeration failed"
    assert excinfo.value.details == {
        "frida_error": _REMOTE_REFUSED,
        "frida_error_type": "ServerNotRunningError",
    }
    assert isinstance(excinfo.value.__cause__, frida.ServerNotRunningError)


@pytest.mark.parametrize(("call"), [pytest.param(case[1], id=case[0]) for case in _DEAD_REMOTE_CALLS])
def test_dead_remote_device_surfaces_as_a_tool_error_not_a_raw_frida_error(
    idle_bridge: FridaBridge,
    dead_remote_host: str,
    call: Callable[[FridaBridge], Coroutine[object, object, object]],
) -> None:
    """Attach, kill and spawn on a remote device with no server raise the documented tool error (suspected defect, red until fixed).

    Args:
        idle_bridge: Initialized bridge without a session.
        dead_remote_host: Loopback endpoint where nothing listens.
        call: The device operation under test.
    """
    _run(idle_bridge.connect_device("remote", dead_remote_host))

    with pytest.raises(ToolError):
        _run(call(idle_bridge))


def test_attach_to_an_exited_process_whose_handle_is_still_open_raises_a_tool_error(
    idle_bridge: FridaBridge,
    tmp_path: Path,
) -> None:
    """A process that has exited but is still referenced cannot take the agent, and the attach reports that as a tool error (suspected defect, red until fixed).

    Args:
        idle_bridge: Initialized bridge without a session.
        tmp_path: Pytest-provided temporary directory.
    """
    ghost = tmp_path / f"critcovghost{uuid.uuid4().hex[:8]}.exe"
    shutil.copy2(Path(os.environ["SYSTEMROOT"]) / "System32" / "cmd.exe", ghost)
    proc = Popen([str(ghost), "/c", "exit", "0"], stdin=DEVNULL, stdout=DEVNULL, stderr=DEVNULL)
    try:
        assert proc.wait(timeout=_WAIT_S) == 0
        with pytest.raises(ToolError):
            _run(idle_bridge.attach(proc.pid))
    finally:
        proc.wait(timeout=_WAIT_S)
