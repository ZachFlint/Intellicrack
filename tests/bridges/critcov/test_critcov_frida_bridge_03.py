# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Critical-coverage tests for the Frida bridge library, Stalker transform, kernel, file, SQLite and code-writer paths.

Every test that needs a session drives the real Frida runtime against a child
process that the test itself starts (a Python interpreter blocked on stdin),
never against the pytest process. The tests cover the not-attached guards of the
extended bridge surface, argument validation, and the error paths that a real
target can trigger: a rejected library injection, a Stalker transform that fails
to compile, runtimes this operating system does not provide, a CModule that does
not compile, an RPC export that raises, and a Stalker call-summary teardown whose
script never acknowledges.
"""

from __future__ import annotations

import asyncio
import sys
from typing import TYPE_CHECKING, Final, cast

import pytest

from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.core.subprocess_compat import DEVNULL, PIPE, Popen
from intellicrack.core.types import StalkerCallSummary, ToolError


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator
    from pathlib import Path

    import frida


pytestmark = pytest.mark.spawns_process

_WAIT_S: Final[float] = 20.0
_ABSENT_PID: Final[int] = 0x7FFFFFFE
_NOT_ATTACHED: Final[str] = "not attached to a process"
_TARGET_READY: Final[bytes] = b"critcov-ready"
_TARGET_SOURCE: Final[str] = "import sys\nsys.stdout.write('critcov-ready\\n')\nsys.stdout.flush()\nsys.stdin.read()\n"
_UNATTACHED_CALLS: Final[tuple[tuple[str, tuple[object, ...], dict[str, object]], ...]] = (
    ("stalker_follow_with_transform", (), {"transform_code": "iterator.keep();"}),
    ("stalker_flush", (), {}),
    ("stalker_follow_call_summary", (), {}),
    ("stalker_unfollow_call_summary", (), {}),
    ("find_export_by_name", ("GetTickCount", "kernel32.dll"), {}),
    ("create_cmodule", ("int critcov(void) { return 0; }",), {}),
    ("kernel_enumerate_ranges", (), {}),
    ("kernel_read", (0, 1), {}),
    ("kernel_write", (0, "00"), {}),
    ("kernel_alloc", (16,), {}),
    ("kernel_protect", (0, 16, "rw-"), {}),
    ("socket_connect", ("127.0.0.1", 1), {}),
    ("socket_type", (0,), {}),
    ("socket_local_address", (0,), {}),
    ("socket_peer_address", (0,), {}),
    ("file_read_target", ("critcov.bin",), {}),
    ("file_write_target", ("critcov.bin", "00"), {}),
    ("sqlite_dump", ("critcov.db",), {}),
    ("write_code", (0x1000, "x86", ["putNop"]), {}),
    ("cloak_add_thread", (1,), {}),
    ("cloak_remove_thread", (1,), {}),
    ("cloak_add_range", (0x1000, 16), {}),
    ("cloak_remove_range", (0x1000, 16), {}),
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


def async_method(obj: object, name: str) -> Callable[..., Coroutine[object, object, object]]:
    """Look up a (possibly private) coroutine method by name.

    Args:
        obj: Object or class that owns the method.
        name: Method name.

    Returns:
        Callable[..., Coroutine[object, object, object]]: The bound coroutine method or plain coroutine function.
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


def _loaded_script(bridge: FridaBridge, source: str) -> tuple[str, frida.Script]:
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


def _registered_scripts(bridge: FridaBridge) -> dict[str, frida.Script]:
    """Return the bridge's live script registry.

    Args:
        bridge: Bridge whose registry is read.

    Returns:
        dict[str, frida.Script]: The script identifier to Frida script mapping.
    """
    return cast("dict[str, frida.Script]", priv(bridge, "_scripts", object))


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


@pytest.mark.parametrize(("method", "args", "kwargs"), _UNATTACHED_CALLS, ids=[name for name, _, _ in _UNATTACHED_CALLS])
def test_operation_without_session_raises_not_attached(method: str, args: tuple[object, ...], kwargs: dict[str, object]) -> None:
    """Every session-bound operation of the extended surface refuses to run before the bridge has attached to a process.

    Args:
        method: Name of the bridge method under test.
        args: Positional arguments for the call.
        kwargs: Keyword arguments for the call.
    """
    bridge = FridaBridge()
    with pytest.raises(ToolError) as excinfo:
        _run(async_method(bridge, method)(*args, **kwargs))
    assert excinfo.value.message == _NOT_ATTACHED


def test_inject_library_blob_without_device_raises_no_device() -> None:
    """Injecting a library through a bridge that never initialized reports the missing device."""
    with pytest.raises(ToolError) as excinfo:
        _run(FridaBridge().inject_library_blob(1, "00", "critcov_entry", ""))
    assert excinfo.value.message == "no Frida device available"


def test_inject_library_blob_into_absent_process_reports_injection_failure(idle_bridge: FridaBridge) -> None:
    """Injecting a library blob into a pid that does not exist surfaces Frida's refusal as an injection failure.

    Args:
        idle_bridge: Initialized bridge without a session.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(idle_bridge.inject_library_blob(_ABSENT_PID, "00 01 02", "critcov_entry", "critcov-data"))
    assert excinfo.value.message == "library injection failed"
    assert excinfo.value.__cause__ is not None


@pytest.mark.parametrize("pattern", [None, "NS*"], ids=["no_pattern", "glob_pattern"])
def test_objc_enumerate_loaded_classes_without_objc_runtime_raises(attached_bridge: FridaBridge, pattern: str | None) -> None:
    """A Windows target has no Objective-C runtime, so enumerating its loaded classes is refused.

    Args:
        attached_bridge: Bridge attached to the child.
        pattern: Optional glob filter passed to the enumeration.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.objc_enumerate_loaded_classes(pattern))
    assert excinfo.value.message == "Objective-C runtime not available"


def test_java_hook_method_without_java_runtime_registers_nothing(attached_bridge: FridaBridge) -> None:
    """A Windows native target has no Java runtime, so the hook is refused and neither a hook nor a script stays registered.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.java_hook_method("com.example.Critcov", "run"))
    assert excinfo.value.message in {"hook installation failed", "Java runtime not available"}
    assert cast("dict[str, object]", priv(attached_bridge, "_hooks", object)) == {}
    assert _registered_scripts(attached_bridge) == {}


def test_stalker_follow_with_transform_rejects_a_transform_that_does_not_compile(attached_bridge: FridaBridge) -> None:
    """Transform code with a syntax error is refused when the script is created and leaves no Stalker script registered.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.stalker_follow_with_transform(events="call", transform_code="var = ;"))
    assert excinfo.value.message == "Stalker tracing operation failed"
    assert excinfo.value.__cause__ is not None
    assert cast("dict[int, str]", priv(attached_bridge, "_stalker_scripts", object)) == {}
    assert _registered_scripts(attached_bridge) == {}


def test_stalker_flush_without_an_active_trace_names_the_thread(attached_bridge: FridaBridge) -> None:
    """Flushing a thread that has no trace is refused with a reason naming that thread.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.stalker_flush(4242))
    assert excinfo.value.message == "Stalker tracing operation failed"
    assert excinfo.value.details == {"reason": "no active Stalker trace for thread 4242"}


def test_stalker_flush_with_a_missing_script_handle_is_refused(attached_bridge: FridaBridge) -> None:
    """Flushing a trace whose script is no longer registered is refused instead of posting to nothing.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    cast("dict[int, str]", priv(attached_bridge, "_stalker_scripts", object))[77] = "ghost"

    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.stalker_flush(77))
    assert excinfo.value.message == "Stalker tracing operation failed"
    assert excinfo.value.details == {"reason": "stalker script handle missing"}


def test_stalker_unfollow_call_summary_without_a_trace_returns_empty_counts(attached_bridge: FridaBridge) -> None:
    """Stopping a call-summary trace that was never started reports an empty summary for the default thread.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    summary = _run(attached_bridge.stalker_unfollow_call_summary())

    assert isinstance(summary, StalkerCallSummary)
    assert summary.thread_id == 0
    assert summary.counts == {}
    assert summary.duration_ms >= 0


def test_stalker_unfollow_call_summary_with_a_missing_script_handle_forgets_the_trace(attached_bridge: FridaBridge) -> None:
    """A call-summary registration whose script is gone is dropped and still yields an empty summary.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    registry = cast("dict[int, str]", priv(attached_bridge, "_stalker_summary_scripts", object))
    registry[5] = "ghost"

    summary = _run(attached_bridge.stalker_unfollow_call_summary(5))

    assert summary.thread_id == 5
    assert summary.counts == {}
    assert registry == {}


def test_stalker_unfollow_call_summary_gives_up_on_a_script_that_never_acknowledges(attached_bridge: FridaBridge) -> None:
    """A call-summary script that ignores the unfollow request is abandoned after the acknowledgement timeout and then unloaded.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    script_id, script = _loaded_script(attached_bridge, "var critcovSilent = 1;")
    registry = cast("dict[int, str]", priv(attached_bridge, "_stalker_summary_scripts", object))
    registry[9] = script_id

    summary = _run(attached_bridge.stalker_unfollow_call_summary(9))

    assert summary.thread_id == 9
    assert summary.counts == {}
    assert summary.duration_ms >= 4500
    assert script.is_destroyed
    assert registry == {}
    assert script_id not in _registered_scripts(attached_bridge)


def test_create_cmodule_rejects_source_that_does_not_compile(attached_bridge: FridaBridge) -> None:
    """C source that does not compile is reported with the compiler's reason and leaves no script registered.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.create_cmodule("this is not valid C source !!!"))
    assert excinfo.value.message == "CModule compilation failed"
    reason = excinfo.value.details["reason"]
    assert isinstance(reason, str)
    assert len(reason) > 0
    assert _registered_scripts(attached_bridge) == {}


def test_kernel_enumerate_ranges_without_kernel_api_raises(attached_bridge: FridaBridge) -> None:
    """A user-mode Windows target has no Kernel API, so enumerating kernel ranges is refused.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.kernel_enumerate_ranges())
    assert excinfo.value.message == "Kernel API not available"


def test_file_read_target_returns_the_bytes_of_a_file_as_hex(attached_bridge: FridaBridge, tmp_path: Path) -> None:
    """Reading a file through the target returns exactly its bytes, hex encoded.

    Args:
        attached_bridge: Bridge attached to the child.
        tmp_path: Directory holding the file the target reads.
    """
    content = bytes(range(16)) + b"critcov"
    path = tmp_path / "payload.bin"
    path.write_bytes(content)

    assert _run(attached_bridge.file_read_target(str(path))) == content.hex()


def test_file_read_target_of_an_empty_file_returns_empty_hex(attached_bridge: FridaBridge, tmp_path: Path) -> None:
    """Reading a file that holds no bytes is a valid read and returns an empty hex string.

    Args:
        attached_bridge: Bridge attached to the child.
        tmp_path: Directory holding the file the target reads.
    """
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")

    result = _run(attached_bridge.file_read_target(str(path)))

    assert isinstance(result, str)
    assert len(result) == 0


def test_sqlite_exec_reports_an_export_that_raises(attached_bridge: FridaBridge) -> None:
    """An RPC export that raises is reported as a SQLite failure chained to Frida's error, and the script stays registered.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    script_id, script = _loaded_script(
        attached_bridge,
        "rpc.exports = { exec: function (sql) { throw new Error('critcov-sql-failure'); } };",
    )

    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.sqlite_exec(script_id, "SELECT 1"))
    assert excinfo.value.message == "SQLite operation failed"
    assert excinfo.value.__cause__ is not None
    assert not script.is_destroyed
    assert script_id in _registered_scripts(attached_bridge)


def test_sqlite_exec_returns_what_the_export_returns(attached_bridge: FridaBridge) -> None:
    """A working RPC export's return value is handed back unchanged, so the failure case above is not a broken RPC channel.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    script_id, _script = _loaded_script(
        attached_bridge,
        "rpc.exports = { exec: function (sql) { return sql.length; } };",
    )

    assert _run(attached_bridge.sqlite_exec(script_id, "SELECT 1")) == len("SELECT 1")


@pytest.mark.parametrize("max_size", [0, -5], ids=["zero", "negative"])
def test_write_code_rejects_a_non_positive_probe_size(attached_bridge: FridaBridge, max_size: int) -> None:
    """A probe buffer budget that is zero or negative is refused with a reason naming the value before any script runs.

    Args:
        attached_bridge: Bridge attached to the child.
        max_size: Probe buffer budget under test.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.write_code(0x1000, "x86", ["putNop"], max_size=max_size))
    assert excinfo.value.message == "code writing failed"
    assert excinfo.value.details == {"reason": f"max_size must be positive, got {max_size}"}
