# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Coverage-gap tests for the x64dbg bridge that run without x64dbg installed.

Every expectation is derived independently of the bridge: the Win32 contracts of
``ReadProcessMemory`` / ``VirtualAlloc`` / ``OpenProcess`` / ``IsWow64Process``,
the x86 opcode table (``90`` is ``nop``, ``c3`` is ``ret``), the UNICODE_STRING
layout, ``subprocess.list2cmdline`` for a child's command line, and the wire
contract of the real standalone named-pipe server in
``tests/_helpers/realcov_pipe_server.py``.

Anything that talks to the plugin goes through that real Win32 named-pipe server
(a child process hosting a genuine pipe). Anything that needs a "debugger process"
uses a real ``DesktopProcess`` running a Python sleeper on a hidden desktop.
Memory-related checks run against real committed pages that the test allocates in
its own address space with ``VirtualAlloc``. Lines that need a live x64dbg
(list-shaped ``bp_list`` replies, ``unknown_command`` codes, registers) are not
covered here.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import functools
import os
import struct
import subprocess
import sys
import time
import uuid
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest

from intellicrack.bridges import x64dbg as x64dbg_mod
from intellicrack.bridges.base import WatchpointInfo
from intellicrack.bridges.named_pipe_client import PipeConfig
from intellicrack.bridges.win32_types import (
    MEM_COMMIT,
    MEM_IMAGE,
    MEM_MAPPED,
    MEM_PRIVATE,
    MEM_RELEASE,
    MEM_RESERVE,
    MEMORY_BASIC_INFORMATION,
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_NOACCESS,
    PAGE_READONLY,
    PAGE_READWRITE,
    PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
)
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import MemoryRegion, ToolError
from intellicrack.core.win32_desktop_process import DesktopProcess, spawn_on_hidden_desktop
from tests._helpers import realcov_pipe_server as srv
from tests._helpers.polling import wait_until


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Callable, Generator, Iterator

    from intellicrack.bridges.x64dbg import PageRights


_REPO_ROOT = Path(__file__).resolve().parents[3]
_SERVER_MODULE = "tests._helpers.realcov_pipe_server"
_PIPE_READY_TIMEOUT_S = 15.0
_WAIT_S = 10.0
_STEP_WAIT_S = 30.0
_CHILD_WAIT_S = 30.0
_SLEEP_CODE = "import time; time.sleep(300)"
_EXIT_CODE_SEVEN = "raise SystemExit(7)"
_BOGUS_HANDLE = 0x0FFFFFF0
_SYNCHRONIZE = 0x00100000
_PAGE_SIZE = 0x1000
_COMMAND_LINE_OFFSET_X64 = 0x70
_UNICODE_STRING_X64_POINTER_SIZE = 8
_NO_INHERIT = False
_PIPE_MAX_MESSAGE_BYTES = PipeConfig().max_message_size
_REMEDIATION_PREFIX = "x64dbg started but the Intellicrack bridge plugin never opened its named pipe"
_DIAG_NOT_CONFIGURED = "x64dbg installation not configured"
_DIAG_PLUGIN_MISSING = (
    "x64dbg bridge plugin not installed. Ensure Visual Studio and CMake are installed for automatic build, "
    "or manually build from src/x64dbg-plugin/"
)
_DIAG_PIPE_DOWN = (
    "Plugin deployed but x64dbg is not running or has not loaded the plugin. Start x64dbg and verify the plugin is loaded (Plugins menu)"
)

_ResourcePathLabels = cast("type[Any]", getattr(x64dbg_mod, "_ResourcePathLabels"))
_region_containing = cast(
    "Callable[[list[MemoryRegion], int], MemoryRegion | None]",
    getattr(x64dbg_mod, "_region_containing"),
)
_classify_legacy_error = cast("Callable[[str], str]", getattr(x64dbg_mod, "_classify_legacy_error"))
_read_process_memory_block = cast(
    "Callable[[int, int, int], bytes | None]",
    getattr(x64dbg_mod, "_read_process_memory_block"),
)
_extract_command_line_from_peb = cast(
    "Callable[[int], str | None]",
    getattr(x64dbg_mod, "_extract_command_line_from_peb"),
)
_read_unicode_string_from_params = cast(
    "Callable[[int, int, int], str | None]",
    getattr(x64dbg_mod, "_read_unicode_string_from_params"),
)
_coerce_address = cast("Callable[[object], int]", getattr(X64DbgBridge, "_coerce_address"))
_is_local_fallback_eligible = cast(
    "Callable[[ToolError], bool]",
    getattr(X64DbgBridge, "_is_local_fallback_eligible"),
)
_set_step_waiter_result = cast(
    "Callable[[asyncio.Future[int], int], None]",
    getattr(X64DbgBridge, "_set_step_waiter_result"),
)
_cancel_step_waiter_future = cast(
    "Callable[[asyncio.Future[int]], None]",
    getattr(X64DbgBridge, "_cancel_step_waiter_future"),
)
_append_committed_region = cast(
    "Callable[[ctypes.Structure, list[MemoryRegion], Callable[[int], str | None]], None]",
    getattr(X64DbgBridge, "_append_committed_region"),
)
_read_iswow64_status = cast("Callable[[int, int], bool | None]", getattr(X64DbgBridge, "_read_iswow64_status"))
_detect_architecture = cast("Callable[[Path], bool]", getattr(X64DbgBridge, "_detect_architecture"))
_bridge_pipe_failure_message = cast(
    "Callable[[str | None], str]",
    getattr(X64DbgBridge, "_bridge_pipe_failure_message"),
)


def _method(obj: object, name: str) -> Callable[..., Any]:
    """Return the bound attribute ``name`` of ``obj`` as an untyped callable.

    Args:
        obj: Object that owns the (private) method.
        name: Attribute name of the method.

    Returns:
        Callable[..., Any]: The attribute, typed loosely so private members stay
        accessible without a direct private-attribute reference.
    """
    return cast("Callable[..., Any]", getattr(obj, name))


def _resolved(path: Path) -> Path:
    """Resolve ``path`` outside any event loop.

    Args:
        path: Path to resolve.

    Returns:
        Path: The resolved absolute path.
    """
    return path.resolve()


@functools.cache
def _k32() -> ctypes.WinDLL:
    """Return a ``kernel32`` binding with the entry points used here typed.

    Returns:
        ctypes.WinDLL: Typed ``kernel32`` library with last-error tracking.
    """
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.CloseHandle.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.GetCurrentProcess.argtypes = []
    k32.VirtualAlloc.restype = ctypes.c_void_p
    k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    k32.VirtualFree.restype = wintypes.BOOL
    k32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
    k32.GetHandleInformation.restype = wintypes.BOOL
    k32.GetHandleInformation.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    k32.WaitNamedPipeW.restype = wintypes.BOOL
    k32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    return k32


def _current_process_handle() -> int:
    """Return the ``GetCurrentProcess`` pseudo handle (full access to this process).

    Returns:
        int: The pseudo handle value.
    """
    return int(_k32().GetCurrentProcess())


def _open_process(pid: int, access: int) -> int:
    """Open ``pid`` with ``access`` through the real ``OpenProcess``.

    Args:
        pid: Process identifier to open.
        access: Requested access mask.

    Returns:
        int: A real process handle.
    """
    handle = _k32().OpenProcess(access, _NO_INHERIT, pid)
    assert handle, f"OpenProcess({pid}, {access:#x}) failed with error {ctypes.get_last_error()}"
    return int(handle)


def _close_handle(handle: int) -> None:
    """Close a handle opened by :func:`_open_process`.

    Args:
        handle: Handle to close.
    """
    _k32().CloseHandle(handle)


def _handle_is_open(handle: int) -> bool:
    """Report whether ``handle`` is still a valid handle in this process.

    Args:
        handle: Handle value to probe with ``GetHandleInformation``.

    Returns:
        bool: ``True`` while the handle is valid, ``False`` once it is closed.
    """
    flags = wintypes.DWORD(0)
    return bool(_k32().GetHandleInformation(handle, ctypes.byref(flags)))


@contextlib.contextmanager
def _committed_page(protect: int) -> Generator[int]:
    """Commit one real page with the given protection in this process.

    Args:
        protect: ``PAGE_*`` protection constant for the new page.

    Yields:
        int: Base address of the committed page.
    """
    address = _k32().VirtualAlloc(None, _PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, protect)
    assert address, f"VirtualAlloc failed with error {ctypes.get_last_error()}"
    try:
        yield int(address)
    finally:
        _k32().VirtualFree(address, 0, MEM_RELEASE)


def _unique_pipe_name() -> str:
    r"""Return a fresh, collision-free local named-pipe path.

    Returns:
        str: A ``\\.\pipe\intellicrack_critcov_x64dbg_01_<uuid>`` endpoint.
    """
    return rf"\\.\pipe\intellicrack_critcov_x64dbg_01_{uuid.uuid4().hex}"


def _spawn_server(pipe_name: str, mode: str) -> subprocess.Popen[bytes]:
    """Start the standalone real named-pipe server for ``pipe_name``.

    Args:
        pipe_name: Fully qualified pipe path the server hosts.
        mode: Server behaviour selector from ``realcov_pipe_server``.

    Returns:
        subprocess.Popen[bytes]: The started server; the caller stops it with
        :func:`_terminate_server`.
    """
    return subprocess.Popen(
        [sys.executable, "-m", _SERVER_MODULE, pipe_name, mode],
        cwd=str(_REPO_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _terminate_server(proc: subprocess.Popen[bytes]) -> None:
    """Stop and reap the standalone pipe-server process.

    Args:
        proc: Server process to stop.
    """
    if proc.poll() is None:
        proc.terminate()
    try:
        proc.wait(timeout=_CHILD_WAIT_S)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=_CHILD_WAIT_S)


def _wait_pipe_available(pipe_name: str, deadline_s: float) -> bool:
    """Block until ``pipe_name`` exists, using the real ``WaitNamedPipeW``.

    Args:
        pipe_name: Endpoint to probe.
        deadline_s: Maximum seconds to wait.

    Returns:
        bool: ``True`` once the pipe is available, ``False`` on timeout.
    """
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        if _k32().WaitNamedPipeW(pipe_name, 200):
            return True
        time.sleep(0.05)
    return False


def _spawn_hidden(code: str) -> DesktopProcess:
    """Run ``code`` in a real Python child on a hidden desktop.

    Args:
        code: Python source passed to ``-c``.

    Returns:
        DesktopProcess: The live (or already finished) hidden-desktop child.
    """
    return spawn_on_hidden_desktop(Path(sys.executable), ["-c", code])


def _reap_hidden(proc: DesktopProcess) -> None:
    """Terminate (when still running), wait for, and close a hidden-desktop child.

    Args:
        proc: Process to clean up.
    """
    try:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=_CHILD_WAIT_S)
    finally:
        proc.close()


@contextlib.contextmanager
def _invalid_process_handle(proc: DesktopProcess) -> Generator[None]:
    """Make ``proc`` report a handle the OS rejects, restoring the real one afterwards.

    Args:
        proc: Process whose private ``_hprocess`` data attribute is swapped.

    Yields:
        None: Control while the invalid handle value is in place.
    """
    real_handle = getattr(proc, "_hprocess")
    setattr(proc, "_hprocess", _BOGUS_HANDLE)
    try:
        yield
    finally:
        setattr(proc, "_hprocess", real_handle)


@contextlib.asynccontextmanager
async def _served_bridge(mode: str, *, with_debugger: bool = False) -> AsyncGenerator[X64DbgBridge]:
    """Yield a bridge wired to a real named-pipe server running in ``mode``.

    The bridge is marked plugin-deployed and pointed at the server's pipe. When
    ``with_debugger`` is set a real hidden-desktop child stands in as the
    tracked debugger process so methods that require a running debugger can run.

    Args:
        mode: Server behaviour selector from ``realcov_pipe_server``.
        with_debugger: Whether to track a live hidden-desktop child as the debugger.

    Yields:
        X64DbgBridge: The wired bridge; its pipe, handles, child and server are
        released when the context exits.
    """
    pipe_name = _unique_pipe_name()
    server = _spawn_server(pipe_name, mode)
    debugger: DesktopProcess | None = None
    bridge = X64DbgBridge()
    try:
        if not _wait_pipe_available(pipe_name, _PIPE_READY_TIMEOUT_S):
            pytest.fail(f"server pipe {pipe_name} never became available")
        setattr(bridge, "_PIPE_NAME", pipe_name)
        setattr(bridge, "_plugin_deployed", True)
        if with_debugger:
            debugger = _spawn_hidden(_SLEEP_CODE)
            setattr(bridge, "_process", debugger)
        yield bridge
    finally:
        try:
            await _method(bridge, "_close_connection")()
            _method(bridge, "_release_process_handles")()
        finally:
            setattr(bridge, "_process", None)
            if debugger is not None:
                _reap_hidden(debugger)
            _terminate_server(server)


@pytest.fixture
def hidden_sleeper() -> Iterator[DesktopProcess]:
    """Provide a live Python child sleeping on a hidden desktop.

    Yields:
        DesktopProcess: The running child; terminated and closed on teardown.
    """
    proc = _spawn_hidden(_SLEEP_CODE)
    try:
        yield proc
    finally:
        _reap_hidden(proc)


@pytest.fixture
def own_process_bridge() -> Iterator[X64DbgBridge]:
    """Provide a bridge attached to this very process for real Win32 memory calls.

    Yields:
        X64DbgBridge: Bridge whose cached process handles are released on teardown.
    """
    bridge = X64DbgBridge()
    bridge.attached_pid = os.getpid()
    try:
        yield bridge
    finally:
        _method(bridge, "_release_process_handles")()


def test_resource_labels_named_entry_at_name_level_clears_the_numeric_id() -> None:
    """A string-named entry at depth 1 records the name and drops any numeric id."""
    parent = _ResourcePathLabels(type_id=3, type_name="RT_ICON", res_id=99)
    child = parent.descend(depth=1, is_named=True, entry_id=0, entry_str="MAINICON")
    assert (child.type_id, child.type_name, child.res_id, child.res_name) == (3, "RT_ICON", None, "MAINICON")


def test_resource_labels_numeric_entry_at_name_level_clears_the_name() -> None:
    """An integer entry at depth 1 records the id and drops any previous name."""
    parent = _ResourcePathLabels(type_id=16, type_name="RT_VERSION", res_name="stale")
    child = parent.descend(depth=1, is_named=False, entry_id=42, entry_str=None)
    assert (child.type_id, child.type_name, child.res_id, child.res_name) == (16, "RT_VERSION", 42, None)


def test_resource_labels_below_name_level_keep_every_label() -> None:
    """Entries deeper than the Name/Id level (the language level) change no label."""
    parent = _ResourcePathLabels(type_id=3, type_name="RT_ICON", res_id=7, res_name=None)
    child = parent.descend(depth=2, is_named=False, entry_id=1033, entry_str=None)
    assert child == parent


def test_region_containing_uses_half_open_address_ranges() -> None:
    """The region end address is exclusive and gaps between regions match nothing."""
    low = MemoryRegion(0x1000, 0x1000, "r--", "committed", "private", None)
    high = MemoryRegion(0x3000, 0x2000, "rw-", "committed", "private", None)
    regions = [low, high]
    assert _region_containing(regions, 0x1000) is low
    assert _region_containing(regions, 0x1FFF) is low
    assert _region_containing(regions, 0x2000) is None
    assert _region_containing(regions, 0x4FFF) is high
    assert _region_containing(regions, 0x5000) is None


@pytest.mark.parametrize(
    ("message", "expected_code"),
    [
        ("Command step_into timed out", "timeout"),
        ("x64dbg bridge plugin not available: x64dbg installation not configured", "plugin_unavailable"),
        ("pipe reader failed: broken", "pipe_disconnected"),
        ("something else entirely", "remote_error"),
    ],
)
def test_classify_legacy_error_maps_transport_texts_to_codes(message: str, expected_code: str) -> None:
    """Legacy plugin error texts map to the structured code of their failure mode.

    Args:
        message: Free-form error text.
        expected_code: Structured ``x64dbg_error_code`` that text must classify as.
    """
    assert _classify_legacy_error(message) == expected_code


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (True, 0),
        (False, 0),
        (None, 0),
        (1.5, 0),
        ([0x10], 0),
        (0x10, 0x10),
        ("0x20", 0x20),
        ("not a number", 0),
    ],
)
def test_coerce_address_returns_zero_for_bools_and_non_numeric_payloads(payload: object, expected: int) -> None:
    """Event addresses accept ints and numeric strings; everything else (even ``True``) is ``0``.

    Args:
        payload: Raw ``address`` field of a plugin event.
        expected: Address the bridge must derive from it.
    """
    assert _coerce_address(payload) == expected


@pytest.mark.parametrize(
    ("details", "eligible"),
    [
        ({}, False),
        ({"x64dbg_error_code": "remote_error"}, False),
        ({"x64dbg_error_code": "protocol_violation"}, False),
        ({"x64dbg_error_code": "unknown_command"}, True),
        ({"x64dbg_error_code": "plugin_unavailable"}, True),
        ({"x64dbg_error_code": "timeout"}, True),
        ({"x64dbg_error_code": "pipe_disconnected"}, True),
    ],
)
def test_local_fallback_is_eligible_only_for_transport_errors(*, details: dict[str, Any], eligible: bool) -> None:
    """Only transport or availability failures allow the in-process fallback.

    Args:
        details: ``ToolError.details`` carried by the raised error.
        eligible: Whether a local fallback is appropriate.
    """
    assert _is_local_fallback_eligible(ToolError("failure", details=details)) is eligible


@pytest.mark.parametrize(
    ("mem_type", "expected_type", "expected_module"),
    [
        (MEM_IMAGE, "image", "probe.dll"),
        (MEM_MAPPED, "mapped", None),
        (MEM_PRIVATE, "private", None),
        (0, "unknown", None),
    ],
)
def test_append_committed_region_classifies_the_memory_type(
    mem_type: int,
    expected_type: str,
    expected_module: str | None,
) -> None:
    """The ``VirtualQueryEx`` type flag selects the region type; only images get a module name.

    Args:
        mem_type: ``MEM_*`` type flag stored in the queried structure.
        expected_type: Region type label the bridge must report.
        expected_module: Module name expected (images only).
    """
    mbi = MEMORY_BASIC_INFORMATION()
    mbi.BaseAddress = 0x10000
    mbi.RegionSize = 0x2000
    mbi.State = MEM_COMMIT
    mbi.Protect = PAGE_READWRITE
    mbi.Type = mem_type
    regions: list[MemoryRegion] = []
    _append_committed_region(mbi, regions, lambda _base: "probe.dll")
    assert regions == [MemoryRegion(0x10000, 0x2000, "rw-", "committed", expected_type, expected_module)]


@pytest.mark.parametrize(
    ("dos_header", "expected_offset_text"),
    [
        (b"MZ" + bytes(0x3A) + struct.pack("<I", 0) + bytes(0xC0), "e_lfanew=0x0"),
        (b"MZ" + bytes(0x3A) + struct.pack("<I", 0x1000) + bytes(0xC0), "e_lfanew=0x1000"),
    ],
)
def test_detect_architecture_rejects_an_unusable_e_lfanew(
    tmp_path: Path,
    dos_header: bytes,
    expected_offset_text: str,
) -> None:
    """A zero or out-of-file ``e_lfanew`` is reported instead of guessing an architecture.

    Args:
        tmp_path: Per-test temporary directory.
        dos_header: Bytes of a DOS stub whose ``e_lfanew`` field is unusable.
        expected_offset_text: Offset text the error message must name.
    """
    image = tmp_path / "bad_lfanew.exe"
    image.write_bytes(dos_header)
    with pytest.raises(ToolError) as caught:
        _detect_architecture(image)
    assert "truncated or invalid" in caught.value.message
    assert expected_offset_text in caught.value.message
    assert caught.value.tool_name == "x64dbg"


def test_bridge_pipe_failure_message_appends_the_underlying_cause_only_when_given() -> None:
    """The remediation text gains an ``Underlying error`` suffix only for a real cause."""
    without_cause = _bridge_pipe_failure_message(None)
    with_cause = _bridge_pipe_failure_message("boom")
    assert without_cause.startswith(_REMEDIATION_PREFIX)
    assert "Underlying error" not in without_cause
    assert with_cause == f"{without_cause} Underlying error: boom"


def test_plugin_status_explains_a_deployed_plugin_with_no_connected_pipe(tmp_path: Path) -> None:
    """With the install found and the plugin deployed but no pipe, the diagnostic says to start x64dbg.

    Args:
        tmp_path: Per-test temporary directory used as the x64dbg install path.
    """
    bridge = X64DbgBridge()
    assert bridge.plugin_status["diagnostic"] == _DIAG_NOT_CONFIGURED
    bridge.x64dbg_path = tmp_path
    bridge.state.connected = True
    assert bridge.plugin_status["diagnostic"] == _DIAG_PLUGIN_MISSING
    setattr(bridge, "_plugin_deployed", True)
    status = bridge.plugin_status
    assert status["diagnostic"] == _DIAG_PIPE_DOWN
    assert status["pipe_connected"] is False
    assert status["ready"] is False


def test_watchpoint_event_increments_only_the_first_matching_watchpoint() -> None:
    """A watchpoint event bumps one hit count and still reaches the registered callbacks."""
    bridge = X64DbgBridge()
    first = WatchpointInfo(id=1, address=0x1000, size=4, watch_type="write", enabled=True, hit_count=0)
    second = WatchpointInfo(id=2, address=0x2000, size=4, watch_type="write", enabled=True, hit_count=0)
    twin = WatchpointInfo(id=3, address=0x2000, size=4, watch_type="read", enabled=True, hit_count=0)
    bridge.watchpoints.update({1: first, 2: second, 3: twin})
    seen: list[str] = []

    def record(event_type: str, _message: dict[str, Any]) -> None:
        """Remember the event type delivered to the callback.

        Args:
            event_type: Event name passed by the bridge.
            _message: Event payload (unused).
        """
        seen.append(event_type)

    bridge.register_event_callback(record)
    handle_event = _method(bridge, "_handle_event")
    handle_event({"event": "watchpoint", "address": "0x2000"})
    assert (first.hit_count, second.hit_count, twin.hit_count) == (0, 1, 0)
    handle_event({"event": "watchpoint", "address": 0x3000})
    assert (first.hit_count, second.hit_count, twin.hit_count) == (0, 1, 0)
    assert seen == ["watchpoint", "watchpoint"]


@pytest.mark.asyncio
async def test_cancel_all_step_waiters_cancels_pending_futures_and_drains_the_list() -> None:
    """Shutdown cancels every pending step waiter on its own loop and empties the registry."""
    bridge = X64DbgBridge()
    register = _method(bridge, "_register_step_waiter")
    finished = register()
    pending = register()
    finished.set_result(0x1234)
    _method(bridge, "_cancel_all_step_waiters")()
    await asyncio.wait({pending}, timeout=_WAIT_S)
    assert pending.cancelled()
    assert finished.result() == 0x1234
    assert getattr(bridge, "_step_waiters") == []


@pytest.mark.asyncio
async def test_step_waiter_helpers_leave_finished_futures_alone() -> None:
    """Resolving or cancelling a finished waiter is a no-op; a pending one is resolved or cancelled."""
    loop = asyncio.get_running_loop()
    finished: asyncio.Future[int] = loop.create_future()
    finished.set_result(5)
    _set_step_waiter_result(finished, 9)
    _cancel_step_waiter_future(finished)
    assert finished.result() == 5
    to_resolve: asyncio.Future[int] = loop.create_future()
    _set_step_waiter_result(to_resolve, 9)
    assert to_resolve.result() == 9
    to_cancel: asyncio.Future[int] = loop.create_future()
    _cancel_step_waiter_future(to_cancel)
    with pytest.raises(asyncio.CancelledError):
        await to_cancel


@pytest.mark.asyncio
async def test_terminate_debugger_process_without_a_process_does_nothing() -> None:
    """With no tracked debugger there is nothing to terminate and nothing to report."""
    bridge = X64DbgBridge()
    errors: list[BaseException] = []
    await _method(bridge, "_terminate_debugger_process")(errors)
    assert errors == []
    assert getattr(bridge, "_process") is None


def test_get_cached_process_handle_requires_an_attached_process() -> None:
    """Without an attached pid no handle can be opened."""
    bridge = X64DbgBridge()
    with pytest.raises(ToolError, match="No process attached"):
        _method(bridge, "_get_cached_process_handle")(PROCESS_VM_READ)


def test_get_cached_process_handle_reports_a_failed_open() -> None:
    """``OpenProcess`` rejects pid 0 (the idle process), and the error names the pid and access mask."""
    bridge = X64DbgBridge()
    bridge.attached_pid = 0
    with pytest.raises(ToolError) as caught:
        _method(bridge, "_get_cached_process_handle")(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
    assert caught.value.message == "Failed to open process 0 (access=0x410)"
    assert caught.value.tool_name == "x64dbg"
    assert getattr(bridge, "_process_handles") == {}


@pytest.mark.asyncio
async def test_free_memory_is_false_without_a_process_or_a_usable_handle() -> None:
    """``free_memory`` reports ``False`` when nothing is attached or the process cannot be opened."""
    bridge = X64DbgBridge()
    assert await bridge.free_memory(0x1000) is False
    bridge.attached_pid = 0
    assert await bridge.free_memory(0x1000) is False


@pytest.mark.asyncio
async def test_allocate_memory_requires_an_attached_process() -> None:
    """Allocating with no attached process raises before any Win32 call."""
    bridge = X64DbgBridge()
    with pytest.raises(ToolError, match="No process attached"):
        await bridge.allocate_memory(0x1000)


@pytest.mark.asyncio
async def test_allocate_memory_reports_a_failed_allocation(own_process_bridge: X64DbgBridge) -> None:
    """A request larger than the whole user address space makes ``VirtualAllocEx`` fail.

    Args:
        own_process_bridge: Bridge attached to this process.
    """
    with pytest.raises(ToolError, match="VirtualAllocEx failed"):
        await own_process_bridge.allocate_memory(1 << 62)


@pytest.mark.asyncio
async def test_write_memory_reports_a_failed_write(own_process_bridge: X64DbgBridge) -> None:
    """Writing to the unmapped null page fails and the error names the address.

    Args:
        own_process_bridge: Bridge attached to this process.
    """
    with pytest.raises(ToolError, match=r"WriteProcessMemory failed at 0x0"):
        await own_process_bridge.write_memory(0, b"\x90")


@pytest.mark.parametrize(
    ("method_name", "args"),
    [
        ("_verify_breakpoint_present", (0x401000, "software")),
        ("_verify_breakpoint_applied", (0x401000,)),
        ("_verify_breakpoint_condition", (0x401000, "software", "eax == 1")),
    ],
)
@pytest.mark.asyncio
async def test_breakpoint_verification_surfaces_an_unavailable_plugin(
    method_name: str,
    args: tuple[object, ...],
) -> None:
    """A ``bp_list`` failure other than ``unknown_command`` is re-raised, not swallowed.

    Args:
        method_name: Verification method under test.
        args: Positional arguments for that method.
    """
    bridge = X64DbgBridge()
    with pytest.raises(ToolError) as caught:
        await _method(bridge, method_name)(*args)
    assert caught.value.details == {"x64dbg_error_code": "plugin_unavailable", "command": "bp_list"}


@pytest.mark.asyncio
async def test_await_debuggee_pid_reraises_a_non_recoverable_pipe_error() -> None:
    """A pid-poll failure that is not a missing RPC aborts instead of retrying until the deadline."""
    bridge = X64DbgBridge()
    setattr(bridge, "VERIFY_TIMEOUT", 0.2)
    with pytest.raises(ToolError) as caught:
        await _method(bridge, "_await_debuggee_pid")()
    assert caught.value.details == {"x64dbg_error_code": "plugin_unavailable", "command": "reg_get"}


@pytest.mark.asyncio
async def test_attach_without_an_x64dbg_path_refuses_to_start_a_debugger() -> None:
    """Attaching with no debugger running and no install path fails before spawning anything."""
    bridge = X64DbgBridge()
    with pytest.raises(ToolError, match="x64dbg path not set"):
        await bridge.attach(os.getpid())
    assert getattr(bridge, "_process") is None
    assert bridge.attached_pid is None


@pytest.mark.asyncio
async def test_start_debugger_reports_a_missing_32bit_executable(tmp_path: Path) -> None:
    """The 32-bit debugger is looked up under ``release/x32`` and its absence is reported.

    Args:
        tmp_path: Per-test temporary directory used as an empty x64dbg install.
    """
    bridge = X64DbgBridge()
    bridge.x64dbg_path = tmp_path
    setattr(bridge, "_plugin_deployed", True)
    with pytest.raises(ToolError) as caught:
        await _method(bridge, "_start_debugger")(is_64bit=False)
    expected_exe = tmp_path / "release" / "x32" / "x32dbg.exe"
    assert caught.value.message == f"x64dbg executable not found: {expected_exe}"
    assert getattr(bridge, "_process") is None


@pytest.mark.asyncio
async def test_connect_failure_clears_the_client_and_appends_the_diagnostic(tmp_path: Path) -> None:
    """Connecting to a pipe nobody hosts raises with the cause and the plugin diagnostic.

    Args:
        tmp_path: Per-test temporary directory used as the x64dbg install path.
    """
    bridge = X64DbgBridge()
    bridge.x64dbg_path = tmp_path
    bridge.state.connected = True
    setattr(bridge, "_plugin_deployed", True)
    setattr(bridge, "_PIPE_NAME", _unique_pipe_name())
    with pytest.raises(ToolError) as caught:
        await _method(bridge, "_connect")()
    message = caught.value.message
    assert message.startswith("Failed to connect to x64dbg pipe: ")
    assert "Named pipe not available" in message
    assert message.endswith(f". {_DIAG_PIPE_DOWN}")
    assert isinstance(caught.value.__cause__, ToolError)
    assert getattr(bridge, "_pipe_client") is None


@pytest.mark.asyncio
async def test_establish_bridge_connection_wraps_a_pipe_wait_timeout() -> None:
    """A pipe that never appears fails with the remediation text, the cause, and a disconnect code."""
    bridge = X64DbgBridge()
    setattr(bridge, "_PIPE_NAME", _unique_pipe_name())
    setattr(bridge, "_PIPE_READY_TIMEOUT_SECONDS", 0.0)
    with pytest.raises(ToolError) as caught:
        await _method(bridge, "_establish_bridge_connection")()
    assert caught.value.message.startswith(_REMEDIATION_PREFIX)
    assert "Underlying error: Timed out waiting for x64dbg bridge pipe" in caught.value.message
    assert caught.value.details == {"x64dbg_error_code": "pipe_disconnected"}
    assert caught.value.tool_name == "x64dbg"


def test_read_process_memory_block_returns_none_for_an_unreadable_address() -> None:
    """Reading the null page fails and yields ``None``, while a mapped buffer reads back exactly."""
    probe = ctypes.create_string_buffer(b"intellicrack-probe", 32)
    handle = _current_process_handle()
    assert _read_process_memory_block(handle, 0, 16) is None
    assert _read_process_memory_block(handle, ctypes.addressof(probe), 18) == b"intellicrack-probe"


def _unicode_string_block(length: int, maximum_length: int, buffer_address: int) -> ctypes.Array[ctypes.c_char]:
    """Lay out an x64 ``RTL_USER_PROCESS_PARAMETERS`` prefix ending in a ``UNICODE_STRING``.

    Args:
        length: ``Length`` field in bytes.
        maximum_length: ``MaximumLength`` field in bytes.
        buffer_address: ``Buffer`` pointer field.

    Returns:
        ctypes.Array[ctypes.c_char]: Memory whose ``CommandLine`` string sits at offset 0x70.
    """
    blob = bytes(_COMMAND_LINE_OFFSET_X64) + struct.pack("<HHIQ", length, maximum_length, 0, buffer_address)
    return ctypes.create_string_buffer(blob, len(blob))


def test_read_unicode_string_returns_none_when_the_descriptor_is_unreadable() -> None:
    """A parameters block at an unmapped address cannot supply a UNICODE_STRING descriptor."""
    handle = _current_process_handle()
    assert _read_unicode_string_from_params(handle, 0, _UNICODE_STRING_X64_POINTER_SIZE) is None


def test_read_unicode_string_decodes_valid_strings_and_rejects_empty_ones() -> None:
    """A populated descriptor decodes to its text; a zero length or null buffer yields ``None``."""
    handle = _current_process_handle()
    text = "C:\\Tools\\sample.exe --flag"
    text_buffer = ctypes.create_unicode_buffer(text)
    length = len(text) * 2
    valid = _unicode_string_block(length, length + 2, ctypes.addressof(text_buffer))
    zero_length = _unicode_string_block(0, 2, ctypes.addressof(text_buffer))
    null_buffer = _unicode_string_block(4, 4, 0)
    pointer_size = _UNICODE_STRING_X64_POINTER_SIZE
    assert _read_unicode_string_from_params(handle, ctypes.addressof(valid), pointer_size) == text
    assert _read_unicode_string_from_params(handle, ctypes.addressof(zero_length), pointer_size) is None
    assert _read_unicode_string_from_params(handle, ctypes.addressof(null_buffer), pointer_size) is None


def test_extract_command_line_returns_none_for_an_invalid_process_handle() -> None:
    """``NtQueryInformationProcess`` rejects a null handle, so no PEB can be located."""
    assert _extract_command_line_from_peb(0) is None


@pytest.mark.spawns_process
def test_extract_command_line_needs_read_access_to_the_child(hidden_sleeper: DesktopProcess) -> None:
    """With ``PROCESS_VM_READ`` the child's real command line is returned; without it the PEB is unreadable.

    Args:
        hidden_sleeper: Live child process.
    """
    expected = subprocess.list2cmdline([sys.executable, "-c", _SLEEP_CODE])
    readable = _open_process(hidden_sleeper.pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
    query_only = _open_process(hidden_sleeper.pid, PROCESS_QUERY_INFORMATION)
    try:
        assert _extract_command_line_from_peb(readable) == expected
        assert _extract_command_line_from_peb(query_only) is None
    finally:
        _close_handle(readable)
        _close_handle(query_only)


@pytest.mark.spawns_process
def test_read_iswow64_status_reports_native_children_and_rejects_handles_without_query_rights(
    hidden_sleeper: DesktopProcess,
) -> None:
    """A native 64-bit child reads as 64-bit; a handle lacking query rights makes ``IsWow64Process`` fail.

    ``IsWow64Process`` requires ``PROCESS_QUERY_INFORMATION`` or
    ``PROCESS_QUERY_LIMITED_INFORMATION``; a real handle opened with only
    ``SYNCHRONIZE`` carries neither.

    Args:
        hidden_sleeper: Live child process (a 64-bit Python interpreter).
    """
    handle = _open_process(hidden_sleeper.pid, PROCESS_QUERY_INFORMATION)
    try:
        assert _read_iswow64_status(handle, hidden_sleeper.pid) is True
    finally:
        _close_handle(handle)
    synchronize_only = _open_process(hidden_sleeper.pid, _SYNCHRONIZE)
    try:
        assert _read_iswow64_status(synchronize_only, hidden_sleeper.pid) is None
    finally:
        _close_handle(synchronize_only)


@pytest.mark.spawns_process
def test_release_process_handles_keeps_closing_after_a_bad_handle(hidden_sleeper: DesktopProcess) -> None:
    """A handle that cannot be closed is skipped; later handles are still closed and the cache is emptied.

    Args:
        hidden_sleeper: Live child process whose handle is cached.
    """
    bridge = X64DbgBridge()
    real = _open_process(hidden_sleeper.pid, PROCESS_QUERY_INFORMATION)
    handles = getattr(bridge, "_process_handles")
    handles[1] = cast("int", [])
    handles[2] = real
    try:
        _method(bridge, "_release_process_handles")()
        assert handles == {}
        assert _handle_is_open(real) is False
    finally:
        if _handle_is_open(real):
            _close_handle(real)


@pytest.mark.spawns_process
def test_debugger_pid_is_the_tracked_process_id(hidden_sleeper: DesktopProcess) -> None:
    """``debugger_pid`` is ``None`` without a debugger and the child's pid with one.

    Args:
        hidden_sleeper: Live child process standing in as the debugger.
    """
    bridge = X64DbgBridge()
    assert bridge.debugger_pid is None
    setattr(bridge, "_process", hidden_sleeper)
    try:
        assert bridge.debugger_pid == hidden_sleeper.pid
    finally:
        setattr(bridge, "_process", None)


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_raise_if_process_exited_reports_the_exit_code() -> None:
    """A debugger that already exited raises with its pid, exit code, and a disconnect code."""
    child = _spawn_hidden(_EXIT_CODE_SEVEN)
    bridge = X64DbgBridge()
    try:
        assert child.wait(timeout=_CHILD_WAIT_S) == 7
        setattr(bridge, "_process", child)
        with pytest.raises(ToolError) as caught:
            await _method(bridge, "_raise_if_process_exited")("step_into")
        assert f"pid={child.pid}" in caught.value.message
        assert "code=7" in caught.value.message
        assert caught.value.details == {"x64dbg_error_code": "pipe_disconnected", "command": "step_into"}
        assert getattr(bridge, "_pipe_client") is None
    finally:
        setattr(bridge, "_process", None)
        _reap_hidden(child)


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_raise_if_process_exited_tolerates_a_failed_liveness_probe(hidden_sleeper: DesktopProcess) -> None:
    """When the exit-code query itself fails the probe is inconclusive and the call returns normally.

    Args:
        hidden_sleeper: Live child process standing in as the debugger.
    """
    bridge = X64DbgBridge()
    setattr(bridge, "_process", hidden_sleeper)
    try:
        with _invalid_process_handle(hidden_sleeper):
            await _method(bridge, "_raise_if_process_exited")("run")
        assert getattr(bridge, "_process") is hidden_sleeper
    finally:
        setattr(bridge, "_process", None)


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_recover_dead_debugger_process_resets_the_session_state() -> None:
    """A dead tracked debugger is closed and every piece of session state is reset."""
    child = _spawn_hidden(_EXIT_CODE_SEVEN)
    bridge = X64DbgBridge()
    try:
        assert child.wait(timeout=_CHILD_WAIT_S) == 7
        setattr(bridge, "_process", child)
        bridge.attached_pid = 4321
        bridge.state.connected = True
        bridge.state.tool_running = True
        assert await _method(bridge, "_recover_dead_debugger_process")() is True
        assert getattr(bridge, "_process") is None
        assert bridge.attached_pid is None
        assert bridge.state.connected is False
        assert bridge.state.tool_running is False
        assert getattr(bridge, "_process_handles") == {}
    finally:
        setattr(bridge, "_process", None)
        _reap_hidden(child)


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_recover_dead_debugger_process_keeps_a_process_it_cannot_probe(hidden_sleeper: DesktopProcess) -> None:
    """A failed liveness query is not proof of death: nothing is torn down and ``False`` is returned.

    Args:
        hidden_sleeper: Live child process standing in as the debugger.
    """
    bridge = X64DbgBridge()
    setattr(bridge, "_process", hidden_sleeper)
    bridge.state.connected = True
    try:
        with _invalid_process_handle(hidden_sleeper):
            assert await _method(bridge, "_recover_dead_debugger_process")() is False
        assert getattr(bridge, "_process") is hidden_sleeper
        assert bridge.state.connected is True
    finally:
        setattr(bridge, "_process", None)


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_terminate_debugger_process_records_a_terminate_failure(hidden_sleeper: DesktopProcess) -> None:
    """An OS error while terminating is collected, and the process is still unregistered and dropped.

    Args:
        hidden_sleeper: Live child process standing in as the debugger.
    """
    bridge = X64DbgBridge()
    setattr(bridge, "_process", hidden_sleeper)
    errors: list[BaseException] = []
    with _invalid_process_handle(hidden_sleeper):
        await _method(bridge, "_terminate_debugger_process")(errors)
    assert len(errors) == 1
    assert isinstance(errors[0], OSError)
    assert "GetExitCodeProcess" in str(errors[0])
    assert getattr(bridge, "_process") is None


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_send_pipe_command_wraps_client_errors_with_a_classified_code() -> None:
    """A message the client refuses to send becomes a classified ``ToolError`` and the pipe stays usable."""
    async with _served_bridge(srv.MODE_ECHO_SUCCESS) as bridge:
        send = _method(bridge, "_send_pipe_command")
        with pytest.raises(ToolError) as caught:
            await send("exec", {"command": "A" * (_PIPE_MAX_MESSAGE_BYTES + 1024)})
        assert caught.value.message == "Message exceeds maximum size"
        assert caught.value.details == {"x64dbg_error_code": "remote_error", "command": "exec"}
        assert caught.value.tool_name == "x64dbg"
        assert await send("ping") == {"echo_command": "ping"}


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_send_command_returns_empty_text_when_the_result_has_no_output() -> None:
    """A dict result without an ``output`` key yields an empty string, not ``"None"``."""
    async with _served_bridge(srv.MODE_ECHO_SUCCESS, with_debugger=True) as bridge:
        output = await _method(bridge, "_send_command")("anything")
    assert isinstance(output, str)
    assert len(output) == 0


@pytest.mark.spawns_process
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method_name", "expected_pid"),
    [("run", 4242), ("pause", 4242), ("stop", None)],
)
async def test_run_pause_and_stop_each_issue_one_pipe_command(method_name: str, expected_pid: int | None) -> None:
    """Each control call sends exactly one command (the one-shot server then drops); only ``stop`` detaches state.

    Args:
        method_name: Control method under test.
        expected_pid: Attached pid expected after the call.
    """
    async with _served_bridge(srv.MODE_DROP_AFTER_ONE) as bridge:
        bridge.attached_pid = 4242
        bridge.state.process_attached = True
        bridge.state.target_pid = 4242
        await _method(bridge, method_name)()
        client = getattr(bridge, "_pipe_client")
        assert client is not None
        await wait_until(lambda: not client.is_connected, budget=_WAIT_S, interval=0.02)
        assert client.is_connected is False
        assert bridge.attached_pid == expected_pid
        assert bridge.state.target_pid == expected_pid
        assert bridge.state.process_attached is (expected_pid is not None)


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_load_without_a_reported_pid_still_marks_the_binary_loaded(real_pe_dll: Path) -> None:
    """When ``$pid`` never reports a process the binary is still loaded but nothing is marked attached.

    Args:
        real_pe_dll: Path of a real System32 DLL used as the binary.
    """
    expected_target = _resolved(real_pe_dll)
    async with _served_bridge(srv.MODE_ECHO_SUCCESS, with_debugger=True) as bridge:
        setattr(bridge, "VERIFY_TIMEOUT", 0.2)
        await bridge.load(real_pe_dll, "-x")
        assert bridge.state.binary_loaded is True
        assert bridge.state.process_attached is False
        assert bridge.state.target_path == expected_target
        assert bridge.attached_pid is None
        assert bridge.plugin_status["pipe_connected"] is True


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_attach_issues_the_command_and_records_the_attached_process() -> None:
    """Attaching to a real process sends the attach command and records the target in the state."""
    pid = os.getpid()
    async with _served_bridge(srv.MODE_ECHO_SUCCESS, with_debugger=True) as bridge:
        await bridge.attach(pid)
        assert bridge.plugin_status["pipe_connected"] is True
        assert bridge.attached_pid == pid
        assert bridge.state.target_pid == pid
        assert bridge.state.process_attached is True
        assert bridge.state.connected is True
        assert bridge.state.tool_running is True


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_disassemble_at_falls_back_to_capstone_on_a_non_list_reply() -> None:
    """A ``disasm`` reply that is not a list falls back to decoding the real bytes with capstone."""
    code = b"\x90\xc3" + b"\x06" * 43
    buffer = ctypes.create_string_buffer(code, len(code))
    address = ctypes.addressof(buffer)
    async with _served_bridge(srv.MODE_ECHO_SUCCESS) as bridge:
        bridge.attached_pid = os.getpid()
        lines = await bridge.disassemble_at(address, 3)
    decoded = [(line.address, line.bytes_str, line.mnemonic, line.operands) for line in lines]
    assert decoded == [(address, "90", "nop", ""), (address + 1, "c3", "ret", "")]


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_disassemble_at_propagates_a_remote_plugin_error() -> None:
    """A genuine remote error is raised to the caller instead of silently using the local decoder."""
    async with _served_bridge(srv.MODE_ECHO) as bridge:
        with pytest.raises(ToolError) as caught:
            await bridge.disassemble_at(0x1000, 1)
        assert caught.value.message == "Command failed"
        assert caught.value.details == {"x64dbg_error_code": "remote_error", "command": "disasm"}


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_breakpoint_verification_rejects_a_non_list_bp_list_reply() -> None:
    """``bp_list`` must answer with a list; any other shape is a protocol violation naming its type."""
    async with _served_bridge(srv.MODE_ECHO_SUCCESS) as bridge:
        with pytest.raises(ToolError) as applied:
            await _method(bridge, "_verify_breakpoint_applied")(0x401000)
        assert applied.value.message == "set_breakpoint verification: bp_list returned dict, expected list"
        assert applied.value.details == {"x64dbg_error_code": "protocol_violation", "address": "0x401000"}
        with pytest.raises(ToolError) as condition:
            await _method(bridge, "_verify_breakpoint_condition")(0x401000, "software", "eax == 1")
        assert condition.value.message == "set_breakpoint condition verification: bp_list returned dict, expected list"
        assert condition.value.details == {"x64dbg_error_code": "protocol_violation", "address": "0x401000"}


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_wait_for_pipe_ready_and_establish_connection_succeed_against_a_live_pipe() -> None:
    """With a real pipe hosted, readiness returns and the connection is established and verified."""
    async with _served_bridge(srv.MODE_ECHO_SUCCESS) as bridge:
        await _method(bridge, "_wait_for_pipe_ready")()
        assert bridge.plugin_status["pipe_connected"] is False
        await _method(bridge, "_establish_bridge_connection")()
        assert bridge.plugin_status["pipe_connected"] is True


@pytest.mark.spawns_process
@pytest.mark.asyncio
@pytest.mark.parametrize(("is_64bit", "expected_ip"), [(True, 0x1_0000_1234), (False, 0x1234)])
async def test_step_returns_the_event_ip_when_the_register_read_fails(*, is_64bit: bool, expected_ip: int) -> None:
    """If registers cannot be read after the paused event, the event's pointer (masked for x86) is returned.

    Args:
        is_64bit: Whether the bridge is in 64-bit mode.
        expected_ip: Instruction pointer the step must return.
    """
    async with _served_bridge(srv.MODE_DROP_AFTER_ONE) as bridge:
        bridge.is_64bit = is_64bit
        step = asyncio.ensure_future(_method(bridge, "_await_step_complete")("step_into"))
        try:
            await wait_until(lambda: bool(getattr(bridge, "_step_waiters")), budget=_WAIT_S, interval=0.01)
            assert len(getattr(bridge, "_step_waiters")) == 1
            _method(bridge, "_handle_event")({"event": "paused", "address": hex(0x1_0000_1234)})
            assert await asyncio.wait_for(step, timeout=_STEP_WAIT_S) == expected_ip
        finally:
            if not step.done():
                step.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await step


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_set_memory_protection_verifies_each_exact_rights_mapping() -> None:
    """Each exact-match right is verified against the real page protection and reported as verified."""
    cases: list[tuple[int, PageRights]] = [
        (PAGE_READONLY, "read_only"),
        (PAGE_READWRITE, "read_write"),
        (PAGE_EXECUTE_READ, "execute_read"),
        (PAGE_EXECUTE_READWRITE, "execute_readwrite"),
        (PAGE_EXECUTE, "execute"),
        (PAGE_NOACCESS, "no_access"),
    ]
    async with _served_bridge(srv.MODE_ECHO_SUCCESS, with_debugger=True) as bridge:
        bridge.attached_pid = os.getpid()
        for protect, rights in cases:
            with _committed_page(protect) as page:
                result = await bridge.set_memory_protection(page + 0x10, rights)
            assert result == {
                "success": True,
                "address": hex(page + 0x10),
                "rights": rights,
                "guard": False,
                "verified": True,
            }, rights


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_set_memory_protection_rejects_a_page_that_kept_its_protection() -> None:
    """When the real page still reports other rights, the mismatch is raised with both protections."""
    async with _served_bridge(srv.MODE_ECHO_SUCCESS, with_debugger=True) as bridge:
        bridge.attached_pid = os.getpid()
        with _committed_page(PAGE_READWRITE) as page, pytest.raises(ToolError) as caught:
            await bridge.set_memory_protection(page, "read_only", guard=True)
    assert "protection 'rw-', expected 'r--'" in caught.value.message
    assert caught.value.details["x64dbg_error_code"] == "remote_error"
    assert caught.value.details["observed_protection"] == "rw-"
    assert caught.value.details["expected_protection"] == "r--"
    assert caught.value.details["guard"] is True


@pytest.mark.spawns_process
@pytest.mark.asyncio
@pytest.mark.parametrize("rights", ["write_copy", "execute_writecopy"])
async def test_set_memory_protection_checks_copy_rights_by_change_from_the_prior_value(rights: PageRights) -> None:
    """Rights with no rwx encoding are verified by change; an unchanged page is rejected with its prior value.

    Args:
        rights: Copy-on-write right under test.
    """
    async with _served_bridge(srv.MODE_ECHO_SUCCESS, with_debugger=True) as bridge:
        bridge.attached_pid = os.getpid()
        with _committed_page(PAGE_READWRITE) as page, pytest.raises(ToolError) as caught:
            await bridge.set_memory_protection(page, rights)
    assert "still reports protection 'rw-'" in caught.value.message
    assert caught.value.details["prior_protection"] == "rw-"
    assert caught.value.details["observed_protection"] == "rw-"
    assert caught.value.details["rights"] == rights


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_set_memory_protection_reports_an_address_outside_every_committed_region() -> None:
    """The null page is not committed, so verification fails with the address and rights in the details."""
    async with _served_bridge(srv.MODE_ECHO_SUCCESS, with_debugger=True) as bridge:
        bridge.attached_pid = os.getpid()
        with pytest.raises(ToolError) as caught:
            await bridge.set_memory_protection(0x10, "read_write")
    assert "no committed region covers 0x10 after setpagerights" in caught.value.message
    assert caught.value.details == {
        "x64dbg_error_code": "remote_error",
        "address": "0x10",
        "rights": "read_write",
        "guard": False,
    }
