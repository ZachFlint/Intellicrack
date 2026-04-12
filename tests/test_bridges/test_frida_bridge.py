# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""End-to-end tests for FridaBridge native parity features.

Tests run against real Frida runtime attached to real Windows processes.
Requires frida-python to be installed.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import sys
import time
from typing import TYPE_CHECKING, Final, cast


if TYPE_CHECKING:
    from collections.abc import Coroutine, Generator

import pytest

from intellicrack.core.types import (
    ApiResolverMatch,
    ChildProcessInfo,
    CrashInfo,
    FridaDeviceInfo,
    FridaProcessEntry,
    HookInfo,
    ImportInfo,
    StalkerEvent,
    StalkerTrace,
    SymbolInfo,
    ThreadInfo,
    ToolDefinition,
    ToolError,
    ToolName,
)


frida = pytest.importorskip("frida", reason="frida-python required for bridge tests")

from intellicrack.bridges.frida_bridge import FridaBridge  # noqa: E402


_logger = logging.getLogger(__name__)

_ADDR: Final[int] = 0x00401000
_ADDR2: Final[int] = 0x00402000
_PID: Final[int] = 1234
_PARENT_PID: Final[int] = 5678
_LINE_NUMBER: Final[int] = 100
_TIMESTAMP: Final[float] = 1700000000.0
_DURATION: Final[float] = 42.5
_NOTEPAD_STARTUP_DELAY: Final[float] = 1.0
_BRIDGE_SLEEP: Final[float] = 0.3
_STALKER_SLEEP: Final[float] = 1.0
_MIN_FUNCTIONS: Final[int] = 36
_ALLOC_SIZE: Final[int] = 4096
_SMALL_ALLOC: Final[int] = 256
_STALKER_LIMIT: Final[int] = 500
_TRACE_EVENT_COUNT: Final[int] = 2
_KERNEL32_MIN_IMPORTS: Final[int] = 10
_NOTEPAD_MIN_REGIONS: Final[int] = 20
_NTDLL_BASE_MIN: Final[int] = 0x70000000


def _run_async(coro: Coroutine[object, object, object]) -> object:
    """Run an async coroutine synchronously for test use.

    Args:
        coro: Awaitable coroutine to execute.

    Returns:
        object: The coroutine's return value.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_symbol_info_full() -> None:
    """Verify SymbolInfo dataclass with all fields set."""
    sym = SymbolInfo(
        name="CreateFileW",
        address=_ADDR,
        module_name="kernel32.dll",
        file_name="fileapi.c",
        line_number=_LINE_NUMBER,
    )
    assert sym.name == "CreateFileW"
    assert sym.address == _ADDR
    assert sym.module_name == "kernel32.dll"
    assert sym.file_name == "fileapi.c"
    assert sym.line_number == _LINE_NUMBER


def test_symbol_info_none_optionals() -> None:
    """Verify SymbolInfo accepts None for optional fields."""
    sym = SymbolInfo(
        name="sub_401000",
        address=_ADDR,
        module_name=None,
        file_name=None,
        line_number=None,
    )
    assert sym.module_name is None
    assert sym.file_name is None
    assert sym.line_number is None


def test_crash_info_construction() -> None:
    """Verify CrashInfo dataclass fields."""
    info = CrashInfo(
        pid=_PID,
        process_name="target.exe",
        summary="access violation",
        report="EXCEPTION_ACCESS_VIOLATION at 0x401000",
        parameters={"code": "c0000005"},
        timestamp=_TIMESTAMP,
    )
    assert info.pid == _PID
    assert info.process_name == "target.exe"
    assert info.summary == "access violation"
    assert "EXCEPTION_ACCESS_VIOLATION" in info.report
    assert info.parameters["code"] == "c0000005"
    assert info.timestamp == _TIMESTAMP


def test_child_process_info_full() -> None:
    """Verify ChildProcessInfo with all fields."""
    info = ChildProcessInfo(
        pid=_PID,
        parent_pid=_PARENT_PID,
        origin="spawn",
        identifier="com.example.app",
        path="C:\\target.exe",
        argv=["target.exe", "--flag"],
    )
    assert info.pid == _PID
    assert info.parent_pid == _PARENT_PID
    assert info.origin == "spawn"
    assert info.identifier == "com.example.app"
    assert info.path == "C:\\target.exe"
    assert info.argv == ["target.exe", "--flag"]


def test_child_process_info_none_optionals() -> None:
    """Verify ChildProcessInfo accepts None for optional fields."""
    info = ChildProcessInfo(
        pid=_PID,
        parent_pid=_PARENT_PID,
        origin="fork",
        identifier=None,
        path=None,
        argv=[],
    )
    assert info.identifier is None
    assert info.path is None
    assert info.argv == []


def test_stalker_event_call() -> None:
    """Verify StalkerEvent call event with destination."""
    evt = StalkerEvent(
        event_type="call",
        from_address=_ADDR,
        to_address=_ADDR2,
        depth=1,
    )
    assert evt.event_type == "call"
    assert evt.from_address == _ADDR
    assert evt.to_address == _ADDR2
    assert evt.depth == 1


def test_stalker_event_exec_no_destination() -> None:
    """Verify StalkerEvent exec event with None destination."""
    evt = StalkerEvent(
        event_type="exec",
        from_address=_ADDR,
        to_address=None,
        depth=0,
    )
    assert evt.to_address is None


def test_stalker_trace_with_events() -> None:
    """Verify StalkerTrace with populated events list."""
    events = [
        StalkerEvent(event_type="call", from_address=_ADDR, to_address=_ADDR2, depth=0),
        StalkerEvent(event_type="ret", from_address=_ADDR2, to_address=_ADDR, depth=0),
    ]
    trace = StalkerTrace(
        thread_id=_LINE_NUMBER,
        events=events,
        event_count=2,
        duration_ms=_DURATION,
    )
    assert trace.thread_id == _LINE_NUMBER
    assert len(trace.events) == _TRACE_EVENT_COUNT
    assert trace.event_count == _TRACE_EVENT_COUNT
    assert trace.duration_ms == _DURATION


def test_stalker_trace_empty() -> None:
    """Verify StalkerTrace can be empty."""
    trace = StalkerTrace(thread_id=0, events=[], event_count=0, duration_ms=0.0)
    assert trace.events == []
    assert trace.event_count == 0


def test_frida_device_info() -> None:
    """Verify FridaDeviceInfo dataclass fields."""
    dev = FridaDeviceInfo(id="local", name="Local System", device_type="local")
    assert dev.id == "local"
    assert dev.name == "Local System"
    assert dev.device_type == "local"


def test_api_resolver_match() -> None:
    """Verify ApiResolverMatch dataclass fields."""
    match = ApiResolverMatch(name="kernel32.dll!CreateFileW", address=_ADDR)
    assert match.name == "kernel32.dll!CreateFileW"
    assert match.address == _ADDR


def test_tool_definition_returns_frida_tool() -> None:
    """Verify tool_definition has correct tool name."""
    bridge = FridaBridge()
    defn = bridge.tool_definition
    assert isinstance(defn, ToolDefinition)
    assert defn.tool_name == ToolName.FRIDA


def test_all_function_names_have_methods() -> None:
    """Every function in tool_definition must map to a real method."""
    bridge = FridaBridge()
    defn = bridge.tool_definition
    missing: list[str] = []
    for func in defn.functions:
        method_name = func.name.split(".", 1)[1] if "." in func.name else func.name
        if not hasattr(bridge, method_name):
            missing.append(func.name)
    assert not missing, f"Tool functions without methods: {missing}"


def test_function_count_minimum() -> None:
    """Verify at least 36 functions are defined (18 original + 18 new)."""
    bridge = FridaBridge()
    defn = bridge.tool_definition
    assert len(defn.functions) >= _MIN_FUNCTIONS


def test_no_duplicate_function_names() -> None:
    """Verify no duplicate function names in tool_definition."""
    bridge = FridaBridge()
    defn = bridge.tool_definition
    names = [f.name for f in defn.functions]
    dupes = [n for n in names if names.count(n) > 1]
    assert len(names) == len(set(names)), f"Duplicates: {dupes}"


def test_new_functions_present() -> None:
    """Verify all 18 new functions from the parity plan are registered."""
    bridge = FridaBridge()
    defn = bridge.tool_definition
    names = {f.name for f in defn.functions}

    expected_new = {
        "frida.enumerate_threads",
        "frida.protect_memory",
        "frida.find_base_address",
        "frida.resolve_symbol",
        "frida.find_functions_named",
        "frida.resolve_api",
        "frida.replace_function",
        "frida.enumerate_processes",
        "frida.stalker_follow",
        "frida.stalker_unfollow",
        "frida.enable_child_gating",
        "frida.disable_child_gating",
        "frida.get_pending_children",
        "frida.resume_child",
        "frida.enable_crash_reporting",
        "frida.get_crashes",
        "frida.enumerate_devices",
        "frida.connect_device",
    }
    missing = expected_new - names
    assert missing == set(), f"Missing new functions: {missing}"


def test_fixed_functions_present() -> None:
    """Verify the 3 fixed functions use correct names."""
    bridge = FridaBridge()
    defn = bridge.tool_definition
    names = {f.name for f in defn.functions}

    assert "frida.enumerate_imports" in names
    assert "frida.allocate_memory" in names
    assert "frida.get_memory_regions" in names
    assert "frida.get_memory_ranges" not in names


@pytest.fixture(scope="module")
def notepad_process() -> Generator[subprocess.Popen[bytes]]:
    """Spawn a real notepad.exe for Frida to attach to.

    Yields:
        Generator[subprocess.Popen[bytes]]: The running notepad process.
    """
    proc = subprocess.Popen(
        ["notepad.exe"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(_NOTEPAD_STARTUP_DELAY)
    yield proc
    proc.terminate()
    proc.wait(timeout=5)


@pytest.fixture(scope="module")
def frida_bridge(notepad_process: subprocess.Popen[bytes]) -> Generator[FridaBridge]:
    """Create a FridaBridge attached to notepad.exe.

    Args:
        notepad_process: The running notepad process fixture.

    Yields:
        Generator[FridaBridge]: An initialized and attached FridaBridge instance.
    """
    bridge = FridaBridge()
    _run_async(bridge.initialize())
    _run_async(bridge.attach(notepad_process.pid))
    time.sleep(_BRIDGE_SLEEP)
    yield bridge
    try:
        _run_async(bridge.shutdown())
    except Exception:
        _logger.debug("frida_bridge_fixture_shutdown_failed", exc_info=True)


_WORKER_THREAD_JS: Final[str] = """
var k32 = Process.findModuleByName('kernel32.dll');
var Sleep = k32.getExportByName('Sleep');
var code = Memory.alloc(4096);
Memory.protect(code, 4096, 'rwx');
var bytes = [
    0x48, 0x83, 0xEC, 0x28,
    0x41, 0xBD, 0x64, 0x00, 0x00, 0x00
];
bytes.push(0x49, 0xBC);
var a = Sleep;
for (var i = 0; i < 8; i++) {
    bytes.push(a.and(0xFF).toInt32());
    a = a.shr(8);
}
bytes = bytes.concat([
    0xB9, 0x0A, 0x00, 0x00, 0x00,
    0x41, 0xFF, 0xD4,
    0x41, 0xFF, 0xCD,
    0x75, 0xF3,
    0x48, 0x83, 0xC4, 0x28,
    0x31, 0xC0, 0xC3
]);
code.writeByteArray(bytes);
var CreateThread = new NativeFunction(
    k32.getExportByName('CreateThread'),
    'pointer', ['pointer', 'size_t', 'pointer', 'pointer', 'uint32', 'pointer']
);
var tidBuf = Memory.alloc(4);
CreateThread(ptr(0), 0, code, ptr(0), 0, tidBuf);
send({ type: 'worker', tid: tidBuf.readU32() });
"""


@pytest.fixture(scope="module")
def worker_thread(frida_bridge: FridaBridge) -> Generator[int]:
    """Spawn a busy worker thread inside notepad for Stalker testing.

    Creates a thread running x86-64 machine code that loops calling Sleep(10)
    a fixed number of times, ensuring user-mode execution for Stalker to trace.
    The thread is created via a persistent script to prevent GC of the code
    memory while the thread is still running.

    Args:
        frida_bridge: Attached FridaBridge instance.

    Yields:
        Generator[int]: The thread ID of the busy worker thread.
    """
    tids_before: set[int] = {t.tid for t in cast("list[ThreadInfo]", _run_async(frida_bridge.enumerate_threads()))}
    script_id: str = _run_async(frida_bridge.execute_persistent_script(_WORKER_THREAD_JS))
    time.sleep(_BRIDGE_SLEEP)
    tids_after: set[int] = {t.tid for t in cast("list[ThreadInfo]", _run_async(frida_bridge.enumerate_threads()))}
    new_tids = tids_after - tids_before
    assert len(new_tids) >= 1, "worker thread must appear in thread list after creation"
    yield next(iter(new_tids))
    try:
        _run_async(frida_bridge.unload_script(script_id))
    except Exception:
        _logger.debug("worker_thread_fixture_cleanup_failed", exc_info=True)


@pytest.fixture(scope="module")
def unattached_bridge() -> Generator[FridaBridge]:
    """Create a FridaBridge that is initialized but not attached.

    Yields:
        Generator[FridaBridge]: An initialized FridaBridge instance.
    """
    bridge = FridaBridge()
    _run_async(bridge.initialize())
    yield bridge
    try:
        _run_async(bridge.shutdown())
    except Exception:
        _logger.debug("unattached_bridge_fixture_shutdown_failed", exc_info=True)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_enumerate_processes(unattached_bridge: FridaBridge) -> None:
    """Verify enumerate_processes returns real running processes."""
    result: list[FridaProcessEntry] = _run_async(unattached_bridge.enumerate_processes())
    assert len(result) > 0
    first = result[0]
    assert isinstance(first.pid, int)
    assert first.pid > 0
    assert isinstance(first.name, str)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_enumerate_devices(unattached_bridge: FridaBridge) -> None:
    """Verify enumerate_devices returns at least the local device."""
    result = cast("list[FridaDeviceInfo]", _run_async(unattached_bridge.enumerate_devices()))
    assert len(result) >= 1
    local_found = False
    for dev in result:
        assert isinstance(dev, FridaDeviceInfo)
        assert dev.id
        assert dev.name
        if dev.device_type == "local":
            local_found = True
    assert local_found


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_connect_device_local(unattached_bridge: FridaBridge) -> None:
    """Verify connecting to local device succeeds."""
    result = _run_async(unattached_bridge.connect_device("local"))
    assert isinstance(result, FridaDeviceInfo)
    assert result.device_type == "local"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_enumerate_threads(frida_bridge: FridaBridge) -> None:
    """Verify enumerate_threads returns multiple real threads from notepad."""
    result = cast("list[ThreadInfo]", _run_async(frida_bridge.enumerate_threads()))
    assert len(result) >= 2, f"notepad should have multiple threads, got {len(result)}"
    tids: set[int] = set()
    for thread in result:
        assert isinstance(thread, ThreadInfo)
        assert thread.tid > 0
        assert thread.state in {"running", "stopped", "waiting", "uninterruptible", "halted"}
        tids.add(thread.tid)
    assert len(tids) == len(result), "all TIDs must be unique"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_enumerate_imports_kernel32(frida_bridge: FridaBridge) -> None:
    """Verify enumerate_imports returns real imports from kernel32.dll."""
    result = cast("list[ImportInfo]", _run_async(frida_bridge.enumerate_imports("kernel32.dll")))
    assert len(result) >= _KERNEL32_MIN_IMPORTS, f"kernel32 should have many imports, got {len(result)}"
    resolved_count = 0
    seen_functions: set[str] = set()
    for imp in result:
        assert isinstance(imp, ImportInfo)
        assert imp.function, "every import must have a function name"
        seen_functions.add(imp.function)
        if imp.address > 0:
            resolved_count += 1
    assert resolved_count >= _KERNEL32_MIN_IMPORTS, f"at least {_KERNEL32_MIN_IMPORTS} imports should resolve, got {resolved_count}"
    assert "NtCreateFile" in seen_functions or "RtlInitUnicodeString" in seen_functions, (
        "kernel32 imports should contain well-known ntdll functions"
    )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_find_base_address_ntdll(frida_bridge: FridaBridge) -> None:
    """Verify find_base_address returns ntdll.dll base in high address range."""
    result = _run_async(frida_bridge.find_base_address("ntdll.dll"))
    assert isinstance(result, int)
    assert result >= _NTDLL_BASE_MIN, f"ntdll base 0x{result:X} should be in high system DLL range (>= 0x{_NTDLL_BASE_MIN:X})"
    assert result % 0x10000 == 0, f"base 0x{result:X} must be 64KB-aligned (PE section alignment)"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_find_base_address_kernel32(frida_bridge: FridaBridge) -> None:
    """Verify find_base_address returns kernel32.dll base, distinct from ntdll."""
    k32_base = _run_async(frida_bridge.find_base_address("kernel32.dll"))
    ntdll_base = _run_async(frida_bridge.find_base_address("ntdll.dll"))
    assert isinstance(k32_base, int)
    assert k32_base >= _NTDLL_BASE_MIN, f"kernel32 base 0x{k32_base:X} should be in high system DLL range"
    assert k32_base % 0x10000 == 0, f"base 0x{k32_base:X} must be 64KB-aligned"
    assert k32_base != ntdll_base, "kernel32 and ntdll must have different bases"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_get_memory_regions(frida_bridge: FridaBridge) -> None:
    """Verify get_memory_regions returns real memory layout with executable regions."""
    from intellicrack.core.types import MemoryRegion  # noqa: PLC0415

    result = cast("list[MemoryRegion]", _run_async(frida_bridge.get_memory_regions()))
    assert len(result) >= _NOTEPAD_MIN_REGIONS, f"notepad should have many memory regions, got {len(result)}"
    has_executable = False
    has_readable = False
    for region in result:
        assert isinstance(region, MemoryRegion)
        assert region.base_address >= 0
        assert region.size > 0, f"region at 0x{region.base_address:X} has zero size"
        if "x" in region.protection:
            has_executable = True
        if "r" in region.protection:
            has_readable = True
    assert has_executable, "process must have at least one executable region"
    assert has_readable, "process must have at least one readable region"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_resolve_api_createfile(frida_bridge: FridaBridge) -> None:
    """Verify resolve_api finds CreateFileW in kernel32."""
    result = cast("list[ApiResolverMatch]", _run_async(frida_bridge.resolve_api("exports:*!CreateFileW")))
    assert len(result) >= 1
    found = False
    for api_match in result:
        assert isinstance(api_match, ApiResolverMatch)
        if "CreateFileW" in api_match.name:
            found = True
            assert api_match.address > 0
    assert found


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_resolve_symbol(frida_bridge: FridaBridge) -> None:
    """Verify resolve_symbol resolves a known function address to its symbol."""
    matches = cast(
        "list[ApiResolverMatch]",
        _run_async(frida_bridge.resolve_api("exports:ntdll.dll!NtCreateFile")),
    )
    assert len(matches) >= 1, "NtCreateFile must exist in ntdll"
    func_addr = matches[0].address
    result = _run_async(frida_bridge.resolve_symbol(func_addr))
    assert isinstance(result, SymbolInfo)
    assert result.address == func_addr, f"resolved address 0x{result.address:X} must match query 0x{func_addr:X}"
    assert result.name, "resolved function must have a symbol name"
    assert "NtCreateFile" in result.name, f"symbol name should contain NtCreateFile, got '{result.name}'"
    assert result.module_name is not None, "known function should resolve with a module name"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_find_functions_named(frida_bridge: FridaBridge) -> None:
    """Verify find_functions_named locates NtCreateFile in ntdll."""
    result = cast("list[SymbolInfo]", _run_async(frida_bridge.find_functions_named("NtCreateFile")))
    assert len(result) >= 1, "NtCreateFile must exist in ntdll on every Windows system"
    sym = result[0]
    assert isinstance(sym, SymbolInfo)
    assert sym.address >= _NTDLL_BASE_MIN, f"NtCreateFile address 0x{sym.address:X} should be in system DLL range"
    assert sym.name, "resolved symbol must have a name"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_allocate_memory(frida_bridge: FridaBridge) -> None:
    """Verify allocate_memory returns writable memory at a valid address."""
    addr: int = _run_async(frida_bridge.allocate_memory(_ALLOC_SIZE))
    assert isinstance(addr, int)
    assert addr > 0x10000, f"allocated address 0x{addr:X} is suspiciously low"
    probe = bytes([0xDE, 0xAD])
    _run_async(frida_bridge.write_memory(addr, probe))
    readback: bytes = _run_async(frida_bridge.read_memory(addr, len(probe)))
    assert readback == probe, f"alloc'd memory at 0x{addr:X} should be writable: wrote {probe!r}, read {readback!r}"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_protect_memory(frida_bridge: FridaBridge) -> None:
    """Verify protect_memory succeeds on allocated memory."""
    addr: int = _run_async(frida_bridge.allocate_memory(_ALLOC_SIZE))
    result: bool = _run_async(frida_bridge.protect_memory(addr, _ALLOC_SIZE, "rwx"))
    assert result


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_read_write_memory_roundtrip(frida_bridge: FridaBridge) -> None:
    """Verify memory write then read returns the same bytes."""
    addr: int = _run_async(frida_bridge.allocate_memory(_SMALL_ALLOC))
    _run_async(frida_bridge.protect_memory(addr, _SMALL_ALLOC, "rwx"))

    test_bytes = bytes([0x41, 0x42, 0x43, 0x44])
    _run_async(frida_bridge.write_memory(addr, test_bytes))
    read_back: bytes = _run_async(frida_bridge.read_memory(addr, len(test_bytes)))
    assert read_back == test_bytes


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_hook_and_remove(frida_bridge: FridaBridge) -> None:
    """Verify hook_function creates a hook and remove_hook removes it."""
    hook: HookInfo = _run_async(frida_bridge.hook_function("kernel32.dll!GetTickCount"))
    assert isinstance(hook, HookInfo)
    assert hook.id
    assert hook.active

    removed: bool = _run_async(frida_bridge.remove_hook(hook.id))
    assert removed


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_stalker_follow_and_unfollow(
    frida_bridge: FridaBridge,
    worker_thread: int,
) -> None:
    """Verify stalker_follow collects real call events from a busy worker thread."""
    trace_id: str = _run_async(
        frida_bridge.stalker_follow(
            thread_id=worker_thread,
            events="call",
            limit=_STALKER_LIMIT,
        ),
    )
    assert isinstance(trace_id, str)
    assert trace_id

    time.sleep(_STALKER_SLEEP)

    trace: StalkerTrace = _run_async(frida_bridge.stalker_unfollow(thread_id=worker_thread))
    assert isinstance(trace, StalkerTrace)
    assert trace.thread_id == worker_thread
    assert trace.event_count > 0, f"Stalker must have collected events from worker thread {worker_thread} after {_STALKER_SLEEP}s, got 0"
    assert len(trace.events) == trace.event_count, f"events list length {len(trace.events)} must match event_count {trace.event_count}"
    first_event = trace.events[0]
    assert isinstance(first_event, StalkerEvent)
    assert first_event.event_type == "call", f"expected 'call' event type, got '{first_event.event_type}'"
    assert first_event.from_address > 0, "call event must have a non-zero source address"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_child_gating_not_supported_on_windows(frida_bridge: FridaBridge) -> None:
    """Verify child gating raises ToolError on Windows (not supported by Frida)."""
    with pytest.raises(ToolError):
        _run_async(frida_bridge.enable_child_gating())


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_get_pending_children_empty(frida_bridge: FridaBridge) -> None:
    """Verify get_pending_children returns typed empty list when gating not active."""
    children: list[ChildProcessInfo] = _run_async(frida_bridge.get_pending_children())
    assert isinstance(children, list)
    assert not children, "no children should be gated without enable_child_gating"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_crash_reporting_lifecycle(frida_bridge: FridaBridge) -> None:
    """Verify enable_crash_reporting succeeds and get_crashes returns typed list."""
    _run_async(frida_bridge.enable_crash_reporting())

    _run_async(frida_bridge.enable_crash_reporting())

    crashes: list[CrashInfo] = _run_async(frida_bridge.get_crashes())
    assert isinstance(crashes, list)
    assert not crashes, "no crashes should have occurred on healthy notepad"
    for crash in crashes:
        assert isinstance(crash, CrashInfo)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_enumerate_processes_contains_notepad(
    frida_bridge: FridaBridge,
    notepad_process: subprocess.Popen[bytes],
) -> None:
    """Verify our spawned notepad shows up in the process list."""
    result: list[FridaProcessEntry] = _run_async(frida_bridge.enumerate_processes())
    pids = {p.pid for p in result}
    assert notepad_process.pid in pids
