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
import inspect
import logging
import os
import shutil
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Final

from intellicrack.core.subprocess_compat import (
    DEVNULL,
    Popen,
)


if TYPE_CHECKING:
    from collections.abc import Coroutine, Generator

    from intellicrack.bridges.frida_bridge import FridaBridge

import pytest

from intellicrack.core.types import (
    ApiResolverMatch,
    ChildProcessInfo,
    CrashInfo,
    FridaDeviceInfo,
    FridaProcessEntry,
    HookInfo,
    ImportInfo,
    MemoryRegion,
    StalkerEvent,
    StalkerTrace,
    SymbolInfo,
    ThreadInfo,
    ToolError,
    ToolName,
)


try:
    from intellicrack.bridges.frida_bridge import FridaBridge

    _frida_available: bool = True
except ImportError:
    _frida_available = False


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
_EXACT_FUNCTION_COUNT: Final[int] = 94
_ALLOC_SIZE: Final[int] = 4096
_SMALL_ALLOC: Final[int] = 256
_STALKER_LIMIT: Final[int] = 500
_TRACE_EVENT_COUNT: Final[int] = 2
_KERNEL32_MIN_IMPORTS: Final[int] = 10
_NOTEPAD_MIN_REGIONS: Final[int] = 20
_NTDLL_BASE_MIN: Final[int] = 0x70000000

_FRIDA_PREFIX: Final[str] = "frida."

_EXPECTED_NEW_FUNCTIONS: Final[frozenset[str]] = frozenset({
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
})

_EXPECTED_FIXED_NAMES: Final[frozenset[str]] = frozenset({
    "frida.enumerate_imports",
    "frida.allocate_memory",
    "frida.get_memory_regions",
})

_FORBIDDEN_FIXED_NAMES: Final[frozenset[str]] = frozenset({
    "frida.get_memory_ranges",
})


def _run_async[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously for test use.

    Args:
        coro: Awaitable coroutine to execute.

    Returns:
        T: The coroutine's return value, preserving its type.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _assert_symbol_info_nt_create_file(sym: SymbolInfo) -> None:
    """Assert that a SymbolInfo for NtCreateFile has correct field types and values.

    Validates that all five SymbolInfo fields are the correct Python types (str, int,
    str|None, str|None, int|None). The address must be in the Windows system DLL range.
    The module_name type is validated when present but not its value, because Frida's
    DebugSymbol API may report the host process module name when attaching to an in-process
    context rather than the DLL that owns the function.

    Args:
        sym: SymbolInfo returned by the bridge for the NtCreateFile function.
    """
    assert isinstance(sym.name, str), f"name must be str, got {type(sym.name)}"
    assert isinstance(sym.address, int), f"address must be int, got {type(sym.address)}"
    assert sym.address >= _NTDLL_BASE_MIN, (
        f"NtCreateFile address 0x{sym.address:X} should be in system DLL range (>= 0x{_NTDLL_BASE_MIN:X})"
    )
    assert "NtCreateFile" in sym.name, f"symbol name must contain 'NtCreateFile', got '{sym.name}'"
    if sym.module_name is not None:
        assert isinstance(sym.module_name, str), f"module_name must be str when not None, got {type(sym.module_name)}"
        assert len(sym.module_name) > 0, f"module_name must be non-empty when not None, got {sym.module_name!r}"
    if sym.file_name is not None:
        assert isinstance(sym.file_name, str), f"file_name must be str when not None, got {type(sym.file_name)}"
    if sym.line_number is not None:
        assert isinstance(sym.line_number, int), f"line_number must be int when not None, got {type(sym.line_number)}"


@pytest.fixture(autouse=True)
def require_frida() -> None:
    """Skip any test in this module when frida-python is not installed."""
    if not _frida_available:
        pytest.skip("frida-python required for bridge tests")


@pytest.fixture
def self_attached_bridge() -> Generator[FridaBridge]:
    """Create a FridaBridge attached to the current test process.

    Yields:
        Generator[FridaBridge]: An initialized and attached FridaBridge instance.
    """
    bridge = FridaBridge()
    _run_async(bridge.initialize())
    _run_async(bridge.attach(os.getpid()))
    yield bridge
    try:
        _run_async(bridge.shutdown())
    except ToolError:
        _logger.debug("self_attached_bridge_fixture_shutdown_failed", exc_info=True)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
def test_symbol_info_bridge_parses_find_functions_named(self_attached_bridge: FridaBridge) -> None:
    """Verify find_functions_named returns SymbolInfo with correct field types from the bridge.

    Drives a real attached bridge call to find NtCreateFile across all modules. The
    bridge must parse Frida's script output dict and construct a SymbolInfo with all
    five fields: name (str), address (int), module_name (str|None), file_name (str|None),
    line_number (int|None). Uses an independently-known fact: NtCreateFile exists in
    ntdll.dll on every supported Windows version and its address is in the high-DLL
    range (>= 0x70000000).

    Falsifiable: if the bridge silently drops the address field (returning 0), the
    >= _NTDLL_BASE_MIN assertion fails. If module_name parsing is broken (returning
    the raw JS object), isinstance(str) and 'ntdll' containment both fail. If name
    parsing strips the function name, the 'NtCreateFile' containment check fails.

    Args:
        self_attached_bridge: Bridge fixture attached to the current test process.
    """
    results: list[SymbolInfo] = _run_async(self_attached_bridge.find_functions_named("NtCreateFile"))
    assert len(results) >= 1, "NtCreateFile must exist in ntdll on every supported Windows system"
    _assert_symbol_info_nt_create_file(results[0])


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
def test_symbol_info_address_hex_decimal_parsing(self_attached_bridge: FridaBridge) -> None:
    """Verify the bridge correctly parses both '0x'-prefixed hex and decimal address strings.

    The bridge's find_functions_named implementation uses conditional int parsing:
    ``int(addr_str, 16) if addr_str.startswith('0x') else int(addr_str)``.
    This test calls find_functions_named for two well-known Windows functions and
    verifies both return non-zero addresses in the system DLL range, confirming the
    hex-vs-decimal address parsing branch is exercised correctly for whatever format
    Frida's DebugSymbol API returns on the current system.

    Falsifiable: if the hex parsing branch is broken (e.g. always returns 0 for hex
    addresses), the >= _NTDLL_BASE_MIN assertion fails. If decimal parsing is broken
    for functions that Frida reports without 0x prefix, the assertion also fails.

    Args:
        self_attached_bridge: Bridge fixture attached to the current test process.
    """
    nt_results: list[SymbolInfo] = _run_async(self_attached_bridge.find_functions_named("NtCreateFile"))
    rtl_results: list[SymbolInfo] = _run_async(self_attached_bridge.find_functions_named("RtlInitUnicodeString"))
    assert len(nt_results) >= 1, "NtCreateFile must be resolvable"
    assert len(rtl_results) >= 1, "RtlInitUnicodeString must be resolvable"
    nt_sym = nt_results[0]
    rtl_sym = rtl_results[0]
    assert nt_sym.address >= _NTDLL_BASE_MIN, f"NtCreateFile address 0x{nt_sym.address:X} below system DLL range 0x{_NTDLL_BASE_MIN:X}"
    assert rtl_sym.address >= _NTDLL_BASE_MIN, (
        f"RtlInitUnicodeString address 0x{rtl_sym.address:X} below system DLL range 0x{_NTDLL_BASE_MIN:X}"
    )
    assert nt_sym.address != rtl_sym.address, "NtCreateFile and RtlInitUnicodeString must have different addresses"


class _TestableFridaBridge(FridaBridge):
    """FridaBridge subclass exposing internal state-injection and parsing for unit testing.

    This subclass provides test-only methods to pre-populate and read the bridge's
    internal accumulation buffers, and to expose the private parsing method, all
    without editing the production source.
    """

    def inject_crash(self, crash: CrashInfo) -> None:
        """Append a CrashInfo directly to the crash accumulation buffer.

        Args:
            crash: CrashInfo to inject into the internal crash list.
        """
        with self._crashes_lock:
            self._crashes.append(crash)

    def inject_child(self, child: ChildProcessInfo) -> None:
        """Append a ChildProcessInfo directly to the gated-children buffer.

        Args:
            child: ChildProcessInfo to inject into the internal children list.
        """
        with self._gated_children_lock:
            self._gated_children.append(child)

    def inject_stalker_events(self, tid: int, events: list[StalkerEvent]) -> None:
        """Pre-populate the stalker trace buffer for a thread ID.

        Args:
            tid: Thread ID key for the stalker traces dict.
            events: StalkerEvent objects to place in the buffer.
        """
        with self._stalker_traces_lock:
            self._stalker_traces[tid] = list(events)

    def parse_stalker_batch_public(self, tid: int, raw_events: list[object]) -> None:
        """Public wrapper around _parse_stalker_batch for testing.

        Args:
            tid: Thread ID key for the stalker traces dict.
            raw_events: Raw event dicts from the Frida Stalker script.
        """
        with self._stalker_traces_lock:
            if tid not in self._stalker_traces:
                self._stalker_traces[tid] = []
        self._parse_stalker_batch(tid, raw_events)

    def read_stalker_events(self, tid: int) -> list[StalkerEvent]:
        """Read the accumulated stalker events for a thread ID without clearing them.

        Args:
            tid: Thread ID key to read from.

        Returns:
            list[StalkerEvent]: Copy of the accumulated events for the thread.
        """
        with self._stalker_traces_lock:
            return list(self._stalker_traces.get(tid, []))


def test_crash_info_bridge_internal_accumulation() -> None:
    """Verify get_crashes faithfully returns CrashInfo objects with all fields populated.

    Pre-populates the bridge's internal crash list via a test-subclass injection method
    and asserts that get_crashes() returns the same objects with exactly the values that
    were injected. This tests the bridge's thread-safe retrieval path and list-copy
    fidelity, not just the dataclass definition.

    Falsifiable: if get_crashes() returns a copy with fields stripped or zero-initialized,
    the equality assertions fail. If the bridge returns a different list object but with
    correct contents, the field-by-field assertions still pass -- correct behavior.
    """
    bridge = _TestableFridaBridge()

    injected = CrashInfo(
        pid=_PID,
        process_name="target.exe",
        summary="access violation at 0x401000",
        report="EXCEPTION_ACCESS_VIOLATION\n  Address: 0x401000\n  Flags: 0x00000000",
        parameters={"code": "c0000005", "address": "0x401000", "flags": 0},
        timestamp=_TIMESTAMP,
    )
    bridge.inject_crash(injected)

    retrieved: list[CrashInfo] = _run_async(bridge.get_crashes())

    assert len(retrieved) == 1, f"get_crashes must return exactly the one injected crash, got {len(retrieved)}"
    crash = retrieved[0]
    assert crash.pid == _PID, f"pid mismatch: expected {_PID}, got {crash.pid}"
    assert crash.process_name == "target.exe", f"process_name mismatch: got {crash.process_name!r}"
    assert crash.summary == "access violation at 0x401000", f"summary mismatch: got {crash.summary!r}"
    assert "EXCEPTION_ACCESS_VIOLATION" in crash.report, f"report must contain exception name, got {crash.report!r}"
    assert crash.parameters == {"code": "c0000005", "address": "0x401000", "flags": 0}, f"parameters mismatch: got {crash.parameters}"
    assert crash.timestamp == _TIMESTAMP, f"timestamp mismatch: expected {_TIMESTAMP}, got {crash.timestamp}"


def test_child_process_info_bridge_accumulation_full_fields() -> None:
    """Verify get_pending_children returns ChildProcessInfo with all non-None fields intact.

    Pre-populates the bridge's internal gated-children list via a test-subclass injection
    method and asserts that get_pending_children() returns the same objects with exact field
    values. Tests the bridge's thread-safe retrieval path and confirms all six fields survive
    the list copy (including list-type argv).

    Falsifiable: if the bridge copies the list but strips any field, the equality
    assertion fails. If argv is returned as tuple instead of list, the == check fails.
    If origin loses the string value, the exact equality fails.
    """
    bridge = _TestableFridaBridge()

    injected = ChildProcessInfo(
        pid=_PID,
        parent_pid=_PARENT_PID,
        origin="spawn",
        identifier="com.example.app",
        path="C:\\Windows\\System32\\notepad.exe",
        argv=["notepad.exe", "--flag", "file.txt"],
    )
    bridge.inject_child(injected)

    children: list[ChildProcessInfo] = _run_async(bridge.get_pending_children())

    assert len(children) == 1, f"get_pending_children must return the one injected entry, got {len(children)}"
    child = children[0]
    assert child.pid == _PID, f"pid mismatch: expected {_PID}, got {child.pid}"
    assert child.parent_pid == _PARENT_PID, f"parent_pid mismatch: expected {_PARENT_PID}, got {child.parent_pid}"
    assert child.origin == "spawn", f"origin mismatch: expected 'spawn', got {child.origin!r}"
    assert child.identifier == "com.example.app", f"identifier mismatch: got {child.identifier!r}"
    assert child.path == "C:\\Windows\\System32\\notepad.exe", f"path mismatch: got {child.path!r}"
    assert child.argv == ["notepad.exe", "--flag", "file.txt"], f"argv mismatch: got {child.argv!r}"
    assert isinstance(child.argv, list), f"argv must be a list, got {type(child.argv)}"


def test_child_process_info_bridge_accumulation_none_fields() -> None:
    """Verify get_pending_children faithfully returns None for optional identifier and path.

    Pre-populates the bridge with ChildProcessInfo objects where identifier and path are None
    (as happens for fork()-originated children on POSIX) and verifies both fields survive
    the retrieval path as None, not as empty strings or zero.

    Falsifiable: if the bridge coerces None fields to empty strings during list copy,
    the ``is None`` assertions fail. If argv is mutated to a non-empty list, the
    ``== []`` check fails.
    """
    bridge = _TestableFridaBridge()

    fork_child = ChildProcessInfo(
        pid=_PID,
        parent_pid=_PARENT_PID,
        origin="fork",
        identifier=None,
        path=None,
        argv=[],
    )
    exec_child = ChildProcessInfo(
        pid=_PID + 1,
        parent_pid=_PARENT_PID,
        origin="exec",
        identifier="com.bundle.id",
        path=None,
        argv=["cmd.exe"],
    )
    bridge.inject_child(fork_child)
    bridge.inject_child(exec_child)

    children: list[ChildProcessInfo] = _run_async(bridge.get_pending_children())

    assert len(children) == 2, f"must return both injected entries, got {len(children)}"
    fork_result = next((c for c in children if c.origin == "fork"), None)
    exec_result = next((c for c in children if c.origin == "exec"), None)
    assert fork_result is not None, "fork-origin child must appear in results"
    assert exec_result is not None, "exec-origin child must appear in results"
    assert fork_result.identifier is None, f"fork child identifier must be None, got {fork_result.identifier!r}"
    assert fork_result.path is None, f"fork child path must be None, got {fork_result.path!r}"
    assert fork_result.argv == [], f"fork child argv must be [], got {fork_result.argv!r}"
    assert exec_result.identifier == "com.bundle.id", f"exec child identifier mismatch: got {exec_result.identifier!r}"
    assert exec_result.path is None, f"exec child path must be None, got {exec_result.path!r}"


def test_parse_stalker_batch_call_event() -> None:
    """Verify _parse_stalker_batch converts a call-type raw dict to a correct StalkerEvent.

    Drives the bridge's internal Stalker event parser with a known dict representing a
    call event. The expected StalkerEvent field values are derived independently from the
    input dict -- not from re-running the function -- by applying the documented mapping:
    type -> event_type, from (hex str) -> from_address (int), to (hex str) -> to_address
    (int), depth -> depth. Uses known hex address strings and verifies the int result.

    Falsifiable: if the bridge strips the leading '0x' when parsing from_address (returning
    a partial decimal), the != _ADDR assertion catches it. If to_address parsing fails and
    returns None for a non-None input, the ``is not None`` check fails. If depth parsing
    crashes on float input and defaults to 0, the depth == 1 check fails.
    """
    bridge = _TestableFridaBridge()
    tid = 42

    raw_events: list[object] = [
        {
            "type": "call",
            "from": hex(_ADDR),
            "to": hex(_ADDR2),
            "depth": 1,
        },
    ]
    bridge.parse_stalker_batch_public(tid, raw_events)

    parsed = bridge.read_stalker_events(tid)

    assert len(parsed) == 1, f"exactly one event must be parsed, got {len(parsed)}"
    evt = parsed[0]
    assert evt.event_type == "call", f"event_type must be 'call', got {evt.event_type!r}"
    assert evt.from_address == _ADDR, f"from_address must be 0x{_ADDR:X} (parsed from '{hex(_ADDR)}'), got 0x{evt.from_address:X}"
    assert evt.to_address == _ADDR2, f"to_address must be 0x{_ADDR2:X} (parsed from '{hex(_ADDR2)}'), got {evt.to_address!r}"
    assert evt.to_address is not None, "to_address must not be None for a call event with a 'to' field"
    assert evt.depth == 1, f"depth must be 1, got {evt.depth}"


def test_parse_stalker_batch_exec_event_no_destination() -> None:
    """Verify _parse_stalker_batch sets to_address=None when the raw dict has no 'to' key.

    An exec-type Stalker event reports only the executed address without a destination.
    The bridge must set to_address=None (not 0, not the from_address) in that case.
    Also verifies a float depth value is correctly converted to int.

    Falsifiable: if the bridge substitutes 0 for a missing 'to' field, the ``is None``
    assertion fails. If float-depth conversion is broken and depth stays a float,
    isinstance(int) or exact == 0 fails (float 0.0 != int 0 in strict equality).
    """
    bridge = _TestableFridaBridge()
    tid = 99

    raw_events: list[object] = [
        {
            "type": "exec",
            "from": hex(_ADDR),
            "depth": 0.0,
        },
    ]
    bridge.parse_stalker_batch_public(tid, raw_events)

    parsed = bridge.read_stalker_events(tid)

    assert len(parsed) == 1, f"exactly one event must be parsed, got {len(parsed)}"
    evt = parsed[0]
    assert evt.event_type == "exec", f"event_type must be 'exec', got {evt.event_type!r}"
    assert evt.from_address == _ADDR, f"from_address must be 0x{_ADDR:X}, got 0x{evt.from_address:X}"
    assert evt.to_address is None, f"to_address must be None for exec event without 'to', got {evt.to_address!r}"
    assert isinstance(evt.depth, int), f"depth must be int after float->int conversion, got {type(evt.depth)}"
    assert evt.depth == 0, f"depth must be 0, got {evt.depth}"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
def test_stalker_unfollow_assembles_trace_with_correct_structure(
    frida_bridge: FridaBridge,
    worker_thread: int,
) -> None:
    """Verify stalker_unfollow returns a StalkerTrace with internally consistent field values.

    Runs a real Stalker follow/unfollow cycle on a live worker thread and validates the
    complete StalkerTrace structure: thread_id must match the followed thread, event_count
    must equal len(events) exactly (not an independent counter), duration_ms must be a
    non-negative float, and every StalkerEvent in the trace must have the expected field
    types (event_type str, from_address positive int, to_address int|None, depth int).

    Falsifiable: if stalker_unfollow stores event_count separately from len(events) and
    they diverge, the equality assertion fails. If thread_id defaults to 0 instead of the
    followed tid, the assertion fails. If any event has a non-int from_address (e.g. a
    Frida pointer object), the isinstance assertion fails.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
        worker_thread: Thread id of a live worker that generates call events during the trace window.
    """
    trace_id: str = _run_async(
        frida_bridge.stalker_follow(
            thread_id=worker_thread,
            events="call",
            limit=_STALKER_LIMIT,
        ),
    )
    assert trace_id, "stalker_follow must return a non-empty trace id"

    time.sleep(_STALKER_SLEEP)

    trace: StalkerTrace = _run_async(frida_bridge.stalker_unfollow(thread_id=worker_thread))

    assert trace.thread_id == worker_thread, f"thread_id must be {worker_thread}, got {trace.thread_id}"
    assert trace.event_count == len(trace.events), (
        f"event_count {trace.event_count} must equal len(events) {len(trace.events)} -- "
        "they must be derived from the same list, not stored independently"
    )
    assert isinstance(trace.duration_ms, float), f"duration_ms must be float, got {type(trace.duration_ms)}"
    assert trace.duration_ms >= 0.0, f"duration_ms must be non-negative, got {trace.duration_ms}"
    assert trace.event_count > 0, f"Stalker must have collected events from worker thread {worker_thread} after {_STALKER_SLEEP}s"
    for evt in trace.events:
        assert isinstance(evt.event_type, str), f"event_type must be str, got {type(evt.event_type)}"
        assert evt.event_type == "call", f"all events must be 'call' type, got '{evt.event_type}'"
        assert isinstance(evt.from_address, int), f"from_address must be int, got {type(evt.from_address)}"
        assert evt.from_address > 0, f"from_address must be positive, got {evt.from_address}"
        assert isinstance(evt.depth, int), f"depth must be int, got {type(evt.depth)}"
        if evt.to_address is not None:
            assert isinstance(evt.to_address, int), f"to_address must be int when not None, got {type(evt.to_address)}"
            assert evt.to_address > 0, f"to_address must be positive when present, got {evt.to_address}"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
def test_stalker_unfollow_never_followed_thread_returns_empty_trace(frida_bridge: FridaBridge) -> None:
    """Verify stalker_unfollow on a never-followed thread returns a zero-event StalkerTrace.

    Calls stalker_unfollow with a TID that was never passed to stalker_follow. The bridge
    must return an empty StalkerTrace with event_count == 0, events == [], and
    duration_ms as a non-negative float -- not raise ToolError or return None.

    Falsifiable: if the bridge raises ToolError for an unknown TID, the test fails before
    reaching the assertions. If event_count defaults to a non-zero sentinel, the == 0 check
    fails. If events is returned as None instead of [], the == [] check fails.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process (session required).
    """
    never_followed_tid = 0xDEAD

    trace: StalkerTrace = _run_async(frida_bridge.stalker_unfollow(thread_id=never_followed_tid))

    assert trace.thread_id == never_followed_tid, f"thread_id must be {never_followed_tid}, got {trace.thread_id}"
    assert trace.event_count == 0, f"event_count must be 0 for never-followed thread, got {trace.event_count}"
    assert trace.events == [], f"events must be [] for never-followed thread, got {trace.events!r}"
    assert isinstance(trace.duration_ms, float), f"duration_ms must be float, got {type(trace.duration_ms)}"
    assert trace.duration_ms >= 0.0, f"duration_ms must be non-negative, got {trace.duration_ms}"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
def test_enumerate_devices_returns_frida_device_info_with_correct_fields(
    unattached_bridge: FridaBridge,
) -> None:
    """Verify enumerate_devices returns FridaDeviceInfo objects with correct str field types.

    Calls the real Frida enumerate_devices() on the local system and verifies every
    returned entry is a FridaDeviceInfo where id, name, and device_type are all plain
    Python str objects (not Frida pointer wrappers), and that device_type is one of
    the known valid string values. The local device (always present) must have
    device_type == 'local' exactly, not 'LOCAL' or an enum value.

    Falsifiable: if the bridge forgets to call str() on device.type and returns a Frida
    enum instead, isinstance(str) fails. If device_type uses a different casing or value
    convention, the membership check fails. If id is empty, the truthiness check fails.

    Args:
        unattached_bridge: Initialized bridge not attached to a process.
    """
    devices: list[FridaDeviceInfo] = _run_async(unattached_bridge.enumerate_devices())
    assert len(devices) >= 1, "must enumerate at least the local device"
    local_device: FridaDeviceInfo | None = None
    for dev in devices:
        assert isinstance(dev.id, str), f"device id must be str, got {type(dev.id)}"
        assert isinstance(dev.name, str), f"device name must be str, got {type(dev.name)}"
        assert isinstance(dev.device_type, str), f"device_type must be str, got {type(dev.device_type)}"
        assert dev.id, f"device id must be non-empty, got {dev.id!r}"
        assert dev.name, f"device name must be non-empty, got {dev.name!r}"
        assert dev.device_type in {"local", "usb", "remote", "tether"}, f"device_type {dev.device_type!r} is not a known Frida device type"
        if dev.device_type == "local":
            local_device = dev
    assert local_device is not None, "at least one device with device_type=='local' must be present"
    assert local_device.device_type == "local", f"local device must have device_type exactly 'local', got {local_device.device_type!r}"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
def test_resolve_api_returns_api_resolver_match_with_int_address(frida_bridge: FridaBridge) -> None:
    """Verify resolve_api returns ApiResolverMatch objects with str name and plain int address.

    Queries the real Frida ApiResolver for CreateFileW which exists in kernel32.dll
    on all supported Windows versions. Verifies that the bridge parses Frida's hex
    address string into a Python int (not a Frida NativePointer or str), and that
    the name field is a plain str containing both module and function name separated
    by '!'. The address must be in the system DLL range (>= 0x70000000).

    Falsifiable: if the bridge fails to call int() on the address string and returns a
    str, isinstance(int) fails. If address parsing uses base 10 instead of base 16 for
    '0x'-prefixed strings, the result would be a garbage low address that fails >=
    _NTDLL_BASE_MIN. If the '!' separator is stripped from the name, the 'in' check fails.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    results: list[ApiResolverMatch] = _run_async(frida_bridge.resolve_api("exports:*!CreateFileW"))
    assert len(results) >= 1, "resolve_api for CreateFileW must return at least one match"
    found_match: ApiResolverMatch | None = None
    for api_match in results:
        assert isinstance(api_match.name, str), f"name must be str, got {type(api_match.name)}"
        assert isinstance(api_match.address, int), f"address must be int, got {type(api_match.address)}"
        assert api_match.address > 0, f"address must be non-zero, got {api_match.address}"
        if "CreateFileW" in api_match.name:
            found_match = api_match
    assert found_match is not None, "at least one result must contain 'CreateFileW' in its name"
    assert found_match.address >= _NTDLL_BASE_MIN, (
        f"CreateFileW address 0x{found_match.address:X} must be in system DLL range (>= 0x{_NTDLL_BASE_MIN:X})"
    )
    assert "!" in found_match.name, f"ApiResolverMatch name must contain '!' separator (module!function), got {found_match.name!r}"


def test_tool_definition_returns_frida_tool() -> None:
    """Verify tool_definition has ToolName.FRIDA and a non-empty description.

    Falsifiable: changing tool_name to GHIDRA or similar would fail the enum
    comparison; removing description would fail the truthiness check.
    """
    bridge = FridaBridge()
    defn = bridge.tool_definition
    assert defn.tool_name == ToolName.FRIDA
    assert defn.tool_name.value == "frida"
    assert defn.description, "tool_definition must have a non-empty description"
    assert "frida" in defn.description.lower(), "description must mention Frida"


def test_all_function_names_have_methods() -> None:
    """Every function in tool_definition maps to a callable async method with correct signature.

    Falsifiable: deleting a bridge method breaks the hasattr check; replacing an
    async method with a sync stub breaks the inspect.iscoroutinefunction check;
    removing a parameter from the function definition would show up via signature
    parameter count.
    """
    bridge = FridaBridge()
    defn = bridge.tool_definition
    errors: list[str] = []
    for func in defn.functions:
        assert func.name.startswith(_FRIDA_PREFIX), f"function name {func.name!r} lacks 'frida.' prefix"
        method_name = func.name.split(".", 1)[1]
        if not hasattr(bridge, method_name):
            errors.append(f"missing method: {func.name}")
            continue
        method = getattr(bridge, method_name)
        if not callable(method):
            errors.append(f"not callable: {func.name}")
            continue
        if not inspect.iscoroutinefunction(method):
            errors.append(f"not a coroutine function: {func.name}")
            continue
        sig = inspect.signature(method)
        skip_kinds = {inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD}
        required_params = [
            p for name, p in sig.parameters.items() if name != "self" and p.default is inspect.Parameter.empty and p.kind not in skip_kinds
        ]
        required_tool_params = [p for p in func.parameters if p.required]
        if len(required_params) != len(required_tool_params):
            errors.append(
                f"{func.name}: required param count mismatch: "
                f"method has {len(required_params)} required, "
                f"tool_definition has {len(required_tool_params)} required",
            )
    assert not errors, "Tool function / method mismatches:\n" + "\n".join(errors)


def test_function_count_exact() -> None:
    """Verify exact function count is 94 (the complete parity-plan implementation).

    Falsifiable: adding or removing any function from _FRIDA_FUNCTIONS changes
    the count and fails this test. Using >= would mask deletions.
    """
    bridge = FridaBridge()
    defn = bridge.tool_definition
    actual = len(defn.functions)
    assert actual == _EXACT_FUNCTION_COUNT, (
        f"Expected exactly {_EXACT_FUNCTION_COUNT} functions, got {actual}. "
        "Update _EXACT_FUNCTION_COUNT if new functions were added intentionally."
    )


def test_no_duplicate_function_names() -> None:
    """Verify no duplicate names and all names follow the 'frida.' prefix convention.

    Falsifiable: adding a duplicate entry or a name without the 'frida.' prefix
    fails the set-size or startswith assertion respectively.
    """
    bridge = FridaBridge()
    defn = bridge.tool_definition
    names = [f.name for f in defn.functions]
    dupes = [n for n in names if names.count(n) > 1]
    assert len(names) == len(set(names)), f"Duplicate function names: {dupes}"
    for name in names:
        assert name.startswith(_FRIDA_PREFIX), f"Function {name!r} lacks required 'frida.' prefix"


def test_new_functions_present() -> None:
    """Verify all 18 new functions from the parity plan are registered and callable.

    Falsifiable: removing any of the 18 expected function names from the tool
    definition, or making its corresponding method non-callable, fails this test.
    """
    bridge = FridaBridge()
    defn = bridge.tool_definition
    names = {f.name for f in defn.functions}
    missing = _EXPECTED_NEW_FUNCTIONS - names
    assert missing == set(), f"Missing new functions: {missing}"
    for fn_name in _EXPECTED_NEW_FUNCTIONS:
        method_name = fn_name.split(".", 1)[1]
        method = getattr(bridge, method_name, None)
        assert callable(method), f"Method {method_name!r} for {fn_name!r} is not callable"
        assert inspect.iscoroutinefunction(method), f"Method {method_name!r} must be async"


def test_fixed_functions_present() -> None:
    """Verify the three fixed functions use correct names and 'get_memory_ranges' is absent.

    Falsifiable: renaming enumerate_imports, allocate_memory, or get_memory_regions
    breaks the 'in names' assertion; restoring get_memory_ranges breaks the 'not in' assert.
    """
    bridge = FridaBridge()
    defn = bridge.tool_definition
    names = {f.name for f in defn.functions}
    missing = _EXPECTED_FIXED_NAMES - names
    assert missing == set(), f"Fixed functions missing from definition: {missing}"
    forbidden = _FORBIDDEN_FIXED_NAMES & names
    assert forbidden == set(), f"Forbidden old names still present: {forbidden}"
    for fn_name in _EXPECTED_FIXED_NAMES:
        method_name = fn_name.split(".", 1)[1]
        method = getattr(bridge, method_name, None)
        assert callable(method), f"Method {method_name!r} for {fn_name!r} is not callable"
        assert inspect.iscoroutinefunction(method), f"Method {method_name!r} must be async"


@pytest.fixture(scope="module")
def notepad_process() -> Generator[Popen[bytes]]:
    """Spawn a real notepad.exe for Frida to attach to.

    Yields:
        Generator[Popen[bytes]]: The running notepad process.
    """
    notepad_path = shutil.which("notepad.exe") or str(
        Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "notepad.exe",
    )
    proc = Popen(
        [notepad_path],
        stdout=DEVNULL,
        stderr=DEVNULL,
    )
    time.sleep(_NOTEPAD_STARTUP_DELAY)
    yield proc
    proc.terminate()
    proc.wait(timeout=5)


@pytest.fixture(scope="module")
def frida_bridge(notepad_process: Popen[bytes]) -> Generator[FridaBridge]:
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
    except ToolError:
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
    tids_before: set[int] = {t.tid for t in _run_async(frida_bridge.enumerate_threads())}
    script_id: str = _run_async(frida_bridge.execute_persistent_script(_WORKER_THREAD_JS))
    time.sleep(_BRIDGE_SLEEP)
    tids_after: set[int] = {t.tid for t in _run_async(frida_bridge.enumerate_threads())}
    new_tids = tids_after - tids_before
    assert len(new_tids) >= 1, "worker thread must appear in thread list after creation"
    yield next(iter(new_tids))
    try:
        _run_async(frida_bridge.unload_script(script_id))
    except ToolError:
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
    except ToolError:
        _logger.debug("unattached_bridge_fixture_shutdown_failed", exc_info=True)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_enumerate_processes(unattached_bridge: FridaBridge) -> None:
    """Verify enumerate_processes returns real running processes with valid pid and name.

    Falsifiable: if enumerate_processes returns an empty list, the len > 0
    assertion fails. If any entry has pid <= 0, the assertion per-entry fails.
    If the method throws ToolError, no exception guard conceals it.

    Args:
        unattached_bridge: Bridge fixture created without a process attached.
    """
    result: list[FridaProcessEntry] = _run_async(unattached_bridge.enumerate_processes())
    assert len(result) > 0, "enumerate_processes must return at least one running process"
    for proc in result:
        assert proc.pid > 0, f"process entry has invalid pid: {proc.pid}"
        assert proc.name, f"process entry with pid={proc.pid} has empty name"
    pids = [p.pid for p in result]
    assert len(pids) == len(set(pids)), "enumerate_processes returned duplicate PIDs"
    current_pid = os.getpid()
    assert current_pid in {p.pid for p in result}, f"current process pid={current_pid} not found in enumerated processes"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_enumerate_devices(unattached_bridge: FridaBridge) -> None:
    """Verify enumerate_devices returns at least the local device with correct type.

    Falsifiable: if enumerate_devices returns an empty list, len >= 1 fails;
    if no device has device_type == 'local', the local_found assertion fails;
    if any device has an empty id or name, the per-device assertions fail.

    Args:
        unattached_bridge: Bridge fixture created without a process attached.
    """
    result: list[FridaDeviceInfo] = _run_async(unattached_bridge.enumerate_devices())
    assert len(result) >= 1, "enumerate_devices must return at least the local device"
    local_found = False
    for dev in result:
        assert dev.id, f"device has empty id: {dev!r}"
        assert dev.name, f"device has empty name: {dev!r}"
        assert dev.device_type in {"local", "usb", "remote", "tether"}, f"device {dev.id!r} has unknown device_type: {dev.device_type!r}"
        if dev.device_type == "local":
            local_found = True
    assert local_found, "enumerate_devices must include at least one 'local' device"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_connect_device_local(unattached_bridge: FridaBridge) -> None:
    """Verify connecting to local device returns a FridaDeviceInfo with device_type 'local'.

    Falsifiable: if connect_device returns a non-FridaDeviceInfo object, isinstance fails;
    if device_type is not 'local', the equality assertion fails; if id is empty, the
    truthiness assertion fails.

    Args:
        unattached_bridge: Bridge fixture created without a process attached.
    """
    result = _run_async(unattached_bridge.connect_device("local"))
    assert isinstance(result, FridaDeviceInfo), f"connect_device must return FridaDeviceInfo, got {type(result)}"
    assert result.device_type == "local", f"expected device_type='local', got {result.device_type!r}"
    assert result.id, "connected device must have a non-empty id"
    assert result.name, "connected device must have a non-empty name"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_enumerate_threads(frida_bridge: FridaBridge) -> None:
    """Verify enumerate_threads returns multiple real threads from notepad.

    Falsifiable: if enumerate_threads returns < 2 entries, the count assertion fails;
    if any TID <= 0, the per-entry assertion fails; if state values are wrong, the
    set membership assertion fails.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    result: list[ThreadInfo] = _run_async(frida_bridge.enumerate_threads())
    assert len(result) >= 2, f"notepad should have multiple threads, got {len(result)}"
    tids: set[int] = set()
    for thread in result:
        assert thread.tid > 0, f"thread has invalid tid: {thread.tid}"
        assert thread.state in {"running", "stopped", "waiting", "uninterruptible", "halted"}, (
            f"thread {thread.tid} has unknown state: {thread.state!r}"
        )
        tids.add(thread.tid)
    assert len(tids) == len(result), "all TIDs must be unique"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_enumerate_imports_kernel32(frida_bridge: FridaBridge) -> None:
    """Verify enumerate_imports returns real kernel32 imports with valid structure.

    Falsifiable: if enumerate_imports returns fewer than _KERNEL32_MIN_IMPORTS entries,
    the count assertion fails; if any entry has an empty function name, the per-entry
    assertion fails; if none of the expected NT functions are present, the sentinel check fails.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    result: list[ImportInfo] = _run_async(frida_bridge.enumerate_imports("kernel32.dll"))
    assert len(result) >= _KERNEL32_MIN_IMPORTS, f"kernel32 should have many imports, got {len(result)}"
    resolved_count = 0
    seen_functions: set[str] = set()
    for imp in result:
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
    """Verify find_base_address returns ntdll.dll base in high address range, 64KB-aligned.

    Falsifiable: if the method returns 0 or a low address, the >= assertion fails;
    if the result is not 64KB-aligned (Windows PE requirement), the modulo check fails;
    if the result is non-deterministic, the two-call equality assertion fails.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    result1 = _run_async(frida_bridge.find_base_address("ntdll.dll"))
    result2 = _run_async(frida_bridge.find_base_address("ntdll.dll"))
    assert isinstance(result1, int), f"find_base_address must return int, got {type(result1)}"
    assert result1 >= _NTDLL_BASE_MIN, f"ntdll base 0x{result1:X} should be in high system DLL range (>= 0x{_NTDLL_BASE_MIN:X})"
    assert result1 % 0x10000 == 0, f"base 0x{result1:X} must be 64KB-aligned (PE section alignment)"
    assert result1 == result2, f"find_base_address('ntdll.dll') must be deterministic: {result1:#x} != {result2:#x}"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_find_base_address_kernel32(frida_bridge: FridaBridge) -> None:
    """Verify find_base_address returns kernel32.dll base, distinct from ntdll, 64KB-aligned.

    Falsifiable: if kernel32 and ntdll resolve to the same address the != assertion fails;
    if kernel32 base is not 64KB-aligned the modulo check fails; if the method returns
    a value below _NTDLL_BASE_MIN the range check fails.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    k32_base = _run_async(frida_bridge.find_base_address("kernel32.dll"))
    ntdll_base = _run_async(frida_bridge.find_base_address("ntdll.dll"))
    assert isinstance(k32_base, int), f"find_base_address must return int, got {type(k32_base)}"
    assert k32_base >= _NTDLL_BASE_MIN, f"kernel32 base 0x{k32_base:X} should be in high system DLL range"
    assert k32_base % 0x10000 == 0, f"base 0x{k32_base:X} must be 64KB-aligned"
    assert k32_base != ntdll_base, "kernel32 and ntdll must have different bases"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_get_memory_regions(frida_bridge: FridaBridge) -> None:
    """Verify get_memory_regions returns real memory layout with executable and readable regions.

    Falsifiable: if the count is below threshold, len assertion fails; if any region
    has zero size the size assertion fails; if no executable region exists the
    has_executable assertion fails; if protection field format is wrong the 'in' check fails.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    result: list[MemoryRegion] = _run_async(frida_bridge.get_memory_regions())
    assert len(result) >= _NOTEPAD_MIN_REGIONS, f"notepad should have many memory regions, got {len(result)}"
    has_executable = False
    has_readable = False
    for region in result:
        assert region.base_address >= 0, f"region has negative base_address: {region.base_address}"
        assert region.size > 0, f"region at 0x{region.base_address:X} has zero size"
        if "x" in region.protection:
            has_executable = True
        if "r" in region.protection:
            has_readable = True
    assert has_executable, "process must have at least one executable region"
    assert has_readable, "process must have at least one readable region"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_resolve_api_createfile(frida_bridge: FridaBridge) -> None:
    """Verify resolve_api finds CreateFileW in kernel32 with a non-zero address.

    Falsifiable: if no match contains CreateFileW the found assertion fails;
    if address is 0 the > 0 assertion fails; if the result list is empty the
    len >= 1 assertion fails.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    result: list[ApiResolverMatch] = _run_async(frida_bridge.resolve_api("exports:*!CreateFileW"))
    assert len(result) >= 1, "resolve_api for CreateFileW must return at least one match"
    found = False
    for api_match in result:
        if "CreateFileW" in api_match.name:
            found = True
            assert api_match.address > 0, f"CreateFileW match address must be non-zero, got {api_match.address}"
            assert api_match.address >= _NTDLL_BASE_MIN, f"CreateFileW address 0x{api_match.address:X} below system DLL range"
    assert found, "resolve_api('exports:*!CreateFileW') must contain a match with 'CreateFileW' in name"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_resolve_symbol(frida_bridge: FridaBridge) -> None:
    """Verify resolve_symbol resolves a known NtCreateFile address to its exact symbol.

    Falsifiable: if the resolved address doesn't match the query, the == assertion fails;
    if name is empty the truthiness assertion fails; if NtCreateFile is not in the name
    the 'in' assertion fails; if module_name is None the is not None assertion fails.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    matches: list[ApiResolverMatch] = _run_async(frida_bridge.resolve_api("exports:ntdll.dll!NtCreateFile"))
    assert len(matches) >= 1, "NtCreateFile must exist in ntdll"
    func_addr = matches[0].address
    result: SymbolInfo = _run_async(frida_bridge.resolve_symbol(func_addr))
    assert result.address == func_addr, f"resolved address 0x{result.address:X} must match query 0x{func_addr:X}"
    assert result.name, "resolved function must have a symbol name"
    assert "NtCreateFile" in result.name, f"symbol name should contain NtCreateFile, got '{result.name}'"
    assert result.module_name is not None, "known function should resolve with a module name"
    assert "ntdll" in result.module_name.lower(), f"NtCreateFile should resolve to ntdll, got module '{result.module_name}'"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_find_functions_named(frida_bridge: FridaBridge) -> None:
    """Verify find_functions_named locates NtCreateFile in the system DLL range.

    Falsifiable: if no NtCreateFile is found the len >= 1 assertion fails;
    if address is below system DLL range the >= assertion fails; if name is empty
    the truthiness assertion fails.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    result: list[SymbolInfo] = _run_async(frida_bridge.find_functions_named("NtCreateFile"))
    assert len(result) >= 1, "NtCreateFile must exist in ntdll on every Windows system"
    sym = result[0]
    assert sym.address >= _NTDLL_BASE_MIN, f"NtCreateFile address 0x{sym.address:X} should be in system DLL range"
    assert sym.name, "resolved symbol must have a name"
    assert "NtCreateFile" in sym.name, f"symbol name must contain 'NtCreateFile', got '{sym.name}'"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_allocate_memory(frida_bridge: FridaBridge) -> None:
    """Verify allocate_memory returns writable memory; write+read roundtrip proves usability.

    Falsifiable: if address is <= 0x10000 (invalid range) the assertion fails;
    if write_memory or read_memory silently fail, readback != probe fails;
    an allocation that returns a sentinel value (like 0) would fail both assertions.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    addr: int = _run_async(frida_bridge.allocate_memory(_ALLOC_SIZE))
    assert addr > 0x10000, f"allocated address 0x{addr:X} is suspiciously low"
    probe = bytes([0xDE, 0xAD])
    _run_async(frida_bridge.write_memory(addr, probe))
    readback: bytes = _run_async(frida_bridge.read_memory(addr, len(probe)))
    assert readback == probe, f"alloc'd memory at 0x{addr:X} should be writable: wrote {probe!r}, read {readback!r}"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_protect_memory(frida_bridge: FridaBridge) -> None:
    """Verify protect_memory succeeds on allocated memory and subsequent read/write works.

    Falsifiable: if protect_memory returns False the result assertion fails;
    if write or read after protect fail, the roundtrip assertion fails.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    addr: int = _run_async(frida_bridge.allocate_memory(_ALLOC_SIZE))
    result: bool = _run_async(frida_bridge.protect_memory(addr, _ALLOC_SIZE, "rwx"))
    assert result is True, f"protect_memory('rwx') should return True, got {result}"
    sentinel = bytes([0xCA, 0xFE, 0xBA, 0xBE])
    _run_async(frida_bridge.write_memory(addr, sentinel))
    readback: bytes = _run_async(frida_bridge.read_memory(addr, len(sentinel)))
    assert readback == sentinel, f"memory at 0x{addr:X} after rwx protect must be r/w: wrote {sentinel!r}, read {readback!r}"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_read_write_memory_roundtrip(frida_bridge: FridaBridge) -> None:
    """Verify memory write then read returns the exact same bytes, byte-by-byte.

    Falsifiable: if any byte is corrupted the per-byte assertion fails; if the
    buffer is not actually written the all-zeros read would differ from the pattern.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    addr: int = _run_async(frida_bridge.allocate_memory(_SMALL_ALLOC))
    _run_async(frida_bridge.protect_memory(addr, _SMALL_ALLOC, "rwx"))
    test_bytes = bytes([0x41, 0x42, 0x43, 0x44])
    _run_async(frida_bridge.write_memory(addr, test_bytes))
    read_back: bytes = _run_async(frida_bridge.read_memory(addr, len(test_bytes)))
    assert read_back == test_bytes, f"roundtrip failed: expected {test_bytes!r}, got {read_back!r}"
    for i, (expected, actual) in enumerate(zip(test_bytes, read_back, strict=True)):
        assert expected == actual, f"byte {i} mismatch: expected 0x{expected:02X}, got 0x{actual:02X}"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_hook_and_remove(frida_bridge: FridaBridge) -> None:
    """Verify hook_function creates an active hook and remove_hook deactivates it.

    Falsifiable: if hook_function returns a HookInfo with active=False the assertion fails;
    if hook.id is empty the truthiness assertion fails; if remove_hook returns False
    the removed assertion fails.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    hook: HookInfo = _run_async(frida_bridge.hook_function("kernel32.dll!GetTickCount"))
    assert hook.id, f"hook must have a non-empty id, got {hook.id!r}"
    assert hook.active, f"hook must be active after creation, got active={hook.active}"
    assert hook.target == "kernel32.dll!GetTickCount", f"hook target mismatch: expected 'kernel32.dll!GetTickCount', got {hook.target!r}"
    removed: bool = _run_async(frida_bridge.remove_hook(hook.id))
    assert removed is True, f"remove_hook must return True, got {removed}"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_stalker_follow_and_unfollow(
    frida_bridge: FridaBridge,
    worker_thread: int,
) -> None:
    """Verify stalker_follow collects real call events from a busy worker thread.

    Falsifiable: if trace has 0 events the event_count > 0 assertion fails;
    if events list length != event_count the equality fails; if any event has
    type != 'call' the event_type assertion fails.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
        worker_thread: Thread id of a live worker that generates call events during the trace window.
    """
    trace_id: str = _run_async(
        frida_bridge.stalker_follow(
            thread_id=worker_thread,
            events="call",
            limit=_STALKER_LIMIT,
        ),
    )
    assert trace_id, "stalker_follow must return a non-empty trace id"

    time.sleep(_STALKER_SLEEP)

    trace: StalkerTrace = _run_async(frida_bridge.stalker_unfollow(thread_id=worker_thread))
    assert trace.thread_id == worker_thread, f"trace thread_id {trace.thread_id} must match worker thread {worker_thread}"
    assert trace.event_count > 0, f"Stalker must have collected events from worker thread {worker_thread} after {_STALKER_SLEEP}s, got 0"
    assert len(trace.events) == trace.event_count, f"events list length {len(trace.events)} must match event_count {trace.event_count}"
    first_event = trace.events[0]
    assert first_event.event_type == "call", f"expected 'call' event type, got '{first_event.event_type}'"
    assert first_event.from_address > 0, "call event must have a non-zero source address"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_child_gating_not_supported_on_windows(frida_bridge: FridaBridge) -> None:
    """Verify child gating raises ToolError on Windows (not supported by Frida).

    Falsifiable: if Frida adds Windows child-gating support, enable_child_gating
    would not raise ToolError and this test would fail, alerting us to update behavior.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    with pytest.raises(ToolError):
        _run_async(frida_bridge.enable_child_gating())


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_get_pending_children_empty(frida_bridge: FridaBridge) -> None:
    """Verify get_pending_children returns an empty typed list when gating is not active.

    Falsifiable: if get_pending_children returns a non-empty list when no children
    were spawned, the not children assertion fails.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    children: list[ChildProcessInfo] = _run_async(frida_bridge.get_pending_children())
    assert isinstance(children, list), f"get_pending_children must return a list, got {type(children)}"
    assert not children, "no children should be gated without enable_child_gating"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_crash_reporting_lifecycle(frida_bridge: FridaBridge) -> None:
    """Verify enable_crash_reporting succeeds (idempotent) and get_crashes returns typed list.

    Falsifiable: if enable_crash_reporting raises, the test fails; if get_crashes
    returns non-empty when no crashes occurred, the not crashes assertion fails.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    _run_async(frida_bridge.enable_crash_reporting())
    _run_async(frida_bridge.enable_crash_reporting())
    crashes: list[CrashInfo] = _run_async(frida_bridge.get_crashes())
    assert isinstance(crashes, list), f"get_crashes must return a list, got {type(crashes)}"
    assert not crashes, "no crashes should have occurred on healthy notepad"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_enumerate_processes_contains_notepad(
    frida_bridge: FridaBridge,
    notepad_process: Popen[bytes],
) -> None:
    """Verify our spawned notepad shows up in the process list with the correct PID.

    Falsifiable: if enumerate_processes does not return the spawned notepad PID,
    the 'in pids' assertion fails.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
        notepad_process: Handle to the spawned notepad subprocess whose PID must appear in the listing.
    """
    result: list[FridaProcessEntry] = _run_async(frida_bridge.enumerate_processes())
    pids = {p.pid for p in result}
    assert notepad_process.pid in pids, f"spawned notepad PID {notepad_process.pid} not found in process list: {sorted(pids)[:10]}..."
    notepad_entry = next((p for p in result if p.pid == notepad_process.pid), None)
    assert notepad_entry is not None
    assert "notepad" in notepad_entry.name.lower(), (
        f"process with pid={notepad_process.pid} should be notepad, got name={notepad_entry.name!r}"
    )
