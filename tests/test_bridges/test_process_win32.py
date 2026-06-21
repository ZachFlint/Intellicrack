# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Phase 1 Win32 expansion tests for ProcessBridge.

Exercises the new methods added in Phase 1 - kernel-debugger detection,
mitigation/extension policy, system process enumeration, handle
enumeration, token duplication / privilege removal, service enumeration,
heap walking with block details, virtual-memory decommit, typed registry
read, and timed thread waits - against real Windows APIs using the
current process as the safe target.
"""

from __future__ import annotations

import ctypes
import os
import sys
import threading
from ctypes import wintypes
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio

from intellicrack.bridges.process import ProcessBridge
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

_PROCESS_DEP_POLICY = 0
_PROCESS_ASLR_POLICY = 1
_PROCESS_EXTENSION_POINT_DISABLE_POLICY = 6
_PROCESS_CFG_POLICY = 7


def _oracle_mitigation_primary_bit(policy_class: int) -> bool:
    """Independently decode the primary bit of a process mitigation policy.

    Calls ``GetProcessMitigationPolicy`` for the current process through a
    fresh ctypes path (separate from the bridge) and returns the value of
    bit 0 of the policy ``Flags`` DWORD, which is the Microsoft-documented
    primary enable bit for the DEP, ASLR, CFG, and extension-point policies.

    Args:
        policy_class: ``PROCESS_MITIGATION_POLICY`` enumeration value.

    Returns:
        bool: ``True`` when bit 0 of the policy flags is set.

    Raises:
        OSError: If ``GetProcessMitigationPolicy`` reports failure.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetProcessMitigationPolicy.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    kernel32.GetProcessMitigationPolicy.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    flags = ctypes.c_ulong(0)
    ok = kernel32.GetProcessMitigationPolicy(
        kernel32.GetCurrentProcess(),
        policy_class,
        ctypes.byref(flags),
        ctypes.sizeof(flags),
    )
    if not ok:
        raise OSError(ctypes.get_last_error(), "GetProcessMitigationPolicy failed")
    return bool(flags.value & 1)


pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
    pytest.mark.asyncio,
    pytest.mark.integration,
]


@pytest_asyncio.fixture(scope="module")
async def bridge() -> AsyncGenerator[ProcessBridge]:
    """Create and initialize a ProcessBridge for the module.

    Yields:
        AsyncGenerator[ProcessBridge]: Initialized bridge that will be
            shut down on teardown.
    """
    instance = ProcessBridge()
    await instance.initialize()
    yield instance
    await instance.shutdown()


async def test_detect_kernel_debugger_returns_bool_for_self(bridge: ProcessBridge) -> None:
    """detect_kernel_debugger returns a bool for the current PID.

    Args:
        bridge: ProcessBridge fixture.
    """
    result = await bridge.detect_kernel_debugger(os.getpid())
    assert isinstance(result, bool)


async def test_detect_kernel_debugger_invalid_pid_raises(bridge: ProcessBridge) -> None:
    """detect_kernel_debugger raises ToolError for an invalid PID.

    Args:
        bridge: ProcessBridge fixture.
    """
    invalid_pid = 0xFFFFFFFE
    with pytest.raises(ToolError):
        await bridge.detect_kernel_debugger(invalid_pid)


async def test_get_mitigation_policy_matches_win32_oracle(bridge: ProcessBridge) -> None:
    """get_mitigation_policy reports DEP/ASLR/CFG matching the Win32 API.

    Independently queries ``GetProcessMitigationPolicy`` for the current
    process and asserts the bridge's decoded ``dep``/``aslr``/``cfg``
    booleans equal the primary enable bit reported by that call.

    Skips when the environment does not support ``GetProcessMitigationPolicy``
    for the queried policy classes (e.g. Windows containers that return
    ``ERROR_INVALID_PARAMETER`` for mitigation policy queries).

    Args:
        bridge: ProcessBridge fixture.
    """
    try:
        expected_dep = _oracle_mitigation_primary_bit(_PROCESS_DEP_POLICY)
        expected_aslr = _oracle_mitigation_primary_bit(_PROCESS_ASLR_POLICY)
        expected_cfg = _oracle_mitigation_primary_bit(_PROCESS_CFG_POLICY)
    except OSError:
        pytest.skip("GetProcessMitigationPolicy not supported in this environment")

    result = await bridge.get_mitigation_policy(os.getpid())
    assert isinstance(result, dict)

    assert result["dep"] is expected_dep
    assert result["aslr"] is expected_aslr
    assert result["cfg"] is expected_cfg
    assert isinstance(result["sehop_via_options_mask"], int)


async def test_get_extension_policy_matches_win32_oracle(bridge: ProcessBridge) -> None:
    """get_extension_policy reports the exact extension-point disable bit.

    Independently queries ``GetProcessMitigationPolicy`` with
    ``ProcessExtensionPointDisablePolicy`` for the current process and
    asserts the bridge's ``disable_extension_points`` boolean equals the
    primary enable bit from that call.

    Skips when the environment does not support ``GetProcessMitigationPolicy``
    for the queried policy class (e.g. Windows containers that return
    ``ERROR_INVALID_PARAMETER`` for mitigation policy queries).

    Args:
        bridge: ProcessBridge fixture.
    """
    try:
        expected = _oracle_mitigation_primary_bit(_PROCESS_EXTENSION_POINT_DISABLE_POLICY)
    except OSError:
        pytest.skip("GetProcessMitigationPolicy not supported in this environment")

    result = await bridge.get_extension_policy(os.getpid())
    assert isinstance(result, dict)
    assert result["disable_extension_points"] is expected


async def test_enumerate_system_processes_includes_self(bridge: ProcessBridge) -> None:
    """enumerate_system_processes returns a list including the current PID.

    Args:
        bridge: ProcessBridge fixture.
    """
    processes = await bridge.enumerate_system_processes()
    assert isinstance(processes, list)
    assert len(processes) > 0
    pids = [p.get("pid") for p in processes]
    assert os.getpid() in pids


async def test_enumerate_handles_surfaces_planted_handle(bridge: ProcessBridge) -> None:
    """enumerate_handles surfaces a handle this test just opened.

    Creates a real kernel object (an unnamed event) in this process,
    records its exact ``HANDLE`` value, then asserts the enumeration
    reports that precise ``handle_value`` attributed to ``os.getpid()``.
    A bridge that fabricated handle values or read the wrong process's
    table could not reproduce the planted handle.

    Args:
        bridge: ProcessBridge fixture.
    """
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateEventW.argtypes = [
        wintypes.LPVOID,
        wintypes.BOOL,
        wintypes.BOOL,
        wintypes.LPCWSTR,
    ]
    kernel32.CreateEventW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    manual_reset = True
    initial_state = False
    event_handle = kernel32.CreateEventW(None, manual_reset, initial_state, None)
    assert event_handle
    try:
        await _assert_planted_handle_enumerated(bridge, int(event_handle))
    finally:
        kernel32.CloseHandle(wintypes.HANDLE(event_handle))


async def _assert_planted_handle_enumerated(bridge: ProcessBridge, planted: int) -> None:
    """Assert ``enumerate_handles`` surfaces a specific planted handle value.

    Args:
        bridge: ProcessBridge attached to the current process.
        planted: Exact numeric ``HANDLE`` value opened by the caller.
    """
    handles = await bridge.enumerate_handles(os.getpid())
    assert isinstance(handles, list)
    assert all(entry.get("pid") == os.getpid() for entry in handles)
    matches = [entry for entry in handles if entry.get("handle_value") == planted]
    assert len(matches) == 1
    match = matches[0]
    assert isinstance(match["object_type_index"], int)
    assert isinstance(match["granted_access"], int)
    assert match["granted_access"] > 0


async def test_enumerate_handles_no_filter_includes_self(bridge: ProcessBridge) -> None:
    """enumerate_handles without a PID filter includes the current PID.

    Args:
        bridge: ProcessBridge fixture.
    """
    all_handles = await bridge.enumerate_handles(None)
    assert isinstance(all_handles, list)
    pids = {entry.get("pid") for entry in all_handles}
    assert os.getpid() in pids


async def test_time_thread_wait_running_thread_times_out(bridge: ProcessBridge) -> None:
    """time_thread_wait reports timeout for a thread that never signals.

    The current thread is actively running and is never signalled within
    the wait, so the only correct outcome is ``"timeout"``. The elapsed
    time must be a non-negative integer.

    Args:
        bridge: ProcessBridge fixture.
    """
    tid = threading.get_native_id()
    result = await bridge.time_thread_wait(tid, timeout_ms=10)
    assert isinstance(result, dict)
    assert result["result"] == "timeout"
    assert isinstance(result["elapsed_us"], int)
    assert result["elapsed_us"] >= 0


async def test_time_thread_wait_exited_thread_signals(bridge: ProcessBridge) -> None:
    """time_thread_wait reports signaled for a thread that has exited.

    A Win32 thread handle becomes signalled when the thread terminates.
    This test starts a worker thread, captures its native thread id, opens
    a handle to keep the thread object (and its id) valid past exit, then
    releases the worker and asserts the bridge reports ``"signaled"``.

    Args:
        bridge: ProcessBridge fixture.
    """
    synchronize = 0x00100000
    captured: dict[str, int] = {}
    ready = threading.Event()
    release = threading.Event()

    def _worker() -> None:
        """Record this thread's native id then wait for release.

        Returns:
            None: The worker exits once released.
        """
        captured["tid"] = threading.get_native_id()
        ready.set()
        release.wait()

    worker = threading.Thread(target=_worker)
    worker.start()
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    keepalive: int = 0
    try:
        keepalive = await _wait_signaled_on_exited_worker(bridge, kernel32, synchronize, captured, ready, release, worker)
    finally:
        release.set()
        if keepalive:
            kernel32.CloseHandle(wintypes.HANDLE(keepalive))


async def _wait_signaled_on_exited_worker(
    bridge: ProcessBridge,
    kernel32: ctypes.WinDLL,
    synchronize: int,
    captured: dict[str, int],
    ready: threading.Event,
    release: threading.Event,
    worker: threading.Thread,
) -> int:
    """Release a worker thread, wait on it, and assert a signaled result.

    Opens a keepalive handle to the worker thread so its id stays valid
    after exit, releases and joins the worker, then asserts the bridge
    reports ``"signaled"`` for the now-terminated thread.

    Args:
        bridge: ProcessBridge attached to the current process.
        kernel32: Loaded ``kernel32`` library with ``OpenThread`` configured.
        synchronize: ``SYNCHRONIZE`` access right used to open the thread.
        captured: Mapping populated by the worker with its native ``tid``.
        ready: Event the worker sets once it has recorded its id.
        release: Event used to release the worker so it can exit.
        worker: The worker thread under test.

    Returns:
        int: The keepalive thread handle the caller must close.
    """
    assert ready.wait(timeout=5.0)
    worker_tid = captured["tid"]
    inherit = False
    keepalive = int(kernel32.OpenThread(synchronize, inherit, worker_tid))
    assert keepalive
    release.set()
    worker.join(timeout=5.0)
    assert not worker.is_alive()
    result = await bridge.time_thread_wait(worker_tid, timeout_ms=1000)
    assert result["result"] == "signaled"
    assert isinstance(result["elapsed_us"], int)
    assert result["elapsed_us"] >= 0
    return keepalive


async def test_time_thread_wait_invalid_tid_raises(bridge: ProcessBridge) -> None:
    """time_thread_wait raises ToolError for a bogus TID.

    Args:
        bridge: ProcessBridge fixture.
    """
    with pytest.raises(ToolError):
        await bridge.time_thread_wait(0xFFFFFFFE, timeout_ms=1)


async def test_enumerate_services_returns_list(bridge: ProcessBridge) -> None:
    """enumerate_services returns a list and does not raise.

    Args:
        bridge: ProcessBridge fixture.
    """
    services = await bridge.enumerate_services()
    assert isinstance(services, list)


async def test_enumerate_services_active_filter(bridge: ProcessBridge) -> None:
    """enumerate_services with active=True returns a list (possibly empty).

    Args:
        bridge: ProcessBridge fixture.
    """
    active_services = await bridge.enumerate_services(active=True)
    assert isinstance(active_services, list)


async def test_enumerate_heaps_includes_process_default_heap(bridge: ProcessBridge) -> None:
    """enumerate_heaps reports the default process heap with valid fields.

    Every Win32 process always owns at least the default heap returned by
    ``GetProcessHeap``. This test independently obtains that heap id and
    asserts the enumeration is non-empty, exposes the ``id``/``flags``/
    ``blocks`` fields with correct types, and contains the default heap id.

    Args:
        bridge: ProcessBridge fixture.
    """
    kernel32 = ctypes.windll.kernel32
    kernel32.GetProcessHeap.restype = ctypes.c_void_p
    default_heap = int(kernel32.GetProcessHeap() or 0)
    assert default_heap != 0

    heaps = await bridge.enumerate_heaps(os.getpid())
    assert isinstance(heaps, list)
    assert len(heaps) > 0
    for heap in heaps:
        assert isinstance(heap["id"], int)
        assert isinstance(heap["flags"], int)
        assert isinstance(heap["blocks"], list)
    heap_ids = {heap["id"] for heap in heaps}
    assert default_heap in heap_ids


async def test_read_registry_product_name(bridge: ProcessBridge) -> None:
    """read_registry returns a string-typed value for ProductName.

    Args:
        bridge: ProcessBridge fixture.
    """
    result = await bridge.read_registry(
        "HKLM",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "ProductName",
    )
    assert isinstance(result, dict)
    assert result.get("type") == "REG_SZ"
    assert isinstance(result.get("data"), str)
    assert len(str(result.get("data"))) > 0


async def test_read_registry_invalid_hive_raises(bridge: ProcessBridge) -> None:
    """read_registry raises ToolError for an unknown hive.

    Args:
        bridge: ProcessBridge fixture.
    """
    with pytest.raises(ToolError):
        await bridge.read_registry("BOGUS", "Software", "x")


async def test_decommit_memory_after_alloc(bridge: ProcessBridge) -> None:
    """decommit_memory succeeds after allocating MEM_COMMIT memory.

    Args:
        bridge: ProcessBridge fixture.
    """
    await bridge.open_process(os.getpid(), "all")
    try:
        await _alloc_decommit_free(bridge)
    finally:
        await bridge.close()


async def _alloc_decommit_free(bridge: ProcessBridge) -> None:
    """Allocate, decommit, and free a region; assert ``decommit_memory`` ok.

    Args:
        bridge: ProcessBridge attached to the current process.
    """
    size = 0x4000
    address = await bridge.allocate(size, "rw")
    assert address > 0
    try:
        ok = await bridge.decommit_memory(os.getpid(), address, size)
        assert ok is True
    finally:
        await bridge.free(address)


async def test_duplicate_token_returns_handle(bridge: ProcessBridge) -> None:
    """duplicate_token returns a usable handle that can be closed.

    Args:
        bridge: ProcessBridge fixture.
    """
    handle = await bridge.duplicate_token(os.getpid())
    assert isinstance(handle, int)
    assert handle != 0
    kernel32 = ctypes.windll.kernel32
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle(wintypes.HANDLE(handle))


async def test_remove_privilege_returns_bool(bridge: ProcessBridge) -> None:
    """remove_privilege returns a bool and does not raise for SeShutdownPrivilege.

    Args:
        bridge: ProcessBridge fixture.
    """
    result = await bridge.remove_privilege(os.getpid(), "SeShutdownPrivilege")
    assert isinstance(result, bool)
