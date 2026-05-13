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


pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
    pytest.mark.asyncio,
    pytest.mark.slow,
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


async def test_get_mitigation_policy_returns_keys(bridge: ProcessBridge) -> None:
    """get_mitigation_policy returns a dict containing dep, aslr, cfg.

    Args:
        bridge: ProcessBridge fixture.
    """
    result = await bridge.get_mitigation_policy(os.getpid())
    assert isinstance(result, dict)
    assert "dep" in result
    assert "aslr" in result
    assert "cfg" in result
    assert "sehop_via_options_mask" in result


async def test_get_extension_policy_returns_dict(bridge: ProcessBridge) -> None:
    """get_extension_policy returns a dict with the disable flag.

    Args:
        bridge: ProcessBridge fixture.
    """
    result = await bridge.get_extension_policy(os.getpid())
    assert isinstance(result, dict)
    assert "disable_extension_points" in result


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


async def test_enumerate_handles_for_self_nonempty(bridge: ProcessBridge) -> None:
    """enumerate_handles returns a non-empty list for the current PID.

    Args:
        bridge: ProcessBridge fixture.
    """
    handles = await bridge.enumerate_handles(os.getpid())
    assert isinstance(handles, list)
    assert len(handles) > 0
    first = handles[0]
    assert "pid" in first
    assert "handle_value" in first
    assert "granted_access" in first
    assert "object_type_index" in first


async def test_enumerate_handles_no_filter_includes_self(bridge: ProcessBridge) -> None:
    """enumerate_handles without a PID filter includes the current PID.

    Args:
        bridge: ProcessBridge fixture.
    """
    all_handles = await bridge.enumerate_handles(None)
    assert isinstance(all_handles, list)
    pids = {entry.get("pid") for entry in all_handles}
    assert os.getpid() in pids


async def test_time_thread_wait_returns_result_dict(bridge: ProcessBridge) -> None:
    """time_thread_wait returns a result dict for the current thread.

    Args:
        bridge: ProcessBridge fixture.
    """
    tid = threading.get_native_id()
    result = await bridge.time_thread_wait(tid, timeout_ms=10)
    assert isinstance(result, dict)
    assert "result" in result
    assert "elapsed_us" in result
    assert isinstance(result["elapsed_us"], int)
    assert result["result"] in {"signaled", "timeout", "failed", "other"} or str(result["result"]).startswith("other_")


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


async def test_enumerate_heaps_for_self(bridge: ProcessBridge) -> None:
    """enumerate_heaps returns a list of heap dicts for the current PID.

    Args:
        bridge: ProcessBridge fixture.
    """
    heaps = await bridge.enumerate_heaps(os.getpid())
    assert isinstance(heaps, list)
    if heaps:
        first = heaps[0]
        assert "id" in first
        assert "flags" in first
        assert "blocks" in first


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
        size = 0x4000
        address = await bridge.allocate(size, "rw")
        assert address > 0
        try:
            ok = await bridge.decommit_memory(os.getpid(), address, size)
            assert ok is True
        finally:
            await bridge.free(address)
    finally:
        await bridge.close()


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
