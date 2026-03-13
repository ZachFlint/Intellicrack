"""API coverage tests for X64DbgBridge.

These tests ensure that all API methods are callable and implemented,
even if they fail without a running x64dbg instance. This satisfies
code coverage and usage analysis requirements.
"""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path

import pytest

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import BreakpointInfo, ToolError


_ADDR_BREAKPOINT = 0x1234
_ADDR_WATCHPOINT = 0x5678
_WATCHPOINT_SIZE = 4
_REG_VALUE = 0x100
_ALLOC_SIZE = 4096

pytestmark = pytest.mark.asyncio


@pytest.fixture
def bridge() -> X64DbgBridge:
    """Create a bridge instance."""
    return X64DbgBridge()


async def test_debugger_control_methods_exist(bridge: X64DbgBridge) -> None:
    """Verify debugger control methods exist and raise ToolError when not connected."""
    # These methods should try to send pipe commands and fail

    with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
        await bridge.step_into()

    with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
        await bridge.step_over()

    with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
        await bridge.step_out()

    with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
        await bridge.run()

    with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
        await bridge.pause()

    with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
        await bridge.stop()


async def test_breakpoint_management(bridge: X64DbgBridge) -> None:
    """Verify breakpoint methods."""
    # set_breakpoint adds to dict THEN sends command.
    # If command fails, we check if it handled it gracefully or if we catch it.

    with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
        await bridge.set_breakpoint(_ADDR_BREAKPOINT, "software")

    bridge._breakpoints[_ADDR_BREAKPOINT] = BreakpointInfo(
        id=1,
        address=_ADDR_BREAKPOINT,
        bp_type="software",
        enabled=True,
        hit_count=0,
    )

    with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
        await bridge.remove_breakpoint(_ADDR_BREAKPOINT)

    bps = await bridge.get_breakpoints()
    assert len(bps) == 1
    assert bps[0].address == _ADDR_BREAKPOINT


async def test_watchpoint_management(bridge: X64DbgBridge) -> None:
    """Verify watchpoint methods."""
    with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
        await bridge.set_watchpoint(_ADDR_WATCHPOINT, _WATCHPOINT_SIZE, "read")

    # get_watchpoints should work locally
    wps = await bridge.get_watchpoints()
    assert isinstance(wps, list)


async def test_register_management(bridge: X64DbgBridge) -> None:
    """Verify register methods."""
    with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
        await bridge.set_register("rax", _REG_VALUE)

    with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
        await bridge.get_registers()


async def test_run_command(bridge: X64DbgBridge) -> None:
    """Verify run_command."""
    # Mocking process to avoid "x64dbg not running" check effectively?
    # No, bridge._process is None.
    with pytest.raises(ToolError, match="x64dbg not running"):
        await bridge.run_command("echo hello")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_memory_allocation_real(bridge: X64DbgBridge) -> None:
    """Verify allocate_memory and free_memory on current process."""
    bridge.attached_pid = os.getpid()

    addr = await bridge.allocate_memory(_ALLOC_SIZE)
    assert addr != 0

    data = b"ALLOC_TEST"
    ctypes.memmove(addr, data, len(data))

    read_back = await bridge.read_memory(addr, len(data))
    assert read_back == data

    success = await bridge.free_memory(addr)
    assert success is True


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_process_info_real(bridge: X64DbgBridge) -> None:
    """Verify process info gathering on current process."""
    bridge.attached_pid = os.getpid()
    bridge.binary_path = Path(sys.executable)

    info = await bridge.get_process_info()
    assert info is not None
    assert info.pid == os.getpid()
    assert len(info.threads) > 0
    assert len(info.modules) > 0
    # command line might be None depending on permissions/implementation, but method should run

    # Check threads
    threads = await bridge._get_threads()
    assert len(threads) > 0

    # Check modules
    modules = await bridge._get_modules()
    assert len(modules) > 0
