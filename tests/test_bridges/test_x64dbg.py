# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Comprehensive integration tests for Intellicrack x64dbg bridge module.

Tests validate:
- X64DbgBridge initialization and configuration
- Breakpoint management state tracking
- Watchpoint management state tracking
- Tool definition schema generation
- Windows API integration (on Windows platforms)
- Memory operations and disassembly integration
- Error handling for edge cases

All tests use real Windows APIs and state management without mocking.
"""

from __future__ import annotations

import ctypes
import os
import sys
from dataclasses import fields
from pathlib import Path

import pytest

from intellicrack.bridges.base import WatchpointInfo
from intellicrack.bridges.x64dbg import (
    X64DbgBridge,
    get_capstone,
    get_keystone,
)
from intellicrack.core.types import (
    BreakpointInfo,
    ToolError,
    ToolName,
)


if sys.platform == "win32":
    from ctypes import wintypes

    from intellicrack.bridges.x64dbg import (
        PAGE_READONLY,
    )

TEST_ADDR_CODE_1 = 0x401000
TEST_ADDR_CODE_2 = 0x402000
TEST_ADDR_CODE_3 = 0x403000
TEST_ADDR_DATA_1 = 0x7FFE0000
TEST_ADDR_DATA_2 = 0x7FFE0004
TEST_WATCHPOINT_SIZE = 4
TEST_READ_SIZE = 16
TEST_DISASM_COUNT_SMALL = 3
TEST_BP_ID_FIRST = 1
TEST_BP_ID_SECOND = 2
TEST_BP_ID_THIRD = 3
TEST_BP_COUNT_TWO = 2
TEST_BP_COUNT_THREE = 3
BUFFER_SIZE_4K = 4096


def test_bridge_instantiation() -> None:
    """Verify bridge can be instantiated."""
    bridge = X64DbgBridge()
    assert bridge is not None


def test_bridge_initial_state() -> None:
    """Verify bridge initializes with correct default state."""
    bridge = X64DbgBridge()
    assert bridge.attached_pid is None
    assert bridge.binary_path is None
    assert bridge.is_64bit is True
    assert bridge.breakpoints == {}
    assert bridge.watchpoints == {}
    assert bridge.next_bp_id == 1
    assert bridge.next_wp_id == 1


def test_bridge_has_capabilities() -> None:
    """Verify bridge exposes its capabilities."""
    bridge = X64DbgBridge()
    caps = bridge.capabilities
    assert caps.supports_debugging is True
    assert caps.supports_dynamic_analysis is True
    assert caps.supports_patching is True
    assert caps.supports_scripting is True
    assert "x86" in caps.supported_architectures
    assert "x86_64" in caps.supported_architectures
    assert "pe" in caps.supported_formats


def test_bridge_name() -> None:
    """Verify bridge has correct name property."""
    bridge = X64DbgBridge()
    assert bridge.name == ToolName.X64DBG


def test_breakpoint_info_fields() -> None:
    """Verify BreakpointInfo has all required fields."""
    field_names = {f.name for f in fields(BreakpointInfo)}
    required = {"id", "address", "bp_type", "enabled", "hit_count"}
    assert required.issubset(field_names)


@pytest.fixture
def x64dbg_bridge() -> X64DbgBridge:
    """Create a fresh bridge instance for tests.

    Returns:
        X64DbgBridge: A new bridge instance.
    """
    return X64DbgBridge()


def test_breakpoint_id_increments(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify breakpoint IDs increment properly.

    Args:
        x64dbg_bridge: Fresh X64DbgBridge instance supplied by the fixture.
    """
    assert x64dbg_bridge.next_bp_id == 1
    x64dbg_bridge.next_bp_id += 1
    assert x64dbg_bridge.next_bp_id == TEST_BP_COUNT_TWO


@pytest.mark.asyncio
async def test_breakpoint_retrieved_via_get_breakpoints(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify a stored breakpoint is returned by the real get_breakpoints path.

    Drives the actual ``get_breakpoints`` retrieval logic (local tracking
    merge, with the plugin skipped because no pipe is connected) rather than
    inspecting the backing dict directly.

    Args:
        x64dbg_bridge: Fresh X64DbgBridge instance supplied by the fixture.
    """
    bp = BreakpointInfo(
        id=TEST_BP_ID_FIRST,
        address=TEST_ADDR_CODE_1,
        bp_type="software",
        enabled=True,
        hit_count=0,
        condition=None,
    )
    x64dbg_bridge.breakpoints[TEST_ADDR_CODE_1] = bp

    retrieved = await x64dbg_bridge.get_breakpoints()
    by_address = {entry.address: entry for entry in retrieved}
    assert TEST_ADDR_CODE_1 in by_address
    assert by_address[TEST_ADDR_CODE_1].id == TEST_BP_ID_FIRST
    assert by_address[TEST_ADDR_CODE_1].bp_type == "software"
    assert by_address[TEST_ADDR_CODE_1].enabled is True


@pytest.mark.asyncio
async def test_multiple_breakpoints_via_get_breakpoints(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify multiple stored breakpoints surface through get_breakpoints.

    Args:
        x64dbg_bridge: Fresh X64DbgBridge instance supplied by the fixture.
    """
    addresses = [TEST_ADDR_CODE_1, TEST_ADDR_CODE_2, TEST_ADDR_CODE_3]
    for i, addr in enumerate(addresses):
        bp = BreakpointInfo(
            id=i + 1,
            address=addr,
            bp_type="software",
            enabled=True,
            hit_count=0,
        )
        x64dbg_bridge.breakpoints[addr] = bp

    retrieved = await x64dbg_bridge.get_breakpoints()
    by_address = {entry.address: entry for entry in retrieved}
    assert len(by_address) == TEST_BP_COUNT_THREE
    assert by_address[TEST_ADDR_CODE_1].id == TEST_BP_ID_FIRST
    assert by_address[TEST_ADDR_CODE_3].id == TEST_BP_ID_THIRD


def test_watchpoint_id_increments(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify watchpoint IDs increment properly.

    Args:
        x64dbg_bridge: Fresh X64DbgBridge instance supplied by the fixture.
    """
    assert x64dbg_bridge.next_wp_id == 1
    x64dbg_bridge.next_wp_id += 1
    assert x64dbg_bridge.next_wp_id == TEST_BP_COUNT_TWO


@pytest.mark.asyncio
async def test_watchpoint_retrieved_via_get_watchpoints(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify a stored watchpoint is returned by the real get_watchpoints path.

    Args:
        x64dbg_bridge: Fresh X64DbgBridge instance supplied by the fixture.
    """
    wp = WatchpointInfo(
        id=TEST_BP_ID_FIRST,
        address=TEST_ADDR_DATA_1,
        size=TEST_WATCHPOINT_SIZE,
        watch_type="write",
        enabled=True,
        hit_count=0,
    )
    x64dbg_bridge.watchpoints[TEST_BP_ID_FIRST] = wp

    retrieved = await x64dbg_bridge.get_watchpoints()
    by_address = {entry.address: entry for entry in retrieved}
    assert TEST_ADDR_DATA_1 in by_address
    assert by_address[TEST_ADDR_DATA_1].id == TEST_BP_ID_FIRST
    assert by_address[TEST_ADDR_DATA_1].size == TEST_WATCHPOINT_SIZE
    assert by_address[TEST_ADDR_DATA_1].watch_type == "write"


def test_tool_definition_maps_to_callable_methods(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify the tool definition is the x64dbg tool and resolves to real methods.

    Strengthens the trivial existence check: confirms the tool definition is
    bound to this bridge, exposes functions, and that every advertised function
    resolves to a callable method actually implemented on the bridge instance.

    Args:
        x64dbg_bridge: Fresh X64DbgBridge instance supplied by the fixture.
    """
    tool_def = x64dbg_bridge.tool_definition
    assert tool_def.tool_name == ToolName.X64DBG
    assert len(tool_def.functions) > 0

    aliases = {"disassemble": "disassemble_at"}
    for func in tool_def.functions:
        method_name = func.name.replace("x64dbg.", "")
        resolved = aliases.get(method_name, method_name)
        method = getattr(x64dbg_bridge, resolved, None)
        assert callable(method), f"Tool function {func.name} has no callable method {resolved}"


def test_tool_definition_function_names(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify key functions are defined.

    Args:
        x64dbg_bridge: Fresh X64DbgBridge instance supplied by the fixture.
    """
    tool_def = x64dbg_bridge.tool_definition
    function_names = {f.name for f in tool_def.functions}
    expected = {
        "x64dbg.set_breakpoint",
        "x64dbg.remove_breakpoint",
        "x64dbg.read_memory",
        "x64dbg.write_memory",
        "x64dbg.disassemble",
        "x64dbg.get_registers",
        "x64dbg.set_register",
    }
    assert expected.issubset(function_names)


@pytest.mark.asyncio
async def test_is_available_no_path(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify is_available returns False when path not set.

    Args:
        x64dbg_bridge: Fresh X64DbgBridge instance supplied by the fixture.
    """
    x64dbg_bridge.x64dbg_path = None
    result = await x64dbg_bridge.is_available()
    assert result is False


@pytest.mark.asyncio
async def test_is_available_nonexistent_path(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify is_available returns False for nonexistent path.

    Args:
        x64dbg_bridge: Fresh X64DbgBridge instance supplied by the fixture.
    """
    x64dbg_bridge.x64dbg_path = Path("/nonexistent/x64dbg")
    result = await x64dbg_bridge.is_available()
    assert result is False


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_read_memory_no_process(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify read_memory raises error when no process attached.

    Args:
        x64dbg_bridge: Fresh X64DbgBridge instance supplied by the fixture.
    """
    x64dbg_bridge.attached_pid = None
    with pytest.raises(ToolError, match="No process attached"):
        await x64dbg_bridge.read_memory(TEST_ADDR_CODE_1, TEST_READ_SIZE)


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_write_memory_no_process(x64dbg_bridge: X64DbgBridge) -> None:
    """Verify write_memory raises error when no process attached.

    Args:
        x64dbg_bridge: Fresh X64DbgBridge instance supplied by the fixture.
    """
    x64dbg_bridge.attached_pid = None
    with pytest.raises(ToolError, match="No process attached"):
        await x64dbg_bridge.write_memory(TEST_ADDR_CODE_1, b"\x90\x90")


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_read_own_process_memory(x64dbg_bridge: X64DbgBridge) -> None:
    """Test reading memory from current process (self-test).

    Args:
        x64dbg_bridge: Fresh X64DbgBridge instance supplied by the fixture.
    """
    x64dbg_bridge.attached_pid = os.getpid()

    test_data = b"INTELLICRACK_TEST_MARKER"
    buffer = ctypes.create_string_buffer(test_data)
    buffer_address = ctypes.addressof(buffer)

    result = await x64dbg_bridge.read_memory(buffer_address, len(test_data))
    assert result == test_data


@pytest.fixture
def x64dbg_bridge_64bit() -> X64DbgBridge:
    """Create a fresh bridge instance with 64-bit mode enabled.

    Returns:
        X64DbgBridge: A bridge instance in 64-bit mode.
    """
    bridge = X64DbgBridge()
    bridge.is_64bit = True
    return bridge


@pytest.mark.asyncio
async def test_disassemble_requires_capstone(
    x64dbg_bridge_64bit: X64DbgBridge,
) -> None:
    """Verify disassemble_at depends on capstone availability.

    Args:
        x64dbg_bridge_64bit: Bridge fixture configured for 64-bit disassembly.
    """
    if get_capstone() is None:
        result = await x64dbg_bridge_64bit.disassemble_at(TEST_ADDR_CODE_1, 5)
        assert result == []


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_disassemble_real_exported_function(x64dbg_bridge_64bit: X64DbgBridge) -> None:
    """Disassemble a real exported kernel32 function and verify real mnemonics.

    Resolves the address of ``kernel32!Sleep`` (a genuine block of x86-64
    machine code), disassembles it through the bridge, and verifies the
    decoded instructions are real: every line has a non-empty mnemonic, the
    decoded raw bytes match the bytes actually present in process memory, and
    the instruction addresses advance monotonically from the entry.

    Args:
        x64dbg_bridge_64bit: Bridge fixture configured for 64-bit disassembly.
    """
    if get_capstone() is None:
        pytest.skip("capstone not available")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_proc_address = kernel32.GetProcAddress
    get_proc_address.restype = ctypes.c_void_p
    get_proc_address.argtypes = [wintypes.HMODULE, ctypes.c_char_p]
    module_handle = ctypes.c_void_p(kernel32._handle).value
    proc = get_proc_address(module_handle, b"Sleep")
    assert proc, "Failed to resolve kernel32!Sleep address"
    func_addr = int(proc)

    x64dbg_bridge_64bit.attached_pid = os.getpid()

    result = await x64dbg_bridge_64bit.disassemble_at(func_addr, TEST_DISASM_COUNT_SMALL)
    assert isinstance(result, list)
    assert len(result) > 0

    raw = await x64dbg_bridge_64bit.read_memory(func_addr, TEST_DISASM_COUNT_SMALL * 15)

    assert result[0].address == func_addr
    for line in result:
        assert line.mnemonic, "Disassembled line is missing a mnemonic"
        decoded_bytes = bytes.fromhex(line.bytes_str.replace(" ", ""))
        offset = line.address - func_addr
        assert raw[offset : offset + len(decoded_bytes)] == decoded_bytes


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_find_pattern_in_own_memory(x64dbg_bridge: X64DbgBridge) -> None:
    """Test finding a pattern in current process memory.

    Args:
        x64dbg_bridge: Fresh X64DbgBridge instance supplied by the fixture.
    """
    x64dbg_bridge.attached_pid = os.getpid()

    needle = b"UNIQUE_PATTERN_FOR_TEST_12345"
    buffer = ctypes.create_string_buffer(needle)
    buffer_addr = ctypes.addressof(buffer)

    results = await x64dbg_bridge.scan_memory(pattern=needle)

    assert isinstance(results, list)
    matches_at_buffer = [r for r in results if r.address == buffer_addr]
    assert matches_at_buffer, "Pattern not found at the address of the planted buffer"
    matched_bytes = bytes.fromhex(matches_at_buffer[0].matched_bytes.replace(" ", ""))
    assert matched_bytes == needle


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_get_memory_map_current_process(x64dbg_bridge: X64DbgBridge) -> None:
    """Test getting memory map for current process.

    Args:
        x64dbg_bridge: Fresh X64DbgBridge instance supplied by the fixture.
    """
    x64dbg_bridge.attached_pid = os.getpid()

    memory_map = await x64dbg_bridge.get_memory_regions()
    assert isinstance(memory_map, list)
    assert len(memory_map) > 0


@pytest.fixture
def x64dbg_bridge_attached() -> X64DbgBridge:
    """Create a fresh bridge with current process attached.

    Returns:
        X64DbgBridge: A bridge attached to the current process.
    """
    bridge = X64DbgBridge()
    bridge.attached_pid = os.getpid()
    return bridge


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_read_write_own_memory(x64dbg_bridge_attached: X64DbgBridge) -> None:
    """Test reading and writing memory in current process.

    Args:
        x64dbg_bridge_attached: Bridge fixture pre-attached to the current Python process.
    """
    test_data = b"TEST_BUFFER_DATA"
    buffer = ctypes.create_string_buffer(len(test_data))
    buffer_address = ctypes.addressof(buffer)

    await x64dbg_bridge_attached.write_memory(buffer_address, test_data)

    result = await x64dbg_bridge_attached.read_memory(buffer_address, len(test_data))
    assert result == test_data


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_memory_protection_changes(x64dbg_bridge_attached: X64DbgBridge) -> None:
    """Test memory protection detection.

    Args:
        x64dbg_bridge_attached: Bridge fixture pre-attached to the current Python process.
    """
    buffer = ctypes.create_string_buffer(BUFFER_SIZE_4K)
    buffer_address = ctypes.addressof(buffer)

    # Change to readonly
    old_protect = wintypes.DWORD()
    ctypes.windll.kernel32.VirtualProtect(ctypes.c_void_p(buffer_address), BUFFER_SIZE_4K, PAGE_READONLY, ctypes.byref(old_protect))

    try:
        await _assert_readonly_region_present(x64dbg_bridge_attached, buffer_address)
    finally:
        # Restore
        ctypes.windll.kernel32.VirtualProtect(ctypes.c_void_p(buffer_address), BUFFER_SIZE_4K, old_protect, ctypes.byref(old_protect))


async def _assert_readonly_region_present(bridge: X64DbgBridge, buffer_address: int) -> None:
    """Assert the bridge reports the readonly region covering ``buffer_address``.

    Args:
        bridge: X64DbgBridge attached to the current process.
        buffer_address: Address of the buffer mutated to ``PAGE_READONLY``.
    """
    memory_map = await bridge.get_memory_regions()
    found = False
    for region in memory_map:
        if region.base_address <= buffer_address < region.base_address + region.size:
            assert "r" in region.protection
            assert "w" not in region.protection
            found = True
            break
    assert found


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
async def test_assemble_with_keystone(x64dbg_bridge_64bit: X64DbgBridge) -> None:
    """Assemble a real instruction and verify it is written into live memory.

    Assembles ``nop`` with keystone and writes it into a real writable buffer
    in the current process, then reads the buffer back through the bridge to
    confirm the assembled byte was actually committed to process memory.

    Args:
        x64dbg_bridge_64bit: Bridge fixture configured for 64-bit disassembly.
    """
    if get_keystone() is None:
        pytest.skip("keystone not available")

    x64dbg_bridge_64bit.attached_pid = os.getpid()
    buffer = ctypes.create_string_buffer(16)
    buffer_address = ctypes.addressof(buffer)

    result = await x64dbg_bridge_64bit.assemble_at(buffer_address, "nop")
    assert result == b"\x90"

    written = await x64dbg_bridge_64bit.read_memory(buffer_address, 1)
    assert written == b"\x90"
