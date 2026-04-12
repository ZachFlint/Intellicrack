# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for core.tools module - tool registry and bridge management.

Tests validate:
- ToolRegistry initialization and bridge lifecycle
- Bridge availability and status reporting
- execute_tool_call dispatch (Phase 1 blocker fix verification)
- Tool definition consistency after initialization
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest


if TYPE_CHECKING:
    from pathlib import Path

from intellicrack.core.tools import ToolRegistry, ToolStatus
from intellicrack.core.types import ToolError, ToolName


_BRIDGE_COUNT_ALL: Final[int] = 7


@pytest.fixture
def registry(tmp_path: Path) -> ToolRegistry:
    """Create a ToolRegistry with tmp_path.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        ToolRegistry: ToolRegistry instance.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    return ToolRegistry(tools_dir=tools_dir)


def test_tools_directory(registry: ToolRegistry) -> None:
    """Verify tools_directory returns configured path."""
    assert registry.tools_directory.exists()


def test_get_available_tools_empty(registry: ToolRegistry) -> None:
    """Verify get_available_tools is empty before initialize."""
    assert registry.get_available_tools() == []


def test_get_tool_definitions_empty(registry: ToolRegistry) -> None:
    """Verify get_tool_definitions is empty before initialize."""
    assert registry.get_tool_definitions() == []


def test_get_returns_none_before_init(registry: ToolRegistry) -> None:
    """Verify get returns None for unregistered tool."""
    assert registry.get(ToolName.PROCESS) is None


def test_get_process_bridge_raises(registry: ToolRegistry) -> None:
    """Verify get_process_bridge raises when not registered."""
    with pytest.raises(ToolError):
        registry.get_process_bridge()


def test_get_frida_bridge_raises(registry: ToolRegistry) -> None:
    """Verify get_frida_bridge raises when not registered."""
    with pytest.raises(ToolError):
        registry.get_frida_bridge()


def test_get_ghidra_bridge_raises(registry: ToolRegistry) -> None:
    """Verify get_ghidra_bridge raises when not registered."""
    with pytest.raises(ToolError):
        registry.get_ghidra_bridge()


def test_get_cutter_bridge_raises(registry: ToolRegistry) -> None:
    """Verify get_cutter_bridge raises when not registered."""
    with pytest.raises(ToolError):
        registry.get_cutter_bridge()


def test_get_x64dbg_bridge_raises(registry: ToolRegistry) -> None:
    """Verify get_x64dbg_bridge raises when not registered."""
    with pytest.raises(ToolError):
        registry.get_x64dbg_bridge()


def test_get_sandbox_bridge_raises(registry: ToolRegistry) -> None:
    """Verify get_sandbox_bridge raises when not registered."""
    with pytest.raises(ToolError):
        registry.get_sandbox_bridge()


@pytest.mark.asyncio
async def test_execute_tool_call_unknown_tool(registry: ToolRegistry) -> None:
    """Verify execute_tool_call raises for unknown tool name."""
    with pytest.raises(ToolError):
        await registry.execute_tool_call("nonexistent", "func", {})


@pytest.mark.asyncio
async def test_execute_tool_call_not_registered(registry: ToolRegistry) -> None:
    """Verify execute_tool_call raises for unregistered tool."""
    with pytest.raises(ToolError):
        await registry.execute_tool_call("binary", "load_file", {})


@pytest.mark.asyncio
async def test_get_status_not_registered(registry: ToolRegistry) -> None:
    """Verify get_status returns unavailable for unregistered tool."""
    status = await registry.get_status(ToolName.GHIDRA)
    assert isinstance(status, ToolStatus)
    assert status.available is False
    assert status.connected is False


@pytest.mark.asyncio
async def test_get_all_status_empty(registry: ToolRegistry) -> None:
    """Verify get_all_status returns empty list before init."""
    statuses = await registry.get_all_status()
    assert statuses == []


@pytest.mark.asyncio
async def test_ensure_tool_ready_not_found(registry: ToolRegistry) -> None:
    """Verify ensure_tool_ready returns False for unregistered tool."""
    result = await registry.ensure_tool_ready(ToolName.GHIDRA)
    assert result is False


@pytest.mark.asyncio
async def test_shutdown_empty(registry: ToolRegistry) -> None:
    """Verify shutdown succeeds on empty registry."""
    await registry.shutdown()


@pytest.mark.asyncio
async def test_initialize_creates_bridges(tmp_path: Path) -> None:
    """Verify initialize creates all bridge instances.

    Args:
        tmp_path: Pytest temporary directory.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    reg = ToolRegistry(tools_dir=tools_dir)
    await reg.initialize()
    available = reg.get_available_tools()
    assert len(available) == _BRIDGE_COUNT_ALL
    assert ToolName.PROCESS in available
    assert ToolName.FRIDA in available
    assert ToolName.GHIDRA in available
    assert ToolName.CUTTER in available
    assert ToolName.X64DBG in available
    assert ToolName.SANDBOX in available
    await reg.shutdown()


@pytest.mark.asyncio
async def test_initialize_idempotent(tmp_path: Path) -> None:
    """Verify calling initialize twice is safe.

    Args:
        tmp_path: Pytest temporary directory.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    reg = ToolRegistry(tools_dir=tools_dir)
    await reg.initialize()
    await reg.initialize()
    assert len(reg.get_available_tools()) == _BRIDGE_COUNT_ALL
    await reg.shutdown()


@pytest.mark.asyncio
async def test_get_tool_definitions_after_init(tmp_path: Path) -> None:
    """Verify get_tool_definitions returns definitions after init.

    Args:
        tmp_path: Pytest temporary directory.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    reg = ToolRegistry(tools_dir=tools_dir)
    await reg.initialize()
    defs = reg.get_tool_definitions()
    assert len(defs) > 0
    await reg.shutdown()


@pytest.mark.asyncio
async def test_get_all_status_after_init(tmp_path: Path) -> None:
    """Verify get_all_status returns statuses after init.

    Args:
        tmp_path: Pytest temporary directory.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    reg = ToolRegistry(tools_dir=tools_dir)
    await reg.initialize()
    statuses = await reg.get_all_status()
    assert len(statuses) == _BRIDGE_COUNT_ALL
    await reg.shutdown()


@pytest.mark.asyncio
async def test_dispatch_no_capability_gate(tmp_path: Path) -> None:
    """Verify execute_tool_call dispatches without has_capability gate.

    This test verifies the Phase 1 fix: the broken has_capability gate
    that blocked ALL AI tool calls has been removed. The method existence
    check (getattr) is now the only validation.

    Args:
        tmp_path: Pytest temporary directory.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    reg = ToolRegistry(tools_dir=tools_dir)
    await reg.initialize()

    ghidra_bridge = reg.get_ghidra_bridge()
    assert ghidra_bridge is not None

    caps = ghidra_bridge.capabilities
    assert hasattr(caps, "has_capability")
    assert caps.has_capability("get_labels") is False

    with pytest.raises(ToolError, match="call failed"):
        await reg.execute_tool_call("ghidra", "get_labels", {"address": 0x401000})

    await reg.shutdown()


@pytest.mark.asyncio
async def test_dispatch_unknown_function_rejected(tmp_path: Path) -> None:
    """Verify execute_tool_call rejects calls to nonexistent methods.

    Args:
        tmp_path: Pytest temporary directory.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    reg = ToolRegistry(tools_dir=tools_dir)
    await reg.initialize()

    with pytest.raises(ToolError):
        await reg.execute_tool_call("ghidra", "totally_fake_method", {})

    await reg.shutdown()


@pytest.mark.asyncio
async def test_dispatch_x64dbg_tool_call(tmp_path: Path) -> None:
    """Verify execute_tool_call routes to x64dbg bridge methods.

    Args:
        tmp_path: Pytest temporary directory.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    reg = ToolRegistry(tools_dir=tools_dir)
    await reg.initialize()

    x64dbg_bridge = reg.get_x64dbg_bridge()
    assert x64dbg_bridge is not None

    bps = await reg.execute_tool_call("x64dbg", "get_breakpoints", {})
    assert isinstance(bps, list)
    assert bps == []

    await reg.shutdown()


@pytest.mark.asyncio
async def test_tool_definitions_have_functions(tmp_path: Path) -> None:
    """Verify all bridges report tool definitions with functions.

    Args:
        tmp_path: Pytest temporary directory.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    reg = ToolRegistry(tools_dir=tools_dir)
    await reg.initialize()

    defs = reg.get_tool_definitions()
    for tool_def in defs:
        assert len(tool_def.functions) > 0, f"Tool {tool_def.tool_name} has no functions"

    await reg.shutdown()
