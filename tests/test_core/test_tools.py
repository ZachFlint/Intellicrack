"""Tests for core.tools module - tool registry and bridge management."""

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
        ToolRegistry instance.
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
    assert registry.get(ToolName.BINARY) is None


def test_get_binary_bridge_raises(registry: ToolRegistry) -> None:
    """Verify get_binary_bridge raises when not registered."""
    with pytest.raises(ToolError):
        registry.get_binary_bridge()


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


def test_get_radare2_bridge_raises(registry: ToolRegistry) -> None:
    """Verify get_radare2_bridge raises when not registered."""
    with pytest.raises(ToolError):
        registry.get_radare2_bridge()


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
    assert ToolName.BINARY in available
    assert ToolName.PROCESS in available
    assert ToolName.FRIDA in available
    assert ToolName.GHIDRA in available
    assert ToolName.RADARE2 in available
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
async def test_get_binary_bridge_after_init(tmp_path: Path) -> None:
    """Verify get_binary_bridge works after initialization.

    Args:
        tmp_path: Pytest temporary directory.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    reg = ToolRegistry(tools_dir=tools_dir)
    await reg.initialize()
    bridge = reg.get_binary_bridge()
    assert bridge is not None
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
