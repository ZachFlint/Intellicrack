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
from intellicrack.core.types import ToolDefinition, ToolError, ToolFunction, ToolName


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


def test_tools_directory(tmp_path: Path) -> None:
    """Verify tools_directory reports the path the registry actually wires and creates.

    The directory is NOT pre-created: ``ToolRegistry.__init__`` passes
    ``tools_dir`` into its ``ToolInstaller``, whose ``__init__`` performs
    ``mkdir(parents=True, exist_ok=True)``. The post-condition that the
    directory now exists proves ``tools_dir`` is genuinely wired into the
    installer (not merely stored), and the equality/name checks prove the
    property reports that exact path rather than a derived one (e.g.
    ``self._tools_dir.parent``).

    Args:
        tmp_path: Pytest temporary directory.
    """
    tools_dir = tmp_path / "tools_root"
    assert not tools_dir.exists(), "precondition: the tools directory must not exist yet"

    reg = ToolRegistry(tools_dir=tools_dir)

    assert reg.tools_directory == tools_dir
    assert reg.tools_directory.name == "tools_root"
    assert tools_dir.is_dir(), (
        "ToolRegistry must wire tools_dir into its ToolInstaller, which creates the "
        "directory on construction; a missing directory means tools_dir is not used"
    )


def test_get_available_tools_empty(registry: ToolRegistry) -> None:
    """Verify get_available_tools is empty before initialize.

    Args:
        registry: ToolRegistry fixture under test.
    """
    assert registry.get_available_tools() == []


def test_get_tool_definitions_empty(registry: ToolRegistry) -> None:
    """Verify get_tool_definitions is empty before initialize.

    Args:
        registry: ToolRegistry fixture under test.
    """
    assert registry.get_tool_definitions() == []


def test_get_returns_none_before_init(registry: ToolRegistry) -> None:
    """Verify get returns None for unregistered tool.

    Args:
        registry: ToolRegistry fixture under test.
    """
    assert registry.get(ToolName.PROCESS) is None


def test_get_process_bridge_raises(registry: ToolRegistry) -> None:
    """Verify get_process_bridge raises when not registered.

    Args:
        registry: ToolRegistry fixture under test.
    """
    with pytest.raises(ToolError):
        registry.get_process_bridge()


def test_get_frida_bridge_raises(registry: ToolRegistry) -> None:
    """Verify get_frida_bridge raises when not registered.

    Args:
        registry: ToolRegistry fixture under test.
    """
    with pytest.raises(ToolError):
        registry.get_frida_bridge()


def test_get_ghidra_bridge_raises(registry: ToolRegistry) -> None:
    """Verify get_ghidra_bridge raises when not registered.

    Args:
        registry: ToolRegistry fixture under test.
    """
    with pytest.raises(ToolError):
        registry.get_ghidra_bridge()


def test_get_cutter_bridge_raises(registry: ToolRegistry) -> None:
    """Verify get_cutter_bridge raises when not registered.

    Args:
        registry: ToolRegistry fixture under test.
    """
    with pytest.raises(ToolError):
        registry.get_cutter_bridge()


def test_get_x64dbg_bridge_raises(registry: ToolRegistry) -> None:
    """Verify get_x64dbg_bridge raises when not registered.

    Args:
        registry: ToolRegistry fixture under test.
    """
    with pytest.raises(ToolError):
        registry.get_x64dbg_bridge()


def test_get_sandbox_bridge_raises(registry: ToolRegistry) -> None:
    """Verify get_sandbox_bridge raises when not registered.

    Args:
        registry: ToolRegistry fixture under test.
    """
    with pytest.raises(ToolError):
        registry.get_sandbox_bridge()


@pytest.mark.asyncio
async def test_execute_tool_call_unknown_tool(registry: ToolRegistry) -> None:
    """Verify execute_tool_call raises for unknown tool name.

    Args:
        registry: ToolRegistry fixture under test.
    """
    with pytest.raises(ToolError):
        await registry.execute_tool_call("nonexistent", "func", {})


@pytest.mark.asyncio
async def test_execute_tool_call_not_registered(registry: ToolRegistry) -> None:
    """Verify execute_tool_call raises for unregistered tool.

    Args:
        registry: ToolRegistry fixture under test.
    """
    with pytest.raises(ToolError):
        await registry.execute_tool_call("binary", "load_file", {})


@pytest.mark.asyncio
async def test_get_status_not_registered(registry: ToolRegistry) -> None:
    """Verify get_status returns unavailable for unregistered tool.

    Args:
        registry: ToolRegistry fixture under test.
    """
    status = await registry.get_status(ToolName.GHIDRA)
    assert isinstance(status, ToolStatus)
    assert status.available is False
    assert status.connected is False


@pytest.mark.asyncio
async def test_get_all_status_empty(registry: ToolRegistry) -> None:
    """Verify get_all_status returns empty list before init.

    Args:
        registry: ToolRegistry fixture under test.
    """
    statuses = await registry.get_all_status()
    assert statuses == []


@pytest.mark.asyncio
async def test_ensure_tool_ready_not_found(registry: ToolRegistry) -> None:
    """Verify ensure_tool_ready returns False for unregistered tool.

    Args:
        registry: ToolRegistry fixture under test.
    """
    result = await registry.ensure_tool_ready(ToolName.GHIDRA)
    assert result is False


@pytest.mark.asyncio
async def test_shutdown_empty(tmp_path: Path) -> None:
    """Verify shutdown clears bridges and definitions from a populated registry.

    The test drives a genuine state transition: initialize() populates the
    registry with all bridges (observable pre-condition), then shutdown()
    must empty it (asserted post-condition). An implementation that omits
    ``self._bridges.clear()`` inside shutdown() would leave len > 0 and fail.

    Mutation that falsifies: remove ``self._bridges.clear()`` from
    ToolRegistry.shutdown() (src/intellicrack/core/tools.py line 281);
    get_available_tools() would then return the same non-empty list it
    returned before shutdown, so both equality assertions would fail.

    Args:
        tmp_path: Pytest temporary directory.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    reg = ToolRegistry(tools_dir=tools_dir)
    await reg.initialize()

    pre_tools = reg.get_available_tools()
    pre_defs = reg.get_tool_definitions()
    assert len(pre_tools) == _BRIDGE_COUNT_ALL, (
        f"Expected {_BRIDGE_COUNT_ALL} bridges before shutdown, got {len(pre_tools)}"
    )
    assert len(pre_defs) == _BRIDGE_COUNT_ALL, (
        f"Expected {_BRIDGE_COUNT_ALL} definitions before shutdown, got {len(pre_defs)}"
    )

    await reg.shutdown()

    assert reg.get_available_tools() == []
    assert reg.get_tool_definitions() == []


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


def _assert_real_tool_definitions(defs: list[ToolDefinition], available: set[ToolName]) -> None:
    """Assert every definition is a real ToolDefinition covering the bridge set.

    Args:
        defs: Tool definitions returned by ``get_tool_definitions``.
        available: The registry's available tool names from ``get_available_tools``.
    """
    assert len(defs) == _BRIDGE_COUNT_ALL
    assert all(isinstance(d, ToolDefinition) for d in defs)
    assert {d.tool_name for d in defs} == available
    for definition in defs:
        assert isinstance(definition.tool_name, ToolName)
        assert definition.description.strip(), (
            f"{definition.tool_name} definition must carry a non-empty description"
        )
        assert definition.functions, (
            f"{definition.tool_name} definition must expose at least one function"
        )
        assert all(isinstance(fn, ToolFunction) for fn in definition.functions)


@pytest.mark.asyncio
async def test_get_tool_definitions_after_init(tmp_path: Path) -> None:
    """Verify get_tool_definitions returns real ToolDefinitions for every bridge.

    Asserts the concrete structure, not just the count: every element is a
    ``ToolDefinition`` (not, say, a raw bridge object that happens to number
    seven), the set of ``tool_name`` values equals the registry's available
    tools exactly, and each definition carries a non-empty description and at
    least one real ``ToolFunction``. A mutation returning
    ``list(self._bridges.values())`` (seven bridge objects) satisfies the old
    ``len == 7`` check but fails the ``isinstance(ToolDefinition)`` gate here.

    Args:
        tmp_path: Pytest temporary directory.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    reg = ToolRegistry(tools_dir=tools_dir)
    await reg.initialize()
    try:
        _assert_real_tool_definitions(reg.get_tool_definitions(), set(reg.get_available_tools()))
    finally:
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
