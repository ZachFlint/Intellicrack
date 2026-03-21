# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tool registry for managing tool bridges.

This module provides a registry for tool bridges that handles
initialization, availability checking, and tool schema generation
for LLM function calling.

Bridge imports are deferred to method bodies to break a circular
dependency: bridges.base -> core.logging -> core.__init__ -> core.tools
-> bridges.binary -> bridges.base.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from .logging import get_logger, log_tool_call
from .types import ToolDefinition, ToolError, ToolName


if TYPE_CHECKING:
    from pathlib import Path

    from ..bridges.base import ToolBridgeBase
    from ..bridges.binary import BinaryBridge
    from ..bridges.cutter import CutterBridge
    from ..bridges.frida_bridge import FridaBridge
    from ..bridges.ghidra import GhidraBridge
    from ..bridges.hex_editor import HexEditorBridge
    from ..bridges.process import ProcessBridge
    from ..bridges.sandbox_bridge import SandboxBridge
    from ..bridges.x64dbg import X64DbgBridge


_logger = get_logger("core.tools")

_ERR_BRIDGE_NA = "bridge not available"
_ERR_UNKNOWN_TOOL = "unknown tool"
_ERR_NOT_REGISTERED = "not registered"
_ERR_UNKNOWN_FUNC = "unknown function"
_ERR_NOT_CALLABLE = "not callable"
_ERR_CALL_FAILED = "call failed"


@dataclass
class ToolStatus:
    """Status of a registered tool.

    Attributes:
        name: Tool name.
        available: Whether the tool is available.
        connected: Whether the tool is connected.
        version: Tool version if known.
        path: Installation path if known.
        error: Last error if any.
    """

    name: ToolName
    available: bool
    connected: bool
    version: str | None = None
    path: Path | None = None
    error: str | None = None


class ToolRegistry:
    """Registry for tool bridges.

    Manages initialization, availability, and provides unified access
    to all tool bridges.

    Attributes:
        _bridges: Registered tool bridges.
        _installer: Tool installer/detector.
        _tools_dir: Directory for tool installations.
    """

    def __init__(self, tools_dir: Path) -> None:
        """Initialize the tool registry.

        Args:
            tools_dir: Directory for tool installations.
        """
        self._bridges: dict[ToolName, ToolBridgeBase] = {}
        from ..bridges.installer import ToolInstaller

        self._installer = ToolInstaller(tools_dir)
        self._tools_dir = tools_dir
        self._initialized = False
        _logger.debug("tool_registry_init", tools_dir=str(tools_dir))

    @property
    def tools_directory(self) -> Path:
        """Get the tools directory.

        Returns:
            Path to tools directory.
        """
        return self._tools_dir

    async def initialize(self) -> None:
        """Initialize all tool bridges.

        Creates bridge instances for all supported tools.
        """
        _logger.debug("tool_registry_initialize_entry", already_initialized=self._initialized)
        if self._initialized:
            _logger.debug("tool_registry_initialize_early_return", reason="already_initialized")
            return

        from ..bridges.binary import BinaryBridge as _BinaryBridge
        from ..bridges.cutter import CutterBridge as _CutterBridge
        from ..bridges.frida_bridge import FridaBridge as _FridaBridge
        from ..bridges.ghidra import GhidraBridge as _GhidraBridge
        from ..bridges.process import ProcessBridge as _ProcessBridge
        from ..bridges.sandbox_bridge import SandboxBridge as _SandboxBridge
        from ..bridges.x64dbg import X64DbgBridge as _X64DbgBridge

        self._bridges[ToolName.BINARY] = _BinaryBridge()
        self._bridges[ToolName.PROCESS] = _ProcessBridge()
        self._bridges[ToolName.FRIDA] = _FridaBridge()
        self._bridges[ToolName.GHIDRA] = _GhidraBridge()
        self._bridges[ToolName.CUTTER] = _CutterBridge()
        self._bridges[ToolName.X64DBG] = _X64DbgBridge()
        self._bridges[ToolName.SANDBOX] = _SandboxBridge()

        from ..bridges.hex_editor import HexEditorBridge as _HexEditorBridge

        self._bridges[ToolName.HEX_EDITOR] = _HexEditorBridge()
        _logger.debug(
            "bridges_instantiated",
            bridge_names=[n.value for n in self._bridges],
        )

        await self._bridges[ToolName.BINARY].initialize()
        await self._bridges[ToolName.PROCESS].initialize()
        await self._bridges[ToolName.FRIDA].initialize()
        await self._bridges[ToolName.SANDBOX].initialize()
        await self._bridges[ToolName.HEX_EDITOR].initialize()

        _logger.info("tool_registry_initialized", bridge_count=len(self._bridges))
        self._initialized = True

    async def initialize_tool(
        self,
        name: ToolName,
        port: int | None = None,
    ) -> bool:
        """Initialize a specific tool.

        Finds or installs the tool and initializes its bridge.

        Args:
            name: Tool to initialize.
            port: Network port for bridge communication if applicable.

        Returns:
            True if initialization succeeded.
        """
        if name not in self._bridges:
            _logger.error("unknown_tool", tool_name=name)
            return False

        bridge = self._bridges[name]

        if name in {ToolName.BINARY, ToolName.PROCESS, ToolName.FRIDA, ToolName.SANDBOX, ToolName.HEX_EDITOR}:
            if not await bridge.is_available():
                await bridge.initialize()
            return await bridge.is_available()

        success = False
        try:
            tool_path = await self._installer.ensure_tool(name)
            if name == ToolName.GHIDRA and port is not None:
                ghidra = cast("GhidraBridge", bridge)
                await ghidra.initialize(tool_path, port=port)
            else:
                await bridge.initialize(tool_path)
            _logger.info("tool_initialized", tool_name=name.value, tool_path=str(tool_path))
            success = True
        except Exception:
            _logger.exception("tool_initialization_failed", tool_name=name.value)

        return success

    async def shutdown(self) -> None:
        """Shutdown all tool bridges."""
        for name, bridge in self._bridges.items():
            try:
                await bridge.shutdown()
                _logger.debug("bridge_shutdown", bridge_name=name.value)
            except Exception as e:
                _logger.warning("bridge_shutdown_error", bridge_name=name.value, error=str(e))

        self._initialized = False
        _logger.info("tool_registry_shutdown", bridge_count=len(self._bridges))

    def get(self, name: ToolName) -> ToolBridgeBase | None:
        """Get a tool bridge by name.

        Args:
            name: Tool name.

        Returns:
            Tool bridge or None if not registered.
        """
        bridge = self._bridges.get(name)
        if bridge is not None:
            _logger.debug("bridge_cache_hit", tool_name=name.value)
        else:
            _logger.debug("bridge_cache_miss", tool_name=name.value)
        return bridge

    def get_binary_bridge(self) -> BinaryBridge:
        """Get the binary operations bridge.

        Returns:
            BinaryBridge instance.

        Raises:
            ToolError: If bridge not available.
        """
        from ..bridges.binary import BinaryBridge as _BinaryBridge

        bridge = self._bridges.get(ToolName.BINARY)
        if bridge is None or not isinstance(bridge, _BinaryBridge):
            raise ToolError(_ERR_BRIDGE_NA)
        _logger.debug("get_binary_bridge_success", bridge_type=type(bridge).__name__)
        return bridge

    def get_process_bridge(self) -> ProcessBridge:
        """Get the process control bridge.

        Returns:
            ProcessBridge instance.

        Raises:
            ToolError: If bridge not available.
        """
        from ..bridges.process import ProcessBridge as _ProcessBridge

        bridge = self._bridges.get(ToolName.PROCESS)
        if bridge is None or not isinstance(bridge, _ProcessBridge):
            raise ToolError(_ERR_BRIDGE_NA)
        _logger.debug("get_process_bridge_success", bridge_type=type(bridge).__name__)
        return bridge

    def get_frida_bridge(self) -> FridaBridge:
        """Get the Frida instrumentation bridge.

        Returns:
            FridaBridge instance.

        Raises:
            ToolError: If bridge not available.
        """
        from ..bridges.frida_bridge import FridaBridge as _FridaBridge

        bridge = self._bridges.get(ToolName.FRIDA)
        if bridge is None or not isinstance(bridge, _FridaBridge):
            raise ToolError(_ERR_BRIDGE_NA)
        _logger.debug("get_frida_bridge_success", bridge_type=type(bridge).__name__)
        return bridge

    def get_ghidra_bridge(self) -> GhidraBridge:
        """Get the Ghidra analysis bridge.

        Returns:
            GhidraBridge instance.

        Raises:
            ToolError: If bridge not available.
        """
        from ..bridges.ghidra import GhidraBridge as _GhidraBridge

        bridge = self._bridges.get(ToolName.GHIDRA)
        if bridge is None or not isinstance(bridge, _GhidraBridge):
            raise ToolError(_ERR_BRIDGE_NA)
        _logger.debug("get_ghidra_bridge_success", bridge_type=type(bridge).__name__)
        return bridge

    def get_cutter_bridge(self) -> CutterBridge:
        """Get the Cutter/Rizin analysis bridge.

        Returns:
            CutterBridge instance.

        Raises:
            ToolError: If bridge not available.
        """
        from ..bridges.cutter import CutterBridge as _CutterBridge

        bridge = self._bridges.get(ToolName.CUTTER)
        if bridge is None or not isinstance(bridge, _CutterBridge):
            raise ToolError(_ERR_BRIDGE_NA)
        _logger.debug("get_cutter_bridge_success", bridge_type=type(bridge).__name__)
        return bridge

    def get_x64dbg_bridge(self) -> X64DbgBridge:
        """Get the x64dbg debugger bridge.

        Returns:
            X64DbgBridge instance.

        Raises:
            ToolError: If bridge not available.
        """
        from ..bridges.x64dbg import X64DbgBridge as _X64DbgBridge

        bridge = self._bridges.get(ToolName.X64DBG)
        if bridge is None or not isinstance(bridge, _X64DbgBridge):
            raise ToolError(_ERR_BRIDGE_NA)
        _logger.debug("get_x64dbg_bridge_success", bridge_type=type(bridge).__name__)
        return bridge

    def get_sandbox_bridge(self) -> SandboxBridge:
        """Get the sandbox bridge.

        Returns:
            SandboxBridge instance.

        Raises:
            ToolError: If bridge not available.
        """
        from ..bridges.sandbox_bridge import SandboxBridge as _SandboxBridge

        bridge = self._bridges.get(ToolName.SANDBOX)
        if bridge is None or not isinstance(bridge, _SandboxBridge):
            raise ToolError(_ERR_BRIDGE_NA)
        _logger.debug("get_sandbox_bridge_success", bridge_type=type(bridge).__name__)
        return bridge

    def get_hex_editor_bridge(self) -> HexEditorBridge:
        """Get the hex editor bridge.

        Returns:
            HexEditorBridge instance.

        Raises:
            ToolError: If bridge not available.
        """
        from ..bridges.hex_editor import HexEditorBridge as _HexEditorBridge

        bridge = self._bridges.get(ToolName.HEX_EDITOR)
        if bridge is None or not isinstance(bridge, _HexEditorBridge):
            raise ToolError(_ERR_BRIDGE_NA)
        _logger.debug("get_hex_editor_bridge_success", bridge_type=type(bridge).__name__)
        return bridge

    async def get_status(self, name: ToolName) -> ToolStatus:
        """Get status of a tool.

        Args:
            name: Tool name.

        Returns:
            ToolStatus instance.
        """
        _logger.debug("get_status_entry", tool_name=name.value)
        bridge = self._bridges.get(name)
        if bridge is None:
            _logger.debug("get_status_not_registered", tool_name=name.value)
            return ToolStatus(
                name=name,
                available=False,
                connected=False,
                error="Tool not registered",
            )

        try:
            available = await bridge.is_available()
            state = bridge.state

            version = None
            path = None

            if name not in {ToolName.BINARY, ToolName.PROCESS, ToolName.FRIDA, ToolName.SANDBOX}:
                try:
                    path = await self._installer.find_tool(name)
                    if path is not None:
                        version = await self._installer.get_version(name, path)
                except Exception as e:
                    _logger.debug(
                        "tool_path_version_lookup_failed",
                        tool_name=name.value,
                        error=str(e),
                    )

            return ToolStatus(
                name=name,
                available=available,
                connected=state.connected,
                version=str(version) if version is not None else None,
                path=path,
                error=state.last_error,
            )

        except Exception as e:
            _logger.exception("tool_status_check_failed", tool=name)
            return ToolStatus(
                name=name,
                available=False,
                connected=False,
                error=str(e),
            )

    async def get_all_status(self) -> list[ToolStatus]:
        """Get status of all tools.

        Returns:
            List of ToolStatus instances.
        """
        _logger.debug("get_all_status_entry", bridge_count=len(self._bridges))
        tasks = [self.get_status(name) for name in self._bridges]
        results: list[ToolStatus] = list(await asyncio.gather(*tasks))
        _logger.debug("get_all_status_complete", status_count=len(results))
        return results

    def get_tool_definitions(self) -> list[ToolDefinition]:
        """Get tool definitions for LLM function calling.

        Returns:
            List of ToolDefinition instances.
        """
        _logger.debug("get_tool_definitions_entry", bridge_count=len(self._bridges))
        definitions: list[ToolDefinition] = []

        for bridge in self._bridges.values():
            try:
                definitions.append(bridge.tool_definition)
            except Exception as e:
                _logger.warning("tool_definition_retrieval_failed", error=str(e))

        _logger.debug("get_tool_definitions_complete", definition_count=len(definitions))
        return definitions

    def get_available_tools(self) -> list[ToolName]:
        """Get list of available tools.

        Returns:
            List of available tool names.
        """
        tools = list(self._bridges.keys())
        _logger.debug(
            "get_available_tools",
            tool_count=len(tools),
            tool_names=[t.value for t in tools],
        )
        return tools

    async def execute_tool_call(
        self,
        tool_name: str,
        function_name: str,
        arguments: dict[str, Any],
    ) -> Any:
        """Execute a tool function call.

        Args:
            tool_name: Name of the tool (e.g., "ghidra", "frida").
            function_name: Function to call (e.g., "decompile", "hook_function").
            arguments: Function arguments.

        Returns:
            Result of the function call.

        Raises:
            ToolError: If execution fails.
        """
        _logger.debug(
            "execute_tool_call_entry",
            tool_name=tool_name,
            function_name=function_name,
        )
        try:
            tool_enum = ToolName(tool_name.lower())
        except ValueError:
            _logger.debug("execute_tool_call_invalid_name", tool_name=tool_name)
            raise ToolError(_ERR_UNKNOWN_TOOL) from None

        _logger.debug("execute_tool_call_resolved", tool_enum=tool_enum.value)
        bridge = self._bridges.get(tool_enum)
        if bridge is None:
            _logger.debug("execute_tool_call_not_registered", tool_name=tool_enum.value)
            raise ToolError(_ERR_NOT_REGISTERED)

        attr_name = function_name.split(".", maxsplit=1)[-1] if "." in function_name else function_name
        method = getattr(bridge, attr_name, None)
        if method is None:
            _logger.debug(
                "execute_tool_call_unknown_func",
                tool_name=tool_enum.value,
                function_name=function_name,
                attr_name=attr_name,
            )
            raise ToolError(_ERR_UNKNOWN_FUNC)

        if not callable(method):
            _logger.debug(
                "execute_tool_call_not_callable",
                tool_name=tool_enum.value,
                function_name=function_name,
            )
            raise ToolError(_ERR_NOT_CALLABLE)

        caps = getattr(bridge, "capabilities", None)
        if caps is not None:
            capability_name = function_name.split("_", 1)[0] if "_" in function_name else function_name
            has_cap = caps.has_capability(capability_name)
            _logger.debug(
                "execute_tool_call_capability_check",
                tool_name=tool_enum.value,
                function_name=function_name,
                capability=capability_name,
                has_capability=has_cap,
            )

        start = time.monotonic()
        result: object = None
        success = True
        try:
            if inspect.iscoroutinefunction(method):
                result = await method(**arguments)
            else:
                result = await asyncio.to_thread(method, **arguments)
        except Exception as e:
            success = False
            _logger.warning("tool_call_failed", tool_name=tool_name, function_name=function_name, error=str(e))
            raise ToolError(_ERR_CALL_FAILED) from e
        finally:
            elapsed_ms = (time.monotonic() - start) * 1000
            log_tool_call(
                tool_name=tool_name,
                function_name=function_name,
                arguments=arguments,
                duration_ms=elapsed_ms,
                success=success,
            )

        if success:
            state = getattr(bridge, "state", None)
            if state is not None and hasattr(state, "clear_error"):
                state.clear_error()

        return result

    async def ensure_tool_ready(self, name: ToolName) -> bool:
        """Ensure a tool is ready for use.

        Initializes the tool if not already initialized.

        Args:
            name: Tool name.

        Returns:
            True if tool is ready.
        """
        _logger.debug("ensure_tool_ready_entry", tool_name=name.value)
        bridge = self._bridges.get(name)
        if bridge is None:
            _logger.debug("ensure_tool_ready_not_found", tool_name=name.value)
            return False

        if await bridge.is_available():
            _logger.debug("ensure_tool_ready_already_available", tool_name=name.value)
            return True

        _logger.debug("ensure_tool_ready_initializing", tool_name=name.value)
        return await self.initialize_tool(name)
