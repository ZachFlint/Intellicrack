# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Frida instrumentation bridge for dynamic analysis.

This module provides runtime instrumentation capabilities using Frida for function hooking, memory manipulation, and process control.
"""

from __future__ import annotations

import asyncio
import threading
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast, override

import frida

from intellicrack.bridges.base import (
    BridgeCapabilities,
    BridgeState,
    InstrumentationBridge,
    MemorySearchResult,
)
from intellicrack.core.logging import get_logger
from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.core.types import (
    ApiResolverMatch,
    ChildProcessInfo,
    CrashInfo,
    ExportInfo,
    FridaDeviceInfo,
    HookInfo,
    ImportInfo,
    MemoryRegion,
    ModuleInfo,
    StalkerEvent,
    StalkerTrace,
    SymbolInfo,
    ThreadInfo,
    ToolDefinition,
    ToolError,
    ToolFunction,
    ToolName,
    ToolParameter,
)


if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from frida.core import ScriptMessage

_logger = get_logger("bridges.frida")

_ERR_INIT_FAILED = "failed to initialize Frida"
_ERR_DEVICE_FAILED = "failed to initialize Frida device"
_ERR_PROCESS_NOT_FOUND = "process not found"
_ERR_ATTACH_FAILED = "failed to attach to process"
_ERR_NOT_ATTACHED = "not attached to a process"
_ERR_NO_SESSION = "no active session"
_ERR_READ_FAILED = "memory read failed"
_ERR_WRITE_FAILED = "memory write failed"
_ERR_ALLOC_FAILED = "memory allocation failed"
_ERR_PROTECT_FAILED = "memory protection change failed"
_ERR_HOOK_FAILED = "hook installation failed"
_ERR_SCRIPT_FAILED = "script execution failed"
_ERR_CALL_FAILED = "function call failed"
_ERR_MODULE_NOT_FOUND = "module not found"
_ERR_EXPORT_NOT_FOUND = "export not found"
_ERR_IMPORT_NOT_FOUND = "import enumeration failed"
_ERR_RESOLVE_FAILED = "symbol resolution failed"
_ERR_STALKER_FAILED = "Stalker tracing operation failed"
_ERR_CHILD_GATING_FAILED = "child gating operation failed"
_ERR_CRASH_REPORTING_FAILED = "crash reporting setup failed"
_ERR_ENUMERATE_FAILED = "enumeration failed"
_ERR_REPLACE_FAILED = "function replacement failed"
_ERR_NO_DEVICE = "no Frida device available"


_FRIDA_FUNCTIONS: list[ToolFunction] = [
    ToolFunction(
        name="frida.spawn",
        description="Spawn a process with Frida instrumentation",
        parameters=[
            ToolParameter(name="path", type="string", description="Path to executable", required=True),
            ToolParameter(name="args", type="array", description="Command line arguments", required=False),
        ],
        returns="Process ID of spawned process",
    ),
    ToolFunction(
        name="frida.attach",
        description="Attach Frida to a running process",
        parameters=[
            ToolParameter(name="target", type="string", description="Process name or PID", required=True),
        ],
        returns="Session information",
    ),
    ToolFunction(
        name="frida.detach",
        description="Detach Frida from current process",
        parameters=[],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.resume",
        description="Resume a spawned process that was paused",
        parameters=[],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.enumerate_modules",
        description="List all loaded modules in the process",
        parameters=[],
        returns="List of ModuleInfo objects",
    ),
    ToolFunction(
        name="frida.enumerate_exports",
        description="List exports of a module",
        parameters=[
            ToolParameter(name="module_name", type="string", description="Name of the module", required=True),
        ],
        returns="List of export names and addresses",
    ),
    ToolFunction(
        name="frida.enumerate_imports",
        description="List imports of a module",
        parameters=[
            ToolParameter(name="module_name", type="string", description="Name of the module", required=True),
        ],
        returns="List of import names and addresses",
    ),
    ToolFunction(
        name="frida.enumerate_threads",
        description="List all threads in the attached process",
        parameters=[],
        returns="List of ThreadInfo with TID, state, and PC",
    ),
    ToolFunction(
        name="frida.hook_function",
        description="Hook a function by name or address",
        parameters=[
            ToolParameter(
                name="target",
                type="string",
                description="Function name (module!func) or hex address",
                required=True,
            ),
            ToolParameter(
                name="on_enter",
                type="string",
                description="JavaScript code to run on function entry",
                required=False,
            ),
            ToolParameter(
                name="on_leave",
                type="string",
                description="JavaScript code to run on function exit",
                required=False,
            ),
        ],
        returns="Hook ID",
    ),
    ToolFunction(
        name="frida.remove_hook",
        description="Remove a previously installed hook",
        parameters=[
            ToolParameter(name="hook_id", type="string", description="ID of the hook to remove", required=True),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.read_memory",
        description="Read memory from the target process",
        parameters=[
            ToolParameter(name="address", type="integer", description="Memory address to read", required=True),
            ToolParameter(name="size", type="integer", description="Number of bytes to read", required=True),
        ],
        returns="Hex string of memory contents",
    ),
    ToolFunction(
        name="frida.write_memory",
        description="Write memory in the target process",
        parameters=[
            ToolParameter(name="address", type="integer", description="Memory address to write", required=True),
            ToolParameter(
                name="hex_data",
                type="string",
                description="Hex string of data to write",
                required=True,
            ),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.scan_memory",
        description="Scan process memory for a pattern",
        parameters=[
            ToolParameter(
                name="pattern",
                type="string",
                description="Hex pattern with wildcards (e.g., '48 8B ?? ??')",
                required=True,
            ),
            ToolParameter(
                name="module_name",
                type="string",
                description="Optional module to limit search",
                required=False,
            ),
        ],
        returns="List of addresses where pattern found",
    ),
    ToolFunction(
        name="frida.execute_script",
        description="Execute custom Frida JavaScript code",
        parameters=[
            ToolParameter(name="script", type="string", description="JavaScript code to execute", required=True),
        ],
        returns="Script execution result",
    ),
    ToolFunction(
        name="frida.intercept_return",
        description="Hook a function and modify its return value",
        parameters=[
            ToolParameter(name="target", type="string", description="Function to hook", required=True),
            ToolParameter(
                name="return_value",
                type="integer",
                description="Value to return instead",
                required=True,
            ),
        ],
        returns="Hook ID",
    ),
    ToolFunction(
        name="frida.call_function",
        description="Call a function in the target process",
        parameters=[
            ToolParameter(name="address", type="integer", description="Function address", required=True),
            ToolParameter(name="args", type="array", description="Function arguments (integers)", required=False),
        ],
        returns="Function return value",
    ),
    ToolFunction(
        name="frida.get_memory_regions",
        description="Get memory map of the process",
        parameters=[
            ToolParameter(
                name="protection",
                type="string",
                description="Filter by protection (e.g., 'r-x', '---' for all)",
                required=False,
            ),
        ],
        returns="List of memory regions",
    ),
    ToolFunction(
        name="frida.allocate_memory",
        description="Allocate memory in the target process (persists until detach)",
        parameters=[
            ToolParameter(name="size", type="integer", description="Size in bytes", required=True),
        ],
        returns="Address of allocated memory",
    ),
    ToolFunction(
        name="frida.get_hooks",
        description="Get all active hooks",
        parameters=[],
        returns="List of active hook information",
    ),
    ToolFunction(
        name="frida.protect_memory",
        description="Change memory protection flags for a region",
        parameters=[
            ToolParameter(name="address", type="integer", description="Start address of the region", required=True),
            ToolParameter(name="size", type="integer", description="Size of the region in bytes", required=True),
            ToolParameter(
                name="protection",
                type="string",
                description="New protection flags (e.g., 'rwx', 'r-x', 'rw-')",
                required=True,
            ),
        ],
        returns="True if protection was changed successfully",
    ),
    ToolFunction(
        name="frida.find_base_address",
        description="Get the base address of a loaded module",
        parameters=[
            ToolParameter(name="module_name", type="string", description="Name of the module", required=True),
        ],
        returns="Base address of the module",
    ),
    ToolFunction(
        name="frida.resolve_symbol",
        description="Resolve debug symbol information from an address",
        parameters=[
            ToolParameter(name="address", type="integer", description="Address to resolve", required=True),
        ],
        returns="SymbolInfo with name, module, file, and line number",
    ),
    ToolFunction(
        name="frida.find_functions_named",
        description="Find all functions matching a name across all modules",
        parameters=[
            ToolParameter(name="name", type="string", description="Function name to search for", required=True),
        ],
        returns="List of SymbolInfo for matching functions",
    ),
    ToolFunction(
        name="frida.resolve_api",
        description="Resolve API functions using Frida's ApiResolver with glob patterns",
        parameters=[
            ToolParameter(
                name="query",
                type="string",
                description="Query pattern (e.g., 'exports:*!CreateFile*', 'exports:kernel32.dll!*')",
                required=True,
            ),
        ],
        returns="List of matching API names and addresses",
    ),
    ToolFunction(
        name="frida.replace_function",
        description="Replace a function implementation with custom code",
        parameters=[
            ToolParameter(
                name="target",
                type="string",
                description="Function name (module!func) or hex address",
                required=True,
            ),
            ToolParameter(
                name="replacement_code",
                type="string",
                description="JavaScript body for the NativeCallback replacement",
                required=True,
            ),
        ],
        returns="Hook ID for the replacement",
    ),
    ToolFunction(
        name="frida.enumerate_processes",
        description="List all running processes on the device (no attachment needed)",
        parameters=[],
        returns="List of {pid, name} for each process",
    ),
    ToolFunction(
        name="frida.stalker_follow",
        description="Start Stalker code tracing on a thread",
        parameters=[
            ToolParameter(
                name="thread_id",
                type="integer",
                description="Thread ID to trace (null for current thread)",
                required=False,
            ),
            ToolParameter(
                name="events",
                type="string",
                description="Comma-separated event types: call, ret, exec, block, compile",
                required=False,
                default="call",
            ),
            ToolParameter(
                name="limit",
                type="integer",
                description="Maximum events to collect before auto-stop",
                required=False,
                default=10000,
            ),
        ],
        returns="Trace ID for later retrieval via stalker_unfollow",
    ),
    ToolFunction(
        name="frida.stalker_unfollow",
        description="Stop Stalker tracing and retrieve collected events",
        parameters=[
            ToolParameter(
                name="thread_id",
                type="integer",
                description="Thread ID to stop tracing (null for current thread)",
                required=False,
            ),
        ],
        returns="StalkerTrace with collected events and duration",
    ),
    ToolFunction(
        name="frida.enable_child_gating",
        description="Enable child process gating to intercept spawned child processes",
        parameters=[],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.disable_child_gating",
        description="Disable child process gating",
        parameters=[],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.get_pending_children",
        description="Get list of child processes intercepted by child gating",
        parameters=[],
        returns="List of ChildProcessInfo",
    ),
    ToolFunction(
        name="frida.resume_child",
        description="Resume a gated child process",
        parameters=[
            ToolParameter(name="pid", type="integer", description="PID of the child process to resume", required=True),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.enable_crash_reporting",
        description="Enable crash event monitoring for attached processes",
        parameters=[],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.get_crashes",
        description="Get all collected crash reports",
        parameters=[],
        returns="List of CrashInfo with crash details",
    ),
    ToolFunction(
        name="frida.enumerate_devices",
        description="List all available Frida devices (local, USB, remote)",
        parameters=[],
        returns="List of FridaDeviceInfo",
    ),
    ToolFunction(
        name="frida.connect_device",
        description="Switch to a different Frida device",
        parameters=[
            ToolParameter(
                name="device_type",
                type="string",
                description="Device type: 'local', 'usb', or 'remote'",
                required=True,
                enum=["local", "usb", "remote"],
            ),
            ToolParameter(
                name="host",
                type="string",
                description="Remote host address (required for 'remote' type)",
                required=False,
            ),
        ],
        returns="FridaDeviceInfo for the connected device",
    ),
]


class FridaBridge(InstrumentationBridge):
    """Bridge for Frida dynamic instrumentation.

    Provides function hooking, memory manipulation, and script execution capabilities using the Frida framework.
    """

    def __init__(self) -> None:
        super().__init__()
        self._device: frida.core.Device | None = None
        self._session: frida.core.Session | None = None
        self._scripts: dict[str, frida.core.Script] = {}
        self._hooks: dict[str, HookInfo] = {}
        self._message_handler: Callable[[dict[str, object]], None] | None = None
        self._pid: int | None = None
        self._spawned_pid: int | None = None
        self._stalker_traces: dict[int, list[StalkerEvent]] = {}
        self._stalker_traces_lock: threading.Lock = threading.Lock()
        self._stalker_scripts: dict[int, str] = {}
        self._child_gating_enabled: bool = False
        self._gated_children: list[ChildProcessInfo] = []
        self._gated_children_lock: threading.Lock = threading.Lock()
        self._crashes: list[CrashInfo] = []
        self._crashes_lock: threading.Lock = threading.Lock()
        self._alloc_scripts: dict[int, str] = {}
        self._capabilities = BridgeCapabilities(
            supports_dynamic_analysis=True,
            supports_patching=True,
            supports_scripting=True,
            supported_architectures=["x86", "x86_64", "arm", "arm64"],
            supported_formats=["pe", "elf", "macho"],
        )

    @property
    def name(self) -> ToolName:
        """Get the tool's name.

        Returns:
            ToolName: ToolName.FRIDA
        """
        return ToolName.FRIDA

    @property
    def tool_definition(self) -> ToolDefinition:
        """Get tool definition for LLM function calling.

        Returns:
            ToolDefinition: ToolDefinition with all available functions.
        """
        return ToolDefinition(
            tool_name=ToolName.FRIDA,
            description="Frida dynamic instrumentation - hooking, tracing, memory manipulation",
            functions=_FRIDA_FUNCTIONS,
        )

    async def initialize(self, tool_path: Path | None = None) -> None:
        """Initialize the Frida bridge.

        Args:
            tool_path: Not used for Frida (uses frida-python).

        Raises:
            ToolError: If Frida device initialization fails.
        """
        del tool_path
        try:
            self._device = await asyncio.to_thread(frida.get_local_device)
            self.state = BridgeState(
                connected=True,
                tool_running=True,
                binary_loaded=False,
                process_attached=False,
                target_path=None,
                target_pid=None,
                last_error=None,
            )
            _logger.info("frida_bridge_initialized", bridge="frida")
        except Exception as e:
            _logger.warning("frida_init_failed", error=str(e))
            self.state.connected = False
            self.state.tool_running = False
            self.state.last_error = str(e)
            raise ToolError(_ERR_INIT_FAILED) from e

    async def shutdown(self) -> None:
        """Shutdown Frida and cleanup resources."""
        for tid in list(self._stalker_scripts.keys()):
            script_id = self._stalker_scripts.get(tid)
            if script_id is not None:
                try:
                    await self._unload_script(script_id)
                except Exception:
                    _logger.exception("stalker_script_unload_failed", thread_id=tid)
        self._stalker_scripts.clear()
        self._stalker_traces.clear()

        if self._child_gating_enabled and self._device is not None:
            try:
                await asyncio.to_thread(self._device.disable_spawn_gating)
            except Exception:
                _logger.exception("child_gating_disable_failed_during_shutdown")
            self._child_gating_enabled = False

        for alloc_addr, alloc_script_id in list(self._alloc_scripts.items()):
            try:
                await self._unload_script(alloc_script_id)
            except Exception:
                _logger.exception("alloc_script_unload_failed", address=hex(alloc_addr))
        self._alloc_scripts.clear()

        for script_id in list(self._scripts.keys()):
            try:
                await self._unload_script(script_id)
            except Exception:
                _logger.exception("script_unload_failed", script_id=script_id)

        if self._session is not None:
            try:
                await asyncio.to_thread(self._session.detach)
            except Exception:
                _logger.exception("session_detach_failed", bridge="frida")
            self._session = None

        if self._spawned_pid is not None and self._device is not None:
            try:
                await asyncio.to_thread(self._device.kill, self._spawned_pid)
                _logger.info("spawned_process_killed", pid=self._spawned_pid)
            except Exception:
                _logger.exception("spawned_process_kill_failed", pid=self._spawned_pid)

            process_manager = ProcessManager.get_instance()
            process_manager.unregister_external_pid(self._spawned_pid)
            self._spawned_pid = None

        self._device = None
        self._pid = None
        self._hooks = {}
        with self._gated_children_lock:
            self._gated_children.clear()
        with self._crashes_lock:
            self._crashes.clear()
        await super().shutdown()
        _logger.info("frida_bridge_shutdown", bridge="frida")

    @override
    async def is_available(self) -> bool:
        """Check if Frida is available.

        Returns:
            bool: True if Frida is installed and working.
        """
        try:
            await asyncio.to_thread(frida.get_local_device)
        except (OSError, RuntimeError) as e:
            _logger.debug("frida_availability_check_failed", error=str(e))
            return False
        else:
            return True

    async def attach(self, pid: int) -> None:
        """Attach to a running process.

        Args:
            pid: Process ID to attach to.

        Raises:
            ToolError: If attachment fails.
        """
        if self._device is None:
            await self.initialize()

        device = self._device
        if device is None:
            raise ToolError(_ERR_DEVICE_FAILED)

        try:
            self._session = await asyncio.to_thread(
                device.attach,
                pid,
            )
            self._pid = pid
            self.state.connected = True
            self.state.tool_running = True
            self.state.process_attached = True
            self.state.target_pid = pid

            _logger.info("process_attached", pid=pid)
        except frida.ProcessNotFoundError as e:
            _logger.warning("frida_process_not_found", pid=pid, error=str(e))
            raise ToolError(_ERR_PROCESS_NOT_FOUND) from e
        except Exception as e:
            _logger.warning("frida_attach_failed", pid=pid, error=str(e))
            raise ToolError(_ERR_ATTACH_FAILED) from e

    async def attach_by_name(self, name: str) -> None:
        """Attach to a process by name.

        Args:
            name: Process name to attach to.

        Raises:
            ToolError: If attachment fails.
        """
        if self._device is None:
            await self.initialize()

        device = self._device
        if device is None:
            raise ToolError(_ERR_DEVICE_FAILED)

        try:
            processes = await asyncio.to_thread(device.enumerate_processes)
        except Exception as e:
            _logger.warning("frida_enumerate_processes_failed", error=str(e))
            raise ToolError(_ERR_ATTACH_FAILED) from e

        target_pid: int | None = next((proc.pid for proc in processes if proc.name == name), None)
        if target_pid is None:
            raise ToolError(_ERR_PROCESS_NOT_FOUND)

        try:
            self._session = await asyncio.to_thread(
                device.attach,
                name,
            )
        except frida.ProcessNotFoundError as e:
            _logger.warning("frida_process_not_found_by_name", process_name=name, error=str(e))
            raise ToolError(_ERR_PROCESS_NOT_FOUND) from e
        except Exception as e:
            _logger.warning("frida_attach_by_name_failed", process_name=name, error=str(e))
            raise ToolError(_ERR_ATTACH_FAILED) from e

        self._pid = target_pid
        self.state.connected = True
        self.state.tool_running = True
        self.state.process_attached = True
        self.state.target_pid = self._pid

        _logger.info("process_attached_by_name", process_name=name, pid=self._pid)

    async def spawn(
        self,
        path: Path,
        args: Sequence[str] | None = None,
    ) -> int:
        """Spawn a new process with Frida instrumentation.

        Args:
            path: Path to executable.
            args: Command line arguments.

        Returns:
            int: PID of spawned process.

        Raises:
            ToolError: If spawn fails.
        """
        if self._device is None:
            await self.initialize()

        device = self._device
        if device is None:
            raise ToolError(_ERR_DEVICE_FAILED)

        spawn_argv: list[str | bytes] = [str(path)]
        if args:
            spawn_argv.extend(args)

        try:
            pid: int = await asyncio.to_thread(
                device.spawn,
                str(path),
                argv=spawn_argv,
            )
        except Exception as e:
            _logger.warning("frida_spawn_failed", path=str(path), error=str(e))
            raise ToolError(_ERR_ATTACH_FAILED) from e

        try:
            self._session = await asyncio.to_thread(
                device.attach,
                pid,
            )
            self._pid = pid
            self._spawned_pid = pid

            process_manager = ProcessManager.get_instance()
            process_manager.register_external_pid(
                pid,
                name=f"frida-spawn-{path.name}",
                process_type=ProcessType.DEBUGGER,
                metadata={"path": str(path), "args": args or []},
            )

            self.state.connected = True
            self.state.tool_running = True
            self.state.process_attached = True
            self.state.target_path = path
            self.state.target_pid = pid

            _logger.info("process_spawned", process_name=path.name, pid=pid)
        except (OSError, RuntimeError) as e:
            try:
                await asyncio.to_thread(device.kill, pid)
            except (OSError, RuntimeError) as kill_err:
                _logger.warning(
                    "failed_to_kill_leaked_process",
                    pid=pid,
                    error=str(kill_err),
                )
            raise ToolError(_ERR_ATTACH_FAILED) from e
        else:
            return pid

    async def resume(self) -> None:
        """Resume a spawned process.

        Raises:
            ToolError: If resume fails.
        """
        if self._device is None or self._pid is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        try:
            await asyncio.to_thread(self._device.resume, self._pid)
            _logger.info("process_resumed", pid=self._pid)
        except Exception as e:
            _logger.warning("frida_resume_failed", pid=self._pid, error=str(e))
            raise ToolError(_ERR_NOT_ATTACHED) from e

    async def detach(self, *, kill_spawned: bool = True) -> None:
        """Detach from the current process.

        Args:
            kill_spawned: If True and process was spawned by us, kill it.

        Raises:
            ToolError: If detachment fails.
        """
        if self._session is None:
            _logger.warning("detach_no_session", bridge="frida", reason=_ERR_NO_SESSION)
            return

        try:
            for script_id in list(self._scripts.keys()):
                await self._unload_script(script_id)

            await asyncio.to_thread(self._session.detach)
            self._session = None

            if kill_spawned and self._spawned_pid is not None and self._device is not None:
                try:
                    await asyncio.to_thread(self._device.kill, self._spawned_pid)
                    _logger.info("spawned_process_killed", pid=self._spawned_pid)
                except Exception:
                    _logger.exception("spawned_process_kill_failed", pid=self._spawned_pid)

                process_manager = ProcessManager.get_instance()
                process_manager.unregister_external_pid(self._spawned_pid)
                self._spawned_pid = None

            self._pid = None
            self._hooks = {}
            self.state.connected = True
            self.state.tool_running = True
            self.state.process_attached = False
            self.state.target_pid = None

            _logger.info("process_detached", bridge="frida")
        except Exception as e:
            _logger.warning("frida_detach_failed", error=str(e))
            raise ToolError(_ERR_NOT_ATTACHED) from e

    async def read_memory(self, address: int, size: int) -> bytes:
        """Read memory from the target process.

        Args:
            address: Memory address.
            size: Number of bytes to read.

        Returns:
            bytes: Memory contents.

        Raises:
            ToolError: If read fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        _logger.debug("memory_read_starting", address=hex(address), size=size)

        script_code = f"""
        var data = ptr({address}).readByteArray({size});
        send({{ type: 'memory' }}, data);
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(_ERR_READ_FAILED)

        read_data = result.get("data")
        if isinstance(read_data, (bytes, bytearray)):
            return bytes(read_data)
        if isinstance(read_data, list):
            return bytes(cast("list[int]", read_data))

        raise ToolError(_ERR_READ_FAILED)

    async def write_memory(self, address: int, data: bytes) -> int:
        """Write memory in the target process.

        Args:
            address: Memory address.
            data: Bytes to write.

        Returns:
            int: Number of bytes written.

        Raises:
            ToolError: If write fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        hex_array = ", ".join(f"0x{b:02x}" for b in data)
        script_code = f"""
        var bytes = [{hex_array}];
        ptr({address}).writeByteArray(bytes);
        send({{ type: 'success' }});
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(_ERR_WRITE_FAILED)

        _logger.debug("memory_written", length=len(data), address=hex(address))
        return len(data)

    async def get_memory_regions(self, protection: str = "---") -> list[MemoryRegion]:
        """Get process memory map.

        Args:
            protection: Memory protection filter (e.g., 'r-x', '---' for all).

        Returns:
            list[MemoryRegion]: List of memory regions.

        Raises:
            ToolError: If operation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        _logger.debug("memory_regions_enumerating", protection=protection)
        script_code = (
            f"var ranges = Process.enumerateRanges('{protection}" + "');\n"
            "var result = ranges.map(function(r) {\n"
            "    return {\n"
            "        base: r.base.toString(),\n"
            "        size: r.size,\n"
            "        protection: r.protection,\n"
            "        file: r.file ? r.file.path : null\n"
            "    };\n"
            "});\n"
            "send({ type: 'ranges', data: result });\n"
        )

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(_ERR_READ_FAILED)

        regions: list[MemoryRegion] = []
        range_data = result.get("data", [])
        if isinstance(range_data, list):
            for raw_item in cast("list[object]", range_data):
                if not isinstance(raw_item, dict):
                    continue
                r = cast("dict[str, object]", raw_item)
                base_str = str(r.get("base", "0"))
                base = int(base_str, 16) if base_str.startswith("0x") else int(base_str)
                size_val = r.get("size", 0)
                protection_val = r.get("protection", "")
                file_val = r.get("file")
                regions.append(
                    MemoryRegion(
                        base_address=base,
                        size=int(size_val) if isinstance(size_val, (int, float)) else 0,
                        protection=str(protection_val) if protection_val else "",
                        state="MEM_COMMIT",
                        type="MEM_PRIVATE",
                        module_name=str(file_val) if file_val is not None else None,
                    ),
                )

        _logger.debug("memory_regions_enumerated", count=len(regions))
        return regions

    async def scan_memory(self, pattern: bytes) -> list[MemorySearchResult]:
        """Scan process memory for a pattern.

        Args:
            pattern: Byte pattern to search for.

        Returns:
            list[MemorySearchResult]: List of matches with context.

        Raises:
            ToolError: If scan fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        _logger.debug("memory_scan_starting", pattern_length=len(pattern))
        hex_pattern = " ".join(f"{b:02x}" for b in pattern)

        script_code = f"""
        var ranges = Process.enumerateRanges('r--');
        var results = [];
        ranges.forEach(function(range) {{
            try {{
                var matches = Memory.scanSync(range.base, range.size, '{hex_pattern}');
                matches.forEach(function(m) {{
                    results.push({{
                        address: m.address.toString(),
                        size: m.size
                    }});
                }});
            }} catch (e) {{}}
        }});
        send({{ type: 'scan', data: results }});
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(_ERR_READ_FAILED)

        matches: list[MemorySearchResult] = []
        scan_data = result.get("data", [])
        if isinstance(scan_data, list):
            for raw_match in cast("list[object]", scan_data):
                if not isinstance(raw_match, dict):
                    continue
                m = cast("dict[str, object]", raw_match)
                addr_str = str(m.get("address", "0"))
                addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                matches.append(
                    MemorySearchResult(
                        address=addr,
                        matched_bytes=hex_pattern,
                        context_before="",
                        context_after="",
                    ),
                )

        _logger.debug("memory_scan_completed", matches=len(matches))
        return matches

    async def enumerate_modules(self) -> list[ModuleInfo]:
        """List all loaded modules in the process.

        Returns:
            list[ModuleInfo]: List of module information.

        Raises:
            ToolError: If operation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = """
        var modules = Process.enumerateModules();
        var result = modules.map(function(m) {
            return {
                name: m.name,
                path: m.path,
                base: m.base.toString(),
                size: m.size
            };
        });
        send({ type: 'modules', data: result });
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(_ERR_MODULE_NOT_FOUND)

        modules: list[ModuleInfo] = []
        mod_data = result.get("data", [])
        if isinstance(mod_data, list):
            for raw_mod in cast("list[object]", mod_data):
                if not isinstance(raw_mod, dict):
                    continue
                m = cast("dict[str, object]", raw_mod)
                base_str = str(m.get("base", "0"))
                base = int(base_str, 16) if base_str.startswith("0x") else int(base_str)
                name_val = m.get("name", "")
                path_val = m.get("path", "")
                size_val = m.get("size", 0)
                modules.append(
                    ModuleInfo(
                        name=str(name_val) if name_val else "",
                        path=Path(str(path_val) if path_val else ""),
                        base_address=base,
                        size=int(size_val) if isinstance(size_val, (int, float)) else 0,
                        entry_point=0,
                    ),
                )

        _logger.debug("modules_enumerated", count=len(modules))
        return modules

    async def enumerate_exports(self, module_name: str) -> list[ExportInfo]:
        """List exports of a module.

        Args:
            module_name: Name of the module.

        Returns:
            list[ExportInfo]: List of export information.

        Raises:
            ToolError: If operation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = f"""
        var mod = Process.findModuleByName('{module_name}');
        if (!mod) {{
            send({{ type: 'exports', data: [] }});
        }} else {{
            var exports = mod.enumerateExports();
            var result = exports.map(function(e) {{
                return {{
                    name: e.name,
                    type: e.type,
                    address: e.address.toString()
                }};
            }});
            send({{ type: 'exports', data: result }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(_ERR_EXPORT_NOT_FOUND)

        exports: list[ExportInfo] = []
        export_data = result.get("data", [])
        if isinstance(export_data, list):
            for idx, raw_export in enumerate(cast("list[object]", export_data)):
                if not isinstance(raw_export, dict):
                    continue
                e = cast("dict[str, object]", raw_export)
                addr_str = str(e.get("address", "0"))
                addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                name_val = e.get("name", "")
                exports.append(
                    ExportInfo(
                        name=str(name_val) if name_val else "",
                        ordinal=idx,
                        address=addr,
                    ),
                )

        _logger.debug("exports_enumerated", module=module_name, count=len(exports))
        return exports

    async def hook_function(
        self,
        target: str,
        on_enter: str | None = None,
        on_leave: str | None = None,
    ) -> HookInfo:
        """Attach a hook to a function by name or address.

        Args:
            target: Function name (module!func) or hex address.
            on_enter: JavaScript code for function entry.
            on_leave: JavaScript code for function exit.

        Returns:
            HookInfo: Hook information.

        Raises:
            ToolError: If hooking fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        hook_id = str(uuid.uuid4())[:8]
        addr_resolve = self._resolve_target_js(target)

        on_enter_code = on_enter or "console.log('[+] Called ' + this.context.pc);"
        on_leave_code = on_leave or ""

        script_code = f"""
        var target = {addr_resolve};
        Interceptor.attach(target, {{
            onEnter: function(args) {{
                {on_enter_code}
            }},
            onLeave: function(retval) {{
                {on_leave_code}
            }}
        }});
        send({{ type: 'hooked', address: target.toString() }});
        """

        try:
            script = await asyncio.to_thread(self._session.create_script, script_code)
        except Exception as e:
            _logger.warning("hook_create_script_failed", target=target, error=str(e))
            raise ToolError(_ERR_HOOK_FAILED) from e

        messages: list[ScriptMessage] = []

        def on_message(message: ScriptMessage, data: bytes | None) -> None:
            del data
            messages.append(message)
            if self._message_handler:
                raw: dict[str, object] = dict(cast("dict[str, object]", message))
                self._message_handler(raw)

        script.on("message", on_message)
        await asyncio.to_thread(script.load)

        await asyncio.sleep(0.1)

        address: int | None = None
        for msg in messages:
            if msg["type"] == "send":
                payload = msg.get("payload", {})
                if isinstance(payload, dict):
                    payload_dict = cast("dict[str, object]", payload)
                    if payload_dict.get("type") == "hooked":
                        addr_val = payload_dict.get("address", "0")
                        if isinstance(addr_val, str):
                            address = int(addr_val, 16) if addr_val.startswith("0x") else int(addr_val)

        self._scripts[hook_id] = script

        hook_info = HookInfo(
            id=hook_id,
            target=target,
            address=address,
            script_id=hook_id,
            active=True,
        )
        self._hooks[hook_id] = hook_info

        _logger.info("hook_installed", hook_id=hook_id, target=target)
        return hook_info

    async def remove_hook(self, hook_id: str) -> bool:
        """Remove a previously installed hook.

        Args:
            hook_id: ID of the hook to remove.

        Returns:
            bool: True if removed successfully, False if hook not found.
        """
        if hook_id not in self._scripts:
            _logger.warning("hook_not_found", hook_id=hook_id)
            return False

        await self._unload_script(hook_id)
        del self._hooks[hook_id]

        _logger.info("hook_removed", hook_id=hook_id)
        return True

    async def get_hooks(self) -> list[HookInfo]:
        """Get all active hooks.

        Returns:
            list[HookInfo]: List of hook information.
        """
        _logger.debug("hooks_listed", count=len(self._hooks))
        return list(self._hooks.values())

    async def execute_script(self, script: str) -> str:
        """Execute custom Frida JavaScript code.

        Args:
            script: JavaScript code to execute.

        Returns:
            str: Script execution result.

        Raises:
            ToolError: If execution fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        _logger.debug("script_executing", script_length=len(script))
        result = await self._execute_script_and_wait(script)

        if "error" in result:
            raise ToolError(_ERR_SCRIPT_FAILED)

        return str(result)

    async def execute_persistent_script(self, script_code: str) -> str:
        """Execute a Frida script that persists until explicitly unloaded.

        Unlike execute_script which runs and immediately unloads,
        this keeps the script active for persistent hooks like
        Interceptor.attach.

        Args:
            script_code: JavaScript code to execute.

        Returns:
            str: Script ID for later unloading via unload_script.

        Raises:
            ToolError: If not attached or script fails to load.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_id = str(uuid.uuid4())[:8]

        script = await asyncio.to_thread(self._session.create_script, script_code)

        def on_message(message: ScriptMessage, data: bytes | None) -> None:
            del data
            if self._message_handler:
                raw: dict[str, object] = dict(cast("dict[str, object]", message))
                self._message_handler(raw)

        script.on("message", on_message)
        await asyncio.to_thread(script.load)

        self._scripts[script_id] = script
        _logger.info("persistent_script_loaded", script_id=script_id)
        return script_id

    async def unload_script(self, script_id: str) -> bool:
        """Unload a specific script by ID.

        Args:
            script_id: Script ID returned by execute_persistent_script.

        Returns:
            bool: True if unloaded, False if script not found.
        """
        if script_id not in self._scripts:
            _logger.warning("script_not_found_for_unload", script_id=script_id)
            return False

        await self._unload_script(script_id)
        _logger.info("script_unloaded", script_id=script_id)
        return True

    async def intercept_return(self, target: str, return_value: int) -> HookInfo:
        """Intercept a function and replace its return value.

        Args:
            target: Function to hook.
            return_value: Value to return instead.

        Returns:
            HookInfo: Hook information.
        """
        _logger.debug("intercept_return_setting", target=target, return_value=return_value)
        on_leave = f"retval.replace({return_value});"
        return await self.hook_function(
            target=target,
            on_leave=on_leave,
        )

    async def call_function(
        self,
        address: int,
        args: Sequence[int] | None = None,
    ) -> int:
        """Call a function in the target process.

        Args:
            address: Function address.
            args: Function arguments.

        Returns:
            int: Function return value.

        Raises:
            ToolError: If call fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        _logger.debug("function_calling", address=hex(address), arg_count=len(args) if args else 0)
        args_list = args or []
        args_code = ", ".join(f"ptr({a})" for a in args_list)

        script_code = f"""
        var func = new NativeFunction(ptr({address}), 'pointer', [{", ".join(["'pointer'"] * len(args_list))}]);
        var result = func({args_code});
        send({{ type: 'call_result', value: result.toInt32() }});
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(_ERR_CALL_FAILED)

        value = result.get("value", 0)
        if isinstance(value, int):
            return value
        return int(value) if isinstance(value, (str, float)) else 0

    async def _execute_script_and_wait(
        self,
        script_code: str,
        max_wait: float = 5.0,
    ) -> dict[str, Any]:
        """Execute a script and wait for result.

        Args:
            script_code: JavaScript code to execute.
            max_wait: Maximum seconds to wait for a response.

        Returns:
            dict[str, Any]: Script result as dictionary.

        Raises:
            ToolError: If not attached to a process.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        result: dict[str, Any] = {}
        event = asyncio.Event()

        def on_message(message: ScriptMessage, data: bytes | None) -> None:
            if message["type"] == "send":
                payload = message.get("payload", {})
                if isinstance(payload, dict):
                    result.update(dict(cast("dict[str, object]", payload).items()))
                    if data:
                        result["data"] = list(data)
            elif message["type"] == "error":
                result["error"] = message["description"]
            event.set()

        script = await asyncio.to_thread(self._session.create_script, script_code)
        script.on("message", on_message)
        await asyncio.to_thread(script.load)

        try:
            await asyncio.wait_for(event.wait(), timeout=max_wait)
        except TimeoutError:
            _logger.warning("frida_script_execution_timeout", max_wait=max_wait)
            result["error"] = "Script execution timed out"

        await asyncio.to_thread(script.unload)

        return result

    async def _unload_script(self, script_id: str) -> None:
        """Unload a script.

        Args:
            script_id: Script ID to unload.
        """
        if script_id in self._scripts:
            script = self._scripts[script_id]
            try:
                await asyncio.to_thread(script.unload)
            except Exception:
                _logger.exception("script_unload_failed", script_id=script_id)
            del self._scripts[script_id]

    async def unload_all_scripts(self) -> None:
        """Unload all active scripts."""
        _logger.debug("unloading_all_scripts", count=len(self._scripts))
        for script_id in list(self._scripts.keys()):
            await self._unload_script(script_id)

    def set_message_handler(
        self,
        handler: Callable[[dict[str, object]], None],
    ) -> None:
        """Set handler for script messages.

        Args:
            handler: Callback function for messages.
        """
        _logger.debug("message_handler_set")
        self._message_handler = handler

    @override
    async def enumerate_imports(self, module_name: str) -> list[ImportInfo]:
        """List imports of a module.

        Args:
            module_name: Name of the module.

        Returns:
            list[ImportInfo]: List of import information.

        Raises:
            ToolError: If operation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = f"""
        var mod = Process.findModuleByName('{module_name}');
        if (!mod) {{
            send({{ type: 'imports', data: [] }});
        }} else {{
            var imports = mod.enumerateImports();
            var result = imports.map(function(i) {{
                return {{
                    name: i.name,
                    module: i.module || '',
                    type: i.type,
                    address: i.address ? i.address.toString() : '0'
                }};
            }});
            send({{ type: 'imports', data: result }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(_ERR_IMPORT_NOT_FOUND)

        imports: list[ImportInfo] = []
        import_data = result.get("data", [])
        if isinstance(import_data, list):
            for raw_import in cast("list[object]", import_data):
                if not isinstance(raw_import, dict):
                    continue
                entry = cast("dict[str, object]", raw_import)
                addr_str = str(entry.get("address", "0"))
                addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                name_val = entry.get("name", "")
                module_val = entry.get("module", "")
                imports.append(
                    ImportInfo(
                        dll=str(module_val) if module_val else "",
                        function=str(name_val) if name_val else "",
                        ordinal=None,
                        address=addr,
                    ),
                )

        _logger.debug("imports_enumerated", module=module_name, count=len(imports))
        return imports

    @override
    async def enumerate_threads(self) -> list[ThreadInfo]:
        """List all threads in the attached process.

        Returns:
            list[ThreadInfo]: List of thread information.

        Raises:
            ToolError: If operation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = """
        var threads = Process.enumerateThreads();
        var result = threads.map(function(t) {
            return {
                id: t.id,
                state: t.state,
                pc: t.context.pc.toString()
            };
        });
        send({ type: 'threads', data: result });
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(_ERR_ENUMERATE_FAILED)

        threads: list[ThreadInfo] = []
        thread_data = result.get("data", [])
        if isinstance(thread_data, list):
            for raw_thread in cast("list[object]", thread_data):
                if not isinstance(raw_thread, dict):
                    continue
                t = cast("dict[str, object]", raw_thread)
                tid_val = t.get("id", 0)
                state_val = t.get("state", "waiting")
                pc_str = str(t.get("pc", "0"))
                pc = int(pc_str, 16) if pc_str.startswith("0x") else int(pc_str)
                threads.append(
                    ThreadInfo(
                        tid=int(tid_val) if isinstance(tid_val, (int, float)) else 0,
                        start_address=pc,
                        state=str(state_val) if state_val else "waiting",
                        priority=0,
                    ),
                )

        _logger.debug("threads_enumerated", count=len(threads))
        return threads

    async def allocate_memory(self, size: int) -> int:
        """Allocate memory in the target process.

        Uses a persistent script to prevent garbage collection of the
        allocated memory block.

        Args:
            size: Number of bytes to allocate.

        Returns:
            int: Address of the allocated memory.

        Raises:
            ToolError: If allocation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = f"""
        var block = Memory.alloc({size});
        send({{ type: 'alloc', address: block.toString() }});
        """

        script_id = str(uuid.uuid4())[:8]
        script = await asyncio.to_thread(self._session.create_script, script_code)

        messages: list[ScriptMessage] = []

        def on_message(message: ScriptMessage, data: bytes | None) -> None:
            del data
            messages.append(message)
            if self._message_handler:
                raw: dict[str, object] = dict(cast("dict[str, object]", message))
                self._message_handler(raw)

        script.on("message", on_message)
        await asyncio.to_thread(script.load)
        await asyncio.sleep(0.1)

        addr: int = 0
        for msg in messages:
            if msg["type"] == "send":
                payload = msg.get("payload", {})
                if isinstance(payload, dict):
                    payload_dict = cast("dict[str, object]", payload)
                    if payload_dict.get("type") == "alloc":
                        addr_str = str(payload_dict.get("address", "0"))
                        addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
            elif msg["type"] == "error":
                await asyncio.to_thread(script.unload)
                raise ToolError(_ERR_ALLOC_FAILED)

        if addr == 0:
            await asyncio.to_thread(script.unload)
            raise ToolError(_ERR_ALLOC_FAILED)

        self._scripts[script_id] = script
        self._alloc_scripts[addr] = script_id

        _logger.info("memory_allocated", address=hex(addr), size=size)
        return addr

    async def protect_memory(self, address: int, size: int, protection: str) -> bool:
        """Change memory protection flags for a region.

        Args:
            address: Start address of the region.
            size: Size of the region in bytes.
            protection: New protection flags (e.g., 'rwx', 'r-x', 'rw-').

        Returns:
            bool: True if the protection was changed successfully.

        Raises:
            ToolError: If the operation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = f"""
        try {{
            Memory.protect(ptr({address}), {size}, '{protection}');
            send({{ type: 'protect', success: true }});
        }} catch (e) {{
            send({{ type: 'protect', success: false, error: e.message }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(_ERR_PROTECT_FAILED)

        success = result.get("success", False)
        if not success:
            _logger.warning(
                "memory_protect_failed",
                address=hex(address),
                size=size,
                protection=protection,
            )
            return False

        _logger.debug(
            "memory_protected",
            address=hex(address),
            size=size,
            protection=protection,
        )
        return True

    async def find_base_address(self, module_name: str) -> int:
        """Get the base address of a loaded module.

        Args:
            module_name: Name of the module.

        Returns:
            int: Base address of the module.

        Raises:
            ToolError: If the module is not found.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = f"""
        var mod = Process.findModuleByName('{module_name}');
        if (mod) {{
            send({{ type: 'base', address: mod.base.toString() }});
        }} else {{
            send({{ type: 'base', address: null }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(_ERR_MODULE_NOT_FOUND)

        addr_val = result.get("address")
        if addr_val is None:
            raise ToolError(_ERR_MODULE_NOT_FOUND)

        addr_str = str(addr_val)
        base = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
        _logger.debug("base_address_found", module=module_name, base=hex(base))
        return base

    async def resolve_symbol(self, address: int) -> SymbolInfo:
        """Resolve debug symbol information from an address.

        Args:
            address: Address to resolve.

        Returns:
            SymbolInfo: Symbol information for the address.

        Raises:
            ToolError: If resolution fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = f"""
        var sym = DebugSymbol.fromAddress(ptr({address}));
        send({{
            type: 'symbol',
            name: sym.name,
            moduleName: sym.moduleName,
            fileName: sym.fileName,
            lineNumber: sym.lineNumber,
            address: sym.address.toString()
        }});
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(_ERR_RESOLVE_FAILED)

        name_val = result.get("name")
        module_val = result.get("moduleName")
        file_val = result.get("fileName")
        line_val = result.get("lineNumber")
        addr_str = str(result.get("address", str(address)))
        resolved_addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)

        _logger.debug("symbol_resolved", address=hex(resolved_addr), symbol_name=str(name_val) if name_val else None)
        return SymbolInfo(
            name=str(name_val) if name_val else f"sub_{address:x}",
            address=resolved_addr,
            module_name=str(module_val) if module_val else None,
            file_name=str(file_val) if file_val else None,
            line_number=int(line_val) if isinstance(line_val, (int, float)) else None,
        )

    async def find_functions_named(self, name: str) -> list[SymbolInfo]:
        """Find all functions matching a name across all modules.

        Args:
            name: Function name to search for.

        Returns:
            list[SymbolInfo]: List of symbol information for matching functions.

        Raises:
            ToolError: If the search fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = f"""
        var addrs = DebugSymbol.findFunctionsNamed('{name}');
        var result = addrs.map(function(a) {{
            var sym = DebugSymbol.fromAddress(a);
            return {{
                name: sym.name,
                address: a.toString(),
                moduleName: sym.moduleName,
                fileName: sym.fileName,
                lineNumber: sym.lineNumber
            }};
        }});
        send({{ type: 'functions', data: result }});
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(_ERR_RESOLVE_FAILED)

        symbols: list[SymbolInfo] = []
        func_data = result.get("data", [])
        if isinstance(func_data, list):
            for raw_sym in cast("list[object]", func_data):
                if not isinstance(raw_sym, dict):
                    continue
                s = cast("dict[str, object]", raw_sym)
                addr_str = str(s.get("address", "0"))
                addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                sym_name = s.get("name")
                mod_name = s.get("moduleName")
                file_name = s.get("fileName")
                line_num = s.get("lineNumber")
                symbols.append(
                    SymbolInfo(
                        name=str(sym_name) if sym_name else name,
                        address=addr,
                        module_name=str(mod_name) if mod_name else None,
                        file_name=str(file_name) if file_name else None,
                        line_number=int(line_num) if isinstance(line_num, (int, float)) else None,
                    ),
                )

        _logger.debug("functions_found", func_name=name, count=len(symbols))
        return symbols

    async def resolve_api(self, query: str) -> list[ApiResolverMatch]:
        """Resolve API functions using Frida's ApiResolver.

        Args:
            query: Query pattern (e.g., 'exports:*!CreateFile*').

        Returns:
            list[ApiResolverMatch]: List of matching API names and addresses.

        Raises:
            ToolError: If resolution fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = f"""
        var resolver = new ApiResolver('module');
        var matches = resolver.enumerateMatches('{query}');
        var result = matches.map(function(m) {{
            return {{
                name: m.name,
                address: m.address.toString()
            }};
        }});
        send({{ type: 'api', data: result }});
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(_ERR_RESOLVE_FAILED)

        matches: list[ApiResolverMatch] = []
        api_data = result.get("data", [])
        if isinstance(api_data, list):
            for raw_match in cast("list[object]", api_data):
                if not isinstance(raw_match, dict):
                    continue
                m = cast("dict[str, object]", raw_match)
                addr_str = str(m.get("address", "0"))
                addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                name_val = m.get("name", "")
                matches.append(
                    ApiResolverMatch(
                        name=str(name_val) if name_val else "",
                        address=addr,
                    ),
                )

        _logger.debug("api_resolved", query=query, matches=len(matches))
        return matches

    async def replace_function(self, target: str, replacement_code: str) -> HookInfo:
        """Replace a function implementation with custom code.

        Args:
            target: Function name (module!func) or hex address.
            replacement_code: JavaScript body defining the NativeCallback.

        Returns:
            HookInfo: Hook information for the replacement.

        Raises:
            ToolError: If replacement fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        hook_id = str(uuid.uuid4())[:8]
        addr_resolve = self._resolve_target_js(target)

        script_code = f"""
        var targetAddr = {addr_resolve};
        var replacement = {replacement_code};
        Interceptor.replace(targetAddr, replacement);
        send({{ type: 'replaced', address: targetAddr.toString() }});
        """

        script = await asyncio.to_thread(self._session.create_script, script_code)

        messages: list[ScriptMessage] = []

        def on_message(message: ScriptMessage, data: bytes | None) -> None:
            del data
            messages.append(message)
            if self._message_handler:
                raw: dict[str, object] = dict(cast("dict[str, object]", message))
                self._message_handler(raw)

        script.on("message", on_message)
        await asyncio.to_thread(script.load)
        await asyncio.sleep(0.1)

        address: int | None = None
        for msg in messages:
            if msg["type"] == "send":
                payload = msg.get("payload", {})
                if isinstance(payload, dict):
                    payload_dict = cast("dict[str, object]", payload)
                    if payload_dict.get("type") == "replaced":
                        addr_val = payload_dict.get("address", "0")
                        if isinstance(addr_val, str):
                            address = int(addr_val, 16) if addr_val.startswith("0x") else int(addr_val)
            elif msg["type"] == "error":
                await asyncio.to_thread(script.unload)
                raise ToolError(_ERR_REPLACE_FAILED)

        self._scripts[hook_id] = script

        hook_info = HookInfo(
            id=hook_id,
            target=target,
            address=address,
            script_id=hook_id,
            active=True,
        )
        self._hooks[hook_id] = hook_info

        _logger.info("function_replaced", hook_id=hook_id, target=target)
        return hook_info

    async def enumerate_processes(self) -> list[dict[str, object]]:
        """List all running processes on the device.

        Does not require an active session attachment.

        Returns:
            list[dict[str, object]]: List of dictionaries with 'pid' and 'name' for each process.

        Raises:
            ToolError: If device is not available.
        """
        if self._device is None:
            await self.initialize()

        device = self._device
        if device is None:
            raise ToolError(_ERR_NO_DEVICE)

        processes = await asyncio.to_thread(device.enumerate_processes)
        _logger.debug("processes_enumerated", count=len(processes))
        return [{"pid": proc.pid, "name": proc.name} for proc in processes]

    @staticmethod
    def _resolve_target_js(target: str) -> str:
        """Build a Frida JS expression that resolves a function target to a NativePointer.

        Accepts hex addresses (``0x...``), ``module!func`` pairs, or bare
        export names.

        Args:
            target: Function target string.

        Returns:
            str: JavaScript expression evaluating to a NativePointer.
        """
        if target.startswith("0x"):
            return f"ptr({target})"
        if "!" in target:
            module, func = target.split("!", 1)
            return f"Process.findModuleByName('{module}').getExportByName('{func}')"
        return f"Module.getGlobalExportByName('{target}')"

    def _parse_stalker_batch(self, tid: int, raw_events: list[object]) -> None:
        """Parse a batch of raw stalker events and accumulate them.

        Called from Frida's callback thread. Thread-safe via
        ``_stalker_traces_lock``.

        Args:
            tid: Effective thread ID key for ``_stalker_traces``.
            raw_events: Raw event dicts from the Frida Stalker script.
        """
        parsed: list[StalkerEvent] = []
        for raw_evt in raw_events:
            if not isinstance(raw_evt, dict):
                continue
            evt = cast("dict[str, object]", raw_evt)
            evt_type = str(evt.get("type", "exec"))
            from_str = str(evt.get("from", "0"))
            from_addr = int(from_str, 16) if from_str.startswith("0x") else int(from_str)
            to_raw = evt.get("to")
            to_addr: int | None = None
            if to_raw is not None:
                to_str = str(to_raw)
                to_addr = int(to_str, 16) if to_str.startswith("0x") else int(to_str)
            depth_raw = evt.get("depth", 0)
            depth = int(depth_raw) if isinstance(depth_raw, (int, float)) else 0
            parsed.append(
                StalkerEvent(
                    event_type=evt_type,
                    from_address=from_addr,
                    to_address=to_addr,
                    depth=depth,
                ),
            )
        with self._stalker_traces_lock:
            trace_list = self._stalker_traces.get(tid)
            if trace_list is not None:
                trace_list.extend(parsed)

    async def stalker_follow(
        self,
        thread_id: int | None = None,
        events: str = "call",
        limit: int = 10000,
    ) -> str:
        """Start Stalker code tracing on a thread.

        Args:
            thread_id: Thread ID to trace. None for current thread.
            events: Comma-separated event types (call, ret, exec, block, compile).
            limit: Maximum events to collect before auto-stop.

        Returns:
            str: Trace ID for later retrieval via stalker_unfollow.

        Raises:
            ToolError: If Stalker fails to start.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        event_list = [e.strip() for e in events.split(",")]
        event_config_parts = [f"{evt}: true" for evt in event_list]
        event_config = ", ".join(event_config_parts)

        effective_tid = thread_id if thread_id is not None else 0
        with self._stalker_traces_lock:
            self._stalker_traces[effective_tid] = []

        tid_js = str(thread_id) if thread_id is not None else "Process.getCurrentThreadId()"

        script_code = f"""
        var count = 0;
        var limit = {limit};
        var batch = [];
        var tid = {tid_js};

        Stalker.follow(tid, {{
            events: {{ {event_config} }},
            onReceive: function(events) {{
                var parsed = Stalker.parse(events, {{ annotate: true, stringify: false }});
                parsed.forEach(function(ev) {{
                    if (count >= limit) return;
                    count++;
                    var entry = {{
                        type: ev[0] || 'exec',
                        from: ev[1] ? ev[1].toString() : '0',
                        to: ev[2] ? ev[2].toString() : null,
                        depth: ev[3] || 0
                    }};
                    batch.push(entry);
                }});
                if (batch.length > 0) {{
                    send({{ type: 'stalker_batch', tid: tid, events: batch }});
                    batch = [];
                }}
                if (count >= limit) {{
                    Stalker.unfollow(tid);
                    Stalker.flush();
                    send({{ type: 'stalker_done', tid: tid, count: count }});
                }}
            }}
        }});
        send({{ type: 'stalker_started', tid: tid }});
        """

        script_id = str(uuid.uuid4())[:8]
        try:
            script = await asyncio.to_thread(self._session.create_script, script_code)
        except Exception as e:
            _logger.warning("stalker_create_script_failed", thread_id=effective_tid, error=str(e))
            raise ToolError(_ERR_STALKER_FAILED) from e

        captured_tid = effective_tid

        def on_stalker_message(message: ScriptMessage, data: bytes | None) -> None:
            del data
            if message["type"] == "send":
                payload = message.get("payload", {})
                if isinstance(payload, dict):
                    payload_dict = cast("dict[str, object]", payload)
                    msg_type = payload_dict.get("type")
                    if msg_type == "stalker_batch":
                        raw_evts = payload_dict.get("events")
                        if isinstance(raw_evts, list):
                            self._parse_stalker_batch(captured_tid, cast("list[object]", raw_evts))
            if self._message_handler:
                raw: dict[str, object] = dict(cast("dict[str, object]", message))
                self._message_handler(raw)

        script.on("message", on_stalker_message)
        try:
            await asyncio.to_thread(script.load)
        except Exception as e:
            _logger.warning("stalker_load_failed", thread_id=effective_tid, error=str(e))
            raise ToolError(_ERR_STALKER_FAILED) from e

        self._scripts[script_id] = script
        self._stalker_scripts[effective_tid] = script_id

        _logger.info(
            "stalker_follow_started",
            thread_id=effective_tid,
            events=events,
            limit=limit,
        )

        return script_id

    async def stalker_unfollow(self, thread_id: int | None = None) -> StalkerTrace:
        """Stop Stalker tracing and retrieve collected events.

        Args:
            thread_id: Thread ID to stop tracing. None for current thread.

        Returns:
            StalkerTrace: StalkerTrace with collected events and duration.

        Raises:
            ToolError: If unfollow fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        effective_tid = thread_id if thread_id is not None else 0
        start_time = time.monotonic()

        tid_js = str(thread_id) if thread_id is not None else "Process.getCurrentThreadId()"

        unfollow_code = f"""
        var tid = {tid_js};
        Stalker.unfollow(tid);
        Stalker.flush();
        send({{ type: 'stalker_unfollowed', tid: tid }});
        """

        await self._execute_script_and_wait(unfollow_code, max_wait=3.0)

        script_id = self._stalker_scripts.pop(effective_tid, None)
        if script_id is not None:
            await self._unload_script(script_id)

        with self._stalker_traces_lock:
            collected_events = self._stalker_traces.pop(effective_tid, [])
        duration = (time.monotonic() - start_time) * 1000

        _logger.info(
            "stalker_unfollow_complete",
            thread_id=effective_tid,
            event_count=len(collected_events),
        )

        return StalkerTrace(
            thread_id=effective_tid,
            events=collected_events,
            event_count=len(collected_events),
            duration_ms=duration,
        )

    async def enable_child_gating(self) -> None:
        """Enable child process gating to intercept spawned children.

        Raises:
            ToolError: If child gating cannot be enabled.
        """
        if self._device is None:
            raise ToolError(_ERR_NO_DEVICE)

        if self._child_gating_enabled:
            return

        def on_child_added(child: object) -> None:
            child_pid = int(getattr(child, "pid", 0))
            child_parent_pid = int(getattr(child, "parent_pid", 0))
            info = ChildProcessInfo(
                pid=child_pid,
                parent_pid=child_parent_pid,
                origin=str(getattr(child, "origin", "unknown")),
                identifier=getattr(child, "identifier", None),
                path=getattr(child, "path", None),
                argv=list(getattr(child, "argv", [])),
            )
            _logger.info("child_process_added", child_pid=child_pid, parent_pid=child_parent_pid)
            with self._gated_children_lock:
                self._gated_children.append(info)
            if self._message_handler:
                self._message_handler({
                    "type": "send",
                    "payload": {
                        "type": "child_added",
                        "pid": child_pid,
                        "parent_pid": child_parent_pid,
                    },
                })

        try:
            self._device.on("child-added", on_child_added)
            await asyncio.to_thread(self._device.enable_spawn_gating)
            self._child_gating_enabled = True
            _logger.info("child_gating_enabled")
        except Exception as e:
            _logger.warning("child_gating_enable_failed", error=str(e))
            raise ToolError(_ERR_CHILD_GATING_FAILED) from e

    async def disable_child_gating(self) -> None:
        """Disable child process gating.

        Raises:
            ToolError: If child gating cannot be disabled.
        """
        if self._device is None:
            raise ToolError(_ERR_NO_DEVICE)

        if not self._child_gating_enabled:
            return

        try:
            await asyncio.to_thread(self._device.disable_spawn_gating)
            self._child_gating_enabled = False
            with self._gated_children_lock:
                self._gated_children.clear()
            _logger.info("child_gating_disabled")
        except Exception as e:
            _logger.warning("child_gating_disable_failed", error=str(e))
            raise ToolError(_ERR_CHILD_GATING_FAILED) from e

    async def get_pending_children(self) -> list[ChildProcessInfo]:
        """Get list of child processes intercepted by child gating.

        Returns:
            list[ChildProcessInfo]: List of pending child process information.
        """
        with self._gated_children_lock:
            result = list(self._gated_children)
        _logger.debug("pending_children_queried", count=len(result))
        return result

    async def resume_child(self, pid: int) -> None:
        """Resume a gated child process.

        Args:
            pid: PID of the child process to resume.

        Raises:
            ToolError: If resume fails.
        """
        if self._device is None:
            raise ToolError(_ERR_NO_DEVICE)

        try:
            await asyncio.to_thread(self._device.resume, pid)
            with self._gated_children_lock:
                self._gated_children = [c for c in self._gated_children if c.pid != pid]
            _logger.info("child_resumed", pid=pid)
        except Exception as e:
            _logger.warning("child_resume_failed", pid=pid, error=str(e))
            raise ToolError(_ERR_CHILD_GATING_FAILED) from e

    async def enable_crash_reporting(self) -> None:
        """Enable crash event monitoring for attached processes.

        Raises:
            ToolError: If crash reporting cannot be enabled.
        """
        if self._device is None:
            raise ToolError(_ERR_NO_DEVICE)

        def on_process_crashed(crash: object) -> None:
            crash_pid = int(getattr(crash, "pid", 0))
            info = CrashInfo(
                pid=crash_pid,
                process_name=str(getattr(crash, "process_name", "")),
                summary=str(getattr(crash, "summary", "")),
                report=str(getattr(crash, "report", "")),
                parameters=dict(getattr(crash, "parameters", {})),
                timestamp=time.time(),
            )
            _logger.warning("process_crashed", crash_pid=crash_pid, summary=info.summary)
            with self._crashes_lock:
                self._crashes.append(info)
            if self._message_handler:
                self._message_handler({
                    "type": "send",
                    "payload": {
                        "type": "process_crashed",
                        "pid": crash_pid,
                        "summary": info.summary,
                    },
                })

        try:
            self._device.on("process-crashed", on_process_crashed)
            _logger.info("crash_reporting_enabled")
        except Exception as e:
            _logger.warning("crash_reporting_enable_failed", error=str(e))
            raise ToolError(_ERR_CRASH_REPORTING_FAILED) from e

    async def get_crashes(self) -> list[CrashInfo]:
        """Get all collected crash reports.

        Returns:
            list[CrashInfo]: List of crash information.
        """
        with self._crashes_lock:
            result = list(self._crashes)
        _logger.debug("crashes_queried", count=len(result))
        return result

    async def enumerate_devices(self) -> list[FridaDeviceInfo]:
        """List all available Frida devices.

        Returns:
            list[FridaDeviceInfo]: List of device information.
        """
        _ = self.state
        devices = await asyncio.to_thread(frida.enumerate_devices)
        _logger.debug("devices_enumerated", count=len(devices))
        return [
            FridaDeviceInfo(
                id=str(d.id),
                name=str(d.name),
                device_type=str(d.type),
            )
            for d in devices
        ]

    async def connect_device(
        self,
        device_type: str,
        host: str | None = None,
    ) -> FridaDeviceInfo:
        """Switch to a different Frida device.

        Args:
            device_type: Device type ('local', 'usb', or 'remote').
            host: Remote host address (required for 'remote' type).

        Returns:
            FridaDeviceInfo: Information about the connected device.

        Raises:
            ToolError: If connection fails.
        """
        if self._session is not None:
            try:
                await self.detach(kill_spawned=False)
            except ToolError:
                _logger.debug("detach_before_device_switch_failed", exc_info=True)

        if device_type == "remote" and host is None:
            raise ToolError(_ERR_DEVICE_FAILED, details={"reason": "host required for remote device"})

        if device_type not in {"local", "usb", "remote"}:
            raise ToolError(_ERR_DEVICE_FAILED, details={"reason": f"unknown device type: {device_type}"})

        try:
            if device_type == "local":
                device = await asyncio.to_thread(frida.get_local_device)
            elif device_type == "usb":
                device = await asyncio.to_thread(frida.get_usb_device)
            else:
                manager = frida.get_device_manager()
                remote_host: str = host if host is not None else ""
                device = await asyncio.to_thread(manager.add_remote_device, remote_host)
        except Exception as e:
            _logger.warning("device_connect_failed", device_type=device_type, error=str(e))
            raise ToolError(_ERR_DEVICE_FAILED) from e

        self._device = device
        self.state.connected = True
        self.state.tool_running = True

        _logger.info("device_connected", device_type=device_type, device_id=str(device.id))

        return FridaDeviceInfo(
            id=str(device.id),
            name=str(device.name),
            device_type=str(device.type),
        )
