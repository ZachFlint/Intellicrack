"""Frida instrumentation bridge for dynamic analysis.

This module provides runtime instrumentation capabilities using Frida
for function hooking, memory manipulation, and process control.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast, override

import frida

from ..core.logging import get_logger
from ..core.process_manager import ProcessManager, ProcessType
from ..core.types import (
    ExportInfo,
    HookInfo,
    MemoryRegion,
    ModuleInfo,
    ToolDefinition,
    ToolError,
    ToolFunction,
    ToolName,
    ToolParameter,
)
from .base import (
    BridgeCapabilities,
    BridgeState,
    InstrumentationBridge,
    MemorySearchResult,
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


class FridaBridge(InstrumentationBridge):
    """Bridge for Frida dynamic instrumentation.

    Provides function hooking, memory manipulation, and script execution
    capabilities using the Frida framework.

    Attributes:
        _device: Frida device connection.
        _session: Active Frida session.
        _scripts: Active scripts by ID.
        _hooks: Active hooks by ID.
        _message_handler: Handler for script messages.
    """

    def __init__(self) -> None:
        """Initialize the Frida bridge."""
        super().__init__()
        self._device: frida.core.Device | None = None
        self._session: frida.core.Session | None = None
        self._scripts: dict[str, frida.core.Script] = {}
        self._hooks: dict[str, HookInfo] = {}
        self._message_handler: Callable[[dict[str, object]], None] | None = None
        self._pid: int | None = None
        self._spawned_pid: int | None = None
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
            ToolName.FRIDA
        """
        return ToolName.FRIDA

    @property
    def tool_definition(self) -> ToolDefinition:
        """Get tool definition for LLM function calling.

        Returns:
            ToolDefinition with all available functions.
        """
        return ToolDefinition(
            tool_name=ToolName.FRIDA,
            description="Frida dynamic instrumentation - hooking, tracing, memory manipulation",
            functions=[
                ToolFunction(
                    name="frida.spawn",
                    description="Spawn a process with Frida instrumentation",
                    parameters=[
                        ToolParameter(
                            name="path",
                            type="string",
                            description="Path to executable",
                            required=True,
                        ),
                        ToolParameter(
                            name="args",
                            type="array",
                            description="Command line arguments",
                            required=False,
                        ),
                    ],
                    returns="Process ID of spawned process",
                ),
                ToolFunction(
                    name="frida.attach",
                    description="Attach Frida to a running process",
                    parameters=[
                        ToolParameter(
                            name="target",
                            type="string",
                            description="Process name or PID",
                            required=True,
                        ),
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
                        ToolParameter(
                            name="module_name",
                            type="string",
                            description="Name of the module",
                            required=True,
                        ),
                    ],
                    returns="List of export names and addresses",
                ),
                ToolFunction(
                    name="frida.enumerate_imports",
                    description="List imports of a module",
                    parameters=[
                        ToolParameter(
                            name="module_name",
                            type="string",
                            description="Name of the module",
                            required=True,
                        ),
                    ],
                    returns="List of import names and addresses",
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
                        ToolParameter(
                            name="hook_id",
                            type="string",
                            description="ID of the hook to remove",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="frida.read_memory",
                    description="Read memory from the target process",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Memory address to read",
                            required=True,
                        ),
                        ToolParameter(
                            name="size",
                            type="integer",
                            description="Number of bytes to read",
                            required=True,
                        ),
                    ],
                    returns="Hex string of memory contents",
                ),
                ToolFunction(
                    name="frida.write_memory",
                    description="Write memory in the target process",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Memory address to write",
                            required=True,
                        ),
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
                        ToolParameter(
                            name="script",
                            type="string",
                            description="JavaScript code to execute",
                            required=True,
                        ),
                    ],
                    returns="Script execution result",
                ),
                ToolFunction(
                    name="frida.intercept_return",
                    description="Hook a function and modify its return value",
                    parameters=[
                        ToolParameter(
                            name="target",
                            type="string",
                            description="Function to hook",
                            required=True,
                        ),
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
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Function address",
                            required=True,
                        ),
                        ToolParameter(
                            name="args",
                            type="array",
                            description="Function arguments (integers)",
                            required=False,
                        ),
                    ],
                    returns="Function return value",
                ),
                ToolFunction(
                    name="frida.get_memory_ranges",
                    description="Get memory map of the process",
                    parameters=[
                        ToolParameter(
                            name="protection",
                            type="string",
                            description="Filter by protection (e.g., 'r-x')",
                            required=False,
                        ),
                    ],
                    returns="List of memory regions",
                ),
                ToolFunction(
                    name="frida.allocate_memory",
                    description="Allocate memory in the target process",
                    parameters=[
                        ToolParameter(
                            name="size",
                            type="integer",
                            description="Size in bytes",
                            required=True,
                        ),
                    ],
                    returns="Address of allocated memory",
                ),
                ToolFunction(
                    name="frida.get_hooks",
                    description="Get all active hooks",
                    parameters=[],
                    returns="List of active hook information",
                ),
            ],
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
            self._state = BridgeState(
                connected=True,
                tool_running=True,
                binary_loaded=False,
                process_attached=False,
                target_path=None,
                target_pid=None,
                last_error=None,
            )
            _logger.info("frida_bridge_initialized")
        except Exception as e:
            self._state.connected = False
            self._state.tool_running = False
            self._state.last_error = str(e)
            raise ToolError(_ERR_INIT_FAILED) from e

    async def shutdown(self) -> None:
        """Shutdown Frida and cleanup resources."""
        for script_id in list(self._scripts.keys()):
            try:
                await self._unload_script(script_id)
            except Exception:
                _logger.exception("script_unload_failed", extra={"script_id": script_id})

        if self._session is not None:
            try:
                await asyncio.to_thread(self._session.detach)
            except Exception:
                _logger.exception("session_detach_failed")
            self._session = None

        if self._spawned_pid is not None and self._device is not None:
            try:
                await asyncio.to_thread(self._device.kill, self._spawned_pid)
                _logger.info("spawned_process_killed", extra={"pid": self._spawned_pid})
            except Exception:
                _logger.exception("spawned_process_kill_failed", extra={"pid": self._spawned_pid})

            process_manager = ProcessManager.get_instance()
            process_manager.unregister_external_pid(self._spawned_pid)
            self._spawned_pid = None

        self._device = None
        self._pid = None
        self._hooks = {}
        await super().shutdown()
        _logger.info("frida_bridge_shutdown")

    @override
    async def is_available(self) -> bool:
        """Check if Frida is available.

        Returns:
            True if Frida is installed and working.
        """
        try:
            await asyncio.to_thread(frida.get_local_device)
        except Exception as e:
            _logger.debug("frida_availability_check_failed", extra={"error": str(e)})
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
            self._state.connected = True
            self._state.tool_running = True
            self._state.process_attached = True
            self._state.target_pid = pid

            _logger.info("process_attached", extra={"pid": pid})
        except frida.ProcessNotFoundError as e:
            raise ToolError(_ERR_PROCESS_NOT_FOUND) from e
        except Exception as e:
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
            raise ToolError(_ERR_PROCESS_NOT_FOUND) from e
        except Exception as e:
            raise ToolError(_ERR_ATTACH_FAILED) from e

        self._pid = target_pid
        self._state.connected = True
        self._state.tool_running = True
        self._state.process_attached = True
        self._state.target_pid = self._pid

        _logger.info("process_attached_by_name", extra={"process_name": name, "pid": self._pid})

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
            PID of spawned process.

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

            self._state.connected = True
            self._state.tool_running = True
            self._state.process_attached = True
            self._state.target_path = path
            self._state.target_pid = pid

            _logger.info("process_spawned", extra={"process_name": path.name, "pid": pid})
        except Exception as e:
            try:
                await asyncio.to_thread(device.kill, pid)
            except Exception as kill_err:
                _logger.warning(
                    "failed_to_kill_leaked_process",
                    extra={"pid": pid, "error": str(kill_err)},
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
            _logger.info("process_resumed", extra={"pid": self._pid})
        except Exception as e:
            raise ToolError(_ERR_NOT_ATTACHED) from e

    async def detach(self, kill_spawned: bool = True) -> None:
        """Detach from the current process.

        Args:
            kill_spawned: If True and process was spawned by us, kill it.

        Raises:
            ToolError: If detachment fails.
        """
        if self._session is None:
            _logger.warning("detach_no_session")
            return

        try:
            for script_id in list(self._scripts.keys()):
                await self._unload_script(script_id)

            await asyncio.to_thread(self._session.detach)
            self._session = None

            if kill_spawned and self._spawned_pid is not None and self._device is not None:
                try:
                    await asyncio.to_thread(self._device.kill, self._spawned_pid)
                    _logger.info("spawned_process_killed", extra={"pid": self._spawned_pid})
                except Exception:
                    _logger.exception("spawned_process_kill_failed", extra={"pid": self._spawned_pid})

                process_manager = ProcessManager.get_instance()
                process_manager.unregister_external_pid(self._spawned_pid)
                self._spawned_pid = None

            self._pid = None
            self._hooks = {}
            self._state.connected = True
            self._state.tool_running = True
            self._state.process_attached = False
            self._state.target_pid = None

            _logger.info("process_detached")
        except Exception as e:
            raise ToolError(_ERR_NOT_ATTACHED) from e

    async def read_memory(self, address: int, size: int) -> bytes:
        """Read memory from the target process.

        Args:
            address: Memory address.
            size: Number of bytes to read.

        Returns:
            Memory contents.

        Raises:
            ToolError: If read fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = f"""
        var data = Memory.readByteArray(ptr({address}), {size});
        send({{ type: 'memory', data: data }});
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
            Number of bytes written.

        Raises:
            ToolError: If write fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        hex_array = ", ".join(f"0x{b:02x}" for b in data)
        script_code = f"""
        var bytes = [{hex_array}];
        Memory.writeByteArray(ptr({address}), bytes);
        send({{ type: 'success' }});
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(_ERR_WRITE_FAILED)

        _logger.debug("memory_written", extra={"length": len(data), "address": hex(address)})
        return len(data)

    async def get_memory_regions(self) -> list[MemoryRegion]:
        """Get process memory map.

        Returns:
            List of memory regions.

        Raises:
            ToolError: If operation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = """
        var ranges = Process.enumerateRanges('---');
        var result = ranges.map(function(r) {
            return {
                base: r.base.toString(),
                size: r.size,
                protection: r.protection,
                file: r.file ? r.file.path : null
            };
        });
        send({ type: 'ranges', data: result });
        """

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
                    )
                )

        return regions

    async def scan_memory(self, pattern: bytes) -> list[MemorySearchResult]:
        """Scan process memory for a pattern.

        Args:
            pattern: Byte pattern to search for.

        Returns:
            List of matches with context.

        Raises:
            ToolError: If scan fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

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
                    )
                )

        return matches

    async def enumerate_modules(self) -> list[ModuleInfo]:
        """List all loaded modules in the process.

        Returns:
            List of module information.

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
                    )
                )

        return modules

    async def enumerate_exports(self, module_name: str) -> list[ExportInfo]:
        """List exports of a module.

        Args:
            module_name: Name of the module.

        Returns:
            List of export information.

        Raises:
            ToolError: If operation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = f"""
        var exports = Module.enumerateExports('{module_name}');
        var result = exports.map(function(e) {{
            return {{
                name: e.name,
                type: e.type,
                address: e.address.toString()
            }};
        }});
        send({{ type: 'exports', data: result }});
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
                    )
                )

        return exports

    async def hook_function(
        self,
        target: str,
        on_enter: str | None = None,
        on_leave: str | None = None,
    ) -> HookInfo:
        """Hook a function by name or address.

        Args:
            target: Function name (module!func) or hex address.
            on_enter: JavaScript code for function entry.
            on_leave: JavaScript code for function exit.

        Returns:
            Hook information.

        Raises:
            ToolError: If hooking fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        hook_id = str(uuid.uuid4())[:8]

        if target.startswith("0x"):
            addr_resolve = f"ptr({target})"
        elif "!" in target:
            module, func = target.split("!", 1)
            addr_resolve = f"Module.getExportByName('{module}', '{func}')"
        else:
            addr_resolve = f"Module.getExportByName(null, '{target}')"

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

        _logger.info("hook_installed", extra={"hook_id": hook_id, "target": target})
        return hook_info

    async def remove_hook(self, hook_id: str) -> bool:
        """Remove a previously installed hook.

        Args:
            hook_id: ID of the hook to remove.

        Returns:
            True if removed successfully, False if hook not found.
        """
        if hook_id not in self._scripts:
            _logger.warning("hook_not_found", extra={"hook_id": hook_id})
            return False

        await self._unload_script(hook_id)
        del self._hooks[hook_id]

        _logger.info("hook_removed", extra={"hook_id": hook_id})
        return True

    async def get_hooks(self) -> list[HookInfo]:
        """Get all active hooks.

        Returns:
            List of hook information.
        """
        return list(self._hooks.values())

    async def execute_script(self, script: str) -> str:
        """Execute custom Frida JavaScript code.

        Args:
            script: JavaScript code to execute.

        Returns:
            Script execution result.

        Raises:
            ToolError: If execution fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        result = await self._execute_script_and_wait(script)

        if "error" in result:
            raise ToolError(_ERR_SCRIPT_FAILED)

        return str(result)

    async def intercept_return(self, target: str, return_value: int) -> HookInfo:
        """Hook a function and modify its return value.

        Args:
            target: Function to hook.
            return_value: Value to return instead.

        Returns:
            Hook information.
        """
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
            Function return value.

        Raises:
            ToolError: If call fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

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
        timeout: float = 5.0,
    ) -> dict[str, Any]:
        """Execute a script and wait for result.

        Args:
            script_code: JavaScript code to execute.
            timeout: Timeout in seconds.

        Returns:
            Script result as dictionary.

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
            await asyncio.wait_for(event.wait(), timeout=timeout)
        except TimeoutError:
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
                _logger.exception("script_unload_failed", extra={"script_id": script_id})
            del self._scripts[script_id]

    def set_message_handler(
        self,
        handler: Callable[[dict[str, object]], None],
    ) -> None:
        """Set handler for script messages.

        Args:
            handler: Callback function for messages.
        """
        self._message_handler = handler
