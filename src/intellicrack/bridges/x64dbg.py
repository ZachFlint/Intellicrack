"""x64dbg bridge for Windows debugging.

This module provides integration with x64dbg for dynamic analysis,
debugging, and memory manipulation on Windows systems.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from intellicrack.core._subprocess import CREATE_NEW_CONSOLE, PIPE, Popen

from ..core.logging import get_logger
from ..core.process_manager import ProcessManager, ProcessType
from ..core.types import (
    BreakpointInfo,
    MemoryRegion,
    ModuleInfo,
    ProcessInfo,
    RegisterState,
    ThreadInfo,
    ToolDefinition,
    ToolError,
    ToolFunction,
    ToolName,
    ToolParameter,
)
from .base import (
    BridgeCapabilities,
    BridgeState,
    DebuggerBridge,
    DisassemblyLine,
    MemorySearchResult,
    StackFrame,
    WatchpointInfo,
)
from .named_pipe_client import NamedPipeClient, PipeConfig


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

if TYPE_CHECKING:
    from collections.abc import Sequence
    from types import ModuleType

_logger = get_logger("bridges.x64dbg")

# Optional disassembler/assembler imports
_capstone: ModuleType | None = None
_keystone: ModuleType | None = None

try:
    import capstone as _capstone_module

    _capstone = _capstone_module
except ImportError:
    _logger.debug("capstone_not_available")

try:
    import keystone as _keystone_module

    _keystone = _keystone_module
except ImportError:
    _logger.debug("keystone_not_available")


def get_capstone() -> ModuleType | None:
    """Get the capstone module if available.

    Returns:
        The capstone module, or None if not installed.
    """
    return _capstone


def get_keystone() -> ModuleType | None:
    """Get the keystone module if available.

    Returns:
        The keystone module, or None if not installed.
    """
    return _keystone


# Windows API constants
WIN_PROCESS_VM_READ = 0x0010
WIN_PROCESS_VM_WRITE = 0x0020
WIN_PROCESS_VM_OPERATION = 0x0008
WIN_PROCESS_QUERY_INFORMATION = 0x0400
WIN_MEM_COMMIT = 0x1000
WIN_MEM_RESERVE = 0x2000
WIN_MEM_RELEASE = 0x8000
WIN_PAGE_EXECUTE_READWRITE = 0x40
PE_HEADER_OFFSET = 0x3C
PE_MAGIC_OFFSET = 0x40
PE64_MACHINE = 0x8664
PE32_MACHINE = 0x14C
MEM_COMMIT_FLAG = 0x1000
MEM_MAPPED_FLAG = 0x20000
MAX_USER_ADDRESS_64 = 0x7FFFFFFFFFFF
MIN_PATTERN_LENGTH = 16
MAX_MEMORY_READ_SIZE = 0x100000
DWORD_MASK = 0xFFFFFFFF
INVALID_HANDLE_VALUE = -1
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE_FLAG = 0x40
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
PEB_PROCESS_PARAMS_OFFSET_64 = 0x20
PEB_PROCESS_PARAMS_OFFSET_32 = 0x10
CMD_LINE_OFFSET_64 = 0x70
POINTER_SIZE_64 = 8
POINTER_SIZE_32 = 4
UNICODE_STRING_SIZE_64 = 16
UNICODE_STRING_SIZE_32 = 8
STACK_FRAME_SIZE_64 = 16  # Size of 64-bit stack frame (saved RBP + return address)


_ERR_REQUIRES_WINDOWS = "requires Windows platform"
_ERR_NOT_ATTACHED = "not attached to a process"
_ERR_OPEN_PROCESS_FAILED = "failed to open process"
_ERR_CREATE_SNAPSHOT_FAILED = "failed to create snapshot"
_ERR_GET_THREADS_FAILED = "failed to get threads"
_ERR_GET_MODULES_FAILED = "failed to get modules"
_ERR_GET_PARENT_PID_FAILED = "failed to get parent PID"

BreakpointType = Literal["software", "hardware", "memory"]
MemoryProtection = Literal["read", "write", "execute"]
PipeCommandResult = str | int | float | bool | dict[str, object] | list[object] | None


def _read_process_memory_block(
    handle: int,
    address: int,
    size: int,
) -> bytes | None:
    """Read a block of memory from a process.

    Args:
        handle: Process handle with VM_READ access.
        address: Memory address to read from.
        size: Number of bytes to read.

    Returns:
        Bytes read, or None on failure.
    """
    if sys.platform != "win32":
        return None

    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    success = ctypes.windll.kernel32.ReadProcessMemory(
        handle,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(bytes_read),
    )
    if not success or bytes_read.value == 0:
        return None
    return buffer.raw[: bytes_read.value]


def _read_process_command_line(pid: int) -> str | None:
    """Read process command line using Windows API.

    Args:
        pid: Process ID to read command line from.

    Returns:
        Command line string, or None if not accessible.
    """
    if sys.platform != "win32":
        return None

    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(
            WIN_PROCESS_QUERY_INFORMATION | WIN_PROCESS_VM_READ,
            False,
            pid,
        )
        if not handle:
            return None

        try:
            return _extract_command_line_from_peb(handle)
        finally:
            kernel32.CloseHandle(handle)

    except Exception as e:
        _logger.warning("command_line_read_failed", extra={"error": str(e)})
        return None


def _extract_command_line_from_peb(handle: int) -> str | None:
    """Extract command line from process PEB.

    Args:
        handle: Process handle with VM_READ access.

    Returns:
        Command line string, or None on failure.
    """
    if sys.platform != "win32":
        return None

    class ProcessBasicInformation(ctypes.Structure):
        _fields_ = [
            ("Reserved1", ctypes.c_void_p),
            ("PebBaseAddress", ctypes.c_void_p),
            ("Reserved2", ctypes.c_void_p * 2),
            ("UniqueProcessId", ctypes.POINTER(ctypes.c_ulong)),
            ("Reserved3", ctypes.c_void_p),
        ]

    pbi = ProcessBasicInformation()
    return_length = wintypes.ULONG()
    status = ctypes.windll.ntdll.NtQueryInformationProcess(handle, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(return_length))

    if status != 0 or not pbi.PebBaseAddress:
        return None

    ptr_size = _get_process_pointer_size(handle)
    peb_addr = int(ctypes.cast(pbi.PebBaseAddress, ctypes.c_void_p).value or 0)

    params_offset = PEB_PROCESS_PARAMS_OFFSET_64 if ptr_size == POINTER_SIZE_64 else PEB_PROCESS_PARAMS_OFFSET_32
    params_bytes = _read_process_memory_block(handle, peb_addr + params_offset, ptr_size)
    if not params_bytes:
        return None

    params_addr = int.from_bytes(params_bytes, "little")
    if params_addr == 0:
        return None

    return _read_unicode_string_from_params(handle, params_addr, ptr_size)


def _get_process_pointer_size(handle: int) -> int:
    """Get pointer size for the target process.

    Args:
        handle: Process handle.

    Returns:
        Pointer size in bytes (4 for 32-bit, 8 for 64-bit).
    """
    if sys.platform != "win32":
        return POINTER_SIZE_64

    is_wow64_fn = getattr(ctypes.windll.kernel32, "IsWow64Process", None)
    if is_wow64_fn is not None:
        wow64_flag = wintypes.BOOL()
        if is_wow64_fn(handle, ctypes.byref(wow64_flag)) and wow64_flag.value:
            return POINTER_SIZE_32
    return ctypes.sizeof(ctypes.c_void_p)


def _read_unicode_string_from_params(handle: int, params_addr: int, ptr_size: int) -> str | None:
    """Read UNICODE_STRING command line from process parameters.

    Args:
        handle: Process handle.
        params_addr: Address of RTL_USER_PROCESS_PARAMETERS.
        ptr_size: Pointer size for the process.

    Returns:
        Command line string, or None on failure.
    """
    if sys.platform != "win32":
        return None

    cmd_offset = CMD_LINE_OFFSET_64 if ptr_size == POINTER_SIZE_64 else PE_MAGIC_OFFSET
    ustr_size = UNICODE_STRING_SIZE_64 if ptr_size == POINTER_SIZE_64 else UNICODE_STRING_SIZE_32
    ustr_bytes = _read_process_memory_block(handle, params_addr + cmd_offset, ustr_size)

    if not ustr_bytes or len(ustr_bytes) < ustr_size:
        return None

    length = int.from_bytes(ustr_bytes[:2], "little")
    buf_offset = POINTER_SIZE_64 if ptr_size == POINTER_SIZE_64 else POINTER_SIZE_32
    buf_ptr = int.from_bytes(ustr_bytes[buf_offset : buf_offset + ptr_size], "little")

    if length <= 0 or buf_ptr == 0:
        return None

    if length % 2 != 0:
        length -= 1

    cmd_bytes = _read_process_memory_block(handle, buf_ptr, length)
    return cmd_bytes.decode("utf-16-le", errors="ignore") if cmd_bytes else None


class X64DbgBridge(DebuggerBridge):
    """Bridge for x64dbg Windows debugger.

    Provides debugging capabilities including breakpoints, stepping,
    register/memory manipulation, and process control.

    Attributes:
        _x64dbg_path: Path to x64dbg installation.
        _process: x64dbg process instance.
        _pipe_client: Named pipe client.
        _attached_pid: Currently attached process ID.
    """

    DEFAULT_PORT = 27015
    COMMAND_TIMEOUT = 10.0

    def __init__(self) -> None:
        """Initialize the x64dbg bridge."""
        super().__init__()
        self._x64dbg_path: Path | None = None
        self._process: Popen[bytes] | None = None
        self._pipe_client: NamedPipeClient | None = None
        self._attached_pid: int | None = None
        self._port: int = self.DEFAULT_PORT
        self._binary_path: Path | None = None
        self._is_64bit: bool = True
        self._breakpoints: dict[int, BreakpointInfo] = {}
        self._next_bp_id: int = 1
        self._watchpoints: dict[int, WatchpointInfo] = {}
        self._next_wp_id: int = 1
        self._capabilities = BridgeCapabilities(
            supports_debugging=True,
            supports_dynamic_analysis=True,
            supports_patching=True,
            supports_scripting=True,
            supported_architectures=["x86", "x86_64"],
            supported_formats=["pe"],
        )

    @property
    def attached_pid(self) -> int | None:
        """Get the currently attached process ID.

        Returns:
            The PID of the attached process, or None if not attached.
        """
        return self._attached_pid

    @attached_pid.setter
    def attached_pid(self, value: int | None) -> None:
        """Set the currently attached process ID.

        Args:
            value: The PID to set, or None to clear.
        """
        self._attached_pid = value

    @property
    def binary_path(self) -> Path | None:
        """Get the path to the loaded binary.

        Returns:
            The binary file path, or None if no binary is loaded.
        """
        return self._binary_path

    @binary_path.setter
    def binary_path(self, value: Path | None) -> None:
        """Set the path to the loaded binary.

        Args:
            value: The binary file path, or None to clear.
        """
        self._binary_path = value

    @property
    def is_64bit(self) -> bool:
        """Get whether the bridge is in 64-bit mode.

        Returns:
            True if operating in 64-bit mode.
        """
        return self._is_64bit

    @is_64bit.setter
    def is_64bit(self, value: bool) -> None:
        """Set whether the bridge is in 64-bit mode.

        Args:
            value: True for 64-bit mode, False for 32-bit.
        """
        self._is_64bit = value

    @property
    def breakpoints(self) -> dict[int, BreakpointInfo]:
        """Get the breakpoints dictionary.

        Returns:
            Mapping of breakpoint IDs to their info.
        """
        return self._breakpoints

    @property
    def next_bp_id(self) -> int:
        """Get the next breakpoint ID.

        Returns:
            The next breakpoint ID to be assigned.
        """
        return self._next_bp_id

    @next_bp_id.setter
    def next_bp_id(self, value: int) -> None:
        """Set the next breakpoint ID.

        Args:
            value: The next breakpoint ID value.
        """
        self._next_bp_id = value

    @property
    def watchpoints(self) -> dict[int, WatchpointInfo]:
        """Get the watchpoints dictionary.

        Returns:
            Mapping of watchpoint IDs to their info.
        """
        return self._watchpoints

    @property
    def next_wp_id(self) -> int:
        """Get the next watchpoint ID.

        Returns:
            The next watchpoint ID to be assigned.
        """
        return self._next_wp_id

    @next_wp_id.setter
    def next_wp_id(self, value: int) -> None:
        """Set the next watchpoint ID.

        Args:
            value: The next watchpoint ID value.
        """
        self._next_wp_id = value

    @property
    def x64dbg_path(self) -> Path | None:
        """Get the path to the x64dbg installation.

        Returns:
            The x64dbg installation path, or None if not found.
        """
        return self._x64dbg_path

    @x64dbg_path.setter
    def x64dbg_path(self, value: Path | None) -> None:
        """Set the path to the x64dbg installation.

        Args:
            value: The x64dbg installation path, or None to clear.
        """
        self._x64dbg_path = value

    @property
    def name(self) -> ToolName:
        """Get the tool's name.

        Returns:
            ToolName.X64DBG
        """
        return ToolName.X64DBG

    @property
    def tool_definition(self) -> ToolDefinition:
        """Get tool definition for LLM function calling.

        Returns:
            ToolDefinition with all available functions.
        """
        return ToolDefinition(
            tool_name=ToolName.X64DBG,
            description="x64dbg debugger - breakpoints, stepping, register/memory manipulation",
            functions=[
                ToolFunction(
                    name="x64dbg.load",
                    description="Load an executable into x64dbg",
                    parameters=[
                        ToolParameter(
                            name="path",
                            type="string",
                            description="Path to executable",
                            required=True,
                        ),
                        ToolParameter(
                            name="args",
                            type="string",
                            description="Command line arguments",
                            required=False,
                        ),
                    ],
                    returns="Load status",
                ),
                ToolFunction(
                    name="x64dbg.attach",
                    description="Attach to a running process",
                    parameters=[
                        ToolParameter(
                            name="pid",
                            type="integer",
                            description="Process ID to attach",
                            required=True,
                        ),
                    ],
                    returns="Attach status",
                ),
                ToolFunction(
                    name="x64dbg.detach",
                    description="Detach from current process",
                    parameters=[],
                    returns="Detach status",
                ),
                ToolFunction(
                    name="x64dbg.run",
                    description="Run/continue execution",
                    parameters=[],
                    returns="Run status",
                ),
                ToolFunction(
                    name="x64dbg.pause",
                    description="Pause execution",
                    parameters=[],
                    returns="Pause status",
                ),
                ToolFunction(
                    name="x64dbg.stop",
                    description="Stop debugging (terminate process)",
                    parameters=[],
                    returns="Stop status",
                ),
                ToolFunction(
                    name="x64dbg.step_into",
                    description="Single step into",
                    parameters=[],
                    returns="New instruction pointer",
                ),
                ToolFunction(
                    name="x64dbg.step_over",
                    description="Single step over",
                    parameters=[],
                    returns="New instruction pointer",
                ),
                ToolFunction(
                    name="x64dbg.step_out",
                    description="Step out of current function",
                    parameters=[],
                    returns="New instruction pointer",
                ),
                ToolFunction(
                    name="x64dbg.set_breakpoint",
                    description="Set a breakpoint",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Address for breakpoint",
                            required=True,
                        ),
                        ToolParameter(
                            name="bp_type",
                            type="string",
                            description="Type: software, hardware, memory",
                            required=False,
                            default="software",
                            enum=["software", "hardware", "memory"],
                        ),
                        ToolParameter(
                            name="condition",
                            type="string",
                            description="Conditional expression",
                            required=False,
                        ),
                    ],
                    returns="Breakpoint ID",
                ),
                ToolFunction(
                    name="x64dbg.remove_breakpoint",
                    description="Remove a breakpoint",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Breakpoint address",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="x64dbg.get_registers",
                    description="Get all register values",
                    parameters=[],
                    returns="RegisterState object",
                ),
                ToolFunction(
                    name="x64dbg.set_register",
                    description="Set a register value",
                    parameters=[
                        ToolParameter(
                            name="register",
                            type="string",
                            description="Register name (rax, rbx, etc.)",
                            required=True,
                        ),
                        ToolParameter(
                            name="value",
                            type="integer",
                            description="New value",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="x64dbg.read_memory",
                    description="Read memory",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Memory address",
                            required=True,
                        ),
                        ToolParameter(
                            name="size",
                            type="integer",
                            description="Bytes to read",
                            required=True,
                        ),
                    ],
                    returns="Hex string of memory",
                ),
                ToolFunction(
                    name="x64dbg.write_memory",
                    description="Write memory",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Memory address",
                            required=True,
                        ),
                        ToolParameter(
                            name="data",
                            type="string",
                            description="Hex data to write",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="x64dbg.disassemble",
                    description="Disassemble at address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Start address",
                            required=True,
                        ),
                        ToolParameter(
                            name="count",
                            type="integer",
                            description="Number of instructions",
                            required=False,
                            default=10,
                        ),
                    ],
                    returns="Disassembly text",
                ),
                ToolFunction(
                    name="x64dbg.assemble",
                    description="Assemble instruction at address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Target address",
                            required=True,
                        ),
                        ToolParameter(
                            name="instruction",
                            type="string",
                            description="Assembly instruction",
                            required=True,
                        ),
                    ],
                    returns="Assembled bytes",
                ),
                ToolFunction(
                    name="x64dbg.get_stack_trace",
                    description="Get current stack trace",
                    parameters=[],
                    returns="List of stack frames",
                ),
                ToolFunction(
                    name="x64dbg.find_pattern",
                    description="Search memory for pattern",
                    parameters=[
                        ToolParameter(
                            name="pattern",
                            type="string",
                            description="Hex pattern with wildcards",
                            required=True,
                        ),
                    ],
                    returns="List of matching addresses",
                ),
                ToolFunction(
                    name="x64dbg.run_command",
                    description="Execute x64dbg command",
                    parameters=[
                        ToolParameter(
                            name="command",
                            type="string",
                            description="Command to execute",
                            required=True,
                        ),
                    ],
                    returns="Command output",
                ),
                ToolFunction(
                    name="x64dbg.set_watchpoint",
                    description="Set a memory watchpoint",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Memory address to watch",
                            required=True,
                        ),
                        ToolParameter(
                            name="size",
                            type="integer",
                            description="Watch region size in bytes",
                            required=True,
                        ),
                        ToolParameter(
                            name="watch_type",
                            type="string",
                            description="Access type to watch (read, write, execute)",
                            required=True,
                            enum=["read", "write", "execute"],
                        ),
                    ],
                    returns="Watchpoint ID",
                ),
                ToolFunction(
                    name="x64dbg.remove_watchpoint",
                    description="Remove a memory watchpoint",
                    parameters=[
                        ToolParameter(
                            name="watchpoint_id",
                            type="integer",
                            description="Watchpoint ID to remove",
                            required=True,
                        ),
                    ],
                    returns="True if removed",
                ),
                ToolFunction(
                    name="x64dbg.get_watchpoints",
                    description="Get all active watchpoints",
                    parameters=[],
                    returns="List of watchpoint information",
                ),
                ToolFunction(
                    name="x64dbg.allocate_memory",
                    description="Allocate memory in target process",
                    parameters=[
                        ToolParameter(
                            name="size",
                            type="integer",
                            description="Size in bytes to allocate",
                            required=True,
                        ),
                        ToolParameter(
                            name="protection",
                            type="string",
                            description="Memory protection flags",
                            required=False,
                            default="rwx",
                        ),
                    ],
                    returns="Address of allocated memory",
                ),
                ToolFunction(
                    name="x64dbg.free_memory",
                    description="Free memory in target process",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Address of memory to free",
                            required=True,
                        ),
                    ],
                    returns="True if freed successfully",
                ),
                ToolFunction(
                    name="x64dbg.assemble_at",
                    description="Assemble instruction at address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Target address",
                            required=True,
                        ),
                        ToolParameter(
                            name="instruction",
                            type="string",
                            description="Assembly instruction",
                            required=True,
                        ),
                    ],
                    returns="Assembled bytes",
                ),
                ToolFunction(
                    name="x64dbg.scan_memory",
                    description="Scan process memory for a byte pattern",
                    parameters=[
                        ToolParameter(
                            name="pattern",
                            type="string",
                            description="Hex byte pattern to search for",
                            required=True,
                        ),
                    ],
                    returns="List of memory search results with context",
                ),
                ToolFunction(
                    name="x64dbg.get_process_info",
                    description="Get complete process information including threads, modules, command line, and parent PID",
                    parameters=[],
                    returns="ProcessInfo with threads, modules, command line, and parent PID",
                ),
            ],
        )

    async def initialize(self, tool_path: Path | None = None) -> None:
        """Initialize the x64dbg bridge.

        Args:
            tool_path: Path to x64dbg installation.
        """
        self._x64dbg_path = tool_path
        self._state = BridgeState(
            connected=False,
            tool_running=False,
            binary_loaded=False,
            process_attached=False,
            target_path=None,
            target_pid=None,
            last_error=None,
        )

        if tool_path is not None:
            x64_exe = tool_path / "release" / "x64" / "x64dbg.exe"
            x32_exe = tool_path / "release" / "x32" / "x32dbg.exe"

            if x64_exe.exists() or x32_exe.exists():
                self._state.connected = True
                _logger.info("x64dbg_found", extra={"path": str(tool_path)})
            else:
                _logger.warning("x64dbg_not_found", extra={"path": str(tool_path)})

    async def shutdown(self) -> None:
        """Shutdown x64dbg and cleanup resources."""
        await self._close_connection()

        if self._process is not None:
            pid = self._process.pid
            process_manager = ProcessManager.get_instance()

            self._process.terminate()
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(self._process.wait),
                    timeout=5,
                )
            except TimeoutError:
                self._process.kill()
                await asyncio.to_thread(self._process.wait)

            process_manager.unregister(pid)
            self._process = None

        self._attached_pid = None
        self._breakpoints.clear()
        self._watchpoints.clear()
        await super().shutdown()
        _logger.info("x64dbg_bridge_shutdown")

    async def is_available(self) -> bool:
        """Check if x64dbg is available.

        Returns:
            True if x64dbg can be used.
        """
        if self._x64dbg_path is None:
            return False

        x64_exe = self._x64dbg_path / "release" / "x64" / "x64dbg.exe"
        x32_exe = self._x64dbg_path / "release" / "x32" / "x32dbg.exe"

        return x64_exe.exists() or x32_exe.exists()

    async def _start_debugger(self, is_64bit: bool = True) -> None:
        """Start the x64dbg debugger process.

        Args:
            is_64bit: Whether to use 64-bit debugger.

        Raises:
            ToolError: If debugger cannot be started.
        """
        if self._x64dbg_path is None:
            msg = "x64dbg path not set"
            raise ToolError(msg)

        if is_64bit:
            exe_path = self._x64dbg_path / "release" / "x64" / "x64dbg.exe"
        else:
            exe_path = self._x64dbg_path / "release" / "x32" / "x32dbg.exe"

        if not exe_path.exists():
            msg = f"x64dbg executable not found: {exe_path}"
            raise ToolError(msg)

        self._is_64bit = is_64bit
        _logger.info("x64dbg_starting", extra={"path": str(exe_path)})

        self._process = await asyncio.to_thread(
            Popen,
            [str(exe_path)],
            stdout=PIPE,
            stderr=PIPE,
            creationflags=CREATE_NEW_CONSOLE,
        )

        process_manager = ProcessManager.get_instance()
        process_manager.register(
            self._process,
            name=f"x64dbg-{'x64' if is_64bit else 'x32'}",
            process_type=ProcessType.DEBUGGER,
            metadata={"binary": str(exe_path)},
            cleanup_callback=self.shutdown,
        )

        await asyncio.sleep(3)
        self._state.connected = True
        self._state.tool_running = True

    async def _connect(self) -> None:
        """Connect to x64dbg via named pipe.

        Raises:
            ToolError: If connection fails.
        """
        try:
            if self._pipe_client is None:
                self._pipe_client = NamedPipeClient(
                    PipeConfig(),
                    event_handler=self._handle_event,
                )
            await self._pipe_client.connect()
            self._pipe_client.set_event_handler(self._handle_event)
            _logger.info("x64dbg_pipe_connected")
        except Exception as e:
            self._pipe_client = None
            msg = f"Failed to connect to x64dbg pipe: {e}"
            raise ToolError(msg) from e

    async def _close_connection(self) -> None:
        """Close named pipe connection."""
        if self._pipe_client is not None:
            await self._pipe_client.close()
            self._pipe_client = None

    def _handle_event(self, message: dict[str, Any]) -> None:
        """Handle asynchronous debug events from x64dbg.

        Args:
            message: Event payload.
        """
        event_type = str(message.get("event", ""))
        if event_type == "breakpoint":
            addr = int(message.get("address", 0))
            bp = self._breakpoints.get(addr)
            if bp is not None:
                bp.hit_count += 1
        elif event_type == "watchpoint":
            addr = int(message.get("address", 0))
            for wp in self._watchpoints.values():
                if wp.address == addr:
                    wp.hit_count += 1
                    break

    async def _send_pipe_command(
        self,
        command: str,
        params: dict[str, Any] | None = None,
    ) -> PipeCommandResult:
        """Send a command through the named pipe.

        Args:
            command: Command name.
            params: Optional parameters.

        Returns:
            Response data payload.

        Raises:
            ToolError: If the command fails.
        """
        if self._pipe_client is None or not self._pipe_client.is_connected:
            await self._connect()

        if self._pipe_client is None:
            msg = "Named pipe client not available"
            raise ToolError(msg)

        try:
            response = await asyncio.wait_for(
                self._pipe_client.send_command(command, params),
                timeout=self.COMMAND_TIMEOUT,
            )
        except TimeoutError as e:
            msg = f"Command {command} timed out"
            raise ToolError(msg) from e

        if not response.get("success", False):
            error = response.get("error", "Command failed")
            msg = str(error)
            raise ToolError(msg)
        data: str | int | float | bool | dict[str, object] | list[object] | None = response.get("data")
        return data

    async def _send_command(self, command: str) -> str:
        """Send command to x64dbg and get response.

        Args:
            command: Command to execute.

        Returns:
            Command response.

        Raises:
            ToolError: If command fails.
        """
        if self._process is None:
            msg = "x64dbg not running"
            raise ToolError(msg)

        result = await self._send_pipe_command("exec", {"command": command})
        if isinstance(result, str):
            return result
        if isinstance(result, dict):
            output = result.get("output")
            return str(output) if output is not None else ""
        return ""

    async def load(self, path: Path, args: str | None = None) -> None:
        """Load an executable into x64dbg.

        Args:
            path: Path to executable.
            args: Optional command line arguments.

        Raises:
            ToolError: If load fails.
        """
        if not path.exists():
            msg = f"File not found: {path}"
            raise ToolError(msg)

        self._binary_path = path.resolve()

        is_64bit = self._detect_architecture(path)

        if self._process is None:
            await self._start_debugger(is_64bit)

        cmd = f'InitDebug "{path.as_posix()}"'
        if args:
            cmd += f', "{args}"'

        await self._send_command(cmd)

        self._state.connected = True
        self._state.tool_running = True
        self._state.binary_loaded = True
        self._state.target_path = self._binary_path

        _logger.info("x64dbg_binary_loaded", extra={"path": path.name})

    @staticmethod
    def _detect_architecture(path: Path) -> bool:
        """Detect if binary is 64-bit.

        Args:
            path: Path to binary.

        Returns:
            True if 64-bit, False if 32-bit.
        """
        try:
            data = path.read_bytes()
        except Exception as e:
            _logger.debug("architecture_detection_failed", extra={"error": str(e)})
            return True

        if len(data) < PE_MAGIC_OFFSET:
            return True

        if data[:2] != b"MZ":
            return True

        pe_offset = int.from_bytes(data[PE_HEADER_OFFSET:PE_MAGIC_OFFSET], "little")

        if len(data) < pe_offset + 6:
            return True

        if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            return True

        machine = int.from_bytes(data[pe_offset + 4 : pe_offset + 6], "little")

        return False if machine == PE32_MACHINE else machine == PE64_MACHINE

    async def attach(self, pid: int) -> None:
        """Attach to a running process.

        Args:
            pid: Process ID.
        """
        if self._process is None:
            await self._start_debugger(True)

        await self._send_command(f"attach {pid}")
        self._attached_pid = pid

        self._state.connected = True
        self._state.tool_running = True
        self._state.process_attached = True
        self._state.target_pid = pid

        _logger.info("x64dbg_process_attached", extra={"pid": pid})

    async def detach(self) -> None:
        """Detach from current process."""
        await self._send_command("detach")
        self._attached_pid = None

        self._state.connected = True
        self._state.tool_running = True
        self._state.process_attached = False
        self._state.target_pid = None

        _logger.info("x64dbg_process_detached")

    async def run(self) -> None:
        """Continue execution."""
        await self._send_pipe_command("run")
        _logger.debug("execution_continued")

    async def pause(self) -> None:
        """Pause execution."""
        await self._send_pipe_command("pause")
        _logger.debug("execution_paused")

    async def stop(self) -> None:
        """Stop debugging and terminate process."""
        await self._send_pipe_command("stop")

        self._attached_pid = None
        self._state.process_attached = False
        self._state.target_pid = None
        _logger.info("debugging_stopped")

    async def step_into(self) -> int:
        """Single step into.

        Returns:
            New instruction pointer.
        """
        await self._send_pipe_command("step_into")
        regs = await self.get_registers()
        return regs.rip if self._is_64bit else regs.rip & DWORD_MASK

    async def step_over(self) -> int:
        """Single step over.

        Returns:
            New instruction pointer.
        """
        await self._send_pipe_command("step_over")
        regs = await self.get_registers()
        return regs.rip if self._is_64bit else regs.rip & DWORD_MASK

    async def step_out(self) -> int:
        """Step out of current function.

        Returns:
            New instruction pointer.
        """
        await self._send_pipe_command("step_out")
        regs = await self.get_registers()
        return regs.rip if self._is_64bit else regs.rip & DWORD_MASK

    async def set_breakpoint(
        self,
        address: int,
        bp_type: BreakpointType = "software",
        condition: str | None = None,
    ) -> int:
        """Set a breakpoint.

        Args:
            address: Breakpoint address.
            bp_type: Type of breakpoint.
            condition: Optional conditional expression.

        Returns:
            Breakpoint ID.
        """
        await self._send_pipe_command(
            "bp_set",
            {
                "address": address,
                "type": bp_type,
                "condition": condition,
            },
        )

        bp_id = self._next_bp_id
        self._next_bp_id += 1

        self._breakpoints[address] = BreakpointInfo(
            id=bp_id,
            address=address,
            bp_type=bp_type,
            enabled=True,
            hit_count=0,
            condition=condition,
        )

        _logger.info("breakpoint_set", extra={"type": bp_type, "address": hex(address), "id": bp_id})
        return bp_id

    async def remove_breakpoint(self, address: int) -> bool:
        """Remove a breakpoint.

        Args:
            address: Breakpoint address.

        Returns:
            True if removed.
        """
        await self._send_pipe_command("bp_remove", {"address": address})

        if address in self._breakpoints:
            del self._breakpoints[address]

        _logger.info("breakpoint_removed", extra={"address": hex(address)})
        return True

    async def get_breakpoints(self) -> list[BreakpointInfo]:
        """Get all breakpoints.

        Returns:
            List of breakpoints.
        """
        return list(self._breakpoints.values())

    async def set_watchpoint(
        self,
        address: int,
        size: int,
        watch_type: MemoryProtection,
    ) -> int:
        """Set a memory watchpoint.

        Args:
            address: Memory address.
            size: Watch size.
            watch_type: Access type to watch.

        Returns:
            Watchpoint ID.
        """
        type_map = {"read": "r", "write": "w", "execute": "x"}
        access = type_map.get(watch_type, "rw")

        await self._send_pipe_command(
            "wp_set",
            {
                "address": address,
                "size": size,
                "access": access,
            },
        )

        wp_id = self._next_wp_id
        self._next_wp_id += 1
        self._watchpoints[wp_id] = WatchpointInfo(
            id=wp_id,
            address=address,
            size=size,
            watch_type=watch_type,
            enabled=True,
            hit_count=0,
        )

        _logger.info("watchpoint_set", extra={"address": hex(address), "size": size, "type": watch_type})
        return wp_id

    async def remove_watchpoint(self, watchpoint_id: int) -> bool:
        """Remove a watchpoint.

        Args:
            watchpoint_id: Watchpoint ID.

        Returns:
            True if removed.
        """
        watchpoint = self._watchpoints.get(watchpoint_id)
        if watchpoint is None:
            return False

        await self._send_pipe_command(
            "wp_remove",
            {"address": watchpoint.address},
        )

        del self._watchpoints[watchpoint_id]
        _logger.info("watchpoint_removed", extra={"id": watchpoint_id})
        return True

    async def get_watchpoints(self) -> list[WatchpointInfo]:
        """Get all watchpoints.

        Returns:
            List of watchpoints.
        """
        return list(self._watchpoints.values())

    async def get_registers(self) -> RegisterState:
        """Get all register values.

        Returns:
            Current register state.

        Raises:
            ToolError: If the register response is invalid.
        """
        result = await self._send_pipe_command("reg_all")
        if not isinstance(result, dict):
            msg = "Invalid register response"
            raise ToolError(msg)

        def parse_int(value: object) -> int:
            if isinstance(value, int):
                return value
            if isinstance(value, str):
                try:
                    return int(value, 0)
                except ValueError:
                    return 0
            return 0

        def get_reg(primary: str, alt: str | None = None) -> int:
            if primary in result:
                return parse_int(result[primary])
            return parse_int(result[alt]) if alt and alt in result else 0

        state = RegisterState(
            rax=get_reg("rax", "eax"),
            rbx=get_reg("rbx", "ebx"),
            rcx=get_reg("rcx", "ecx"),
            rdx=get_reg("rdx", "edx"),
            rsi=get_reg("rsi", "esi"),
            rdi=get_reg("rdi", "edi"),
            rbp=get_reg("rbp", "ebp"),
            rsp=get_reg("rsp", "esp"),
            rip=get_reg("rip", "eip"),
            r8=get_reg("r8"),
            r9=get_reg("r9"),
            r10=get_reg("r10"),
            r11=get_reg("r11"),
            r12=get_reg("r12"),
            r13=get_reg("r13"),
            r14=get_reg("r14"),
            r15=get_reg("r15"),
            rflags=get_reg("rflags", "eflags"),
            cs=get_reg("cs"),
            ds=get_reg("ds"),
            es=get_reg("es"),
            fs=get_reg("fs"),
            gs=get_reg("gs"),
            ss=get_reg("ss"),
        )

        gpr_dict = state.get_gpr_dict()
        segment_regs = state.get_segment_registers()
        _logger.debug(
            "registers_read",
            extra={
                "gpr_count": len(gpr_dict),
                "segment_count": len(segment_regs),
            },
        )

        return state

    async def set_register(self, register: str, value: int) -> bool:
        """Set a register value.

        Args:
            register: Register name.
            value: New value.

        Returns:
            True if set.
        """
        await self._send_pipe_command(
            "reg_set",
            {"register": register, "value": value},
        )
        _logger.info("register_set", extra={"register": register, "value": hex(value)})
        return True

    async def read_memory(self, address: int, size: int) -> bytes:
        """Read process memory.

        Args:
            address: Memory address.
            size: Bytes to read.

        Returns:
            Memory contents.

        Raises:
            ToolError: If read fails.
        """
        if sys.platform != "win32":
            msg = "Windows API not available"
            raise ToolError(msg)

        kernel32 = ctypes.windll.kernel32

        if self._attached_pid is None:
            msg = "No process attached"
            raise ToolError(msg)

        handle = kernel32.OpenProcess(
            WIN_PROCESS_VM_READ,
            False,
            self._attached_pid,
        )

        if not handle:
            msg = f"Failed to open process {self._attached_pid}"
            raise ToolError(msg)

        try:
            buffer = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t()

            success = kernel32.ReadProcessMemory(
                handle,
                ctypes.c_void_p(address),
                buffer,
                size,
                ctypes.byref(bytes_read),
            )

            if not success:
                msg = f"ReadProcessMemory failed at 0x{address:X}"
                raise ToolError(msg)

            return buffer.raw[: bytes_read.value]

        finally:
            kernel32.CloseHandle(handle)

    async def write_memory(self, address: int, data: bytes) -> int:
        """Write to process memory.

        Args:
            address: Memory address.
            data: Bytes to write.

        Returns:
            Bytes written.

        Raises:
            ToolError: If write fails.
        """
        if sys.platform != "win32":
            msg = "Windows API not available"
            raise ToolError(msg)

        kernel32 = ctypes.windll.kernel32

        if self._attached_pid is None:
            msg = "No process attached"
            raise ToolError(msg)

        handle = kernel32.OpenProcess(
            WIN_PROCESS_VM_WRITE | WIN_PROCESS_VM_OPERATION,
            False,
            self._attached_pid,
        )

        if not handle:
            msg = f"Failed to open process {self._attached_pid}"
            raise ToolError(msg)

        try:
            bytes_written = ctypes.c_size_t()

            success = kernel32.WriteProcessMemory(
                handle,
                ctypes.c_void_p(address),
                data,
                len(data),
                ctypes.byref(bytes_written),
            )

            if not success:
                msg = f"WriteProcessMemory failed at 0x{address:X}"
                raise ToolError(msg)

            _logger.info("memory_written", extra={"bytes": bytes_written.value, "address": hex(address)})
            return bytes_written.value

        finally:
            kernel32.CloseHandle(handle)

    async def allocate_memory(self, size: int, protection: str = "rwx") -> int:
        """Allocate memory in target process.

        Args:
            size: Size to allocate.
            protection: Memory protection.

        Returns:
            Allocated address.

        Raises:
            ToolError: If allocation fails.
        """
        del protection
        if sys.platform != "win32":
            msg = "Windows API not available"
            raise ToolError(msg)

        kernel32 = ctypes.windll.kernel32

        if self._attached_pid is None:
            msg = "No process attached"
            raise ToolError(msg)

        handle = kernel32.OpenProcess(
            WIN_PROCESS_VM_OPERATION,
            False,
            self._attached_pid,
        )

        if not handle:
            msg = f"Failed to open process {self._attached_pid}"
            raise ToolError(msg)

        try:
            kernel32.VirtualAllocEx.restype = ctypes.c_void_p
            address_result = kernel32.VirtualAllocEx(
                handle,
                0,
                size,
                WIN_MEM_COMMIT | WIN_MEM_RESERVE,
                WIN_PAGE_EXECUTE_READWRITE,
            )

            if not address_result:
                msg = "VirtualAllocEx failed"
                raise ToolError(msg)

            address: int = int(address_result)
            _logger.info("memory_allocated", extra={"size": size, "address": hex(address)})
            return address

        finally:
            kernel32.CloseHandle(handle)

    async def free_memory(self, address: int) -> bool:
        """Free memory in target process.

        Args:
            address: Address to free.

        Returns:
            True if freed.
        """
        if sys.platform != "win32":
            return False

        kernel32 = ctypes.windll.kernel32

        if self._attached_pid is None:
            return False

        handle = kernel32.OpenProcess(
            WIN_PROCESS_VM_OPERATION,
            False,
            self._attached_pid,
        )

        if not handle:
            return False

        try:
            success = kernel32.VirtualFreeEx(
                handle,
                ctypes.c_void_p(address),
                0,
                WIN_MEM_RELEASE,
            )

            return bool(success)

        finally:
            kernel32.CloseHandle(handle)

    async def get_memory_regions(self) -> list[MemoryRegion]:
        """Get memory map of target process.

        Returns:
            List of memory regions.

        Raises:
            ToolError: If not on Windows, not attached, or API call fails.
        """
        if sys.platform != "win32":
            msg = f"get_memory_regions {_ERR_REQUIRES_WINDOWS}"
            raise ToolError(msg, tool_name="x64dbg")

        kernel32 = ctypes.windll.kernel32

        if self._attached_pid is None:
            msg = f"get_memory_regions: {_ERR_NOT_ATTACHED}"
            raise ToolError(msg, tool_name="x64dbg")

        class MemoryBasicInformation(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        handle = kernel32.OpenProcess(
            WIN_PROCESS_QUERY_INFORMATION | WIN_PROCESS_VM_READ,
            False,
            self._attached_pid,
        )

        if not handle:
            error_code = ctypes.get_last_error()
            msg = f"{_ERR_OPEN_PROCESS_FAILED} {self._attached_pid} for memory query"
            raise ToolError(msg, tool_name="x64dbg", exit_code=error_code)

        regions: list[MemoryRegion] = []

        try:
            address = 0
            mbi = MemoryBasicInformation()

            while True:
                result = kernel32.VirtualQueryEx(
                    handle,
                    ctypes.c_void_p(address),
                    ctypes.byref(mbi),
                    ctypes.sizeof(mbi),
                )

                if result == 0:
                    break

                if mbi.State == MEM_COMMIT_FLAG:
                    prot_map = {
                        PAGE_NOACCESS: "---",
                        PAGE_READONLY: "r--",
                        PAGE_READWRITE: "rw-",
                        PAGE_EXECUTE: "--x",
                        PAGE_EXECUTE_READ: "r-x",
                        PAGE_EXECUTE_READWRITE_FLAG: "rwx",
                    }

                    regions.append(
                        MemoryRegion(
                            base_address=mbi.BaseAddress or 0,
                            size=mbi.RegionSize,
                            protection=prot_map.get(mbi.Protect, "???"),
                            state="committed",
                            type="private" if mbi.Type == MEM_MAPPED_FLAG else "mapped",
                            module_name=None,
                        )
                    )

                address = (mbi.BaseAddress or 0) + mbi.RegionSize

                if address > MAX_USER_ADDRESS_64:
                    break

        finally:
            kernel32.CloseHandle(handle)

        return regions

    async def disassemble_at(
        self,
        address: int,
        count: int = 10,
    ) -> list[DisassemblyLine]:
        """Disassemble at address.

        Args:
            address: Start address.
            count: Number of instructions.

        Returns:
            Disassembly lines. Returns empty list on error.
        """
        capstone = get_capstone()
        if capstone is None:
            _logger.warning("capstone_unavailable")
            return []

        try:
            data = await self.read_memory(address, count * 15)

            mode = capstone.CS_MODE_64 if self._is_64bit else capstone.CS_MODE_32
            md = capstone.Cs(capstone.CS_ARCH_X86, mode)

            lines: list[DisassemblyLine] = []

            for instr in md.disasm(data, address):
                lines.append(
                    DisassemblyLine(
                        address=instr.address,
                        bytes_str=" ".join(f"{b:02x}" for b in instr.bytes),
                        mnemonic=instr.mnemonic,
                        operands=instr.op_str,
                        comment=None,
                    )
                )
                if len(lines) >= count:
                    break

        except Exception:
            _logger.exception("disassembly_failed")
            return []
        else:
            return lines

    async def assemble_at(self, address: int, instruction: str) -> bytes:
        """Assemble instruction at address.

        Args:
            address: Target address.
            instruction: Assembly instruction.

        Returns:
            Assembled bytes.

        Raises:
            ToolError: If assembly fails.
        """
        keystone = get_keystone()
        if keystone is None:
            msg = "keystone not available"
            raise ToolError(msg)

        mode = keystone.KS_MODE_64 if self._is_64bit else keystone.KS_MODE_32
        ks = keystone.Ks(keystone.KS_ARCH_X86, mode)

        encoding, _count = ks.asm(instruction, address)

        if encoding is None:
            msg = f"Failed to assemble: {instruction}"
            raise ToolError(msg)

        return bytes(encoding)

    async def get_stack_trace(self) -> list[StackFrame]:
        """Get current stack trace.

        Returns:
            List of stack frames.
        """
        frames: list[StackFrame] = []

        regs = await self.get_registers()
        rsp = regs.rsp
        rbp = regs.rbp
        rip = regs.rip

        frames.append(
            StackFrame(
                index=0,
                address=rip,
                return_address=0,
                frame_pointer=rbp,
                stack_pointer=rsp,
                function_name=None,
                module_name=None,
            )
        )

        for i in range(1, 32):
            try:
                if rbp == 0:
                    break

                data = await self.read_memory(rbp, STACK_FRAME_SIZE_64)

                if len(data) < STACK_FRAME_SIZE_64:
                    break

                if self._is_64bit:
                    saved_rbp = int.from_bytes(data[:8], "little")
                    return_addr = int.from_bytes(data[8:16], "little")
                else:
                    saved_rbp = int.from_bytes(data[:4], "little")
                    return_addr = int.from_bytes(data[4:8], "little")

                if return_addr == 0 or saved_rbp == 0:
                    break

                frames.append(
                    StackFrame(
                        index=i,
                        address=return_addr,
                        return_address=return_addr,
                        frame_pointer=saved_rbp,
                        stack_pointer=rbp + (16 if self._is_64bit else 8),
                        function_name=None,
                        module_name=None,
                    )
                )

                rbp = saved_rbp

            except ToolError as e:
                _logger.warning("stack_trace_unavailable", extra={"error": str(e)})
                break

        return frames

    async def scan_memory(self, pattern: bytes) -> list[MemorySearchResult]:
        """Scan process memory for a pattern.

        Args:
            pattern: Byte pattern to search for.

        Returns:
            List of matches with context.
        """
        if len(pattern) < MIN_PATTERN_LENGTH:
            _logger.warning("scan_pattern_too_short", extra={"length": len(pattern)})

        regions = await self.get_memory_regions()
        matches: list[MemorySearchResult] = []

        for region in regions:
            if "r" not in region.protection:
                continue

            try:
                data = await self.read_memory(region.base_address, min(region.size, MAX_MEMORY_READ_SIZE))
                offset = 0
                while True:
                    idx = data.find(pattern, offset)
                    if idx == -1:
                        break

                    addr = region.base_address + idx
                    context_before = data[max(0, idx - 16) : idx].hex()
                    context_after = data[idx + len(pattern) : idx + len(pattern) + 16].hex()

                    matches.append(
                        MemorySearchResult(
                            address=addr,
                            matched_bytes=pattern.hex(),
                            context_before=context_before,
                            context_after=context_after,
                        )
                    )
                    offset = idx + 1

            except ToolError as e:
                _logger.warning("memory_scan_failed", extra={"error": str(e)})
                continue

        return matches

    async def run_command(self, command: str) -> str:
        """Execute x64dbg command.

        Args:
            command: Command to execute.

        Returns:
            Command output.
        """
        return await self._send_command(command)

    async def spawn(self, path: Path, args: Sequence[str] | None = None) -> int:
        """Spawn a process for debugging.

        Args:
            path: Path to executable.
            args: Optional arguments.

        Returns:
            Process ID.
        """
        args_str = " ".join(args) if args else None
        await self.load(path, args_str)
        return self._attached_pid or 0

    async def _get_threads(self) -> list[ThreadInfo]:
        """Get thread information for the attached process.

        Uses Windows Toolhelp API (CreateToolhelp32Snapshot with TH32CS_SNAPTHREAD)
        to enumerate all threads belonging to the attached process.

        Returns:
            List of ThreadInfo objects for each thread in the process.

        Raises:
            ToolError: If not on Windows, not attached, or API call fails.
        """
        if sys.platform != "win32":
            msg = f"get_threads {_ERR_REQUIRES_WINDOWS}"
            raise ToolError(msg, tool_name="x64dbg")

        if self._attached_pid is None:
            msg = f"get_threads: {_ERR_NOT_ATTACHED}"
            raise ToolError(msg, tool_name="x64dbg")

        kernel32 = ctypes.windll.kernel32

        class ThreadEntry32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ThreadID", wintypes.DWORD),
                ("th32OwnerProcessID", wintypes.DWORD),
                ("tpBasePri", wintypes.LONG),
                ("tpDeltaPri", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
            ]

        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        if snapshot in {INVALID_HANDLE_VALUE, DWORD_MASK}:
            error_code = ctypes.get_last_error()
            msg = f"{_ERR_CREATE_SNAPSHOT_FAILED} for threads: error {error_code}"
            raise ToolError(msg, tool_name="x64dbg", exit_code=error_code)

        threads: list[ThreadInfo] = []

        try:
            te32 = ThreadEntry32()
            te32.dwSize = ctypes.sizeof(ThreadEntry32)
            _logger.debug("initialized_thread_entry", extra={"size": te32.dwSize})

            if kernel32.Thread32First(snapshot, ctypes.byref(te32)):
                while True:
                    if te32.th32OwnerProcessID == self._attached_pid:
                        threads.append(
                            ThreadInfo(
                                tid=te32.th32ThreadID,
                                start_address=0,
                                state="unknown",
                                priority=te32.tpBasePri,
                            )
                        )
                    if not kernel32.Thread32Next(snapshot, ctypes.byref(te32)):
                        break
        except Exception as e:
            msg = f"{_ERR_GET_THREADS_FAILED}: {e}"
            raise ToolError(msg, tool_name="x64dbg") from e
        finally:
            kernel32.CloseHandle(snapshot)

        _logger.debug("threads_found", extra={"count": len(threads), "pid": self._attached_pid})
        return threads

    async def _get_modules(self) -> list[ModuleInfo]:
        """Get loaded modules for the attached process.

        Uses Windows Toolhelp API (CreateToolhelp32Snapshot with TH32CS_SNAPMODULE)
        to enumerate all loaded DLLs and the main executable.

        Returns:
            List of ModuleInfo objects for each loaded module.

        Raises:
            ToolError: If not on Windows, not attached, or API call fails.
        """
        if sys.platform != "win32":
            msg = f"get_modules {_ERR_REQUIRES_WINDOWS}"
            raise ToolError(msg, tool_name="x64dbg")

        if self._attached_pid is None:
            msg = f"get_modules: {_ERR_NOT_ATTACHED}"
            raise ToolError(msg, tool_name="x64dbg")

        kernel32 = ctypes.windll.kernel32

        class ModuleEntry32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("th32ModuleID", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("GlblcntUsage", wintypes.DWORD),
                ("ProccntUsage", wintypes.DWORD),
                ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", wintypes.DWORD),
                ("hModule", ctypes.c_void_p),
                ("szModule", ctypes.c_wchar * 256),
                ("szExePath", ctypes.c_wchar * 260),
            ]

        snapshot = kernel32.CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            self._attached_pid,
        )
        if snapshot in {INVALID_HANDLE_VALUE, DWORD_MASK}:
            error_code = ctypes.get_last_error()
            msg = f"{_ERR_CREATE_SNAPSHOT_FAILED} for modules PID {self._attached_pid}: error {error_code}"
            raise ToolError(msg, tool_name="x64dbg", exit_code=error_code)

        modules: list[ModuleInfo] = []

        try:
            me32 = ModuleEntry32W()
            me32.dwSize = ctypes.sizeof(ModuleEntry32W)
            _logger.debug("initialized_module_entry", extra={"size": me32.dwSize})

            if kernel32.Module32FirstW(snapshot, ctypes.byref(me32)):
                while True:
                    base_addr = me32.modBaseAddr or 0
                    modules.append(
                        ModuleInfo(
                            name=me32.szModule,
                            path=Path(me32.szExePath),
                            base_address=base_addr,
                            size=me32.modBaseSize,
                            entry_point=0,
                        )
                    )
                    if not kernel32.Module32NextW(snapshot, ctypes.byref(me32)):
                        break
        except Exception as e:
            msg = f"{_ERR_GET_MODULES_FAILED}: {e}"
            raise ToolError(msg, tool_name="x64dbg") from e
        finally:
            kernel32.CloseHandle(snapshot)

        _logger.debug("modules_found", extra={"count": len(modules), "pid": self._attached_pid})
        return modules

    async def get_process_info(self) -> ProcessInfo | None:
        """Get complete process information including threads and modules.

        Aggregates thread and module information along with process details
        using Windows APIs.

        Returns:
            ProcessInfo with populated threads and modules, or None if not attached.
        """
        if self._attached_pid is None:
            return None

        threads = await self._get_threads()
        modules = await self._get_modules()

        command_line = self._get_command_line(self._attached_pid)
        parent_pid = self._get_parent_pid(self._attached_pid)

        return ProcessInfo(
            pid=self._attached_pid,
            name=self._binary_path.name if self._binary_path else "unknown",
            path=self._binary_path,
            command_line=command_line,
            parent_pid=parent_pid,
            threads=threads,
            modules=modules,
        )

    @staticmethod
    def _get_parent_pid(pid: int) -> int:
        """Get parent process ID using Windows Toolhelp API.

        Args:
            pid: Process ID to get parent for.

        Returns:
            Parent process ID.

        Raises:
            ToolError: If not on Windows or API call fails.
        """
        if sys.platform != "win32":
            msg = f"_get_parent_pid {_ERR_REQUIRES_WINDOWS}"
            raise ToolError(msg, tool_name="x64dbg")

        parent_pid: int = 0
        kernel32 = ctypes.windll.kernel32

        class ProcessEntry32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_wchar * 260),
            ]

        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot in {INVALID_HANDLE_VALUE, DWORD_MASK}:
            error_code = ctypes.get_last_error()
            msg = f"{_ERR_CREATE_SNAPSHOT_FAILED} for process: error {error_code}"
            raise ToolError(msg, tool_name="x64dbg", exit_code=error_code)

        try:
            pe32 = ProcessEntry32W()
            pe32.dwSize = ctypes.sizeof(ProcessEntry32W)
            _logger.debug("initialized_process_entry", extra={"size": pe32.dwSize})

            if kernel32.Process32FirstW(snapshot, ctypes.byref(pe32)):
                while True:
                    if pe32.th32ProcessID == pid:
                        parent_pid = int(pe32.th32ParentProcessID)
                        break
                    if not kernel32.Process32NextW(snapshot, ctypes.byref(pe32)):
                        break
        except Exception as e:
            msg = f"{_ERR_GET_PARENT_PID_FAILED}: {e}"
            raise ToolError(msg, tool_name="x64dbg") from e
        finally:
            kernel32.CloseHandle(snapshot)

        return parent_pid

    @staticmethod
    def _get_command_line(pid: int) -> str | None:
        """Get process command line using Windows API.

        Args:
            pid: Process ID to get command line for.

        Returns:
            Command line string, or None if not accessible.
        """
        return None if sys.platform != "win32" else _read_process_command_line(pid)
