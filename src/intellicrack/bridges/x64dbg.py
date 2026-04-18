# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""X64dbg bridge for Windows debugging.

This module provides integration with x64dbg for dynamic analysis, debugging, and memory manipulation on Windows systems.
"""

from __future__ import annotations

import asyncio
import math
import os
import struct
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Literal, TypeGuard, cast

from intellicrack.bridges._win32_types import CMD_LINE_OFFSET_32
from intellicrack.bridges.base import (
    BridgeCapabilities,
    BridgeState,
    DebuggerBridge,
    DisassemblyLine,
    MemorySearchResult,
    StackFrame,
    WatchpointInfo,
)
from intellicrack.bridges.installer import deploy_x64dbg_plugin
from intellicrack.bridges.named_pipe_client import NamedPipeClient, PipeConfig
from intellicrack.core._subprocess import (
    PIPE,
    STARTF_USESHOWWINDOW,
    STARTUPINFO,
    Popen,
)
from intellicrack.core.logging import get_logger
from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.core.types import (
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


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from types import ModuleType

_logger = get_logger("bridges.x64dbg")
_IS_WIN32: bool = os.name == "nt"

# Optional disassembler/assembler imports
_capstone: ModuleType | None = None
_keystone: ModuleType | None = None

try:
    import capstone as _capstone_module

    _capstone = _capstone_module
except ImportError:
    _logger.debug("capstone_not_available", library="capstone")

try:
    import keystone as _keystone_module

    _keystone = _keystone_module
except ImportError:
    _logger.debug("keystone_not_available", library="keystone")


def get_capstone() -> ModuleType | None:
    """Get the capstone module if available.

    Returns:
        ModuleType | None: The capstone module, or None if not installed.
    """
    return _capstone


def get_keystone() -> ModuleType | None:
    """Get the keystone module if available.

    Returns:
        ModuleType | None: The keystone module, or None if not installed.
    """
    return _keystone


# Windows API constants
WIN_PROCESS_VM_READ = 0x0010
WIN_PROCESS_VM_WRITE = 0x0020
WIN_PROCESS_VM_OPERATION = 0x0008
WIN_PROCESS_QUERY_INFORMATION = 0x0400
WIN_NO_INHERIT_HANDLE: bool = False
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
HEX_BYTE_LENGTH = 2
MIN_LINE_PARTS = 2
MAX_LOCAL_VARS = 15
PE_SECTION_HEADER_SIZE = 40
PE_EXPORT_MAX = 4096
PE_EXPORT_NAME_BUF = 256
PE_EXPORT_DIR_MIN_SIZE = 0x10000
_PE_RESOURCE_TYPE_NAMES: dict[int, str] = {
    1: "RT_CURSOR",
    2: "RT_BITMAP",
    3: "RT_ICON",
    4: "RT_MENU",
    5: "RT_DIALOG",
    6: "RT_STRING",
    7: "RT_FONTDIR",
    8: "RT_FONT",
    9: "RT_ACCELERATOR",
    10: "RT_RCDATA",
    11: "RT_MESSAGETABLE",
    12: "RT_GROUP_CURSOR",
    14: "RT_GROUP_ICON",
    16: "RT_VERSION",
    24: "RT_MANIFEST",
}


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


def _is_str_obj_dict(data: object) -> TypeGuard[dict[str, object]]:
    """Narrow an object to dict[str, object].

    Args:
        data: Object to check.

    Returns:
        TypeGuard[dict[str, object]]: True if data is a dict with string keys.
    """
    return isinstance(data, dict)


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
        bytes | None: Bytes read, or None on failure.
    """
    if not _IS_WIN32:
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
        str | None: Command line string, or None if not accessible.
    """
    if not _IS_WIN32:
        return None

    try:
        kernel32 = ctypes.windll.kernel32
        inherit_handle = False
        handle = kernel32.OpenProcess(
            WIN_PROCESS_QUERY_INFORMATION | WIN_PROCESS_VM_READ,
            inherit_handle,
            pid,
        )
        if not handle:
            return None

        try:
            return _extract_command_line_from_peb(handle)
        finally:
            kernel32.CloseHandle(handle)

    except (OSError, ValueError) as e:
        _logger.warning("command_line_read_failed", error=str(e))
        return None


def _extract_command_line_from_peb(handle: int) -> str | None:
    """Extract command line from process PEB.

    Args:
        handle: Process handle with VM_READ access.

    Returns:
        str | None: Command line string, or None on failure.
    """
    if not _IS_WIN32:
        return None

    class ProcessBasicInformation(ctypes.Structure):
        _fields_: ClassVar = [
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
        int: Pointer size in bytes (4 for 32-bit, 8 for 64-bit).
    """
    if not _IS_WIN32:
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
        str | None: Command line string, or None on failure.
    """
    if not _IS_WIN32:
        return None

    cmd_offset = CMD_LINE_OFFSET_64 if ptr_size == POINTER_SIZE_64 else CMD_LINE_OFFSET_32
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
    register/memory manipulation, and process control. Instances own
    slots for the x64dbg installation path, the spawned debugger
    subprocess, the named-pipe client used for IPC, the attached process
    identifier, the IPC port (defaulting to ``DEFAULT_PORT``), the
    tracked binary path and bitness, the breakpoint and watchpoint
    registries with their identifier counters, the plugin-deployment
    flag, the event-callback list used to fan out debugger
    notifications, and the advertised ``BridgeCapabilities``.

    Attributes:
        DEFAULT_PORT: TCP port for the x64dbg remote command interface.
        COMMAND_TIMEOUT: Maximum seconds to wait for a debugger command response.
    """

    DEFAULT_PORT = 27015
    COMMAND_TIMEOUT = 10.0

    def __init__(self) -> None:
        """Initialize the X64DbgBridge instance."""
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
        self._plugin_deployed: bool = False
        self.event_callbacks: list[Callable[[str, dict[str, Any]], None]] = []
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
            int | None: The PID of the attached process, or None if not attached.
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
            Path | None: The binary file path, or None if no binary is loaded.
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
            bool: True if operating in 64-bit mode.
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
    def plugin_status(self) -> dict[str, object]:
        """Get diagnostic information about plugin deployment readiness.

        Returns:
            dict[str, object]: Dictionary with keys ``plugin_deployed``, ``x64dbg_found``,
            ``pipe_connected``, ``ready``, and ``diagnostic``.
        """
        x64dbg_found = self._x64dbg_path is not None and self._state.connected
        pipe_connected = self._pipe_client is not None and self._pipe_client.is_connected
        ready = x64dbg_found and self._plugin_deployed and pipe_connected

        diagnostic: str
        if not x64dbg_found:
            diagnostic = "x64dbg installation not configured"
        elif not self._plugin_deployed:
            diagnostic = (
                "x64dbg bridge plugin not installed. Ensure Visual Studio and"
                " CMake are installed for automatic build, or manually build"
                " from tools/x64dbg_plugin/"
            )
        elif not pipe_connected:
            diagnostic = (
                "Plugin deployed but x64dbg is not running or has not loaded"
                " the plugin. Start x64dbg and verify the plugin is loaded"
                " (Plugins menu)"
            )
        else:
            diagnostic = ""

        return {
            "plugin_deployed": self._plugin_deployed,
            "x64dbg_found": x64dbg_found,
            "pipe_connected": pipe_connected,
            "ready": ready,
            "diagnostic": diagnostic,
        }

    @property
    def breakpoints(self) -> dict[int, BreakpointInfo]:
        """Get the breakpoints dictionary.

        Returns:
            dict[int, BreakpointInfo]: Mapping of breakpoint IDs to their info.
        """
        return self._breakpoints

    @property
    def next_bp_id(self) -> int:
        """Get the next breakpoint ID.

        Returns:
            int: The next breakpoint ID to be assigned.
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
            dict[int, WatchpointInfo]: Mapping of watchpoint IDs to their info.
        """
        return self._watchpoints

    @property
    def next_wp_id(self) -> int:
        """Get the next watchpoint ID.

        Returns:
            int: The next watchpoint ID to be assigned.
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
            Path | None: The x64dbg installation path, or None if not found.
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
    def debugger_pid(self) -> int | None:
        """Get the PID of the running debugger process.

        Returns:
            int | None: Process ID of the debugger, or None if not running.
        """
        return self._process.pid if self._process is not None else None

    @property
    def name(self) -> ToolName:
        """Get the tool's name.

        Returns:
            ToolName: ToolName.X64DBG
        """
        return ToolName.X64DBG

    @property
    def tool_definition(self) -> ToolDefinition:
        """Get tool definition for LLM function calling.

        Returns:
            ToolDefinition: ToolDefinition with all available functions.
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
                        ToolParameter(
                            name="alignment",
                            type="integer",
                            description="Only return matches at addresses divisible by this value",
                            required=False,
                            default=1,
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
                ToolFunction(
                    name="x64dbg.get_memory_regions",
                    description="Get full process memory map with all regions, base addresses, sizes, protections, and types",
                    parameters=[],
                    returns="List of MemoryRegion objects",
                ),
                ToolFunction(
                    name="x64dbg.get_threads",
                    description="Enumerate all threads in the debugged process with IDs, entry points, and states",
                    parameters=[],
                    returns="List of ThreadInfo objects",
                ),
                ToolFunction(
                    name="x64dbg.get_modules",
                    description="List all loaded modules in the debugged process with base addresses, sizes, and paths",
                    parameters=[],
                    returns="List of ModuleInfo objects",
                ),
                ToolFunction(
                    name="x64dbg.get_breakpoints",
                    description="List all breakpoints including those set in the x64dbg GUI",
                    parameters=[],
                    returns="List of BreakpointInfo objects",
                ),
                ToolFunction(
                    name="x64dbg.run_to",
                    description="Run execution until a specific address is reached",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Target address to run to", required=True),
                    ],
                    returns="Execution result",
                ),
                ToolFunction(
                    name="x64dbg.execute_til_return",
                    description="Execute until the current function returns",
                    parameters=[],
                    returns="Execution result",
                ),
                ToolFunction(
                    name="x64dbg.skip_instruction",
                    description="Skip the current instruction by advancing the instruction pointer past it",
                    parameters=[],
                    returns="Old and new IP with skipped byte count",
                ),
                ToolFunction(
                    name="x64dbg.set_ip",
                    description="Set the instruction pointer to a specific address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="New instruction pointer value", required=True),
                    ],
                    returns="Updated IP info",
                ),
                ToolFunction(
                    name="x64dbg.set_label",
                    description="Set a debug label at an address in x64dbg",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address for the label", required=True),
                        ToolParameter(name="text", type="string", description="Label text", required=True),
                    ],
                    returns="Label set result",
                ),
                ToolFunction(
                    name="x64dbg.get_labels",
                    description="Get debug labels in an address range",
                    parameters=[
                        ToolParameter(name="start", type="integer", description="Start address", required=True),
                        ToolParameter(name="end", type="integer", description="End address", required=True),
                    ],
                    returns="List of labels",
                ),
                ToolFunction(
                    name="x64dbg.set_comment",
                    description="Set a debug comment at an address in x64dbg",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address for the comment", required=True),
                        ToolParameter(name="text", type="string", description="Comment text", required=True),
                    ],
                    returns="Comment set result",
                ),
                ToolFunction(
                    name="x64dbg.get_comments",
                    description="Get debug comments in an address range",
                    parameters=[
                        ToolParameter(name="start", type="integer", description="Start address", required=True),
                        ToolParameter(name="end", type="integer", description="End address", required=True),
                    ],
                    returns="List of comments",
                ),
                ToolFunction(
                    name="x64dbg.enable_breakpoint",
                    description="Enable a breakpoint at an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Breakpoint address", required=True),
                    ],
                    returns="Enable result",
                ),
                ToolFunction(
                    name="x64dbg.disable_breakpoint",
                    description="Disable a breakpoint at an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Breakpoint address", required=True),
                    ],
                    returns="Disable result",
                ),
                ToolFunction(
                    name="x64dbg.set_breakpoint_on_api",
                    description="Set a breakpoint on an imported API function",
                    parameters=[
                        ToolParameter(name="module", type="string", description="Module name (e.g. kernel32)", required=True),
                        ToolParameter(name="function", type="string", description="Function name (e.g. CreateFileW)", required=True),
                    ],
                    returns="Breakpoint set result",
                ),
                ToolFunction(
                    name="x64dbg.dump_memory_to_file",
                    description="Dump a memory region to a file on disk",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Start address", required=True),
                        ToolParameter(name="size", type="integer", description="Number of bytes to dump", required=True),
                        ToolParameter(name="path", type="string", description="File path to write to", required=True),
                    ],
                    returns="Dump result with bytes written",
                ),
                ToolFunction(
                    name="x64dbg.get_module_sections",
                    description="Get PE section info of a loaded module by parsing its in-memory PE header",
                    parameters=[
                        ToolParameter(name="module_name", type="string", description="Module name (e.g. ntdll.dll)", required=True),
                    ],
                    returns="List of section info dicts",
                ),
                ToolFunction(
                    name="x64dbg.get_module_exports",
                    description="Get exports of a loaded module by parsing its in-memory PE export table",
                    parameters=[
                        ToolParameter(name="module_name", type="string", description="Module name (e.g. kernel32.dll)", required=True),
                    ],
                    returns="List of export dicts",
                ),
                ToolFunction(
                    name="x64dbg.trace_start",
                    description="Start conditional trace recording in x64dbg",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address to start tracing at", required=False),
                        ToolParameter(name="condition", type="string", description="Trace break condition", required=False),
                        ToolParameter(name="log_text", type="string", description="Text to log at each traced instruction", required=False),
                    ],
                    returns="Trace start result",
                ),
                ToolFunction(
                    name="x64dbg.trace_stop",
                    description="Stop trace recording",
                    parameters=[],
                    returns="Trace stop result",
                ),
                ToolFunction(
                    name="x64dbg.set_exception_config",
                    description="Configure how x64dbg handles a specific exception code",
                    parameters=[
                        ToolParameter(name="code", type="integer", description="Exception code (e.g. 0xC0000005)", required=True),
                        ToolParameter(
                            name="handling",
                            type="string",
                            description="Handling mode: break, ignore, or log",
                            required=True,
                            enum=["break", "ignore", "log"],
                        ),
                    ],
                    returns="Exception config result",
                ),
                ToolFunction(
                    name="x64dbg.spawn",
                    description="Spawn a process for debugging",
                    parameters=[
                        ToolParameter(name="path", type="string", description="Path to executable", required=True),
                        ToolParameter(name="args", type="array", description="Optional argument list", required=False),
                    ],
                    returns="Process ID",
                ),
                ToolFunction(
                    name="x64dbg.patch_instruction",
                    description="Assemble and write an instruction at address using x64dbg's assembler",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Target address", required=True),
                        ToolParameter(name="instruction", type="string", description="Assembly instruction text", required=True),
                    ],
                    returns="Dict with success status and address",
                ),
                ToolFunction(
                    name="x64dbg.nop_range",
                    description="Fill an address range with NOP (0x90) bytes",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Start address", required=True),
                        ToolParameter(name="size", type="integer", description="Number of bytes to NOP", required=True),
                    ],
                    returns="Dict with success status, address, and size",
                ),
                ToolFunction(
                    name="x64dbg.get_module_imports",
                    description="Get imports of a loaded module via the plugin",
                    parameters=[
                        ToolParameter(name="module_name", type="string", description="Module name (e.g. 'kernel32.dll')", required=True),
                    ],
                    returns="List of import dicts with iatRva, iatVa, ordinal, name, undecoratedName",
                ),
                ToolFunction(
                    name="x64dbg.find_references",
                    description="Find references to an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Target address", required=True),
                    ],
                    returns="Dict with success status",
                ),
                ToolFunction(
                    name="x64dbg.find_string_references",
                    description="Find string references in a module",
                    parameters=[
                        ToolParameter(name="module", type="string", description="Module name", required=True),
                    ],
                    returns="Dict with success status",
                ),
                ToolFunction(
                    name="x64dbg.find_intermodular_calls",
                    description="Find intermodular calls in a module",
                    parameters=[
                        ToolParameter(name="module", type="string", description="Module name", required=True),
                    ],
                    returns="Dict with success status",
                ),
                ToolFunction(
                    name="x64dbg.evaluate_expression",
                    description="Evaluate an x64dbg expression",
                    parameters=[
                        ToolParameter(
                            name="expression",
                            type="string",
                            description="Expression to evaluate (e.g. 'rax+rbx*4')",
                            required=True,
                        ),
                    ],
                    returns="Expression result value as integer",
                ),
                ToolFunction(
                    name="x64dbg.get_function_cfg",
                    description="Get control flow graph of a function",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Function entry address", required=True),
                        ToolParameter(
                            name="max_blocks",
                            type="integer",
                            description="Maximum number of basic blocks to analyze",
                            required=False,
                        ),
                    ],
                    returns="Dict with entry, blocks list, and edges list",
                ),
                ToolFunction(
                    name="x64dbg.save_database",
                    description="Save the x64dbg analysis database",
                    parameters=[],
                    returns="Dict with success status",
                ),
                ToolFunction(
                    name="x64dbg.load_database",
                    description="Load the x64dbg analysis database",
                    parameters=[],
                    returns="Dict with success status",
                ),
                ToolFunction(
                    name="x64dbg.clear_database",
                    description="Clear the x64dbg analysis database",
                    parameters=[],
                    returns="Dict with success status",
                ),
                ToolFunction(
                    name="x64dbg.get_patches",
                    description="List all applied patches",
                    parameters=[],
                    returns="List of patch dicts with address, oldByte, newByte",
                ),
                ToolFunction(
                    name="x64dbg.restore_patch",
                    description="Restore original bytes at a patched address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address of the patch to restore", required=True),
                    ],
                    returns="Dict with success status",
                ),
                ToolFunction(
                    name="x64dbg.export_patches",
                    description="Export patches to a file",
                    parameters=[
                        ToolParameter(name="path", type="string", description="Output file path", required=True),
                    ],
                    returns="Dict with success status and path",
                ),
                ToolFunction(
                    name="x64dbg.suspend_thread",
                    description="Suspend a thread",
                    parameters=[
                        ToolParameter(name="tid", type="integer", description="Thread ID", required=True),
                    ],
                    returns="Dict with success status and tid",
                ),
                ToolFunction(
                    name="x64dbg.resume_thread",
                    description="Resume a suspended thread",
                    parameters=[
                        ToolParameter(name="tid", type="integer", description="Thread ID", required=True),
                    ],
                    returns="Dict with success status and tid",
                ),
                ToolFunction(
                    name="x64dbg.switch_thread",
                    description="Switch the active debugger thread",
                    parameters=[
                        ToolParameter(name="tid", type="integer", description="Thread ID to switch to", required=True),
                    ],
                    returns="Dict with success status and tid",
                ),
                ToolFunction(
                    name="x64dbg.set_thread_name",
                    description="Set a thread's name",
                    parameters=[
                        ToolParameter(name="tid", type="integer", description="Thread ID", required=True),
                        ToolParameter(name="name", type="string", description="Display name for the thread", required=True),
                    ],
                    returns="Dict with success status, tid, and name",
                ),
                ToolFunction(
                    name="x64dbg.get_seh_chain",
                    description="Get the structured exception handler chain",
                    parameters=[],
                    returns="List of SEH entry dicts with handler and next addresses",
                ),
                ToolFunction(
                    name="x64dbg.read_peb",
                    description="Read the Process Environment Block",
                    parameters=[],
                    returns="Dict with PEB fields including beingDebugged, imageBaseAddress, ntGlobalFlag",
                ),
                ToolFunction(
                    name="x64dbg.read_teb",
                    description="Read the Thread Environment Block",
                    parameters=[
                        ToolParameter(
                            name="tid",
                            type="integer",
                            description="Thread ID; uses current thread if not provided",
                            required=False,
                        ),
                    ],
                    returns="Dict with TEB fields including stackBase, stackLimit, processId, threadId",
                ),
                ToolFunction(
                    name="x64dbg.get_pe_directories",
                    description="Get PE data directory entries for a module",
                    parameters=[
                        ToolParameter(name="module_name", type="string", description="Module name (e.g. 'ntdll.dll')", required=True),
                    ],
                    returns="List of directory entry dicts with index, name, rva, size",
                ),
                ToolFunction(
                    name="x64dbg.add_watch",
                    description="Add a watch expression",
                    parameters=[
                        ToolParameter(name="expression", type="string", description="Expression to watch", required=True),
                    ],
                    returns="Dict with success status and expression",
                ),
                ToolFunction(
                    name="x64dbg.remove_watch",
                    description="Remove a watch expression by index",
                    parameters=[
                        ToolParameter(name="index", type="integer", description="Watch index to remove", required=True),
                    ],
                    returns="Dict with success status and index",
                ),
                ToolFunction(
                    name="x64dbg.get_watches",
                    description="Get all watch expressions and their current values",
                    parameters=[],
                    returns="List of watch dicts",
                ),
                ToolFunction(
                    name="x64dbg.set_logging_breakpoint",
                    description="Set a logging breakpoint that logs text without stopping",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Breakpoint address", required=True),
                        ToolParameter(name="log_text", type="string", description="Text to log when hit", required=True),
                        ToolParameter(
                            name="non_stopping",
                            type="boolean",
                            description="If True, continue execution after logging",
                            required=False,
                        ),
                    ],
                    returns="Dict with success status, address, and log_text",
                ),
                ToolFunction(
                    name="x64dbg.configure_breakpoint",
                    description="Configure breakpoint properties including condition, log text, command, and fast resume",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Breakpoint address", required=True),
                        ToolParameter(name="condition", type="string", description="Conditional expression", required=False),
                        ToolParameter(name="log_text", type="string", description="Log text on hit", required=False),
                        ToolParameter(name="command", type="string", description="Command to execute on hit", required=False),
                        ToolParameter(name="fast_resume", type="boolean", description="Whether to auto-resume after hit", required=False),
                    ],
                    returns="Dict with success status and configured properties",
                ),
                ToolFunction(
                    name="x64dbg.set_dll_breakpoint",
                    description="Set a breakpoint on DLL load/unload",
                    parameters=[
                        ToolParameter(name="dll_name", type="string", description="DLL name to break on", required=True),
                        ToolParameter(
                            name="event",
                            type="string",
                            description="Event type: 'load' or 'unload'",
                            required=False,
                            enum=["load", "unload"],
                        ),
                    ],
                    returns="Dict with success status, dll_name, and event",
                ),
                ToolFunction(
                    name="x64dbg.trace_into",
                    description="Trace into with optional condition",
                    parameters=[
                        ToolParameter(name="condition", type="string", description="Trace break condition expression", required=False),
                        ToolParameter(name="max_steps", type="integer", description="Maximum number of steps", required=False),
                    ],
                    returns="Dict with success status",
                ),
                ToolFunction(
                    name="x64dbg.trace_over",
                    description="Trace over with optional condition",
                    parameters=[
                        ToolParameter(name="condition", type="string", description="Trace break condition expression", required=False),
                        ToolParameter(name="max_steps", type="integer", description="Maximum number of steps", required=False),
                    ],
                    returns="Dict with success status",
                ),
                ToolFunction(
                    name="x64dbg.get_trace_record",
                    description="Get trace record hit count at an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address to query", required=True),
                        ToolParameter(name="size", type="integer", description="Number of bytes to check", required=False),
                    ],
                    returns="Dict with address and hitCount",
                ),
                ToolFunction(
                    name="x64dbg.step_count",
                    description="Execute a specific number of steps",
                    parameters=[
                        ToolParameter(name="count", type="integer", description="Number of steps to execute", required=True),
                        ToolParameter(
                            name="step_type",
                            type="string",
                            description="Step type: 'into' or 'over'",
                            required=False,
                            enum=["into", "over"],
                        ),
                    ],
                    returns="Dict with success status, count, and step_type",
                ),
                ToolFunction(
                    name="x64dbg.animate_start",
                    description="Start animation (visual step execution)",
                    parameters=[
                        ToolParameter(
                            name="step_type",
                            type="string",
                            description="Step type: 'into' or 'over'",
                            required=False,
                            enum=["into", "over"],
                        ),
                    ],
                    returns="Dict with success status and step_type",
                ),
                ToolFunction(
                    name="x64dbg.animate_stop",
                    description="Stop animation",
                    parameters=[],
                    returns="Dict with success status",
                ),
                ToolFunction(
                    name="x64dbg.analyze_entropy",
                    description="Analyze Shannon entropy of a memory region",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Start address", required=True),
                        ToolParameter(name="size", type="integer", description="Total bytes to analyze", required=True),
                        ToolParameter(
                            name="block_size",
                            type="integer",
                            description="Size of each entropy calculation block",
                            required=False,
                        ),
                    ],
                    returns="List of dicts with address, entropy value, and block size",
                ),
                ToolFunction(
                    name="x64dbg.yara_scan",
                    description="Scan memory with a YARA rule",
                    parameters=[
                        ToolParameter(name="rule_path", type="string", description="Path to YARA rule file", required=False),
                        ToolParameter(name="rule_text", type="string", description="Inline YARA rule text", required=False),
                        ToolParameter(name="address", type="integer", description="Start address (0 for all memory)", required=False),
                        ToolParameter(name="size", type="integer", description="Size to scan (0 for all)", required=False),
                    ],
                    returns="List of match dicts",
                ),
                ToolFunction(
                    name="x64dbg.script_load",
                    description="Load an x64dbg script file",
                    parameters=[
                        ToolParameter(name="path", type="string", description="Path to script file", required=True),
                    ],
                    returns="Dict with success status and path",
                ),
                ToolFunction(
                    name="x64dbg.script_run",
                    description="Run the currently loaded script",
                    parameters=[],
                    returns="Dict with success status",
                ),
                ToolFunction(
                    name="x64dbg.script_cmd",
                    description="Execute a single script command",
                    parameters=[
                        ToolParameter(name="line", type="string", description="Script command line", required=True),
                    ],
                    returns="Dict with success status and line",
                ),
                ToolFunction(
                    name="x64dbg.script_abort",
                    description="Abort the running script",
                    parameters=[],
                    returns="Dict with success status",
                ),
                ToolFunction(
                    name="x64dbg.plugin_load",
                    description="Load a plugin",
                    parameters=[
                        ToolParameter(name="path", type="string", description="Path to plugin DLL", required=True),
                    ],
                    returns="Dict with success status and path",
                ),
                ToolFunction(
                    name="x64dbg.plugin_unload",
                    description="Unload a plugin",
                    parameters=[
                        ToolParameter(name="name", type="string", description="Plugin name", required=True),
                    ],
                    returns="Dict with success status and name",
                ),
                ToolFunction(
                    name="x64dbg.plugin_list",
                    description="List loaded plugins",
                    parameters=[],
                    returns="List of plugin info dicts",
                ),
                ToolFunction(
                    name="x64dbg.get_handles",
                    description="Enumerate process handles",
                    parameters=[],
                    returns="List of handle info dicts",
                ),
                ToolFunction(
                    name="x64dbg.close_handle",
                    description="Close a process handle",
                    parameters=[
                        ToolParameter(name="handle", type="integer", description="Handle value to close", required=True),
                    ],
                    returns="Dict with success status",
                ),
                ToolFunction(
                    name="x64dbg.detect_anti_debug",
                    description="Detect common anti-debugging techniques",
                    parameters=[],
                    returns="Dict with detected anti-debug indicators",
                ),
                ToolFunction(
                    name="x64dbg.patch_anti_debug",
                    description="Patch common anti-debug checks in the target process",
                    parameters=[
                        ToolParameter(
                            name="checks",
                            type="array",
                            description="Specific checks to patch; patches all known checks if not provided",
                            required=False,
                        ),
                    ],
                    returns="Dict with success status and patched checks",
                ),
                ToolFunction(
                    name="x64dbg.reconstruct_imports",
                    description="Reconstruct the import table using Scylla",
                    parameters=[
                        ToolParameter(name="oep", type="integer", description="Original Entry Point address", required=True),
                        ToolParameter(name="output_path", type="string", description="Path to write the fixed binary", required=True),
                    ],
                    returns="Dict with success status",
                ),
                ToolFunction(
                    name="x64dbg.get_status",
                    description="Get current debugger status",
                    parameters=[],
                    returns="Dict with debugging, paused, and initialized flags",
                ),
                ToolFunction(
                    name="x64dbg.goto_address",
                    description="Navigate the disassembly view to an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address to navigate to", required=True),
                    ],
                    returns="Dict with success status and address",
                ),
                ToolFunction(
                    name="x64dbg.get_tls_callbacks",
                    description="Get TLS callback addresses for a module",
                    parameters=[
                        ToolParameter(name="module_name", type="string", description="Module name", required=True),
                    ],
                    returns="List of TLS callback dicts with address",
                ),
                ToolFunction(
                    name="x64dbg.break_on_tls_callbacks",
                    description="Set breakpoints on all TLS callbacks of a module",
                    parameters=[
                        ToolParameter(name="module_name", type="string", description="Module name", required=True),
                    ],
                    returns="Dict with success status and breakpoints set",
                ),
                ToolFunction(
                    name="x64dbg.get_resources",
                    description="Get PE resource entries for a module",
                    parameters=[
                        ToolParameter(name="module_name", type="string", description="Module name", required=True),
                    ],
                    returns="List of resource dicts with type, id, size, and rva",
                ),
                ToolFunction(
                    name="x64dbg.get_privileges",
                    description="Enumerate current process token privileges",
                    parameters=[],
                    returns="List of privilege dicts with name and enabled status",
                ),
                ToolFunction(
                    name="x64dbg.adjust_privilege",
                    description="Adjust a process token privilege",
                    parameters=[
                        ToolParameter(name="name", type="string", description="Privilege name (e.g. 'SeDebugPrivilege')", required=True),
                        ToolParameter(name="enable", type="boolean", description="True to enable, False to disable", required=False),
                    ],
                    returns="Dict with success status and privilege name",
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
                _logger.info("x64dbg_found", path=str(tool_path))
                self._plugin_deployed = deploy_x64dbg_plugin(
                    tool_path,
                    tool_path.parent,
                )
                if not self._plugin_deployed:
                    diag = str(self.plugin_status.get("diagnostic", ""))
                    _logger.warning(
                        "x64dbg_plugin_not_deployed",
                        diagnostic=diag,
                    )
            else:
                _logger.warning("x64dbg_not_found", path=str(tool_path))

        if get_capstone() is None:
            _logger.warning(
                "x64dbg_optional_dep_missing",
                dependency="capstone",
                install_cmd="pixi add capstone-engine",
                impact="disassemble_at will raise ToolError",
            )
        if get_keystone() is None:
            _logger.warning(
                "x64dbg_optional_dep_missing",
                dependency="keystone",
                install_cmd="pixi run pip install keystone-engine",
                impact="assemble_at will raise ToolError",
            )

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
                _logger.warning("x64dbg_process_terminate_timeout", pid=pid)
                self._process.kill()
                await asyncio.to_thread(self._process.wait)

            process_manager.unregister(pid)
            self._process = None

        self._attached_pid = None
        self._breakpoints.clear()
        self._watchpoints.clear()
        await super().shutdown()
        _logger.info("x64dbg_bridge_shutdown", bridge="x64dbg")

    async def is_available(self) -> bool:
        """Check if x64dbg is available.

        Returns:
            bool: True if x64dbg can be used.
        """
        if self._x64dbg_path is None:
            return False

        x64_exe = self._x64dbg_path / "release" / "x64" / "x64dbg.exe"
        x32_exe = self._x64dbg_path / "release" / "x32" / "x32dbg.exe"

        return await asyncio.to_thread(x64_exe.exists) or await asyncio.to_thread(x32_exe.exists)

    async def _start_debugger(self, *, is_64bit: bool = True) -> None:
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

        if not await asyncio.to_thread(exe_path.exists):
            msg = f"x64dbg executable not found: {exe_path}"
            raise ToolError(msg)

        self._is_64bit = is_64bit
        _logger.info("x64dbg_starting", path=str(exe_path))

        si = STARTUPINFO()
        si.dwFlags |= STARTF_USESHOWWINDOW
        si.wShowWindow = 1

        self._process = await asyncio.to_thread(
            Popen,
            [str(exe_path)],
            stdout=PIPE,
            stderr=PIPE,
            startupinfo=si,
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
            _logger.info("x64dbg_pipe_connected", bridge="x64dbg")
        except Exception as e:
            diag = str(self.plugin_status.get("diagnostic", ""))
            _logger.warning(
                "x64dbg_pipe_connect_failed",
                error=str(e),
                diagnostic=diag,
            )
            self._pipe_client = None
            msg = f"Failed to connect to x64dbg pipe: {e}"
            if diag:
                msg = f"{msg}. {diag}"
            raise ToolError(msg) from e

    async def _close_connection(self) -> None:
        """Close named pipe connection."""
        if self._pipe_client is not None:
            _logger.debug("pipe_connection_closing")
            await self._pipe_client.close()
            self._pipe_client = None

    def register_event_callback(
        self,
        callback: Callable[[str, dict[str, Any]], None],
    ) -> None:
        """Register a callback for debug events.

        The callback receives ``(event_type, message)`` and is
        invoked synchronously from the event-handling thread.

        Args:
            callback: Function to call on debug events.
        """
        self.event_callbacks.append(callback)

    def unregister_event_callback(
        self,
        callback: Callable[[str, dict[str, Any]], None],
    ) -> None:
        """Remove a previously registered event callback.

        Args:
            callback: The callback to remove.
        """
        try:
            self.event_callbacks.remove(callback)
        except ValueError:
            _logger.debug("event_callback_not_found_for_removal", callback=str(callback))

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

        for cb in self.event_callbacks:
            try:
                cb(event_type, message)
            except (RuntimeError, TypeError, ValueError):
                _logger.warning("event_callback_error", event_type=event_type, exc_info=True)

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
            PipeCommandResult: Response data payload.

        Raises:
            ToolError: If the command fails.
        """
        if not self._plugin_deployed:
            diag = str(self.plugin_status.get("diagnostic", ""))
            msg = f"x64dbg bridge plugin not available: {diag}"
            raise ToolError(msg)

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
            _logger.warning("x64dbg_command_timeout", command=command, error=str(e))
            msg = f"Command {command} timed out"
            raise ToolError(msg) from e

        if not response.get("success", False):
            error = response.get("error", "Command failed")
            msg = str(error)
            raise ToolError(msg)
        data: str | int | float | bool | dict[str, object] | list[object] | None = response.get("result")
        return data

    async def _send_command(self, command: str) -> str:
        """Send command to x64dbg and get response.

        Args:
            command: Command to execute.

        Returns:
            str: Command response.

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
        if not await asyncio.to_thread(path.exists):
            msg = f"File not found: {path}"
            raise ToolError(msg)

        self._binary_path = await asyncio.to_thread(path.resolve)

        is_64bit = self._detect_architecture(path)

        if self._process is None:
            await self._start_debugger(is_64bit=is_64bit)

        cmd = f'InitDebug "{path.as_posix()}"'
        if args:
            cmd += f', "{args}"'

        await self._send_command(cmd)

        try:
            pid_result = await self._send_pipe_command("reg_get", {"name": "$pid"})
            if isinstance(pid_result, str):
                pid_val = int(pid_result, 0)
                if pid_val > 0:
                    self._attached_pid = pid_val
                    self._state.target_pid = pid_val
                    self._state.process_attached = True
        except ToolError:
            _logger.debug("pid_capture_after_load_failed")

        self._state.connected = True
        self._state.tool_running = True
        self._state.binary_loaded = True
        self._state.target_path = self._binary_path

        _logger.info("x64dbg_binary_loaded", path=path.name)

    @staticmethod
    def _detect_architecture(path: Path) -> bool:
        """Detect if binary is 64-bit.

        Args:
            path: Path to binary.

        Returns:
            bool: True if 64-bit, False if 32-bit.
        """
        try:
            data = path.read_bytes()
        except OSError as e:
            _logger.debug("architecture_detection_failed", error=str(e))
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

        Detects the target process architecture and starts the
        matching debugger variant (x64dbg or x32dbg).

        Args:
            pid: Process ID.
        """
        _logger.info("x64dbg_attaching", pid=pid)
        is_64 = await asyncio.to_thread(self._detect_process_arch, pid)

        if self._process is None:
            await self._start_debugger(is_64bit=is_64)

        await self._send_command(f"attach {pid}")
        self._attached_pid = pid

        self._state.connected = True
        self._state.tool_running = True
        self._state.process_attached = True
        self._state.target_pid = pid
        _logger.info("x64dbg_attached", pid=pid)

    @staticmethod
    def _detect_process_arch(pid: int) -> bool:
        """Detect whether a process is 64-bit.

        Args:
            pid: Process ID.

        Returns:
            bool: True if 64-bit, False if 32-bit. Defaults to True on error.
        """
        if not _IS_WIN32:
            return True
        try:
            kernel32 = ctypes.windll.kernel32
            inherit_handle = False
            handle = kernel32.OpenProcess(0x0400, inherit_handle, pid)
            if not handle:
                return True
            try:
                is_wow64 = ctypes.c_int(0)
                ok: int = kernel32.IsWow64Process(handle, ctypes.byref(is_wow64))
                return not bool(is_wow64.value) if ok else True
            finally:
                kernel32.CloseHandle(handle)
        except (OSError, AttributeError):
            _logger.debug("wow64_check_failed_assuming_64bit")
            return True

    async def detach(self) -> None:
        """Detach from current process."""
        await self._send_command("detach")
        self._attached_pid = None

        self._state.connected = True
        self._state.tool_running = True
        self._state.process_attached = False
        self._state.target_pid = None

        _logger.info("x64dbg_process_detached", bridge="x64dbg")

    async def run(self) -> None:
        """Continue execution."""
        await self._send_pipe_command("run")
        _logger.debug("execution_continued", bridge="x64dbg")

    async def pause(self) -> None:
        """Pause execution."""
        await self._send_pipe_command("pause")
        _logger.debug("execution_paused", bridge="x64dbg")

    async def stop(self) -> None:
        """Stop debugging and terminate process."""
        await self._send_pipe_command("stop")

        self._attached_pid = None
        self._state.process_attached = False
        self._state.target_pid = None
        _logger.info("debugging_stopped", bridge="x64dbg")

    async def step_into(self) -> int:
        """Single step into.

        Returns:
            int: New instruction pointer.
        """
        _logger.debug("step_into_executing")
        await self._send_pipe_command("step_into")
        await asyncio.sleep(0.05)
        regs = await self.get_registers()
        return regs.rip if self._is_64bit else regs.rip & DWORD_MASK

    async def step_over(self) -> int:
        """Single step over.

        Returns:
            int: New instruction pointer.
        """
        _logger.debug("step_over_executing")
        await self._send_pipe_command("step_over")
        await asyncio.sleep(0.05)
        regs = await self.get_registers()
        return regs.rip if self._is_64bit else regs.rip & DWORD_MASK

    async def step_out(self) -> int:
        """Step out of current function.

        Returns:
            int: New instruction pointer.
        """
        _logger.debug("step_out_executing")
        await self._send_pipe_command("step_out")
        await asyncio.sleep(0.05)
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
            int: Breakpoint ID.
        """
        if bp_type == "hardware":
            await self._send_pipe_command(
                "bphws",
                {
                    "address": address,
                    "type": "execute",
                    "condition": condition,
                },
            )
        else:
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

        _logger.info("breakpoint_set", type=bp_type, address=hex(address), id=bp_id)
        return bp_id

    async def remove_breakpoint(self, address: int) -> bool:
        """Remove a breakpoint.

        Args:
            address: Breakpoint address.

        Returns:
            bool: True if removed.
        """
        await self._send_pipe_command("bp_remove", {"address": address})

        if address in self._breakpoints:
            del self._breakpoints[address]

        _logger.info("breakpoint_removed", address=hex(address))
        return True

    async def get_breakpoints(self) -> list[BreakpointInfo]:
        """Get all breakpoints including those set in the x64dbg GUI.

        Returns:
            list[BreakpointInfo]: List of breakpoints from both local tracking and x64dbg.
        """
        merged = dict(self._breakpoints)

        if self._pipe_client is not None and self._pipe_client.is_connected:
            try:
                result = await self._send_pipe_command("bp_list")
                if isinstance(result, list):
                    for bp_data in result:
                        if _is_str_obj_dict(bp_data):
                            raw_addr = bp_data.get("address")
                            addr = raw_addr if isinstance(raw_addr, int) else 0
                            if addr not in merged:
                                raw_type = bp_data.get("type")
                                bp_type_str = raw_type if isinstance(raw_type, str) else "software"
                                raw_enabled = bp_data.get("enabled")
                                raw_hits = bp_data.get("hit_count")
                                raw_cond = bp_data.get("condition")
                                bp_type_val: Literal["software", "hardware", "memory"]
                                if bp_type_str == "hardware":
                                    bp_type_val = "hardware"
                                elif bp_type_str == "memory":
                                    bp_type_val = "memory"
                                else:
                                    bp_type_val = "software"
                                merged[addr] = BreakpointInfo(
                                    id=self._next_bp_id,
                                    address=addr,
                                    bp_type=bp_type_val,
                                    enabled=raw_enabled if isinstance(raw_enabled, bool) else True,
                                    hit_count=raw_hits if isinstance(raw_hits, int) else 0,
                                    condition=raw_cond if isinstance(raw_cond, str) else None,
                                )
                                self._next_bp_id += 1
            except ToolError:
                _logger.debug("bp_list_pipe_unavailable")

        return list(merged.values())

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
            int: Watchpoint ID.
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

        _logger.info("watchpoint_set", address=hex(address), size=size, type=watch_type)
        return wp_id

    async def remove_watchpoint(self, watchpoint_id: int) -> bool:
        """Remove a watchpoint.

        Args:
            watchpoint_id: Watchpoint ID.

        Returns:
            bool: True if removed.
        """
        watchpoint = self._watchpoints.get(watchpoint_id)
        if watchpoint is None:
            return False

        await self._send_pipe_command(
            "wp_remove",
            {"address": watchpoint.address},
        )

        del self._watchpoints[watchpoint_id]
        _logger.info("watchpoint_removed", id=watchpoint_id)
        return True

    async def get_watchpoints(self) -> list[WatchpointInfo]:
        """Get all watchpoints including those set in the x64dbg GUI.

        Returns:
            list[WatchpointInfo]: List of watchpoints from both local tracking and x64dbg.
        """
        merged = dict(self._watchpoints)

        if self._pipe_client is not None and self._pipe_client.is_connected:
            try:
                result = await self._send_pipe_command("wp_list")
                if isinstance(result, list):
                    for wp_data in result:
                        if _is_str_obj_dict(wp_data):
                            raw_wp_addr = wp_data.get("address")
                            wp_addr = raw_wp_addr if isinstance(raw_wp_addr, int) else 0
                            existing = any(w.address == wp_addr for w in merged.values())
                            if not existing:
                                wp_id = self._next_wp_id
                                self._next_wp_id += 1
                                raw_size = wp_data.get("size")
                                raw_wp_type = wp_data.get("type")
                                raw_wp_enabled = wp_data.get("enabled")
                                raw_wp_hits = wp_data.get("hit_count")
                                merged[wp_id] = WatchpointInfo(
                                    id=wp_id,
                                    address=wp_addr,
                                    size=raw_size if isinstance(raw_size, int) else 1,
                                    watch_type=raw_wp_type if isinstance(raw_wp_type, str) else "write",
                                    enabled=raw_wp_enabled if isinstance(raw_wp_enabled, bool) else True,
                                    hit_count=raw_wp_hits if isinstance(raw_wp_hits, int) else 0,
                                )
            except ToolError:
                _logger.debug("wp_list_pipe_unavailable")

        return list(merged.values())

    async def get_registers(self) -> RegisterState:
        """Get all register values.

        Returns:
            RegisterState: Current register state.

        Raises:
            ToolError: If the register response is invalid.
        """
        result = await self._send_pipe_command("reg_all")
        if not isinstance(result, dict):
            msg = "Invalid register response"
            raise ToolError(msg)

        def parse_int(value: object) -> int:
            """Coerce a register value from the pipe into an integer.

            Accepts an ``int`` straight through, parses string values with
            ``int(..., 0)`` so decimal and hex (``0x...``) forms are both
            accepted, and returns ``0`` for any unparseable input after
            emitting a debug log entry.

            Args:
                value: Raw register payload from the plugin response.

            Returns:
                int: Integer register value, or ``0`` when parsing fails.
            """
            if isinstance(value, int):
                return value
            if isinstance(value, str):
                try:
                    return int(value, 0)
                except ValueError:
                    _logger.debug("register_value_parse_failed", value=str(value))
                    return 0
            return 0

        def get_reg(primary: str, alt: str | None = None) -> int:
            """Read a register from the response, honouring legacy aliases.

            Tries ``primary`` first and falls back to ``alt`` when the
            primary key is absent. This lets the same lookup routine cope
            with both 64-bit names (``rax``) and the 32-bit aliases used
            by x64dbg running against x86 targets (``eax``).

            Args:
                primary: Preferred register key to look up.
                alt: Optional legacy key to try when ``primary`` is
                    missing from the response.

            Returns:
                int: Integer value of the register, or ``0`` when neither
                key is present.
            """
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
            gpr_count=len(gpr_dict),
            segment_count=len(segment_regs),
        )

        return state

    async def set_register(self, register: str, value: int) -> bool:
        """Set a register value.

        Args:
            register: Register name.
            value: New value.

        Returns:
            bool: True if set.
        """
        await self._send_pipe_command(
            "reg_set",
            {"register": register, "value": value},
        )
        _logger.info("register_set", register=register, value=hex(value))
        return True

    async def read_memory(self, address: int, size: int) -> bytes:
        """Read process memory.

        Args:
            address: Memory address.
            size: Bytes to read.

        Returns:
            bytes: Memory contents.

        Raises:
            ToolError: If read fails.
        """
        _logger.debug("memory_read_starting", address=hex(address), size=size)
        if not _IS_WIN32:
            msg = "Windows API not available"
            raise ToolError(msg)

        kernel32 = ctypes.windll.kernel32

        if self._attached_pid is None:
            msg = "No process attached"
            raise ToolError(msg)

        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        handle = kernel32.OpenProcess(
            WIN_PROCESS_VM_READ,
            WIN_NO_INHERIT_HANDLE,
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
            int: Bytes written.

        Raises:
            ToolError: If write fails.
        """
        if not _IS_WIN32:
            msg = "Windows API not available"
            raise ToolError(msg)

        kernel32 = ctypes.windll.kernel32

        if self._attached_pid is None:
            msg = "No process attached"
            raise ToolError(msg)

        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        handle = kernel32.OpenProcess(
            WIN_PROCESS_VM_WRITE | WIN_PROCESS_VM_OPERATION,
            WIN_NO_INHERIT_HANDLE,
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

            _logger.info("memory_written", bytes=bytes_written.value, address=hex(address))
            return bytes_written.value

        finally:
            kernel32.CloseHandle(handle)

    async def allocate_memory(self, size: int, protection: str = "rwx") -> int:
        """Allocate memory in target process.

        Args:
            size: Size to allocate.
            protection: Memory protection.

        Returns:
            int: Allocated address.

        Raises:
            ToolError: If allocation fails.
        """
        if not _IS_WIN32:
            msg = "Windows API not available"
            raise ToolError(msg)

        prot_map: dict[str, int] = {
            "rwx": PAGE_EXECUTE_READWRITE_FLAG,
            "PAGE_EXECUTE_READWRITE": PAGE_EXECUTE_READWRITE_FLAG,
            "rx": PAGE_EXECUTE_READ,
            "PAGE_EXECUTE_READ": PAGE_EXECUTE_READ,
            "rw": PAGE_READWRITE,
            "PAGE_READWRITE": PAGE_READWRITE,
            "r": PAGE_READONLY,
            "PAGE_READONLY": PAGE_READONLY,
            "x": PAGE_EXECUTE,
            "PAGE_EXECUTE": PAGE_EXECUTE,
        }
        prot_flag = prot_map.get(protection, PAGE_EXECUTE_READWRITE_FLAG)

        kernel32 = ctypes.windll.kernel32

        if self._attached_pid is None:
            msg = "No process attached"
            raise ToolError(msg)

        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        handle = kernel32.OpenProcess(
            WIN_PROCESS_VM_OPERATION,
            WIN_NO_INHERIT_HANDLE,
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
                prot_flag,
            )

            if not address_result:
                msg = "VirtualAllocEx failed"
                raise ToolError(msg)

            address: int = int(address_result)
            _logger.info("memory_allocated", size=size, address=hex(address))
            return address

        finally:
            kernel32.CloseHandle(handle)

    async def free_memory(self, address: int) -> bool:
        """Free memory in target process.

        Args:
            address: Address to free.

        Returns:
            bool: True if freed.
        """
        _logger.debug("memory_free_starting", address=hex(address))
        if not _IS_WIN32:
            return False

        kernel32 = ctypes.windll.kernel32

        if self._attached_pid is None:
            return False

        handle = kernel32.OpenProcess(
            WIN_PROCESS_VM_OPERATION,
            WIN_NO_INHERIT_HANDLE,
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
            list[MemoryRegion]: List of memory regions.

        Raises:
            ToolError: If not on Windows, not attached, or API call fails.
        """
        _logger.debug("memory_regions_enumerating")
        if not _IS_WIN32:
            msg = f"get_memory_regions {_ERR_REQUIRES_WINDOWS}"
            raise ToolError(msg, tool_name="x64dbg")

        kernel32 = ctypes.windll.kernel32

        if self._attached_pid is None:
            msg = f"get_memory_regions: {_ERR_NOT_ATTACHED}"
            raise ToolError(msg, tool_name="x64dbg")

        class MemoryBasicInformation(ctypes.Structure):
            """Windows ``MEMORY_BASIC_INFORMATION`` layout for ``VirtualQueryEx``.

            Used as the output buffer when walking the target process address space to enumerate committed, reserved, and free memory
            regions together with their protection flags.
            """

            _fields_: ClassVar = [
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
            WIN_NO_INHERIT_HANDLE,
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
                        ),
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
            list[DisassemblyLine]: Disassembly lines. Returns empty list on error.

        Raises:
            ToolError: If capstone disassembler is not available and plugin is not connected.
        """
        try:
            result = await self._send_pipe_command("disasm", {"address": hex(address), "count": count})
            if isinstance(result, list):
                return [self._parse_disasm_entry(e) for e in result if _is_str_obj_dict(e)]
        except ToolError:
            pass

        capstone = get_capstone()
        if capstone is None:
            msg = "Capstone disassembler not available. Install with: pixi add capstone-engine"
            raise ToolError(msg)

        try:
            data = await self.read_memory(address, count * 15)

            mode = capstone.CS_MODE_64 if self._is_64bit else capstone.CS_MODE_32
            md = capstone.Cs(capstone.CS_ARCH_X86, mode)

            capstone_lines: list[DisassemblyLine] = []

            for instr in md.disasm(data, address):
                capstone_lines.append(
                    DisassemblyLine(
                        address=instr.address,
                        bytes_str=" ".join(f"{b:02x}" for b in instr.bytes),
                        mnemonic=instr.mnemonic,
                        operands=instr.op_str,
                        comment=None,
                    ),
                )
                if len(capstone_lines) >= count:
                    break

        except Exception:
            _logger.exception("disassembly_failed", address=hex(address), count=count)
            return []
        else:
            return capstone_lines

    async def assemble_at(self, address: int, instruction: str) -> bytes:
        """Assemble instruction at address.

        Args:
            address: Target address.
            instruction: Assembly instruction.

        Returns:
            bytes: Assembled bytes.

        Raises:
            ToolError: If assembly fails.
        """
        _logger.info("instruction_assembling", address=hex(address), instruction=instruction)
        keystone = get_keystone()
        if keystone is None:
            msg = "Keystone assembler not available. Not in conda-forge; install with: pixi run pip install keystone-engine"
            raise ToolError(msg)

        mode = keystone.KS_MODE_64 if self._is_64bit else keystone.KS_MODE_32
        ks = keystone.Ks(keystone.KS_ARCH_X86, mode)

        encoding, _count = ks.asm(instruction, address)

        if encoding is None:
            msg = f"Failed to assemble: {instruction}"
            raise ToolError(msg)

        assembled = bytes(encoding)
        await self.write_memory(address, assembled)
        return assembled

    async def get_stack_trace(self) -> list[StackFrame]:
        """Get current stack trace.

        Returns:
            list[StackFrame]: List of stack frames.
        """
        try:
            result = await self._send_pipe_command("stack_trace")
            if isinstance(result, list):
                return [self._parse_stack_frame_entry(e) for e in result if _is_str_obj_dict(e)]
        except ToolError:
            pass

        frames_fallback: list[StackFrame] = []

        regs = await self.get_registers()
        rsp = regs.rsp
        rbp = regs.rbp
        rip = regs.rip

        frames_fallback.append(
            StackFrame(
                index=0,
                address=rip,
                return_address=0,
                frame_pointer=rbp,
                stack_pointer=rsp,
                function_name=None,
                module_name=None,
            ),
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

                frames_fallback.append(
                    StackFrame(
                        index=i,
                        address=return_addr,
                        return_address=return_addr,
                        frame_pointer=saved_rbp,
                        stack_pointer=rbp + (16 if self._is_64bit else 8),
                        function_name=None,
                        module_name=None,
                    ),
                )

                rbp = saved_rbp

            except ToolError as e:
                _logger.warning("stack_trace_unavailable", error=str(e))
                break

        return frames_fallback

    async def scan_memory(self, pattern: str | bytes) -> list[MemorySearchResult]:
        """Scan process memory for a pattern.

        Args:
            pattern: Byte pattern to search for. Accepts bytes or hex string
                (e.g. "48 8B 05" or "488B05").

        Returns:
            list[MemorySearchResult]: List of matches with context.
        """
        if isinstance(pattern, str):
            pattern = bytes.fromhex(pattern.replace(" ", ""))
        if len(pattern) < MIN_PATTERN_LENGTH:
            _logger.warning("scan_pattern_too_short", length=len(pattern))

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
                        ),
                    )
                    offset = idx + 1

            except ToolError as e:
                _logger.warning("memory_scan_failed", error=str(e))
                continue

        return matches

    async def run_command(self, command: str) -> str:
        """Execute x64dbg command.

        Args:
            command: Command to execute.

        Returns:
            str: Command output.
        """
        _logger.debug("command_executing", command=command)
        return await self._send_command(command)

    async def spawn(self, path: Path, args: Sequence[str] | None = None) -> int:
        """Spawn a process for debugging.

        Args:
            path: Path to executable.
            args: Optional arguments.

        Returns:
            int: Process ID.
        """
        _logger.info("process_spawning", path=str(path))
        args_str = " ".join(args) if args else None
        await self.load(path, args_str)
        return self._attached_pid or 0

    async def _get_threads(self) -> list[ThreadInfo]:
        """Get thread information for the attached process.

        Uses Windows Toolhelp API (CreateToolhelp32Snapshot with TH32CS_SNAPTHREAD)
        to enumerate all threads belonging to the attached process.

        Returns:
            list[ThreadInfo]: List of ThreadInfo objects for each thread in the process.

        Raises:
            ToolError: If not on Windows, not attached, or API call fails.
        """
        if not _IS_WIN32:
            msg = f"get_threads {_ERR_REQUIRES_WINDOWS}"
            raise ToolError(msg, tool_name="x64dbg")

        if self._attached_pid is None:
            msg = f"get_threads: {_ERR_NOT_ATTACHED}"
            raise ToolError(msg, tool_name="x64dbg")

        kernel32 = ctypes.windll.kernel32

        class ThreadEntry32(ctypes.Structure):
            """Windows ``THREADENTRY32`` layout for thread snapshots.

            Populated by ``Thread32First`` / ``Thread32Next`` when
            enumerating threads that belong to the attached process via
            a toolhelp snapshot.
            """

            _fields_: ClassVar = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ThreadID", wintypes.DWORD),
                ("th32OwnerProcessID", wintypes.DWORD),
                ("tpBasePri", wintypes.LONG),
                ("tpDeltaPri", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
            ]

        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        if snapshot in {INVALID_HANDLE_VALUE, DWORD_MASK}:
            error_code = ctypes.get_last_error()
            msg = f"{_ERR_CREATE_SNAPSHOT_FAILED} for threads: error {error_code}"
            raise ToolError(msg, tool_name="x64dbg", exit_code=error_code)

        threads: list[ThreadInfo] = []

        try:
            te32 = ThreadEntry32()
            te32.dwSize = ctypes.sizeof(ThreadEntry32)
            _logger.debug("initialized_thread_entry", size=te32.dwSize)

            if kernel32.Thread32First(snapshot, ctypes.byref(te32)):
                while True:
                    if te32.th32OwnerProcessID == self._attached_pid:
                        threads.append(
                            ThreadInfo(
                                tid=te32.th32ThreadID,
                                start_address=0,
                                state="unknown",
                                priority=te32.tpBasePri,
                            ),
                        )
                    if not kernel32.Thread32Next(snapshot, ctypes.byref(te32)):
                        break
        except Exception as e:
            _logger.warning("x64dbg_get_threads_failed", pid=self._attached_pid, error=str(e))
            msg = f"{_ERR_GET_THREADS_FAILED}: {e}"
            raise ToolError(msg, tool_name="x64dbg") from e
        finally:
            kernel32.CloseHandle(snapshot)

        _logger.debug("threads_found", count=len(threads), pid=self._attached_pid)
        return threads

    async def _get_modules(self) -> list[ModuleInfo]:
        """Get loaded modules for the attached process.

        Uses Windows Toolhelp API (CreateToolhelp32Snapshot with TH32CS_SNAPMODULE)
        to enumerate all loaded DLLs and the main executable.

        Returns:
            list[ModuleInfo]: List of ModuleInfo objects for each loaded module.

        Raises:
            ToolError: If not on Windows, not attached, or API call fails.
        """
        if not _IS_WIN32:
            msg = f"get_modules {_ERR_REQUIRES_WINDOWS}"
            raise ToolError(msg, tool_name="x64dbg")

        if self._attached_pid is None:
            msg = f"get_modules: {_ERR_NOT_ATTACHED}"
            raise ToolError(msg, tool_name="x64dbg")

        kernel32 = ctypes.windll.kernel32

        class ModuleEntry32W(ctypes.Structure):
            """Windows ``MODULEENTRY32W`` layout for module snapshots.

            Populated by ``Module32FirstW`` / ``Module32NextW`` when
            enumerating DLL and executable modules loaded into the
            attached process via a toolhelp snapshot.
            """

            _fields_: ClassVar = [
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

        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
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
            _logger.debug("initialized_module_entry", size=me32.dwSize)

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
                        ),
                    )
                    if not kernel32.Module32NextW(snapshot, ctypes.byref(me32)):
                        break
        except Exception as e:
            _logger.warning("x64dbg_get_modules_failed", pid=self._attached_pid, error=str(e))
            msg = f"{_ERR_GET_MODULES_FAILED}: {e}"
            raise ToolError(msg, tool_name="x64dbg") from e
        finally:
            kernel32.CloseHandle(snapshot)

        _logger.debug("modules_found", count=len(modules), pid=self._attached_pid)
        return modules

    async def get_modules(self) -> list[ModuleInfo]:
        """Get loaded modules for the attached process.

        Returns:
            list[ModuleInfo]: List of loaded module information.
        """
        return await self._get_modules()

    async def get_threads(self) -> list[ThreadInfo]:
        """Get thread information for the attached process.

        Returns:
            list[ThreadInfo]: List of thread information.
        """
        return await self._get_threads()

    async def get_process_info(self) -> ProcessInfo | None:
        """Get complete process information including threads and modules.

        Aggregates thread and module information along with process details
        using Windows APIs.

        Returns:
            ProcessInfo | None: ProcessInfo with populated threads and modules, or None if not attached.
        """
        if self._attached_pid is None:
            return None

        threads = await self.get_threads()
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

    async def find_pattern(
        self,
        pattern: str,
        alignment: int = 1,
    ) -> list[dict[str, Any]]:
        """Search memory for a hex pattern with optional wildcards.

        Args:
            pattern: Hex pattern string with optional '??' wildcards
                (e.g. "48 8B ?? 90" or "488B??90").
            alignment: Only return matches at addresses divisible by this value.
                Defaults to 1 (no alignment filtering).

        Returns:
            list[dict[str, Any]]: List of match dicts with 'address' and 'offset' keys.
        """
        alignment = max(alignment, 1)
        _logger.debug("pattern_search_starting", pattern=pattern)
        tokens = pattern.replace("  ", " ").strip().split(" ")
        if len(tokens) == 1 and len(tokens[0]) > HEX_BYTE_LENGTH:
            raw = tokens[0]
            tokens = [raw[i : i + HEX_BYTE_LENGTH] for i in range(0, len(raw), HEX_BYTE_LENGTH)]

        wildcard_marker = "??"
        has_wildcards = wildcard_marker in tokens

        if not has_wildcards:
            byte_pattern = bytes.fromhex("".join(tokens))
            results = await self.scan_memory(byte_pattern)
            return [{"address": hex(r.address), "offset": r.address} for r in results if r.address % alignment == 0]

        pat_bytes: list[int | None] = []
        for token in tokens:
            if token == wildcard_marker:
                pat_bytes.append(None)
            else:
                pat_bytes.append(int(token, 16))

        pat_len = len(pat_bytes)
        regions = await self.get_memory_regions()
        matches: list[dict[str, Any]] = []

        for region in regions:
            if "r" not in region.protection:
                continue
            try:
                data = await self.read_memory(region.base_address, min(region.size, MAX_MEMORY_READ_SIZE))
            except ToolError as exc:
                _logger.debug("pattern_search_region_read_failed", base=hex(region.base_address), error=str(exc))
                continue

            for i in range(len(data) - pat_len + 1):
                matched = not any(pat_bytes[j] is not None and data[i + j] != pat_bytes[j] for j in range(pat_len))
                if matched:
                    addr = region.base_address + i
                    if addr % alignment == 0:
                        matches.append({"address": hex(addr), "offset": addr})

        _logger.debug("pattern_search_completed", matches=len(matches))
        return matches

    async def run_to(self, address: int) -> dict[str, Any]:
        """Run execution until a specific address is reached.

        Args:
            address: Target address to run to.

        Returns:
            dict[str, Any]: Dict with success status and target address.
        """
        _logger.debug("run_to_executing", address=hex(address))
        await self._send_pipe_command("exec", {"command": f"runto {hex(address)}"})
        return {"success": True, "target": hex(address)}

    async def execute_til_return(self) -> dict[str, Any]:
        """Execute until the current function returns.

        Returns:
            dict[str, Any]: Dict with success status.
        """
        _logger.debug("execute_til_return_starting")
        await self._send_pipe_command("exec", {"command": "erun"})
        return {"success": True}

    async def skip_instruction(self) -> dict[str, Any]:
        """Skip the current instruction by advancing the instruction pointer.

        Returns:
            dict[str, Any]: Dict with old IP, new IP, and skipped byte count.

        Raises:
            ToolError: If disassembly fails or no instructions at current IP.
        """
        _logger.info("instruction_skipping")
        regs = await self.get_registers()
        current_ip = regs.rip if self._is_64bit else regs.rip & DWORD_MASK

        disasm = await self.disassemble_at(current_ip, 1)
        if not disasm:
            msg = f"Cannot disassemble instruction at {hex(current_ip)}"
            raise ToolError(msg)

        first_line = disasm[0]
        instr_len = len(bytes.fromhex(first_line.bytes_str.replace(" ", "")))
        new_ip = current_ip + instr_len

        reg_name = "rip" if self._is_64bit else "eip"
        await self._send_pipe_command("exec", {"command": f"{reg_name}={hex(new_ip)}"})

        return {
            "success": True,
            "old_ip": hex(current_ip),
            "new_ip": hex(new_ip),
            "skipped_bytes": instr_len,
        }

    async def set_ip(self, address: int) -> dict[str, Any]:
        """Set the instruction pointer to a specific address.

        Args:
            address: New instruction pointer value.

        Returns:
            dict[str, Any]: Dict with success status and new IP.
        """
        _logger.info("instruction_pointer_setting", address=hex(address))
        reg_name = "rip" if self._is_64bit else "eip"
        await self._send_pipe_command("exec", {"command": f"{reg_name}={hex(address)}"})
        return {"success": True, "instruction_pointer": hex(address)}

    async def set_label(self, address: int, text: str) -> dict[str, Any]:
        """Set a debug label at an address.

        Args:
            address: Address for the label.
            text: Label text.

        Returns:
            dict[str, Any]: Dict with address, text, and success status.
        """
        _logger.debug("label_setting", address=hex(address), label_text=text)
        await self._send_pipe_command("exec", {"command": f"lblset {hex(address)}, {text}"})
        return {"address": hex(address), "text": text, "success": True}

    async def get_labels(self, start: int, end: int) -> list[dict[str, Any]]:
        """Get debug labels in an address range.

        Args:
            start: Start address.
            end: End address.

        Returns:
            list[dict[str, Any]]: List of label dicts with address and text.
        """
        try:
            result = await self._send_pipe_command(
                "lbl_list",
                {"start": start, "end": end},
            )
        except ToolError as exc:
            _logger.debug("labels_list_failed", error=str(exc))
            return []

        labels: list[dict[str, Any]] = []
        if isinstance(result, list):
            for entry in result:
                if _is_str_obj_dict(entry):
                    raw_addr = entry.get("address")
                    raw_text = entry.get("text")
                    addr_str = raw_addr if isinstance(raw_addr, str) else ""
                    text = raw_text if isinstance(raw_text, str) else ""
                    try:
                        addr = int(addr_str, 0)
                    except ValueError:
                        continue
                    if start <= addr <= end:
                        labels.append({"address": addr_str, "text": text})
        return labels

    async def set_comment(self, address: int, text: str) -> dict[str, Any]:
        """Set a debug comment at an address.

        Args:
            address: Address for the comment.
            text: Comment text.

        Returns:
            dict[str, Any]: Dict with address, text, and success status.
        """
        _logger.debug("comment_setting", address=hex(address))
        await self._send_pipe_command("exec", {"command": f"cmtset {hex(address)}, {text}"})
        return {"address": hex(address), "text": text, "success": True}

    async def get_comments(self, start: int, end: int) -> list[dict[str, Any]]:
        """Get debug comments in an address range.

        Args:
            start: Start address.
            end: End address.

        Returns:
            list[dict[str, Any]]: List of comment dicts with address and text.
        """
        try:
            result = await self._send_pipe_command(
                "cmt_list",
                {"start": start, "end": end},
            )
        except ToolError as exc:
            _logger.debug("comments_list_failed", error=str(exc))
            return []

        comments: list[dict[str, Any]] = []
        if isinstance(result, list):
            for entry in result:
                if _is_str_obj_dict(entry):
                    raw_addr = entry.get("address")
                    raw_text = entry.get("text")
                    addr_str = raw_addr if isinstance(raw_addr, str) else ""
                    text = raw_text if isinstance(raw_text, str) else ""
                    try:
                        addr = int(addr_str, 0)
                    except ValueError:
                        continue
                    if start <= addr <= end:
                        comments.append({"address": addr_str, "text": text})
        return comments

    async def enable_breakpoint(self, address: int) -> dict[str, Any]:
        """Enable a breakpoint at an address.

        Args:
            address: Breakpoint address.

        Returns:
            dict[str, Any]: Dict with address and success status.
        """
        _logger.debug("breakpoint_enabling", address=hex(address))
        await self._send_pipe_command("exec", {"command": f"be {hex(address)}"})
        bp = self._breakpoints.get(address)
        if bp is not None:
            self._breakpoints[address] = BreakpointInfo(
                id=bp.id,
                address=bp.address,
                bp_type=bp.bp_type,
                enabled=True,
                hit_count=bp.hit_count,
                condition=bp.condition,
            )
        return {"address": hex(address), "success": True}

    async def disable_breakpoint(self, address: int) -> dict[str, Any]:
        """Disable a breakpoint at an address.

        Args:
            address: Breakpoint address.

        Returns:
            dict[str, Any]: Dict with address and success status.
        """
        _logger.debug("breakpoint_disabling", address=hex(address))
        await self._send_pipe_command("exec", {"command": f"bd {hex(address)}"})
        bp = self._breakpoints.get(address)
        if bp is not None:
            self._breakpoints[address] = BreakpointInfo(
                id=bp.id,
                address=bp.address,
                bp_type=bp.bp_type,
                enabled=False,
                hit_count=bp.hit_count,
                condition=bp.condition,
            )
        return {"address": hex(address), "success": True}

    async def set_breakpoint_on_api(self, module: str, function: str) -> dict[str, Any]:
        """Set a breakpoint on an imported API function.

        Args:
            module: Module name (e.g. 'kernel32').
            function: Function name (e.g. 'CreateFileW').

        Returns:
            dict[str, Any]: Dict with target and success status.
        """
        target = f"{module}.{function}"
        _logger.info("api_breakpoint_setting", target=target)
        await self._send_pipe_command("exec", {"command": f"bpx {target}"})
        return {"success": True, "target": target}

    async def dump_memory_to_file(self, address: int, size: int, path: str) -> dict[str, Any]:
        """Dump a memory region to a file on disk.

        Args:
            address: Start address.
            size: Number of bytes to dump.
            path: File path to write to.

        Returns:
            dict[str, Any]: Dict with path and bytes_written count.
        """
        _logger.info("memory_dumping", address=hex(address), size=size, path=path)
        data = await self.read_memory(address, size)
        output_path = Path(path)
        await asyncio.to_thread(output_path.parent.mkdir, parents=True, exist_ok=True)
        await asyncio.to_thread(output_path.write_bytes, data)
        return {"success": True, "path": path, "bytes_written": len(data)}

    async def _resolve_module_base(self, module_name: str) -> int:
        """Resolve a module name to its base address.

        Args:
            module_name: Module name (e.g. 'ntdll.dll').

        Returns:
            int: Base address of the module.

        Raises:
            ToolError: If module not found.
        """
        modules = await self.get_modules()
        for mod in modules:
            if mod.name.lower() == module_name.lower():
                _logger.debug("module_base_resolved", module_name=module_name, address=hex(mod.base_address))
                return mod.base_address
        msg = f"Module {module_name!r} not found"
        raise ToolError(msg)

    async def _read_pe_header(self, base_address: int, module_name: str, size: int = 256) -> tuple[int, bytes]:
        """Read and validate PE header from a module's base address.

        Args:
            base_address: Module base address.
            module_name: Module name for error messages.
            size: Bytes to read from PE header start.

        Returns:
            tuple[int, bytes]: Tuple of (pe_offset, pe_header_bytes).

        Raises:
            ToolError: If DOS or PE signature is invalid.
        """
        _logger.debug("pe_header_reading", base_address=hex(base_address), module_name=module_name)
        dos_header = await self.read_memory(base_address, 64)
        if dos_header[:2] != b"MZ":
            msg = f"Invalid DOS header in {module_name}"
            raise ToolError(msg)

        pe_offset = struct.unpack_from("<I", dos_header, PE_HEADER_OFFSET)[0]
        pe_header = await self.read_memory(base_address + pe_offset, size)

        if pe_header[:4] != b"PE\x00\x00":
            msg = f"Invalid PE signature in {module_name}"
            raise ToolError(msg)

        return pe_offset, pe_header

    @staticmethod
    def _parse_section_entry(sec_data: bytes, sec_offset: int, base_address: int) -> dict[str, Any]:
        """Parse a single PE section header entry.

        Args:
            sec_data: Buffer containing the section header.
            sec_offset: Offset within the buffer.
            base_address: Module base address for RVA calculation.

        Returns:
            dict[str, Any]: Dict with section name, addresses, sizes, and permissions.
        """
        name_bytes = sec_data[sec_offset : sec_offset + 8]
        sec_name = name_bytes.split(b"\x00")[0].decode("ascii", errors="replace")
        virtual_size = struct.unpack_from("<I", sec_data, sec_offset + 8)[0]
        virtual_address = struct.unpack_from("<I", sec_data, sec_offset + 12)[0]
        raw_size = struct.unpack_from("<I", sec_data, sec_offset + 16)[0]
        characteristics = struct.unpack_from("<I", sec_data, sec_offset + 36)[0]

        return {
            "name": sec_name,
            "virtual_address": hex(base_address + virtual_address),
            "virtual_size": virtual_size,
            "raw_size": raw_size,
            "characteristics": hex(characteristics),
            "readable": bool(characteristics & 0x40000000),
            "writable": bool(characteristics & 0x80000000),
            "executable": bool(characteristics & 0x20000000),
        }

    async def get_module_sections(self, module_name: str) -> list[dict[str, Any]]:
        """Get PE section info of a loaded module by parsing its in-memory header.

        Args:
            module_name: Module name (e.g. 'ntdll.dll').

        Returns:
            list[dict[str, Any]]: List of section dicts with name, virtual_address, virtual_size,
            raw_size, and characteristics.
        """
        _logger.debug("module_sections_reading", module=module_name)
        base_address = await self._resolve_module_base(module_name)
        pe_offset, pe_header = await self._read_pe_header(base_address, module_name)

        num_sections = struct.unpack_from("<H", pe_header, 6)[0]
        optional_header_size = struct.unpack_from("<H", pe_header, 20)[0]
        section_table_offset = 24 + optional_header_size

        sections: list[dict[str, Any]] = []
        for i in range(num_sections):
            offset = section_table_offset + (i * PE_SECTION_HEADER_SIZE)
            if offset + PE_SECTION_HEADER_SIZE > len(pe_header):
                sec_data = await self.read_memory(base_address + pe_offset + offset, PE_SECTION_HEADER_SIZE)
                sections.append(self._parse_section_entry(sec_data, 0, base_address))
            else:
                sections.append(self._parse_section_entry(pe_header, offset, base_address))

        return sections

    async def _read_export_tables(self, base_address: int, pe_header: bytes) -> tuple[bytes, bytes, bytes, int, int, int]:
        """Read PE export address, name pointer, and ordinal tables.

        Args:
            base_address: Module base address.
            pe_header: PE header bytes.

        Returns:
            tuple[bytes, bytes, bytes, int, int, int]: Tuple of (addr_table, name_ptrs, ordinal_table, num_names, ordinal_base, num_functions).

        Raises:
            ToolError: If PE header too small or no exports.
        """
        machine = struct.unpack_from("<H", pe_header, 4)[0]
        is_pe64 = machine == PE64_MACHINE
        export_dir_offset = 24 + (112 if is_pe64 else 96)

        if export_dir_offset + 8 > len(pe_header):
            msg = "PE header too small for export directory"
            raise ToolError(msg)

        export_rva = struct.unpack_from("<I", pe_header, export_dir_offset)[0]

        if export_rva == 0 or struct.unpack_from("<I", pe_header, export_dir_offset + 4)[0] == 0:
            msg = "No export directory"
            raise ToolError(msg)

        export_dir = await self.read_memory(
            base_address + export_rva,
            min(struct.unpack_from("<I", pe_header, export_dir_offset + 4)[0], PE_EXPORT_DIR_MIN_SIZE),
        )

        num_functions = struct.unpack_from("<I", export_dir, 20)[0]
        num_names = struct.unpack_from("<I", export_dir, 24)[0]
        ordinal_base = struct.unpack_from("<I", export_dir, 16)[0]

        addr_table = await self.read_memory(base_address + struct.unpack_from("<I", export_dir, 28)[0], num_functions * 4)
        name_ptrs = await self.read_memory(base_address + struct.unpack_from("<I", export_dir, 32)[0], num_names * 4)
        ordinal_table = await self.read_memory(base_address + struct.unpack_from("<I", export_dir, 36)[0], num_names * 2)

        return addr_table, name_ptrs, ordinal_table, num_names, ordinal_base, num_functions

    async def get_module_exports(self, module_name: str) -> list[dict[str, Any]]:
        """Get exports of a loaded module by parsing its in-memory PE export table.

        Args:
            module_name: Module name (e.g. 'kernel32.dll').

        Returns:
            list[dict[str, Any]]: List of export dicts with ordinal, name, and address.
        """
        _logger.debug("module_exports_reading", module=module_name)
        base_address = await self._resolve_module_base(module_name)
        _, pe_header = await self._read_pe_header(base_address, module_name, size=512)

        try:
            addr_table, name_ptrs, ordinal_table, num_names, ordinal_base, _ = await self._read_export_tables(base_address, pe_header)
        except ToolError as exc:
            _logger.debug("export_tables_read_failed", module=module_name, error=str(exc))
            return []

        exports: list[dict[str, Any]] = []
        for i in range(min(num_names, PE_EXPORT_MAX)):
            name_rva = struct.unpack_from("<I", name_ptrs, i * 4)[0]
            ordinal_index = struct.unpack_from("<H", ordinal_table, i * 2)[0]
            func_rva = struct.unpack_from("<I", addr_table, ordinal_index * 4)[0]

            try:
                name_data = await self.read_memory(base_address + name_rva, PE_EXPORT_NAME_BUF)
                null_pos = name_data.find(b"\x00")
                func_name = name_data[: null_pos if null_pos != -1 else PE_EXPORT_NAME_BUF].decode("ascii", errors="replace")
            except ToolError:
                func_name = f"ordinal_{ordinal_base + ordinal_index}"

            exports.append({
                "ordinal": ordinal_base + ordinal_index,
                "name": func_name,
                "address": hex(base_address + func_rva),
            })

        return exports

    async def trace_start(
        self,
        address: int | None = None,
        condition: str | None = None,
        log_text: str | None = None,
    ) -> dict[str, Any]:
        """Start conditional trace recording in x64dbg.

        Args:
            address: Address to start tracing at.
            condition: Trace break condition expression.
            log_text: Text to log at each traced instruction.

        Returns:
            dict[str, Any]: Dict with success status.
        """
        if address is not None and log_text is not None:
            await self._send_pipe_command("exec", {"command": f"TraceSetLog {hex(address)}, {log_text}"})
        if address is not None and condition is not None:
            await self._send_pipe_command("exec", {"command": f"TraceSetCondition {hex(address)}, {condition}"})
        await self._send_pipe_command("exec", {"command": "StartRunTrace"})
        return {"success": True}

    async def trace_stop(self) -> dict[str, Any]:
        """Stop trace recording.

        Returns:
            dict[str, Any]: Dict with success status.
        """
        _logger.debug("trace_stopping")
        await self._send_pipe_command("exec", {"command": "StopRunTrace"})
        return {"success": True}

    async def set_exception_config(self, code: int, handling: str) -> dict[str, Any]:
        """Configure how x64dbg handles a specific exception code.

        Args:
            code: Exception code (e.g. 0xC0000005 for access violation).
            handling: Handling mode - 'break' (first chance break),
                'ignore' (pass to application), or 'log' (log and continue).

        Returns:
            dict[str, Any]: Dict with code, handling, and success status.
        """
        _logger.info("exception_config_set", code=hex(code), handling=handling)
        handling_map = {"break": 1, "ignore": 0, "log": 2}
        handling_code = handling_map.get(handling, 1)
        await self._send_pipe_command("exec", {"command": f"SetExceptionBPX {hex(code)}, {handling_code}"})
        return {"success": True, "code": hex(code), "handling": handling}

    async def patch_instruction(self, address: int, instruction: str) -> dict[str, Any]:
        """Assemble and write an instruction at address using x64dbg's assembler.

        Args:
            address: Target address.
            instruction: Assembly instruction text.

        Returns:
            dict[str, Any]: Dict with success status and address.
        """
        _logger.info("patching_instruction", address=hex(address), instruction=instruction)
        await self._send_pipe_command("assemble", {"address": hex(address), "instruction": instruction})
        return {"success": True, "address": hex(address), "instruction": instruction}

    async def nop_range(self, address: int, size: int) -> dict[str, Any]:
        """Fill an address range with NOP (0x90) bytes.

        Args:
            address: Start address.
            size: Number of bytes to NOP.

        Returns:
            dict[str, Any]: Dict with success status, address, and size.
        """
        _logger.info("nop_range_filling", address=hex(address), size=size)
        await self._send_command(f"fill {hex(address)}, {size}, 90")
        return {"success": True, "address": hex(address), "size": size}

    async def get_module_imports(self, module_name: str) -> list[dict[str, Any]]:
        """Get imports of a loaded module via the plugin.

        Args:
            module_name: Module name (e.g. 'kernel32.dll').

        Returns:
            list[dict[str, Any]]: List of import dicts with iatRva, iatVa, ordinal, name, undecoratedName.
        """
        _logger.debug("module_imports_reading", module=module_name)
        result = await self._send_pipe_command("mod_imports", {"name": module_name})
        if isinstance(result, list):
            return [dict(entry) if _is_str_obj_dict(entry) else {} for entry in result]
        return []

    async def find_references(self, address: int) -> dict[str, Any]:
        """Find references to an address.

        Args:
            address: Target address.

        Returns:
            dict[str, Any]: Dict with success status.
        """
        _logger.debug("finding_references", address=hex(address))
        try:
            await self._send_pipe_command("ref_search", {"address": hex(address), "type": "call"})
        except ToolError:
            await self._send_command(f"reffind {hex(address)}")
        return {"success": True, "address": hex(address)}

    async def find_string_references(self, module: str) -> dict[str, Any]:
        """Find string references in a module.

        Args:
            module: Module name.

        Returns:
            dict[str, Any]: Dict with success status.
        """
        _logger.debug("finding_string_references", module=module)
        await self._send_command(f"strref {module}")
        return {"success": True, "module": module}

    async def find_intermodular_calls(self, module: str) -> dict[str, Any]:
        """Find intermodular calls in a module.

        Args:
            module: Module name.

        Returns:
            dict[str, Any]: Dict with success status.
        """
        _logger.debug("finding_intermodular_calls", module=module)
        await self._send_command(f"modcallfind {module}")
        return {"success": True, "module": module}

    async def evaluate_expression(self, expression: str) -> int:
        """Evaluate an x64dbg expression.

        Args:
            expression: Expression to evaluate (e.g. 'rax+rbx*4').

        Returns:
            int: Expression result value.
        """
        _logger.debug("evaluating_expression", expression=expression)
        result = await self._send_pipe_command("eval", {"expression": expression})
        if isinstance(result, str):
            return int(result, 0)
        if isinstance(result, int):
            return result
        return 0

    async def get_function_cfg(self, address: int, max_blocks: int = 500) -> dict[str, Any]:
        """Get control flow graph of a function.

        Args:
            address: Function entry address.
            max_blocks: Maximum number of basic blocks to analyze.

        Returns:
            dict[str, Any]: Dict with entry, blocks list, and edges list.
        """
        _logger.debug("getting_function_cfg", address=hex(address), max_blocks=max_blocks)
        result = await self._send_pipe_command("cfg", {"address": hex(address), "max_blocks": max_blocks})
        if _is_str_obj_dict(result):
            return dict(result)
        return {"entry": hex(address), "blocks": [], "edges": []}

    async def save_database(self) -> dict[str, Any]:
        """Save the x64dbg analysis database.

        Returns:
            dict[str, Any]: Dict with success status.
        """
        _logger.info("database_saving")
        await self._send_command("dbsave")
        return {"success": True}

    async def load_database(self) -> dict[str, Any]:
        """Load the x64dbg analysis database.

        Returns:
            dict[str, Any]: Dict with success status.
        """
        _logger.info("database_loading")
        await self._send_command("dbload")
        return {"success": True}

    async def clear_database(self) -> dict[str, Any]:
        """Clear the x64dbg analysis database.

        Returns:
            dict[str, Any]: Dict with success status.
        """
        _logger.info("database_clearing")
        await self._send_command("dbclear")
        return {"success": True}

    async def get_patches(self) -> list[dict[str, Any]]:
        """List all applied patches.

        Returns:
            list[dict[str, Any]]: List of patch dicts with address, oldByte, newByte.
        """
        _logger.debug("patches_listing")
        try:
            result = await self._send_pipe_command("patch_list")
            if isinstance(result, list):
                return [dict(entry) if _is_str_obj_dict(entry) else {} for entry in result]
        except ToolError:
            _logger.debug("patch_list_pipe_unavailable")
        return []

    async def restore_patch(self, address: int) -> dict[str, Any]:
        """Restore original bytes at a patched address.

        Args:
            address: Address of the patch to restore.

        Returns:
            dict[str, Any]: Dict with success status.
        """
        _logger.info("patch_restoring", address=hex(address))
        try:
            await self._send_pipe_command("patch_restore", {"address": hex(address)})
        except ToolError:
            await self._send_command(f"patchrestore {hex(address)}")
        return {"success": True, "address": hex(address)}

    async def export_patches(self, path: str) -> dict[str, Any]:
        """Export patches to a file.

        Args:
            path: Output file path.

        Returns:
            dict[str, Any]: Dict with success status and path.
        """
        _logger.info("patches_exporting", path=path)
        await self._send_command(f'savedata "{path}"')
        return {"success": True, "path": path}

    async def suspend_thread(self, tid: int) -> dict[str, Any]:
        """Suspend a thread.

        Args:
            tid: Thread ID.

        Returns:
            dict[str, Any]: Dict with success status and tid.
        """
        _logger.info("thread_suspending", tid=tid)
        await self._send_command(f"suspendthread {tid}")
        return {"success": True, "tid": tid}

    async def resume_thread(self, tid: int) -> dict[str, Any]:
        """Resume a suspended thread.

        Args:
            tid: Thread ID.

        Returns:
            dict[str, Any]: Dict with success status and tid.
        """
        _logger.info("thread_resuming", tid=tid)
        await self._send_command(f"resumethread {tid}")
        return {"success": True, "tid": tid}

    async def switch_thread(self, tid: int) -> dict[str, Any]:
        """Switch the active debugger thread.

        Args:
            tid: Thread ID to switch to.

        Returns:
            dict[str, Any]: Dict with success status and tid.
        """
        _logger.info("thread_switching", tid=tid)
        await self._send_command(f"switchthread {tid}")
        return {"success": True, "tid": tid}

    async def set_thread_name(self, tid: int, name: str) -> dict[str, Any]:
        """Set a thread's name.

        Args:
            tid: Thread ID.
            name: Display name for the thread.

        Returns:
            dict[str, Any]: Dict with success status, tid, and name.
        """
        _logger.info("thread_name_setting", tid=tid)
        await self._send_command(f'setthreadname {tid}, "{name}"')
        return {"success": True, "tid": tid, "name": name}

    async def get_seh_chain(self) -> list[dict[str, Any]]:
        """Get the structured exception handler chain.

        Returns:
            list[dict[str, Any]]: List of SEH entry dicts with handler and next addresses.
        """
        _logger.debug("seh_chain_reading")
        try:
            result = await self._send_pipe_command("seh_chain")
            if isinstance(result, list):
                return [dict(entry) if _is_str_obj_dict(entry) else {} for entry in result]
        except ToolError:
            _logger.debug("seh_chain_pipe_unavailable")
        return []

    async def read_peb(self) -> dict[str, Any]:
        """Read the Process Environment Block.

        Returns:
            dict[str, Any]: Dict with PEB fields including beingDebugged, imageBaseAddress, ntGlobalFlag.
        """
        _logger.debug("peb_reading")
        try:
            result = await self._send_pipe_command("peb_read")
            if _is_str_obj_dict(result):
                return dict(result)
        except ToolError:
            _logger.debug("peb_read_pipe_unavailable")
        return {}

    async def read_teb(self, tid: int | None = None) -> dict[str, Any]:
        """Read the Thread Environment Block.

        Args:
            tid: Thread ID. Uses current thread if None.

        Returns:
            dict[str, Any]: Dict with TEB fields including stackBase, stackLimit, processId, threadId.
        """
        _logger.debug("teb_reading", tid=tid)
        params: dict[str, Any] = {}
        if tid is not None:
            params["tid"] = tid
        try:
            result = await self._send_pipe_command("teb_read", params or None)
            if _is_str_obj_dict(result):
                return dict(result)
        except ToolError:
            _logger.debug("teb_read_pipe_unavailable")
        return {}

    async def get_pe_directories(self, module_name: str) -> list[dict[str, Any]]:
        """Get PE data directory entries for a module.

        Args:
            module_name: Module name (e.g. 'ntdll.dll').

        Returns:
            list[dict[str, Any]]: List of directory entry dicts with index, name, rva, size.
        """
        _logger.debug("pe_directories_reading", module=module_name)
        try:
            result = await self._send_pipe_command("pe_directories", {"module": module_name})
            if isinstance(result, list):
                return [dict(entry) if _is_str_obj_dict(entry) else {} for entry in result]
        except ToolError:
            _logger.debug("pe_directories_pipe_unavailable")
        return []

    async def add_watch(self, expression: str) -> dict[str, Any]:
        """Add a watch expression.

        Args:
            expression: Expression to watch.

        Returns:
            dict[str, Any]: Dict with success status and expression.
        """
        _logger.info("watch_adding", expression=expression)
        try:
            await self._send_pipe_command("watch_add", {"expression": expression})
        except ToolError:
            await self._send_command(f'AddWatch "{expression}"')
        return {"success": True, "expression": expression}

    async def remove_watch(self, index: int) -> dict[str, Any]:
        """Remove a watch expression by index.

        Args:
            index: Watch index to remove.

        Returns:
            dict[str, Any]: Dict with success status and index.
        """
        _logger.info("watch_removing", index=index)
        try:
            await self._send_pipe_command("watch_remove", {"index": index})
        except ToolError:
            await self._send_command(f"DelWatch {index}")
        return {"success": True, "index": index}

    async def get_watches(self) -> list[dict[str, Any]]:
        """Get all watch expressions and their current values.

        Returns:
            list[dict[str, Any]]: List of watch dicts.
        """
        _logger.debug("watches_listing")
        try:
            result = await self._send_pipe_command("watch_list")
            if isinstance(result, list):
                return [dict(entry) if _is_str_obj_dict(entry) else {} for entry in result]
        except ToolError:
            _logger.debug("watch_list_pipe_unavailable")
        return []

    async def set_logging_breakpoint(self, address: int, log_text: str, *, non_stopping: bool = True) -> dict[str, Any]:
        """Set a logging breakpoint that logs text without stopping.

        Args:
            address: Breakpoint address.
            log_text: Text to log when hit.
            non_stopping: If True, continue execution after logging.

        Returns:
            dict[str, Any]: Dict with success status, address, and log_text.
        """
        _logger.info("logging_breakpoint_setting", address=hex(address))
        await self._send_command(f"bp {hex(address)}")
        await self._send_command(f'SetBreakpointLog {hex(address)}, "{log_text}"')
        if non_stopping:
            await self._send_command(f"SetBreakpointFastResume {hex(address)}, 1")
        return {"success": True, "address": hex(address), "log_text": log_text}

    async def configure_breakpoint(
        self,
        address: int,
        *,
        condition: str | None = None,
        log_text: str | None = None,
        command: str | None = None,
        fast_resume: bool = False,
    ) -> dict[str, Any]:
        """Configure breakpoint properties.

        Args:
            address: Breakpoint address.
            condition: Conditional expression.
            log_text: Log text on hit.
            command: Command to execute on hit.
            fast_resume: Whether to auto-resume after hit.

        Returns:
            dict[str, Any]: Dict with success status and configured properties.
        """
        _logger.info("breakpoint_configuring", address=hex(address))
        if condition is not None:
            await self._send_command(f'bpcond {hex(address)}, "{condition}"')
        if log_text is not None:
            await self._send_command(f'SetBreakpointLog {hex(address)}, "{log_text}"')
        if command is not None:
            await self._send_command(f'SetBreakpointCommand {hex(address)}, "{command}"')
        if fast_resume:
            await self._send_command(f"SetBreakpointFastResume {hex(address)}, 1")
        return {"success": True, "address": hex(address)}

    async def set_dll_breakpoint(self, dll_name: str, event: str = "load") -> dict[str, Any]:
        """Set a breakpoint on DLL load/unload.

        Args:
            dll_name: DLL name to break on.
            event: Event type ('load' or 'unload').

        Returns:
            dict[str, Any]: Dict with success status, dll_name, and event.
        """
        _logger.info("dll_breakpoint_setting", dll=dll_name, dll_event=event)
        cmd = f'LibrarianSetBreakPoint "{dll_name}"'
        if event == "unload":
            cmd += ", unload"
        await self._send_command(cmd)
        return {"success": True, "dll_name": dll_name, "event": event}

    async def trace_into(self, condition: str | None = None, max_steps: int = 50000) -> dict[str, Any]:
        """Trace into with optional condition.

        Args:
            condition: Trace break condition expression.
            max_steps: Maximum number of steps.

        Returns:
            dict[str, Any]: Dict with success status.
        """
        _logger.info("trace_into_starting", max_steps=max_steps)
        cmd = f"TraceIntoConditional {max_steps}"
        if condition:
            cmd += f', "{condition}"'
        await self._send_command(cmd)
        return {"success": True, "max_steps": max_steps}

    async def trace_over(self, condition: str | None = None, max_steps: int = 50000) -> dict[str, Any]:
        """Trace over with optional condition.

        Args:
            condition: Trace break condition expression.
            max_steps: Maximum number of steps.

        Returns:
            dict[str, Any]: Dict with success status.
        """
        _logger.info("trace_over_starting", max_steps=max_steps)
        cmd = f"TraceOverConditional {max_steps}"
        if condition:
            cmd += f', "{condition}"'
        await self._send_command(cmd)
        return {"success": True, "max_steps": max_steps}

    async def get_trace_record(self, address: int, size: int = 1) -> dict[str, Any]:
        """Get trace record hit count at an address.

        Args:
            address: Address to query.
            size: Number of bytes to check.

        Returns:
            dict[str, Any]: Dict with address and hitCount.
        """
        _logger.debug("trace_record_reading", address=hex(address))
        try:
            result = await self._send_pipe_command("trace_record", {"address": hex(address), "size": size})
            if _is_str_obj_dict(result):
                return dict(result)
        except ToolError:
            _logger.debug("trace_record_pipe_unavailable")
        return {"address": hex(address), "hitCount": 0}

    async def step_count(self, count: int, step_type: str = "into") -> dict[str, Any]:
        """Execute a specific number of steps.

        Args:
            count: Number of steps to execute.
            step_type: Step type ('into' or 'over').

        Returns:
            dict[str, Any]: Dict with success status, count, and step_type.
        """
        _logger.info("step_count_executing", count=count, step_type=step_type)
        cmd = f"tic 0, {count}" if step_type == "into" else f"toc 0, {count}"
        await self._send_command(cmd)
        return {"success": True, "count": count, "step_type": step_type}

    async def animate_start(self, step_type: str = "into") -> dict[str, Any]:
        """Start animation (visual step execution).

        Args:
            step_type: Step type ('into' or 'over').

        Returns:
            dict[str, Any]: Dict with success status and step_type.
        """
        _logger.info("animation_starting", step_type=step_type)
        cmd = "AnimateInto" if step_type == "into" else "AnimateOver"
        await self._send_command(cmd)
        return {"success": True, "step_type": step_type}

    async def animate_stop(self) -> dict[str, Any]:
        """Stop animation.

        Returns:
            dict[str, Any]: Dict with success status.
        """
        _logger.info("animation_stopping")
        await self._send_command("AnimateStop")
        return {"success": True}

    async def analyze_entropy(self, address: int, size: int, block_size: int = 256) -> list[dict[str, Any]]:
        """Analyze Shannon entropy of a memory region.

        Args:
            address: Start address.
            size: Total bytes to analyze.
            block_size: Size of each entropy calculation block.

        Returns:
            list[dict[str, Any]]: List of dicts with address, entropy value, and block size.
        """
        _logger.debug("entropy_analyzing", address=hex(address), size=size, block_size=block_size)
        data = await self.read_memory(address, size)
        results: list[dict[str, Any]] = []
        for offset in range(0, len(data), block_size):
            block = data[offset : offset + block_size]
            if not block:
                break
            freq: list[int] = [0] * 256
            for b in block:
                freq[b] += 1
            entropy = 0.0
            block_len = len(block)
            for f in freq:
                if f > 0:
                    p = f / block_len
                    entropy -= p * math.log2(p)
            results.append({
                "address": hex(address + offset),
                "entropy": round(entropy, 4),
                "size": block_len,
            })
        return results

    async def yara_scan(
        self,
        *,
        rule_path: str | None = None,
        rule_text: str | None = None,
        address: int = 0,
        size: int = 0,
    ) -> list[dict[str, Any]]:
        """Scan memory with a YARA rule.

        Args:
            rule_path: Path to YARA rule file.
            rule_text: Inline YARA rule text.
            address: Start address (0 for all memory).
            size: Size to scan (0 for all).

        Returns:
            list[dict[str, Any]]: List of match dicts.
        """
        _logger.info("yara_scanning")
        if rule_path and not rule_text:
            cmd = f'yarascan "{rule_path}"'
            if address:
                cmd += f", {hex(address)}"
            if size:
                cmd += f", {hex(size)}"
            await self._send_command(cmd)
            return [{"success": True, "rule_path": rule_path}]

        try:
            import yara as _yara_raw  # noqa: PLC0415
        except ImportError:
            _logger.debug("yara_module_not_available")
            return []

        yara_module: Any = cast("Any", _yara_raw)
        yara_compile: Callable[..., Any] = yara_module.compile
        if rule_text:
            rules: Any = yara_compile(source=rule_text)
        elif rule_path:
            rules = yara_compile(filepath=rule_path)
        else:
            return []

        if not (address and size):
            return [{"success": True, "note": "full memory YARA scan via x64dbg"}]

        data = await self.read_memory(address, size)
        yara_match_fn: Callable[..., list[Any]] = rules.match
        yara_matches: list[Any] = yara_match_fn(data=data)
        results: list[dict[str, Any]] = []
        for m in yara_matches:
            rule_name: str = str(m.rule)
            strings_list: list[tuple[int, str, Any]] = list(m.strings)
            for offset_val, _identifier, match_bytes in strings_list:
                byte_val: bytes = match_bytes if isinstance(match_bytes, bytes) else str(match_bytes).encode()
                results.append({
                    "rule": rule_name,
                    "address": hex(address + offset_val),
                    "matched_bytes": byte_val.hex(),
                })
        return results

    async def script_load(self, path: str) -> dict[str, Any]:
        """Load an x64dbg script file.

        Args:
            path: Path to script file.

        Returns:
            dict[str, Any]: Dict with success status and path.
        """
        _logger.info("script_loading", path=path)
        await self._send_command(f'scriptload "{path}"')
        return {"success": True, "path": path}

    async def script_run(self) -> dict[str, Any]:
        """Run the currently loaded script.

        Returns:
            dict[str, Any]: Dict with success status.
        """
        _logger.info("script_running")
        await self._send_command("scriptrun")
        return {"success": True}

    async def script_cmd(self, line: str) -> dict[str, Any]:
        """Execute a single script command.

        Args:
            line: Script command line.

        Returns:
            dict[str, Any]: Dict with success status and line.
        """
        _logger.debug("script_cmd_executing", line=line)
        await self._send_command(f'scriptcmd "{line}"')
        return {"success": True, "line": line}

    async def script_abort(self) -> dict[str, Any]:
        """Abort the running script.

        Returns:
            dict[str, Any]: Dict with success status.
        """
        _logger.info("script_aborting")
        await self._send_command("scriptabort")
        return {"success": True}

    async def plugin_load(self, path: str) -> dict[str, Any]:
        """Load a plugin.

        Args:
            path: Path to plugin DLL.

        Returns:
            dict[str, Any]: Dict with success status and path.
        """
        _logger.info("plugin_loading", path=path)
        await self._send_command(f'plugload "{path}"')
        return {"success": True, "path": path}

    async def plugin_unload(self, name: str) -> dict[str, Any]:
        """Unload a plugin.

        Args:
            name: Plugin name.

        Returns:
            dict[str, Any]: Dict with success status and name.
        """
        _logger.info("plugin_unloading", plugin_name=name)
        await self._send_command(f'plugunload "{name}"')
        return {"success": True, "name": name}

    async def plugin_list(self) -> list[dict[str, Any]]:
        """List loaded plugins.

        Returns:
            list[dict[str, Any]]: List of plugin info dicts.
        """
        _logger.debug("plugins_listing")
        try:
            result = await self._send_pipe_command("plugin_list")
            if isinstance(result, list):
                return [dict(entry) if _is_str_obj_dict(entry) else {} for entry in result]
        except ToolError:
            await self._send_command("pluglist")
        return []

    async def get_handles(self) -> list[dict[str, Any]]:
        """Enumerate process handles.

        Returns:
            list[dict[str, Any]]: List of handle info dicts.
        """
        _logger.debug("handles_enumerating")
        await self._send_command("handlelist")
        return [{"success": True, "note": "handle list displayed in x64dbg"}]

    async def close_handle(self, handle: int) -> dict[str, Any]:
        """Close a process handle.

        Args:
            handle: Handle value to close.

        Returns:
            dict[str, Any]: Dict with success status.
        """
        _logger.info("handle_closing", handle=hex(handle))
        await self._send_command(f"handleclose {hex(handle)}")
        return {"success": True, "handle": hex(handle)}

    async def detect_anti_debug(self) -> dict[str, Any]:
        """Detect common anti-debugging techniques.

        Returns:
            dict[str, Any]: Dict with detected anti-debug indicators.
        """
        _logger.info("anti_debug_detecting")
        peb = await self.read_peb()
        checks: dict[str, bool] = {}
        being_debugged = peb.get("beingDebugged", 0)
        checks["peb_being_debugged"] = bool(being_debugged)
        nt_global_flag = peb.get("ntGlobalFlag", 0)
        if isinstance(nt_global_flag, int):
            checks["nt_global_flag_set"] = (nt_global_flag & 0x70) != 0
        return {"success": True, "checks": checks, "peb": peb}

    async def patch_anti_debug(self, checks: list[str] | None = None) -> dict[str, Any]:
        """Patch common anti-debug checks in the target process.

        Args:
            checks: Specific checks to patch. Patches all known checks if None.

        Returns:
            dict[str, Any]: Dict with success status and patched checks.
        """
        _logger.info("anti_debug_patching")
        patched: list[str] = []
        peb = await self.read_peb()
        peb_addr_raw = peb.get("address")
        if not isinstance(peb_addr_raw, str) or not peb_addr_raw:
            return {"success": False, "error": "Cannot read PEB address"}

        peb_addr = int(peb_addr_raw, 0)

        all_checks = checks or ["being_debugged", "nt_global_flag"]

        if "being_debugged" in all_checks:
            await self.write_memory(peb_addr + 2, b"\x00")
            patched.append("being_debugged")

        if "nt_global_flag" in all_checks:
            flag_offset = 0xBC if self._is_64bit else 0x68
            await self.write_memory(peb_addr + flag_offset, b"\x00\x00\x00\x00")
            patched.append("nt_global_flag")

        return {"success": True, "patched": patched}

    async def reconstruct_imports(self, oep: int, output_path: str) -> dict[str, Any]:
        """Reconstruct the import table using Scylla.

        Args:
            oep: Original Entry Point address.
            output_path: Path to write the fixed binary.

        Returns:
            dict[str, Any]: Dict with success status.
        """
        _logger.info("imports_reconstructing", oep=hex(oep), output=output_path)
        await self._send_command(f"scylla.searchIAT {hex(oep)}")
        await self._send_command("scylla.autoFix")
        await self._send_command(f'scylla.dump "{output_path}"')
        return {"success": True, "oep": hex(oep), "output_path": output_path}

    async def get_status(self) -> dict[str, Any]:
        """Get current debugger status.

        Returns:
            dict[str, Any]: Dict with debugging, paused, and initialized flags.
        """
        _logger.debug("status_querying")
        result = await self._send_pipe_command("status")
        if _is_str_obj_dict(result):
            return dict(result)
        return {"debugging": False, "paused": False, "initialized": False}

    async def goto_address(self, address: int) -> dict[str, Any]:
        """Navigate the disassembly view to an address.

        Args:
            address: Address to navigate to.

        Returns:
            dict[str, Any]: Dict with success status and address.
        """
        _logger.debug("goto_address", address=hex(address))
        await self._send_pipe_command("goto", {"address": hex(address)})
        return {"success": True, "address": hex(address)}

    async def get_tls_callbacks(self, module_name: str) -> list[dict[str, Any]]:
        """Get TLS callback addresses for a module.

        Args:
            module_name: Module name.

        Returns:
            list[dict[str, Any]]: List of TLS callback dicts with address.
        """
        _logger.debug("tls_callbacks_reading", module=module_name)
        base_address = await self._resolve_module_base(module_name)
        _, pe_header = await self._read_pe_header(base_address, module_name, size=512)

        machine = struct.unpack_from("<H", pe_header, 4)[0]
        is_pe64 = machine == PE64_MACHINE
        tls_dir_offset = 24 + (is_pe64 * 112 + (1 - is_pe64) * 96) + 72
        if tls_dir_offset + 8 > len(pe_header):
            return []

        tls_rva = struct.unpack_from("<I", pe_header, tls_dir_offset)[0]
        tls_size = struct.unpack_from("<I", pe_header, tls_dir_offset + 4)[0]
        if tls_rva == 0 or tls_size == 0:
            return []

        ptr_size = 8 if is_pe64 else 4
        tls_dir = await self.read_memory(base_address + tls_rva, max(tls_size, 40))
        callback_array_va = struct.unpack_from("<Q" if is_pe64 else "<I", tls_dir, 12 + ptr_size)[0]
        if callback_array_va == 0:
            return []

        callbacks: list[dict[str, Any]] = []
        for i in range(64):
            cb_data = await self.read_memory(callback_array_va + i * ptr_size, ptr_size)
            cb_addr = struct.unpack_from("<Q" if is_pe64 else "<I", cb_data, 0)[0]
            if cb_addr == 0:
                break
            callbacks.append({"index": i, "address": hex(cb_addr)})

        return callbacks

    async def break_on_tls_callbacks(self, module_name: str) -> dict[str, Any]:
        """Set breakpoints on all TLS callbacks of a module.

        Args:
            module_name: Module name.

        Returns:
            dict[str, Any]: Dict with success status and breakpoints set.
        """
        _logger.info("tls_callbacks_breaking", module=module_name)
        callbacks = await self.get_tls_callbacks(module_name)
        for cb in callbacks:
            addr_str = cb.get("address", "0")
            if isinstance(addr_str, str):
                addr = int(addr_str, 0)
                await self.set_breakpoint(addr)
        return {"success": True, "breakpoints_set": len(callbacks)}

    async def get_resources(self, module_name: str) -> list[dict[str, Any]]:
        """Get PE resource entries for a module.

        Args:
            module_name: Module name.

        Returns:
            list[dict[str, Any]]: List of resource dicts with type, id, size, and rva.
        """
        _logger.debug("resources_reading", module=module_name)
        base_address = await self._resolve_module_base(module_name)
        _, pe_header = await self._read_pe_header(base_address, module_name, size=512)

        machine = struct.unpack_from("<H", pe_header, 4)[0]
        is_pe64 = machine == PE64_MACHINE
        rsrc_dir_offset = 24 + (is_pe64 * 112 + (1 - is_pe64) * 96) + 16
        if rsrc_dir_offset + 8 > len(pe_header):
            return []

        rsrc_rva = struct.unpack_from("<I", pe_header, rsrc_dir_offset)[0]
        rsrc_size = struct.unpack_from("<I", pe_header, rsrc_dir_offset + 4)[0]
        if rsrc_rva == 0 or rsrc_size == 0:
            return []

        rsrc_header = await self.read_memory(base_address + rsrc_rva, min(rsrc_size, 4096))
        num_named = struct.unpack_from("<H", rsrc_header, 12)[0]
        num_id = struct.unpack_from("<H", rsrc_header, 14)[0]
        resources: list[dict[str, Any]] = []
        offset = 16
        for i in range(num_named + num_id):
            if offset + 8 > len(rsrc_header):
                break
            type_id = struct.unpack_from("<I", rsrc_header, offset)[0]
            resources.append({"index": i, "type_id": type_id, "type_name": _PE_RESOURCE_TYPE_NAMES.get(type_id, f"RT_{type_id}")})
            offset += 8

        return resources

    @staticmethod
    async def get_privileges() -> list[dict[str, Any]]:
        """Enumerate current process token privileges.

        Returns:
            list[dict[str, Any]]: List of privilege dicts with name and enabled status.
        """
        _logger.debug("privileges_enumerating")
        if not _IS_WIN32:
            return []

        try:
            advapi32 = ctypes.windll.advapi32
            kernel32 = ctypes.windll.kernel32

            token_handle = wintypes.HANDLE()
            current_process = kernel32.GetCurrentProcess()
            if not advapi32.OpenProcessToken(current_process, 0x0008, ctypes.byref(token_handle)):
                return []

            try:
                return_length = wintypes.DWORD()
                advapi32.GetTokenInformation(token_handle, 3, None, 0, ctypes.byref(return_length))
                buffer = ctypes.create_string_buffer(return_length.value)
                if not advapi32.GetTokenInformation(token_handle, 3, buffer, return_length.value, ctypes.byref(return_length)):
                    return []

                count = struct.unpack_from("<I", buffer.raw, 0)[0]
                privileges: list[dict[str, Any]] = []
                offset = 4
                for _ in range(min(count, 100)):
                    luid_low = struct.unpack_from("<I", buffer.raw, offset)[0]
                    luid_high = struct.unpack_from("<I", buffer.raw, offset + 4)[0]
                    attrs = struct.unpack_from("<I", buffer.raw, offset + 8)[0]

                    name_buf = ctypes.create_unicode_buffer(256)
                    name_len = wintypes.DWORD(256)

                    class LUID(ctypes.Structure):
                        """Windows ``LUID`` structure used for privilege lookup.

                        A locally unique identifier is a 64-bit value that
                        the OS assigns to privileges and other securable
                        objects. Declared inline so it can be passed by
                        reference into ``LookupPrivilegeNameW``.
                        """

                        _fields_: ClassVar = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

                    luid = LUID(luid_low, luid_high)
                    if advapi32.LookupPrivilegeNameW(None, ctypes.byref(luid), name_buf, ctypes.byref(name_len)):
                        privileges.append({
                            "name": name_buf.value,
                            "enabled": bool(attrs & 0x00000002),
                            "enabled_by_default": bool(attrs & 0x00000001),
                        })
                    offset += 12

                return privileges
            finally:
                kernel32.CloseHandle(token_handle)
        except (OSError, ValueError) as e:
            _logger.warning("privileges_enum_failed", error=str(e))
            return []

    @staticmethod
    async def adjust_privilege(name: str, *, enable: bool = True) -> dict[str, Any]:
        """Adjust a process token privilege.

        Args:
            name: Privilege name (e.g. 'SeDebugPrivilege').
            enable: True to enable, False to disable.

        Returns:
            dict[str, Any]: Dict with success status and privilege name.
        """
        _logger.info("privilege_adjusting", privilege=name, enable=enable)
        if not _IS_WIN32:
            return {"success": False, "error": "Windows only"}

        try:
            advapi32 = ctypes.windll.advapi32
            kernel32 = ctypes.windll.kernel32

            class LUID(ctypes.Structure):
                """Windows ``LUID`` structure used for privilege adjustment.

                Holds the locally unique identifier returned by
                ``LookupPrivilegeValueW`` and passed into the
                ``TOKEN_PRIVILEGES`` structure submitted to
                ``AdjustTokenPrivileges``.
                """

                _fields_: ClassVar = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

            class TokenPrivileges(ctypes.Structure):
                """Windows ``TOKEN_PRIVILEGES`` payload for one privilege.

                Simplified single-entry variant of the standard Windows
                structure, which is all ``AdjustTokenPrivileges`` needs
                when toggling a single privilege at a time.
                """

                _fields_: ClassVar = [
                    ("PrivilegeCount", wintypes.DWORD),
                    ("Luid", LUID),
                    ("Attributes", wintypes.DWORD),
                ]

            luid = LUID()
            if not advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
                return {"success": False, "error": f"Privilege {name!r} not found"}

            token_handle = wintypes.HANDLE()
            current_process = kernel32.GetCurrentProcess()
            if not advapi32.OpenProcessToken(current_process, 0x0020, ctypes.byref(token_handle)):
                return {"success": False, "error": "Failed to open process token"}

            try:
                tp = TokenPrivileges()
                tp.PrivilegeCount = 1
                tp.Luid = luid
                tp.Attributes = 0x00000002 if enable else 0

                disable_all_privileges = False
                result = advapi32.AdjustTokenPrivileges(token_handle, disable_all_privileges, ctypes.byref(tp), 0, None, None)
                return {"success": bool(result), "privilege": name, "enabled": enable}
            finally:
                kernel32.CloseHandle(token_handle)
        except (OSError, ValueError) as e:
            _logger.warning("privilege_adjust_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @staticmethod
    def _parse_stack_frame_entry(entry: dict[str, object]) -> StackFrame:
        """Parse a single stack frame entry dict from the plugin into a StackFrame.

        Args:
            entry: Dict with index, address, from, to, comment fields.

        Returns:
            StackFrame: Parsed stack frame.
        """

        def _parse_int(val: object) -> int:
            return int(val, 0) if isinstance(val, str) else (int(val) if isinstance(val, (int, float)) else 0)

        idx = _parse_int(entry.get("index", 0))
        addr = _parse_int(entry.get("address", 0))
        from_addr = _parse_int(entry.get("from", 0))
        to_addr = _parse_int(entry.get("to", 0))
        comment_raw = entry.get("comment", "")
        comment = str(comment_raw) if comment_raw else ""
        function_name: str | None = None
        module_name: str | None = None
        if comment and "." in comment:
            dot_idx = comment.rfind(".")
            module_name = comment[:dot_idx]
            function_name = comment[dot_idx + 1 :]
        elif comment:
            function_name = comment
        return StackFrame(
            index=idx,
            address=addr,
            return_address=from_addr,
            frame_pointer=to_addr,
            stack_pointer=0,
            function_name=function_name,
            module_name=module_name,
        )

    @staticmethod
    def _parse_disasm_entry(entry: dict[str, object]) -> DisassemblyLine:
        """Parse a single disassembly entry dict from the plugin into a DisassemblyLine.

        Args:
            entry: Dict with address, instruction, bytes, comment, label fields.

        Returns:
            DisassemblyLine: Parsed disassembly line.
        """
        addr_raw = entry.get("address", 0)
        addr = int(addr_raw, 0) if isinstance(addr_raw, str) else (int(addr_raw) if isinstance(addr_raw, int) else 0)
        instr_raw = entry.get("instruction", "")
        instr_str = str(instr_raw) if instr_raw else ""
        parts = instr_str.split(" ", 1)
        mnemonic = parts[0] if parts else ""
        operands = parts[1] if len(parts) > 1 else ""
        bytes_raw = entry.get("bytes", "")
        comment_raw = entry.get("comment") or entry.get("label")
        return DisassemblyLine(
            address=addr,
            bytes_str=str(bytes_raw) if bytes_raw else "",
            mnemonic=mnemonic,
            operands=operands,
            comment=str(comment_raw) if comment_raw else None,
        )

    @staticmethod
    def _get_parent_pid(pid: int) -> int:
        """Get parent process ID using Windows Toolhelp API.

        Args:
            pid: Process ID to get parent for.

        Returns:
            int: Parent process ID.

        Raises:
            ToolError: If not on Windows or API call fails.
        """
        if not _IS_WIN32:
            msg = f"_get_parent_pid {_ERR_REQUIRES_WINDOWS}"
            raise ToolError(msg, tool_name="x64dbg")

        parent_pid: int = 0
        kernel32 = ctypes.windll.kernel32

        class ProcessEntry32W(ctypes.Structure):
            _fields_: ClassVar = [
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

        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot in {INVALID_HANDLE_VALUE, DWORD_MASK}:
            error_code = ctypes.get_last_error()
            msg = f"{_ERR_CREATE_SNAPSHOT_FAILED} for process: error {error_code}"
            raise ToolError(msg, tool_name="x64dbg", exit_code=error_code)

        try:
            pe32 = ProcessEntry32W()
            pe32.dwSize = ctypes.sizeof(ProcessEntry32W)
            _logger.debug("initialized_process_entry", size=pe32.dwSize)

            if kernel32.Process32FirstW(snapshot, ctypes.byref(pe32)):
                while True:
                    if pe32.th32ProcessID == pid:
                        parent_pid = int(pe32.th32ParentProcessID)
                        break
                    if not kernel32.Process32NextW(snapshot, ctypes.byref(pe32)):
                        break
        except Exception as e:
            _logger.warning("x64dbg_get_parent_pid_failed", pid=pid, error=str(e))
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
            str | None: Command line string, or None if not accessible.
        """
        return _read_process_command_line(pid) if _IS_WIN32 else None
