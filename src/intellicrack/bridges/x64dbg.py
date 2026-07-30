# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""X64dbg bridge for Windows debugging.

This module provides integration with x64dbg for dynamic analysis, debugging, and memory manipulation on Windows systems.
"""

from __future__ import annotations

import asyncio
import functools
import math
import os
import re
import struct
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Literal, TypeGuard, cast

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
from intellicrack.bridges.parse_helpers import safe_int_from_str
from intellicrack.bridges.pe_format import (
    PE32_OPTIONAL_HEADER_SIZE,
    PE32PLUS_OPTIONAL_HEADER_SIZE,
    PE_OPTIONAL_HEADER_MAGIC_PE32,
    PE_OPTIONAL_HEADER_MAGIC_PE32PLUS,
    PE_OPTIONAL_HEADER_OFFSET,
    PE_SECTION_CHARACTERISTIC_EXECUTE,
    PE_SECTION_CHARACTERISTIC_READ,
    PE_SECTION_CHARACTERISTIC_WRITE,
    PE_SIGNATURE,
    detect_format,
    get_data_directory_offset,
    is_pe64_optional_header,
    read_data_directory_entry,
    read_dos_e_lfanew,
    unpack_coff_header,
    unpack_section_header,
)
from intellicrack.bridges.win32_types import (
    CMD_LINE_OFFSET_32,
    CMD_LINE_OFFSET_64,
    CONTEXT32,
    CONTEXT64,
    CONTEXT_ALL,
    CONTEXT_I386_ALL,
    IMAGE_FILE_MACHINE_AMD64 as PE64_MACHINE,
    IMAGE_FILE_MACHINE_I386 as PE32_MACHINE,
    INVALID_HANDLE_VALUE,
    MEM_COMMIT as WIN_MEM_COMMIT,
    MEM_IMAGE as MEM_IMAGE_FLAG,
    MEM_MAPPED as MEM_MAPPED_FLAG,
    MEM_PRIVATE as MEM_PRIVATE_FLAG,
    MEM_RELEASE as WIN_MEM_RELEASE,
    MEM_RESERVE as WIN_MEM_RESERVE,
    NT_HEADERS_OPTIONAL_OFFSET,
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE as PAGE_EXECUTE_READWRITE_FLAG,
    PAGE_NOACCESS,
    PAGE_READONLY,
    PAGE_READWRITE,
    PE_HEADER_OFFSET,
    PE_MAGIC_OFFSET,
    PROCESS_QUERY_INFORMATION as WIN_PROCESS_QUERY_INFORMATION,
    PROCESS_VM_OPERATION as WIN_PROCESS_VM_OPERATION,
    PROCESS_VM_READ as WIN_PROCESS_VM_READ,
    PROCESS_VM_WRITE as WIN_PROCESS_VM_WRITE,
    SYSTEM_HANDLE_INFORMATION_EX,
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX,
    TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
    TH32CS_SNAPPROCESS,
    TH32CS_SNAPTHREAD,
    THREAD_GET_CONTEXT,
    THREAD_QUERY_INFORMATION,
    THREAD_SUSPEND_RESUME,
    SystemExtendedHandleInformation,
    ThreadQuerySetWin32StartAddress,
    get_ntdll,
)
from intellicrack.core.error_logging import log_passthrough
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
from intellicrack.core.win32_desktop_process import (
    DesktopProcess,
    spawn_on_hidden_desktop,
)


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from types import ModuleType

_logger = get_logger(__name__)
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

_yara: ModuleType | None = None
try:
    import yara as _yara_module

    _yara = _yara_module
except ImportError:
    _logger.debug("yara_not_available", library="yara-python")


def _get_yara() -> ModuleType | None:
    """Return the yara-python module if available.

    Returns:
        ModuleType | None: The yara module, or None if not installed.
    """
    return _yara


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


MAX_USER_ADDRESS_64 = 0x7FFFFFFFFFFF
MIN_PATTERN_LENGTH = 16
MAX_MEMORY_READ_SIZE = 0x100000
DWORD_MASK = 0xFFFFFFFF
PEB_PROCESS_PARAMS_OFFSET_64 = 0x20
PEB_PROCESS_PARAMS_OFFSET_32 = 0x10
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


@dataclass(frozen=True, slots=True)
class _ResourcePathLabels:
    """Path labels accumulated while walking the PE resource tree.

    Attributes:
        type_id: Resolved Type id when available (depth >= 1, integer
            type entry).
        type_name: Resolved Type string name when available (depth >= 1).
        res_id: Resolved Name/Id resource id when available (depth >= 2,
            integer entry).
        res_name: Resolved Name string when available (depth >= 2).
    """

    type_id: int | None = None
    type_name: str | None = None
    res_id: int | None = None
    res_name: str | None = None

    def descend(
        self,
        *,
        depth: int,
        is_named: bool,
        entry_id: int,
        entry_str: str | None,
    ) -> _ResourcePathLabels:
        """Return a new label set for the directory below ``self``.

        Args:
            depth: Current depth of the entry being descended into
                (0 = Type level, 1 = Name/Id level).
            is_named: Whether the entry's name field is a string.
            entry_id: Numeric id (when ``is_named`` is False).
            entry_str: Decoded string name (when ``is_named`` is True).

        Returns:
            _ResourcePathLabels: Updated label set for the child level.
        """
        next_type_id = self.type_id
        next_type_name = self.type_name
        next_res_id = self.res_id
        next_res_name = self.res_name
        if depth == 0:
            if is_named:
                next_type_id = None
                next_type_name = entry_str
            else:
                next_type_id = entry_id
                next_type_name = _PE_RESOURCE_TYPE_NAMES.get(entry_id, f"RT_{entry_id}")
        elif depth == 1:
            if is_named:
                next_res_id = None
                next_res_name = entry_str
            else:
                next_res_id = entry_id
                next_res_name = None
        return _ResourcePathLabels(
            type_id=next_type_id,
            type_name=next_type_name,
            res_id=next_res_id,
            res_name=next_res_name,
        )


_ERR_REQUIRES_WINDOWS = "requires Windows platform"
_PLUGIN_PIPE_REMEDIATION = (
    "x64dbg started but the Intellicrack bridge plugin never opened its named pipe, so no debugger "
    "command can be issued. This usually means x64dbg loaded (or silently skipped) the plugin DLL but "
    "the plugin failed to initialise - most often an x64dbg SDK/ABI or architecture (x64 vs x32) "
    "mismatch. Open x64dbg and check the Log window and the Plugins menu for the 'Intellicrack Bridge' "
    "entry; if it is missing, rebuild the plugin from src/x64dbg-plugin against this x64dbg build's "
    "pluginsdk and redeploy."
)
_ERR_NOT_ATTACHED = "not attached to a process"
_ERR_OPEN_PROCESS_FAILED = "failed to open process"
_ERR_CREATE_SNAPSHOT_FAILED = "failed to create snapshot"
_ERR_GET_THREADS_FAILED = "failed to get threads"
_ERR_GET_MODULES_FAILED = "failed to get modules"
_ERR_GET_PARENT_PID_FAILED = "failed to get parent PID"
_STILL_ACTIVE = 259
# Windows error code 24, reported as GetLastError() after a module-snapshot
# call that raced a debuggee still finishing process creation.
_ERROR_BAD_LENGTH = 24
_TOOLHELP_MODULE_SNAPSHOT_MAX_ATTEMPTS = 10
_TOOLHELP_MODULE_SNAPSHOT_RETRY_DELAY = 0.1
_PE_HEADER_READ_SIZE = PE_OPTIONAL_HEADER_OFFSET + PE32PLUS_OPTIONAL_HEADER_SIZE + 0x100
_ERR_YARA_NOT_AVAILABLE = "yara-python is not installed. Install with 'pixi run pip install yara-python' to enable YARA scanning"
_ERR_YARA_EMPTY_RULE = "YARA rule must be non-empty"
_ERR_YARA_NO_RULE = "yara_scan requires rule_text or rule_path"
_ERR_YARA_RULE_FILE_EMPTY = "YARA rule file is empty"
_ERR_YARA_RULE_FILE_NOT_FOUND = "YARA rule file not found"
MIN_YARA_PATTERN_BYTES = 1
PE_ENTRY_POINT_OFFSET = 0x28
_HANDLE_QUERY_MAX_BUFFER = 0x10000000
_X86_NOP_OPCODE = 0x90

# Structured pipe-protocol error codes used to drive recovery decisions
# without resorting to substring matching on the human-readable message
# (see audit6.md F-0008/F-0028). The bridge attaches one of these values
# via ``ToolError.details["x64dbg_error_code"]`` so callers can branch on
# the actual failure mode (no transport vs. RPC name unknown vs. timeout)
# rather than guessing from text.
_X64DBG_ERR_PLUGIN_UNAVAILABLE = "plugin_unavailable"
_X64DBG_ERR_PIPE_DISCONNECTED = "pipe_disconnected"
_X64DBG_ERR_TIMEOUT = "timeout"
_X64DBG_ERR_UNKNOWN_COMMAND = "unknown_command"
_X64DBG_ERR_REMOTE = "remote_error"
_X64DBG_ERR_PROTOCOL_VIOLATION = "protocol_violation"

# Environment variable the bridge exports when spawning x64dbg so the
# deployed Intellicrack plugin runs the debugger as an embedded, windowless
# engine (hiding its main window and dismissing startup popups) driven over
# the pipe rather than presenting a second top-level debugger window.
_HEADLESS_ENV_VAR: str = "INTELLICRACK_X64DBG_HEADLESS"


# Marker substrings recognised on legacy plugin builds that returned a
# raw error string rather than a structured ``code`` field. Mapping is
# strict to specific transport/RPC failures - any other text is treated
# as a real plugin error and propagated.
_LEGACY_UNKNOWN_COMMAND_MARKERS = ("unknown command", "unknown rpc", "unknown method")
_LEGACY_PIPE_DISCONNECTED_MARKERS = ("pipe not connected", "pipe disconnected", "pipe reader failed")
_LEGACY_TIMEOUT_MARKERS = ("timed out",)
_LEGACY_PLUGIN_UNAVAILABLE_MARKERS = ("bridge plugin not available",)

# Codes that classify as "RPC missing" - allowed to fall back to the
# x64dbg console-script command for the same operation.
_RECOVERABLE_RPC_MISSING_CODES = frozenset({_X64DBG_ERR_UNKNOWN_COMMAND})

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


def _classify_legacy_error(message: str) -> str:
    """Map a legacy plugin error string to a structured x64dbg error code.

    Older builds of the x64dbg bridge plugin returned only a free-form
    ``error`` string in their responses. To preserve recovery behaviour
    against those builds without resorting to substring matching at
    every call site (audit6.md F-0008), classify the legacy text once
    here and attach the resulting code to ``ToolError.details``.

    Args:
        message: The free-form error message reported by the plugin.

    Returns:
        str: One of the ``_X64DBG_ERR_*`` constants. Returns
        ``_X64DBG_ERR_REMOTE`` when no specific transport pattern
        matches so the caller does not silently treat a real plugin
        error as recoverable.
    """
    text = message.lower()
    if any(marker in text for marker in _LEGACY_UNKNOWN_COMMAND_MARKERS):
        return _X64DBG_ERR_UNKNOWN_COMMAND
    if any(marker in text for marker in _LEGACY_PIPE_DISCONNECTED_MARKERS):
        return _X64DBG_ERR_PIPE_DISCONNECTED
    if any(marker in text for marker in _LEGACY_TIMEOUT_MARKERS):
        return _X64DBG_ERR_TIMEOUT
    if any(marker in text for marker in _LEGACY_PLUGIN_UNAVAILABLE_MARKERS):
        return _X64DBG_ERR_PLUGIN_UNAVAILABLE
    return _X64DBG_ERR_REMOTE


def _x64dbg_error_code(exc: ToolError) -> str | None:
    """Return the structured x64dbg error code attached to a ToolError.

    Args:
        exc: ToolError raised by the bridge.

    Returns:
        str | None: The ``x64dbg_error_code`` value from
        ``exc.details`` if present, otherwise ``None``.
    """
    raw_code = exc.details.get("x64dbg_error_code")
    return raw_code if isinstance(raw_code, str) else None


def _coerce_address(value: object) -> int | None:
    """Coerce a raw plugin-supplied address payload into an integer.

    The C++ x64dbg bridge plugin currently formats every address through
    ``format_address`` which produces a hex string (e.g. ``"0xDEADBEEF"``).
    Older response paths and tests can also produce integers directly.
    Returns ``None`` for any value that cannot be parsed so callers can
    distinguish a missing/unparseable address from address ``0``.

    Args:
        value: Raw payload extracted from a plugin response field.

    Returns:
        int | None: Parsed integer address, or ``None`` when the value
        is neither an ``int`` nor a parseable hex/decimal string.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        if candidate := value.strip():
            return safe_int_from_str(candidate, base=0, context="x64dbg_safe_int_or_none")
        return None
    return None


@functools.cache
def _configure_win32_apis() -> None:
    """Configure ``restype``/``argtypes`` for every Win32 API used by this bridge.

    Without explicit ``restype`` / ``argtypes``, ``ctypes`` defaults to ``c_int`` for return values, which silently truncates 64-bit
    ``HANDLE`` pointers on 64-bit Python and corrupts subsequent ``ReadProcessMemory`` / ``CloseHandle`` / ``VirtualQueryEx`` calls.
    Centralising the declarations guarantees they are configured exactly once and that every call site sees consistent signatures.

    The ``functools.cache`` wrapper makes the body run at most once per process; the function is a no-op on non-Windows platforms.
    """
    if not _IS_WIN32:
        return

    kernel32 = ctypes.windll.kernel32
    advapi32 = ctypes.windll.advapi32

    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetCurrentProcess.argtypes = []

    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]

    kernel32.WriteProcessMemory.restype = wintypes.BOOL
    kernel32.WriteProcessMemory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]

    kernel32.VirtualAllocEx.restype = ctypes.c_void_p
    kernel32.VirtualAllocEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_size_t,
        wintypes.DWORD,
        wintypes.DWORD,
    ]

    kernel32.VirtualFreeEx.restype = wintypes.BOOL
    kernel32.VirtualFreeEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_size_t,
        wintypes.DWORD,
    ]

    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]

    kernel32.IsWow64Process.restype = wintypes.BOOL
    kernel32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]

    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]

    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.c_void_p]

    kernel32.Thread32Next.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.c_void_p]

    kernel32.Module32FirstW.restype = wintypes.BOOL
    kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]

    kernel32.Module32NextW.restype = wintypes.BOOL
    kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]

    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]

    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]

    kernel32.WaitNamedPipeW.restype = wintypes.BOOL
    kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]

    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]

    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

    kernel32.GetThreadContext.restype = wintypes.BOOL
    kernel32.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]

    kernel32.SuspendThread.restype = wintypes.DWORD
    kernel32.SuspendThread.argtypes = [wintypes.HANDLE]

    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]

    kernel32.GetCurrentThreadId.restype = wintypes.DWORD
    kernel32.GetCurrentThreadId.argtypes = []

    wow64_get_ctx = getattr(kernel32, "Wow64GetThreadContext", None)
    if wow64_get_ctx is not None:
        wow64_get_ctx.restype = wintypes.BOOL
        wow64_get_ctx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]


if _IS_WIN32:
    _configure_win32_apis()


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


def _open_process_and_extract_command_line(pid: int) -> str | None:
    """Open a process handle and extract its command line via the PEB.

    Args:
        pid: Process ID whose command line should be extracted.

    Returns:
        str | None: Command line string, or None if the process handle
        cannot be opened.
    """
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
        return _open_process_and_extract_command_line(pid)
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
        """NtQueryInformationProcess ProcessBasicInformation layout for PEB lookup."""

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

    The Windows ``UNICODE_STRING`` layout is ``Length`` (USHORT, in
    bytes), ``MaximumLength`` (USHORT, in bytes), then the buffer
    pointer. A well-formed string always has an even ``Length`` (UTF-16
    code units are 2 bytes) and ``Length <= MaximumLength``. Any
    deviation indicates a corrupt read - silently coercing odd lengths
    would mask the corruption. Reject malformed input via ``None`` and
    log at debug.

    Args:
        handle: Process handle.
        params_addr: Address of RTL_USER_PROCESS_PARAMETERS.
        ptr_size: Pointer size for the process.

    Returns:
        str | None: Command line string, or None on failure or
        malformed input.
    """
    if not _IS_WIN32:
        return None

    cmd_offset = CMD_LINE_OFFSET_64 if ptr_size == POINTER_SIZE_64 else CMD_LINE_OFFSET_32
    ustr_size = UNICODE_STRING_SIZE_64 if ptr_size == POINTER_SIZE_64 else UNICODE_STRING_SIZE_32
    ustr_bytes = _read_process_memory_block(handle, params_addr + cmd_offset, ustr_size)

    if not ustr_bytes or len(ustr_bytes) < ustr_size:
        return None

    length = int.from_bytes(ustr_bytes[:2], "little")
    maximum_length = int.from_bytes(ustr_bytes[2:4], "little")
    buf_offset = POINTER_SIZE_64 if ptr_size == POINTER_SIZE_64 else POINTER_SIZE_32
    buf_ptr = int.from_bytes(ustr_bytes[buf_offset : buf_offset + ptr_size], "little")

    if length <= 0 or buf_ptr == 0:
        return None

    if length % 2 != 0:
        _logger.debug(
            "command_line_unicode_string_odd_length",
            length=length,
            maximum_length=maximum_length,
            params_addr=hex(params_addr),
        )
        return None

    if length > maximum_length:
        _logger.debug(
            "command_line_unicode_string_length_exceeds_maximum",
            length=length,
            maximum_length=maximum_length,
            params_addr=hex(params_addr),
        )
        return None

    cmd_bytes = _read_process_memory_block(handle, buf_ptr, length)
    return cmd_bytes.decode("utf-16-le", errors="ignore") if cmd_bytes else None


class _X64DbgBridgeBase(DebuggerBridge):
    """Base class for X64DbgBridge: initialization, properties, and IPC plumbing.

    Owns the bridge state (subprocess, pipe client, attached PID/bitness,
    breakpoint/watchpoint registries, event-callback list, capability
    advertisement) and the shared low-level helpers used by the
    downstream mixins: pipe send/recv, command dispatch, step-waiter
    bookkeeping, event dispatch, system handle enumeration helpers,
    token privilege helpers, and the Windows snapshot helpers used by
    architecture detection and process-info population.

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
        RUN_TO_TIMEOUT: Maximum seconds to wait for the IP to reach a
            ``run_to`` target before treating the command as failed.
        RUN_TO_POLL_INTERVAL: Seconds between successive ``reg_get rip``
            polls during a ``run_to`` verification wait.
        VERIFY_TIMEOUT: Maximum seconds to poll a post-condition (label
            or comment readback, breakpoint enable/disable state,
            thread state transition, trace/animate ``is_running``
            flip, script error register, plugin presence) before
            raising ``ToolError`` from the F-0001 fire-and-forget
            wrappers (audit7.md F-0001).
        VERIFY_POLL_INTERVAL: Seconds between successive post-condition
            polls during a F-0001 verification wait.
        STEP_TIMEOUT_SECONDS: Maximum seconds to wait for the plugin's
            paused-event reply before a step coroutine times out (the
            audit6 F-0004 bound that replaces the legacy fixed sleep).
    """

    DEFAULT_PORT = 27015
    COMMAND_TIMEOUT = 10.0
    RUN_TO_TIMEOUT = 30.0
    RUN_TO_POLL_INTERVAL = 0.05
    VERIFY_TIMEOUT = 5.0
    VERIFY_POLL_INTERVAL = 0.05

    def __init__(self) -> None:
        """Initialize the X64DbgBridge instance."""
        super().__init__()
        self._x64dbg_path: Path | None = None
        self._process: DesktopProcess | None = None
        self._pipe_client: NamedPipeClient | None = None
        self._attached_pid: int | None = None
        self._port: int = self.DEFAULT_PORT
        self._binary_path: Path | None = None
        self._launch_args: str | None = None
        self._is_64bit: bool = True
        self._breakpoints: dict[int, BreakpointInfo] = {}
        self._next_bp_id: int = 1
        self._watchpoints: dict[int, WatchpointInfo] = {}
        self._next_wp_id: int = 1
        self._plugin_deployed: bool = False
        self.event_callbacks: list[Callable[[str, dict[str, Any]], None]] = []
        self._pipe_connect_lock: asyncio.Lock = asyncio.Lock()
        self._state_lock: threading.Lock = threading.Lock()
        self._process_handles: dict[int, int] = {}
        self._handle_cache_lock: threading.Lock = threading.Lock()
        self._step_waiters: list[asyncio.Future[int]] = []
        self._step_waiters_lock: threading.Lock = threading.Lock()
        self._capabilities = BridgeCapabilities(
            supports_static_analysis=True,
            supports_debugging=True,
            supports_dynamic_analysis=True,
            supports_patching=True,
            supports_scripting=True,
            supports_memory_access=True,
            supported_architectures=["x86", "x86_64"],
            supported_formats=["pe"],
        )
        _logger.info("x64dbg_bridge_initialized", bridge="x64dbg", port=self._port)

    @property
    def attached_pid(self) -> int | None:
        """PID of the currently attached process, or ``None`` if not attached.

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
        """Path to the loaded binary, or None if no binary is loaded.

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
        """Whether the bridge is operating in 64-bit mode.

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
        """Diagnostic information about plugin deployment readiness.

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
                " from src/x64dbg-plugin/"
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
        """Mapping of breakpoint IDs to their info.

        Returns:
            dict[int, BreakpointInfo]: Mapping of breakpoint IDs to their info.
        """
        return self._breakpoints

    @property
    def next_bp_id(self) -> int:
        """Next breakpoint ID to be assigned.

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
        """Mapping of watchpoint IDs to their info.

        Returns:
            dict[int, WatchpointInfo]: Mapping of watchpoint IDs to their info.
        """
        return self._watchpoints

    @property
    def next_wp_id(self) -> int:
        """Next watchpoint ID to be assigned.

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
        """Path to the x64dbg installation, or None if not found.

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
        """PID of the running debugger process, or None if not running.

        Returns:
            int | None: Process ID of the debugger, or None if not running.
        """
        return self._process.pid if self._process is not None else None

    @property
    def name(self) -> ToolName:
        """Tool name identifier for x64dbg.

        Returns:
            ToolName: ToolName.X64DBG
        """
        return ToolName.X64DBG

    @property
    def tool_definition(self) -> ToolDefinition:
        """Tool definition for LLM function calling.

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
                    name="x64dbg.restart",
                    description="Restart the currently loaded debuggee (native Ctrl+F2 semantics)",
                    parameters=[],
                    returns="Restart status",
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
                    name="x64dbg.disassemble_at",
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
                    name="x64dbg.get_entry_point",
                    description="Read the PE AddressOfEntryPoint of a loaded module (uses the attached binary by default)",
                    parameters=[
                        ToolParameter(
                            name="module_name",
                            type="string",
                            description="Module to query; uses the attached binary when omitted",
                            required=False,
                        ),
                    ],
                    returns="Dict with module, base_address, entry_point_rva, and entry_point_va",
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
                    returns=(
                        "Dict with PEB fields: address (PEB base, hex string), beingDebugged (int), "
                        "imageBaseAddress (hex string), ldr (hex string), processParameters (hex string), "
                        "ntGlobalFlag (int)"
                    ),
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
        self.state = BridgeState(
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
                self._publish_tool_state()
                _logger.info("x64dbg_found", path=str(tool_path))
                self._plugin_deployed = deploy_x64dbg_plugin(tool_path)
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

    async def _run_shutdown_phase(self, cleanup_errors: list[BaseException]) -> None:
        """Close the IPC connection and terminate the spawned debugger.

        Args:
            cleanup_errors: Mutable list that collects exceptions raised by
                any sub-phase so the caller can re-raise the first one
                after all stages have completed.
        """
        try:
            await self._close_connection()
        except (ToolError, OSError, RuntimeError) as exc:
            _logger.warning("x64dbg_close_connection_failed_during_shutdown", error=str(exc))
            cleanup_errors.append(exc)

        if self._process is not None:
            await self._terminate_debugger_process(cleanup_errors)

    async def _terminate_debugger_process(self, cleanup_errors: list[BaseException]) -> None:
        """Terminate the spawned x64dbg process and unregister it.

        Args:
            cleanup_errors: Mutable list that collects exceptions raised
                during termination, kill, or process-manager
                deregistration.
        """
        process = self._process
        if process is None:
            return
        pid = process.pid
        process_manager = ProcessManager.get_instance()
        try:
            await self._terminate_process_with_timeout(process, pid, cleanup_errors)
        except OSError as exc:
            _logger.warning("x64dbg_process_terminate_failed", pid=pid, error=str(exc))
            cleanup_errors.append(exc)
        finally:
            try:
                process_manager.unregister_external_pid(pid)
            except (RuntimeError, KeyError) as exc:
                _logger.warning("x64dbg_process_unregister_failed", pid=pid, error=str(exc))
                cleanup_errors.append(exc)
            try:
                process.close()
            except OSError as exc:
                _logger.warning("x64dbg_process_handle_close_failed", pid=pid, error=str(exc))
                cleanup_errors.append(exc)
            self._process = None

    @staticmethod
    async def _terminate_process_with_timeout(
        process: DesktopProcess,
        pid: int,
        cleanup_errors: list[BaseException],
    ) -> None:
        """Terminate a process and fall back to ``kill`` on timeout.

        Args:
            process: The hidden-desktop process handle representing the
                spawned x64dbg debugger.
            pid: Process ID, used for logging context.
            cleanup_errors: Mutable list that records exceptions raised
                by the fallback ``kill`` call.
        """
        process.terminate()
        try:
            await asyncio.wait_for(
                asyncio.to_thread(process.wait),
                timeout=5,
            )
        except TimeoutError:
            _logger.warning("x64dbg_process_terminate_timeout", pid=pid)
            try:
                process.kill()
            except OSError as kill_exc:
                _logger.warning("x64dbg_process_kill_failed", pid=pid, error=str(kill_exc))
                cleanup_errors.append(kill_exc)
            else:
                await asyncio.to_thread(process.wait)

    async def _run_shutdown_finalization(self, cleanup_errors: list[BaseException]) -> None:
        """Reset bookkeeping state and run base-class shutdown.

        Args:
            cleanup_errors: Mutable list that collects exceptions raised
                by handle release or the base shutdown coroutine.
        """
        self._attached_pid = None
        with self._state_lock:
            self._breakpoints.clear()
            self._watchpoints.clear()
        self._cancel_all_step_waiters()
        try:
            self._release_process_handles()
        except (OSError, RuntimeError) as exc:
            _logger.warning("x64dbg_release_handles_failed", error=str(exc))
            cleanup_errors.append(exc)
        try:
            await super().shutdown()
        except (ToolError, OSError, RuntimeError) as exc:
            _logger.warning("x64dbg_super_shutdown_failed", error=str(exc))
            cleanup_errors.append(exc)
        _logger.info("x64dbg_bridge_shutdown", bridge="x64dbg", errors=len(cleanup_errors))

    def _cancel_all_step_waiters(self) -> None:
        """Cancel every pending step waiter future during shutdown.

        Drains :attr:`_step_waiters` under the lock and signals each
        future with a cancellation so callers stuck inside
        :meth:`step_into` / :meth:`step_over` / :meth:`step_out` exit
        promptly when the bridge is being torn down.
        """
        with self._step_waiters_lock:
            waiters = self._step_waiters[:]
            self._step_waiters.clear()
        for waiter in waiters:
            try:
                loop = waiter.get_loop()
            except RuntimeError:
                _logger.warning("step_waiter_loop_unavailable_on_cancel", waiter=id(waiter))
                continue
            loop.call_soon_threadsafe(self._cancel_step_waiter_future, waiter)

    @staticmethod
    def _cancel_step_waiter_future(waiter: asyncio.Future[int]) -> None:
        """Cancel a single step waiter future on its own loop.

        Args:
            waiter: The future created by :meth:`_register_step_waiter`.
        """
        if not waiter.done():
            waiter.cancel()

    async def is_available(self) -> bool:
        """Check if x64dbg is available.

        Returns:
            bool: True if x64dbg can be used.
        """
        _logger.info("is_available_started")
        if self._x64dbg_path is None:
            return False

        x64_exe = self._x64dbg_path / "release" / "x64" / "x64dbg.exe"
        x32_exe = self._x64dbg_path / "release" / "x32" / "x32dbg.exe"

        return await asyncio.to_thread(x64_exe.exists) or await asyncio.to_thread(x32_exe.exists)

    async def _start_debugger(self, *, is_64bit: bool = True) -> None:
        """Start the x64dbg debugger process.

        Polls the named pipe with ``WaitNamedPipeW`` until the bridge
        plugin is ready to accept connections, up to
        ``_PIPE_READY_TIMEOUT_SECONDS`` seconds, rather than sleeping for
        a fixed interval.

        The bridge requires the Intellicrack x64dbg plugin to be
        deployed because every public RPC method routes through
        ``_send_pipe_command``. When the plugin is not present this
        method raises immediately rather than starting an x64dbg.exe
        whose UI would advertise as "connected" while every command
        raised at the point of invocation (audit6.md F-0013).

        Args:
            is_64bit: Whether to use 64-bit debugger.

        Raises:
            ToolError: If invoked on a non-Windows platform, the bridge
                plugin is not deployed, the configured x64dbg
                executable is missing, or the named pipe never becomes
                available.
        """
        if not _IS_WIN32:
            msg = f"x64dbg {_ERR_REQUIRES_WINDOWS}; cannot start the debugger on this OS"
            raise ToolError(msg, tool_name="x64dbg")

        if self._x64dbg_path is None:
            msg = "x64dbg path not set"
            raise ToolError(msg, tool_name="x64dbg")

        if not self._plugin_deployed:
            diag = str(self.plugin_status.get("diagnostic", ""))
            msg = (
                "x64dbg bridge plugin not deployed; refusing to start the debugger because every RPC tool "
                "would fail at the point of invocation"
            )
            if diag:
                msg = f"{msg}. {diag}"
            raise ToolError(msg, tool_name="x64dbg")

        if is_64bit:
            exe_path = self._x64dbg_path / "release" / "x64" / "x64dbg.exe"
        else:
            exe_path = self._x64dbg_path / "release" / "x32" / "x32dbg.exe"

        if not await asyncio.to_thread(exe_path.exists):
            msg = f"x64dbg executable not found: {exe_path}"
            raise ToolError(msg, tool_name="x64dbg")

        self._is_64bit = is_64bit
        _logger.info("x64dbg_starting", path=str(exe_path))

        # x64dbg is a Qt GUI application that calls ShowWindow(SW_SHOW)
        # unconditionally during startup, ignoring STARTUPINFO.wShowWindow, so a
        # SW_HIDE spawn still flashes the window until an in-process hook hides
        # it. Launching x64dbg on a dedicated desktop that is never made the
        # input desktop keeps every window it creates off-screen from the very
        # first frame - the Intellicrack x64dbg panel is the only user-facing
        # surface. INTELLICRACK_X64DBG_HEADLESS still tells the deployed plugin
        # to dismiss the modal dialogs x64dbg would otherwise block on while
        # driven headlessly. Standard handles are wired to NUL inside
        # spawn_on_hidden_desktop so a plugin that writes diagnostics cannot
        # deadlock on an undrained pipe (audit6.md F-0015).
        headless_env = dict(os.environ)
        headless_env[_HEADLESS_ENV_VAR] = "1"
        # The vendored x64dbg build only ships the Windows Qt platform
        # plugin, not the offscreen one. Intellicrack's own headless test
        # tooling sets an offscreen Qt platform on the parent environment,
        # and that setting must never leak into this child - it would make
        # x64dbg's own Qt platform-plugin init fail and hang before the
        # bridge plugin ever opens its pipe. A spawned GUI debugger must
        # always resolve its own bundled platform plugin, never inherit the
        # host application's headless one.
        headless_env.pop("QT_QPA_PLATFORM", None)
        headless_env.pop("QT_QPA_PLATFORM_PLUGIN_PATH", None)
        headless_env.pop("QT_PLUGIN_PATH", None)

        self._process = await asyncio.to_thread(
            spawn_on_hidden_desktop,
            exe_path,
            None,
            headless_env,
        )
        _logger.info("x64dbg_spawned", pid=self._process.pid, path=str(exe_path))

        process_manager = ProcessManager.get_instance()
        try:
            process_manager.register_external_pid(
                self._process.pid,
                name=f"x64dbg-{'x64' if is_64bit else 'x32'}",
                process_type=ProcessType.DEBUGGER,
                metadata={"binary": str(exe_path)},
            )
        except ValueError as exc:
            self._process.close()
            self._process = None
            msg = f"x64dbg exited immediately after launch: {exc}"
            raise ToolError(msg, tool_name="x64dbg") from exc

        await self._establish_bridge_connection()
        self._state.connected = True
        self._state.tool_running = True
        self._publish_tool_state()

    async def _establish_bridge_connection(self) -> None:
        """Wait for the bridge pipe, connect to it, and verify readiness.

        Runs immediately after x64dbg.exe is spawned so a plugin that
        was deployed but never actually loaded - for example an x64dbg
        SDK/ABI or architecture (x64 vs x32) mismatch - fails the
        :meth:`load` call outright with an actionable remediation
        message, rather than deferring the failure to the first debugger
        RPC such as :meth:`step_into`.

        Keeps the existing bounded :meth:`_wait_for_pipe_ready` poll and
        then establishes the real pipe connection so
        ``plugin_status["pipe_connected"]`` reflects a genuine, verified
        transport before any command is issued.

        Raises:
            ToolError: If the bridge pipe never becomes available, the
                connection cannot be established, or the pipe still
                reports as disconnected after connecting.
        """
        try:
            await self._wait_for_pipe_ready()
            await self._connect()
        except ToolError as exc:
            raise ToolError(
                self._bridge_pipe_failure_message(str(exc)),
                tool_name="x64dbg",
                details={"x64dbg_error_code": _X64DBG_ERR_PIPE_DISCONNECTED},
            ) from exc

        if not bool(self.plugin_status.get("pipe_connected")):
            raise ToolError(
                self._bridge_pipe_failure_message(None),
                tool_name="x64dbg",
                details={"x64dbg_error_code": _X64DBG_ERR_PIPE_DISCONNECTED},
            )

    @staticmethod
    def _bridge_pipe_failure_message(cause: str | None) -> str:
        """Build the actionable message for a bridge-pipe readiness failure.

        Args:
            cause: Underlying error text to append for diagnostics, or
                None when the failure is simply that the pipe reported
                as disconnected after the connect attempt.

        Returns:
            str: The remediation guidance, optionally suffixed with the
            underlying error, used as a :class:`ToolError` message.
        """
        message = _PLUGIN_PIPE_REMEDIATION
        if cause:
            message = f"{message} Underlying error: {cause}"
        return message

    _PIPE_READY_TIMEOUT_SECONDS: float = 15.0
    _PIPE_READY_POLL_MS: int = 500
    _PIPE_NAME: str = r"\\.\pipe\intellicrack_x64dbg"

    async def _wait_for_pipe_ready(self) -> None:
        r"""Poll the named pipe via ``WaitNamedPipeW`` until it is ready.

        x64dbg.exe is a Windows-only debugger and the bridge plugin
        publishes its IPC channel over a Win32 named pipe at
        ``\\\\.\\pipe\\intellicrack_x64dbg``. Named pipes do not exist
        on POSIX platforms, so this method refuses to run on non-Windows
        rather than sleeping for a hard-coded interval and reporting
        readiness when the pipe never existed - a misclassification
        that would cascade into a misleading ``CreateFileW`` failure
        downstream (audit6.md F-0017).

        On Windows the call loops ``WaitNamedPipeW`` with a small
        per-iteration timeout until the pipe is available or the overall
        timeout elapses.

        Raises:
            ToolError: If invoked on a non-Windows platform, or if the
                pipe never becomes available inside the overall timeout
                window.
        """
        if not _IS_WIN32:
            msg = f"x64dbg {_ERR_REQUIRES_WINDOWS}; named pipes are unavailable on this OS"
            raise ToolError(msg, tool_name="x64dbg")

        kernel32 = ctypes.windll.kernel32
        wait_fn = kernel32.WaitNamedPipeW

        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._PIPE_READY_TIMEOUT_SECONDS

        while True:
            ready = await asyncio.to_thread(wait_fn, self._PIPE_NAME, self._PIPE_READY_POLL_MS)
            if ready:
                _logger.debug("x64dbg_pipe_ready")
                return
            if loop.time() >= deadline:
                msg = f"Timed out waiting for x64dbg bridge pipe {self._PIPE_NAME!r} to become ready"
                raise ToolError(msg, tool_name="x64dbg")

    async def _connect(self) -> None:
        """Connect to x64dbg via named pipe.

        Serialises every caller on ``_pipe_connect_lock`` and always
        discards any existing pipe client before opening a fresh one
        (unless that client is already verified connected). The x64dbg
        bridge plugin hosts a single-instance named pipe, so two coroutines
        racing to reconnect it concurrently - a command discovering a dead
        connection at the same moment as the register/stack panel's
        periodic refresh, or a fresh ``load()`` racing an in-flight command
        - would otherwise either collide on ``ERROR_PIPE_BUSY`` (231) or
        silently reuse a stale handle left over from a previous x64dbg
        process generation, both of which starve the server's one pipe
        instance until every subsequent connect attempt times out with
        ``ERROR_SEM_TIMEOUT`` (121) (F16). Always replacing the client here
        - rather than only when it is ``None`` - also guarantees that a
        fresh ``load()`` never reuses a handle from a previous session.

        Raises:
            ToolError: If connection fails.
        """
        async with self._pipe_connect_lock:
            if self._pipe_client is not None and self._pipe_client.is_connected:
                return
            try:
                await self._reconnect_pipe_client_locked()
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

    async def _reconnect_pipe_client_locked(self) -> None:
        """Discard any existing pipe client and connect a fresh one.

        Callers must hold ``_pipe_connect_lock`` for the duration of this
        call; it is a private helper for :meth:`_connect` split out purely
        to keep that method's exception-translation ``try`` block small.
        Any exception from the underlying ``NamedPipeClient.close``/
        ``connect`` calls propagates to the caller unmodified so
        :meth:`_connect` can classify and wrap it.
        """
        if self._pipe_client is not None:
            await self._pipe_client.close()
        self._pipe_client = NamedPipeClient(
            PipeConfig(pipe_name=self._PIPE_NAME),
            event_handler=self._handle_event,
        )
        await self._pipe_client.connect()
        self._pipe_client.set_event_handler(self._handle_event)
        _logger.info("x64dbg_pipe_connected", bridge="x64dbg")

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
        _logger.info("event_callback_registered", callback=str(callback))
        self.event_callbacks.append(callback)

    def unregister_event_callback(
        self,
        callback: Callable[[str, dict[str, Any]], None],
    ) -> None:
        """Remove a previously registered event callback.

        Args:
            callback: The callback to remove.
        """
        if callback in self.event_callbacks:
            self.event_callbacks.remove(callback)
        else:
            _logger.debug("event_callback_not_found_for_removal", callback=str(callback))

    def _handle_event(self, message: dict[str, Any]) -> None:
        """Handle asynchronous debug events from x64dbg.

        ``_handle_event`` is invoked from the named-pipe client's reader
        background thread (via the asyncio default executor) while
        coroutines on the main loop concurrently mutate ``_breakpoints``
        and ``_watchpoints``. ``_state_lock`` serialises reads and
        writes against the breakpoint/watchpoint registries so the
        ``hit_count`` increment, dictionary lookup, and value iteration
        cannot race a coroutine that simultaneously inserts, deletes,
        or rebuilds a registry entry. Because this runs in an executor
        thread, any interaction with asyncio futures must use
        ``loop.call_soon_threadsafe``. ``paused`` events resolve any
        pending step waiters with the reported instruction pointer
        (audit6.md F-0004); the pause-emitting plugin extracts the IP
        via ``Script::Register::GetCIP``. ``breakpoint`` and
        ``watchpoint`` events also pause the debuggee, so those resolve
        step waiters as well to avoid hanging when a step lands on a
        live breakpoint.

        Args:
            message: Event payload.
        """
        event_type = str(message.get("event", ""))
        if event_type == "breakpoint":
            addr = self._coerce_address(message.get("address"))
            with self._state_lock:
                bp = self._breakpoints.get(addr)
                if bp is not None:
                    bp.hit_count += 1
            self._resolve_step_waiters(addr)
        elif event_type == "watchpoint":
            addr = self._coerce_address(message.get("address"))
            with self._state_lock:
                for wp in self._watchpoints.values():
                    if wp.address == addr:
                        wp.hit_count += 1
                        break
            self._resolve_step_waiters(addr)
        elif event_type == "paused":
            addr = self._coerce_address(message.get("address"))
            self._resolve_step_waiters(addr)

        for cb in self.event_callbacks:
            try:
                cb(event_type, message)
            except (RuntimeError, TypeError, ValueError):
                _logger.warning("event_callback_error", event_type=event_type, exc_info=True)

    @staticmethod
    def _coerce_address(raw: object) -> int:
        """Coerce a JSON address payload to an integer.

        The plugin emits addresses as ``"0xDEADBEEF"`` strings but legacy
        builds and unit tests sometimes send raw integers. Both forms
        are accepted; everything else falls back to ``0``.

        Args:
            raw: The raw payload from the event message.

        Returns:
            int: The address as an integer, or ``0`` if it cannot be
            parsed.
        """
        if isinstance(raw, bool):
            return 0
        if isinstance(raw, int):
            return raw
        if isinstance(raw, str):
            parsed = safe_int_from_str(raw, base=0, context="x64dbg_coerce_address", default=0)
            return 0 if parsed is None else parsed
        return 0

    def _resolve_step_waiters(self, address: int) -> None:
        """Wake every coroutine awaiting the next pause event.

        Drains the waiter list under the lock and schedules each
        future's ``set_result`` on the future's own event loop using
        ``loop.call_soon_threadsafe``. A step always completes by
        x64dbg pausing the target, so resolving on every paused-class
        event (paused / breakpoint / watchpoint) lets the corresponding
        step coroutine return the new instruction pointer rather than
        racing a hard-coded sleep (audit6.md F-0004).

        Args:
            address: Instruction pointer reported by the plugin in the
                paused event payload.
        """
        with self._step_waiters_lock:
            waiters = self._step_waiters[:]
            self._step_waiters.clear()
        for waiter in waiters:
            try:
                loop = waiter.get_loop()
            except RuntimeError:
                _logger.warning("step_waiter_loop_unavailable_on_resolve", waiter=id(waiter))
                continue
            loop.call_soon_threadsafe(self._set_step_waiter_result, waiter, address)

    @staticmethod
    def _set_step_waiter_result(waiter: asyncio.Future[int], address: int) -> None:
        """Set the result of a step waiter future if it is still pending.

        Args:
            waiter: The future created by :meth:`_register_step_waiter`.
            address: Instruction pointer to deliver as the result.
        """
        if not waiter.done():
            waiter.set_result(address)

    def _register_step_waiter(self) -> asyncio.Future[int]:
        """Allocate a future that will be resolved by the next pause event.

        Returns:
            asyncio.Future[int]: A future bound to the running event
            loop whose result will be the instruction pointer reported
            in the next paused/breakpoint/watchpoint event.
        """
        loop = asyncio.get_running_loop()
        future: asyncio.Future[int] = loop.create_future()
        with self._step_waiters_lock:
            self._step_waiters.append(future)
        return future

    def _cancel_step_waiter(self, waiter: asyncio.Future[int]) -> None:
        """Remove a waiter from the pending list.

        Used when a step coroutine times out so a stale future is not
        held by ``_step_waiters`` indefinitely.

        Args:
            waiter: The future to remove.
        """
        with self._step_waiters_lock:
            if waiter in self._step_waiters:
                self._step_waiters.remove(waiter)
            else:
                _logger.debug("step_waiter_dequeue_noop", waiter=id(waiter))

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
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={"x64dbg_error_code": _X64DBG_ERR_PLUGIN_UNAVAILABLE, "command": command},
            )

        if self._pipe_client is None or not self._pipe_client.is_connected:
            _logger.info("x64dbg_pipe_reconnecting", command=command)
            await self._connect()

        if self._pipe_client is None:
            msg = "Named pipe client not available"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={"x64dbg_error_code": _X64DBG_ERR_PIPE_DISCONNECTED, "command": command},
            )

        try:
            response = await asyncio.wait_for(
                self._pipe_client.send_command(command, params),
                timeout=self.COMMAND_TIMEOUT,
            )
        except TimeoutError as e:
            _logger.warning("x64dbg_command_timeout", command=command, error=str(e))
            msg = f"Command {command} timed out"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={"x64dbg_error_code": _X64DBG_ERR_TIMEOUT, "command": command},
            ) from e
        except ToolError as exc:
            raise ToolError(
                str(exc),
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _classify_legacy_error(str(exc)),
                    "command": command,
                },
            ) from exc

        if not response.get("success", False):
            error = response.get("error", "Command failed")
            msg = str(error)
            raw_code = response.get("code")
            classified = str(raw_code) if isinstance(raw_code, str) and raw_code else _classify_legacy_error(msg)
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={"x64dbg_error_code": classified, "command": command},
            )
        data: str | int | float | bool | dict[str, object] | list[object] | None = response.get("result")
        return data

    @staticmethod
    def _is_recoverable_pipe_error(exc: ToolError) -> bool:
        """Return True only when the structured error code indicates a missing RPC.

        Replaces the legacy substring-matching classifier (audit6.md
        F-0008/F-0028). The bridge attaches a structured
        ``x64dbg_error_code`` to every ``ToolError`` raised from
        ``_send_pipe_command``; this helper inspects that code and
        returns ``True`` only for codes that are genuinely recoverable
        via the alternative ``_send_command`` console-script path.

        A "pipe not connected" or "plugin unavailable" failure is
        explicitly *not* recoverable because the script-command
        fallback travels the same broken pipe; treating it as
        recoverable would mask the underlying transport failure
        (F-0028).

        Args:
            exc: The raised ``ToolError`` to classify.

        Returns:
            bool: True when the underlying failure is "RPC name unknown
            on this plugin build", indicating the script-command
            fallback may legitimately succeed.
        """
        code = _x64dbg_error_code(exc)
        return False if code is None else code in _RECOVERABLE_RPC_MISSING_CODES

    @staticmethod
    def _is_local_fallback_eligible(exc: ToolError) -> bool:
        """Return True when a non-pipe local fallback is appropriate.

        Some bridge methods (e.g. :meth:`disassemble_at`) have a local
        fallback that does not travel the pipe at all - it uses an
        in-process Python library such as Capstone. For those methods
        any pipe/plugin-side failure may legitimately be retried via
        the local path, including transport-level failures that would
        be non-recoverable for fallbacks routed through
        :meth:`_send_command`.

        Genuine remote errors (e.g. malformed input, semantic failure)
        still propagate so the caller learns about real failures.

        Args:
            exc: The raised ``ToolError`` to classify.

        Returns:
            bool: True when the failure is transport- or
            availability-related and a local fallback may be tried.
        """
        code = _x64dbg_error_code(exc)
        if code is None:
            return False
        return code not in {_X64DBG_ERR_REMOTE, _X64DBG_ERR_PROTOCOL_VIOLATION}

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
            _logger.warning("send_command_no_process", command=command)
            raise ToolError(msg)

        result = await self._send_pipe_command("exec", {"command": command})
        if isinstance(result, str):
            return result
        if isinstance(result, dict):
            output = result.get("output")
            return str(output) if output is not None else ""
        return ""

    def _register_attached_pid(self, pid: int) -> None:
        """Record ``pid`` as the currently attached or debugged process.

        Shared by :meth:`attach`, :meth:`load`, and :meth:`restart` so
        every path that learns a target process id updates the same
        state the process-inspection commands (``read_memory``,
        ``get_memory_regions``, ``get_modules``, ``get_threads``,
        ``get_process_info``) consult via ``self._attached_pid``.

        Args:
            pid: Process id of the attached or newly launched debuggee.
        """
        self._attached_pid = pid
        self._state.target_pid = pid
        self._state.process_attached = True

    async def _await_debuggee_pid(self) -> int | None:
        """Poll ``reg_get $pid`` until the debuggee reports a real process id.

        ``InitDebug`` (used by :meth:`load` and :meth:`restart`) returns
        as soon as the command is queued, not once the debuggee process
        actually exists. Querying ``$pid`` immediately afterwards can
        race the debug loop and observe ``0`` (or a transient pipe
        failure) before the process has been created, which previously
        left ``self._attached_pid`` permanently unset and made every
        process-inspection command report "not attached" even though
        the debuggee was running. Polling for up to
        :attr:`VERIFY_TIMEOUT` absorbs that race instead of giving up
        after a single attempt.

        Returns:
            int | None: The debuggee's process id once ``reg_get``
            reports a positive value, or ``None`` if no positive pid
            was observed before the deadline elapsed.

        Raises:
            ToolError: If ``reg_get`` fails with a pipe error that
                :meth:`_is_recoverable_pipe_error` classifies as
                non-recoverable.
        """
        deadline = asyncio.get_running_loop().time() + self.VERIFY_TIMEOUT
        while True:
            try:
                pid_result = await self._send_pipe_command("reg_get", {"name": "$pid"})
            except ToolError as exc:
                if not self._is_recoverable_pipe_error(exc):
                    raise
                _logger.warning("pid_capture_retry_failed", error=str(exc))
            else:
                if isinstance(pid_result, str):
                    pid_val = int(pid_result, 0)
                    if pid_val > 0:
                        return pid_val
            if asyncio.get_running_loop().time() >= deadline:
                return None
            await asyncio.sleep(self.VERIFY_POLL_INTERVAL)

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
            _logger.warning("x64dbg_load_path_missing", binary_path=str(path))
            raise ToolError(msg)

        self._binary_path = await asyncio.to_thread(path.resolve)
        self._launch_args = args

        is_64bit = self._detect_architecture(path)

        if self._process is None:
            await self._start_debugger(is_64bit=is_64bit)

        cmd = f'InitDebug "{path.as_posix()}"'
        if args:
            cmd += f', "{args}"'

        await self._send_command(cmd)

        pid_val = await self._await_debuggee_pid()
        if pid_val is not None:
            self._register_attached_pid(pid_val)

        self._state.connected = True
        self._state.tool_running = True
        self._state.binary_loaded = True
        self._state.target_path = self._binary_path
        self._publish_tool_state()

        _logger.info("x64dbg_binary_loaded", path=path.name)

    @staticmethod
    def _detect_architecture(path: Path) -> bool:
        r"""Detect whether a binary should be opened with x64dbg or x32dbg.

        Inspects the PE COFF ``Machine`` field directly so the result is
        derived from the binary header rather than guessed. Only the two
        x86 ``Machine`` codes that the x64dbg / x32dbg pair can debug
        are accepted; every other failure mode (I/O error, truncated
        image, missing ``MZ`` / ``PE\\x00\\x00`` signatures, or a
        non-x86 ``Machine`` such as ARM/ARM64/IA64) raises
        :class:`ToolError` so the caller cannot launch the wrong
        debugger and silently fail to attach (audit6.md F-0023).

        Args:
            path: Path to binary.

        Returns:
            bool: ``True`` for an x86_64 PE, ``False`` for an x86 PE.

        Raises:
            ToolError: If the file cannot be read, is too short to hold
                a DOS+PE header, lacks the ``MZ`` or ``PE\\x00\\x00``
                signatures, or has a ``Machine`` value other than
                :data:`IMAGE_FILE_MACHINE_I386` /
                :data:`IMAGE_FILE_MACHINE_AMD64`.
        """
        try:
            data = path.read_bytes()
        except OSError as exc:
            _logger.warning("x64dbg_architecture_detection_io_failed", path=str(path), error=str(exc))
            msg = f"x64dbg cannot read PE header for {path}: {exc}"
            raise ToolError(msg, tool_name="x64dbg") from exc

        if len(data) < PE_MAGIC_OFFSET + 4:
            msg = f"x64dbg cannot detect architecture: {path} is too short to be a PE image"
            raise ToolError(msg, tool_name="x64dbg")

        if data[:2] != b"MZ":
            msg = f"x64dbg cannot detect architecture: {path} is not a PE image (missing MZ signature)"
            raise ToolError(msg, tool_name="x64dbg")

        pe_offset = int.from_bytes(data[PE_HEADER_OFFSET:PE_MAGIC_OFFSET], "little")

        if pe_offset <= 0 or len(data) < pe_offset + 6:
            msg = f"x64dbg cannot detect architecture: {path} has truncated or invalid e_lfanew={pe_offset:#x}"
            raise ToolError(msg, tool_name="x64dbg")

        if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            msg = f"x64dbg cannot detect architecture: {path} is missing the PE\\x00\\x00 signature at {pe_offset:#x}"
            raise ToolError(msg, tool_name="x64dbg")

        machine = int.from_bytes(data[pe_offset + 4 : pe_offset + 6], "little")

        if machine == PE64_MACHINE:
            return True
        if machine == PE32_MACHINE:
            return False

        msg = (
            f"x64dbg does not support PE Machine {machine:#06x} in {path}; "
            f"only IMAGE_FILE_MACHINE_I386 ({PE32_MACHINE:#06x}) and "
            f"IMAGE_FILE_MACHINE_AMD64 ({PE64_MACHINE:#06x}) are debuggable"
        )
        raise ToolError(msg, tool_name="x64dbg")

    async def attach(self, pid: int) -> None:
        """Attach to a running process.

        Detects the target process architecture and starts the matching
        debugger variant (x64dbg or x32dbg). When the architecture
        cannot be determined the call refuses rather than guessing
        64-bit and silently launching the wrong debugger (audit6.md
        F-0018).

        Args:
            pid: Process ID.

        Raises:
            ToolError: If the target process architecture cannot be
                determined (non-Windows host, ``OpenProcess`` denied,
                ``IsWow64Process`` failed, etc.).
        """
        _logger.info("x64dbg_attaching", pid=pid)
        self._release_process_handles()
        is_64 = await asyncio.to_thread(self._detect_process_arch, pid)
        if is_64 is None:
            msg = (
                f"x64dbg cannot detect architecture for pid {pid}; refusing to launch a debugger that may not "
                "match the target. Re-run with elevated privileges, or attach to a process that grants "
                "PROCESS_QUERY_INFORMATION."
            )
            raise ToolError(msg, tool_name="x64dbg")

        if self._process is None:
            await self._start_debugger(is_64bit=is_64)

        await self._send_command(f"attach {pid}")
        self._register_attached_pid(pid)

        self._state.connected = True
        self._state.tool_running = True
        self._publish_tool_state()
        _logger.info("x64dbg_attached", pid=pid)

    @classmethod
    def _detect_process_arch(cls, pid: int) -> bool | None:
        """Detect whether a running process is 64-bit.

        Returns ``True`` for native x86_64 processes, ``False`` for
        WOW64 (32-bit) processes, and ``None`` for every error mode
        (non-Windows host, ``OpenProcess`` denied, ``IsWow64Process``
        failed, or no x64dbg-debuggable architecture). Returning
        ``None`` instead of defaulting to ``True`` prevents the bridge
        from launching x64dbg.exe against a 32-bit target it cannot
        attach to, so :meth:`attach` can surface the failure to the
        caller (audit6.md F-0018).

        Args:
            pid: Process ID of the target process.

        Returns:
            bool | None: ``True`` for x86_64, ``False`` for x86, or
            ``None`` if the architecture could not be determined.
        """
        if not _IS_WIN32:
            _logger.debug("x64dbg_arch_detect_skipped_non_windows", pid=pid)
            return None
        try:
            return cls._open_process_and_detect_arch(pid)
        except (OSError, AttributeError) as exc:
            _logger.warning("x64dbg_arch_detect_unexpected_error", pid=pid, error=str(exc))
            return None

    @classmethod
    def _open_process_and_detect_arch(cls, pid: int) -> bool | None:
        """Open the target process and read its WOW64 status.

        Args:
            pid: Process ID of the target process.

        Returns:
            bool | None: ``True`` for native x86_64, ``False`` for
            WOW64, or ``None`` if the handle could not be opened or
            ``IsWow64Process`` reported failure.
        """
        kernel32 = ctypes.windll.kernel32
        inherit_handle = False
        handle = kernel32.OpenProcess(WIN_PROCESS_QUERY_INFORMATION, inherit_handle, pid)
        if not handle:
            last_error = ctypes.get_last_error() if hasattr(ctypes, "get_last_error") else 0
            _logger.warning(
                "x64dbg_arch_detect_open_process_failed",
                pid=pid,
                last_error=last_error,
            )
            return None
        try:
            return cls._read_iswow64_status(handle, pid)
        finally:
            kernel32.CloseHandle(handle)

    @staticmethod
    def _read_iswow64_status(handle: int, pid: int) -> bool | None:
        """Invoke ``IsWow64Process`` on an open process handle.

        Args:
            handle: Process handle previously returned by
                ``OpenProcess`` with ``PROCESS_QUERY_INFORMATION``.
            pid: Process ID, used only for logging context.

        Returns:
            bool | None: ``True`` if the process is a native 64-bit
            process, ``False`` if it is WOW64, or ``None`` when
            ``IsWow64Process`` failed.
        """
        kernel32 = ctypes.windll.kernel32
        is_wow64 = ctypes.c_int(0)
        ok: int = kernel32.IsWow64Process(handle, ctypes.byref(is_wow64))
        if not ok:
            last_error = ctypes.get_last_error() if hasattr(ctypes, "get_last_error") else 0
            _logger.warning(
                "x64dbg_arch_detect_iswow64_failed",
                pid=pid,
                last_error=last_error,
            )
            return None
        return not bool(is_wow64.value)

    async def detach(self) -> None:
        """Detach from current process."""
        _logger.info("x64dbg_detach_started", pid=self._attached_pid)
        await self._send_command("detach")
        self._release_process_handles()
        self._attached_pid = None

        self._state.connected = True
        self._state.tool_running = True
        self._state.process_attached = False
        self._state.target_pid = None
        self._publish_tool_state()

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

    STEP_TIMEOUT_SECONDS: float = 30.0

    async def _dispatch_step_and_await(
        self,
        command: str,
        waiter: asyncio.Future[int],
    ) -> int:
        """Send a step command and wait for the matching paused event.

        Args:
            command: The step command (``step_into`` / ``step_over`` /
                ``step_out``).
            waiter: Future previously registered via
                :meth:`_register_step_waiter` that will resolve with the
                event instruction pointer when the plugin emits the
                paused notification.

        Returns:
            int: Instruction pointer reported by the paused event.

        Raises:
            ToolError: If the step did not complete within
                :attr:`STEP_TIMEOUT_SECONDS`.
        """
        await self._send_pipe_command(command)
        try:
            return await asyncio.wait_for(waiter, timeout=self.STEP_TIMEOUT_SECONDS)
        except TimeoutError as exc:
            self._cancel_step_waiter(waiter)
            _logger.warning(
                "x64dbg_step_timeout",
                command=command,
                timeout_s=self.STEP_TIMEOUT_SECONDS,
                error=str(exc),
            )
            msg = (
                f"x64dbg {command} did not complete within {self.STEP_TIMEOUT_SECONDS:.0f}s; "
                "the debuggee may be blocked in a syscall, on a long-running call, or hung"
            )
            raise ToolError(msg, tool_name="x64dbg") from exc

    async def _await_step_complete(self, command: str) -> int:
        """Send a step command and await the resulting paused event.

        Registers a waiter future before issuing the RPC so a paused
        event that fires immediately (for example, a step that lands on
        an existing breakpoint) cannot race past us. Reads the
        instruction pointer from a register fetch only after the event
        reports completion, masking the result to the architecture's
        pointer width. This replaces the previous hard-coded
        ``asyncio.sleep(0.05)`` (audit6.md F-0004), which was both too
        short for stepping into syscalls/long calls and unsynchronised
        with x64dbg's actual paused state.

        Args:
            command: One of ``step_into`` / ``step_over`` / ``step_out``.

        Returns:
            int: Instruction pointer after the step completes, masked to
            32 bits for x86 targets.

        Raises:
            BaseException: Re-raised after cancelling the step waiter
                when :meth:`_dispatch_step_and_await` raises (most
                notably :class:`ToolError` on timeout, but the bare
                re-raise also preserves cancellations and any other
                framework-level errors so callers see the original
                cause).
        """
        waiter = self._register_step_waiter()
        try:
            event_ip = await self._dispatch_step_and_await(command, waiter)
        except BaseException:
            self._cancel_step_waiter(waiter)
            _logger.debug("x64dbg_step_cancelled", command=command, exc_info=True)
            raise

        try:
            regs = await self.get_registers()
        except ToolError as exc:
            _logger.warning(
                "x64dbg_step_register_read_failed_after_event",
                command=command,
                event_ip=hex(event_ip),
                error=str(exc),
            )
            return event_ip if self._is_64bit else event_ip & DWORD_MASK
        return regs.rip if self._is_64bit else regs.rip & DWORD_MASK

    async def step_into(self) -> int:
        """Single step into.

        Awaits the plugin's ``paused`` event so the returned instruction
        pointer reflects the post-step CPU state rather than racing a
        hard-coded delay (audit6.md F-0004). Propagates any exception
        raised by :meth:`_await_step_complete`, including ``ToolError``
        when the step does not complete within
        :attr:`STEP_TIMEOUT_SECONDS`.

        Returns:
            int: New instruction pointer.
        """
        _logger.debug("step_into_executing")
        return await self._await_step_complete("step_into")

    async def step_over(self) -> int:
        """Single step over.

        Awaits the plugin's ``paused`` event so the returned instruction
        pointer reflects the post-step CPU state (audit6.md F-0004).
        Propagates any exception raised by :meth:`_await_step_complete`,
        including ``ToolError`` when the step does not complete within
        :attr:`STEP_TIMEOUT_SECONDS`.

        Returns:
            int: New instruction pointer.
        """
        _logger.debug("step_over_executing")
        return await self._await_step_complete("step_over")

    async def step_out(self) -> int:
        """Step out of current function.

        Awaits the plugin's ``paused`` event so the returned instruction
        pointer reflects the post-step CPU state (audit6.md F-0004).
        Propagates any exception raised by :meth:`_await_step_complete`,
        including ``ToolError`` when the step does not complete within
        :attr:`STEP_TIMEOUT_SECONDS`.

        Returns:
            int: New instruction pointer.
        """
        _logger.debug("step_out_executing")
        return await self._await_step_complete("step_out")

    async def set_breakpoint(
        self,
        address: int,
        bp_type: BreakpointType = "software",
        condition: str | None = None,
    ) -> int:
        """Set a breakpoint and verify the debugger actually applied it.

        x64dbg breakpoints are uniquely identified by their target
        address - the ``BPMAP`` returned by ``DbgGetBpList`` keys each
        entry by ``addr`` and exposes no separate numeric id, so the
        breakpoint id round-tripped to the caller is the address
        (audit6.md F-0002). After the plugin reports a successful
        ``bp_set``, the local registry is only updated once a follow-up
        ``bp_list`` confirms the breakpoint really exists at ``address``
        (audit6.md F-0001); this rejects the case where the textual
        x64dbg console command parses but the debugger never installs
        the breakpoint (e.g. unmapped address, type rejected for the
        active target). When ``condition`` is supplied, ``bpcond`` is
        issued after the breakpoint is verified so the conditional
        expression is honoured even when the plugin ignores the
        in-payload ``condition`` field (audit6.md F-0026).

        Args:
            address: Breakpoint address.
            bp_type: Type of breakpoint.
            condition: Optional conditional expression.

        Returns:
            int: Native breakpoint id (the breakpoint address) used by
            x64dbg's ``BPMAP`` keying.

        Raises:
            ToolError: When the plugin cannot apply the breakpoint or
                the post-condition ``bp_list`` lookup fails to find it.
        """
        _logger.info("set_breakpoint_started", address=hex(address), type=bp_type, has_condition=condition is not None)
        await self._send_pipe_command(
            "bp_set",
            {
                "address": hex(address),
                "type": bp_type,
                "condition": condition,
            },
        )

        verification_state = await self._verify_breakpoint_present(address, bp_type)
        if verification_state is False:
            msg = f"x64dbg accepted bp_set but no {bp_type} breakpoint exists at {hex(address)}"
            raise ToolError(msg, tool_name="x64dbg")

        if condition is not None:
            await self._send_pipe_command(
                "exec",
                {"command": f'bpcond {hex(address)}, "{condition}"'},
            )

        with self._state_lock:
            self._breakpoints[address] = BreakpointInfo(
                id=address,
                address=address,
                bp_type=bp_type,
                enabled=True,
                hit_count=0,
                condition=condition,
            )

        _logger.info("breakpoint_set", type=bp_type, address=hex(address), native_id=hex(address))
        return address

    async def _verify_breakpoint_present(self, address: int, bp_type: BreakpointType) -> bool | None:
        """Confirm the plugin's ``bp_list`` reports a breakpoint at ``address``.

        Args:
            address: Address that ``bp_set`` was just issued for.
            bp_type: Expected breakpoint type for the verification.

        Returns:
            bool | None: ``True`` when the active breakpoint set
            contains a matching entry; ``False`` when ``bp_list`` was
            successfully returned but no entry matches; ``None`` when
            the plugin reports ``bp_list`` as an unknown command (older
            plugin builds) so the caller can skip verification rather
            than fail.

        Raises:
            ToolError: When ``bp_list`` returns a non-list payload
                (protocol violation that the caller must surface).
        """
        try:
            result = await self._send_pipe_command("bp_list")
        except ToolError as exc:
            if _x64dbg_error_code(exc) == _X64DBG_ERR_UNKNOWN_COMMAND:
                _logger.warning(
                    "breakpoint_verification_skipped_no_bp_list",
                    address=hex(address),
                )
                return None
            _logger.warning("bp_set_verify_list_failed", address=hex(address), error=str(exc))
            raise

        if not isinstance(result, list):
            msg = f"set_breakpoint verification: bp_list returned {type(result).__name__}, expected list"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_PROTOCOL_VIOLATION,
                    "address": hex(address),
                },
            )

        type_aliases: dict[BreakpointType, set[str]] = {
            "software": {"software", "normal"},
            "hardware": {"hardware"},
            "memory": {"memory"},
        }
        accepted_types = type_aliases[bp_type]

        for bp_entry in result:
            if not _is_str_obj_dict(bp_entry):
                continue
            entry_addr_raw = bp_entry.get("address")
            entry_addr = _coerce_address(entry_addr_raw)
            if entry_addr != address:
                continue
            entry_type = bp_entry.get("type")
            if isinstance(entry_type, str) and entry_type not in accepted_types:
                continue
            return True
        return False

    async def _verify_breakpoint_applied(self, address: int) -> None:
        """Confirm via ``bp_list`` that a breakpoint exists at ``address``.

        Issues a single ``bp_list`` RPC and matches the response
        against ``address`` using the same address-extraction rules as
        :meth:`get_breakpoints`. Falls back gracefully when the plugin
        build does not implement ``bp_list``: in that case there is no
        secondary source of truth and the bridge has to trust the
        ``bp_set`` response, so verification is skipped with a debug
        log rather than raising.

        Args:
            address: Breakpoint address that ``bp_set`` was issued for.

        Raises:
            ToolError: If ``bp_list`` succeeds but does not include
                ``address`` in its returned list.
        """
        try:
            result = await self._send_pipe_command("bp_list")
        except ToolError as exc:
            if _x64dbg_error_code(exc) == _X64DBG_ERR_UNKNOWN_COMMAND:
                _logger.warning(
                    "breakpoint_verification_skipped_no_bp_list",
                    address=hex(address),
                )
                return
            log_passthrough(
                _logger,
                "verify_breakpoint_applied_passthrough",
                exc,
                bridge="x64dbg",
                address=hex(address),
                x64dbg_error_code=_x64dbg_error_code(exc),
            )
            raise
        if not isinstance(result, list):
            msg = f"set_breakpoint verification: bp_list returned {type(result).__name__}, expected list"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_PROTOCOL_VIOLATION,
                    "address": hex(address),
                },
            )
        for entry in result:
            if not _is_str_obj_dict(entry):
                continue
            raw_addr = entry.get("address")
            entry_addr: int | None = None
            if isinstance(raw_addr, int):
                entry_addr = raw_addr
            elif isinstance(raw_addr, str):
                entry_addr = safe_int_from_str(raw_addr, base=0, context="x64dbg_verify_breakpoint_applied")
                if entry_addr is None:
                    continue
            if entry_addr == address:
                return
        msg = f"set_breakpoint verification failed: address {hex(address)} not present in bp_list after bp_set"
        raise ToolError(
            msg,
            tool_name="x64dbg",
            details={"x64dbg_error_code": _X64DBG_ERR_REMOTE, "address": hex(address)},
        )

    async def remove_breakpoint(self, address: int) -> bool:
        """Remove a breakpoint.

        Args:
            address: Breakpoint address.

        Returns:
            bool: True if removed.
        """
        _logger.info("remove_breakpoint_started", address=hex(address))
        await self._send_pipe_command("bp_remove", {"address": hex(address)})

        with self._state_lock:
            self._breakpoints.pop(address, None)

        _logger.info("breakpoint_removed", address=hex(address))
        return True

    async def get_breakpoints(self) -> list[BreakpointInfo]:
        """Get all breakpoints including those set in the x64dbg GUI.

        Returns:
            list[BreakpointInfo]: List of breakpoints from both local tracking and x64dbg.

        Raises:
            ToolError: If the plugin reports a non-recoverable error.
        """
        _logger.debug("get_breakpoints_started")
        with self._state_lock:
            merged = dict(self._breakpoints)

        if self._pipe_client is not None and self._pipe_client.is_connected:
            try:
                result = await self._send_pipe_command("bp_list")
            except ToolError as exc:
                if not self._is_recoverable_pipe_error(exc):
                    raise
                _logger.warning("bp_list_pipe_unavailable", error=str(exc))
            else:
                if isinstance(result, list):
                    for bp_data in result:
                        if _is_str_obj_dict(bp_data):
                            addr = _coerce_address(bp_data.get("address"))
                            if addr is None or addr in merged:
                                continue
                            raw_type = bp_data.get("type")
                            bp_type_str = raw_type if isinstance(raw_type, str) else "software"
                            raw_enabled = bp_data.get("enabled")
                            raw_hits = bp_data.get("hitCount", bp_data.get("hit_count"))
                            raw_cond = bp_data.get("breakCondition", bp_data.get("condition"))
                            bp_type_val: Literal["software", "hardware", "memory"]
                            if bp_type_str == "hardware":
                                bp_type_val = "hardware"
                            elif bp_type_str == "memory":
                                bp_type_val = "memory"
                            else:
                                bp_type_val = "software"
                            cond_value: str | None = raw_cond if isinstance(raw_cond, str) and raw_cond else None
                            merged[addr] = BreakpointInfo(
                                id=addr,
                                address=addr,
                                bp_type=bp_type_val,
                                enabled=raw_enabled if isinstance(raw_enabled, bool) else True,
                                hit_count=raw_hits if isinstance(raw_hits, int) else 0,
                                condition=cond_value,
                            )

        result_list = list(merged.values())
        _logger.debug("get_breakpoints_completed", count=len(result_list))
        return result_list

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
        _logger.info("set_watchpoint_started", address=hex(address), size=size, watch_type=watch_type)
        type_map = {"read": "r", "write": "w", "execute": "x"}
        access = type_map.get(watch_type, "rw")

        await self._send_pipe_command(
            "wp_set",
            {
                "address": hex(address),
                "size": size,
                "access": access,
            },
        )

        with self._state_lock:
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
        with self._state_lock:
            watchpoint = self._watchpoints.get(watchpoint_id)
        if watchpoint is None:
            return False

        await self._send_pipe_command(
            "wp_remove",
            {"address": hex(watchpoint.address)},
        )

        with self._state_lock:
            self._watchpoints.pop(watchpoint_id, None)
        _logger.info("watchpoint_removed", id=watchpoint_id)
        return True

    async def get_watchpoints(self) -> list[WatchpointInfo]:
        """Get all watchpoints including those set in the x64dbg GUI.

        Returns:
            list[WatchpointInfo]: List of watchpoints from both local tracking and x64dbg.

        Raises:
            ToolError: If the plugin reports a non-recoverable error.
        """
        _logger.debug("get_watchpoints_started")
        with self._state_lock:
            merged = dict(self._watchpoints)

        if self._pipe_client is not None and self._pipe_client.is_connected:
            try:
                result = await self._send_pipe_command("wp_list")
            except ToolError as exc:
                if not self._is_recoverable_pipe_error(exc):
                    raise
                _logger.warning("wp_list_pipe_unavailable", error=str(exc))
                result = None
            if isinstance(result, list):
                for wp_data in result:
                    if _is_str_obj_dict(wp_data):
                        wp_addr = _coerce_address(wp_data.get("address")) or 0
                        existing = any(w.address == wp_addr for w in merged.values())
                        if not existing:
                            with self._state_lock:
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

        wp_list = list(merged.values())
        _logger.debug("get_watchpoints_completed", count=len(wp_list))
        return wp_list

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
                    _logger.warning("register_value_parse_failed", value=str(value))
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

    def _get_cached_process_handle(self, access_mask: int) -> int:
        """Return a cached process handle for ``access_mask``, opening one when absent.

        The cache lives for the duration of a single attachment. Each
        unique access mask maps to one open ``OpenProcess`` handle so
        repeated memory reads, writes, and allocations against the
        same target do not pay the ``OpenProcess`` / ``CloseHandle``
        cost on every call (and do not generate per-call audit events
        in environments that audit handle opens). The cache is cleared
        by :meth:`_release_process_handles`, which is called on detach
        and on shutdown so handles never outlive the target attachment.

        Args:
            access_mask: Win32 access flags requested for the handle.

        Returns:
            int: Open Windows handle. Always non-zero on success.

        Raises:
            ToolError: When called on a non-Windows platform, when no
                process is attached, or when ``OpenProcess`` fails.
        """
        if not _IS_WIN32:
            msg = "Windows API not available"
            raise ToolError(msg)
        if self._attached_pid is None:
            msg = "No process attached"
            raise ToolError(msg)
        with self._handle_cache_lock:
            if cached := self._process_handles.get(access_mask):
                return cached
            kernel32 = ctypes.windll.kernel32
            inherit_handle = False
            handle: int = kernel32.OpenProcess(access_mask, inherit_handle, self._attached_pid)
            if not handle:
                error_code = ctypes.get_last_error()
                msg = f"Failed to open process {self._attached_pid} (access=0x{access_mask:X})"
                raise ToolError(msg, tool_name="x64dbg", exit_code=error_code)
            self._process_handles[access_mask] = handle
            return handle

    def _release_process_handles(self) -> None:
        """Close and forget every cached process handle.

        Closes every open handle in ``_process_handles`` and clears the cache atomically under ``_handle_cache_lock``. Errors raised by
        ``CloseHandle`` are logged at ``debug`` so a partial cleanup cannot mask later failures or block teardown. Safe to call when the
        cache is empty (e.g. on a bridge that never attached).
        """
        if not _IS_WIN32:
            return
        with self._handle_cache_lock:
            if not self._process_handles:
                return
            kernel32 = ctypes.windll.kernel32
            for access_mask, handle in self._process_handles.items():
                try:
                    kernel32.CloseHandle(handle)
                except (OSError, ctypes.ArgumentError) as exc:
                    _logger.warning(
                        "process_handle_close_failed",
                        access=hex(access_mask),
                        error=str(exc),
                        error_type=type(exc).__name__,
                    )
            self._process_handles.clear()

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

        handle = self._get_cached_process_handle(WIN_PROCESS_VM_READ | WIN_PROCESS_QUERY_INFORMATION)

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
        _logger.info("write_memory_started", address=hex(address), size=len(data))
        if not _IS_WIN32:
            msg = "Windows API not available"
            raise ToolError(msg)

        kernel32 = ctypes.windll.kernel32

        if self._attached_pid is None:
            msg = "No process attached"
            raise ToolError(msg)

        handle = self._get_cached_process_handle(WIN_PROCESS_VM_WRITE | WIN_PROCESS_VM_OPERATION)

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

        _logger.info("memory_written", bytes_count=bytes_written.value, address=hex(address))
        return bytes_written.value

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
        _logger.info("allocate_memory_started", size=size, protection=protection)
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

        handle = self._get_cached_process_handle(WIN_PROCESS_VM_OPERATION)

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

        try:
            handle = self._get_cached_process_handle(WIN_PROCESS_VM_OPERATION)
        except ToolError as exc:
            _logger.warning("free_memory_handle_unavailable", address=hex(address), error=str(exc))
            return False

        success = kernel32.VirtualFreeEx(
            handle,
            ctypes.c_void_p(address),
            0,
            WIN_MEM_RELEASE,
        )

        return bool(success)

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

        inherit_handle = False
        handle = kernel32.OpenProcess(
            WIN_PROCESS_QUERY_INFORMATION | WIN_PROCESS_VM_READ,
            inherit_handle,
            self._attached_pid,
        )

        if not handle:
            error_code = ctypes.get_last_error()
            msg = f"{_ERR_OPEN_PROCESS_FAILED} {self._attached_pid} for memory query"
            raise ToolError(msg, tool_name="x64dbg", exit_code=error_code)

        regions: list[MemoryRegion] = []

        modules: list[ModuleInfo]
        try:
            modules = await self._get_modules()
        except ToolError as mod_err:
            _logger.warning("memory_regions_modules_unavailable", error=str(mod_err))
            modules = []

        def _resolve_module(base: int) -> str | None:
            """Find which module (if any) contains an address.

            Args:
                base: Region base address.

            Returns:
                str | None: Module name, or None when no module matches.
            """
            for mod in modules:
                if mod.base_address <= base < mod.base_address + mod.size:
                    return mod.name
            return None

        try:
            self._walk_committed_memory_regions(
                kernel32,
                handle,
                MemoryBasicInformation(),
                regions,
                _resolve_module,
            )
        finally:
            kernel32.CloseHandle(handle)

        return regions

    @classmethod
    def _walk_committed_memory_regions(
        cls,
        kernel32: ctypes.WinDLL,
        handle: int,
        mbi: ctypes.Structure,
        regions: list[MemoryRegion],
        resolve_module: Callable[[int], str | None],
    ) -> None:
        """Walk the target process address space via ``VirtualQueryEx``.

        Appends every committed region to ``regions`` and stops when
        ``VirtualQueryEx`` returns zero or the cursor passes the
        x86_64 user-mode boundary.

        Args:
            kernel32: ``ctypes.windll.kernel32`` proxy used to issue
                ``VirtualQueryEx``.
            handle: Open process handle with ``PROCESS_QUERY_INFORMATION``
                and ``PROCESS_VM_READ`` access.
            mbi: A freshly allocated ``MEMORY_BASIC_INFORMATION``
                structure that ``VirtualQueryEx`` will populate in place
                on every iteration.
            regions: Mutable list that receives one :class:`MemoryRegion`
                per committed range encountered.
            resolve_module: Callback that returns the name of the module
                covering a given base address, or ``None`` if no module
                matches.
        """
        address = 0
        while True:
            result = kernel32.VirtualQueryEx(
                handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if result == 0:
                break
            if mbi.State == WIN_MEM_COMMIT:
                cls._append_committed_region(mbi, regions, resolve_module)
            address = (mbi.BaseAddress or 0) + mbi.RegionSize
            if address > MAX_USER_ADDRESS_64:
                break

    @staticmethod
    def _append_committed_region(
        mbi: ctypes.Structure,
        regions: list[MemoryRegion],
        resolve_module: Callable[[int], str | None],
    ) -> None:
        """Translate one ``MEMORY_BASIC_INFORMATION`` into a region.

        Args:
            mbi: Populated ``MEMORY_BASIC_INFORMATION`` describing a
                single committed range.
            regions: Mutable list that receives the new
                :class:`MemoryRegion` entry.
            resolve_module: Callback that returns the name of the module
                covering ``mbi.BaseAddress`` when ``mbi`` describes an
                image-backed region.
        """
        prot_map = {
            PAGE_NOACCESS: "---",
            PAGE_READONLY: "r--",
            PAGE_READWRITE: "rw-",
            PAGE_EXECUTE: "--x",
            PAGE_EXECUTE_READ: "r-x",
            PAGE_EXECUTE_READWRITE_FLAG: "rwx",
        }
        mem_type_raw = int(mbi.Type)
        if mem_type_raw == MEM_IMAGE_FLAG:
            region_type = "image"
        elif mem_type_raw == MEM_MAPPED_FLAG:
            region_type = "mapped"
        elif mem_type_raw == MEM_PRIVATE_FLAG:
            region_type = "private"
        else:
            region_type = "unknown"
        base_addr = int(mbi.BaseAddress or 0)
        module_name = resolve_module(base_addr) if region_type == "image" else None
        regions.append(
            MemoryRegion(
                base_address=base_addr,
                size=mbi.RegionSize,
                protection=prot_map.get(mbi.Protect, "???"),
                state="committed",
                type=region_type,
                module_name=module_name,
            ),
        )

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
            ToolError: If the plugin reports a non-recoverable error, or
                the plugin is unavailable and capstone is not installed.
        """
        last_error: ToolError | None = None
        try:
            result = await self._send_pipe_command("disasm", {"address": hex(address), "count": count})
            if isinstance(result, list):
                return [self._parse_disasm_entry(e) for e in result if _is_str_obj_dict(e)]
        except ToolError as exc:
            if not self._is_local_fallback_eligible(exc):
                raise
            last_error = exc
            _logger.warning("disasm_pipe_unavailable_using_capstone", error=str(exc))

        capstone = get_capstone()
        if capstone is None:
            detail = f" (plugin error: {last_error})" if last_error is not None else ""
            msg = f"Capstone disassembler not available. Install with: pixi add capstone-engine{detail}"
            raise ToolError(msg)

        try:
            capstone_lines = await self._capstone_disassemble(capstone, address, count)
        except (OSError, struct.error, ValueError, ToolError) as exc:
            _logger.warning(
                "disassembly_failed",
                address=hex(address),
                count=count,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            msg = f"Disassembly failed at {hex(address)}: {exc}"
            raise ToolError(msg, tool_name="x64dbg") from exc
        return capstone_lines

    async def _capstone_disassemble(
        self,
        capstone: ModuleType,
        address: int,
        count: int,
    ) -> list[DisassemblyLine]:
        """Disassemble ``count`` instructions starting at ``address`` via capstone.

        Args:
            capstone: The imported capstone module.
            address: Address in the attached process to disassemble from.
            count: Maximum number of instructions to decode.

        Returns:
            list[DisassemblyLine]: Decoded instructions, up to ``count``.
        """
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

        Raises:
            ToolError: If the plugin reports a non-recoverable error.
        """
        try:
            result = await self._send_pipe_command("stack_trace")
            if isinstance(result, list):
                return [self._parse_stack_frame_entry(e) for e in result if _is_str_obj_dict(e)]
        except ToolError as exc:
            if not self._is_recoverable_pipe_error(exc):
                raise
            _logger.warning("stack_trace_pipe_unavailable_walking_manually", error=str(exc))

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
                next_rbp = await self._walk_one_stack_frame(i, rbp, frames_fallback)
            except ToolError as e:
                _logger.warning("stack_trace_unavailable", error=str(e))
                break
            if next_rbp is None:
                break
            rbp = next_rbp

        return frames_fallback

    async def _walk_one_stack_frame(
        self,
        index: int,
        rbp: int,
        frames_fallback: list[StackFrame],
    ) -> int | None:
        """Append one frame walked from ``rbp`` to ``frames_fallback``.

        Reads the saved frame pointer and return address at ``[rbp]``
        and ``[rbp + 8 / 4]`` and appends the resulting
        :class:`StackFrame` to ``frames_fallback`` when both values are
        non-zero.

        Args:
            index: Zero-based frame index for the new entry.
            rbp: Current frame pointer to walk.
            frames_fallback: Mutable list that receives the new frame.

        Returns:
            int | None: The saved frame pointer to continue walking
            from, or ``None`` when the walk should terminate.
        """
        if rbp == 0:
            return None
        data = await self.read_memory(rbp, STACK_FRAME_SIZE_64)
        if len(data) < STACK_FRAME_SIZE_64:
            return None
        if self._is_64bit:
            saved_rbp = int.from_bytes(data[:8], "little")
            return_addr = int.from_bytes(data[8:16], "little")
        else:
            saved_rbp = int.from_bytes(data[:4], "little")
            return_addr = int.from_bytes(data[4:8], "little")
        if return_addr == 0 or saved_rbp == 0:
            return None
        frames_fallback.append(
            StackFrame(
                index=index,
                address=return_addr,
                return_address=return_addr,
                frame_pointer=saved_rbp,
                stack_pointer=rbp + (16 if self._is_64bit else 8),
                function_name=None,
                module_name=None,
            ),
        )
        return saved_rbp

    async def scan_memory(self, pattern: str | bytes) -> list[MemorySearchResult]:
        """Scan process memory for a pattern.

        Reads each region in ``MAX_MEMORY_READ_SIZE`` chunks while
        keeping a rolling tail equal to ``len(pattern) - 1`` bytes
        between chunks so matches spanning a chunk boundary are not
        missed.

        Args:
            pattern: Byte pattern to search for. Accepts bytes or hex string
                (e.g. "48 8B 05" or "488B05").

        Returns:
            list[MemorySearchResult]: List of matches with context.

        Raises:
            ToolError: If the pattern is empty or shorter than
                ``MIN_PATTERN_LENGTH`` bytes (such patterns produce too
                many false-positive matches to be useful).
        """
        _logger.info("scan_memory_started")
        if isinstance(pattern, str):
            pattern = bytes.fromhex(pattern.replace(" ", ""))
        if not pattern:
            msg = "scan_memory: pattern must be non-empty"
            raise ToolError(msg, tool_name="x64dbg")
        if len(pattern) < MIN_PATTERN_LENGTH:
            msg = f"scan_memory: pattern too short for reliable scan (got {len(pattern)} bytes, need at least {MIN_PATTERN_LENGTH})"
            raise ToolError(msg, tool_name="x64dbg")

        regions = await self.get_memory_regions()
        matches: list[MemorySearchResult] = []
        for region in regions:
            if "r" not in region.protection:
                continue
            await self._scan_region_chunks(region, pattern, matches)
        return matches

    async def _scan_region_chunks(
        self,
        region: MemoryRegion,
        pattern: bytes,
        matches: list[MemorySearchResult],
    ) -> None:
        """Scan one memory region in chunks with rolling tail overlap.

        Args:
            region: Memory region metadata.
            pattern: Byte pattern being searched for.
            matches: Output list that matches are appended to.
        """
        pattern_len = len(pattern)
        overlap = pattern_len - 1
        region_end = region.base_address + region.size
        chunk_start = region.base_address
        carry: bytes = b""
        carry_addr = chunk_start

        while chunk_start < region_end:
            read_size = min(MAX_MEMORY_READ_SIZE, region_end - chunk_start)
            try:
                chunk = await self.read_memory(chunk_start, read_size)
            except ToolError as e:
                _logger.warning(
                    "memory_scan_chunk_failed",
                    base=hex(chunk_start),
                    size=read_size,
                    error=str(e),
                )
                carry = b""
                chunk_start += read_size
                carry_addr = chunk_start
                continue
            if not chunk:
                break

            buffer = carry + chunk
            self._extend_matches_from_buffer(buffer, carry_addr, pattern, matches)

            chunk_start += read_size
            if overlap > 0 and chunk_start < region_end:
                carry = buffer[-overlap:] if len(buffer) >= overlap else buffer
                carry_addr = chunk_start - len(carry)
            else:
                carry = b""
                carry_addr = chunk_start

    @staticmethod
    def _extend_matches_from_buffer(
        buffer: bytes,
        buffer_base: int,
        pattern: bytes,
        matches: list[MemorySearchResult],
    ) -> None:
        """Find every occurrence of ``pattern`` in ``buffer`` and append matches.

        Args:
            buffer: Raw memory buffer to search.
            buffer_base: Virtual address of ``buffer[0]``.
            pattern: Byte pattern being searched for.
            matches: Output list that matches are appended to.
        """
        pattern_len = len(pattern)
        offset = 0
        while True:
            idx = buffer.find(pattern, offset)
            if idx == -1:
                return
            matches.append(
                MemorySearchResult(
                    address=buffer_base + idx,
                    matched_bytes=pattern.hex(),
                    context_before=buffer[max(0, idx - 16) : idx].hex(),
                    context_after=buffer[idx + pattern_len : idx + pattern_len + 16].hex(),
                ),
            )
            offset = idx + 1

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

        Builds the final command line via ``subprocess.list2cmdline`` so
        that arguments containing spaces, quotes, or backslashes are
        quoted using the same rules as the Windows C runtime.

        Args:
            path: Path to executable.
            args: Optional arguments.

        Returns:
            int: Process ID of the spawned process, or 0 if unavailable.
        """
        _logger.info("process_spawning", path=str(path))
        args_str: str | None = self._build_cmdline(args) if args else None
        await self.load(path, args_str)
        return self._attached_pid or 0

    @staticmethod
    def _build_cmdline(args: Sequence[str]) -> str:
        """Quote a sequence of args per the Windows C runtime rules.

        Mirrors ``subprocess.list2cmdline`` so we can avoid importing
        the subprocess module here while still producing output the
        x64dbg ``InitDebug`` handler parses identically.

        Args:
            args: Arguments to quote and join.

        Returns:
            str: Final command-line string.
        """
        parts: list[str] = []
        for arg in args:
            if arg and all(ch not in arg for ch in ' \t\n\v"'):
                parts.append(arg)
                continue
            quoted = ['"']
            backslashes = 0
            for ch in arg:
                if ch == "\\":
                    backslashes += 1
                    continue
                if ch == '"':
                    quoted.extend(("\\" * (2 * backslashes + 1), '"'))
                    backslashes = 0
                    continue
                if backslashes:
                    quoted.append("\\" * backslashes)
                    backslashes = 0
                quoted.append(ch)
            if backslashes:
                quoted.append("\\" * (2 * backslashes))
            quoted.append('"')
            parts.append("".join(quoted))
        return " ".join(parts)

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

            Populated by ``Thread32First`` / ``Thread32Next`` when enumerating threads that belong to the attached process via a toolhelp
            snapshot.
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

        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        if snapshot in {INVALID_HANDLE_VALUE, DWORD_MASK}:
            error_code = ctypes.get_last_error()
            msg = f"{_ERR_CREATE_SNAPSHOT_FAILED} for threads: error {error_code}"
            raise ToolError(msg, tool_name="x64dbg", exit_code=error_code)

        threads: list[ThreadInfo] = []

        try:
            self._enumerate_attached_threads(kernel32, snapshot, ThreadEntry32, threads)
        except (OSError, ctypes.ArgumentError) as e:
            _logger.warning("x64dbg_get_threads_failed", pid=self._attached_pid, error=str(e))
            msg = f"{_ERR_GET_THREADS_FAILED}: {e}"
            raise ToolError(msg, tool_name="x64dbg") from e
        finally:
            kernel32.CloseHandle(snapshot)

        _logger.debug("threads_found", count=len(threads), pid=self._attached_pid)
        return threads

    def _enumerate_attached_threads(
        self,
        kernel32: ctypes.WinDLL,
        snapshot: int,
        thread_entry_cls: type[ctypes.Structure],
        threads: list[ThreadInfo],
    ) -> None:
        """Iterate the thread snapshot and append matching threads.

        Args:
            kernel32: ``ctypes.windll.kernel32`` proxy used to walk the
                snapshot via ``Thread32First`` / ``Thread32Next``.
            snapshot: Open ``CreateToolhelp32Snapshot`` handle for the
                ``TH32CS_SNAPTHREAD`` class.
            thread_entry_cls: ``THREADENTRY32`` ctypes structure class
                whose instances will be populated by the walk.
            threads: Mutable list that receives one :class:`ThreadInfo`
                entry per thread owned by the attached process.
        """
        te32 = thread_entry_cls()
        te32.dwSize = ctypes.sizeof(thread_entry_cls)
        _logger.debug("initialized_thread_entry", size=te32.dwSize)
        if not kernel32.Thread32First(snapshot, ctypes.byref(te32)):
            return
        while True:
            if te32.th32OwnerProcessID == self._attached_pid:
                tid = int(te32.th32ThreadID)
                start_address = self._query_thread_start_address(tid)
                current_pc, state = self._query_thread_pc_and_state(tid)
                threads.append(
                    ThreadInfo(
                        tid=tid,
                        start_address=start_address,
                        current_pc=current_pc,
                        state=state,
                    ),
                )
            if not kernel32.Thread32Next(snapshot, ctypes.byref(te32)):
                break

    @classmethod
    def _query_thread_start_address(cls, tid: int) -> int:
        """Query the Win32 thread start address via ``NtQueryInformationThread``.

        Opens the thread with ``THREAD_QUERY_LIMITED_INFORMATION`` (the
        minimal access right that NTSTATUS-bearing
        ``ThreadQuerySetWin32StartAddress`` accepts on modern Windows)
        and reads the ``Win32StartAddress`` produced by
        ``CreateRemoteThread`` / ``CreateThread``. Returns ``0`` when
        the thread cannot be opened or the kernel call reports an error
        so the surrounding enumeration is not aborted by a transient
        access-denied on a single thread.

        Args:
            tid: Thread identifier.

        Returns:
            int: Resolved start address, or ``0`` when unavailable.
        """
        if not _IS_WIN32:
            return 0
        try:
            ntdll = get_ntdll()
        except OSError as exc:
            _logger.warning(
                "thread_start_address_ntdll_unavailable",
                tid=tid,
                error=str(exc),
            )
            return 0
        kernel32 = ctypes.windll.kernel32
        inherit_handle = False
        handle = kernel32.OpenThread(THREAD_QUERY_INFORMATION, inherit_handle, tid)
        if not handle:
            _logger.debug(
                "thread_start_address_open_failed",
                tid=tid,
                error_code=ctypes.get_last_error(),
            )
            return 0
        try:
            return cls._query_thread_start_address_with_handle(ntdll, handle, tid)
        finally:
            kernel32.CloseHandle(handle)

    @staticmethod
    def _query_thread_start_address_with_handle(
        ntdll: ctypes.WinDLL,
        handle: int,
        tid: int,
    ) -> int:
        """Invoke ``NtQueryInformationThread`` for an opened thread.

        Args:
            ntdll: ``ntdll`` proxy returned by :func:`get_ntdll`.
            handle: Open thread handle with ``THREAD_QUERY_INFORMATION``
                rights.
            tid: Thread identifier, used only for logging context.

        Returns:
            int: Resolved start address, or ``0`` when the query failed
            or returned a negative NTSTATUS.
        """
        start_address = ctypes.c_void_p(0)
        try:
            status: int = ntdll.NtQueryInformationThread(
                handle,
                ThreadQuerySetWin32StartAddress,
                ctypes.byref(start_address),
                ctypes.sizeof(start_address),
                None,
            )
        except (OSError, ctypes.ArgumentError) as exc:
            _logger.warning(
                "thread_start_address_query_exception",
                tid=tid,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return 0
        if status >= 0:
            return int(start_address.value or 0)
        _logger.debug(
            "thread_start_address_nt_failed",
            tid=tid,
            ntstatus=hex(status & 0xFFFFFFFF),
        )
        return 0

    def _query_thread_pc_and_state(self, tid: int) -> tuple[int, str]:
        """Read the current PC and execution state for a single thread.

        Suspends the thread once via ``SuspendThread`` (so the
        ``GetThreadContext`` / ``Wow64GetThreadContext`` snapshot is
        coherent), reads ``Rip`` (or ``Eip`` on WOW64) and derives a
        textual state from the prior suspend count. ``ResumeThread`` is
        called inside a ``finally`` block so the thread is never left
        suspended on an exceptional path. The current Python thread is
        skipped (``GetThreadContext`` against the calling thread is
        undefined) and reported as ``"running"``.

        Args:
            tid: Thread identifier.

        Returns:
            tuple[int, str]: ``(current_pc, state)`` where ``state`` is
            one of ``"running"``, ``"suspended"``, ``"terminated"``, or
            ``"unknown"``.
        """
        if not _IS_WIN32:
            return 0, "unknown"
        kernel32 = ctypes.windll.kernel32
        if tid == int(kernel32.GetCurrentThreadId()):
            return 0, "running"

        access = THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME
        inherit_handle = False
        handle = kernel32.OpenThread(access, inherit_handle, tid)
        if not handle:
            _logger.debug(
                "thread_pc_open_failed",
                tid=tid,
                error_code=ctypes.get_last_error(),
            )
            return 0, "unknown"
        try:
            return self._read_thread_pc_and_state_with_handle(kernel32, handle, tid)
        finally:
            kernel32.CloseHandle(handle)

    def _read_thread_pc_and_state_with_handle(
        self,
        kernel32: ctypes.WinDLL,
        handle: int,
        tid: int,
    ) -> tuple[int, str]:
        """Suspend a thread, read its PC, then resume it.

        Args:
            kernel32: ``ctypes.windll.kernel32`` proxy used for the
                suspend/resume pair.
            handle: Open thread handle with the
                ``THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT |
                THREAD_SUSPEND_RESUME`` access mask.
            tid: Thread identifier, used only for logging context.

        Returns:
            tuple[int, str]: ``(pc, state)`` where ``state`` is one of
            ``"suspended"``, ``"running"``, or ``"unknown"``.
        """
        try:
            raw_count: int = kernel32.SuspendThread(handle)
        except (OSError, ctypes.ArgumentError) as exc:
            _logger.warning(
                "thread_pc_suspend_exception",
                tid=tid,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return 0, "unknown"
        signed_count = ctypes.c_long(raw_count).value
        if signed_count < 0:
            return 0, "unknown"
        try:
            state = "suspended" if signed_count > 0 else "running"
            pc = self._read_thread_program_counter(handle)
            return pc, state
        finally:
            kernel32.ResumeThread(handle)

    def _read_thread_program_counter(self, handle: int) -> int:
        """Read the instruction pointer of a thread via ``GetThreadContext``.

        Uses ``Wow64GetThreadContext`` against the 32-bit context layout
        when the bridge tracks a WOW64 (32-bit) target, and ``GetThreadContext``
        with the AMD64 layout otherwise. Returns ``0`` when the kernel
        call fails so the caller can record an unresolved PC without
        aborting enumeration.

        Args:
            handle: Open thread handle with ``THREAD_GET_CONTEXT`` rights.

        Returns:
            int: Instruction pointer (``Rip`` or ``Eip``) for the
            thread, or ``0`` when the context read fails.
        """
        if not _IS_WIN32:
            return 0
        kernel32 = ctypes.windll.kernel32
        if not self._is_64bit:
            wow64_get_ctx = getattr(kernel32, "Wow64GetThreadContext", None)
            if wow64_get_ctx is not None:
                ctx32 = CONTEXT32()
                ctx32.ContextFlags = CONTEXT_I386_ALL
                return int(ctx32.Eip) if wow64_get_ctx(handle, ctypes.byref(ctx32)) else 0
            ctx32_alt = CONTEXT32()
            ctx32_alt.ContextFlags = CONTEXT_I386_ALL
            if kernel32.GetThreadContext(handle, ctypes.byref(ctx32_alt)):
                return int(ctx32_alt.Eip)
            return 0
        ctx64 = CONTEXT64()
        ctx64.ContextFlags = CONTEXT_ALL
        if kernel32.GetThreadContext(handle, ctypes.byref(ctx64)):
            return int(ctx64.Rip)
        return 0

    @staticmethod
    async def _create_module_snapshot_with_retry(kernel32: ctypes.WinDLL, pid: int) -> int:
        """Create a Toolhelp module snapshot, retrying transient failures.

        ``CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ...)`` commonly fails
        with ``ERROR_BAD_LENGTH`` (24) for a process that has only just been
        created - or is still sitting at its initial system breakpoint with
        its module list not yet fully populated - which is exactly the state
        a debuggee is in immediately after :meth:`load` or :meth:`attach`
        registers ``self._attached_pid``. Retrying a handful of times with a
        short delay lets the snapshot succeed once the target has finished
        loading instead of surfacing a spurious failure to a caller that
        attached only moments earlier.

        Args:
            kernel32: ``ctypes.windll.kernel32`` proxy used to call
                ``CreateToolhelp32Snapshot``.
            pid: Process id of the attached debuggee to snapshot.

        Returns:
            int: A valid, open ``CreateToolhelp32Snapshot`` handle.

        Raises:
            ToolError: If every retry attempt fails, reporting the real
                ``GetLastError`` value from the final attempt.
        """
        error_code = 0
        for attempt in range(_TOOLHELP_MODULE_SNAPSHOT_MAX_ATTEMPTS):
            snapshot = kernel32.CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                pid,
            )
            if snapshot not in {INVALID_HANDLE_VALUE, DWORD_MASK}:
                return cast("int", snapshot)

            error_code = ctypes.get_last_error()
            if error_code != _ERROR_BAD_LENGTH:
                msg = f"{_ERR_CREATE_SNAPSHOT_FAILED} for modules PID {pid}: error {error_code}"
                raise ToolError(msg, tool_name="x64dbg", exit_code=error_code)

            if attempt < _TOOLHELP_MODULE_SNAPSHOT_MAX_ATTEMPTS - 1:
                _logger.debug(
                    "toolhelp_module_snapshot_retry",
                    pid=pid,
                    attempt=attempt + 1,
                    error_code=error_code,
                )
                await asyncio.sleep(_TOOLHELP_MODULE_SNAPSHOT_RETRY_DELAY)

        msg = (
            f"{_ERR_CREATE_SNAPSHOT_FAILED} for modules PID {pid} after "
            f"{_TOOLHELP_MODULE_SNAPSHOT_MAX_ATTEMPTS} attempts: error {error_code}"
        )
        raise ToolError(msg, tool_name="x64dbg", exit_code=error_code)

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

        # ctypes.windll.kernel32 is not constructed with use_last_error=True,
        # so ctypes.get_last_error() would always read back 0 for calls made
        # through it. The retry loop below needs the real code
        # CreateToolhelp32Snapshot reported through GetLastError to tell a
        # transient, retryable failure apart from a genuine one, so a
        # dedicated handle with last-error tracking enabled is required here.
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class ModuleEntry32W(ctypes.Structure):
            """Windows ``MODULEENTRY32W`` layout for module snapshots.

            Populated by ``Module32FirstW`` / ``Module32NextW`` when enumerating DLL and executable modules loaded into the attached process
            via a toolhelp snapshot.
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

        # A snapshot taken immediately after CREATE_PROCESS_DEBUG_EVENT can be
        # valid yet empty: the loader has only mapped the main executable and
        # ntdll at that point, and Module32FirstW briefly reports no entries
        # until the debuggee reaches its initial system breakpoint and the
        # rest of the import table finishes loading. Retrying the whole
        # snapshot-and-walk cycle absorbs that race instead of returning an
        # empty list for a debuggee that is, in fact, running with modules
        # loaded moments later.
        deadline = asyncio.get_running_loop().time() + self.VERIFY_TIMEOUT
        modules: list[ModuleInfo] = []
        while True:
            snapshot = await self._create_module_snapshot_with_retry(kernel32, self._attached_pid)
            modules = []
            try:
                self._enumerate_modules_into(kernel32, snapshot, ModuleEntry32W, modules)
            except (OSError, ctypes.ArgumentError) as e:
                _logger.warning("x64dbg_get_modules_failed", pid=self._attached_pid, error=str(e))
                msg = f"{_ERR_GET_MODULES_FAILED}: {e}"
                raise ToolError(msg, tool_name="x64dbg") from e
            finally:
                kernel32.CloseHandle(snapshot)

            if modules or asyncio.get_running_loop().time() >= deadline:
                break
            await asyncio.sleep(self.VERIFY_POLL_INTERVAL)

        _logger.debug("modules_found", count=len(modules), pid=self._attached_pid)
        return modules

    @staticmethod
    def _enumerate_modules_into(
        kernel32: ctypes.WinDLL,
        snapshot: int,
        module_entry_cls: type[ctypes.Structure],
        modules: list[ModuleInfo],
    ) -> None:
        """Walk a module snapshot and append every module entry.

        Args:
            kernel32: ``ctypes.windll.kernel32`` proxy used to walk the
                snapshot via ``Module32FirstW`` / ``Module32NextW``.
            snapshot: Open ``CreateToolhelp32Snapshot`` handle for the
                ``TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32`` classes.
            module_entry_cls: ``MODULEENTRY32W`` ctypes structure class
                whose instances will be populated by the walk.
            modules: Mutable list that receives one :class:`ModuleInfo`
                per loaded module.
        """
        me32 = module_entry_cls()
        me32.dwSize = ctypes.sizeof(module_entry_cls)
        _logger.debug("initialized_module_entry", size=me32.dwSize)
        if not kernel32.Module32FirstW(snapshot, ctypes.byref(me32)):
            return
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

    async def evaluate_expression(self, expression: str) -> int:
        """Evaluate an x64dbg expression.

        Args:
            expression: Expression to evaluate (e.g. 'rax+rbx*4').

        Returns:
            int: Expression result value.

        Raises:
            ToolError: If the plugin returns a value that is neither an
                integer nor a parseable hex/decimal string. A failure to
                evaluate must not be conflated with a legitimate
                expression that evaluates to ``0`` (audit6.md F-0014).
        """
        _logger.debug("evaluating_expression", expression=expression)
        result = await self._send_pipe_command("eval", {"expression": expression})
        if isinstance(result, bool):
            msg = f"evaluate_expression: plugin returned bool for {expression!r}"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_PROTOCOL_VIOLATION,
                    "expression": expression,
                },
            )
        if isinstance(result, int):
            return result
        if isinstance(result, str):
            try:
                return int(result, 0)
            except ValueError as parse_err:
                msg = f"evaluate_expression: plugin returned unparseable value {result!r} for {expression!r}"
                raise ToolError(
                    msg,
                    tool_name="x64dbg",
                    details={
                        "x64dbg_error_code": _X64DBG_ERR_PROTOCOL_VIOLATION,
                        "expression": expression,
                    },
                ) from parse_err
        msg = f"evaluate_expression: plugin returned unexpected type {type(result).__name__} for {expression!r}"
        raise ToolError(
            msg,
            tool_name="x64dbg",
            details={
                "x64dbg_error_code": _X64DBG_ERR_PROTOCOL_VIOLATION,
                "expression": expression,
            },
        )

    @staticmethod
    def _parse_stack_frame_entry(entry: dict[str, object]) -> StackFrame:
        """Parse a single stack frame entry dict from the plugin into a StackFrame.

        Args:
            entry: Dict with index, address, from, to, comment fields.

        Returns:
            StackFrame: Parsed stack frame.
        """

        def _parse_int(val: object) -> int:
            """Coerce a stack-frame field into an integer.

            Accepts decimal or ``0x``-prefixed strings via ``int(..., 0)``,
            converts numeric values with ``int(...)``, and returns ``0`` for
            any other type.

            Args:
                val: Raw field value from the stack-frame entry dict.

            Returns:
                int: Parsed integer, or ``0`` when ``val`` is unusable.
            """
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

    @classmethod
    def _get_parent_pid(cls, pid: int) -> int:
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
            """Toolhelp32 PROCESSENTRY32W layout for parent-PID snapshot walks."""

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

        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot in {INVALID_HANDLE_VALUE, DWORD_MASK}:
            error_code = ctypes.get_last_error()
            msg = f"{_ERR_CREATE_SNAPSHOT_FAILED} for process: error {error_code}"
            raise ToolError(msg, tool_name="x64dbg", exit_code=error_code)

        try:
            parent_pid = cls._find_parent_pid_in_snapshot(
                kernel32,
                snapshot,
                ProcessEntry32W,
                pid,
            )
        except (OSError, ctypes.ArgumentError) as e:
            _logger.warning("x64dbg_get_parent_pid_failed", pid=pid, error=str(e))
            msg = f"{_ERR_GET_PARENT_PID_FAILED}: {e}"
            raise ToolError(msg, tool_name="x64dbg") from e
        finally:
            kernel32.CloseHandle(snapshot)

        return parent_pid

    @staticmethod
    def _find_parent_pid_in_snapshot(
        kernel32: ctypes.WinDLL,
        snapshot: int,
        process_entry_cls: type[ctypes.Structure],
        pid: int,
    ) -> int:
        """Walk a process snapshot and return the parent PID of ``pid``.

        Args:
            kernel32: ``ctypes.windll.kernel32`` proxy used to walk the
                snapshot via ``Process32FirstW`` / ``Process32NextW``.
            snapshot: Open ``CreateToolhelp32Snapshot`` handle for the
                ``TH32CS_SNAPPROCESS`` class.
            process_entry_cls: ``PROCESSENTRY32W`` ctypes structure
                class whose instances will be populated by the walk.
            pid: Target process ID whose parent should be located.

        Returns:
            int: Parent process ID, or ``0`` when the target was not
            found in the snapshot.
        """
        pe32 = process_entry_cls()
        pe32.dwSize = ctypes.sizeof(process_entry_cls)
        _logger.debug("initialized_process_entry", size=pe32.dwSize)
        if not kernel32.Process32FirstW(snapshot, ctypes.byref(pe32)):
            return 0
        while True:
            if pe32.th32ProcessID == pid:
                return int(pe32.th32ParentProcessID)
            if not kernel32.Process32NextW(snapshot, ctypes.byref(pe32)):
                return 0

    @staticmethod
    def _get_command_line(pid: int) -> str | None:
        """Get process command line using Windows API.

        Args:
            pid: Process ID to get command line for.

        Returns:
            str | None: Command line string, or None if not accessible.
        """
        return _read_process_command_line(pid) if _IS_WIN32 else None


class _X64DbgAnalysisMixin(_X64DbgBridgeBase):
    """Module/thread enumeration, labels, patching, and breakpoint orchestration.

    Hosts the high-level analysis surface: module/thread/process info,
    pattern searching, run-to coordination, instruction labels and
    comments, breakpoint enable/disable + API/DLL/TLS dispatch,
    instruction patching, memory dump-to-file, PE section/export/entry
    point readers, and the supporting private helpers each of those
    entry points dispatches into.
    """

    async def get_modules(self) -> list[ModuleInfo]:
        """Get loaded modules for the attached process.

        For each enumerated module the in-memory PE header is parsed to
        populate ``ModuleInfo.entry_point`` with the fully-resolved virtual
        address (``base + AddressOfEntryPoint``). Modules whose PE header
        cannot be read (e.g. paged-out, native dlls, partial reads) keep
        ``entry_point = 0``.

        Returns:
            list[ModuleInfo]: List of loaded module information with
            entry points populated where the PE header is readable.
        """
        _logger.info("get_modules_started", pid=self._attached_pid)
        modules = await self._get_modules()
        for module in modules:
            module.entry_point = await self._read_module_entry_point(module.base_address, module.name)
        return modules

    async def _read_module_entry_point(self, base_address: int, module_name: str) -> int:
        """Read the PE ``AddressOfEntryPoint`` for a loaded module.

        Reads enough of the in-memory NT headers to span any standard
        Optional Header layout (PE32 or PE32+ plus the data-directory
        slack), validates ``SizeOfOptionalHeader`` against the buffer
        actually returned, branches on the Optional Header ``Magic``
        field to pick the correct layout, and extracts
        ``AddressOfEntryPoint`` from the documented fixed offset. The
        entry-point field is the 5th 32-bit field of the Optional
        Header (i.e. RVA at offset ``PE_ENTRY_POINT_OFFSET = 0x28``)
        and is the same for both PE32 and PE32+, but bracketing the
        read by ``SizeOfOptionalHeader`` lets us detect cropped headers
        (paged-out trailing pages) before silently producing junk.

        Args:
            base_address: Module base address in the target process.
            module_name: Module name for diagnostic logging.

        Returns:
            int: Resolved virtual address of the entry point, or 0 if the
            PE header could not be read or validated.
        """
        try:
            _, pe_header = await self._read_pe_header(base_address, module_name, size=_PE_HEADER_READ_SIZE)
        except ToolError as exc:
            _logger.warning("module_entry_point_read_failed", module_name=module_name, base=hex(base_address), error=str(exc))
            return 0

        try:
            _machine, _num_sections, optional_header_size, _characteristics = unpack_coff_header(
                pe_header,
                NT_HEADERS_OPTIONAL_OFFSET - 20,
            )
        except struct.error as exc:
            _logger.warning(
                "module_entry_point_coff_unpack_failed",
                module_name=module_name,
                length=len(pe_header),
                error=str(exc),
            )
            return 0

        if optional_header_size <= 0:
            _logger.debug(
                "module_entry_point_optional_header_zero",
                module_name=module_name,
                base=hex(base_address),
            )
            return 0

        try:
            magic = int(struct.unpack_from("<H", pe_header, NT_HEADERS_OPTIONAL_OFFSET)[0])
        except struct.error as exc:
            _logger.warning(
                "module_entry_point_magic_unpack_failed",
                module_name=module_name,
                length=len(pe_header),
                error=str(exc),
            )
            return 0

        if magic == PE_OPTIONAL_HEADER_MAGIC_PE32:
            min_optional_size = PE32_OPTIONAL_HEADER_SIZE
        elif magic == PE_OPTIONAL_HEADER_MAGIC_PE32PLUS:
            min_optional_size = PE32PLUS_OPTIONAL_HEADER_SIZE
        else:
            _logger.debug(
                "module_entry_point_unknown_magic",
                module_name=module_name,
                magic=hex(magic),
                base=hex(base_address),
            )
            return 0

        if optional_header_size < min_optional_size:
            _logger.debug(
                "module_entry_point_optional_header_too_small",
                module_name=module_name,
                optional_header_size=optional_header_size,
                required=min_optional_size,
            )
            return 0

        entry_offset = NT_HEADERS_OPTIONAL_OFFSET + PE_ENTRY_POINT_OFFSET
        if len(pe_header) < entry_offset + 4:
            _logger.debug("module_entry_point_header_short", module_name=module_name, length=len(pe_header))
            return 0

        try:
            entry_rva = int(struct.unpack_from("<I", pe_header, entry_offset)[0])
        except struct.error as exc:
            _logger.warning(
                "module_entry_point_rva_unpack_failed",
                module_name=module_name,
                error=str(exc),
            )
            return 0

        return 0 if entry_rva == 0 else base_address + entry_rva

    async def get_threads(self) -> list[ThreadInfo]:
        """Get thread information for the attached process.

        Returns:
            list[ThreadInfo]: List of thread information.
        """
        return await self._get_threads()

    async def get_process_info(self) -> ProcessInfo:
        """Get complete process information including threads and modules.

        Aggregates thread and module information along with process
        details using Windows APIs.

        Returns:
            ProcessInfo: ProcessInfo with populated threads and modules.

        Raises:
            ToolError: If no process is currently attached.
        """
        _logger.info("get_process_info_started")
        if self._attached_pid is None:
            msg = f"get_process_info: {_ERR_NOT_ATTACHED}"
            raise ToolError(msg, tool_name="x64dbg")

        threads = await self.get_threads()
        modules = await self.get_modules()

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

        Both the no-wildcard and wildcard branches stream each readable
        region in ``MAX_MEMORY_READ_SIZE`` chunks while keeping a rolling
        tail of ``len(pattern) - 1`` bytes between chunks so matches that
        span a chunk boundary are not missed.

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

        regions = await self.get_memory_regions()
        matches: list[dict[str, Any]] = []

        for region in regions:
            if "r" not in region.protection:
                continue
            await self._scan_region_chunks_wildcard(region, pat_bytes, alignment, matches)

        _logger.debug("pattern_search_completed", matches=len(matches))
        return matches

    async def _scan_region_chunks_wildcard(
        self,
        region: MemoryRegion,
        pat_bytes: list[int | None],
        alignment: int,
        matches: list[dict[str, Any]],
    ) -> None:
        """Scan one memory region for a wildcard pattern in chunks with rolling overlap.

        Args:
            region: Memory region metadata.
            pat_bytes: Wildcard pattern; ``None`` entries match any byte.
            alignment: Only return matches at addresses divisible by this value.
            matches: Output list that match dicts are appended to.
        """
        pat_len = len(pat_bytes)
        if pat_len == 0:
            return
        compiled = self._compile_wildcard_regex(pat_bytes)
        overlap = pat_len - 1
        region_end = region.base_address + region.size
        chunk_start = region.base_address
        carry: bytes = b""
        carry_addr = chunk_start

        while chunk_start < region_end:
            read_size = min(MAX_MEMORY_READ_SIZE, region_end - chunk_start)
            try:
                chunk = await self.read_memory(chunk_start, read_size)
            except ToolError as exc:
                _logger.warning(
                    "pattern_search_region_read_failed",
                    base=hex(chunk_start),
                    size=read_size,
                    error=str(exc),
                )
                carry = b""
                chunk_start += read_size
                carry_addr = chunk_start
                continue
            if not chunk:
                break

            buffer = carry + chunk
            self._extend_wildcard_matches(buffer, carry_addr, compiled, pat_len, alignment, matches)

            chunk_start += read_size
            if overlap > 0 and chunk_start < region_end:
                carry = buffer[-overlap:] if len(buffer) >= overlap else buffer
                carry_addr = chunk_start - len(carry)
            else:
                carry = b""
                carry_addr = chunk_start

    @staticmethod
    def _compile_wildcard_regex(pat_bytes: list[int | None]) -> re.Pattern[bytes]:
        """Compile a wildcard byte pattern to a ``re`` Pattern.

        ``None`` bytes become ``b"."`` (any single byte under DOTALL);
        concrete bytes become their escaped literal so a value like
        ``0x2E`` ('.') is not interpreted as a regex metacharacter.

        Args:
            pat_bytes: Wildcard pattern; ``None`` entries match any byte.

        Returns:
            re.Pattern[bytes]: Compiled regex (DOTALL) for fast scanning.
        """
        parts: list[bytes] = [b"." if b is None else re.escape(bytes([b])) for b in pat_bytes]
        return re.compile(b"".join(parts), re.DOTALL)

    @staticmethod
    def _extend_wildcard_matches(
        buffer: bytes,
        buffer_base: int,
        compiled: re.Pattern[bytes],
        pat_len: int,
        alignment: int,
        matches: list[dict[str, Any]],
    ) -> None:
        """Find every wildcard-pattern occurrence in ``buffer`` and append match dicts.

        Iterates with ``re.search`` and advances by one byte after each
        hit so overlapping matches are not skipped.

        Args:
            buffer: Raw memory buffer to search.
            buffer_base: Virtual address of ``buffer[0]``.
            compiled: Pre-compiled regex matching the wildcard pattern.
            pat_len: Pattern length in bytes.
            alignment: Only return matches at addresses divisible by this value.
            matches: Output list that match dicts are appended to.
        """
        buffer_len = len(buffer)
        if buffer_len < pat_len:
            return
        pos = 0
        while pos <= buffer_len - pat_len:
            match = compiled.search(buffer, pos)
            if match is None:
                return
            addr = buffer_base + match.start()
            if addr % alignment == 0:
                matches.append({"address": hex(addr), "offset": addr})
            pos = match.start() + 1

    async def run_to(self, address: int) -> dict[str, Any]:
        """Run execution until a specific address is reached.

        Sends the ``runto`` console command, then polls ``reg_get rip``
        with a bounded timeout to confirm the debugger has actually
        reached ``address``. The previous implementation returned
        ``{"success": True}`` immediately after queuing the command,
        even though x64dbg's interpreter dispatches ``runto``
        asynchronously and the IP may still be at the original site
        (audit6.md F-0001).

        Args:
            address: Target address to run to.

        Returns:
            dict[str, Any]: Dict with ``success``, ``target`` (hex
            string), ``current_ip`` (hex string of the IP observed
            after the command settled), and ``verified`` (bool). When
            the bridge cannot poll ``reg_get`` because the plugin is
            older, ``current_ip`` is ``None`` and ``verified`` is
            ``False``.

        Raises:
            ToolError: If the IP did not reach ``target`` within the
                configured timeout.
        """
        _logger.debug("run_to_queueing", address=hex(address))
        await self._send_pipe_command("exec", {"command": f"runto {hex(address)}"})
        observed = await self._wait_for_instruction_pointer(
            address,
            timeout_s=self.RUN_TO_TIMEOUT,
        )
        if observed is None:
            return {
                "success": True,
                "target": hex(address),
                "current_ip": None,
                "verified": False,
            }
        if observed != address:
            msg = f"run_to verification failed: instruction pointer is {hex(observed)} after timeout, expected {hex(address)}"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_TIMEOUT,
                    "target": hex(address),
                    "observed": hex(observed),
                },
            )
        _logger.info("run_to_reached", address=hex(address))
        return {
            "success": True,
            "target": hex(address),
            "current_ip": hex(observed),
            "verified": True,
        }

    async def _wait_for_instruction_pointer(
        self,
        target: int,
        *,
        timeout_s: float,
    ) -> int | None:
        """Poll ``reg_get rip`` until the IP reaches ``target`` or timeout.

        Used to verify that an asynchronous control-flow command (e.g.
        ``runto``) actually landed at the requested address before
        reporting success. Returns ``None`` when the plugin lacks the
        ``reg_get`` RPC (older builds) so the caller can surface
        ``verified=False`` instead of synthesising an unverified
        success status.

        Args:
            target: Address the instruction pointer should reach.
            timeout_s: Maximum total seconds to poll before giving up.

        Returns:
            int | None: The instruction pointer value last observed -
            ``target`` when the wait succeeded, the last sampled value
            when the timeout elapsed, or ``None`` when polling could
            not be performed.

        Raises:
            ToolError: If ``reg_get rip`` fails with any code other
                than ``unknown_command`` (e.g. pipe disconnected, real
                RPC error). Unknown-command failures are silently
                converted to ``None`` so older plugins skip polling.
        """
        deadline = asyncio.get_running_loop().time() + timeout_s
        last_ip: int | None = None
        while True:
            try:
                rip_result = await self._send_pipe_command("reg_get", {"name": "rip"})
            except ToolError as exc:
                if _x64dbg_error_code(exc) == _X64DBG_ERR_UNKNOWN_COMMAND:
                    return None
                log_passthrough(
                    _logger,
                    "wait_for_instruction_pointer_passthrough",
                    exc,
                    bridge="x64dbg",
                    rpc="reg_get",
                    x64dbg_error_code=_x64dbg_error_code(exc),
                )
                raise
            ip_value: int | None = None
            if isinstance(rip_result, int):
                ip_value = rip_result
            elif isinstance(rip_result, str):
                ip_value = safe_int_from_str(rip_result, base=0, context="x64dbg_wait_for_ip")
            if ip_value is not None:
                last_ip = ip_value
                if last_ip == target:
                    return last_ip
            if asyncio.get_running_loop().time() >= deadline:
                return last_ip
            await asyncio.sleep(self.RUN_TO_POLL_INTERVAL)

    async def _lookup_annotation_text(self, rpc: str, address: int) -> str | None:
        """Read the label/comment text at ``address`` via the given list RPC.

        Shared backend for :meth:`_lookup_label_text` (``lbl_list``)
        and :meth:`_lookup_comment_text` (``cmt_list``). Returns
        ``None`` when the plugin reports the RPC is unknown so callers
        can flag the verification as unavailable rather than synthesise
        success.

        Args:
            rpc: ``"lbl_list"`` or ``"cmt_list"``.
            address: Address whose annotation should be read.

        Returns:
            str | None: The annotation text at ``address`` (empty
            string when no annotation exists), or ``None`` when the
            plugin lacks the requested RPC.

        Raises:
            ToolError: If ``rpc`` fails with any code other than
                ``unknown_command``.
        """
        try:
            result = await self._send_pipe_command(rpc, {"start": address, "end": address})
        except ToolError as exc:
            if _x64dbg_error_code(exc) == _X64DBG_ERR_UNKNOWN_COMMAND:
                return None
            log_passthrough(
                _logger,
                "lookup_annotation_text_passthrough",
                exc,
                bridge="x64dbg",
                rpc=rpc,
                address=hex(address),
                x64dbg_error_code=_x64dbg_error_code(exc),
            )
            raise
        if not isinstance(result, list):
            return ""
        for entry in result:
            if not _is_str_obj_dict(entry):
                continue
            raw_addr = entry.get("address")
            raw_text = entry.get("text")
            addr_str = raw_addr if isinstance(raw_addr, str) else ""
            text = raw_text if isinstance(raw_text, str) else ""
            addr_val = safe_int_from_str(addr_str, base=0, context="x64dbg_lookup_annotation_text")
            if addr_val is None:
                continue
            if addr_val == address:
                return text
        return ""

    async def _lookup_label_text(self, address: int) -> str | None:
        """Read the label currently assigned to ``address`` via ``lbl_list``.

        Used by :meth:`set_label` to confirm the plugin actually wrote
        the requested label (audit7.md F-0001). Propagates any
        ``ToolError`` raised by :meth:`_lookup_annotation_text` other
        than the recoverable ``unknown_command`` code.

        Args:
            address: Address whose label should be read.

        Returns:
            str | None: The label text at ``address`` (empty string
            when the address has no label), or ``None`` when the
            plugin lacks ``lbl_list`` support.
        """
        return await self._lookup_annotation_text("lbl_list", address)

    async def _lookup_comment_text(self, address: int) -> str | None:
        """Read the comment currently assigned to ``address`` via ``cmt_list``.

        Used by :meth:`set_comment` to confirm the plugin actually wrote
        the requested comment (audit7.md F-0001). Propagates any
        ``ToolError`` raised by :meth:`_lookup_annotation_text` other
        than the recoverable ``unknown_command`` code.

        Args:
            address: Address whose comment should be read.

        Returns:
            str | None: The comment text at ``address`` (empty string
            when the address has no comment), or ``None`` when the
            plugin lacks ``cmt_list`` support.
        """
        return await self._lookup_annotation_text("cmt_list", address)

    async def _query_bp_list(self) -> list[object] | None:
        """Fetch the breakpoint list, or ``None`` when the RPC is unknown.

        Returns:
            list[object] | None: The raw ``bp_list`` payload as a list,
            or ``None`` when the plugin reports ``unknown_command``.

        Raises:
            ToolError: If ``bp_list`` fails with any code other than
                ``unknown_command``.
        """
        try:
            result = await self._send_pipe_command("bp_list")
        except ToolError as exc:
            if _x64dbg_error_code(exc) == _X64DBG_ERR_UNKNOWN_COMMAND:
                return None
            log_passthrough(
                _logger,
                "query_bp_list_passthrough",
                exc,
                bridge="x64dbg",
                rpc="bp_list",
                x64dbg_error_code=_x64dbg_error_code(exc),
            )
            raise
        return result if isinstance(result, list) else []

    @staticmethod
    def _find_bp_enabled(entries: list[object], address: int) -> bool | None:
        """Extract the ``enabled`` flag for ``address`` from a ``bp_list`` payload.

        Args:
            entries: Raw entries returned by the plugin.
            address: Breakpoint address to find.

        Returns:
            bool | None: The ``enabled`` flag for the matched
            breakpoint, or ``None`` when no entry matched.
        """
        for entry in entries:
            if not _is_str_obj_dict(entry):
                continue
            entry_addr = _coerce_address(entry.get("address"))
            if entry_addr != address:
                continue
            enabled_raw = entry.get("enabled")
            return enabled_raw if isinstance(enabled_raw, bool) else None
        return None

    async def _wait_for_breakpoint_enabled_state(
        self,
        address: int,
        *,
        expected: bool,
    ) -> tuple[bool | None, bool]:
        """Poll ``bp_list`` until a breakpoint's enabled flag matches ``expected``.

        Propagates any ``ToolError`` raised by ``_query_bp_list`` (i.e.
        any ``bp_list`` failure that is not the recoverable
        ``unknown_command`` code).

        Args:
            address: Breakpoint address.
            expected: Expected ``enabled`` flag value.

        Returns:
            tuple[bool | None, bool]: ``(observed, rpc_available)``.
            ``observed`` is the most recent ``enabled`` value (``True``
            or ``False``) when the breakpoint appeared in ``bp_list``
            at least once, otherwise ``None``. ``rpc_available`` is
            ``True`` when the plugin answered ``bp_list`` at any poll
            (even with no matching entry), ``False`` when the RPC was
            reported unknown for every attempt.
        """
        deadline = asyncio.get_running_loop().time() + self.VERIFY_TIMEOUT
        last_state: bool | None = None
        rpc_available = False
        while True:
            entries = await self._query_bp_list()
            if entries is not None:
                rpc_available = True
                current = self._find_bp_enabled(entries, address)
                if current is not None:
                    last_state = current
                    if last_state == expected:
                        return last_state, rpc_available
            if asyncio.get_running_loop().time() >= deadline:
                return last_state, rpc_available
            await asyncio.sleep(self.VERIFY_POLL_INTERVAL)

    async def _query_thread_details(self) -> list[dict[str, Any]] | None:
        """Fetch the full thread detail list from the plugin.

        Returns:
            list[dict[str, Any]] | None: The list of per-thread record
            dicts, or ``None`` when the plugin reports
            ``unknown_command`` for ``thread_detail``.

        Raises:
            ToolError: If ``thread_detail`` fails with any code other
                than ``unknown_command``.
        """
        try:
            result = await self._send_pipe_command("thread_detail")
        except ToolError as exc:
            if _x64dbg_error_code(exc) == _X64DBG_ERR_UNKNOWN_COMMAND:
                return None
            log_passthrough(
                _logger,
                "query_thread_details_passthrough",
                exc,
                bridge="x64dbg",
                rpc="thread_detail",
                x64dbg_error_code=_x64dbg_error_code(exc),
            )
            raise
        if not isinstance(result, list):
            return []
        return [dict(entry) for entry in result if _is_str_obj_dict(entry)]

    @staticmethod
    def _find_thread_record(entries: list[dict[str, Any]], tid: int) -> dict[str, Any] | None:
        """Locate the per-thread record with the given thread id.

        Args:
            entries: Records returned by ``thread_detail``.
            tid: Thread identifier to find.

        Returns:
            dict[str, Any] | None: The matched record, or ``None``.
        """
        for entry in entries:
            raw_id = entry.get("threadId")
            if isinstance(raw_id, int) and raw_id == tid:
                return entry
        return None

    async def _wait_for_thread_state(
        self,
        tid: int,
        *,
        predicate: Callable[[dict[str, Any]], bool],
    ) -> tuple[dict[str, Any] | None, bool]:
        """Poll ``thread_detail`` until ``predicate`` evaluates true.

        Propagates any ``ToolError`` raised by ``_query_thread_details``
        (i.e. any ``thread_detail`` failure that is not the recoverable
        ``unknown_command`` code).

        Args:
            tid: Thread identifier.
            predicate: Callable that returns ``True`` once the thread's
                observed state satisfies the wrapper's post-condition.

        Returns:
            tuple[dict[str, Any] | None, bool]: ``(record,
            rpc_available)``. ``record`` is the matched thread record
            once ``predicate`` was satisfied, the last observed record
            if the deadline elapsed, or ``None`` when the thread never
            appeared in any successful poll. ``rpc_available`` is
            ``True`` when ``thread_detail`` answered at least once,
            ``False`` when the RPC was reported unknown for every
            attempt.
        """
        deadline = asyncio.get_running_loop().time() + self.VERIFY_TIMEOUT
        last_record: dict[str, Any] | None = None
        rpc_available = False
        while True:
            entries = await self._query_thread_details()
            if entries is not None:
                rpc_available = True
                record = self._find_thread_record(entries, tid)
                if record is not None:
                    last_record = record
                    if predicate(record):
                        return record, rpc_available
            if asyncio.get_running_loop().time() >= deadline:
                return last_record, rpc_available
            await asyncio.sleep(self.VERIFY_POLL_INTERVAL)

    async def _wait_for_running_state(
        self,
        *,
        expected: bool,
    ) -> tuple[bool | None, bool]:
        """Poll ``status`` until the debugger's running flag matches ``expected``.

        Args:
            expected: ``True`` to wait until the debugger is running,
                ``False`` to wait until it is paused.

        Returns:
            tuple[bool | None, bool]: ``(observed, rpc_available)``.
            ``observed`` is the most recent ``is_running`` value
            sampled from ``status`` (``True``=running, ``False``=paused)
            when ``status`` answered at least once, otherwise ``None``.
            ``rpc_available`` is ``True`` when ``status`` answered at
            any poll, ``False`` when the RPC was reported unknown for
            every attempt.

        Raises:
            ToolError: If ``status`` fails with any code other than
                ``unknown_command``.
        """
        deadline = asyncio.get_running_loop().time() + self.VERIFY_TIMEOUT
        last_state: bool | None = None
        rpc_available = False
        while True:
            try:
                result = await self._send_pipe_command("status")
            except ToolError as exc:
                if _x64dbg_error_code(exc) == _X64DBG_ERR_UNKNOWN_COMMAND:
                    if asyncio.get_running_loop().time() >= deadline:
                        return last_state, rpc_available
                    await asyncio.sleep(self.VERIFY_POLL_INTERVAL)
                    continue
                log_passthrough(
                    _logger,
                    "wait_for_running_state_passthrough",
                    exc,
                    bridge="x64dbg",
                    rpc="status",
                    x64dbg_error_code=_x64dbg_error_code(exc),
                )
                raise
            rpc_available = True
            current: bool | None = None
            if _is_str_obj_dict(result):
                paused_raw = result.get("paused")
                debugging_raw = result.get("debugging")
                if isinstance(paused_raw, bool) and isinstance(debugging_raw, bool):
                    current = debugging_raw and not paused_raw
                elif isinstance(paused_raw, bool):
                    current = not paused_raw
            if current is not None:
                last_state = current
                if current == expected:
                    return current, rpc_available
            if asyncio.get_running_loop().time() >= deadline:
                return last_state, rpc_available
            await asyncio.sleep(self.VERIFY_POLL_INTERVAL)

    async def _query_script_error(self) -> bool | None:
        """Query the script-error register via the x64dbg expression evaluator.

        x64dbg exposes ``script.iserror()`` which returns 1 when the
        most recently executed script command raised an error. Used to
        verify :meth:`script_load`, :meth:`script_run`,
        :meth:`script_cmd`, and :meth:`script_abort` (audit7.md F-0001).

        Returns:
            bool | None: ``True`` when the script error flag is set,
            ``False`` when it is clear, or ``None`` when neither the
            expression evaluator nor the ``script.iserror()`` symbol
            is available on the current plugin/x64dbg build.

        Raises:
            ToolError: If ``eval`` fails with any code other than
                ``unknown_command``.
        """
        try:
            value = await self.evaluate_expression("script.iserror()")
        except ToolError as exc:
            code = _x64dbg_error_code(exc)
            if code == _X64DBG_ERR_UNKNOWN_COMMAND:
                return None
            log_passthrough(
                _logger,
                "query_script_error_passthrough",
                exc,
                bridge="x64dbg",
                rpc="script.iserror()",
                x64dbg_error_code=code,
            )
            raise
        return bool(value)

    async def _query_plugin_present(self, name: str) -> bool | None:
        """Check whether a plugin called ``name`` is loaded.

        First attempts the structured ``plugin_list`` RPC and inspects
        any returned dict entries for a matching plugin name. Falls
        back to ``plugin.find(<name>)`` via the expression evaluator
        which x64dbg implements to return a non-zero plugin handle when
        the plugin is loaded.

        Args:
            name: Plugin display name (without ``.dp64`` extension).

        Returns:
            bool | None: ``True`` if the plugin is present, ``False``
            if absent, or ``None`` when neither verification path is
            available on the current plugin build.

        Raises:
            ToolError: If either underlying RPC fails with any code
                other than ``unknown_command``.
        """
        list_result: object | None = None
        try:
            list_result = await self._send_pipe_command("plugin_list")
        except ToolError as exc:
            if _x64dbg_error_code(exc) != _X64DBG_ERR_UNKNOWN_COMMAND:
                log_passthrough(
                    _logger,
                    "query_plugin_present_plugin_list_passthrough",
                    exc,
                    bridge="x64dbg",
                    rpc="plugin_list",
                    plugin=name,
                    x64dbg_error_code=_x64dbg_error_code(exc),
                )
                raise
        if isinstance(list_result, list):
            needle = name.lower()
            for entry in list_result:
                if not _is_str_obj_dict(entry):
                    continue
                raw_name = entry.get("name") or entry.get("plugName") or entry.get("pluginName")
                if isinstance(raw_name, str) and raw_name.lower() == needle:
                    return True
            return False
        try:
            handle = await self.evaluate_expression(f'plugin.find("{name}")')
        except ToolError as exc:
            if _x64dbg_error_code(exc) == _X64DBG_ERR_UNKNOWN_COMMAND:
                return None
            log_passthrough(
                _logger,
                "query_plugin_present_plugin_find_passthrough",
                exc,
                bridge="x64dbg",
                rpc="plugin.find",
                plugin=name,
                x64dbg_error_code=_x64dbg_error_code(exc),
            )
            raise
        return handle != 0

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
        """Set a debug label at an address and verify the label was applied.

        After queuing the ``lblset`` console command, reads the label
        back via the ``lbl_list`` plugin RPC and compares it against
        ``text``. The wrapper used to claim ``success: True`` without
        inspecting the result of the queued console command
        (audit7.md F-0001).

        Args:
            address: Address for the label.
            text: Label text.

        Returns:
            dict[str, Any]: Dict with ``success``, ``address``,
            ``text``, and ``verified``. ``verified`` is ``True`` when
            the plugin readback observed ``text`` at ``address``;
            ``False`` only when the plugin lacks ``lbl_list`` so a
            readback cannot be performed.

        Raises:
            ToolError: If the readback observes a different label
                (or no label) at ``address`` after the verification
                window elapses.
        """
        _logger.debug("x64dbg_command_queued", command="lblset", address=hex(address), label_text=text)
        await self._send_pipe_command("exec", {"command": f"lblset {hex(address)}, {text}"})
        observed = await self._lookup_label_text(address)
        if observed is None:
            return {"address": hex(address), "text": text, "success": True, "verified": False}
        if observed != text:
            msg = f"set_label verification failed: label at {hex(address)} is {observed!r} after lblset, expected {text!r}"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_REMOTE,
                    "address": hex(address),
                    "expected": text,
                    "observed": observed,
                },
            )
        return {"address": hex(address), "text": text, "success": True, "verified": True}

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
            _logger.warning("labels_list_failed", error=str(exc))
            return []

        labels: list[dict[str, Any]] = []
        if isinstance(result, list):
            for entry in result:
                if _is_str_obj_dict(entry):
                    raw_addr = entry.get("address")
                    raw_text = entry.get("text")
                    addr_str = raw_addr if isinstance(raw_addr, str) else ""
                    text = raw_text if isinstance(raw_text, str) else ""
                    addr = safe_int_from_str(addr_str, base=0, context="x64dbg_get_labels")
                    if addr is None:
                        continue
                    if start <= addr <= end:
                        labels.append({"address": addr_str, "text": text})
        return labels

    async def set_comment(self, address: int, text: str) -> dict[str, Any]:
        """Set a debug comment at an address and verify the comment was applied.

        After queuing the ``cmtset`` console command, reads the comment
        back via the ``cmt_list`` plugin RPC and compares it against
        ``text``. The wrapper used to claim ``success: True`` without
        inspecting the result of the queued console command
        (audit7.md F-0001).

        Args:
            address: Address for the comment.
            text: Comment text.

        Returns:
            dict[str, Any]: Dict with ``success``, ``address``,
            ``text``, and ``verified``. ``verified`` is ``True`` when
            the plugin readback observed ``text`` at ``address``;
            ``False`` only when the plugin lacks ``cmt_list`` so a
            readback cannot be performed.

        Raises:
            ToolError: If the readback observes a different comment
                (or no comment) at ``address`` after the verification
                window elapses.
        """
        _logger.debug("x64dbg_command_queued", command="cmtset", address=hex(address))
        await self._send_pipe_command("exec", {"command": f"cmtset {hex(address)}, {text}"})
        observed = await self._lookup_comment_text(address)
        if observed is None:
            return {"address": hex(address), "text": text, "success": True, "verified": False}
        if observed != text:
            msg = f"set_comment verification failed: comment at {hex(address)} is {observed!r} after cmtset, expected {text!r}"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_REMOTE,
                    "address": hex(address),
                    "expected": text,
                    "observed": observed,
                },
            )
        return {"address": hex(address), "text": text, "success": True, "verified": True}

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
            _logger.warning("comments_list_failed", error=str(exc))
            return []

        comments: list[dict[str, Any]] = []
        if isinstance(result, list):
            for entry in result:
                if _is_str_obj_dict(entry):
                    raw_addr = entry.get("address")
                    raw_text = entry.get("text")
                    addr_str = raw_addr if isinstance(raw_addr, str) else ""
                    text = raw_text if isinstance(raw_text, str) else ""
                    addr = safe_int_from_str(addr_str, base=0, context="x64dbg_get_comments")
                    if addr is None:
                        continue
                    if start <= addr <= end:
                        comments.append({"address": addr_str, "text": text})
        return comments

    async def enable_breakpoint(self, address: int) -> dict[str, Any]:
        """Enable a breakpoint at an address and verify the debugger applied it.

        After queuing the ``be`` console command, polls ``bp_list`` and
        confirms the breakpoint at ``address`` is reported with
        ``enabled=True``. The wrapper used to claim ``success: True``
        and update the local ``_breakpoints`` mirror without inspecting
        the debugger's authoritative state (audit7.md F-0001).

        Args:
            address: Breakpoint address.

        Returns:
            dict[str, Any]: Dict with ``success``, ``address``, and
            ``verified``. ``verified`` is ``True`` when ``bp_list``
            reports ``enabled=True`` for the address; ``False`` only
            when the plugin lacks ``bp_list``.

        Raises:
            ToolError: If the debugger continues to report
                ``enabled=False`` (or no entry at all) at ``address``
                after the verification window elapses.
        """
        _logger.debug("x64dbg_command_queued", command="be", address=hex(address))
        await self._send_pipe_command("exec", {"command": f"be {hex(address)}"})
        observed, rpc_available = await self._wait_for_breakpoint_enabled_state(address, expected=True)
        if observed is False:
            msg = f"enable_breakpoint verification failed: bp_list reports enabled=False for {hex(address)}"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_REMOTE,
                    "address": hex(address),
                    "expected_enabled": True,
                    "observed_enabled": False,
                },
            )
        if observed is None and rpc_available:
            msg = f"enable_breakpoint verification failed: bp_list returned no entry for {hex(address)} within {self.VERIFY_TIMEOUT}s"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_TIMEOUT,
                    "address": hex(address),
                    "expected_enabled": True,
                },
            )
        verified = observed is True
        with self._state_lock:
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
        return {"address": hex(address), "success": True, "verified": verified}

    async def disable_breakpoint(self, address: int) -> dict[str, Any]:
        """Disable a breakpoint at an address and verify the debugger applied it.

        After queuing the ``bd`` console command, polls ``bp_list`` and
        confirms the breakpoint at ``address`` is reported with
        ``enabled=False``. The wrapper used to claim ``success: True``
        and update the local ``_breakpoints`` mirror without inspecting
        the debugger's authoritative state (audit7.md F-0001).

        Args:
            address: Breakpoint address.

        Returns:
            dict[str, Any]: Dict with ``success``, ``address``, and
            ``verified``. ``verified`` is ``True`` when ``bp_list``
            reports ``enabled=False`` for the address; ``False`` only
            when the plugin lacks ``bp_list``.

        Raises:
            ToolError: If the debugger continues to report
                ``enabled=True`` (or no entry at all) at ``address``
                after the verification window elapses.
        """
        _logger.debug("x64dbg_command_queued", command="bd", address=hex(address))
        await self._send_pipe_command("exec", {"command": f"bd {hex(address)}"})
        observed, rpc_available = await self._wait_for_breakpoint_enabled_state(address, expected=False)
        if observed is True:
            msg = f"disable_breakpoint verification failed: bp_list reports enabled=True for {hex(address)}"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_REMOTE,
                    "address": hex(address),
                    "expected_enabled": False,
                    "observed_enabled": True,
                },
            )
        if observed is None and rpc_available:
            msg = f"disable_breakpoint verification failed: bp_list returned no entry for {hex(address)} within {self.VERIFY_TIMEOUT}s"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_TIMEOUT,
                    "address": hex(address),
                    "expected_enabled": False,
                },
            )
        verified = observed is False
        with self._state_lock:
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
        return {"address": hex(address), "success": True, "verified": verified}

    async def set_breakpoint_on_api(self, module: str, function: str) -> dict[str, Any]:
        """Set a breakpoint on an imported API function.

        Resolves the function via x64dbg's expression evaluator
        (``GetProcAddress(<module>,"<function>")``); when that yields a
        non-zero VA the breakpoint is installed at the resolved address
        through ``set_breakpoint``. When ``GetProcAddress`` returns 0
        (unresolved forwarder, ordinal-only export, manifest-resolved
        import, etc.) the call falls back to the historical
        ``bpx module.function`` script command and surfaces
        ``resolved_address: None`` / ``resolution_method: "bpx"`` so
        callers can detect the unresolved case.

        Args:
            module: Module name (e.g. 'kernel32').
            function: Function name (e.g. 'CreateFileW').

        Returns:
            dict[str, Any]: Dict with ``success``, ``target``,
            ``resolved_address`` (hex string of VA or ``None``),
            ``resolution_method`` (``"GetProcAddress"`` or ``"bpx"``),
            and ``breakpoint_id`` (only when set via ``set_breakpoint``).
        """
        target = f"{module}.{function}"
        _logger.debug("api_breakpoint_resolving", target=target)
        resolution_expr = f'GetProcAddress({module},"{function}")'
        try:
            resolved_va = await self.evaluate_expression(resolution_expr)
        except ToolError as exc:
            _logger.warning(
                "api_breakpoint_resolution_eval_failed",
                target=target,
                error=str(exc),
            )
            resolved_va = 0

        if resolved_va > 0:
            bp_id = await self.set_breakpoint(resolved_va, "software")
            _logger.info(
                "api_breakpoint_setting",
                target=target,
                resolved_address=hex(resolved_va),
                method="GetProcAddress",
                breakpoint_id=bp_id,
            )
            return {
                "success": True,
                "target": target,
                "resolved_address": hex(resolved_va),
                "resolution_method": "GetProcAddress",
                "breakpoint_id": bp_id,
            }

        _logger.info(
            "api_breakpoint_setting",
            target=target,
            resolved_address="unresolved",
            method="bpx",
        )
        await self._send_pipe_command("exec", {"command": f"bpx {target}"})
        return {
            "success": True,
            "target": target,
            "resolved_address": None,
            "resolution_method": "bpx",
        }

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
        if detect_format(dos_header) != "pe":
            msg = f"Invalid DOS header in {module_name}"
            raise ToolError(msg)

        pe_offset = read_dos_e_lfanew(dos_header)
        pe_header = await self.read_memory(base_address + pe_offset, size)

        if pe_header[:4] != PE_SIGNATURE:
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
        section = unpack_section_header(sec_data, sec_offset)
        virtual_address = cast("int", section["virtual_address"])
        characteristics = cast("int", section["characteristics"])
        return {
            "name": section["name"],
            "virtual_address": hex(base_address + virtual_address),
            "virtual_size": section["virtual_size"],
            "raw_size": section["raw_size"],
            "characteristics": hex(characteristics),
            "readable": bool(characteristics & PE_SECTION_CHARACTERISTIC_READ),
            "writable": bool(characteristics & PE_SECTION_CHARACTERISTIC_WRITE),
            "executable": bool(characteristics & PE_SECTION_CHARACTERISTIC_EXECUTE),
        }

    async def get_module_sections(self, module_name: str) -> list[dict[str, Any]]:
        """Get PE section info of a loaded module by parsing its in-memory header.

        Args:
            module_name: Module name (e.g. 'ntdll.dll').

        Returns:
            list[dict[str, Any]]: List of section dicts with name, virtual_address, virtual_size,
            raw_size, and characteristics.
        """
        _logger.debug("module_sections_reading", module_name=module_name)
        base_address = await self._resolve_module_base(module_name)
        pe_offset, pe_header = await self._read_pe_header(base_address, module_name)

        _machine, num_sections, optional_header_size, _characteristics = unpack_coff_header(pe_header, 4)
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
        is_pe64 = is_pe64_optional_header(pe_header, PE_OPTIONAL_HEADER_OFFSET)
        export_dir_offset = get_data_directory_offset(0, is_pe64=is_pe64, entry_index=0)

        if export_dir_offset + 8 > len(pe_header):
            msg = "PE header too small for export directory"
            raise ToolError(msg)

        export_rva, export_size = read_data_directory_entry(pe_header, export_dir_offset)

        if export_rva == 0 or export_size == 0:
            msg = "No export directory"
            raise ToolError(msg)

        export_dir = await self.read_memory(
            base_address + export_rva,
            min(export_size, PE_EXPORT_DIR_MIN_SIZE),
        )

        num_functions = struct.unpack_from("<I", export_dir, 20)[0]
        num_names = struct.unpack_from("<I", export_dir, 24)[0]
        ordinal_base = struct.unpack_from("<I", export_dir, 16)[0]

        addr_table = await self.read_memory(base_address + struct.unpack_from("<I", export_dir, 28)[0], num_functions * 4)
        name_ptrs = await self.read_memory(base_address + struct.unpack_from("<I", export_dir, 32)[0], num_names * 4)
        ordinal_table = await self.read_memory(base_address + struct.unpack_from("<I", export_dir, 36)[0], num_names * 2)

        return addr_table, name_ptrs, ordinal_table, num_names, ordinal_base, num_functions

    async def _read_export_name(
        self,
        base_address: int,
        name_rva: int,
        ordinal: int,
        module_name: str,
    ) -> tuple[str, ToolError | None]:
        """Read a single PE export name from process memory.

        Args:
            base_address: Module base address.
            name_rva: Relative virtual address of the name string.
            ordinal: Resolved ordinal for the export, used for the
                synthetic name when the read is silently skipped.
            module_name: Module name for diagnostic logging.

        Returns:
            tuple[str, ToolError | None]: Tuple of (resolved name,
            recoverable read error). The error is non-None only when the
            read failed with a recoverable pipe/file error.

        Raises:
            ToolError: If ``read_memory`` raises a non-recoverable error
                that callers must surface.
        """
        try:
            name_data = await self.read_memory(base_address + name_rva, PE_EXPORT_NAME_BUF)
        except ToolError as exc:
            if not self._is_recoverable_pipe_error(exc):
                raise
            _logger.warning(
                "export_name_read_recoverable",
                module_name=module_name,
                ordinal=ordinal,
                error=str(exc),
            )
            return f"ordinal_{ordinal}", exc

        null_pos = name_data.find(b"\x00")
        return name_data[: null_pos if null_pos != -1 else PE_EXPORT_NAME_BUF].decode("ascii", errors="replace"), None

    async def _build_export_entries(
        self,
        base_address: int,
        module_name: str,
        tables: tuple[bytes, bytes, bytes, int, int, int],
    ) -> tuple[list[dict[str, Any]], ToolError | None]:
        """Build per-export dicts from previously-read PE export tables.

        Walks every named export reported by the PE export directory; no
        cap is applied. When ``num_names`` exceeds the
        ``PE_EXPORT_MAX`` soft threshold a warning log is emitted but
        enumeration continues, and every entry carries an explicit
        ``truncated`` field set to ``False``.

        Args:
            base_address: Module base address.
            module_name: Module name for diagnostic logging.
            tables: Tuple returned by ``_read_export_tables``: (addr_table,
                name_ptrs, ordinal_table, num_names, ordinal_base, num_functions).

        Returns:
            tuple[list[dict[str, Any]], ToolError | None]: Tuple of
            (exports list, last recoverable read error if any).
            Non-recoverable read errors are propagated from
            ``_read_export_name`` rather than returned.
        """
        addr_table, name_ptrs, ordinal_table, num_names, ordinal_base, _ = tables
        exports: list[dict[str, Any]] = []
        last_error: ToolError | None = None
        if num_names > PE_EXPORT_MAX:
            _logger.warning(
                "module_exports_large",
                module_name=module_name,
                num_names=num_names,
                soft_limit=PE_EXPORT_MAX,
            )
        for i in range(num_names):
            name_rva = struct.unpack_from("<I", name_ptrs, i * 4)[0]
            ordinal_index = struct.unpack_from("<H", ordinal_table, i * 2)[0]
            func_rva = struct.unpack_from("<I", addr_table, ordinal_index * 4)[0]
            ordinal = ordinal_base + ordinal_index
            func_name, read_error = await self._read_export_name(base_address, name_rva, ordinal, module_name)
            if read_error is not None:
                last_error = read_error
            exports.append({
                "ordinal": ordinal,
                "name": func_name,
                "address": hex(base_address + func_rva),
                "truncated": False,
            })
        return exports, last_error

    async def get_module_exports(self, module_name: str) -> list[dict[str, Any]]:
        """Get exports of a loaded module by parsing its in-memory PE export table.

        Per-name ``read_memory`` failures with a non-pipe / non-file-not-found
        error are propagated from ``_build_export_entries`` so callers see
        real plugin or RPC failures. Recoverable pipe/file errors during
        name reads are tolerated and the affected entry's ``name`` field
        is set to the synthetic ``ordinal_<N>`` form.

        Args:
            module_name: Module name (e.g. 'kernel32.dll').

        Returns:
            list[dict[str, Any]]: List of export dicts with ordinal, name, and address.
        """
        _logger.debug("module_exports_reading", module_name=module_name)
        base_address = await self._resolve_module_base(module_name)
        _, pe_header = await self._read_pe_header(base_address, module_name, size=512)

        try:
            tables = await self._read_export_tables(base_address, pe_header)
        except ToolError as exc:
            _logger.warning("export_tables_read_failed", module_name=module_name, error=str(exc))
            return []

        exports, last_error = await self._build_export_entries(base_address, module_name, tables)
        if last_error is not None:
            _logger.debug("module_exports_partial", module_name=module_name, last_error=str(last_error))
        return exports

    async def get_entry_point(self, module_name: str | None = None) -> dict[str, Any]:
        """Read the PE AddressOfEntryPoint for a loaded module.

        Parses the module's in-memory PE header (DOS header, NT headers,
        Optional Header) to extract the entry point RVA and compute the
        fully-resolved virtual address.

        Args:
            module_name: Module to query. Uses the attached binary's
                module when None.

        Returns:
            dict[str, Any]: Dict with ``module``, ``base_address``,
            ``entry_point_rva``, and ``entry_point_va`` fields.

        Raises:
            ToolError: If no module can be resolved or the PE header is
                invalid.
        """
        target_module: str
        if module_name is not None:
            target_module = module_name
        elif self._binary_path is not None:
            target_module = self._binary_path.name
        else:
            modules = await self.get_modules()
            if not modules:
                msg = "No modules loaded; cannot determine entry point"
                raise ToolError(msg, tool_name="x64dbg")
            target_module = modules[0].name

        base_address = await self._resolve_module_base(target_module)
        pe_offset, pe_header = await self._read_pe_header(base_address, target_module, size=256)

        if len(pe_header) < NT_HEADERS_OPTIONAL_OFFSET + PE_ENTRY_POINT_OFFSET + 4:
            msg = f"PE header too small to read entry point in {target_module}"
            raise ToolError(msg, tool_name="x64dbg")

        entry_rva = struct.unpack_from("<I", pe_header, NT_HEADERS_OPTIONAL_OFFSET + PE_ENTRY_POINT_OFFSET)[0]
        entry_va = base_address + entry_rva

        _logger.debug(
            "entry_point_read",
            module_name=target_module,
            base=hex(base_address),
            pe_offset=hex(pe_offset),
            rva=hex(entry_rva),
            va=hex(entry_va),
        )
        return {
            "module": target_module,
            "base_address": hex(base_address),
            "entry_point_rva": hex(entry_rva),
            "entry_point_va": hex(entry_va),
        }


class _X64DbgTraceMixin(_X64DbgAnalysisMixin):
    """Tracing, patching, navigation, database, threads, PEB/TEB, watches, animation.

    Hosts the trace controller, patch lifecycle (assemble/nop/save/ restore/export), conditional tracing and step counting, cross- reference
    and string/intermodular discovery, expression evaluator, control-flow graph, database save/load/clear, thread switching and naming,
    SEH/PEB/TEB readers, PE directory inspection, watch expressions, logging/DLL/anti-debug breakpoint variants, and the animate start/stop
    loops.
    """

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
        _logger.info("trace_start_started", address=address)
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
        _logger.debug("x64dbg_command_queued", command="SetExceptionBPX", code=hex(code), handling=handling)
        handling_map = {"break": 1, "ignore": 0, "log": 2}
        handling_code = handling_map.get(handling, 1)
        await self._send_pipe_command("exec", {"command": f"SetExceptionBPX {hex(code)}, {handling_code}"})
        return {"success": True, "code": hex(code), "handling": handling}

    async def patch_instruction(self, address: int, instruction: str) -> dict[str, Any]:
        """Assemble and write an instruction at address, then verify the patch.

        Issues the plugin's ``assemble`` RPC and, when attached, reads
        memory back at ``address`` to confirm the bytes actually
        changed. Returns the post-patch byte string so callers can
        correlate the assembled output with the requested mnemonic
        (audit6.md F-0001).

        Args:
            address: Target address.
            instruction: Assembly instruction text.

        Returns:
            dict[str, Any]: Dict with ``success``, ``address``,
            ``instruction``, and ``patched_bytes`` (hex string of bytes
            now resident at ``address``). When the bridge is not yet
            attached and cannot read memory back, ``patched_bytes`` is
            ``None`` and ``verified`` is ``False``.

        Raises:
            ToolError: If the verifying read finds memory unchanged
                after the assemble RPC returned successfully.
        """
        _logger.info("patch_instruction_queueing", address=hex(address), instruction=instruction)
        original = await self._read_memory_for_verification(address, 16)
        await self._send_pipe_command(
            "assemble",
            {"address": hex(address), "instruction": instruction},
        )
        patched = await self._read_memory_for_verification(address, 16)
        if original is not None and patched is not None and original == patched:
            msg = f"patch_instruction verification failed: memory at {hex(address)} is unchanged after assemble"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={"x64dbg_error_code": _X64DBG_ERR_REMOTE, "address": hex(address)},
            )
        _logger.info("patching_instruction", address=hex(address), instruction=instruction)
        return {
            "success": True,
            "address": hex(address),
            "instruction": instruction,
            "patched_bytes": patched.hex() if patched is not None else None,
            "verified": patched is not None,
        }

    async def nop_range(self, address: int, size: int) -> dict[str, Any]:
        """Fill an address range with NOP (0x90) bytes and verify the fill.

        After issuing the ``fill`` console command, reads ``size`` bytes
        back from ``address`` (when attached) and confirms every byte is
        ``0x90``. The wrapper used to claim ``success: True``
        unconditionally; that masked silent fill failures (audit6.md
        F-0001).

        Args:
            address: Start address.
            size: Number of bytes to NOP.

        Returns:
            dict[str, Any]: Dict with ``success``, ``address``,
            ``size``, and ``verified``. When verification can be
            performed, ``verified`` is ``True`` and the dict echoes
            ``bytes_filled``.

        Raises:
            ToolError: If post-condition verification reads back any
                non-NOP byte in the requested range.
        """
        _logger.debug("nop_range_queueing", address=hex(address), size=size)
        await self._send_command(f"fill {hex(address)}, {size}, 90")
        verified = await self._read_memory_for_verification(address, size)
        if verified is None:
            _logger.info("nop_range_filling", address=hex(address), size=size)
            return {"success": True, "address": hex(address), "size": size, "verified": False}
        if verified != bytes([_X86_NOP_OPCODE]) * size:
            non_nop_offset = next(
                (off for off, b in enumerate(verified) if b != _X86_NOP_OPCODE),
                None,
            )
            failed_address = address + (non_nop_offset or 0)
            msg = f"nop_range verification failed: byte at {hex(failed_address)} is not {hex(_X86_NOP_OPCODE)} after fill"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_REMOTE,
                    "address": hex(address),
                    "size": size,
                },
            )
        _logger.info("nop_range_filled", address=hex(address), size=size)
        return {
            "success": True,
            "address": hex(address),
            "size": size,
            "verified": True,
            "bytes_filled": size,
        }

    async def _read_memory_for_verification(self, address: int, size: int) -> bytes | None:
        """Best-effort read used to verify a write side-effect.

        Returns ``None`` (rather than raising) when the bridge is not
        currently attached to a process or when the read otherwise
        cannot complete (no Win32 host, OpenProcess refused). In those
        cases the verification is skipped and the caller surfaces
        ``verified=False`` instead of synthesising an unverified
        success status.

        Args:
            address: Memory address to read.
            size: Number of bytes to read.

        Returns:
            bytes | None: The bytes read, or ``None`` when verification
            is not possible in the current environment.
        """
        if self._attached_pid is None or not _IS_WIN32:
            return None
        try:
            return await self.read_memory(address, size)
        except ToolError as exc:
            _logger.warning(
                "verification_read_failed",
                address=hex(address),
                size=size,
                error=str(exc),
            )
            return None

    async def get_module_imports(self, module_name: str) -> list[dict[str, Any]]:
        """Get imports of a loaded module via the plugin.

        Args:
            module_name: Module name (e.g. 'kernel32.dll').

        Returns:
            list[dict[str, Any]]: List of import dicts with iatRva, iatVa, ordinal, name, undecoratedName.
        """
        _logger.debug("module_imports_reading", module_name=module_name)
        result = await self._send_pipe_command("mod_imports", {"name": module_name})
        if isinstance(result, list):
            return [dict(entry) if _is_str_obj_dict(entry) else {} for entry in result]
        return []

    async def find_references(self, address: int) -> dict[str, Any]:
        """Find references to an address via the plugin's ``ref_search``.

        Args:
            address: Target address.

        Returns:
            dict[str, Any]: Dict with ``success``, ``address``, and any
            ``references`` returned by the plugin.
        """
        _logger.debug("finding_references", address=hex(address))
        result = await self._send_pipe_command(
            "ref_search",
            {"address": hex(address), "type": "reference"},
        )
        references: list[object] = result if isinstance(result, list) else []
        return {"success": True, "address": hex(address), "references": references}

    async def find_string_references(self, module: str) -> dict[str, Any]:
        """Find string references in a module via the plugin's ``ref_search``.

        Args:
            module: Module name.

        Returns:
            dict[str, Any]: Dict with ``success``, ``module``, and any
            ``references`` returned by the plugin.
        """
        _logger.debug("finding_string_references", module_name=module)
        result = await self._send_pipe_command(
            "ref_search",
            {"module": module, "type": "string"},
        )
        references: list[object] = result if isinstance(result, list) else []
        return {"success": True, "module": module, "references": references}

    async def find_intermodular_calls(self, module: str) -> dict[str, Any]:
        """Find intermodular calls in a module via the plugin's ``ref_search``.

        Args:
            module: Module name.

        Returns:
            dict[str, Any]: Dict with ``success``, ``module``, and any
            ``references`` returned by the plugin.
        """
        _logger.debug("finding_intermodular_calls", module_name=module)
        result = await self._send_pipe_command(
            "ref_search",
            {"module": module, "type": "intermodular"},
        )
        references: list[object] = result if isinstance(result, list) else []
        return {"success": True, "module": module, "references": references}

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
        """Save the x64dbg persistent analysis database.

        Routes through the plugin's ``db_save`` RPC so the save is
        serialised against the plugin's own persistence lock. Falls back
        to the ``dbsave`` script command if the plugin is older.

        Returns:
            dict[str, Any]: Dict with ``success`` status.

        Raises:
            ToolError: If the plugin reports a non-recoverable error.
        """
        _logger.info("database_saving")
        try:
            await self._send_pipe_command("db_save")
        except ToolError as exc:
            if not self._is_recoverable_pipe_error(exc):
                raise
            _logger.warning("db_save_pipe_unavailable_using_script", error=str(exc))
            await self._send_command("dbsave")
        return {"success": True}

    async def load_database(self) -> dict[str, Any]:
        """Load the x64dbg persistent analysis database.

        Returns:
            dict[str, Any]: Dict with ``success`` status.

        Raises:
            ToolError: If the plugin reports a non-recoverable error.
        """
        _logger.info("database_loading")
        try:
            await self._send_pipe_command("db_load")
        except ToolError as exc:
            if not self._is_recoverable_pipe_error(exc):
                raise
            _logger.warning("db_load_pipe_unavailable_using_script", error=str(exc))
            await self._send_command("dbload")
        return {"success": True}

    async def clear_database(self) -> dict[str, Any]:
        """Clear the x64dbg persistent analysis database.

        Returns:
            dict[str, Any]: Dict with ``success`` status.

        Raises:
            ToolError: If the plugin reports a non-recoverable error.
        """
        _logger.info("database_clearing")
        try:
            await self._send_pipe_command("db_clear")
        except ToolError as exc:
            if not self._is_recoverable_pipe_error(exc):
                raise
            _logger.warning("db_clear_pipe_unavailable_using_script", error=str(exc))
            await self._send_command("dbclear")
        return {"success": True}

    async def get_patches(self) -> list[dict[str, Any]]:
        """List all applied patches.

        Returns:
            list[dict[str, Any]]: List of patch dicts with address, oldByte, newByte.

        Raises:
            ToolError: If the plugin reports a non-recoverable error.
        """
        _logger.debug("patches_listing")
        try:
            result = await self._send_pipe_command("patch_list")
        except ToolError as exc:
            if not self._is_recoverable_pipe_error(exc):
                raise
            _logger.warning("patch_list_pipe_unavailable", error=str(exc))
            return []
        if isinstance(result, list):
            return [dict(entry) if _is_str_obj_dict(entry) else {} for entry in result]
        return []

    async def restore_patch(self, address: int) -> dict[str, Any]:
        """Restore original bytes at a patched address.

        Args:
            address: Address of the patch to restore.

        Returns:
            dict[str, Any]: Dict with success status.

        Raises:
            ToolError: If the plugin reports a non-recoverable error.
        """
        _logger.info("patch_restoring", address=hex(address))
        try:
            await self._send_pipe_command("patch_restore", {"address": hex(address)})
        except ToolError as exc:
            if not self._is_recoverable_pipe_error(exc):
                raise
            _logger.warning("patch_restore_pipe_unavailable_using_script", error=str(exc))
            await self._send_command(f"patchrestore {hex(address)}")
        return {"success": True, "address": hex(address)}

    async def export_patches(self, path: str) -> dict[str, Any]:
        """Export patches to a file.

        Args:
            path: Output file path.

        Returns:
            dict[str, Any]: Dict with success status and path.
        """
        _logger.debug("x64dbg_command_queued", command="savedata", path=path)
        await self._send_command(f'savedata "{path}"')
        return {"success": True, "path": path}

    async def suspend_thread(self, tid: int) -> dict[str, Any]:
        """Suspend a thread and verify the suspend transition was observed.

        After queuing ``suspendthread``, polls ``thread_detail`` for
        the thread record matching ``tid`` and waits until the
        ``suspended`` flag is ``True``. The wrapper used to claim
        ``success: True`` without observing the actual thread state
        (audit7.md F-0001).

        Args:
            tid: Thread ID.

        Returns:
            dict[str, Any]: Dict with ``success``, ``tid``, and
            ``verified``. ``verified`` is ``True`` when
            ``thread_detail`` reported ``suspended=True``; ``False``
            only when the plugin lacks ``thread_detail``.

        Raises:
            ToolError: If ``thread_detail`` continues to report
                ``suspended=False`` (or no entry at all) for ``tid``
                after the verification window elapses.
        """
        _logger.debug("x64dbg_command_queued", command="suspendthread", tid=tid)
        await self._send_command(f"suspendthread {tid}")
        record, rpc_available = await self._wait_for_thread_state(
            tid,
            predicate=lambda entry: entry.get("suspended") is True,
        )
        if not rpc_available:
            return {"success": True, "tid": tid, "verified": False}
        if record is None:
            msg = f"suspend_thread verification failed: thread_detail returned no entry for tid={tid} within {self.VERIFY_TIMEOUT}s"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_TIMEOUT,
                    "tid": tid,
                    "expected_suspended": True,
                },
            )
        if record.get("suspended") is not True:
            msg = (
                f"suspend_thread verification failed: thread {tid} still reports suspended={record.get('suspended')!r} after suspendthread"
            )
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_REMOTE,
                    "tid": tid,
                    "expected_suspended": True,
                    "observed_suspended": record.get("suspended"),
                },
            )
        return {"success": True, "tid": tid, "verified": True}

    async def resume_thread(self, tid: int) -> dict[str, Any]:
        """Resume a suspended thread and verify the resume was observed.

        After queuing ``resumethread``, polls ``thread_detail`` for
        the thread record matching ``tid`` and waits until the
        ``suspended`` flag is ``False``. The wrapper used to claim
        ``success: True`` without observing the actual thread state
        (audit7.md F-0001).

        Args:
            tid: Thread ID.

        Returns:
            dict[str, Any]: Dict with ``success``, ``tid``, and
            ``verified``. ``verified`` is ``True`` when
            ``thread_detail`` reported ``suspended=False``; ``False``
            only when the plugin lacks ``thread_detail``.

        Raises:
            ToolError: If ``thread_detail`` continues to report
                ``suspended=True`` (or no entry at all) for ``tid``
                after the verification window elapses.
        """
        _logger.debug("x64dbg_command_queued", command="resumethread", tid=tid)
        await self._send_command(f"resumethread {tid}")
        record, rpc_available = await self._wait_for_thread_state(
            tid,
            predicate=lambda entry: entry.get("suspended") is False,
        )
        if not rpc_available:
            return {"success": True, "tid": tid, "verified": False}
        if record is None:
            msg = f"resume_thread verification failed: thread_detail returned no entry for tid={tid} within {self.VERIFY_TIMEOUT}s"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_TIMEOUT,
                    "tid": tid,
                    "expected_suspended": False,
                },
            )
        if record.get("suspended") is not False:
            msg = f"resume_thread verification failed: thread {tid} still reports suspended={record.get('suspended')!r} after resumethread"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_REMOTE,
                    "tid": tid,
                    "expected_suspended": False,
                    "observed_suspended": record.get("suspended"),
                },
            )
        return {"success": True, "tid": tid, "verified": True}

    async def switch_thread(self, tid: int) -> dict[str, Any]:
        """Switch the active debugger thread and verify the switch occurred.

        After queuing ``switchthread``, polls ``thread_detail`` to
        confirm the requested thread is present in the listing. The
        wrapper used to claim ``success: True`` without observing the
        debugger's actual thread state (audit7.md F-0001).

        Args:
            tid: Thread ID to switch to.

        Returns:
            dict[str, Any]: Dict with ``success``, ``tid``, and
            ``verified``. ``verified`` is ``True`` when
            ``thread_detail`` listed the thread (i.e. it exists in the
            target process and can be the active thread); ``False``
            only when the plugin lacks ``thread_detail``.

        Raises:
            ToolError: If ``thread_detail`` does not list ``tid`` at
                all after the verification window elapses (switch
                target gone or never existed).
        """
        _logger.debug("x64dbg_command_queued", command="switchthread", tid=tid)
        await self._send_command(f"switchthread {tid}")
        record, rpc_available = await self._wait_for_thread_state(
            tid,
            predicate=lambda _entry: True,
        )
        if not rpc_available:
            return {"success": True, "tid": tid, "verified": False}
        if record is None:
            msg = f"switch_thread verification failed: thread_detail returned no entry for tid={tid} within {self.VERIFY_TIMEOUT}s"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_REMOTE,
                    "tid": tid,
                },
            )
        return {"success": True, "tid": tid, "verified": True}

    async def set_thread_name(self, tid: int, name: str) -> dict[str, Any]:
        """Set a thread's display name and verify the new name was applied.

        After queuing ``setthreadname``, polls ``thread_detail`` until
        the matching thread record reports ``name == name``. The
        wrapper used to claim ``success: True`` without inspecting the
        actual thread metadata (audit7.md F-0001).

        Args:
            tid: Thread ID.
            name: Display name for the thread.

        Returns:
            dict[str, Any]: Dict with ``success``, ``tid``, ``name``,
            and ``verified``. ``verified`` is ``True`` when
            ``thread_detail`` reported the matching name; ``False``
            only when the plugin lacks ``thread_detail``.

        Raises:
            ToolError: If ``thread_detail`` does not report the
                requested name (or no entry at all) after the
                verification window elapses.
        """
        _logger.debug("x64dbg_command_queued", command="setthreadname", tid=tid)
        await self._send_command(f'setthreadname {tid}, "{name}"')
        record, rpc_available = await self._wait_for_thread_state(
            tid,
            predicate=lambda entry: entry.get("name") == name,
        )
        if not rpc_available:
            return {"success": True, "tid": tid, "name": name, "verified": False}
        if record is None:
            msg = f"set_thread_name verification failed: thread_detail returned no entry for tid={tid} within {self.VERIFY_TIMEOUT}s"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_TIMEOUT,
                    "tid": tid,
                    "expected_name": name,
                },
            )
        observed_name = record.get("name")
        if observed_name != name:
            msg = f"set_thread_name verification failed: thread {tid} reports name={observed_name!r} after setthreadname, expected {name!r}"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_REMOTE,
                    "tid": tid,
                    "expected_name": name,
                    "observed_name": observed_name,
                },
            )
        return {"success": True, "tid": tid, "name": name, "verified": True}

    async def get_seh_chain(self) -> list[dict[str, Any]]:
        """Get the structured exception handler chain.

        Returns:
            list[dict[str, Any]]: List of SEH entry dicts with handler and next addresses.

        Raises:
            ToolError: If the plugin reports a non-recoverable error.
        """
        _logger.debug("seh_chain_reading")
        try:
            result = await self._send_pipe_command("seh_chain")
        except ToolError as exc:
            if not self._is_recoverable_pipe_error(exc):
                raise
            _logger.warning("seh_chain_pipe_unavailable", error=str(exc))
            return []
        if isinstance(result, list):
            return [dict(entry) if _is_str_obj_dict(entry) else {} for entry in result]
        return []

    async def read_peb(self) -> dict[str, Any]:
        """Read the Process Environment Block.

        Forwards to the bridge plugin's ``peb_read`` RPC. The plugin
        returns a dict containing the PEB base address (``address``),
        the ``beingDebugged`` flag, ``imageBaseAddress``, ``ldr``,
        ``processParameters``, and ``ntGlobalFlag``.

        Returns:
            dict[str, Any]: Dict with PEB fields. Keys include
            ``address`` (PEB base, hex string), ``beingDebugged`` (int),
            ``imageBaseAddress`` (hex string), ``ldr`` (hex string),
            ``processParameters`` (hex string), and ``ntGlobalFlag``
            (int).

        Raises:
            ToolError: If the plugin reports a non-recoverable error.
        """
        _logger.debug("peb_reading")
        try:
            result = await self._send_pipe_command("peb_read")
        except ToolError as exc:
            if not self._is_recoverable_pipe_error(exc):
                raise
            _logger.warning("peb_read_pipe_unavailable", error=str(exc))
            return {}
        return dict(result) if _is_str_obj_dict(result) else {}

    async def read_teb(self, tid: int | None = None) -> dict[str, Any]:
        """Read the Thread Environment Block.

        Args:
            tid: Thread ID. Uses current thread if None.

        Returns:
            dict[str, Any]: Dict with TEB fields including stackBase, stackLimit, processId, threadId.

        Raises:
            ToolError: If the plugin reports a non-recoverable error.
        """
        _logger.debug("teb_reading", tid=tid)
        params: dict[str, Any] = {}
        if tid is not None:
            params["tid"] = tid
        try:
            result = await self._send_pipe_command("teb_read", params or None)
        except ToolError as exc:
            if not self._is_recoverable_pipe_error(exc):
                raise
            _logger.warning("teb_read_pipe_unavailable", error=str(exc))
            return {}
        return dict(result) if _is_str_obj_dict(result) else {}

    async def get_pe_directories(self, module_name: str) -> list[dict[str, Any]]:
        """Get PE data directory entries for a module.

        Args:
            module_name: Module name (e.g. 'ntdll.dll').

        Returns:
            list[dict[str, Any]]: List of directory entry dicts with index, name, rva, size.

        Raises:
            ToolError: If the plugin reports a non-recoverable error.
        """
        _logger.debug("pe_directories_reading", module_name=module_name)
        try:
            result = await self._send_pipe_command("pe_directories", {"module": module_name})
        except ToolError as exc:
            if not self._is_recoverable_pipe_error(exc):
                raise
            _logger.warning("pe_directories_pipe_unavailable", error=str(exc))
            return []
        if isinstance(result, list):
            return [dict(entry) if _is_str_obj_dict(entry) else {} for entry in result]
        return []

    async def add_watch(self, expression: str) -> dict[str, Any]:
        """Add a watch expression.

        Args:
            expression: Expression to watch.

        Returns:
            dict[str, Any]: Dict with success status and expression.

        Raises:
            ToolError: If the plugin reports a non-recoverable error.
        """
        _logger.info("watch_adding", expression=expression)
        try:
            await self._send_pipe_command("watch_add", {"expression": expression})
        except ToolError as exc:
            if not self._is_recoverable_pipe_error(exc):
                raise
            _logger.warning("watch_add_pipe_unavailable_using_script", error=str(exc))
            await self._send_command(f'AddWatch "{expression}"')
        return {"success": True, "expression": expression}

    async def remove_watch(self, index: int) -> dict[str, Any]:
        """Remove a watch expression by index.

        Args:
            index: Watch index to remove.

        Returns:
            dict[str, Any]: Dict with success status and index.

        Raises:
            ToolError: If the plugin reports a non-recoverable error.
        """
        _logger.info("watch_removing", index=index)
        try:
            await self._send_pipe_command("watch_remove", {"index": index})
        except ToolError as exc:
            if not self._is_recoverable_pipe_error(exc):
                raise
            _logger.warning("watch_remove_pipe_unavailable_using_script", error=str(exc))
            await self._send_command(f"DelWatch {index}")
        return {"success": True, "index": index}

    async def get_watches(self) -> list[dict[str, Any]]:
        """Get all watch expressions and their current values.

        Returns:
            list[dict[str, Any]]: List of watch dicts.

        Raises:
            ToolError: If the plugin reports a non-recoverable error.
        """
        _logger.debug("watches_listing")
        try:
            result = await self._send_pipe_command("watch_list")
        except ToolError as exc:
            if not self._is_recoverable_pipe_error(exc):
                raise
            _logger.warning("watch_list_pipe_unavailable", error=str(exc))
            return []
        if isinstance(result, list):
            return [dict(entry) if _is_str_obj_dict(entry) else {} for entry in result]
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
        _logger.debug("x64dbg_command_queued", command="logging_breakpoint", address=hex(address))
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
        _logger.debug("x64dbg_command_queued", command="configure_breakpoint", address=hex(address))
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
        _logger.debug("x64dbg_command_queued", command="dll_breakpoint", dll=dll_name, dll_event=event)
        cmd = f'LibrarianSetBreakPoint "{dll_name}"'
        if event == "unload":
            cmd += ", unload"
        await self._send_command(cmd)
        return {"success": True, "dll_name": dll_name, "event": event}

    async def trace_into(self, condition: str | None = None, max_steps: int = 50000) -> dict[str, Any]:
        """Trace into with optional condition and verify the debugger started running.

        After queuing ``TraceIntoConditional``, polls ``status`` and
        waits for the debugger's ``is_running`` flag to flip to
        ``True`` (paused -> running, which is what a successful trace
        start looks like before the condition fires). The wrapper used
        to claim ``success: True`` without inspecting the debugger
        state at all (audit7.md F-0001).

        Args:
            condition: Trace break condition expression.
            max_steps: Maximum number of steps.

        Returns:
            dict[str, Any]: Dict with ``success``, ``max_steps``, and
            ``verified``. ``verified`` is ``True`` when ``status``
            reported the debugger as running (or transitioning back to
            paused after the trace already finished); ``False`` only
            when the plugin lacks ``status``.

        Raises:
            ToolError: If ``status`` reports the debugger never
                started running and remained paused after the
                verification window elapses (real trace failure).
        """
        _logger.debug("x64dbg_command_queued", command="trace_into", max_steps=max_steps)
        cmd = f"TraceIntoConditional {max_steps}"
        if condition:
            cmd += f', "{condition}"'
        await self._send_command(cmd)
        observed, rpc_available = await self._wait_for_running_state(expected=True)
        if not rpc_available:
            return {"success": True, "max_steps": max_steps, "verified": False}
        if observed is False:
            msg = f"trace_into verification failed: debugger never entered running state after TraceIntoConditional within {self.VERIFY_TIMEOUT}s"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_TIMEOUT,
                    "max_steps": max_steps,
                    "expected_running": True,
                    "observed_running": False,
                },
            )
        return {"success": True, "max_steps": max_steps, "verified": True}

    async def trace_over(self, condition: str | None = None, max_steps: int = 50000) -> dict[str, Any]:
        """Trace over with optional condition and verify the debugger started running.

        After queuing ``TraceOverConditional``, polls ``status`` and
        waits for the debugger's ``is_running`` flag to flip to
        ``True``. The wrapper used to claim ``success: True`` without
        inspecting the debugger state at all (audit7.md F-0001).

        Args:
            condition: Trace break condition expression.
            max_steps: Maximum number of steps.

        Returns:
            dict[str, Any]: Dict with ``success``, ``max_steps``, and
            ``verified``. ``verified`` is ``True`` when ``status``
            reported the debugger as running; ``False`` only when the
            plugin lacks ``status``.

        Raises:
            ToolError: If ``status`` reports the debugger never
                started running and remained paused after the
                verification window elapses.
        """
        _logger.debug("x64dbg_command_queued", command="trace_over", max_steps=max_steps)
        cmd = f"TraceOverConditional {max_steps}"
        if condition:
            cmd += f', "{condition}"'
        await self._send_command(cmd)
        observed, rpc_available = await self._wait_for_running_state(expected=True)
        if not rpc_available:
            return {"success": True, "max_steps": max_steps, "verified": False}
        if observed is False:
            msg = f"trace_over verification failed: debugger never entered running state after TraceOverConditional within {self.VERIFY_TIMEOUT}s"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_TIMEOUT,
                    "max_steps": max_steps,
                    "expected_running": True,
                    "observed_running": False,
                },
            )
        return {"success": True, "max_steps": max_steps, "verified": True}

    async def get_trace_record(self, address: int, size: int = 1) -> dict[str, Any]:
        """Get trace record hit count at an address.

        Args:
            address: Address to query.
            size: Number of bytes to check.

        Returns:
            dict[str, Any]: Dict with address and hitCount.

        Raises:
            ToolError: If the plugin reports a non-recoverable error.
        """
        _logger.debug("trace_record_reading", address=hex(address))
        try:
            result = await self._send_pipe_command("trace_record", {"address": hex(address), "size": size})
        except ToolError as exc:
            if not self._is_recoverable_pipe_error(exc):
                raise
            _logger.warning("trace_record_pipe_unavailable", error=str(exc))
            return {"address": hex(address), "hitCount": 0}
        if _is_str_obj_dict(result):
            return dict(result)
        return {"address": hex(address), "hitCount": 0}

    async def step_count(self, count: int, step_type: str = "into") -> dict[str, Any]:
        """Execute ``count`` steps and verify the debugger pauses again afterwards.

        Sends ``tic`` (into) or ``toc`` (over) with the requested step
        count. The console commands block the debugger until the step
        budget is exhausted; this wrapper then waits for the debugger
        to return to a paused state via ``status``. The previous
        implementation returned ``success: True`` immediately and
        offered the caller no way to distinguish "step issued" from
        "step completed" (audit7.md F-0001).

        Args:
            count: Number of steps to execute.
            step_type: Step type ('into' or 'over').

        Returns:
            dict[str, Any]: Dict with ``success``, ``count``,
            ``step_type``, and ``verified``. ``verified`` is ``True``
            when ``status`` reported the debugger as paused after the
            step budget; ``False`` only when the plugin lacks
            ``status``.

        Raises:
            ToolError: If ``status`` reports the debugger remained
                running and never returned to a paused state after the
                verification window elapses.
        """
        _logger.debug("x64dbg_command_queued", command="step_count", count=count, step_type=step_type)
        cmd = f"tic 0, {count}" if step_type == "into" else f"toc 0, {count}"
        await self._send_command(cmd)
        observed, rpc_available = await self._wait_for_running_state(expected=False)
        if not rpc_available:
            return {"success": True, "count": count, "step_type": step_type, "verified": False}
        if observed is True:
            msg = f"step_count verification failed: debugger still running after {step_type} step budget {count}, never returned to paused within {self.VERIFY_TIMEOUT}s"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_TIMEOUT,
                    "count": count,
                    "step_type": step_type,
                    "expected_running": False,
                    "observed_running": True,
                },
            )
        return {"success": True, "count": count, "step_type": step_type, "verified": True}

    async def animate_start(self, step_type: str = "into") -> dict[str, Any]:
        """Start animation (visual step execution) and verify the debugger started.

        After queuing ``AnimateInto`` or ``AnimateOver``, polls
        ``status`` and waits for the debugger's ``is_running`` flag to
        flip to ``True`` (animation kicks the debugger into a
        continuous step loop). The wrapper used to claim
        ``success: True`` without observing the actual debugger state
        (audit7.md F-0001).

        Args:
            step_type: Step type ('into' or 'over').

        Returns:
            dict[str, Any]: Dict with ``success``, ``step_type``, and
            ``verified``. ``verified`` is ``True`` when ``status``
            reported the debugger as running; ``False`` only when the
            plugin lacks ``status``.

        Raises:
            ToolError: If ``status`` reports the debugger never
                entered the running state after the verification
                window elapses.
        """
        _logger.debug("x64dbg_command_queued", command="animate_start", step_type=step_type)
        cmd = "AnimateInto" if step_type == "into" else "AnimateOver"
        await self._send_command(cmd)
        observed, rpc_available = await self._wait_for_running_state(expected=True)
        if not rpc_available:
            return {"success": True, "step_type": step_type, "verified": False}
        if observed is False:
            msg = f"animate_start verification failed: debugger never entered running state after {cmd} within {self.VERIFY_TIMEOUT}s"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_TIMEOUT,
                    "step_type": step_type,
                    "expected_running": True,
                    "observed_running": False,
                },
            )
        return {"success": True, "step_type": step_type, "verified": True}

    async def animate_stop(self) -> dict[str, Any]:
        """Stop animation and verify the debugger paused.

        After queuing ``AnimateStop``, polls ``status`` and waits for
        the debugger's ``is_running`` flag to flip to ``False``. The
        wrapper used to claim ``success: True`` without observing the
        actual debugger state (audit7.md F-0001).

        Returns:
            dict[str, Any]: Dict with ``success`` and ``verified``.
            ``verified`` is ``True`` when ``status`` reported the
            debugger as paused after the stop command; ``False`` only
            when the plugin lacks ``status``.

        Raises:
            ToolError: If ``status`` reports the debugger remained
                running and never paused after the verification
                window elapses.
        """
        _logger.debug("x64dbg_command_queued", command="animate_stop")
        await self._send_command("AnimateStop")
        observed, rpc_available = await self._wait_for_running_state(expected=False)
        if not rpc_available:
            return {"success": True, "verified": False}
        if observed is True:
            msg = f"animate_stop verification failed: debugger still running after AnimateStop within {self.VERIFY_TIMEOUT}s"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_TIMEOUT,
                    "expected_running": False,
                    "observed_running": True,
                },
            )
        return {"success": True, "verified": True}

    async def restart(self) -> dict[str, Any]:
        """Restart the currently loaded debuggee (native Ctrl+F2 semantics).

        Re-issues ``InitDebug`` against the same binary path and launch
        arguments most recently passed to :meth:`load`, without
        requiring the caller to resupply them or re-run architecture
        detection. This mirrors x64dbg's own "restart" toolbar action,
        which restarts the current debug session on the already-loaded
        target rather than starting a fresh session from scratch. After
        queuing the command, polls ``status`` to confirm the debugger
        actually reached a paused state at the new entry point before
        reporting success, rather than claiming success immediately
        after queuing the command.

        Returns:
            dict[str, Any]: Dict with ``success``, ``path`` (the
            restarted binary's path as a string), and ``verified``.
            ``verified`` is ``True`` when ``status`` confirmed the
            debugger returned to a paused state; ``False`` only when
            the plugin lacks the ``status`` RPC.

        Raises:
            ToolError: If no binary has previously been loaded via
                :meth:`load`, or if ``status`` reports the debugger
                never returned to a paused state within the
                verification window.
        """
        if self._binary_path is None:
            msg = "x64dbg cannot restart: no binary has been loaded via load()"
            raise ToolError(msg, tool_name="x64dbg")

        path = self._binary_path
        _logger.info("x64dbg_restart_queueing", path=path.name)

        cmd = f'InitDebug "{path.as_posix()}"'
        if self._launch_args:
            cmd += f', "{self._launch_args}"'
        await self._send_command(cmd)

        pid_val = await self._await_debuggee_pid()
        if pid_val is not None:
            self._register_attached_pid(pid_val)

        observed, rpc_available = await self._wait_for_running_state(expected=False)
        self._state.connected = True
        self._state.tool_running = True
        self._state.binary_loaded = True
        self._state.target_path = path
        self._publish_tool_state()

        if not rpc_available:
            _logger.info("x64dbg_restarted", path=path.name, verified=False)
            return {"success": True, "path": str(path), "verified": False}
        if observed is True:
            msg = f"restart verification failed: debugger still running after InitDebug re-issue, never returned to paused within {self.VERIFY_TIMEOUT}s"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_TIMEOUT,
                    "path": str(path),
                    "expected_running": False,
                    "observed_running": True,
                },
            )
        _logger.info("x64dbg_restarted", path=path.name, verified=True)
        return {"success": True, "path": str(path), "verified": True}


class _X64DbgScriptingMixin(_X64DbgTraceMixin):
    """Entropy, YARA, scripting, plugins, anti-debug, handles, navigation, privileges.

    Hosts the analytical and integration surface: entropy histogramming,
    YARA scanning, x64dbg script lifecycle, plugin load/unload/list,
    anti-debug detection and patching, OEP import reconstruction, status
    inspection, GUI navigation, TLS callback inspection, raw resource
    enumeration, handle enumeration and close, and the Windows token
    privilege query/adjust helpers.
    """

    async def analyze_entropy(self, address: int, size: int, block_size: int = 256) -> list[dict[str, Any]]:
        """Analyze Shannon entropy of a memory region.

        Reads each ``block_size``-byte block independently so a single
        unreadable page (guarded, paged-out, or otherwise rejected by
        ``ReadProcessMemory``) does not abort the whole scan. Each block
        result carries ``readable`` to distinguish a block that yielded
        zero entropy from one that could not be read; an explicit
        ``error`` field captures the read-failure message when the block
        could not be read.

        Args:
            address: Start address.
            size: Total bytes to analyze.
            block_size: Size of each entropy calculation block.

        Returns:
            list[dict[str, Any]]: List of dicts with ``address``,
            ``entropy``, ``size``, ``readable``, and (when not readable)
            ``error``.

        Raises:
            ToolError: If ``block_size`` or ``size`` is non-positive.
        """
        if block_size <= 0:
            _logger.warning("analyze_entropy_invalid_block_size", block_size=block_size)
            msg = f"analyze_entropy: block_size must be positive, got {block_size}"
            raise ToolError(msg, tool_name="x64dbg")
        if size <= 0:
            _logger.warning("analyze_entropy_invalid_size", size=size)
            msg = f"analyze_entropy: size must be positive, got {size}"
            raise ToolError(msg, tool_name="x64dbg")
        _logger.debug("entropy_analyzing", address=hex(address), size=size, block_size=block_size)
        results: list[dict[str, Any]] = []
        skipped = 0
        for offset in range(0, size, block_size):
            current_size = min(block_size, size - offset)
            current_addr = address + offset
            try:
                block = await self.read_memory(current_addr, current_size)
            except ToolError as exc:
                skipped += 1
                _logger.warning(
                    "entropy_block_read_failed",
                    address=hex(current_addr),
                    size=current_size,
                    error=str(exc),
                )
                results.append({
                    "address": hex(current_addr),
                    "entropy": 0.0,
                    "size": current_size,
                    "readable": False,
                    "error": str(exc),
                })
                continue
            if not block:
                results.append({
                    "address": hex(current_addr),
                    "entropy": 0.0,
                    "size": 0,
                    "readable": False,
                    "error": "empty read",
                })
                skipped += 1
                continue
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
                "address": hex(current_addr),
                "entropy": round(entropy, 4),
                "size": block_len,
                "readable": True,
            })
        if skipped:
            _logger.debug(
                "entropy_blocks_skipped",
                address=hex(address),
                size=size,
                skipped=skipped,
                total=len(results),
            )
        return results

    async def yara_scan(
        self,
        rule_path: str | None = None,
        rule_text: str | None = None,
        address: int = 0,
        size: int = 0,
    ) -> list[dict[str, Any]]:
        """Scan memory with a YARA rule via yara-python.

        Compiles the provided rule (from inline text or file path) and runs
        it against either a specific ``(address, size)`` window of the
        attached process or every readable memory region.

        Args:
            rule_path: Path to YARA rule file.
            rule_text: Inline YARA rule text.
            address: Start address (0 to scan every readable region).
            size: Size to scan (0 to scan every readable region).

        Returns:
            list[dict[str, Any]]: List of match dicts with ``rule``,
            ``address``, and ``matched_bytes`` fields.

        Raises:
            ToolError: If yara-python is unavailable, if neither
                ``rule_path`` nor ``rule_text`` is supplied, if the rule
                file does not exist or is empty, or if the inline rule
                text is shorter than one byte.
        """
        _logger.info("yara_scanning", address=hex(address) if address else "all", size=size)
        if not rule_text and not rule_path:
            raise ToolError(_ERR_YARA_NO_RULE, tool_name="x64dbg")

        if rule_text is not None and len(rule_text.encode("utf-8")) < MIN_YARA_PATTERN_BYTES:
            raise ToolError(_ERR_YARA_EMPTY_RULE, tool_name="x64dbg")

        if rule_path is not None:
            rule_file = Path(rule_path)
            if not await asyncio.to_thread(rule_file.exists):
                msg = f"{_ERR_YARA_RULE_FILE_NOT_FOUND}: {rule_path}"
                raise ToolError(msg, tool_name="x64dbg")
            stat_result = await asyncio.to_thread(rule_file.stat)
            if stat_result.st_size < MIN_YARA_PATTERN_BYTES:
                raise ToolError(_ERR_YARA_RULE_FILE_EMPTY, tool_name="x64dbg")

        yara_raw = _get_yara()
        if yara_raw is None:
            raise ToolError(_ERR_YARA_NOT_AVAILABLE, tool_name="x64dbg")

        yara_module: Any = cast("Any", yara_raw)
        yara_compile: Callable[..., Any] = yara_module.compile
        rules: Any = yara_compile(source=rule_text) if rule_text else yara_compile(filepath=rule_path)

        yara_match_fn: Callable[..., list[Any]] = rules.match
        results: list[dict[str, Any]] = []

        async def _scan_window(window_addr: int, window_size: int) -> None:
            """Scan a specific memory window with the compiled rules.

            Args:
                window_addr: Start address of the window.
                window_size: Size of the window in bytes.
            """
            if window_size <= 0:
                return
            try:
                data = await self.read_memory(window_addr, window_size)
            except ToolError as read_err:
                _logger.warning(
                    "yara_scan_read_failed",
                    address=hex(window_addr),
                    size=window_size,
                    error=str(read_err),
                )
                return
            yara_matches: list[Any] = yara_match_fn(data=data)
            for m in yara_matches:
                rule_name: str = str(m.rule)
                for string_match in list(m.strings):
                    for instance in list(string_match.instances):
                        offset_val: int = int(instance.offset)
                        raw_bytes: Any = instance.matched_data
                        byte_val: bytes = raw_bytes if isinstance(raw_bytes, bytes) else bytes(raw_bytes)
                        results.append({
                            "rule": rule_name,
                            "address": hex(window_addr + offset_val),
                            "matched_bytes": byte_val.hex(),
                        })

        if address and size:
            await _scan_window(address, size)
        else:
            regions = await self.get_memory_regions()
            for region in regions:
                if "r" not in region.protection:
                    continue
                await _scan_window(region.base_address, min(region.size, MAX_MEMORY_READ_SIZE))

        return results

    async def script_load(self, path: str) -> dict[str, Any]:
        """Load an x64dbg script file and verify the load did not raise a script error.

        After queuing ``scriptload``, queries the
        ``script.iserror()`` register via the expression evaluator and
        raises ``ToolError`` when it is set. The wrapper used to claim
        ``success: True`` without inspecting the script error register
        (audit7.md F-0001).

        Args:
            path: Path to script file.

        Returns:
            dict[str, Any]: Dict with ``success``, ``path``, and
            ``verified``. ``verified`` is ``True`` when
            ``script.iserror()`` returned ``0`` (no error); ``False``
            only when the expression evaluator is unavailable.

        Raises:
            ToolError: If ``script.iserror()`` reports a non-zero
                value (the load failed inside x64dbg's script
                interpreter).
        """
        _logger.debug("x64dbg_command_queued", command="scriptload", path=path)
        await self._send_command(f'scriptload "{path}"')
        error_flag = await self._query_script_error()
        if error_flag is None:
            return {"success": True, "path": path, "verified": False}
        if error_flag:
            msg = f"script_load verification failed: script.iserror() is set after scriptload {path!r}"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_REMOTE,
                    "path": path,
                    "script_iserror": True,
                },
            )
        return {"success": True, "path": path, "verified": True}

    async def script_run(self) -> dict[str, Any]:
        """Run the currently loaded script and verify it ran without a script error.

        After queuing ``scriptrun``, queries the
        ``script.iserror()`` register via the expression evaluator and
        raises ``ToolError`` when it is set. The wrapper used to claim
        ``success: True`` without inspecting the script error register
        (audit7.md F-0001).

        Returns:
            dict[str, Any]: Dict with ``success`` and ``verified``.
            ``verified`` is ``True`` when ``script.iserror()`` returned
            ``0``; ``False`` only when the expression evaluator is
            unavailable.

        Raises:
            ToolError: If ``script.iserror()`` reports a non-zero
                value (the script raised an error during execution).
        """
        _logger.debug("x64dbg_command_queued", command="scriptrun")
        await self._send_command("scriptrun")
        error_flag = await self._query_script_error()
        if error_flag is None:
            return {"success": True, "verified": False}
        if error_flag:
            msg = "script_run verification failed: script.iserror() is set after scriptrun"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_REMOTE,
                    "script_iserror": True,
                },
            )
        return {"success": True, "verified": True}

    async def script_cmd(self, line: str) -> dict[str, Any]:
        """Execute a single script command and verify it ran without a script error.

        After queuing ``scriptcmd``, queries the
        ``script.iserror()`` register via the expression evaluator and
        raises ``ToolError`` when it is set. The wrapper used to claim
        ``success: True`` without inspecting the script error register
        (audit7.md F-0001).

        Args:
            line: Script command line.

        Returns:
            dict[str, Any]: Dict with ``success``, ``line``, and
            ``verified``. ``verified`` is ``True`` when
            ``script.iserror()`` returned ``0``; ``False`` only when
            the expression evaluator is unavailable.

        Raises:
            ToolError: If ``script.iserror()`` reports a non-zero
                value (the script command raised an error).
        """
        _logger.debug("x64dbg_command_queued", command="scriptcmd", line=line)
        await self._send_command(f'scriptcmd "{line}"')
        error_flag = await self._query_script_error()
        if error_flag is None:
            return {"success": True, "line": line, "verified": False}
        if error_flag:
            msg = f"script_cmd verification failed: script.iserror() is set after scriptcmd {line!r}"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_REMOTE,
                    "line": line,
                    "script_iserror": True,
                },
            )
        return {"success": True, "line": line, "verified": True}

    async def script_abort(self) -> dict[str, Any]:
        """Abort the running script and verify the abort did not raise a script error.

        After queuing ``scriptabort``, queries the
        ``script.iserror()`` register via the expression evaluator and
        raises ``ToolError`` when it is set. The wrapper used to claim
        ``success: True`` without inspecting the script error register
        (audit7.md F-0001).

        Returns:
            dict[str, Any]: Dict with ``success`` and ``verified``.
            ``verified`` is ``True`` when ``script.iserror()`` returned
            ``0``; ``False`` only when the expression evaluator is
            unavailable.

        Raises:
            ToolError: If ``script.iserror()`` reports a non-zero
                value (the abort raised an error inside the script
                interpreter).
        """
        _logger.debug("x64dbg_command_queued", command="scriptabort")
        await self._send_command("scriptabort")
        error_flag = await self._query_script_error()
        if error_flag is None:
            return {"success": True, "verified": False}
        if error_flag:
            msg = "script_abort verification failed: script.iserror() is set after scriptabort"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_REMOTE,
                    "script_iserror": True,
                },
            )
        return {"success": True, "verified": True}

    async def plugin_load(self, path: str) -> dict[str, Any]:
        """Load a plugin and verify it is present in the loaded plugin list.

        After queuing ``plugload``, checks ``plugin_list`` (preferred)
        or ``plugin.find(<name>)`` via the expression evaluator and
        raises ``ToolError`` when the plugin is absent. The wrapper
        used to claim ``success: True`` without observing the actual
        plugin manager state (audit7.md F-0001).

        Args:
            path: Path to plugin DLL.

        Returns:
            dict[str, Any]: Dict with ``success``, ``path``, and
            ``verified``. ``verified`` is ``True`` when the readback
            confirmed the plugin is present; ``False`` only when the
            plugin lacks both ``plugin_list`` and the
            ``plugin.find()`` expression.

        Raises:
            ToolError: If neither verification path reports the
                plugin as present (real load failure).
        """
        _logger.debug("x64dbg_command_queued", command="plugload", path=path)
        await self._send_command(f'plugload "{path}"')
        plugin_name = Path(path).stem
        present = await self._query_plugin_present(plugin_name)
        if present is None:
            return {"success": True, "path": path, "verified": False}
        if not present:
            msg = f"plugin_load verification failed: plugin {plugin_name!r} not present after plugload {path!r}"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_REMOTE,
                    "path": path,
                    "plugin_name": plugin_name,
                    "expected_present": True,
                    "observed_present": False,
                },
            )
        return {"success": True, "path": path, "verified": True}

    async def plugin_unload(self, name: str) -> dict[str, Any]:
        """Unload a plugin and verify it is no longer present in the plugin list.

        After queuing ``plugunload``, checks ``plugin_list``
        (preferred) or ``plugin.find(<name>)`` via the expression
        evaluator and raises ``ToolError`` when the plugin is still
        loaded. The wrapper used to claim ``success: True`` without
        observing the actual plugin manager state (audit7.md F-0001).

        Args:
            name: Plugin name.

        Returns:
            dict[str, Any]: Dict with ``success``, ``name``, and
            ``verified``. ``verified`` is ``True`` when the readback
            confirmed the plugin is absent; ``False`` only when the
            plugin lacks both ``plugin_list`` and the
            ``plugin.find()`` expression.

        Raises:
            ToolError: If both verification paths still report the
                plugin as present (real unload failure).
        """
        _logger.debug("x64dbg_command_queued", command="plugunload", plugin_name=name)
        await self._send_command(f'plugunload "{name}"')
        present = await self._query_plugin_present(name)
        if present is None:
            return {"success": True, "name": name, "verified": False}
        if present:
            msg = f"plugin_unload verification failed: plugin {name!r} still present after plugunload"
            raise ToolError(
                msg,
                tool_name="x64dbg",
                details={
                    "x64dbg_error_code": _X64DBG_ERR_REMOTE,
                    "plugin_name": name,
                    "expected_present": False,
                    "observed_present": True,
                },
            )
        return {"success": True, "name": name, "verified": True}

    async def plugin_list(self) -> list[dict[str, Any]]:
        """List loaded plugins.

        Returns:
            list[dict[str, Any]]: List of plugin info dicts.

        Raises:
            ToolError: If the plugin reports a non-recoverable error.
        """
        _logger.debug("plugins_listing")
        try:
            result = await self._send_pipe_command("plugin_list")
        except ToolError as exc:
            if not self._is_recoverable_pipe_error(exc):
                raise
            _logger.warning("plugin_list_pipe_unavailable_using_script", error=str(exc))
            await self._send_command("pluglist")
            return []
        if isinstance(result, list):
            return [dict(entry) if _is_str_obj_dict(entry) else {} for entry in result]
        return []

    async def get_handles(self) -> list[dict[str, Any]]:
        """Enumerate handles owned by the attached process.

        Uses ``NtQuerySystemInformation`` with the
        ``SystemExtendedHandleInformation`` class to enumerate every
        handle on the system and filters to those owned by the attached
        process.

        Returns:
            list[dict[str, Any]]: List of handle info dicts with
            ``handle``, ``object``, ``granted_access``,
            ``object_type_index``, and ``handle_attributes``.

        Raises:
            ToolError: If not on Windows, not attached, or the NT call
                fails.
        """
        _logger.debug("handles_enumerating")
        if not _IS_WIN32:
            msg = f"get_handles {_ERR_REQUIRES_WINDOWS}"
            raise ToolError(msg, tool_name="x64dbg")
        if self._attached_pid is None:
            msg = f"get_handles: {_ERR_NOT_ATTACHED}"
            raise ToolError(msg, tool_name="x64dbg")

        return await asyncio.to_thread(self._query_system_handles, self._attached_pid)

    @classmethod
    def _query_system_handles(cls, target_pid: int) -> list[dict[str, Any]]:
        """Query system-wide handle information and filter by PID.

        Args:
            target_pid: Process ID to filter handles by.

        Returns:
            list[dict[str, Any]]: Filtered list of handle info dicts.
        """
        raw_buffer = cls._fetch_handle_buffer()
        return cls._parse_handle_buffer(raw_buffer, target_pid)

    @staticmethod
    def _fetch_handle_buffer() -> bytes:
        """Call ``NtQuerySystemInformation`` with growing buffers until success.

        Returns:
            bytes: Raw bytes returned by NtQuerySystemInformation for the
            ``SystemExtendedHandleInformation`` class.

        Raises:
            ToolError: If the NT call returns a hard failure status or
                the buffer grows past the sanity limit.
        """
        ntdll = get_ntdll()
        buffer_size = 0x10000
        nt_status_info_length_mismatch = 0xC0000004
        nt_status_success = 0

        while True:
            buffer = ctypes.create_string_buffer(buffer_size)
            return_length = wintypes.ULONG(0)
            status = ntdll.NtQuerySystemInformation(
                SystemExtendedHandleInformation,
                buffer,
                buffer_size,
                ctypes.byref(return_length),
            )
            status_masked = status & 0xFFFFFFFF
            if status_masked == nt_status_success:
                return bytes(buffer.raw)
            if status_masked == nt_status_info_length_mismatch:
                new_size = max(return_length.value, buffer_size * 2)
                if new_size <= buffer_size:
                    new_size = buffer_size * 2
                buffer_size = new_size
                if buffer_size > _HANDLE_QUERY_MAX_BUFFER:
                    msg = "SystemExtendedHandleInformation buffer exceeded sanity limit"
                    raise ToolError(msg, tool_name="x64dbg")
                continue
            msg = f"NtQuerySystemInformation failed with status 0x{status_masked:08X}"
            raise ToolError(msg, tool_name="x64dbg", exit_code=int(status_masked))

    @staticmethod
    def _parse_handle_buffer(raw: bytes, target_pid: int) -> list[dict[str, Any]]:
        """Decode a SystemExtendedHandleInformation buffer into dicts.

        Args:
            raw: Raw bytes returned by NtQuerySystemInformation.
            target_pid: Process ID to filter handles by.

        Returns:
            list[dict[str, Any]]: Filtered list of handle info dicts.
        """
        header = SYSTEM_HANDLE_INFORMATION_EX.from_buffer_copy(raw[: ctypes.sizeof(SYSTEM_HANDLE_INFORMATION_EX)])
        number_of_handles = int(header.NumberOfHandles or 0)
        entry_size = ctypes.sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
        entries_offset = ctypes.sizeof(ctypes.c_void_p) * 2

        results: list[dict[str, Any]] = []
        for index in range(number_of_handles):
            entry_offset = entries_offset + index * entry_size
            if entry_offset + entry_size > len(raw):
                break
            entry = SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.from_buffer_copy(
                raw[entry_offset : entry_offset + entry_size],
            )
            owner_pid = int(entry.UniqueProcessId or 0)
            if owner_pid != target_pid:
                continue
            results.append({
                "handle": hex(int(entry.HandleValue or 0)),
                "object": hex(int(entry.Object or 0)),
                "granted_access": hex(int(entry.GrantedAccess)),
                "object_type_index": int(entry.ObjectTypeIndex),
                "handle_attributes": int(entry.HandleAttributes),
            })

        return results

    async def close_handle(self, handle: int) -> dict[str, Any]:
        """Close a process handle.

        Args:
            handle: Handle value to close.

        Returns:
            dict[str, Any]: Dict with success status.
        """
        _logger.debug("x64dbg_command_queued", command="handleclose", handle=hex(handle))
        await self._send_command(f"handleclose {hex(handle)}")
        return {"success": True, "handle": hex(handle)}

    async def detect_anti_debug(self) -> dict[str, Any]:
        """Detect common anti-debugging techniques.

        Returns:
            dict[str, Any]: Dict with detected anti-debug indicators.
        """
        _logger.info("anti_debug_detecting")
        peb = await self.read_peb()
        being_debugged = peb.get("beingDebugged", 0)
        checks: dict[str, bool] = {"peb_being_debugged": bool(being_debugged)}
        nt_global_flag = peb.get("ntGlobalFlag", 0)
        if isinstance(nt_global_flag, int):
            checks["nt_global_flag_set"] = (nt_global_flag & 0x70) != 0
        return {"success": True, "checks": checks, "peb": peb}

    SUPPORTED_ANTI_DEBUG_PATCHES: ClassVar[tuple[str, ...]] = (
        "being_debugged",
        "nt_global_flag",
        "heap_flags",
        "process_heap_flags",
    )

    async def patch_anti_debug(self, checks: list[str] | None = None) -> dict[str, Any]:
        """Patch supported PEB-resident anti-debug checks in the target process.

        Returns a per-check status map so callers can tell exactly which
        patches were applied, which were skipped, and which failed. Only
        the checks listed in :pyattr:`SUPPORTED_ANTI_DEBUG_PATCHES` are
        honoured; passing an unknown check name records an error for
        that entry without aborting other patches. The supported
        patches are:

        * ``being_debugged`` - clears ``PEB.BeingDebugged`` (PEB+0x02).
        * ``nt_global_flag`` - clears ``PEB.NtGlobalFlag`` (PEB+0x68 on
          32-bit, PEB+0xBC on 64-bit).
        * ``heap_flags`` - clears the ``HeapFlags`` and ``ForceFlags``
          fields of the process default heap (read via PEB+0x18 on
          32-bit, PEB+0x30 on 64-bit; flag fields at heap+0x40/+0x44 on
          32-bit, heap+0x70/+0x74 on 64-bit).
        * ``process_heap_flags`` - alias for ``heap_flags``.

        Other anti-debug techniques (ProcessDebugFlags,
        ProcessDebugObjectHandle, KdDebuggerNotPresent, hardware
        breakpoints, IsDebuggerPresent IAT hooks,
        NtQueryInformationProcess hooks) are out of scope for this
        method - they require kernel queries or IAT manipulation that
        cannot be issued through the PEB-write primitive used here.
        Passing unsupported names results in a per-check error rather
        than a misleading success.

        Args:
            checks: Specific checks to patch. Patches the default set
                (``being_debugged``, ``nt_global_flag``, ``heap_flags``)
                when ``None``.

        Returns:
            dict[str, Any]: Dict with ``success`` (True when every
            requested patch applied and no unknown check names were
            supplied), ``status`` mapping each requested check name to
            a bool, ``supported`` listing every accepted check name,
            and optional ``errors`` mapping check names to error
            strings when patches failed or the name is unknown.
        """
        _logger.info("anti_debug_patching")
        all_checks: list[str] = list(checks) if checks is not None else ["being_debugged", "nt_global_flag", "heap_flags"]
        status: dict[str, bool] = dict.fromkeys(all_checks, False)
        errors: dict[str, str] = {
            name: f"unsupported anti-debug check: {name}; supported checks are {', '.join(self.SUPPORTED_ANTI_DEBUG_PATCHES)}"
            for name in all_checks
            if name not in self.SUPPORTED_ANTI_DEBUG_PATCHES
        }
        actionable = [name for name in all_checks if name in self.SUPPORTED_ANTI_DEBUG_PATCHES]
        if not actionable:
            return self._anti_debug_result(all_checks, status, errors)

        try:
            peb = await self.read_peb()
        except ToolError as peb_err:
            for name in actionable:
                errors[name] = f"read_peb failed: {peb_err}"
            return self._anti_debug_result(all_checks, status, errors)

        peb_addr = self._coerce_hex_int(peb.get("address"))
        if peb_addr is None:
            for name in actionable:
                errors[name] = "PEB base address missing or malformed in peb_read response"
            return self._anti_debug_result(all_checks, status, errors)

        if "being_debugged" in actionable:
            try:
                await self.write_memory(peb_addr + 2, b"\x00")
                status["being_debugged"] = True
            except ToolError as bd_err:
                _logger.warning("anti_debug_being_debugged_patch_failed", error=str(bd_err))
                errors["being_debugged"] = str(bd_err)

        if "nt_global_flag" in actionable:
            flag_offset = 0xBC if self._is_64bit else 0x68
            try:
                await self.write_memory(peb_addr + flag_offset, b"\x00\x00\x00\x00")
                status["nt_global_flag"] = True
            except ToolError as nt_err:
                _logger.warning("anti_debug_nt_global_flag_patch_failed", error=str(nt_err))
                errors["nt_global_flag"] = str(nt_err)

        if "heap_flags" in actionable or "process_heap_flags" in actionable:
            heap_status, heap_error = await self._patch_process_heap_flags(peb_addr)
            for alias in ("heap_flags", "process_heap_flags"):
                if alias in actionable:
                    status[alias] = heap_status
                    if heap_error is not None:
                        errors[alias] = heap_error

        return self._anti_debug_result(all_checks, status, errors)

    def _anti_debug_result(
        self,
        all_checks: list[str],
        status: dict[str, bool],
        errors: dict[str, str],
    ) -> dict[str, Any]:
        """Assemble the final ``patch_anti_debug`` response payload.

        Args:
            all_checks: Every check name the caller requested.
            status: Per-check applied/not-applied flags.
            errors: Per-check error messages (may be empty).

        Returns:
            dict[str, Any]: Response with ``success``, ``status``,
            ``supported``, and (when non-empty) ``errors`` keys.
        """
        result: dict[str, Any] = {
            "success": all(status[name] for name in all_checks) and not errors,
            "status": status,
            "supported": list(self.SUPPORTED_ANTI_DEBUG_PATCHES),
        }
        if errors:
            result["errors"] = errors
        return result

    @staticmethod
    def _coerce_hex_int(raw: object) -> int | None:
        """Parse an integer from a hex string or numeric input.

        Args:
            raw: Value to parse. Accepts ``int`` directly or ``str`` in
                hex (``0x...``) or decimal form.

        Returns:
            int | None: Parsed integer, or ``None`` when input is
            missing, empty, or unparseable.
        """
        if isinstance(raw, bool):
            return None
        if isinstance(raw, int):
            return raw
        if isinstance(raw, str) and raw:
            return safe_int_from_str(raw, base=0, context="x64dbg_coerce_hex_int")
        return None

    async def _patch_process_heap_flags(self, peb_addr: int) -> tuple[bool, str | None]:
        """Clear the process default heap's HeapFlags and ForceFlags.

        Reads ``PEB.ProcessHeap`` (PEB+0x18 on 32-bit, PEB+0x30 on
        64-bit) through ``read_memory`` and writes zero into the heap's
        ``HeapFlags`` and ``ForceFlags`` fields (heap+0x40/+0x44 on
        32-bit, heap+0x70/+0x74 on 64-bit). The default heap is what
        ``HeapAlloc`` etc. use, so clearing the flags neuters the
        ``HEAP_TAIL_CHECKING_ENABLED`` /
        ``HEAP_FREE_CHECKING_ENABLED`` markers that anti-debug code
        samples to detect a debugger.

        Args:
            peb_addr: PEB base address in the target process.

        Returns:
            tuple[bool, str | None]: Tuple of
            ``(applied, error_message)``. ``applied`` is True only
            when both ``HeapFlags`` and ``ForceFlags`` were written.
        """
        ptr_size = POINTER_SIZE_64 if self._is_64bit else POINTER_SIZE_32
        process_heap_offset = 0x30 if self._is_64bit else 0x18
        heap_flags_offset = 0x70 if self._is_64bit else 0x40
        force_flags_offset = 0x74 if self._is_64bit else 0x44
        try:
            heap_ptr_bytes = await self.read_memory(peb_addr + process_heap_offset, ptr_size)
        except ToolError as read_err:
            _logger.warning("anti_debug_peb_process_heap_read_failed", error=str(read_err))
            return False, f"read PEB.ProcessHeap failed: {read_err}"
        if len(heap_ptr_bytes) < ptr_size:
            return False, "PEB.ProcessHeap read returned truncated data"
        heap_addr = int.from_bytes(heap_ptr_bytes, "little")
        if heap_addr == 0:
            return False, "PEB.ProcessHeap is null"
        try:
            await self.write_memory(heap_addr + heap_flags_offset, b"\x00\x00\x00\x00")
            await self.write_memory(heap_addr + force_flags_offset, b"\x00\x00\x00\x00")
        except ToolError as write_err:
            _logger.warning("anti_debug_heap_flags_write_failed", error=str(write_err))
            return False, f"write heap flags failed: {write_err}"
        return True, None

    async def reconstruct_imports(self, oep: int, output_path: str) -> dict[str, Any]:
        """Reconstruct the import table using Scylla via the bridge plugin.

        Sends a structured ``scylla_reconstruct`` RPC so the plugin can
        orchestrate the IAT search, auto-fix, and dump steps atomically.
        Falls back to the stepwise script commands when the RPC is not
        available in older plugin builds.

        Args:
            oep: Original Entry Point address.
            output_path: Path to write the fixed binary.

        Returns:
            dict[str, Any]: Dict with ``success``, ``oep``, and
            ``output_path`` fields; includes plugin-supplied details
            under ``details`` when the RPC returns extra data.

        Raises:
            ToolError: If the plugin reports a non-recoverable error.
        """
        _logger.debug("x64dbg_command_queued", command="scylla_reconstruct", oep=hex(oep), output=output_path)
        try:
            result = await self._send_pipe_command(
                "scylla_reconstruct",
                {"oep": hex(oep), "output_path": output_path},
            )
        except ToolError as exc:
            if not self._is_recoverable_pipe_error(exc):
                raise
            _logger.warning("scylla_rpc_unavailable_using_script", error=str(exc))
            await self._send_command(f"scylla.searchIAT {hex(oep)}")
            await self._send_command("scylla.autoFix")
            await self._send_command(f'scylla.dump "{output_path}"')
            return {"success": True, "oep": hex(oep), "output_path": output_path}

        response: dict[str, Any] = {"success": True, "oep": hex(oep), "output_path": output_path}
        if _is_str_obj_dict(result):
            response["details"] = dict(result)
        return response

    async def get_status(self) -> dict[str, Any]:
        """Get current debugger status.

        Returns:
            dict[str, Any]: Dict with debugging, paused, and initialized flags.

        Raises:
            ToolError: If the plugin returns a non-dict payload. A
                degenerate fallback of ``{"debugging": False, ...}`` is
                indistinguishable from a real "not running" state and
                would cause orchestrators polling this endpoint to act
                on stale information (audit6.md F-0029).
        """
        _logger.debug("status_querying")
        result = await self._send_pipe_command("status")
        if _is_str_obj_dict(result):
            return dict(result)
        msg = f"get_status: plugin returned non-dict payload of type {type(result).__name__}"
        raise ToolError(
            msg,
            tool_name="x64dbg",
            details={"x64dbg_error_code": _X64DBG_ERR_PROTOCOL_VIOLATION, "command": "status"},
        )

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
        _logger.debug("tls_callbacks_reading", module_name=module_name)
        base_address = await self._resolve_module_base(module_name)
        _, pe_header = await self._read_pe_header(base_address, module_name, size=512)

        is_pe64 = is_pe64_optional_header(pe_header, PE_OPTIONAL_HEADER_OFFSET)
        tls_dir_offset = get_data_directory_offset(0, is_pe64=is_pe64, entry_index=9)
        if tls_dir_offset + 8 > len(pe_header):
            return []

        tls_rva, tls_size = read_data_directory_entry(pe_header, tls_dir_offset)
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
        _logger.info("tls_callbacks_breaking", module_name=module_name)
        callbacks = await self.get_tls_callbacks(module_name)
        for cb in callbacks:
            addr_str = cb.get("address", "0")
            if isinstance(addr_str, str):
                addr = int(addr_str, 0)
                await self.set_breakpoint(addr)
        return {"success": True, "breakpoints_set": len(callbacks)}

    async def get_resources(self, module_name: str) -> list[dict[str, Any]]:
        """Get PE resource leaf entries for a module.

        Walks the resource tree recursively (Type -> Name/Id -> Language ->
        DataEntry), reading every directory level via the in-memory PE
        image and emitting one dict per leaf ``IMAGE_RESOURCE_DATA_ENTRY``
        with the full triple (type, id, language) plus the leaf's RVA,
        size, and code page.

        Args:
            module_name: Module name.

        Returns:
            list[dict[str, Any]]: List of resource leaf dicts. Each entry
            contains ``type_id``, ``type_name`` (well-known
            ``RT_*`` name when known, otherwise ``"RT_<id>"``),
            ``id`` (numeric resource id), ``name`` (string name when
            applicable), ``language``, ``rva`` (hex string of leaf VA),
            ``size`` (bytes), and ``code_page``.
        """
        _logger.debug("resources_reading", module_name=module_name)
        base_address = await self._resolve_module_base(module_name)
        _, pe_header = await self._read_pe_header(base_address, module_name, size=512)

        is_pe64 = is_pe64_optional_header(pe_header, PE_OPTIONAL_HEADER_OFFSET)
        rsrc_dir_offset = get_data_directory_offset(0, is_pe64=is_pe64, entry_index=2)
        if rsrc_dir_offset + 8 > len(pe_header):
            return []

        rsrc_rva, rsrc_size = read_data_directory_entry(pe_header, rsrc_dir_offset)
        if rsrc_rva == 0 or rsrc_size == 0:
            return []

        rsrc_blob = await self.read_memory(base_address + rsrc_rva, rsrc_size)
        resources: list[dict[str, Any]] = []
        self._walk_resource_directory(
            blob=rsrc_blob,
            module_base=base_address,
            dir_offset=0,
            depth=0,
            resources=resources,
            labels=_ResourcePathLabels(),
        )
        _logger.debug("resources_walk_completed", module_name=module_name, count=len(resources))
        return resources

    def _walk_resource_directory(
        self,
        *,
        blob: bytes,
        module_base: int,
        dir_offset: int,
        depth: int,
        resources: list[dict[str, Any]],
        labels: _ResourcePathLabels,
    ) -> None:
        """Recursively walk one IMAGE_RESOURCE_DIRECTORY level.

        Args:
            blob: Raw resource section bytes copied from the target.
            module_base: Module base VA (used to resolve leaf RVAs).
            dir_offset: Offset of the current directory inside ``blob``.
            depth: Current depth (0=Type, 1=Name/Id, 2=Language).
            resources: Output list to append leaf dicts to.
            labels: Path-so-far labels (type_id, type_name, res_id,
                res_name) accumulated by the parent directories.
        """
        header_size = 16
        if dir_offset + header_size > len(blob):
            return
        num_named = struct.unpack_from("<H", blob, dir_offset + 12)[0]
        num_id = struct.unpack_from("<H", blob, dir_offset + 14)[0]
        cursor = dir_offset + header_size
        for _ in range(num_named + num_id):
            cursor = self._walk_resource_entry(
                blob=blob,
                module_base=module_base,
                cursor=cursor,
                depth=depth,
                resources=resources,
                labels=labels,
            )
            if cursor < 0:
                return

    def _walk_resource_entry(
        self,
        *,
        blob: bytes,
        module_base: int,
        cursor: int,
        depth: int,
        resources: list[dict[str, Any]],
        labels: _ResourcePathLabels,
    ) -> int:
        """Process a single IMAGE_RESOURCE_DIRECTORY_ENTRY.

        Args:
            blob: Raw resource section bytes.
            module_base: Module base VA.
            cursor: Offset of the entry inside ``blob``.
            depth: Current tree depth.
            resources: Output list for leaf dicts.
            labels: Path labels accumulated by parent directories.

        Returns:
            int: The new cursor (advanced by 8) when processing
            succeeded; -1 when the entry was truncated and the caller
            must abort.
        """
        entry_size = 8
        if cursor + entry_size > len(blob):
            return -1
        name_field = struct.unpack_from("<I", blob, cursor)[0]
        offset_to_data = struct.unpack_from("<I", blob, cursor + 4)[0]
        next_cursor = cursor + entry_size

        is_named = bool(name_field & 0x80000000)
        entry_id_value: int = (name_field & 0x7FFFFFFF) if is_named else (name_field & 0xFFFFFFFF)
        entry_str: str | None = self._read_resource_name_string(blob, name_field & 0x7FFFFFFF) if is_named else None

        is_subdir = bool(offset_to_data & 0x80000000)
        child_offset = offset_to_data & 0x7FFFFFFF
        if is_subdir:
            self._walk_resource_directory(
                blob=blob,
                module_base=module_base,
                dir_offset=child_offset,
                depth=depth + 1,
                resources=resources,
                labels=labels.descend(
                    depth=depth,
                    is_named=is_named,
                    entry_id=entry_id_value,
                    entry_str=entry_str,
                ),
            )
        else:
            language = 0 if is_named else entry_id_value
            leaf = self._read_resource_data_entry(blob, module_base, child_offset)
            if leaf is not None:
                leaf_va, leaf_size, code_page = leaf
                resources.append({
                    "type_id": labels.type_id,
                    "type_name": labels.type_name,
                    "id": labels.res_id,
                    "name": labels.res_name,
                    "language": language,
                    "rva": hex(leaf_va),
                    "size": leaf_size,
                    "code_page": code_page,
                })
        return next_cursor

    @staticmethod
    def _read_resource_name_string(blob: bytes, offset: int) -> str | None:
        """Read an ``IMAGE_RESOURCE_DIR_STRING_U`` from the resource blob.

        Args:
            blob: Raw resource section bytes.
            offset: Offset within ``blob`` to the IMAGE_RESOURCE_DIR_STRING_U.

        Returns:
            str | None: Decoded UTF-16-LE string, or ``None`` on read failure.
        """
        if offset + 2 > len(blob):
            return None
        length = struct.unpack_from("<H", blob, offset)[0]
        start = offset + 2
        end = start + length * 2
        if end > len(blob):
            return None
        return blob[start:end].decode("utf-16-le", errors="replace")

    @staticmethod
    def _read_resource_data_entry(
        blob: bytes,
        module_base: int,
        offset: int,
    ) -> tuple[int, int, int] | None:
        """Read an ``IMAGE_RESOURCE_DATA_ENTRY`` at ``offset`` in the blob.

        Args:
            blob: Raw resource section bytes.
            module_base: Module base VA used to translate the leaf's image-relative RVA.
            offset: Offset within ``blob`` of the leaf entry.

        Returns:
            tuple[int, int, int] | None: ``(leaf_va, size, code_page)`` or
            ``None`` when the entry is truncated.
        """
        entry_size = 16
        if offset + entry_size > len(blob):
            return None
        data_rva, size, code_page = struct.unpack_from("<III", blob, offset)
        return module_base + int(data_rva), int(size), int(code_page)

    @classmethod
    async def get_privileges(cls) -> list[dict[str, Any]]:
        """Enumerate current process token privileges.

        Returns:
            list[dict[str, Any]]: List of privilege dicts with name and enabled status.
        """
        _logger.debug("privileges_enumerating")
        if not _IS_WIN32:
            return []

        try:
            return cls._enumerate_process_token_privileges()
        except (OSError, ValueError) as e:
            _logger.warning("privileges_enum_failed", error=str(e))
            return []

    @classmethod
    def _enumerate_process_token_privileges(cls) -> list[dict[str, Any]]:
        """Open the current process token and enumerate its privileges.

        Returns:
            list[dict[str, Any]]: List of privilege dictionaries with
            ``name``, ``enabled``, and ``enabled_by_default`` keys, or an
            empty list when the token could not be opened.
        """
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32
        token_handle = wintypes.HANDLE()
        current_process = kernel32.GetCurrentProcess()
        if not advapi32.OpenProcessToken(current_process, 0x0008, ctypes.byref(token_handle)):
            return []
        try:
            return cls._read_token_privileges(advapi32, token_handle)
        finally:
            kernel32.CloseHandle(token_handle)

    @classmethod
    def _read_token_privileges(
        cls,
        advapi32: ctypes.WinDLL,
        token_handle: wintypes.HANDLE,
    ) -> list[dict[str, Any]]:
        """Fetch and parse ``TokenPrivileges`` data for an open token.

        Args:
            advapi32: ``ctypes.windll.advapi32`` proxy used to query the
                token via ``GetTokenInformation`` and resolve LUIDs via
                ``LookupPrivilegeNameW``.
            token_handle: Open process-token handle returned by
                ``OpenProcessToken`` with ``TOKEN_QUERY``.

        Returns:
            list[dict[str, Any]]: List of privilege dictionaries with
            ``name``, ``enabled``, and ``enabled_by_default`` keys.
        """
        return_length = wintypes.DWORD()
        advapi32.GetTokenInformation(token_handle, 3, None, 0, ctypes.byref(return_length))
        buffer = ctypes.create_string_buffer(return_length.value)
        if not advapi32.GetTokenInformation(token_handle, 3, buffer, return_length.value, ctypes.byref(return_length)):
            return []
        count = struct.unpack_from("<I", buffer.raw, 0)[0]
        privileges: list[dict[str, Any]] = []
        offset = 4
        for _ in range(min(count, 100)):
            cls._append_token_privilege(advapi32, buffer.raw, offset, privileges)
            offset += 12
        return privileges

    @staticmethod
    def _append_token_privilege(
        advapi32: ctypes.WinDLL,
        raw: bytes,
        offset: int,
        privileges: list[dict[str, Any]],
    ) -> None:
        """Resolve one ``LUID_AND_ATTRIBUTES`` entry and append it.

        Args:
            advapi32: ``ctypes.windll.advapi32`` proxy used to resolve
                the LUID via ``LookupPrivilegeNameW``.
            raw: Raw ``TOKEN_PRIVILEGES`` byte buffer.
            offset: Byte offset of the ``LUID_AND_ATTRIBUTES`` record to
                read.
            privileges: Mutable list that receives the resolved
                privilege dictionary when the LUID lookup succeeds.
        """
        luid_low = struct.unpack_from("<I", raw, offset)[0]
        luid_high = struct.unpack_from("<I", raw, offset + 4)[0]
        attrs = struct.unpack_from("<I", raw, offset + 8)[0]
        name_buf = ctypes.create_unicode_buffer(256)
        name_len = wintypes.DWORD(256)

        class LUID(ctypes.Structure):
            """Windows ``LUID`` structure used for privilege lookup.

            A locally unique identifier is a 64-bit value that the OS assigns to privileges and other securable objects. Declared inline so
            it can be passed by reference into ``LookupPrivilegeNameW``.
            """

            _fields_: ClassVar = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

        luid = LUID(luid_low, luid_high)
        if advapi32.LookupPrivilegeNameW(None, ctypes.byref(luid), name_buf, ctypes.byref(name_len)):
            privileges.append({
                "name": name_buf.value,
                "enabled": bool(attrs & 0x00000002),
                "enabled_by_default": bool(attrs & 0x00000001),
            })

    @classmethod
    async def adjust_privilege(cls, name: str, *, enable: bool = True) -> dict[str, Any]:
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
            return cls._adjust_token_privilege_by_name(name, enable=enable)
        except (OSError, ValueError) as e:
            _logger.warning("privilege_adjust_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    def _adjust_token_privilege_by_name(cls, name: str, *, enable: bool) -> dict[str, Any]:
        """Look up ``name``, open the process token, and toggle the privilege.

        Args:
            name: Privilege name (for example ``"SeDebugPrivilege"``).
            enable: ``True`` to enable the privilege,
                ``False`` to disable it.

        Returns:
            dict[str, Any]: Result payload with ``success``, optional
            ``error``, and ``privilege`` / ``enabled`` keys.
        """
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

            Simplified single-entry variant of the standard Windows structure, which is all ``AdjustTokenPrivileges`` needs when toggling a
            single privilege at a time.
            """

            _fields_: ClassVar = [
                ("PrivilegeCount", wintypes.DWORD),
                ("Luid", LUID),
                ("Attributes", wintypes.DWORD),
            ]

        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            _logger.warning("adjust_privilege_lookup_failed", privilege=name)
            return {"success": False, "error": f"Privilege {name!r} not found"}

        token_handle = wintypes.HANDLE()
        current_process = kernel32.GetCurrentProcess()
        if not advapi32.OpenProcessToken(current_process, 0x0020, ctypes.byref(token_handle)):
            _logger.warning("adjust_privilege_open_token_failed", privilege=name)
            return {"success": False, "error": "Failed to open process token"}

        try:
            return cls._invoke_adjust_token_privileges(
                advapi32,
                token_handle,
                TokenPrivileges,
                luid,
                name,
                enable=enable,
            )
        finally:
            kernel32.CloseHandle(token_handle)

    @staticmethod
    def _invoke_adjust_token_privileges(
        advapi32: ctypes.WinDLL,
        token_handle: wintypes.HANDLE,
        token_privileges_cls: type[ctypes.Structure],
        luid: ctypes.Structure,
        name: str,
        *,
        enable: bool,
    ) -> dict[str, Any]:
        """Build a ``TOKEN_PRIVILEGES`` payload and submit it.

        Args:
            advapi32: ``ctypes.windll.advapi32`` proxy used to invoke
                ``AdjustTokenPrivileges``.
            token_handle: Open process-token handle with
                ``TOKEN_ADJUST_PRIVILEGES`` access.
            token_privileges_cls: Locally-declared ``TOKEN_PRIVILEGES``
                ctypes structure class.
            luid: Resolved ``LUID`` for the privilege to toggle.
            name: Privilege name, returned in the result for diagnostics.
            enable: ``True`` to enable the privilege, ``False`` to
                disable it.

        Returns:
            dict[str, Any]: Result payload with ``success``,
            ``privilege``, and ``enabled`` keys.
        """
        tp = token_privileges_cls()
        tp.PrivilegeCount = 1
        tp.Luid = luid
        tp.Attributes = 0x00000002 if enable else 0
        disable_all_privileges = False
        result = advapi32.AdjustTokenPrivileges(
            token_handle,
            disable_all_privileges,
            ctypes.byref(tp),
            0,
            None,
            None,
        )
        return {"success": bool(result), "privilege": name, "enabled": enable}


class X64DbgBridge(_X64DbgScriptingMixin):
    """Bridge for x64dbg Windows debugger.

    Composed from the ``_X64DbgBridgeBase`` core class together with topical mixin classes that inherit linearly so cross-references resolve
    through normal MRO. Each mixin groups one surface area so no single class definition exceeds the public method limit. The public
    interface, attribute set, and behavior are identical to the pre-refactor monolithic class.
    """

    async def shutdown(self) -> None:
        """Shutdown x64dbg and cleanup resources.

        Each cleanup phase is wrapped so that a fault in one stage cannot
        strand a later one. An exception from ``_close_connection`` no
        longer leaks the spawned ``x64dbg.exe`` process (audit6.md
        F-0011): the process-termination block is reached
        unconditionally, and the bookkeeping state (attached PID,
        breakpoints, watchpoints, pending step waiters, cached process
        handles) is always cleared in the ``finally`` arm even when
        termination itself raises. The first captured cleanup exception
        is re-raised after every other stage has run so callers can
        observe shutdown failures.

        Raises:
            ToolError: Re-raises the first ``ToolError`` captured from
                ``_close_connection`` or ``super().shutdown()`` after
                every other cleanup stage has run.
            OSError: Re-raises the first ``OSError`` captured from
                process termination, kill, ``super().shutdown()``, or
                ``_release_process_handles``.
            KeyError: Re-raises a ``KeyError`` from the process manager
                if it could not unregister the captured PID.
            RuntimeError: Re-raises the first ``RuntimeError`` captured
                from any other cleanup stage (this branch also handles
                the residual case where ``cleanup_errors`` contains an
                exception class outside the typed-handler tuples).
        """
        _logger.info(
            "x64dbg_shutdown_started",
            bridge="x64dbg",
            attached_pid=self._attached_pid,
            has_process=self._process is not None,
        )
        cleanup_errors: list[BaseException] = []

        try:
            await self._run_shutdown_phase(cleanup_errors)
        finally:
            await self._run_shutdown_finalization(cleanup_errors)

        if cleanup_errors:
            first = cleanup_errors[0]
            if isinstance(first, ToolError):
                raise ToolError(
                    first.message,
                    tool_name=first.tool_name,
                    exit_code=first.exit_code,
                    stderr=first.stderr,
                    error_code=first.error_code,
                    details=dict(first.details),
                ) from first
            if isinstance(first, OSError):
                raise OSError(*first.args) from first
            if isinstance(first, KeyError):
                raise KeyError(*first.args) from first
            raise RuntimeError(*first.args) from first
