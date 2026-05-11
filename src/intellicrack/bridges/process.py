# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Process control bridge for Windows process manipulation.

This module provides direct process control capabilities including memory access, thread manipulation, module enumeration, token/privilege
management, handle enumeration, window enumeration, service inspection, PEB/TEB access, heap enumeration, thread context manipulation, stack
walking, SEH chain traversal, mitigation policy queries, and many other Win32 capabilities using the Windows API.
"""

from __future__ import annotations

import asyncio
import ctypes
import re
import struct
import time
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Literal, cast, override


if TYPE_CHECKING:
    from collections.abc import Callable

from intellicrack.bridges._pe_format import (
    PE_DOS_LFANEW_OFFSET,
    PE_OPTIONAL_HEADER_OFFSET,
    PE_SIGNATURE,
    detect_format,
    get_data_directory_offset,
    is_pe64_optional_header,
    iterate_section_headers,
    pe_machine_to_arch,
    read_data_directory_entry,
    read_dos_e_lfanew,
    rva_to_file_offset,
    unpack_coff_header,
)
from intellicrack.bridges._win32_types import (
    CONTEXT64,
    CONTEXT_ALL,
    CONTEXT_I386_ALL,
    ENUM_SERVICE_STATUS_PROCESSW,
    ERROR_NOT_ALL_ASSIGNED,
    GR_GDIOBJECTS,
    GR_USEROBJECTS,
    HEAPENTRY32,
    HEAPLIST32,
    HKEY_CLASSES_ROOT,
    HKEY_CURRENT_CONFIG,
    HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE,
    HKEY_USERS,
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_ARM64,
    IMAGE_FILE_MACHINE_I386,
    IMAGE_FILE_MACHINE_UNKNOWN,
    INVALID_HANDLE_VALUE,
    IO_COUNTERS,
    JOBOBJECT_BASIC_LIMIT_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    KEY_ENUMERATE_SUB_KEYS,
    KEY_QUERY_VALUE,
    KEY_READ,
    LUID,
    LUID_AND_ATTRIBUTES,
    MEM_COMMIT,
    MEM_DECOMMIT,
    MEM_IMAGE,
    MEM_MAPPED,
    MEM_RELEASE,
    MEM_RESERVE,
    MEMORY_BASIC_INFORMATION,
    MODULEENTRY32,
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_NOACCESS,
    PAGE_READONLY,
    PAGE_READWRITE,
    PROCESS_ALL_ACCESS,
    PROCESS_BASIC_INFORMATION,
    PROCESS_DUP_HANDLE,
    PROCESS_MEMORY_COUNTERS,
    PROCESS_MITIGATION_ASLR_POLICY,
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY,
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY,
    PROCESS_MITIGATION_DEP_POLICY,
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY,
    PROCESS_MITIGATION_FONT_DISABLE_POLICY,
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY,
    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY,
    PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SUSPEND_RESUME,
    PROCESS_TERMINATE,
    PROCESS_VM_OPERATION,
    PROCESS_VM_READ,
    PROCESS_VM_WRITE,
    PROCESSENTRY32,
    SC_MANAGER_ENUMERATE_SERVICE,
    SE_PRIVILEGE_ENABLED,
    SE_PRIVILEGE_REMOVED,
    SERVICE_ACTIVE,
    SERVICE_STATE_ALL,
    SERVICE_WIN32,
    STACKFRAME64,
    SYMBOL_INFO,
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX,
    TH32CS_SNAPHEAPLIST,
    TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
    TH32CS_SNAPPROCESS,
    TH32CS_SNAPTHREAD,
    THREAD_BASIC_INFORMATION,
    THREAD_GET_CONTEXT,
    THREAD_QUERY_INFORMATION,
    THREAD_SET_CONTEXT,
    THREAD_SUSPEND_RESUME,
    THREADENTRY32,
    TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ALL_ACCESS,
    TOKEN_DUPLICATE,
    TOKEN_PRIVILEGES,
    TOKEN_QUERY,
    WAIT_FAILED,
    WAIT_OBJECT_0,
    WAIT_TIMEOUT,
    WOW64_CONTEXT,
    JobObjectBasicLimitInformation,
    JobObjectExtendedLimitInformation,
    ProcessASLRPolicy,
    ProcessBasicInformation,
    ProcessControlFlowGuardPolicy,
    ProcessDebugPort,
    ProcessDEPPolicy,
    ProcessDynamicCodePolicy,
    ProcessExtensionPointDisablePolicy,
    ProcessFontDisablePolicy,
    ProcessImageLoadPolicy,
    ProcessMitigationOptionsMask,
    ProcessSignaturePolicy,
    ProcessStrictHandleCheckPolicy,
    ProcessSystemCallDisablePolicy,
    ProcessWow64Information,
    SystemExtendedHandleInformation,
    ThreadBasicInformation,
    ThreadQuerySetWin32StartAddress,
    decode_protection,
    get_advapi32,
    get_dbghelp,
    get_ntdll,
    get_user32,
    mem_type_to_string,
    protection_to_string,
    state_to_string,
)
from intellicrack.bridges.base import BridgeCapabilities, BridgeState, ToolBridgeBase
from intellicrack.core.logging import get_logger
from intellicrack.core.types import (
    MemoryRegion,
    ModuleInfo,
    ProcessInfo,
    ThreadInfo,
    ToolDefinition,
    ToolError,
    ToolFunction,
    ToolName,
    ToolParameter,
)


_logger = get_logger(__name__)

_ERR_KERNEL32_NA = "kernel32 not available"
_ERR_SNAPSHOT_FAILED = "snapshot creation failed"
_ERR_OPEN_FAILED = "process open failed"
_ERR_NO_PROCESS = "no process specified"
_ERR_NOT_ATTACHED = "no process attached"
_ERR_TERMINATE_FAILED = "terminate failed"
_ERR_READ_FAILED = "memory read failed"
_ERR_WRITE_FAILED = "memory write failed"
_ERR_ALLOC_FAILED = "memory allocation failed"
_ERR_FREE_FAILED = "memory free failed"
_ERR_PROTECT_FAILED = "memory protection change failed"
_ERR_DLL_NOT_FOUND = "DLL not found"
_ERR_KERNEL32_HANDLE = "kernel32 handle failed"
_ERR_LOADLIB_ADDR = "LoadLibraryW address failed"
_ERR_REMOTE_THREAD = "remote thread creation failed"
_ERR_INJECT_WAIT_FAILED = "WaitForSingleObject failed on remote thread"
_ERR_INJECT_TIMEOUT = "remote thread timed out"
_ERR_INJECT_LOADLIB_FAILED = "LoadLibraryW failed in target"
_ERR_INJECT_GETEXITCODE_FAILED = "GetExitCodeThread failed"
_ERR_NTDLL_NA = "ntdll not available"
_ERR_ADVAPI32_NA = "advapi32 not available"
_ERR_USER32_NA = "user32 not available"
_ERR_DBGHELP_NA = "dbghelp not available"
_ERR_PSAPI_NA = "psapi not available"
_ERR_THREAD_OPEN_FAILED = "thread open failed"
_ERR_NO_THREAD = "no thread specified"
_ERR_CONTEXT_GET_FAILED = "GetThreadContext failed"
_ERR_CONTEXT_SET_FAILED = "SetThreadContext failed"
_ERR_SCM_OPEN_FAILED = "service control manager open failed"
_ERR_PIPE_CONNECT_FAILED = "pipe connect failed"
_ERR_DEVICE_OPEN_FAILED = "device open failed"
_ERR_IOCTL_FAILED = "DeviceIoControl failed"
_ERR_PIPE_CLOSE_FAILED = "pipe close failed"
_ERR_DEVICE_CLOSE_FAILED = "device close failed"
_ERR_INVALID_HEX = "input_data is not a valid hex string"
_ERR_SEH_NOT_APPLICABLE_X64 = "SEH chain not applicable to x64 target"

_MAX_MEMORY_ADDRESS = 0x7FFFFFFFFFFF
_WILDCARD_PATTERNS = {"??", "?"}

_ERROR_NO_MORE_FILES: int = 18
_ERROR_MORE_DATA: int = 234
_REG_INITIAL_BUF_SIZE: int = 4096
_REG_MAX_BUF_SIZE: int = 16 * 1024 * 1024
_REG_GROWTH_RETRY_LIMIT: int = 8

_STATUS_BUFFER_OVERFLOW_RAW: int = 0x80000005
_STATUS_BUFFER_TOO_SMALL_RAW: int = 0xC0000023
_STATUS_BUFFER_OVERFLOW: int = -2147483643
_STATUS_BUFFER_TOO_SMALL: int = -1073741789
_OBJECT_ALL_TYPES_INFORMATION: int = 3
_UNICODE_STRING_HEADER_SIZE: int = 4

_REG_TYPE_NAMES: dict[int, str] = {
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST",
    11: "REG_QWORD",
}

_BITS_PER_BYTE = 8
_POINTER_BITS_64 = 64

_MB_DIVISOR = 1024.0 * 1024.0

_STILL_ACTIVE = 259
_NTQUERY_BUF_MAX = 0x40000000
_STATUS_INFO_LENGTH_MISMATCH = -1073741820
_PTR_SIZE_64 = 8
_SEH_TERMINAL_32 = 0xFFFFFFFF
_SEH_TERMINAL_64 = 0xFFFFFFFFFFFFFFFF
_REG_TYPE_DWORD = 4
_REG_TYPE_QWORD = 11
_REG_TYPE_SZ = 1
_REG_TYPE_EXPAND_SZ = 2

_SEARCH_CHUNK_SIZE = 0x100000
_PE_SIGNATURE_SIZE = 4
_MAX_TYPE_NAME_BYTES = 512
_OBJECT_TYPE_INFO_HEADER_SIZE = 104

_JOB_QUERY_INFORMATION = 0x0004

_PE_DATA_DIR_COM_DESCRIPTOR = 14
_DOTNET_METADATA_SIGNATURE = 0x424A5342
_DOTNET_MIN_HEADER_READ = 0x400
_DOTNET_METADATA_VERSION_MAX = 256
_DOTNET_COR20_HEADER_SIZE = 72
_DOTNET_METADATA_MIN_SIZE = 20

_MAX_SYM_NAME: int = 2000
_MAX_PATH: int = 260

_MITIGATION_FLAG_NAMES: dict[str, tuple[str, ...]] = {
    "DEP": ("Enable", "DisableAtlThunkEmulation"),
    "ASLR": (
        "EnableBottomUpRandomization",
        "EnableForceRelocateImages",
        "EnableHighEntropy",
        "DisallowStrippedImages",
    ),
    "DynamicCode": (
        "ProhibitDynamicCode",
        "AllowThreadOptOut",
        "AllowRemoteDowngrade",
        "AuditProhibitDynamicCode",
    ),
    "StrictHandleCheck": (
        "RaiseExceptionOnInvalidHandleReference",
        "HandleExceptionsPermanentlyEnabled",
    ),
    "SystemCallDisable": (
        "DisallowWin32kSystemCalls",
        "AuditDisallowWin32kSystemCalls",
        "DisallowFsctlSystemCalls",
        "AuditDisallowFsctlSystemCalls",
    ),
    "CFG": (
        "EnableControlFlowGuard",
        "EnableExportSuppression",
        "StrictMode",
        "EnableXfg",
        "EnableXfgAuditMode",
    ),
    "BinarySignature": (
        "MicrosoftSignedOnly",
        "StoreSignedOnly",
        "MitigationOptIn",
        "AuditMicrosoftSignedOnly",
        "AuditStoreSignedOnly",
        "AuditMitigationOptIn",
    ),
    "FontDisable": (
        "DisableNonSystemFonts",
        "AuditNonSystemFontLoading",
    ),
    "ImageLoad": (
        "NoRemoteImages",
        "NoLowMandatoryLabelImages",
        "PreferSystem32Images",
        "AuditNoRemoteImages",
        "AuditNoLowMandatoryLabelImages",
    ),
}

_MITIGATION_PRIMARY_FLAG: dict[str, str] = {
    "DEP": "Enable",
    "ASLR": "EnableBottomUpRandomization",
    "DynamicCode": "ProhibitDynamicCode",
    "StrictHandleCheck": "RaiseExceptionOnInvalidHandleReference",
    "SystemCallDisable": "DisallowWin32kSystemCalls",
    "CFG": "EnableControlFlowGuard",
    "BinarySignature": "MicrosoftSignedOnly",
    "FontDisable": "DisableNonSystemFonts",
    "ImageLoad": "NoRemoteImages",
}

_PEB32_MIN_PARSE_LENGTH = 0x18
_PEB_BEING_DEBUGGED_OFFSET = 2

TLS_ARRAY_OFFSET_X64 = 0x1480
_TLS_EXPANSION_OFFSET_X64 = 0x1780
TLS_ARRAY_OFFSET_X86 = 0xE10
TLS_STATIC_SLOT_COUNT = 64
_ENV_POINTER_OFFSET_X64 = 0x80
_ENV_SIZE_OFFSET_X64 = 0x3F0
_ENV_POINTER_OFFSET_X86 = 0x48
_ENV_SIZE_OFFSET_X86 = 0x290
_PARAMS_READ_SIZE_X64 = 0x400
_PARAMS_READ_SIZE_X86 = 0x2A0

_ERR_WOW64_UNAVAILABLE = "WOW64 detection unavailable"
_ERR_ACCESS_HANDLE_OPEN = "token open failed"
_ERR_PRIV_QUERY_FAILED = "GetTokenInformation failed"
_ERR_PEB_READ = "PEB read failed"
_ERR_TEB_READ = "TEB read failed"
_ERR_NTQUERY_PROC = "NtQueryInformationProcess failed: 0x"
_ERR_NTQUERY_THREAD = "NtQueryInformationThread failed: 0x"
_ERR_NTQUERY_SYS = "NtQuerySystemInformation failed: 0x"
_ERR_NTQUERY_SYS_BUF_MAX = "NtQuerySystemInformation buffer exceeded maximum size"
_ERR_HANDLE_ENUM_BUF_MAX = "handle enumeration buffer exceeded maximum size"
_ERR_PRIV_LOOKUP = "privilege lookup failed: "
_ERR_PRIV_NOT_HELD = "privilege not held: "
_ERR_ENUM_SVC = "EnumServicesStatusExW failed"
_ERR_REG_KEY_OPEN = "registry key open failed: "
_ERR_REG_VALUE_READ = "registry value read failed: "
_ERR_REG_VALUE_TOO_LARGE = "registry value exceeds maximum supported size: "
_ERR_INVALID_REG_ROOT = "invalid registry root: "
_ERR_SECTION_CREATE = "section creation failed"
_ERR_SECTION_MAP = "section mapping failed"
_ERR_SECTION_NAME_COLLISION = "section name already in use"
_ERR_SECTION_UNMAP = "section unmap failed"
_ERR_SECTION_NOT_MAPPED = "section base address not tracked"

_ERROR_ALREADY_EXISTS = 183
_CODE_SECTION_NAME_COLLISION = "SECTION_NAME_COLLISION"
_CODE_SECTION_CREATE_FAILED = "SECTION_CREATE_FAILED"
_CODE_SECTION_UNMAP_FAILED = "SECTION_UNMAP_FAILED"
_CODE_SECTION_NOT_MAPPED = "SECTION_NOT_MAPPED"

_THREAD_OP_FAILURE_SENTINEL: int = 0xFFFFFFFF


class PEB64(ctypes.Structure):
    """64-bit Process Environment Block layout through ProcessParameters.

    MS-documented offsets for ntdll!_PEB on amd64/arm64 targets. Fields beyond ProcessParameters are not accessed and are omitted.
    """

    _fields_: ClassVar = [
        ("InheritedAddressSpace", ctypes.c_byte),
        ("ReadImageFileExecOptions", ctypes.c_byte),
        ("BeingDebugged", ctypes.c_byte),
        ("BitField", ctypes.c_byte),
        ("_Padding0", ctypes.c_byte * 4),
        ("Mutant", ctypes.c_uint64),
        ("ImageBaseAddress", ctypes.c_uint64),
        ("Ldr", ctypes.c_uint64),
        ("ProcessParameters", ctypes.c_uint64),
    ]


class PEB32(ctypes.Structure):
    """32-bit Process Environment Block layout through ProcessParameters.

    MS-documented offsets for ntdll!_PEB on i386 targets and WOW64. Fields beyond ProcessParameters are not accessed and are omitted.
    """

    _fields_: ClassVar = [
        ("InheritedAddressSpace", ctypes.c_byte),
        ("ReadImageFileExecOptions", ctypes.c_byte),
        ("BeingDebugged", ctypes.c_byte),
        ("BitField", ctypes.c_byte),
        ("Mutant", ctypes.c_uint32),
        ("ImageBaseAddress", ctypes.c_uint32),
        ("Ldr", ctypes.c_uint32),
        ("ProcessParameters", ctypes.c_uint32),
    ]


class TEB64(ctypes.Structure):
    """64-bit Thread Environment Block layout through TlsExpansionSlots.

    MS-documented offsets for ntdll!_TEB on amd64/arm64 targets. Gaps between named fields are filled with reserved byte arrays so that
    ctypes.sizeof(TEB64) equals the true in-memory size and buffer allocation covers TlsSlots[64] at +0x1480 and TlsExpansionSlots at
    +0x1780.
    """

    _fields_: ClassVar = [
        ("ExceptionList", ctypes.c_uint64),
        ("StackBase", ctypes.c_uint64),
        ("StackLimit", ctypes.c_uint64),
        ("SubSystemTib", ctypes.c_uint64),
        ("FiberData", ctypes.c_uint64),
        ("ArbitraryUserPointer", ctypes.c_uint64),
        ("Self", ctypes.c_uint64),
        ("EnvironmentPointer", ctypes.c_uint64),
        ("ClientId_UniqueProcess", ctypes.c_uint64),
        ("ClientId_UniqueThread", ctypes.c_uint64),
        ("ActiveRpcHandle", ctypes.c_uint64),
        ("ThreadLocalStoragePointer", ctypes.c_uint64),
        ("ProcessEnvironmentBlock", ctypes.c_uint64),
        ("LastErrorValue", ctypes.c_uint32),
        ("_Reserved06c", ctypes.c_byte * (TLS_ARRAY_OFFSET_X64 - 0x06C)),
        ("TlsSlots", ctypes.c_uint64 * 64),
        ("TlsLinks", ctypes.c_uint64 * 2),
        ("_Reserved1690", ctypes.c_byte * (_TLS_EXPANSION_OFFSET_X64 - 0x1690)),
        ("TlsExpansionSlots", ctypes.c_uint64),
    ]


class TEB32(ctypes.Structure):
    """32-bit Thread Environment Block layout through TlsSlots[64].

    MS-documented offsets for ntdll!_TEB on i386 targets and WOW64. Gaps between named fields are filled with reserved byte arrays so that
    ctypes.sizeof(TEB32) equals the true in-memory size and buffer allocation covers TlsSlots[64] at +0xE10.
    """

    _fields_: ClassVar = [
        ("ExceptionList", ctypes.c_uint32),
        ("StackBase", ctypes.c_uint32),
        ("StackLimit", ctypes.c_uint32),
        ("SubSystemTib", ctypes.c_uint32),
        ("FiberData", ctypes.c_uint32),
        ("ArbitraryUserPointer", ctypes.c_uint32),
        ("Self", ctypes.c_uint32),
        ("EnvironmentPointer", ctypes.c_uint32),
        ("ClientId_UniqueProcess", ctypes.c_uint32),
        ("ClientId_UniqueThread", ctypes.c_uint32),
        ("ActiveRpcHandle", ctypes.c_uint32),
        ("ThreadLocalStoragePointer", ctypes.c_uint32),
        ("ProcessEnvironmentBlock", ctypes.c_uint32),
        ("LastErrorValue", ctypes.c_uint32),
        ("_Reserved038", ctypes.c_byte * (TLS_ARRAY_OFFSET_X86 - 0x038)),
        ("TlsSlots", ctypes.c_uint32 * 64),
    ]


class IMAGEHLP_MODULE64(ctypes.Structure):
    """DbgHelp IMAGEHLP_MODULE64 structure for module information via SymGetModuleInfo64.

    Matches the layout from dbghelp.h. ``SizeOfStruct`` must be set to ``ctypes.sizeof(IMAGEHLP_MODULE64)`` before passing to
    ``SymGetModuleInfo64``.
    """

    _fields_: ClassVar = [
        ("SizeOfStruct", wintypes.DWORD),
        ("BaseOfImage", ctypes.c_ulonglong),
        ("ImageSize", wintypes.DWORD),
        ("TimeDateStamp", wintypes.DWORD),
        ("CheckSum", wintypes.DWORD),
        ("NumSyms", wintypes.DWORD),
        ("SymType", wintypes.DWORD),
        ("ModuleName", ctypes.c_char * 32),
        ("ImageName", ctypes.c_char * 256),
        ("LoadedImageName", ctypes.c_char * 256),
        ("LoadedPdbName", ctypes.c_char * 256),
        ("CVSig", wintypes.DWORD),
        ("CVData", ctypes.c_wchar * (_MAX_PATH * 3)),
        ("PdbSig", wintypes.DWORD),
        ("PdbSig70", ctypes.c_byte * 16),
        ("PdbAge", wintypes.DWORD),
        ("PdbUnmatched", wintypes.BOOL),
        ("DbgUnmatched", wintypes.BOOL),
        ("LineNumbers", wintypes.BOOL),
        ("GlobalSymbols", wintypes.BOOL),
        ("TypeInfo", wintypes.BOOL),
        ("SourceIndexed", wintypes.BOOL),
        ("Publics", wintypes.BOOL),
    ]


ProcessAccessRights = Literal[
    "all",
    "query",
    "read",
    "write",
    "terminate",
    "suspend",
]

# ---------------------------------------------------------------------------
# Module-level ToolFunction list (FridaBridge pattern)
# ---------------------------------------------------------------------------

_PROCESS_FUNCTIONS: list[ToolFunction] = [
    ToolFunction(
        name="process.list",
        description="List all running processes",
        parameters=[
            ToolParameter(name="filter_name", type="string", description="Optional name filter", required=False),
        ],
        returns="List of ProcessInfo objects",
    ),
    ToolFunction(
        name="process.list_detailed",
        description="List processes with architecture, memory, and thread count in a single call",
        parameters=[
            ToolParameter(name="filter_name", type="string", description="Optional name filter", required=False),
        ],
        returns="List of dicts with pid, name, thread_count, architecture, memory_mb",
    ),
    ToolFunction(
        name="process.open",
        description="Open a process for manipulation",
        parameters=[
            ToolParameter(name="pid", type="integer", description="Process ID", required=True),
            ToolParameter(
                name="access",
                type="string",
                description="Access rights: all, query, read, write, terminate",
                required=False,
                default="all",
                enum=["all", "query", "read", "write", "terminate", "suspend"],
            ),
        ],
        returns="Success status",
    ),
    ToolFunction(name="process.close", description="Close the current process handle", parameters=[], returns="Success status"),
    ToolFunction(
        name="process.terminate",
        description="Terminate a process",
        parameters=[
            ToolParameter(name="pid", type="integer", description="Process ID (uses current if not specified)", required=False),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="process.suspend",
        description="Suspend all threads of a process",
        parameters=[
            ToolParameter(name="pid", type="integer", description="Process ID (uses current if not specified)", required=False),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="process.resume",
        description="Resume all threads of a process",
        parameters=[
            ToolParameter(name="pid", type="integer", description="Process ID (uses current if not specified)", required=False),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="process.read_memory",
        description="Read memory from process",
        parameters=[
            ToolParameter(name="address", type="integer", description="Memory address", required=True),
            ToolParameter(name="size", type="integer", description="Bytes to read", required=True),
        ],
        returns="Hex string of memory contents",
    ),
    ToolFunction(
        name="process.write_memory",
        description="Write memory to process",
        parameters=[
            ToolParameter(name="address", type="integer", description="Memory address", required=True),
            ToolParameter(name="data", type="string", description="Hex data to write", required=True),
        ],
        returns="Bytes written",
    ),
    ToolFunction(
        name="process.allocate",
        description="Allocate memory in process",
        parameters=[
            ToolParameter(name="size", type="integer", description="Size to allocate", required=True),
            ToolParameter(
                name="protection",
                type="string",
                description="Memory protection (rwx, rw, rx, r)",
                required=False,
                default="rwx",
            ),
        ],
        returns="Allocated address",
    ),
    ToolFunction(
        name="process.free",
        description="Free allocated memory",
        parameters=[
            ToolParameter(name="address", type="integer", description="Address to free", required=True),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="process.protect",
        description="Change memory protection",
        parameters=[
            ToolParameter(name="address", type="integer", description="Memory address", required=True),
            ToolParameter(name="size", type="integer", description="Region size", required=True),
            ToolParameter(name="protection", type="string", description="New protection (rwx, rw, rx, r)", required=True),
        ],
        returns="Previous protection",
    ),
    ToolFunction(
        name="process.get_modules",
        description="Get loaded modules",
        parameters=[
            ToolParameter(name="pid", type="integer", description="Process ID (uses current if not specified)", required=False),
        ],
        returns="List of ModuleInfo objects",
    ),
    ToolFunction(
        name="process.get_threads",
        description="Get process threads with start address and real state",
        parameters=[
            ToolParameter(name="pid", type="integer", description="Process ID (uses current if not specified)", required=False),
        ],
        returns="List of ThreadInfo objects",
    ),
    ToolFunction(
        name="process.get_memory_map",
        description="Get process memory map; optionally resolve mapped-file names",
        parameters=[
            ToolParameter(
                name="resolve_names",
                type="boolean",
                description="Resolve module/mapped-file names for MEM_MAPPED and MEM_IMAGE regions via GetMappedFileNameW",
                required=False,
                default=False,
            ),
        ],
        returns="List of MemoryRegion objects",
    ),
    ToolFunction(
        name="process.search_pattern",
        description="Search for byte pattern in memory with optional address bounds",
        parameters=[
            ToolParameter(name="pattern", type="string", description="Hex pattern with wildcards (e.g. '48 8B ?? ??')", required=True),
            ToolParameter(
                name="start_address",
                type="integer",
                description="Optional inclusive lower bound of address range to scan",
                required=False,
            ),
            ToolParameter(
                name="end_address",
                type="integer",
                description="Optional inclusive upper bound of address range to scan",
                required=False,
            ),
        ],
        returns="List of matching addresses",
    ),
    ToolFunction(
        name="process.inject_dll",
        description="Inject a DLL into the process",
        parameters=[
            ToolParameter(name="dll_path", type="string", description="Path to DLL file", required=True),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="process.get_process_info",
        description="Get detailed process information",
        parameters=[
            ToolParameter(name="pid", type="integer", description="Process ID (uses current if not specified)", required=False),
        ],
        returns="Process info or None if not found",
    ),
    ToolFunction(
        name="process.get_process_memory_mb",
        description="Get working set memory size in megabytes",
        parameters=[ToolParameter(name="pid", type="integer", description="Process ID", required=True)],
        returns="Memory size in MB",
    ),
    ToolFunction(
        name="process.detect_architecture",
        description="Detect whether a process is 32-bit or 64-bit",
        parameters=[ToolParameter(name="pid", type="integer", description="Process ID", required=True)],
        returns="Architecture string (x86_64, x86, arm64, arm, Unknown)",
    ),
    ToolFunction(
        name="process.get_token_privileges",
        description="Get token privileges for a process",
        parameters=[
            ToolParameter(name="pid", type="integer", description="Process ID (uses current if not specified)", required=False),
        ],
        returns="List of privilege dicts with name, luid, enabled fields",
    ),
    ToolFunction(
        name="process.adjust_token_privilege",
        description="Enable or disable a specific token privilege",
        parameters=[
            ToolParameter(name="privilege_name", type="string", description="Privilege name (e.g. SeDebugPrivilege)", required=True),
            ToolParameter(name="enable", type="boolean", description="True to enable, False to disable", required=True),
            ToolParameter(name="pid", type="integer", description="Process ID (uses current if not specified)", required=False),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="process.get_handles",
        description="Enumerate open handles for a process",
        parameters=[
            ToolParameter(name="pid", type="integer", description="Process ID (uses current if not specified)", required=False),
        ],
        returns="List of handle dicts with value, type_index, access fields",
    ),
    ToolFunction(
        name="process.get_windows",
        description="Enumerate windows belonging to a process",
        parameters=[
            ToolParameter(name="pid", type="integer", description="Process ID (uses current if not specified)", required=False),
        ],
        returns="List of window dicts with hwnd, title, class_name, visible fields",
    ),
    ToolFunction(
        name="process.list_services",
        description="List Windows services, optionally filtered by owning PID",
        parameters=[
            ToolParameter(name="filter_pid", type="integer", description="Filter to services owned by this PID", required=False),
        ],
        returns="List of service dicts",
    ),
    ToolFunction(
        name="process.read_peb",
        description="Read Process Environment Block fields",
        parameters=[
            ToolParameter(name="pid", type="integer", description="Process ID (uses current if not specified)", required=False),
        ],
        returns="Dict with PEB field values",
    ),
    ToolFunction(
        name="process.read_teb",
        description="Read Thread Environment Block fields for a thread",
        parameters=[
            ToolParameter(name="tid", type="integer", description="Thread ID", required=True),
        ],
        returns="Dict with TEB field values",
    ),
    ToolFunction(
        name="process.get_heaps",
        description="Enumerate heaps of a process via Toolhelp32",
        parameters=[
            ToolParameter(name="pid", type="integer", description="Process ID (uses current if not specified)", required=False),
        ],
        returns="List of heap dicts with id, base, flags fields",
    ),
    ToolFunction(
        name="process.get_thread_context",
        description="Get CPU register context for a thread",
        parameters=[
            ToolParameter(name="tid", type="integer", description="Thread ID", required=True),
        ],
        returns="Dict of register name to value",
    ),
    ToolFunction(
        name="process.set_thread_context",
        description="Set CPU register values for a thread",
        parameters=[
            ToolParameter(name="tid", type="integer", description="Thread ID", required=True),
            ToolParameter(name="registers", type="object", description="Dict of register name to value", required=True),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="process.stack_walk",
        description="Walk the call stack of a thread using DbgHelp",
        parameters=[
            ToolParameter(name="tid", type="integer", description="Thread ID", required=True),
        ],
        returns="List of stack frame dicts",
    ),
    ToolFunction(
        name="process.get_seh_chain",
        description="Get the SEH exception handler chain for a thread",
        parameters=[
            ToolParameter(name="tid", type="integer", description="Thread ID", required=True),
        ],
        returns="List of SEH handler dicts",
    ),
    ToolFunction(
        name="process.get_mitigation_policies",
        description="Query process mitigation policies (DEP, ASLR, CFG, etc.)",
        parameters=[
            ToolParameter(name="pid", type="integer", description="Process ID (uses current if not specified)", required=False),
        ],
        returns="Dict of policy name to enabled/flags",
    ),
    ToolFunction(
        name="process.get_environment",
        description="Read environment variables from process PEB",
        parameters=[
            ToolParameter(name="pid", type="integer", description="Process ID (uses current if not specified)", required=False),
        ],
        returns="Dict of environment variable name to value",
    ),
    ToolFunction(
        name="process.pipe_connect",
        description="Connect to a named pipe",
        parameters=[
            ToolParameter(name="pipe_name", type="string", description="Pipe name (e.g. \\\\.\\pipe\\MyPipe)", required=True),
            ToolParameter(name="timeout_ms", type="integer", description="Timeout in milliseconds", required=False, default="5000"),
        ],
        returns="Pipe handle value",
    ),
    ToolFunction(
        name="process.pipe_read",
        description="Read data from a named pipe handle",
        parameters=[
            ToolParameter(name="handle", type="integer", description="Pipe handle", required=True),
            ToolParameter(name="size", type="integer", description="Bytes to read", required=True),
        ],
        returns="Hex string of data read",
    ),
    ToolFunction(
        name="process.pipe_write",
        description="Write data to a named pipe handle",
        parameters=[
            ToolParameter(name="handle", type="integer", description="Pipe handle", required=True),
            ToolParameter(name="data", type="string", description="Hex data to write", required=True),
        ],
        returns="Bytes written",
    ),
    ToolFunction(
        name="process.pipe_close",
        description="Close a named pipe handle",
        parameters=[
            ToolParameter(name="handle", type="integer", description="Pipe handle", required=True),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="process.enumerate_com_servers",
        description="Enumerate COM servers loaded in a process",
        parameters=[
            ToolParameter(name="pid", type="integer", description="Process ID (uses current if not specified)", required=False),
        ],
        returns="List of COM server dicts",
    ),
    ToolFunction(
        name="process.detect_dotnet",
        description="Detect .NET CLR presence and version in a process",
        parameters=[
            ToolParameter(name="pid", type="integer", description="Process ID (uses current if not specified)", required=False),
        ],
        returns="Dict with clr_loaded (bool), clr_version (str | None), runtime_dlls (list[str]) fields",
    ),
    ToolFunction(
        name="process.device_open",
        description="Open a device driver path for IOCTL communication",
        parameters=[
            ToolParameter(name="device_path", type="string", description="Device path (e.g. \\\\.\\MyDriver)", required=True),
        ],
        returns="Device handle value",
    ),
    ToolFunction(
        name="process.device_ioctl",
        description="Send an IOCTL to an open device handle",
        parameters=[
            ToolParameter(name="handle", type="integer", description="Device handle", required=True),
            ToolParameter(name="ioctl_code", type="integer", description="IOCTL control code", required=True),
            ToolParameter(name="input_data", type="string", description="Hex input data", required=False),
            ToolParameter(name="output_size", type="integer", description="Expected output buffer size", required=False, default="4096"),
        ],
        returns="Hex string of output data",
    ),
    ToolFunction(
        name="process.device_close",
        description="Close a device handle",
        parameters=[
            ToolParameter(name="handle", type="integer", description="Device handle", required=True),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="process.get_job_info",
        description="Query job object information for a process",
        parameters=[
            ToolParameter(name="pid", type="integer", description="Process ID (uses current if not specified)", required=False),
        ],
        returns="Dict with job object limit information",
    ),
    ToolFunction(
        name="process.get_gui_resources",
        description="Get GDI and User object counts for a process",
        parameters=[
            ToolParameter(name="pid", type="integer", description="Process ID (uses current if not specified)", required=False),
        ],
        returns="Dict with gdi_objects and user_objects counts",
    ),
    ToolFunction(
        name="process.reg_read_value",
        description="Read a registry value",
        parameters=[
            ToolParameter(name="key_path", type="string", description="Registry key path (e.g. HKLM\\SOFTWARE\\...)", required=True),
            ToolParameter(name="value_name", type="string", description="Value name to read", required=True),
        ],
        returns="Dict with type and data fields",
    ),
    ToolFunction(
        name="process.reg_enum_keys",
        description="Enumerate subkeys of a registry key",
        parameters=[
            ToolParameter(name="key_path", type="string", description="Registry key path", required=True),
        ],
        returns="List of subkey name strings",
    ),
    ToolFunction(
        name="process.reg_enum_values",
        description="Enumerate values under a registry key",
        parameters=[
            ToolParameter(name="key_path", type="string", description="Registry key path", required=True),
        ],
        returns="List of value name strings",
    ),
    ToolFunction(
        name="process.create_section",
        description="Create a named section (file mapping) object",
        parameters=[
            ToolParameter(name="size", type="integer", description="Section size in bytes", required=True),
            ToolParameter(name="section_name", type="string", description="Optional section name", required=False),
        ],
        returns="Section handle value",
    ),
    ToolFunction(
        name="process.map_section",
        description="Map a section into the current process address space",
        parameters=[
            ToolParameter(name="handle", type="integer", description="Section handle", required=True),
            ToolParameter(name="size", type="integer", description="Size to map", required=True),
        ],
        returns="Mapped base address",
    ),
    ToolFunction(
        name="process.unmap_section",
        description="Unmap a previously mapped section view from the current process and close the section handle if it was created via process.create_section",
        parameters=[
            ToolParameter(
                name="base_address",
                type="integer",
                description="Mapped base address returned by process.map_section",
                required=True,
            ),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="process.get_tls_values",
        description="Read TLS slot values for a thread",
        parameters=[
            ToolParameter(name="tid", type="integer", description="Thread ID", required=True),
            ToolParameter(name="max_slots", type="integer", description="Maximum TLS slots to read", required=False, default="64"),
        ],
        returns="List of TLS slot dicts with index and value",
    ),
    ToolFunction(
        name="process.get_fiber_data",
        description="Read fiber data pointer for a thread",
        parameters=[
            ToolParameter(name="tid", type="integer", description="Thread ID", required=True),
        ],
        returns="Dict with fiber_data address",
    ),
    ToolFunction(
        name="process.query_system_info",
        description="Raw NtQuerySystemInformation bridge",
        parameters=[
            ToolParameter(name="info_class", type="integer", description="SystemInformationClass value", required=True),
            ToolParameter(name="buffer_size", type="integer", description="Initial buffer size", required=False, default="65536"),
        ],
        returns="Hex string of raw output buffer",
    ),
]


class _MODULEINFO(ctypes.Structure):
    """PSAPI MODULEINFO structure returned by GetModuleInformation."""

    _fields_: ClassVar = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", ctypes.c_void_p),
    ]


class ProcessBridge(ToolBridgeBase):
    """Bridge for Windows process control.

    Provides direct process manipulation including memory access,
    thread control, module enumeration, token/privilege management,
    handle enumeration, window enumeration, service inspection,
    PEB/TEB access, heap enumeration, thread context manipulation,
    stack walking, SEH chain traversal, mitigation policy queries,
    and many other Win32 capabilities. Instances own slots for the
    attached process identifier and handle, cached lazy-loaded Windows
    DLL references (``kernel32``, ``psapi``, ``ntdll``, ``advapi32``,
    ``user32``, ``dbghelp``), the debug-privilege flag that records
    whether ``SeDebugPrivilege`` has been elevated, and the advertised
    ``BridgeCapabilities``.

    Attributes:
        PROCESS_ALL_ACCESS: Win32 access mask granting all process permissions.
        PROCESS_QUERY_INFORMATION: Win32 right to query process metadata.
        PROCESS_VM_READ: Win32 right to read process virtual memory.
        PROCESS_VM_WRITE: Win32 right to write process virtual memory.
        PROCESS_VM_OPERATION: Win32 right for VM operations (VirtualAllocEx, etc.).
        PROCESS_TERMINATE: Win32 right to terminate a process.
        PROCESS_SUSPEND_RESUME: Win32 right to suspend or resume process threads.
        TH32CS_SNAPPROCESS: Toolhelp32 flag to include processes in snapshot.
        TH32CS_SNAPTHREAD: Toolhelp32 flag to include threads in snapshot.
        TH32CS_SNAPMODULE: Toolhelp32 flag to include modules in snapshot.
        TH32CS_SNAPMODULE32: Toolhelp32 flag to include 32-bit modules from 64-bit process.
        MEM_COMMIT: VirtualAlloc flag to commit physical storage for a region.
        MEM_RESERVE: VirtualAlloc flag to reserve virtual address space.
        MEM_RELEASE: VirtualFree flag to release a memory region.
        PAGE_NOACCESS: Memory protection: no access permitted.
        PAGE_READONLY: Memory protection: read-only access.
        PAGE_READWRITE: Memory protection: read and write access.
        PAGE_EXECUTE: Memory protection: execute-only access.
        PAGE_EXECUTE_READ: Memory protection: execute and read access.
        PAGE_EXECUTE_READWRITE: Memory protection: execute, read, and write access.
    """

    PROCESS_ALL_ACCESS = PROCESS_ALL_ACCESS
    PROCESS_QUERY_INFORMATION = PROCESS_QUERY_INFORMATION
    PROCESS_VM_READ = PROCESS_VM_READ
    PROCESS_VM_WRITE = PROCESS_VM_WRITE
    PROCESS_VM_OPERATION = PROCESS_VM_OPERATION
    PROCESS_TERMINATE = PROCESS_TERMINATE
    PROCESS_SUSPEND_RESUME = PROCESS_SUSPEND_RESUME

    TH32CS_SNAPPROCESS = TH32CS_SNAPPROCESS
    TH32CS_SNAPTHREAD = TH32CS_SNAPTHREAD
    TH32CS_SNAPMODULE = TH32CS_SNAPMODULE
    TH32CS_SNAPMODULE32 = TH32CS_SNAPMODULE32

    MEM_COMMIT = MEM_COMMIT
    MEM_RESERVE = MEM_RESERVE
    MEM_RELEASE = MEM_RELEASE

    PAGE_NOACCESS = PAGE_NOACCESS
    PAGE_READONLY = PAGE_READONLY
    PAGE_READWRITE = PAGE_READWRITE
    PAGE_EXECUTE = PAGE_EXECUTE
    PAGE_EXECUTE_READ = PAGE_EXECUTE_READ
    PAGE_EXECUTE_READWRITE = PAGE_EXECUTE_READWRITE

    def __init__(self) -> None:
        """Initialize the ProcessBridge instance.

        Allocates tracking dictionaries used by section/view, pipe, and
        device lifecycle so :meth:`shutdown` can release any handles the
        caller forgot:

        * ``_section_handles`` maps section handle -> section name (or
          empty string for anonymous sections) for create/cleanup.
        * ``_section_views`` maps mapped base address -> section handle
          so :meth:`unmap_section` can find the owning handle.
        * ``_pipe_handles`` maps open pipe handle -> pipe name.
        * ``_device_handles`` maps open device handle -> device path.
        """
        super().__init__()
        self._attached_pid: int | None = None
        self._process_handle: int | None = None
        self._kernel32: ctypes.WinDLL | None = None
        self._psapi: ctypes.WinDLL | None = None
        self._ntdll: ctypes.WinDLL | None = None
        self._advapi32: ctypes.WinDLL | None = None
        self._user32: ctypes.WinDLL | None = None
        self._dbghelp: ctypes.WinDLL | None = None
        self._debug_privilege_enabled: bool = False
        self._section_handles: dict[int, str] = {}
        self._section_views: dict[int, int] = {}
        self._pipe_handles: dict[int, str] = {}
        self._device_handles: dict[int, str] = {}
        self._handle_type_cache: dict[int, str] = {}
        self._privileges_changed_callbacks: list[Callable[[], None]] = []
        self._capabilities = BridgeCapabilities(
            supports_memory_access=True,
            supports_debugging=False,
            supported_architectures=["x86", "x86_64"],
            supported_formats=["pe"],
        )
        _logger.debug("process_bridge_initialized")

    @property
    def name(self) -> ToolName:
        """Get the tool's name.

        Returns:
            ToolName: ToolName.PROCESS
        """
        return ToolName.PROCESS

    @property
    def tool_definition(self) -> ToolDefinition:
        """Get tool definition for LLM function calling.

        Returns:
            ToolDefinition: ToolDefinition with all available functions.
        """
        return ToolDefinition(
            tool_name=ToolName.PROCESS,
            description="Windows process control - memory, threads, modules, tokens, handles, windows, services, PEB/TEB, heaps, context, stack walk, SEH, mitigations, pipes, COM, .NET, devices, registry, and more",
            functions=_PROCESS_FUNCTIONS,
        )

    @property
    def kernel32(self) -> ctypes.WinDLL | None:
        """Read-only handle to kernel32.dll loaded during initialization.

        Returns:
            ctypes.WinDLL | None: kernel32 DLL handle or None if not loaded.
        """
        return self._kernel32

    @property
    def psapi(self) -> ctypes.WinDLL | None:
        """Read-only handle to psapi.dll loaded during initialization.

        Returns:
            ctypes.WinDLL | None: psapi DLL handle or None if not loaded.
        """
        return self._psapi

    @property
    def ntdll(self) -> ctypes.WinDLL | None:
        """Read-only handle to ntdll.dll loaded during initialization.

        Returns:
            ctypes.WinDLL | None: ntdll DLL handle or None if not loaded.
        """
        return self._ntdll

    @property
    def advapi32(self) -> ctypes.WinDLL | None:
        """Read-only handle to advapi32.dll loaded during initialization.

        Returns:
            ctypes.WinDLL | None: advapi32 DLL handle or None if not loaded.
        """
        return self._advapi32

    @property
    def user32(self) -> ctypes.WinDLL | None:
        """Read-only handle to user32.dll loaded during initialization.

        Returns:
            ctypes.WinDLL | None: user32 DLL handle or None if not loaded.
        """
        return self._user32

    @property
    def dbghelp(self) -> ctypes.WinDLL | None:
        """Read-only handle to dbghelp.dll loaded during initialization.

        Returns:
            ctypes.WinDLL | None: dbghelp DLL handle or None if not loaded.
        """
        return self._dbghelp

    @property
    def debug_privilege_enabled(self) -> bool:
        """Read-only flag indicating whether SeDebugPrivilege has been elevated.

        Returns:
            bool: True if the privilege was successfully enabled at initialization.
        """
        return self._debug_privilege_enabled

    @property
    def attached_pid(self) -> int | None:
        """Read-only currently attached process identifier.

        Returns:
            int | None: PID of the attached process or None if not attached.
        """
        return self._attached_pid

    @property
    def process_handle(self) -> int | None:
        """Read-only handle to the currently attached process.

        Returns:
            int | None: Process handle value or None if not attached.
        """
        return self._process_handle

    @property
    def pipe_handles(self) -> dict[int, str]:
        """Read-only view of tracked named-pipe handles.

        Returns:
            dict[int, str]: Mapping of open pipe handles to their pipe names.
        """
        return self._pipe_handles

    @property
    def device_handles(self) -> dict[int, str]:
        """Read-only view of tracked device handles.

        Returns:
            dict[int, str]: Mapping of open device handles to their device paths.
        """
        return self._device_handles

    @property
    def section_views(self) -> dict[int, int]:
        """Read-only view of tracked mapped section views.

        Returns:
            dict[int, int]: Mapping of mapped base addresses to section handles.
        """
        return self._section_views

    @property
    def section_handles(self) -> dict[int, str]:
        """Read-only view of tracked section handles.

        Returns:
            dict[int, str]: Mapping of section handles to section names.
        """
        return self._section_handles

    async def initialize(self, tool_path: Path | None = None) -> None:
        """Initialize the process bridge and load DLL references.

        Loads kernel32, psapi, ntdll, advapi32, user32, and dbghelp.
        Attempts to enable SeDebugPrivilege for elevated access.

        Args:
            tool_path: Not used for process bridge.
        """
        del tool_path
        try:
            self._kernel32 = ctypes.windll.kernel32
            self._psapi = ctypes.windll.psapi
            try:
                self._ntdll = get_ntdll()
            except OSError:
                _logger.exception("ntdll_load_failed")
            try:
                self._advapi32 = get_advapi32()
            except OSError:
                _logger.exception("advapi32_load_failed")
            try:
                self._user32 = get_user32()
            except OSError:
                _logger.exception("user32_load_failed")
            try:
                self._dbghelp = get_dbghelp()
            except OSError:
                _logger.exception("dbghelp_load_failed")

            try:
                self._elevate_debug_privilege()
            except ToolError:
                _logger.debug("se_debug_privilege_skipped")

            self.state = BridgeState(
                connected=True,
                tool_running=True,
                binary_loaded=False,
                process_attached=False,
                target_path=None,
                target_pid=None,
                last_error=None,
            )
            _logger.debug("process_bridge_initialized", bridge="process", debug_privilege=self._debug_privilege_enabled)
        except (AttributeError, OSError, RuntimeError) as e:
            _logger.exception("process_bridge_init_failed", bridge="process")
            self.state = BridgeState(
                connected=False,
                tool_running=False,
                binary_loaded=False,
                process_attached=False,
                target_path=None,
                target_pid=None,
                last_error=str(e),
            )

    def _elevate_debug_privilege(self) -> None:
        """Attempt to enable SeDebugPrivilege on the current process token.

        Uses a ``use_last_error=True`` advapi32 handle so that
        ``ctypes.get_last_error()`` faithfully reflects the Win32 last-error
        set by ``AdjustTokenPrivileges``.  Logs and raises ``ToolError`` when
        privilege adjustment fails.

        Raises:
            ToolError: If ``AdjustTokenPrivileges`` returns FALSE or sets
                ``ERROR_NOT_ALL_ASSIGNED`` for the requested privilege.
        """
        if self._kernel32 is None:
            return

        try:
            advapi32_le: ctypes.WinDLL = ctypes.WinDLL("advapi32", use_last_error=True)

            advapi32_le.OpenProcessToken.restype = wintypes.BOOL
            advapi32_le.OpenProcessToken.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.HANDLE),
            ]
            advapi32_le.LookupPrivilegeValueW.restype = wintypes.BOOL
            advapi32_le.LookupPrivilegeValueW.argtypes = [
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                ctypes.c_void_p,
            ]
            advapi32_le.AdjustTokenPrivileges.restype = wintypes.BOOL
            advapi32_le.AdjustTokenPrivileges.argtypes = [
                wintypes.HANDLE,
                wintypes.BOOL,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.c_void_p,
                ctypes.c_void_p,
            ]

            self._kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            token_handle = wintypes.HANDLE()
            current_process: wintypes.HANDLE = self._kernel32.GetCurrentProcess()
            if not advapi32_le.OpenProcessToken(
                current_process,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                ctypes.byref(token_handle),
            ):
                return

            try:
                luid = LUID()
                if not advapi32_le.LookupPrivilegeValueW(
                    None,
                    "SeDebugPrivilege",
                    ctypes.byref(luid),
                ):
                    return

                tp = TOKEN_PRIVILEGES()
                tp.PrivilegeCount = 1
                tp.Privileges[0].Luid = luid
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

                disable_all_privileges = wintypes.BOOL(0)
                adjust_result: int = advapi32_le.AdjustTokenPrivileges(
                    token_handle,
                    disable_all_privileges,
                    ctypes.byref(tp),
                    ctypes.sizeof(TOKEN_PRIVILEGES),
                    None,
                    None,
                )

                last_error = ctypes.get_last_error()

                if not adjust_result or last_error == ERROR_NOT_ALL_ASSIGNED:
                    _logger.debug(
                        "se_debug_privilege_not_granted",
                        adjust_result=adjust_result,
                        last_error=last_error,
                    )
                    msg = f"SeDebugPrivilege not granted: adjust_result={adjust_result} last_error={last_error}"
                    raise ToolError(msg)

                self._debug_privilege_enabled = True
                _logger.debug("se_debug_privilege_enabled")
            finally:
                self._kernel32.CloseHandle(token_handle)
        except ToolError:
            raise
        except (OSError, AttributeError, ctypes.ArgumentError):
            _logger.exception("se_debug_privilege_elevation_failed")

    async def shutdown(self) -> None:
        """Shutdown and cleanup resources.

        Releases every Win32 handle the bridge tracked during the
        session before dropping references to the loaded DLLs:

        * Each mapped section view is unmapped through
          :meth:`unmap_section`, which also releases the underlying
          section handle.
        * Any section handles that were created but never mapped (or
          whose view-tracking entry was already cleared) are closed
          directly via ``CloseHandle``.
        * Pipe handles in :attr:`_pipe_handles` and device handles in
          :attr:`_device_handles` are closed with ``CloseHandle`` and
          purged from the tracking dicts.
        * Finally, the attached process handle is released via
          :meth:`close` and the cached DLL handles are cleared so the
          bridge can be re-initialized cleanly.
        """
        for base_address in list(self._section_views):
            try:
                await self.unmap_section(base_address)
            except ToolError:
                _logger.debug("shutdown_unmap_section_failed", base_address=hex(base_address))

        if self._kernel32 is not None:
            close_handle = getattr(self._kernel32, "CloseHandle", None)
            if close_handle is not None:
                close_handle.argtypes = [wintypes.HANDLE]
                close_handle.restype = wintypes.BOOL
                for handle in list(self._section_handles):
                    close_handle(handle)
                for handle in list(self._pipe_handles):
                    close_handle(handle)
                for handle in list(self._device_handles):
                    close_handle(handle)

        self._section_handles.clear()
        self._section_views.clear()
        self._pipe_handles.clear()
        self._device_handles.clear()

        await self.close()
        self._kernel32 = None
        self._psapi = None
        self._ntdll = None
        self._advapi32 = None
        self._user32 = None
        self._dbghelp = None
        await super().shutdown()
        _logger.info("process_bridge_shutdown", bridge="process")

    @override
    async def is_available(self) -> bool:
        """Check if process bridge is available.

        Returns:
            bool: True on Windows systems.
        """
        try:
            _ = ctypes.windll.kernel32
        except AttributeError as e:
            _logger.debug("kernel32_check_failed", error=str(e))
            return False
        else:
            return True

    # ------------------------------------------------------------------
    # Process listing and management
    # ------------------------------------------------------------------

    async def list(
        self,
        filter_name: str | None = None,
    ) -> list[ProcessInfo]:
        """List all running processes (ToolRegistry dispatch alias).

        Dispatch shim that maps the LLM-visible ``process.list`` tool
        function onto :meth:`list_processes` so the orchestrator's
        ``getattr(bridge, attr_name)`` lookup resolves the attribute
        after the tool-name prefix is stripped.

        Args:
            filter_name: Optional name filter.

        Returns:
            list[ProcessInfo]: List of processes.
        """
        return await self.list_processes(filter_name)

    async def list_detailed(
        self,
        filter_name: str | None = None,
    ) -> list[dict[str, int | str | float]]:
        """List processes with architecture, memory, and thread count.

        Dispatch shim for the LLM-visible ``process.list_detailed`` tool
        function. Delegates to :meth:`list_processes_detailed`.

        Args:
            filter_name: Optional name filter.

        Returns:
            list[dict[str, int | str | float]]: Process detail dicts.
        """
        return await self.list_processes_detailed(filter_name)

    async def open(
        self,
        pid: int,
        access: ProcessAccessRights = "all",
    ) -> bool:
        """Open a process handle (ToolRegistry dispatch alias).

        Dispatch shim for the LLM-visible ``process.open`` tool function.
        Delegates to :meth:`open_process`.

        Args:
            pid: Process ID.
            access: Access rights required.

        Returns:
            bool: True if successful.
        """
        return await self.open_process(pid, access)

    async def list_processes(
        self,
        filter_name: str | None = None,
    ) -> list[ProcessInfo]:
        """List all running processes.

        Args:
            filter_name: Optional name filter.

        Returns:
            list[ProcessInfo]: List of processes.

        Raises:
            ToolError: If enumeration fails.
        """
        _logger.debug("processes_listing", filter_name=filter_name)
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        self._kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        snapshot: int = self._kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot == INVALID_HANDLE_VALUE:
            raise ToolError(_ERR_SNAPSHOT_FAILED)

        processes: list[ProcessInfo] = []
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

        try:
            if not self._kernel32.Process32First(snapshot, ctypes.byref(entry)):
                error_code: int = ctypes.get_last_error()
                if error_code != _ERROR_NO_MORE_FILES:
                    msg = _ERR_SNAPSHOT_FAILED + f" (Process32First: {error_code})"
                    raise ToolError(msg)
                return processes
            while True:
                name = entry.szExeFile.decode("utf-8", errors="ignore")
                if filter_name is None or filter_name.lower() in name.lower():
                    processes.append(
                        ProcessInfo(
                            pid=entry.th32ProcessID,
                            name=name,
                            path=None,
                            command_line=None,
                            parent_pid=entry.th32ParentProcessID,
                            threads=[],
                            modules=[],
                        ),
                    )
                if not self._kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                    break
        finally:
            self._kernel32.CloseHandle(snapshot)

        return processes

    async def list_processes_detailed(
        self,
        filter_name: str | None = None,
    ) -> list[dict[str, int | str | float]]:
        """List processes with architecture, memory, and thread count.

        Batch method to avoid N+1 queries in the GUI process list.

        Args:
            filter_name: Optional name filter.

        Returns:
            list[dict[str, int | str | float]]: List of process detail dicts.

        Raises:
            ToolError: If enumeration fails.
        """
        _logger.debug("process_list_processes_detailed_started", filter_name=filter_name)
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="list_processes_detailed")
            raise ToolError(_ERR_KERNEL32_NA)

        self._kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        snapshot: int = self._kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot == INVALID_HANDLE_VALUE:
            raise ToolError(_ERR_SNAPSHOT_FAILED)

        results: list[dict[str, int | str | float]] = []
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

        try:
            if self._kernel32.Process32First(snapshot, ctypes.byref(entry)):
                while True:
                    name = entry.szExeFile.decode("utf-8", errors="ignore")
                    pid = entry.th32ProcessID
                    if filter_name is None or filter_name.lower() in name.lower():
                        arch = await self.detect_architecture(pid)
                        mem_mb = await self.get_process_memory_mb(pid)
                        results.append({
                            "pid": pid,
                            "name": name,
                            "parent_pid": entry.th32ParentProcessID,
                            "thread_count": entry.cntThreads,
                            "architecture": arch,
                            "memory_mb": round(mem_mb, 1),
                        })
                    if not self._kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                        break
        finally:
            self._kernel32.CloseHandle(snapshot)

        return results

    async def get_process_memory_mb(self, pid: int) -> float:
        """Get working set memory size for a process in megabytes.

        Args:
            pid: Process ID.

        Returns:
            float: Working set size in MB, or 0.0 on failure.
        """
        _logger.debug("process_get_memory_mb_started", pid=pid)
        if self._kernel32 is None or self._psapi is None:
            return 0.0

        inherit_handle = False
        handle = self._kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            inherit_handle,
            pid,
        )
        if not handle:
            return 0.0

        try:
            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            if self._psapi.GetProcessMemoryInfo(
                handle,
                ctypes.byref(counters),
                counters.cb,
            ):
                return counters.WorkingSetSize / _MB_DIVISOR
        finally:
            self._kernel32.CloseHandle(handle)

        return 0.0

    async def detect_architecture(self, pid: int) -> str:
        """Detect whether a process is 32-bit or 64-bit.

        Uses ``IsWow64Process2`` when available for accurate architecture
        identification on modern Windows (distinguishes x86, x86_64, ARM,
        and ARM64 native / emulated combinations). Falls back to parsing
        the PE header Machine field of the main module when the Win32
        call reports ``IMAGE_FILE_MACHINE_UNKNOWN``, and finally to the
        legacy ``IsWow64Process`` + pointer-size heuristic. Architecture
        names follow the canonical convention shared with
        :class:`GhidraBridge` and the orchestrator.

        Args:
            pid: Process ID.

        Returns:
            str: Architecture string such as ``'x86_64'``, ``'x86'``,
                ``'arm64'``, ``'arm'``, or ``'Unknown'``.
        """
        _logger.debug("process_detect_architecture_started", pid=pid)
        if self._kernel32 is None:
            return "Unknown"

        inherit_handle = False
        handle = self._kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, inherit_handle, pid)
        if not handle:
            handle = self._kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, inherit_handle, pid)
            if not handle:
                return "Unknown"

        try:
            arch = self._detect_arch_via_iswow64process2(handle)
            if arch is not None and arch != "Unknown":
                return arch

            pe_arch = self._detect_arch_via_pe_header(pid)
            if pe_arch is not None:
                return pe_arch

            return self._detect_arch_via_iswow64process(handle)
        finally:
            self._kernel32.CloseHandle(handle)

    def _call_iswow64process2(self, handle: int) -> tuple[int, int] | None:
        """Invoke the Win10+ ``IsWow64Process2`` API with prepared argtypes.

        Shared helper for every caller that needs the
        ``(process_machine, native_machine)`` pair. Returns ``None`` on
        OSes that predate ``IsWow64Process2`` or if the call itself
        fails so callers can branch into their legacy fallbacks without
        each re-declaring the argtypes / restype block.

        Args:
            handle: Open process handle with at least
                ``PROCESS_QUERY_LIMITED_INFORMATION`` access.

        Returns:
            tuple[int, int] | None: ``(process_machine, native_machine)``
                as ``IMAGE_FILE_MACHINE_*`` values, or ``None`` on
                failure / unavailability.
        """
        if self._kernel32 is None:
            return None

        is_wow64_process2 = getattr(self._kernel32, "IsWow64Process2", None)
        if is_wow64_process2 is None:
            return None

        is_wow64_process2.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.USHORT),
            ctypes.POINTER(wintypes.USHORT),
        ]
        is_wow64_process2.restype = wintypes.BOOL

        process_machine = wintypes.USHORT(0)
        native_machine = wintypes.USHORT(0)
        if not is_wow64_process2(
            handle,
            ctypes.byref(process_machine),
            ctypes.byref(native_machine),
        ):
            return None

        return process_machine.value, native_machine.value

    def _detect_arch_via_iswow64process2(self, handle: int) -> str | None:
        """Detect architecture using the Win10+ ``IsWow64Process2`` API.

        Args:
            handle: Open process handle with at least
                ``PROCESS_QUERY_LIMITED_INFORMATION`` access.

        Returns:
            str | None: Architecture string, ``'Unknown'`` if the API
                reports an unknown machine, or ``None`` if the API is not
                available on this Windows build.
        """
        result = self._call_iswow64process2(handle)
        if result is None:
            return None

        process_machine, native_machine = result
        if process_machine == IMAGE_FILE_MACHINE_UNKNOWN:
            native = self._machine_to_arch_string(native_machine)
            if native == "Unknown":
                return "Unknown"
            return native

        return self._machine_to_arch_string(process_machine)

    @staticmethod
    def _machine_to_arch_string(machine: int) -> str:
        """Translate an ``IMAGE_FILE_MACHINE_*`` value to an arch string.

        Delegates to :func:`pe_machine_to_arch` for the canonical
        ``(arch, is_64bit)`` mapping and returns just the arch name.
        Unknown machine values become ``'Unknown'`` (capitalised) to
        match the contract documented on
        :meth:`detect_architecture`.

        Args:
            machine: Win32 ``IMAGE_FILE_MACHINE_*`` constant value.

        Returns:
            str: Architecture string like ``'x86_64'``, ``'x86'``,
                ``'arm64'``, ``'arm'``, ``'ia64'``, ``'mips'``,
                ``'ppc'``, ``'riscv'``, ``'riscv64'``, ``'riscv128'``,
                or ``'Unknown'``.
        """
        arch, _is_64bit = pe_machine_to_arch(machine)
        if arch == "unknown":
            return "Unknown"
        return arch

    def _detect_arch_via_pe_header(self, pid: int) -> str | None:
        """Detect architecture by parsing the PE header of the main module.

        Reads the DOS header, PE signature, and COFF file header machine
        field of the process's primary image. This fallback is used when
        ``IsWow64Process2`` reports ``IMAGE_FILE_MACHINE_UNKNOWN`` or is
        unavailable on the host OS.

        Args:
            pid: Process ID to inspect.

        Returns:
            str | None: Architecture string or ``None`` if the PE header
                could not be located and parsed.
        """
        if self._kernel32 is None or self._psapi is None:
            return None

        access_rights = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        inherit_handle = False
        read_handle = self._kernel32.OpenProcess(access_rights, inherit_handle, pid)
        if not read_handle:
            return None

        try:
            module_handle = wintypes.HMODULE()
            bytes_needed = wintypes.DWORD(0)
            if not self._psapi.EnumProcessModules(
                read_handle,
                ctypes.byref(module_handle),
                ctypes.sizeof(wintypes.HMODULE),
                ctypes.byref(bytes_needed),
            ):
                return None

            base = ctypes.cast(module_handle, ctypes.c_void_p).value or 0
            if base == 0:
                return None

            dos_header = ctypes.create_string_buffer(0x40)
            bytes_read = ctypes.c_size_t()
            if not self._kernel32.ReadProcessMemory(
                read_handle,
                ctypes.c_void_p(base),
                dos_header,
                0x40,
                ctypes.byref(bytes_read),
            ):
                return None

            if detect_format(dos_header.raw) != "pe":
                return None

            pe_offset = struct.unpack_from("<I", dos_header.raw, PE_DOS_LFANEW_OFFSET)[0]

            header_buffer = ctypes.create_string_buffer(_PE_SIGNATURE_SIZE + 0x14)
            if not self._kernel32.ReadProcessMemory(
                read_handle,
                ctypes.c_void_p(base + pe_offset),
                header_buffer,
                _PE_SIGNATURE_SIZE + 0x14,
                ctypes.byref(bytes_read),
            ):
                return None

            if header_buffer.raw[:_PE_SIGNATURE_SIZE] != PE_SIGNATURE:
                return None

            machine = struct.unpack_from(
                "<H",
                header_buffer.raw,
                _PE_SIGNATURE_SIZE,
            )[0]
            arch = self._machine_to_arch_string(machine)
            return arch if arch != "Unknown" else None
        finally:
            self._kernel32.CloseHandle(read_handle)

    def _detect_arch_via_iswow64process(self, handle: int) -> str:
        """Legacy architecture detection via ``IsWow64Process``.

        Args:
            handle: Open process handle with
                ``PROCESS_QUERY_(LIMITED_)INFORMATION`` access.

        Returns:
            str: ``'x86'`` if the target runs under WOW64, else the
                architecture matching the host's pointer size, or
                ``'Unknown'`` if the API is unavailable.
        """
        if self._kernel32 is None:
            return "Unknown"

        is_wow64 = wintypes.BOOL(0)
        if hasattr(self._kernel32, "IsWow64Process"):
            self._kernel32.IsWow64Process(handle, ctypes.byref(is_wow64))
            if is_wow64.value:
                return "x86"

        pointer_bits = struct.calcsize("P") * _BITS_PER_BYTE
        return "x86_64" if pointer_bits == _POINTER_BITS_64 else "x86"

    async def open_process(
        self,
        pid: int,
        access: ProcessAccessRights = "all",
    ) -> bool:
        """Open a process handle.

        Args:
            pid: Process ID.
            access: Access rights required.

        Returns:
            bool: True if successful.

        Raises:
            ToolError: If open fails.
        """
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        await self.close()

        access_map: dict[str, int] = {
            "all": PROCESS_ALL_ACCESS,
            "query": PROCESS_QUERY_INFORMATION,
            "read": PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            "write": PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            "terminate": PROCESS_TERMINATE,
            "suspend": PROCESS_SUSPEND_RESUME,
        }

        access_rights = access_map.get(access, PROCESS_ALL_ACCESS)
        inherit_handle = False
        handle = self._kernel32.OpenProcess(access_rights, inherit_handle, pid)

        if not handle:
            raise ToolError(_ERR_OPEN_FAILED)

        self._attached_pid = pid
        self._process_handle = handle

        self.state.connected = True
        self.state.tool_running = True
        self.state.process_attached = True
        self.state.target_pid = pid

        _logger.info("process_opened", pid=pid, access=access)
        return True

    async def close(self) -> bool:
        """Close the current process handle.

        Returns:
            bool: True if closed.
        """
        if self._process_handle is not None and self._kernel32 is not None:
            self._kernel32.CloseHandle(self._process_handle)
            self._process_handle = None
            self._attached_pid = None
            _logger.info("process_handle_closed", bridge="process")

        self.state.connected = True
        self.state.tool_running = True
        self.state.process_attached = False
        self.state.target_pid = None

        return True

    async def terminate(self, pid: int | None = None) -> bool:
        """Terminate a process.

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            bool: True if terminated.

        Raises:
            ToolError: If termination fails.
        """
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        if pid is not None:
            inherit_handle = False
            handle = self._kernel32.OpenProcess(PROCESS_TERMINATE, inherit_handle, pid)
            if not handle:
                raise ToolError(_ERR_OPEN_FAILED)
            close_handle = True
        else:
            if self._process_handle is None:
                raise ToolError(_ERR_NOT_ATTACHED)
            handle = self._process_handle
            close_handle = False

        result = self._kernel32.TerminateProcess(handle, 1)
        if not result:
            if close_handle:
                self._kernel32.CloseHandle(handle)
            _logger.warning("process_terminate_failed", pid=pid or self._attached_pid)
            raise ToolError(_ERR_TERMINATE_FAILED)

        _logger.info("process_terminated", pid=pid or self._attached_pid)
        if close_handle:
            self._kernel32.CloseHandle(handle)
        else:
            await self.close()
        return True

    async def suspend(self, pid: int | None = None) -> bool:
        """Suspend all threads of a process.

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            bool: True if suspended.

        Raises:
            ToolError: If suspension fails.
        """
        target_pid = pid or self._attached_pid
        if target_pid is None:
            raise ToolError(_ERR_NO_PROCESS)

        threads = await self.get_threads(target_pid)

        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        failed_tids: list[int] = []
        for thread in threads:
            inherit_handle = False
            th_handle: int = self._kernel32.OpenThread(THREAD_SUSPEND_RESUME, inherit_handle, thread.tid)
            if not th_handle:
                failed_tids.append(thread.tid)
                continue
            suspend_result: int = self._kernel32.SuspendThread(th_handle)
            if suspend_result == _THREAD_OP_FAILURE_SENTINEL:
                failed_tids.append(thread.tid)
            self._kernel32.CloseHandle(th_handle)

        if failed_tids:
            _logger.warning("process_suspend_partial_failure", pid=target_pid, failed_tids=failed_tids)
            msg = f"suspend failed for thread IDs: {failed_tids}"
            raise ToolError(msg)

        _logger.info("process_suspended", pid=target_pid, thread_count=len(threads))
        return True

    async def resume(self, pid: int | None = None) -> bool:
        """Resume all threads of a process.

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            bool: True if resumed.

        Raises:
            ToolError: If resume fails.
        """
        target_pid = pid or self._attached_pid
        if target_pid is None:
            raise ToolError(_ERR_NO_PROCESS)

        threads = await self.get_threads(target_pid)

        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        failed_tids: list[int] = []
        for thread in threads:
            inherit_handle = False
            th_handle: int = self._kernel32.OpenThread(THREAD_SUSPEND_RESUME, inherit_handle, thread.tid)
            if not th_handle:
                failed_tids.append(thread.tid)
                continue
            resume_result: int = self._kernel32.ResumeThread(th_handle)
            if resume_result == _THREAD_OP_FAILURE_SENTINEL:
                failed_tids.append(thread.tid)
            self._kernel32.CloseHandle(th_handle)

        if failed_tids:
            _logger.warning("process_resume_partial_failure", pid=target_pid, failed_tids=failed_tids)
            msg = f"resume failed for thread IDs: {failed_tids}"
            raise ToolError(msg)

        _logger.info("process_resumed", pid=target_pid, thread_count=len(threads))
        return True

    # ------------------------------------------------------------------
    # Memory operations
    # ------------------------------------------------------------------

    async def read_memory(self, address: int, size: int) -> str:
        """Read memory from process and return it as a hex string.

        The hex-string return type matches the tool definition advertised
        to LLM consumers (``returns="Hex string of memory contents"``)
        and keeps the value JSON-serialisable when the orchestrator
        forwards bridge results to model providers. Internal callers that
        need raw bytes should call :meth:`_sync_read_memory` instead.

        Args:
            address: Memory address.
            size: Bytes to read.

        Returns:
            str: Hex-encoded memory contents (lowercase, no separators).

        Raises:
            ToolError: If read fails.
        """
        if self._process_handle is None:
            raise ToolError(_ERR_NOT_ATTACHED)
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)
        _logger.debug("memory_read_starting", address=hex(address), size=size)
        return self._sync_read_memory(address, size).hex()

    async def write_memory(self, address: int, data: bytes) -> int:
        """Write memory to process.

        Args:
            address: Memory address.
            data: Bytes to write.

        Returns:
            int: Bytes written.

        Raises:
            ToolError: If write fails.
        """
        if self._process_handle is None:
            raise ToolError(_ERR_NOT_ATTACHED)
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        bytes_written = ctypes.c_size_t()
        result = self._kernel32.WriteProcessMemory(
            self._process_handle,
            ctypes.c_void_p(address),
            data,
            len(data),
            ctypes.byref(bytes_written),
        )

        if not result:
            raise ToolError(_ERR_WRITE_FAILED)

        _logger.info("memory_written", bytes_written=bytes_written.value, address=hex(address))
        return bytes_written.value

    async def allocate(self, size: int, protection: str = "rwx") -> int:
        """Allocate memory in process.

        Args:
            size: Size to allocate.
            protection: Memory protection string.

        Returns:
            int: Allocated address.

        Raises:
            ToolError: If allocation fails.
        """
        if self._process_handle is None:
            raise ToolError(_ERR_NOT_ATTACHED)
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        prot = self._prot_from_string(protection)
        address: int = cast(
            "int",
            self._kernel32.VirtualAllocEx(
                self._process_handle,
                0,
                size,
                MEM_COMMIT | MEM_RESERVE,
                prot,
            ),
        )

        if not address:
            raise ToolError(_ERR_ALLOC_FAILED)

        _logger.info("memory_allocated", size=size, address=hex(address), protection=protection)
        return address

    async def free(self, address: int) -> bool:
        """Free allocated memory.

        Args:
            address: Address to free.

        Returns:
            bool: True if freed.

        Raises:
            ToolError: If free fails.
        """
        if self._process_handle is None:
            raise ToolError(_ERR_NOT_ATTACHED)
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        result = self._kernel32.VirtualFreeEx(
            self._process_handle,
            address,
            0,
            MEM_RELEASE,
        )

        if not result:
            raise ToolError(_ERR_FREE_FAILED)

        _logger.info("memory_freed", address=hex(address))
        return True

    async def protect(self, address: int, size: int, protection: str) -> str:
        """Change memory protection.

        Args:
            address: Memory address.
            size: Region size.
            protection: New protection.

        Returns:
            str: Previous protection.

        Raises:
            ToolError: If operation fails.
        """
        if self._process_handle is None:
            raise ToolError(_ERR_NOT_ATTACHED)
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        new_prot = self._prot_from_string(protection)
        old_prot = wintypes.DWORD()

        result = self._kernel32.VirtualProtectEx(
            self._process_handle,
            ctypes.c_void_p(address),
            size,
            new_prot,
            ctypes.byref(old_prot),
        )

        if not result:
            raise ToolError(_ERR_PROTECT_FAILED)

        old_flags = decode_protection(old_prot.value)
        old_prot_str = protection_to_string(old_prot.value)
        _logger.info(
            "memory_protection_changed",
            address=hex(address),
            old_protection=old_prot_str,
            old_read=old_flags["read"],
            old_write=old_flags["write"],
            old_execute=old_flags["execute"],
            old_copy_on_write=old_flags["copy_on_write"],
            old_guard=old_flags["guard"],
            old_raw=hex(old_flags["raw"]),
            new_protection=protection,
        )
        return old_prot_str

    async def get_memory_map(self, *, resolve_names: bool = False) -> list[MemoryRegion]:
        """Get process memory map.

        Args:
            resolve_names: If True, resolve mapped file names for MEM_MAPPED/MEM_IMAGE regions.

        Returns:
            list[MemoryRegion]: List of memory regions.

        Raises:
            ToolError: If operation fails.
        """
        _logger.debug("memory_map_reading")
        if self._process_handle is None:
            raise ToolError(_ERR_NOT_ATTACHED)
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        regions: list[MemoryRegion] = []
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()

        while True:
            result = self._kernel32.VirtualQueryEx(
                self._process_handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )

            if result == 0:
                break

            if mbi.State == MEM_COMMIT:
                module_name: str | None = None
                if resolve_names and self._psapi is not None and mbi.Type in {MEM_MAPPED, MEM_IMAGE}:
                    name_buf = ctypes.create_unicode_buffer(260)
                    name_len: int = self._psapi.GetMappedFileNameW(
                        self._process_handle,
                        ctypes.c_void_p(mbi.BaseAddress or 0),
                        name_buf,
                        260,
                    )
                    if name_len > 0:
                        module_name = name_buf.value

                regions.append(
                    MemoryRegion(
                        base_address=mbi.BaseAddress or 0,
                        size=mbi.RegionSize,
                        protection=protection_to_string(mbi.Protect),
                        state=state_to_string(mbi.State),
                        type=mem_type_to_string(mbi.Type),
                        module_name=module_name,
                    ),
                )

            address = (mbi.BaseAddress or 0) + mbi.RegionSize
            if address > _MAX_MEMORY_ADDRESS:
                break

        return regions

    async def search_pattern(
        self,
        pattern: str,
        start_address: int | None = None,
        end_address: int | None = None,
    ) -> list[int]:
        """Search for byte pattern in memory.

        Scans each readable memory region in chunks of
        ``_SEARCH_CHUNK_SIZE`` bytes. Each subsequent chunk overlaps the
        previous one by ``len(pattern) - 1`` bytes so matches that
        straddle chunk boundaries are still detected.

        Args:
            pattern: Hex pattern with wildcards (e.g., "48 8B ?? ??").
            start_address: Optional start address.
            end_address: Optional end address.

        Returns:
            list[int]: List of matching addresses.
        """
        _logger.debug("pattern_search_starting", pattern=pattern)
        pattern_bytes: list[int | None] = []

        for part in pattern.split():
            if part in _WILDCARD_PATTERNS:
                pattern_bytes.append(None)
            else:
                pattern_bytes.append(int(part, 16))

        pattern_len = len(pattern_bytes)
        if pattern_len == 0:
            return []

        regions = await self.get_memory_map()
        matches: list[int] = []
        overlap = pattern_len - 1

        for region in regions:
            if "r" not in region.protection:
                continue
            if start_address and region.base_address + region.size < start_address:
                continue
            if end_address and region.base_address > end_address:
                continue

            scan_base = region.base_address
            scan_end = region.base_address + region.size
            if start_address is not None and start_address > scan_base:
                scan_base = start_address
            if end_address is not None and end_address < scan_end:
                scan_end = end_address

            scan_size = scan_end - scan_base
            if scan_size < pattern_len:
                continue

            self._scan_region_pattern(
                scan_base,
                scan_size,
                pattern_bytes,
                overlap,
                matches,
            )

        return matches

    def _scan_region_pattern(
        self,
        region_base: int,
        region_size: int,
        pattern_bytes: list[int | None],
        overlap: int,
        matches: list[int],
    ) -> None:
        """Chunk-scan a single region for a pattern, preserving overlap.

        On a chunk read failure the scan logs at debug level and continues
        with the next chunk so a single transient failure (e.g., a guard
        page or page-not-resident error) does not abort the entire region.
        The scan only aborts early if a re-issued ``VirtualQueryEx``
        observes the region is no longer committed (e.g., freed or
        decommitted mid-scan).

        Args:
            region_base: Base virtual address of the region to scan.
            region_size: Size of the region in bytes.
            pattern_bytes: Pattern byte list; ``None`` entries are
                wildcards that match any byte value.
            overlap: Number of bytes of overlap between adjacent chunks
                (should be ``len(pattern_bytes) - 1``).
            matches: Mutable list to which absolute match addresses are
                appended.
        """
        pattern_len = len(pattern_bytes)
        offset = 0
        step = max(1, _SEARCH_CHUNK_SIZE - overlap)

        while offset < region_size:
            chunk_size = min(_SEARCH_CHUNK_SIZE, region_size - offset)
            if chunk_size < pattern_len:
                break

            chunk_address = region_base + offset
            try:
                data_bytes = self._sync_read_memory(chunk_address, chunk_size)
            except (ToolError, OSError) as exc:
                _logger.debug(
                    "pattern_search_chunk_read_failed",
                    address=hex(chunk_address),
                    size=chunk_size,
                    error=str(exc),
                )
                if not self._region_still_committed(chunk_address):
                    _logger.debug(
                        "pattern_search_region_freed",
                        address=hex(chunk_address),
                    )
                    break
                offset += step
                continue

            limit = len(data_bytes) - pattern_len + 1
            for i in range(limit):
                match = not any(pb is not None and data_bytes[i + j] != pb for j, pb in enumerate(pattern_bytes))
                if match:
                    matches.append(chunk_address + i)

            if chunk_size < _SEARCH_CHUNK_SIZE:
                break

            offset += chunk_size - overlap

    def _region_still_committed(self, address: int) -> bool:
        """Re-query a virtual address to confirm it is still committed.

        Used by chunked scanners to distinguish a transient per-chunk read
        failure (which should not abort the scan) from a region that was
        freed or decommitted mid-scan (which must abort the scan).

        Args:
            address: Virtual address inside the region of interest.

        Returns:
            bool: True if ``VirtualQueryEx`` succeeds and reports
                ``State == MEM_COMMIT`` for ``address``; False if the
                query fails or the region is no longer committed.
        """
        if self._kernel32 is None or self._process_handle is None:
            return False
        mbi = MEMORY_BASIC_INFORMATION()
        result = self._kernel32.VirtualQueryEx(
            self._process_handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )
        if result == 0:
            return False
        return mbi.State == MEM_COMMIT

    def _sync_read_memory(self, address: int, size: int) -> bytes:
        """Read process memory synchronously via ``ReadProcessMemory``.

        Mirror of the async :meth:`read_memory` coroutine used by
        synchronous scan loops that cannot ``await`` inside a nested
        per-chunk iteration. Performs the same handle / kernel32
        availability validation and raises the same ``ToolError`` codes.

        Args:
            address: Virtual memory address to read from.
            size: Number of bytes to read.

        Returns:
            bytes: The bytes actually read (may be shorter than ``size``
                if the kernel returned a truncated read).

        Raises:
            ToolError: If no process is attached, kernel32 is not
                available, or the underlying ``ReadProcessMemory`` call
                fails.
        """
        if self._process_handle is None:
            _logger.error("process_not_attached", operation="_sync_read_memory")
            raise ToolError(_ERR_NOT_ATTACHED)
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="_sync_read_memory")
            raise ToolError(_ERR_KERNEL32_NA)

        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t()

        if self._kernel32.ReadProcessMemory(
            self._process_handle,
            ctypes.c_void_p(address),
            buffer,
            size,
            ctypes.byref(bytes_read),
        ):
            return buffer.raw[: bytes_read.value]
        _logger.error(
            "process_memory_read_failed",
            address=hex(address),
            size=size,
        )
        raise ToolError(_ERR_READ_FAILED)

    # ------------------------------------------------------------------
    # Module and thread enumeration
    # ------------------------------------------------------------------

    async def get_modules(self, pid: int | None = None) -> list[ModuleInfo]:
        """Get loaded modules.

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            list[ModuleInfo]: List of modules.

        Raises:
            ToolError: If operation fails.
        """
        _logger.debug("process_get_modules_started", pid=pid)
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="get_modules")
            raise ToolError(_ERR_KERNEL32_NA)

        target_pid = pid or self._attached_pid
        if target_pid is None:
            _logger.error("no_process_specified", operation="get_modules")
            raise ToolError(_ERR_NO_PROCESS)

        self._kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        snapshot: int = self._kernel32.CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            target_pid,
        )

        if snapshot == INVALID_HANDLE_VALUE:
            error_code: int = ctypes.get_last_error()
            _logger.warning("module_snapshot_failed", pid=target_pid, error_code=error_code)
            return []

        modules: list[ModuleInfo] = []
        entry = MODULEENTRY32()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32)

        proc_handle: int | None = None
        if self._psapi is not None:
            inherit_handle = False
            proc_handle = self._kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                inherit_handle,
                target_pid,
            )
            if not proc_handle:
                proc_handle = None

        try:
            if self._kernel32.Module32First(snapshot, ctypes.byref(entry)):
                while True:
                    base_addr = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0
                    ep = self._query_module_entry_point(proc_handle, entry.hModule) if proc_handle else 0
                    modules.append(
                        ModuleInfo(
                            name=entry.szModule.decode("utf-8", errors="ignore"),
                            path=Path(entry.szExePath.decode("utf-8", errors="ignore")),
                            base_address=base_addr,
                            size=entry.modBaseSize,
                            entry_point=ep,
                        ),
                    )
                    if not self._kernel32.Module32Next(snapshot, ctypes.byref(entry)):
                        break
        finally:
            self._kernel32.CloseHandle(snapshot)
            if proc_handle:
                self._kernel32.CloseHandle(proc_handle)

        return modules

    async def get_threads(self, pid: int | None = None) -> list[ThreadInfo]:
        """Get process threads with real start address and state.

        Uses NtQueryInformationThread to retrieve the actual Win32
        start address and thread state for each thread, falling back
        to Toolhelp32 defaults if the NT call fails.

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            list[ThreadInfo]: List of threads.

        Raises:
            ToolError: If operation fails.
        """
        _logger.debug("process_get_threads_started", pid=pid)
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="get_threads")
            raise ToolError(_ERR_KERNEL32_NA)

        target_pid = pid or self._attached_pid
        if target_pid is None:
            raise ToolError(_ERR_NO_PROCESS)

        self._kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        snapshot: int = self._kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        if snapshot == INVALID_HANDLE_VALUE:
            error_code: int = ctypes.get_last_error()
            _logger.warning("thread_snapshot_failed", error_code=error_code)
            return []

        threads: list[ThreadInfo] = []
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(THREADENTRY32)

        try:
            if self._kernel32.Thread32First(snapshot, ctypes.byref(entry)):
                while True:
                    if entry.th32OwnerProcessID == target_pid:
                        tid = entry.th32ThreadID
                        start_addr = self._query_thread_start_address(tid)
                        current_pc = self._query_thread_current_pc(tid, owner_pid=target_pid)
                        state = self._query_thread_state(tid)

                        threads.append(
                            ThreadInfo(
                                tid=tid,
                                start_address=start_addr,
                                current_pc=current_pc,
                                state=state,
                            ),
                        )

                    if not self._kernel32.Thread32Next(snapshot, ctypes.byref(entry)):
                        break
        finally:
            self._kernel32.CloseHandle(snapshot)

        return threads

    def _query_thread_start_address(self, tid: int) -> int:
        """Query the Win32 start address of a thread via NtQueryInformationThread.

        Logs a debug record including the negative NTSTATUS (converted to
        its unsigned 32-bit form for readability) when the kernel call
        fails, so diagnostic traces retain the actual error code instead
        of silently degrading to a zero start address.

        Args:
            tid: Thread ID.

        Returns:
            int: Start address, or 0 if query fails.
        """
        if self._ntdll is None or self._kernel32 is None:
            return 0

        inherit_handle = False
        handle = self._kernel32.OpenThread(THREAD_QUERY_INFORMATION, inherit_handle, tid)
        if not handle:
            _logger.debug(
                "thread_start_address_open_failed",
                tid=tid,
                error_code=ctypes.get_last_error(),
            )
            return 0

        try:
            start_address = ctypes.c_void_p(0)
            status: int = self._ntdll.NtQueryInformationThread(
                handle,
                ThreadQuerySetWin32StartAddress,
                ctypes.byref(start_address),
                ctypes.sizeof(start_address),
                None,
            )
            if status >= 0:
                return start_address.value or 0

            _logger.debug(
                "thread_start_address_nt_failed",
                tid=tid,
                ntstatus=hex(status & 0xFFFFFFFF),
                raw_status=status,
            )
        except (OSError, ctypes.ArgumentError) as exc:
            _logger.warning(
                "thread_start_address_query_exception",
                tid=tid,
                error=str(exc),
                error_type=type(exc).__name__,
            )
        finally:
            self._kernel32.CloseHandle(handle)

        return 0

    def _query_thread_state(self, tid: int) -> str:
        """Query the execution state of a thread via NtQueryInformationThread.

        Opens the thread with ``THREAD_QUERY_INFORMATION |
        THREAD_SUSPEND_RESUME`` so the follow-up ``SuspendThread`` /
        ``ResumeThread`` probe that derives the running-vs-suspended
        state actually has the access rights required by Win32. The
        probe applies a signed LONG cast to the ``SuspendThread`` return
        value so the -1 error sentinel is detected instead of being
        treated as a 32-bit unsigned count of 4294967295.

        Args:
            tid: Thread ID.

        Returns:
            str: Thread state string, or 'unknown' if query fails.
        """
        if self._ntdll is None or self._kernel32 is None:
            return "unknown"

        if tid == self._kernel32.GetCurrentThreadId():
            return "running"

        inherit_handle = False
        handle = self._kernel32.OpenThread(
            THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
            inherit_handle,
            tid,
        )
        if not handle:
            return "unknown"

        try:
            tbi = THREAD_BASIC_INFORMATION()
            status: int = self._ntdll.NtQueryInformationThread(
                handle,
                ThreadBasicInformation,
                ctypes.byref(tbi),
                ctypes.sizeof(tbi),
                None,
            )
            if status >= 0:
                if tbi.ExitStatus != _STILL_ACTIVE:
                    return "terminated"

                raw_count: int = self._kernel32.SuspendThread(handle)
                signed_count = ctypes.c_long(raw_count).value
                if signed_count >= 0:
                    try:
                        result = "suspended" if signed_count > 0 else "running"
                    finally:
                        self._kernel32.ResumeThread(handle)
                    return result
        except (OSError, ctypes.ArgumentError):
            pass
        finally:
            self._kernel32.CloseHandle(handle)

        return "unknown"

    def _query_thread_pc_and_state(self, tid: int) -> tuple[int, str]:
        """Query both current_pc and state in a single suspend/resume cycle.

        Opens the thread with the union of rights needed for both
        GetThreadContext and the state probe, performs exactly one
        SuspendThread / ResumeThread pair, reads the instruction pointer
        (Rip on x64, Eip on WOW64/x86) and determines the running-vs-
        suspended state from the prior suspend count.  ResumeThread is
        called in a finally block so the thread is never left suspended.

        Args:
            tid: Thread ID.

        Returns:
            tuple[int, str]: ``(current_pc, state)`` where ``current_pc``
                is 0 when the context read fails and ``state`` is
                ``'unknown'`` when the probe fails.
        """
        if self._ntdll is None or self._kernel32 is None:
            return 0, "unknown"

        current_tid: int = self._kernel32.GetCurrentThreadId()
        if tid == current_tid:
            return 0, "running"

        access = THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT
        inherit_handle = False
        handle = self._kernel32.OpenThread(access, inherit_handle, tid)
        if not handle:
            return 0, "unknown"

        result: tuple[int, str] = (0, "unknown")
        try:
            tbi = THREAD_BASIC_INFORMATION()
            status: int = self._ntdll.NtQueryInformationThread(
                handle,
                ThreadBasicInformation,
                ctypes.byref(tbi),
                ctypes.sizeof(tbi),
                None,
            )
            if status >= 0 and tbi.ExitStatus != _STILL_ACTIVE:
                result = (0, "terminated")
            else:
                raw_count: int = self._kernel32.SuspendThread(handle)
                signed_count = ctypes.c_long(raw_count).value
                if signed_count >= 0:
                    try:
                        state = "suspended" if signed_count > 0 else "running"
                        is_wow64 = self._target_is_wow64()
                        pc: int = 0
                        if is_wow64:
                            wow64_get_ctx = getattr(self._kernel32, "Wow64GetThreadContext", None)
                            if wow64_get_ctx is not None:
                                wow64_get_ctx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
                                wow64_get_ctx.restype = wintypes.BOOL
                                ctx32 = WOW64_CONTEXT()
                                ctx32.ContextFlags = CONTEXT_I386_ALL
                                if wow64_get_ctx(handle, ctypes.byref(ctx32)):
                                    pc = int(ctx32.Eip)
                        else:
                            ctx64 = CONTEXT64()
                            ctx64.ContextFlags = CONTEXT_ALL
                            if self._kernel32.GetThreadContext(handle, ctypes.byref(ctx64)):
                                pc = int(ctx64.Rip)
                        result = (pc, state)
                    finally:
                        self._kernel32.ResumeThread(handle)
        except (OSError, ctypes.ArgumentError):
            pass
        finally:
            self._kernel32.CloseHandle(handle)

        return result

    def _query_module_entry_point(self, proc_handle: int, module_handle: int) -> int:
        """Query the entry point address of a module via GetModuleInformation.

        Args:
            proc_handle: Open process handle with PROCESS_QUERY_INFORMATION
                and PROCESS_VM_READ access.
            module_handle: HMODULE value from MODULEENTRY32.hModule.

        Returns:
            int: Entry point virtual address, or 0 if the query fails.
        """
        if self._psapi is None:
            return 0
        get_module_information = getattr(self._psapi, "GetModuleInformation", None)
        if get_module_information is None:
            return 0
        get_module_information.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.POINTER(_MODULEINFO),
            wintypes.DWORD,
        ]
        get_module_information.restype = wintypes.BOOL
        modinfo = _MODULEINFO()
        if get_module_information(
            proc_handle,
            ctypes.c_void_p(module_handle),
            ctypes.byref(modinfo),
            ctypes.sizeof(modinfo),
        ):
            return int(modinfo.EntryPoint) if modinfo.EntryPoint is not None else 0
        return 0

    def _query_thread_current_pc(self, tid: int, owner_pid: int | None = None) -> int:
        """Query the current program counter of a thread via GetThreadContext.

        Opens the thread with THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
        suspends it, reads Rip (x64) or Eip (x86 / WOW64), then resumes
        in a finally block so the thread is never left suspended on error.

        WOW64 status is determined from ``owner_pid`` when supplied (so the
        correct CONTEXT struct is selected when enumerating threads of a
        process other than the attached one). When ``owner_pid`` is None,
        falls back to the attached-process WOW64 detection.

        Args:
            tid: Thread ID.
            owner_pid: PID that owns this thread. When provided, WOW64
                status is queried for that PID directly (cross-arch safe).

        Returns:
            int: Current instruction pointer, or 0 if the query fails.
        """
        if self._kernel32 is None:
            return 0

        if tid == self._kernel32.GetCurrentThreadId():
            return 0

        inherit_handle = False
        handle = self._kernel32.OpenThread(
            THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
            inherit_handle,
            tid,
        )
        if not handle:
            return 0

        try:
            raw_count: int = self._kernel32.SuspendThread(handle)
            signed_count = ctypes.c_long(raw_count).value
            if signed_count < 0:
                return 0

            try:
                is_wow64 = self._pid_is_wow64(owner_pid) if owner_pid is not None else self._target_is_wow64()
                if is_wow64:
                    wow64_get_ctx = getattr(self._kernel32, "Wow64GetThreadContext", None)
                    if wow64_get_ctx is None:
                        return 0
                    wow64_get_ctx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
                    wow64_get_ctx.restype = wintypes.BOOL
                    ctx32 = WOW64_CONTEXT()
                    ctx32.ContextFlags = CONTEXT_I386_ALL
                    if wow64_get_ctx(handle, ctypes.byref(ctx32)):
                        return int(ctx32.Eip)
                    return 0
                ctx64 = CONTEXT64()
                ctx64.ContextFlags = CONTEXT_ALL
                if self._kernel32.GetThreadContext(handle, ctypes.byref(ctx64)):
                    return int(ctx64.Rip)
                return 0
            finally:
                self._kernel32.ResumeThread(handle)
        except (OSError, ctypes.ArgumentError) as exc:
            _logger.debug(
                "thread_current_pc_query_exception",
                tid=tid,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return 0
        finally:
            self._kernel32.CloseHandle(handle)

    # ------------------------------------------------------------------
    # DLL injection
    # ------------------------------------------------------------------

    async def inject_dll(self, dll_path: str) -> bool:
        """Inject a DLL into the process.

        Args:
            dll_path: Path to DLL file.

        Returns:
            bool: True if injected.

        Raises:
            ToolError: If injection fails.
        """
        _logger.info("dll_injecting", dll_path=dll_path)
        if self._process_handle is None:
            raise ToolError(_ERR_NOT_ATTACHED)
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        dll_path_resolved = await asyncio.to_thread(Path(dll_path).resolve)
        if not await asyncio.to_thread(dll_path_resolved.exists):
            raise ToolError(_ERR_DLL_NOT_FOUND)

        dll_path_utf16 = str(dll_path_resolved).encode("utf-16-le") + b"\x00\x00"
        remote_mem = await self.allocate(len(dll_path_utf16), "rw")

        try:
            await self.write_memory(remote_mem, dll_path_utf16)

            kernel32_handle = self._kernel32.GetModuleHandleW("kernel32.dll")
            if not kernel32_handle:
                raise ToolError(_ERR_KERNEL32_HANDLE)

            load_library_addr = self._kernel32.GetProcAddress(kernel32_handle, b"LoadLibraryW")
            if not load_library_addr:
                raise ToolError(_ERR_LOADLIB_ADDR)

            thread_handle = self._kernel32.CreateRemoteThread(
                self._process_handle,
                None,
                0,
                load_library_addr,
                remote_mem,
                0,
                None,
            )

            if not thread_handle:
                raise ToolError(_ERR_REMOTE_THREAD)

            try:
                wait_result: int = self._kernel32.WaitForSingleObject(thread_handle, 5000)
                if wait_result == WAIT_FAILED:
                    raise ToolError(_ERR_INJECT_WAIT_FAILED)
                if wait_result == WAIT_TIMEOUT:
                    raise ToolError(_ERR_INJECT_TIMEOUT)
                if wait_result != WAIT_OBJECT_0:
                    raise ToolError(_ERR_INJECT_WAIT_FAILED)

                self._kernel32.GetExitCodeThread.restype = wintypes.BOOL
                self._kernel32.GetExitCodeThread.argtypes = [
                    wintypes.HANDLE,
                    ctypes.POINTER(wintypes.DWORD),
                ]
                exit_code = wintypes.DWORD(0)
                if not self._kernel32.GetExitCodeThread(thread_handle, ctypes.byref(exit_code)):
                    last_error: int = self._kernel32.GetLastError()
                    err_msg = f"{_ERR_INJECT_GETEXITCODE_FAILED}: {last_error}"
                    raise ToolError(err_msg)
                if exit_code.value == 0:
                    raise ToolError(_ERR_INJECT_LOADLIB_FAILED)
            finally:
                self._kernel32.CloseHandle(thread_handle)

            _logger.info("dll_injected", dll_path=dll_path)
            return True
        finally:
            await self.free(remote_mem)

    async def get_process_info(self, pid: int | None = None) -> ProcessInfo | None:
        """Get detailed process information.

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            ProcessInfo | None: Process info or None if not found.
        """
        _logger.debug("process_info_reading", pid=pid)
        target_pid = pid or self._attached_pid
        if target_pid is None:
            return None

        processes = await self.list_processes()

        for proc in processes:
            if proc.pid == target_pid:
                proc.threads = await self.get_threads(target_pid)
                proc.modules = await self.get_modules(target_pid)
                return proc

        return None

    # ------------------------------------------------------------------
    # Token / privilege manipulation
    # ------------------------------------------------------------------

    def add_privileges_changed_callback(self, callback: Callable[[], None]) -> None:
        """Register a callback to invoke when token privileges change.

        Args:
            callback: Zero-argument callable invoked after a privilege mutation.
        """
        if callback not in self._privileges_changed_callbacks:
            self._privileges_changed_callbacks.append(callback)

    def remove_privileges_changed_callback(self, callback: Callable[[], None]) -> None:
        """Unregister a previously added privileges-changed callback.

        Args:
            callback: Callback to remove; silently ignored if not registered.
        """
        try:
            self._privileges_changed_callbacks.remove(callback)
        except ValueError:
            _logger.debug("privileges_changed_callback_not_registered")

    def _notify_privileges_changed(self) -> None:
        """Invoke all registered privileges-changed callbacks."""
        for cb in list(self._privileges_changed_callbacks):
            try:
                cb()
            except Exception:
                _logger.exception("privileges_changed_callback_failed")

    async def get_token_privileges(self, pid: int | None = None) -> list[dict[str, object]]:
        """Get token privileges for a process.

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            list[dict[str, object]]: List of privilege dicts.

        Raises:
            ToolError: If operation fails.
        """
        _logger.debug("process_get_token_privileges_started", pid=pid)
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="get_token_privileges")
            raise ToolError(_ERR_KERNEL32_NA)
        if self._advapi32 is None:
            _logger.error("advapi32_unavailable", operation="get_token_privileges")
            raise ToolError(_ERR_ADVAPI32_NA)

        target_pid = pid or self._attached_pid
        proc_handle: int | None = None
        close_proc = False

        if target_pid is not None:
            inherit_handle = False
            proc_handle = self._kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, inherit_handle, target_pid)
            close_proc = True
        else:
            proc_handle = self._kernel32.GetCurrentProcess()

        if not proc_handle:
            raise ToolError(_ERR_OPEN_FAILED)

        try:
            token_handle = wintypes.HANDLE()
            if not self._advapi32.OpenProcessToken(proc_handle, TOKEN_QUERY, ctypes.byref(token_handle)):
                raise ToolError(_ERR_ACCESS_HANDLE_OPEN)

            try:
                return self._read_token_privileges(token_handle)
            finally:
                self._kernel32.CloseHandle(token_handle)
        finally:
            if close_proc and proc_handle:
                self._kernel32.CloseHandle(proc_handle)

    def _read_token_privileges(self, token_handle: wintypes.HANDLE) -> list[dict[str, object]]:
        """Read privilege entries from an opened token handle.

        Args:
            token_handle: Open token handle with TOKEN_QUERY access.

        Returns:
            list[dict[str, object]]: List of privilege dicts.

        Raises:
            ToolError: If required DLLs are unavailable or token query fails.
        """
        if self._advapi32 is None:
            raise ToolError(_ERR_ADVAPI32_NA)
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        return_length = wintypes.DWORD()
        self._advapi32.GetTokenInformation(token_handle, 3, None, 0, ctypes.byref(return_length))

        buffer = ctypes.create_string_buffer(return_length.value)
        if not self._advapi32.GetTokenInformation(
            token_handle,
            3,
            buffer,
            return_length.value,
            ctypes.byref(return_length),
        ):
            raise ToolError(_ERR_PRIV_QUERY_FAILED)

        count = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
        base_offset = ctypes.sizeof(wintypes.DWORD)
        luid_attr_size = ctypes.sizeof(LUID_AND_ATTRIBUTES)

        privileges: list[dict[str, object]] = []
        for i in range(count):
            la = ctypes.cast(
                ctypes.byref(buffer, base_offset + i * luid_attr_size),
                ctypes.POINTER(LUID_AND_ATTRIBUTES),
            ).contents
            privileges.append(self._privilege_entry_to_dict(la))

        return privileges

    def _privilege_entry_to_dict(self, la: LUID_AND_ATTRIBUTES) -> dict[str, object]:
        """Convert a single LUID_AND_ATTRIBUTES to a privilege dict.

        Args:
            la: LUID_AND_ATTRIBUTES structure.

        Returns:
            dict[str, object]: Privilege dict with name, luid, enabled, attributes.

        Raises:
            ToolError: If advapi32 is not available.
        """
        if self._advapi32 is None:
            _logger.error("advapi32_unavailable", operation="_privilege_entry_to_dict")
            raise ToolError(_ERR_ADVAPI32_NA)

        name_buf = ctypes.create_unicode_buffer(256)
        name_size = wintypes.DWORD(256)
        luid_copy = LUID()
        luid_copy.LowPart = la.Luid.LowPart
        luid_copy.HighPart = la.Luid.HighPart

        priv_name = "Unknown"
        if self._advapi32.LookupPrivilegeNameW(
            None,
            ctypes.byref(luid_copy),
            name_buf,
            ctypes.byref(name_size),
        ):
            priv_name = name_buf.value

        return {
            "name": priv_name,
            "luid_low": la.Luid.LowPart,
            "luid_high": la.Luid.HighPart,
            "enabled": bool(la.Attributes & SE_PRIVILEGE_ENABLED),
            "attributes": la.Attributes,
        }

    async def adjust_token_privilege(
        self,
        privilege_name: str,
        *,
        enable: bool,
        pid: int | None = None,
    ) -> bool:
        """Enable or disable a specific token privilege.

        Args:
            privilege_name: Privilege name (e.g. SeDebugPrivilege).
            enable: True to enable, False to disable.
            pid: Process ID (uses current if not specified).

        Returns:
            bool: True if successful.

        Raises:
            ToolError: If operation fails.
        """
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)
        if self._advapi32 is None:
            raise ToolError(_ERR_ADVAPI32_NA)

        target_pid = pid or self._attached_pid
        proc_handle: int | None = None
        close_proc = False

        if target_pid is not None:
            inherit_handle = False
            proc_handle = self._kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, inherit_handle, target_pid)
            close_proc = True
        else:
            proc_handle = self._kernel32.GetCurrentProcess()

        if not proc_handle:
            raise ToolError(_ERR_OPEN_FAILED)

        try:
            token_handle = wintypes.HANDLE()
            if not self._advapi32.OpenProcessToken(
                proc_handle,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                ctypes.byref(token_handle),
            ):
                raise ToolError(_ERR_ACCESS_HANDLE_OPEN)

            try:
                luid = LUID()
                if not self._advapi32.LookupPrivilegeValueW(None, privilege_name, ctypes.byref(luid)):
                    msg = _ERR_PRIV_LOOKUP + privilege_name
                    raise ToolError(msg)

                tp = TOKEN_PRIVILEGES()
                tp.PrivilegeCount = 1
                tp.Privileges[0].Luid = luid
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED if enable else 0

                disable_all = False
                self._advapi32.AdjustTokenPrivileges(
                    token_handle,
                    disable_all,
                    ctypes.byref(tp),
                    ctypes.sizeof(TOKEN_PRIVILEGES),
                    None,
                    None,
                )

                last_error = ctypes.get_last_error()
                if last_error == ERROR_NOT_ALL_ASSIGNED:
                    msg = _ERR_PRIV_NOT_HELD + privilege_name
                    raise ToolError(msg)

                _logger.info("privilege_adjusted", privilege=privilege_name, enabled=enable)
                self._notify_privileges_changed()
                return True
            finally:
                self._kernel32.CloseHandle(token_handle)
        finally:
            if close_proc and proc_handle:
                self._kernel32.CloseHandle(proc_handle)

    # ------------------------------------------------------------------
    # Handle enumeration
    # ------------------------------------------------------------------

    def _query_extended_handles_buffer(self) -> tuple[ctypes.Array[ctypes.c_char], int, int]:
        """Query NtQuerySystemInformation for SystemExtendedHandleInformation.

        Returns the validated raw buffer, the number of handles, and the
        per-entry size. Raises on NTSTATUS failure or buffer overflow.

        Returns:
            tuple[ctypes.Array[ctypes.c_char], int, int]: Tuple of
                ``(buffer, num_handles, entry_size)``.

        Raises:
            ToolError: If ntdll is unavailable, the query fails, or the
                buffer is too small for the claimed handle count.
        """
        if self._ntdll is None:
            raise ToolError(_ERR_NTDLL_NA)

        buf_size = 0x100000
        while buf_size <= _NTQUERY_BUF_MAX:
            buffer = ctypes.create_string_buffer(buf_size)
            return_length = wintypes.ULONG(0)
            status: int = self._ntdll.NtQuerySystemInformation(
                SystemExtendedHandleInformation,
                buffer,
                buf_size,
                ctypes.byref(return_length),
            )
            if status == _STATUS_INFO_LENGTH_MISMATCH:
                buf_size *= 2
                continue
            if status < 0:
                msg = _ERR_NTQUERY_SYS + f"{status & 0xFFFFFFFF:08X}"
                raise ToolError(msg)
            break
        else:
            raise ToolError(_ERR_HANDLE_ENUM_BUF_MAX)

        num_handles_ptr = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))
        num_handles = num_handles_ptr.contents.value or 0
        entry_size = ctypes.sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
        header_size = ctypes.sizeof(ctypes.c_void_p) * 2
        required_size = header_size + num_handles * entry_size

        if required_size > buf_size:
            msg = f"handle buffer overflow: claimed {num_handles} handles requires {required_size} bytes but buffer is {buf_size}"
            raise ToolError(msg)

        return buffer, num_handles, entry_size

    async def get_handles(self, pid: int | None = None) -> list[dict[str, object]]:
        """Enumerate open handles for a process using NtQuerySystemInformation.

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            list[dict[str, object]]: List of handle dicts.

        Raises:
            ToolError: If operation fails.
        """
        _logger.debug("process_get_handles_starting", pid=pid)
        target_pid = pid or self._attached_pid
        if target_pid is None:
            _logger.error("no_process_specified", operation="get_handles")
            raise ToolError(_ERR_NO_PROCESS)

        return await asyncio.to_thread(self._sync_iterate_handles_for_pid, target_pid)

    def _sync_iterate_handles_for_pid(self, target_pid: int) -> list[dict[str, object]]:
        """Synchronously iterate the system handle table for a specific PID.

        Pulled out of :meth:`get_handles` so the potentially long
        iteration over tens of thousands of handle entries can be
        dispatched off the asyncio event loop via
        :func:`asyncio.to_thread`. Performs the same per-entry
        validation and dict construction as the inline loop did.

        Args:
            target_pid: PID to filter handle entries on.

        Returns:
            list[dict[str, object]]: List of handle dicts matching
            ``target_pid``.

        Raises:
            ToolError: If ntdll is unavailable or
                :meth:`_query_extended_handles_buffer` fails.
        """
        if self._ntdll is None:
            raise ToolError(_ERR_NTDLL_NA)
        buffer, num_handles, entry_size = self._query_extended_handles_buffer()
        header_size = ctypes.sizeof(ctypes.c_void_p) * 2
        handles: list[dict[str, object]] = []

        for i in range(num_handles):
            entry_ptr = ctypes.cast(
                ctypes.byref(buffer, header_size + i * entry_size),
                ctypes.POINTER(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX),
            )
            entry = entry_ptr.contents

            entry_pid = entry.UniqueProcessId
            if isinstance(entry_pid, int) and entry_pid == target_pid:
                handles.append({
                    "handle_value": entry.HandleValue or 0,
                    "type_index": entry.ObjectTypeIndex,
                    "granted_access": entry.GrantedAccess,
                    "object_address": entry.Object or 0,
                })

        return handles

    @staticmethod
    def _read_object_type_name(buffer: ctypes.Array[ctypes.c_char], offset: int, ptr_size: int) -> str:
        """Read a UNICODE_STRING type name from an OBJECT_TYPE_INFORMATION entry.

        The string data is stored at a fixed offset of ``_OBJECT_TYPE_INFO_HEADER_SIZE``
        bytes from the start of each entry, immediately after the full
        ``OBJECT_TYPE_INFORMATION`` structure. The UNICODE_STRING header resides
        at ``offset`` and provides the ``Length`` and ``MaximumLength`` values
        used for bounds checking.

        Args:
            buffer: Raw buffer from NtQueryObject.
            offset: Byte offset of the entry (and its UNICODE_STRING header) within buffer.
            ptr_size: Platform pointer size in bytes.

        Returns:
            str: Decoded type name, or empty string on failure.
        """
        del ptr_size
        try:
            length_ptr = ctypes.cast(ctypes.byref(buffer, offset), ctypes.POINTER(wintypes.USHORT))
            max_length_ptr = ctypes.cast(ctypes.byref(buffer, offset + 2), ctypes.POINTER(wintypes.USHORT))
            length = length_ptr.contents.value
            max_length = max_length_ptr.contents.value
            if length == 0 or length > max_length or length > _MAX_TYPE_NAME_BYTES:
                return ""
            buf_len = getattr(buffer, "_length_", 0)
            str_offset = offset + _OBJECT_TYPE_INFO_HEADER_SIZE
            if str_offset + length > buf_len:
                return ""
            raw = bytes(buffer[str_offset : str_offset + length])
            return raw.decode("utf-16-le", errors="ignore").rstrip("\x00")
        except (ValueError, OSError, ctypes.ArgumentError):
            return ""

    def _parse_type_info_buffer(
        self,
        buffer: ctypes.Array[ctypes.c_char],
        buf_size: int,
    ) -> dict[int, str]:
        """Parse the NtQueryObject ObjectAllTypesInformation buffer.

        Windows assigns object type indices starting from 2, incrementing by 1
        for each type in the order returned by NtQueryObject. Each entry
        starts with a UNICODE_STRING header (Length + MaximumLength + padding +
        Buffer pointer), followed by the inline string data and the rest of
        the OBJECT_TYPE_INFORMATION fields.

        Args:
            buffer: Raw buffer returned by NtQueryObject.
            buf_size: Usable length of the buffer in bytes.

        Returns:
            dict[int, str]: Mapping of type index to type name string.
        """
        ptr_size = ctypes.sizeof(ctypes.c_void_p)
        num_types_ptr = ctypes.cast(buffer, ctypes.POINTER(wintypes.ULONG))
        num_types = num_types_ptr.contents.value
        offset = ptr_size

        type_map: dict[int, str] = {}
        for entry_idx in range(num_types):
            if offset + _OBJECT_TYPE_INFO_HEADER_SIZE > buf_size:
                break

            name = self._read_object_type_name(buffer, offset, ptr_size)
            max_length_ptr = ctypes.cast(ctypes.byref(buffer, offset + 2), ctypes.POINTER(wintypes.USHORT))
            max_length = max_length_ptr.contents.value

            type_index = entry_idx + 2
            if name:
                type_map[type_index] = name

            entry_size = _OBJECT_TYPE_INFO_HEADER_SIZE + (max_length if max_length > 0 else 2)
            entry_size = (entry_size + ptr_size - 1) & ~(ptr_size - 1)
            offset += entry_size

        return type_map

    def _build_handle_type_map(self) -> dict[int, str]:
        """Build an index-to-name map for Windows object types via NtQueryObject.

        Calls ``NtQueryObject`` with ``ObjectAllTypesInformation`` (class 3)
        to retrieve the kernel's live object type registry. The resulting map
        is stored in :attr:`_handle_type_cache` and returned.

        Returns:
            dict[int, str]: Mapping of object type index to type name string.
                Falls back to the cached value on any failure.
        """
        if self._ntdll is None:
            return self._handle_type_cache

        buf_size = 0x10000
        buffer = ctypes.create_string_buffer(buf_size)
        for _ in range(8):
            return_length = wintypes.ULONG(0)
            status: int = self._ntdll.NtQueryObject(
                None,
                _OBJECT_ALL_TYPES_INFORMATION,
                buffer,
                buf_size,
                ctypes.byref(return_length),
            )
            if status in {
                _STATUS_INFO_LENGTH_MISMATCH,
                _STATUS_BUFFER_OVERFLOW,
                _STATUS_BUFFER_TOO_SMALL,
            }:
                buf_size = max(buf_size * 2, return_length.value + 4096)
                buffer = ctypes.create_string_buffer(buf_size)
                continue
            if status < 0:
                _logger.warning("ntquery_object_types_failed", status=f"{status & 0xFFFFFFFF:08X}")
                return self._handle_type_cache
            break
        else:
            return self._handle_type_cache

        type_map = self._parse_type_info_buffer(buffer, buf_size)
        if type_map:
            self._handle_type_cache = type_map
        return self._handle_type_cache

    async def enum_handles(self, pid: int | None = None) -> list[dict[str, object]]:
        """Enumerate open handles for a process, resolving type indices to names.

        Calls ``NtQuerySystemInformation`` with ``SystemExtendedHandleInformation``
        and resolves each handle's numeric ``ObjectTypeIndex`` to a human-readable
        type name string (e.g. ``"Process"``, ``"File"``, ``"Event"``) via
        ``NtQueryObject(ObjectAllTypesInformation)``. The type-name map is built
        once and cached in :attr:`_handle_type_cache`.

        Args:
            pid: Process ID to filter on. Returns handles for all processes
                when ``None``.

        Returns:
            list[dict[str, object]]: List of handle dicts with keys:
                ``pid``, ``handle_value``, ``type_name``, ``granted_access``,
                ``object_address``.

        Raises:
            ToolError: If ntdll is unavailable or the system query fails.
        """
        _logger.debug("process_enum_handles_starting", pid=pid)
        if self._ntdll is None:
            raise ToolError(_ERR_NTDLL_NA)
        if not self._handle_type_cache:
            self._build_handle_type_map()

        return await asyncio.to_thread(self._sync_enum_handles, pid)

    def _sync_enum_handles(self, pid: int | None) -> list[dict[str, object]]:
        """Synchronously iterate the system handle table with type-name resolution.

        Pulled out of :meth:`enum_handles` so the iteration over the
        full system handle table (potentially tens of thousands of
        entries) can be dispatched via :func:`asyncio.to_thread` and
        not block the event loop.

        Args:
            pid: Optional PID filter. ``None`` returns handles for all
                processes.

        Returns:
            list[dict[str, object]]: List of handle dicts with keys
            ``pid``, ``handle_value``, ``type_name``, ``granted_access``,
            ``object_address``.

        Raises:
            ToolError: If ntdll is unavailable or
                :meth:`_query_extended_handles_buffer` fails.
        """
        if self._ntdll is None:
            raise ToolError(_ERR_NTDLL_NA)
        buffer, num_handles, entry_size = self._query_extended_handles_buffer()
        header_size = ctypes.sizeof(ctypes.c_void_p) * 2
        handles: list[dict[str, object]] = []
        type_map = self._handle_type_cache
        for i in range(num_handles):
            entry_ptr = ctypes.cast(
                ctypes.byref(buffer, header_size + i * entry_size),
                ctypes.POINTER(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX),
            )
            entry = entry_ptr.contents

            entry_pid = entry.UniqueProcessId
            if not isinstance(entry_pid, int):
                continue
            if pid is not None and entry_pid != pid:
                continue

            type_index = entry.ObjectTypeIndex
            type_name: str = type_map.get(type_index, f"type_{type_index}")

            handles.append({
                "pid": entry_pid,
                "handle_value": entry.HandleValue or 0,
                "type_name": type_name,
                "granted_access": entry.GrantedAccess,
                "object_address": entry.Object or 0,
            })

        return handles

    # ------------------------------------------------------------------
    # Window enumeration
    # ------------------------------------------------------------------

    async def get_windows(self, pid: int | None = None) -> list[dict[str, object]]:
        """Enumerate windows belonging to a process.

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            list[dict[str, object]]: List of window dicts.

        Raises:
            ToolError: If operation fails.
        """
        _logger.debug("process_get_windows_started", pid=pid)
        if self._user32 is None:
            _logger.error("user32_unavailable", operation="get_windows")
            raise ToolError(_ERR_USER32_NA)
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="get_windows")
            raise ToolError(_ERR_KERNEL32_NA)

        target_pid = pid or self._attached_pid
        if target_pid is None:
            _logger.error("no_process_specified", operation="get_windows")
            raise ToolError(_ERR_NO_PROCESS)

        windows: list[dict[str, object]] = []
        user32 = self._user32

        enum_proc_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        def _enum_impl(hwnd: int, _lparam: int) -> bool:
            """Collect window metadata for windows owned by the target PID.

            Invoked once per top-level window by ``EnumWindows``. Windows
            that belong to the attached process are captured into the
            ``windows`` list with their title, class name, and visibility.

            Args:
                hwnd: Handle of the enumerated top-level window.
                _lparam: User-supplied parameter from ``EnumWindows``;
                    unused by this implementation.

            Returns:
                bool: ``True`` unconditionally so enumeration continues
                until the Windows API has visited every top-level window.
            """
            window_pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(window_pid))

            if window_pid.value == target_pid:
                title_buf = ctypes.create_unicode_buffer(512)
                user32.GetWindowTextW(hwnd, title_buf, 512)

                class_buf = ctypes.create_unicode_buffer(256)
                user32.GetClassNameW(hwnd, class_buf, 256)

                is_visible = bool(user32.IsWindowVisible(hwnd))

                windows.append({
                    "hwnd": hwnd,
                    "title": title_buf.value,
                    "class_name": class_buf.value,
                    "visible": is_visible,
                })
            return True

        enum_callback = enum_proc_type(_enum_impl)
        user32.EnumWindows(enum_callback, 0)
        return windows

    # ------------------------------------------------------------------
    # Service management
    # ------------------------------------------------------------------

    async def list_services(self, filter_pid: int | None = None) -> list[dict[str, object]]:
        """List Windows services, optionally filtered by owning PID.

        Args:
            filter_pid: Filter to services owned by this PID.

        Returns:
            list[dict[str, object]]: List of service dicts.

        Raises:
            ToolError: If operation fails.
        """
        _logger.debug("process_list_services_started", filter_pid=filter_pid)
        if self._advapi32 is None:
            _logger.error("advapi32_unavailable", operation="list_services")
            raise ToolError(_ERR_ADVAPI32_NA)

        open_scm = self._advapi32.OpenSCManagerW
        open_scm.restype = wintypes.SC_HANDLE
        open_scm.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]

        enum_svc = self._advapi32.EnumServicesStatusExW
        enum_svc.restype = wintypes.BOOL
        enum_svc.argtypes = [
            wintypes.SC_HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPCWSTR,
        ]

        close_svc = self._advapi32.CloseServiceHandle
        close_svc.restype = wintypes.BOOL
        close_svc.argtypes = [wintypes.SC_HANDLE]

        scm = open_scm(None, None, SC_MANAGER_ENUMERATE_SERVICE)
        if not scm:
            _logger.error("scm_open_failed", operation="list_services")
            raise ToolError(_ERR_SCM_OPEN_FAILED)

        try:
            bytes_needed = wintypes.DWORD(0)
            services_returned = wintypes.DWORD(0)
            resume_handle = wintypes.DWORD(0)

            enum_svc(
                scm,
                0,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                None,
                0,
                ctypes.byref(bytes_needed),
                ctypes.byref(services_returned),
                ctypes.byref(resume_handle),
                None,
            )

            buf_size = bytes_needed.value
            if buf_size == 0:
                return []

            buffer = ctypes.create_string_buffer(buf_size)
            if not enum_svc(
                scm,
                0,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                buffer,
                buf_size,
                ctypes.byref(bytes_needed),
                ctypes.byref(services_returned),
                ctypes.byref(resume_handle),
                None,
            ):
                raise ToolError(_ERR_ENUM_SVC)

            return self._parse_service_entries(buffer, services_returned.value, filter_pid)
        finally:
            close_svc(scm)

    @staticmethod
    def _parse_service_entries(
        buffer: ctypes.Array[ctypes.c_char],
        count: int,
        filter_pid: int | None,
    ) -> list[dict[str, object]]:
        """Parse service status entries from the enumeration buffer.

        Args:
            buffer: Raw buffer from EnumServicesStatusExW.
            count: Number of service entries.
            filter_pid: Optional PID filter.

        Returns:
            list[dict[str, object]]: Parsed service dicts.
        """
        state_map: dict[int, str] = {
            1: "stopped",
            2: "start_pending",
            3: "stop_pending",
            4: "running",
            5: "continue_pending",
            6: "pause_pending",
            7: "paused",
        }

        services: list[dict[str, object]] = []
        entry_size = ctypes.sizeof(ENUM_SERVICE_STATUS_PROCESSW)
        buf_len = len(buffer)

        for i in range(count):
            offset = i * entry_size
            if offset + entry_size > buf_len:
                _logger.warning("service_entry_out_of_bounds", index=i, offset=offset, buf_len=buf_len)
                break
            entry = ctypes.cast(
                ctypes.byref(buffer, offset),
                ctypes.POINTER(ENUM_SERVICE_STATUS_PROCESSW),
            ).contents

            raw_name: str | None = entry.lpServiceName
            raw_display: str | None = entry.lpDisplayName
            svc_name: str = str(raw_name) if raw_name is not None else ""
            svc_display: str = str(raw_display) if raw_display is not None else ""
            ssp = entry.ServiceStatusProcess

            svc_pid = ssp.dwProcessId
            if filter_pid is not None and svc_pid != filter_pid:
                continue

            services.append({
                "name": svc_name,
                "display_name": svc_display,
                "state": state_map.get(ssp.dwCurrentState, "unknown"),
                "pid": svc_pid,
                "service_type": ssp.dwServiceType,
            })

        return services

    # ------------------------------------------------------------------
    # PEB / TEB access
    # ------------------------------------------------------------------

    async def read_peb(self, pid: int | None = None) -> dict[str, object]:
        """Read Process Environment Block fields.

        Pointer-size aware: the native PEB is parsed using the *target*
        process's bitness (detected via ``IsWow64Process2``), not the
        host's. A 64-bit host debugging a 32-bit WOW64 target still gets
        correct ``image_base_address`` / ``ldr_address`` /
        ``process_parameters_address`` values because the parser is
        told to use i386 offsets. When the target is running under
        WOW64, ``NtQueryInformationProcess(ProcessWow64Information)``
        is also queried to expose the 32-bit PEB address and a parallel
        ``wow64_peb`` sub-dict.

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            dict[str, object]: Dict with PEB field values plus optional
                WOW64 PEB information.

        Raises:
            ToolError: If the bridge is not initialised, the target
                cannot be opened, the Nt query fails, or
                ``ReadProcessMemory`` fails.
        """
        _logger.debug("process_read_peb_started", pid=pid)
        if self._ntdll is None:
            _logger.error("ntdll_unavailable", operation="read_peb")
            raise ToolError(_ERR_NTDLL_NA)
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="read_peb")
            raise ToolError(_ERR_KERNEL32_NA)

        target_pid = pid or self._attached_pid
        close_handle = False
        proc_handle: int | None = None

        if target_pid is not None and target_pid != self._attached_pid:
            inherit_handle = False
            proc_handle = self._kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                inherit_handle,
                target_pid,
            )
            close_handle = True
        elif self._process_handle is not None:
            proc_handle = self._process_handle
        else:
            raise ToolError(_ERR_NOT_ATTACHED)

        if not proc_handle:
            raise ToolError(_ERR_OPEN_FAILED)

        try:
            return self._read_peb_from_handle(proc_handle)
        finally:
            if close_handle and proc_handle:
                self._kernel32.CloseHandle(proc_handle)

    def _read_peb_from_handle(self, proc_handle: int) -> dict[str, object]:
        """Read and parse PEB from an already-opened process handle.

        Args:
            proc_handle: Open process handle with
                ``PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`` access.

        Returns:
            dict[str, object]: Parsed PEB fields including ``raw`` bytes.

        Raises:
            ToolError: If NtQueryInformationProcess fails, WOW64
                detection is unavailable, or ReadProcessMemory fails.
        """
        if self._ntdll is None:
            raise ToolError(_ERR_NTDLL_NA)
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        pbi = PROCESS_BASIC_INFORMATION()
        return_length = wintypes.ULONG(0)
        status: int = self._ntdll.NtQueryInformationProcess(
            proc_handle,
            ProcessBasicInformation,
            ctypes.byref(pbi),
            ctypes.sizeof(pbi),
            ctypes.byref(return_length),
        )
        if status < 0:
            msg = _ERR_NTQUERY_PROC + f"{status & 0xFFFFFFFF:08X}"
            raise ToolError(msg)

        peb_address = pbi.PebBaseAddress or 0
        target_is_64bit = self._target_is_64bit(proc_handle)
        peb_read_size = ctypes.sizeof(PEB64) if target_is_64bit else ctypes.sizeof(PEB32)
        peb_data = ctypes.create_string_buffer(peb_read_size)
        bytes_read = ctypes.c_size_t()
        if not self._kernel32.ReadProcessMemory(
            proc_handle,
            ctypes.c_void_p(peb_address),
            peb_data,
            peb_read_size,
            ctypes.byref(bytes_read),
        ):
            raise ToolError(_ERR_PEB_READ)

        raw_bytes = peb_data.raw[: bytes_read.value]
        result = self._parse_peb_fields(raw_bytes, peb_address, target_is_64bit=target_is_64bit)
        result["raw"] = raw_bytes
        wow64_info = self._read_wow64_peb(proc_handle)
        if wow64_info is not None:
            result["wow64_peb_address"] = wow64_info[0]
            result["wow64_peb"] = wow64_info[1]
        return result

    def _target_is_64bit(self, proc_handle: int) -> bool:
        """Determine whether the process bound to ``proc_handle`` is 64-bit.

        Uses ``IsWow64Process2`` when available (Win10+) to distinguish
        native-64-bit from WOW64-hosted-32-bit. Falls back to the legacy
        ``IsWow64Process`` when the newer API is absent. Raises if both
        APIs are unavailable so callers never silently use the host
        pointer size as a proxy for the target's bitness.

        Args:
            proc_handle: Open process handle with at least
                ``PROCESS_QUERY_LIMITED_INFORMATION`` access.

        Returns:
            bool: ``True`` if the target process address space is
                64-bit; ``False`` if the target is 32-bit (WOW64 or
                native i386).

        Raises:
            ToolError: If kernel32 is unavailable or both
                ``IsWow64Process2`` and ``IsWow64Process`` are absent,
                making bitness detection impossible.
        """
        if self._kernel32 is None:
            raise ToolError(_ERR_WOW64_UNAVAILABLE)

        native_64bit_machines = {IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64}
        machines = self._call_iswow64process2(proc_handle)
        if machines is not None:
            process_machine, native_machine = machines
            if process_machine == IMAGE_FILE_MACHINE_I386:
                return False
            if process_machine in native_64bit_machines:
                return True
            if process_machine == IMAGE_FILE_MACHINE_UNKNOWN:
                return native_machine in native_64bit_machines

        is_wow64 = wintypes.BOOL(0)
        if hasattr(self._kernel32, "IsWow64Process") and self._kernel32.IsWow64Process(
            proc_handle,
            ctypes.byref(is_wow64),
        ):
            if is_wow64.value:
                return False
            return struct.calcsize("P") == _PTR_SIZE_64

        raise ToolError(_ERR_WOW64_UNAVAILABLE)

    def _read_wow64_peb(
        self,
        proc_handle: int,
    ) -> tuple[int, dict[str, object]] | None:
        """Read and parse the 32-bit WOW64 PEB if the target is WOW64.

        Args:
            proc_handle: Open process handle with
                ``PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`` rights.

        Returns:
            tuple[int, dict[str, object]] | None: ``(wow64_peb_address,
                parsed_fields)`` when the target has a 32-bit PEB,
                ``None`` otherwise (native 64-bit target or information
                class unsupported).
        """
        if self._ntdll is None or self._kernel32 is None:
            return None

        wow64_peb_ptr = ctypes.c_void_p(0)
        returned = wintypes.ULONG(0)
        status: int = self._ntdll.NtQueryInformationProcess(
            proc_handle,
            ProcessWow64Information,
            ctypes.byref(wow64_peb_ptr),
            ctypes.sizeof(wow64_peb_ptr),
            ctypes.byref(returned),
        )

        if status < 0:
            _logger.debug(
                "wow64_peb_query_failed",
                ntstatus=hex(status & 0xFFFFFFFF),
            )
            return None

        wow64_peb_address = wow64_peb_ptr.value or 0
        if wow64_peb_address == 0:
            return None

        peb32_size = ctypes.sizeof(PEB32)
        peb32 = ctypes.create_string_buffer(peb32_size)
        bytes_read = ctypes.c_size_t()
        if not self._kernel32.ReadProcessMemory(
            proc_handle,
            ctypes.c_void_p(wow64_peb_address),
            peb32,
            peb32_size,
            ctypes.byref(bytes_read),
        ):
            _logger.debug(
                "wow64_peb_read_failed",
                address=hex(wow64_peb_address),
            )
            return None

        return wow64_peb_address, self._parse_peb32_fields(
            peb32.raw[: bytes_read.value],
            wow64_peb_address,
        )

    @staticmethod
    def _parse_peb_fields(
        raw: bytes,
        peb_address: int,
        *,
        target_is_64bit: bool = True,
    ) -> dict[str, object]:
        """Parse PEB fields from raw memory bytes.

        Args:
            raw: Raw PEB memory bytes.
            peb_address: PEB base address.
            target_is_64bit: ``True`` when the inspected PEB belongs to
                a 64-bit process (use 64-bit field offsets); ``False``
                for i386 / WOW64 32-bit PEBs.

        Returns:
            dict[str, object]: Parsed PEB field values.
        """
        if target_is_64bit:
            image_base = struct.unpack_from("<Q", raw, 0x10)[0]
            ldr_address = struct.unpack_from("<Q", raw, 0x18)[0]
            process_params = struct.unpack_from("<Q", raw, 0x20)[0]
        else:
            image_base = struct.unpack_from("<I", raw, 0x08)[0]
            ldr_address = struct.unpack_from("<I", raw, 0x0C)[0]
            process_params = struct.unpack_from("<I", raw, 0x10)[0]

        return {
            "peb_address": peb_address,
            "image_base_address": image_base,
            "ldr_address": ldr_address,
            "process_parameters_address": process_params,
            "being_debugged": raw[2],
            "inherited_address_space": raw[0],
        }

    @staticmethod
    def _parse_peb32_fields(raw: bytes, peb_address: int) -> dict[str, object]:
        """Parse the 32-bit PEB layout used inside WOW64.

        Args:
            raw: Raw i386 PEB memory bytes (at least ``0x18`` bytes).
            peb_address: 32-bit PEB base address as returned by
                ``ProcessWow64Information``.

        Returns:
            dict[str, object]: Parsed 32-bit PEB field values. Missing
                fields are reported as zero when the buffer is short.
        """
        if len(raw) < _PEB32_MIN_PARSE_LENGTH:
            return {
                "peb_address": peb_address,
                "image_base_address": 0,
                "ldr_address": 0,
                "process_parameters_address": 0,
                "being_debugged": raw[_PEB_BEING_DEBUGGED_OFFSET] if len(raw) > _PEB_BEING_DEBUGGED_OFFSET else 0,
                "inherited_address_space": raw[0] if raw else 0,
            }

        image_base = struct.unpack_from("<I", raw, 0x08)[0]
        ldr_address = struct.unpack_from("<I", raw, 0x0C)[0]
        process_params = struct.unpack_from("<I", raw, 0x10)[0]

        return {
            "peb_address": peb_address,
            "image_base_address": image_base,
            "ldr_address": ldr_address,
            "process_parameters_address": process_params,
            "being_debugged": raw[2],
            "inherited_address_space": raw[0],
        }

    async def read_teb(self, tid: int) -> dict[str, object]:
        """Read Thread Environment Block fields for a thread.

        Opens a dedicated thread handle with ``THREAD_QUERY_INFORMATION``
        and calls ``NtQueryInformationThread(ThreadBasicInformation)`` to
        obtain the thread's TEB base address. A separate process handle is
        opened from the thread's owning PID (``ClientId.UniqueProcess``)
        for ``ReadProcessMemory`` so the caller is not required to have an
        active ``open_process`` session. Both handles are closed on return.

        Args:
            tid: Thread ID.

        Returns:
            dict[str, object]: Dict with TEB field values.

        Raises:
            ToolError: If the bridge is not initialised, the thread
                cannot be opened, ``NtQueryInformationThread`` fails, the
                owning process cannot be opened, or ``ReadProcessMemory``
                fails.
        """
        _logger.debug("process_read_teb_started", tid=tid)
        if self._ntdll is None:
            _logger.error("ntdll_unavailable", operation="read_teb")
            raise ToolError(_ERR_NTDLL_NA)
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="read_teb")
            raise ToolError(_ERR_KERNEL32_NA)

        inherit_handle = False
        thread_handle = self._kernel32.OpenThread(THREAD_QUERY_INFORMATION, inherit_handle, tid)
        if not thread_handle:
            raise ToolError(_ERR_THREAD_OPEN_FAILED)

        proc_handle: int | None = None
        try:
            tbi = THREAD_BASIC_INFORMATION()
            status: int = self._ntdll.NtQueryInformationThread(
                thread_handle,
                ThreadBasicInformation,
                ctypes.byref(tbi),
                ctypes.sizeof(tbi),
                None,
            )

            if status < 0:
                msg = _ERR_NTQUERY_THREAD + f"{status & 0xFFFFFFFF:08X}"
                raise ToolError(msg)

            teb_address = tbi.TebBaseAddress or 0
            owner_pid = tbi.ClientId_UniqueProcess or 0

            inherit_handle = False
            proc_handle = self._kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                inherit_handle,
                owner_pid,
            )
            if not proc_handle:
                raise ToolError(_ERR_OPEN_FAILED)

            target_is_64bit = self._target_is_64bit(proc_handle)
            teb_read_size = ctypes.sizeof(TEB64) if target_is_64bit else ctypes.sizeof(TEB32)
            teb_data = ctypes.create_string_buffer(teb_read_size)
            bytes_read = ctypes.c_size_t()
            if not self._kernel32.ReadProcessMemory(
                proc_handle,
                ctypes.c_void_p(teb_address),
                teb_data,
                teb_read_size,
                ctypes.byref(bytes_read),
            ):
                raise ToolError(_ERR_TEB_READ)

            result = self._parse_teb_fields(
                teb_data.raw,
                teb_address,
                target_is_64bit=target_is_64bit,
            )
            result["exit_status"] = tbi.ExitStatus
            return result
        finally:
            self._kernel32.CloseHandle(thread_handle)
            if proc_handle:
                self._kernel32.CloseHandle(proc_handle)

    @staticmethod
    def _parse_teb_fields(
        raw: bytes,
        teb_address: int,
        *,
        target_is_64bit: bool = True,
    ) -> dict[str, object]:
        """Parse TEB fields from raw memory bytes.

        Args:
            raw: Raw TEB memory bytes.
            teb_address: TEB base address.
            target_is_64bit: ``True`` when the inspected TEB belongs to
                a 64-bit thread; ``False`` for i386 / WOW64 32-bit TEBs.

        Returns:
            dict[str, object]: Parsed TEB field values.
        """
        if target_is_64bit:
            seh_frame = struct.unpack_from("<Q", raw, 0x00)[0]
            stack_base = struct.unpack_from("<Q", raw, 0x08)[0]
            stack_limit = struct.unpack_from("<Q", raw, 0x10)[0]
            fiber_data = struct.unpack_from("<Q", raw, 0x20)[0]
            thread_local_storage_pointer = struct.unpack_from("<Q", raw, 0x58)[0]
            peb_ptr = struct.unpack_from("<Q", raw, 0x60)[0]
            last_error = struct.unpack_from("<I", raw, 0x68)[0]
            tls_array_base = teb_address + TLS_ARRAY_OFFSET_X64
        else:
            seh_frame = struct.unpack_from("<I", raw, 0x00)[0]
            stack_base = struct.unpack_from("<I", raw, 0x04)[0]
            stack_limit = struct.unpack_from("<I", raw, 0x08)[0]
            fiber_data = struct.unpack_from("<I", raw, 0x10)[0]
            thread_local_storage_pointer = struct.unpack_from("<I", raw, 0x2C)[0]
            peb_ptr = struct.unpack_from("<I", raw, 0x30)[0]
            last_error = struct.unpack_from("<I", raw, 0x34)[0]
            tls_array_base = teb_address + TLS_ARRAY_OFFSET_X86

        return {
            "teb_address": teb_address,
            "seh_frame": seh_frame,
            "stack_base": stack_base,
            "stack_limit": stack_limit,
            "fiber_data": fiber_data,
            "thread_local_storage_pointer": thread_local_storage_pointer,
            "peb_address": peb_ptr,
            "last_error_value": last_error,
            "tls_array_base": tls_array_base,
        }

    # ------------------------------------------------------------------
    # Heap enumeration
    # ------------------------------------------------------------------

    async def get_heaps(self, pid: int | None = None) -> list[dict[str, object]]:
        """Enumerate heaps of a process via Toolhelp32.

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            list[dict[str, object]]: List of heap dicts.

        Raises:
            ToolError: If operation fails.
        """
        _logger.debug("process_get_heaps_started", pid=pid)
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="get_heaps")
            raise ToolError(_ERR_KERNEL32_NA)

        target_pid = pid or self._attached_pid
        if target_pid is None:
            _logger.error("no_process_specified", operation="get_heaps")
            raise ToolError(_ERR_NO_PROCESS)

        self._kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        snapshot: int = self._kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, target_pid)
        if snapshot == INVALID_HANDLE_VALUE:
            _logger.error("snapshot_failed", operation="get_heaps", target_pid=target_pid)
            raise ToolError(_ERR_SNAPSHOT_FAILED)

        heaps: list[dict[str, object]] = []
        entry = HEAPLIST32()
        entry.dwSize = ctypes.sizeof(HEAPLIST32)

        try:
            if self._kernel32.Heap32ListFirst(snapshot, ctypes.byref(entry)):
                while True:
                    heaps.append({
                        "heap_id": entry.th32HeapID,
                        "flags": entry.dwFlags,
                        "is_default": bool(entry.dwFlags & 1),
                    })
                    entry.dwSize = ctypes.sizeof(HEAPLIST32)
                    if not self._kernel32.Heap32ListNext(snapshot, ctypes.byref(entry)):
                        break
        finally:
            self._kernel32.CloseHandle(snapshot)

        return heaps

    # ------------------------------------------------------------------
    # Thread context (registers)
    # ------------------------------------------------------------------

    async def get_thread_context(self, tid: int) -> dict[str, int]:
        """Get CPU register context for a thread.

        Args:
            tid: Thread ID.

        Returns:
            dict[str, int]: Dict of register name to value.

        Raises:
            ToolError: If operation fails.
        """
        _logger.debug("process_get_thread_context_started", tid=tid)
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="get_thread_context")
            raise ToolError(_ERR_KERNEL32_NA)

        inherit_handle = False
        thread_handle = self._kernel32.OpenThread(
            THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
            inherit_handle,
            tid,
        )
        if not thread_handle:
            _logger.error("thread_open_failed", operation="get_thread_context", tid=tid)
            raise ToolError(_ERR_THREAD_OPEN_FAILED)

        try:
            suspend_count: int = self._kernel32.SuspendThread(thread_handle)
            if ctypes.c_long(suspend_count).value < 0:
                raise ToolError(_ERR_CONTEXT_GET_FAILED)

            try:
                is_wow64_target = self._target_is_wow64()

                if is_wow64_target:
                    wow64_get_ctx = getattr(self._kernel32, "Wow64GetThreadContext", None)
                    if wow64_get_ctx is None:
                        raise ToolError(_ERR_CONTEXT_GET_FAILED)
                    wow64_get_ctx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
                    wow64_get_ctx.restype = wintypes.BOOL
                    ctx32 = WOW64_CONTEXT()
                    ctx32.ContextFlags = CONTEXT_I386_ALL
                    if not wow64_get_ctx(thread_handle, ctypes.byref(ctx32)):
                        raise ToolError(_ERR_CONTEXT_GET_FAILED)
                    return {
                        "eax": ctx32.Eax,
                        "ebx": ctx32.Ebx,
                        "ecx": ctx32.Ecx,
                        "edx": ctx32.Edx,
                        "esi": ctx32.Esi,
                        "edi": ctx32.Edi,
                        "ebp": ctx32.Ebp,
                        "esp": ctx32.Esp,
                        "eip": ctx32.Eip,
                        "eflags": ctx32.EFlags,
                        "cs": ctx32.SegCs,
                        "ds": ctx32.SegDs,
                        "es": ctx32.SegEs,
                        "fs": ctx32.SegFs,
                        "gs": ctx32.SegGs,
                        "ss": ctx32.SegSs,
                        "dr0": ctx32.Dr0,
                        "dr1": ctx32.Dr1,
                        "dr2": ctx32.Dr2,
                        "dr3": ctx32.Dr3,
                        "dr6": ctx32.Dr6,
                        "dr7": ctx32.Dr7,
                    }

                ctx = CONTEXT64()
                ctx.ContextFlags = CONTEXT_ALL
                if not self._kernel32.GetThreadContext(thread_handle, ctypes.byref(ctx)):
                    raise ToolError(_ERR_CONTEXT_GET_FAILED)

                return {
                    "rax": ctx.Rax,
                    "rbx": ctx.Rbx,
                    "rcx": ctx.Rcx,
                    "rdx": ctx.Rdx,
                    "rsi": ctx.Rsi,
                    "rdi": ctx.Rdi,
                    "rbp": ctx.Rbp,
                    "rsp": ctx.Rsp,
                    "r8": ctx.R8,
                    "r9": ctx.R9,
                    "r10": ctx.R10,
                    "r11": ctx.R11,
                    "r12": ctx.R12,
                    "r13": ctx.R13,
                    "r14": ctx.R14,
                    "r15": ctx.R15,
                    "rip": ctx.Rip,
                    "eflags": ctx.EFlags,
                    "cs": ctx.SegCs,
                    "ds": ctx.SegDs,
                    "es": ctx.SegEs,
                    "fs": ctx.SegFs,
                    "gs": ctx.SegGs,
                    "ss": ctx.SegSs,
                    "dr0": ctx.Dr0,
                    "dr1": ctx.Dr1,
                    "dr2": ctx.Dr2,
                    "dr3": ctx.Dr3,
                    "dr6": ctx.Dr6,
                    "dr7": ctx.Dr7,
                }
            finally:
                self._kernel32.ResumeThread(thread_handle)
        finally:
            self._kernel32.CloseHandle(thread_handle)

    async def set_thread_context(self, tid: int, registers: dict[str, int]) -> bool:
        """Set CPU register values for a thread.

        Args:
            tid: Thread ID.
            registers: Dict of register name to value.

        Returns:
            bool: True if successful.

        Raises:
            ToolError: If operation fails.
        """
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        inherit_handle = False
        thread_handle = self._kernel32.OpenThread(
            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
            inherit_handle,
            tid,
        )
        if not thread_handle:
            raise ToolError(_ERR_THREAD_OPEN_FAILED)

        try:
            suspend_count_set: int = self._kernel32.SuspendThread(thread_handle)
            if ctypes.c_long(suspend_count_set).value < 0:
                raise ToolError(_ERR_CONTEXT_SET_FAILED)

            try:
                is_wow64_target = self._target_is_wow64()

                if is_wow64_target:
                    wow64_get_ctx = getattr(self._kernel32, "Wow64GetThreadContext", None)
                    wow64_set_ctx = getattr(self._kernel32, "Wow64SetThreadContext", None)
                    if wow64_get_ctx is None or wow64_set_ctx is None:
                        raise ToolError(_ERR_CONTEXT_SET_FAILED)
                    wow64_get_ctx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
                    wow64_get_ctx.restype = wintypes.BOOL
                    wow64_set_ctx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
                    wow64_set_ctx.restype = wintypes.BOOL
                    ctx32 = WOW64_CONTEXT()
                    ctx32.ContextFlags = CONTEXT_I386_ALL
                    if not wow64_get_ctx(thread_handle, ctypes.byref(ctx32)):
                        raise ToolError(_ERR_CONTEXT_GET_FAILED)
                    reg_map_wow64: dict[str, str] = {
                        "eax": "Eax",
                        "ebx": "Ebx",
                        "ecx": "Ecx",
                        "edx": "Edx",
                        "esi": "Esi",
                        "edi": "Edi",
                        "ebp": "Ebp",
                        "esp": "Esp",
                        "eip": "Eip",
                    }
                    for name, value in registers.items():
                        attr = reg_map_wow64.get(name.lower())
                        if attr is not None:
                            setattr(ctx32, attr, value)
                    if not wow64_set_ctx(thread_handle, ctypes.byref(ctx32)):
                        raise ToolError(_ERR_CONTEXT_SET_FAILED)
                else:
                    ctx = CONTEXT64()
                    ctx.ContextFlags = CONTEXT_ALL
                    if not self._kernel32.GetThreadContext(thread_handle, ctypes.byref(ctx)):
                        raise ToolError(_ERR_CONTEXT_GET_FAILED)

                    reg_map: dict[str, str] = {
                        "rax": "Rax",
                        "rbx": "Rbx",
                        "rcx": "Rcx",
                        "rdx": "Rdx",
                        "rsi": "Rsi",
                        "rdi": "Rdi",
                        "rbp": "Rbp",
                        "rsp": "Rsp",
                        "r8": "R8",
                        "r9": "R9",
                        "r10": "R10",
                        "r11": "R11",
                        "r12": "R12",
                        "r13": "R13",
                        "r14": "R14",
                        "r15": "R15",
                        "rip": "Rip",
                    }
                    for name, value in registers.items():
                        attr = reg_map.get(name.lower())
                        if attr is not None:
                            setattr(ctx, attr, value)

                    if not self._kernel32.SetThreadContext(thread_handle, ctypes.byref(ctx)):
                        raise ToolError(_ERR_CONTEXT_SET_FAILED)

                _logger.info("thread_context_set", tid=tid, registers=list(registers.keys()))
                return True
            finally:
                self._kernel32.ResumeThread(thread_handle)
        finally:
            self._kernel32.CloseHandle(thread_handle)

    # ------------------------------------------------------------------
    # Stack walk + symbols
    # ------------------------------------------------------------------

    async def stack_walk(self, tid: int) -> list[dict[str, object]]:
        """Walk the call stack of a thread using DbgHelp StackWalk64.

        Chooses between the native AMD64 path and a WOW64-aware I386
        path based on ``IsWow64Process2``. When the target is a 32-bit
        process running inside a 64-bit host (``x86`` on ``x64`` /
        ``arm64``), ``Wow64GetThreadContext`` is used to retrieve a
        ``WOW64_CONTEXT`` and ``StackWalk64`` is invoked with
        ``IMAGE_FILE_MACHINE_I386``. Native 64-bit targets keep the
        existing ``CONTEXT64`` + ``IMAGE_FILE_MACHINE_AMD64`` path.

        Args:
            tid: Thread ID.

        Returns:
            list[dict[str, object]]: List of stack frame dicts.

        Raises:
            ToolError: If the bridge is not initialised, no process is
                attached, the thread cannot be opened, or the
                ``GetThreadContext`` call fails.
        """
        _logger.debug("process_stack_walk_started", tid=tid)
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="stack_walk")
            raise ToolError(_ERR_KERNEL32_NA)
        if self._dbghelp is None:
            raise ToolError(_ERR_DBGHELP_NA)
        if self._process_handle is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        inherit_handle = False
        thread_handle = self._kernel32.OpenThread(
            THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
            inherit_handle,
            tid,
        )
        if not thread_handle:
            raise ToolError(_ERR_THREAD_OPEN_FAILED)

        frames: list[dict[str, object]] = []
        try:
            sw_suspend: int = self._kernel32.SuspendThread(thread_handle)
            if ctypes.c_long(sw_suspend).value < 0:
                raise ToolError(_ERR_THREAD_OPEN_FAILED)

            try:
                invade_process = True
                if not self._dbghelp.SymInitialize(self._process_handle, None, invade_process):
                    raise ToolError(_ERR_DBGHELP_NA)
                try:
                    is_wow64_target = self._target_is_wow64()
                    frames = self._walk_stack_wow64(thread_handle) if is_wow64_target else self._walk_stack_native(thread_handle)
                finally:
                    self._dbghelp.SymCleanup(self._process_handle)
            finally:
                self._kernel32.ResumeThread(thread_handle)
        finally:
            self._kernel32.CloseHandle(thread_handle)

        return frames

    def _target_is_wow64(self) -> bool:
        """Return True when the attached process runs under WOW64.

        Uses ``IsWow64Process2`` when available so the decision works on
        both x64-hosted and arm64-hosted Windows. Falls back to the
        legacy ``IsWow64Process`` when the newer API is absent. Raises
        if both APIs are unavailable so callers never silently assume
        non-WOW64 when detection is impossible.

        Returns:
            bool: ``True`` when the attached process is a 32-bit x86
                binary on a 64-bit host; ``False`` otherwise.

        Raises:
            ToolError: If kernel32 is unavailable, no process is
                attached, or both ``IsWow64Process2`` and
                ``IsWow64Process`` are absent.
        """
        if self._kernel32 is None or self._process_handle is None:
            raise ToolError(_ERR_WOW64_UNAVAILABLE)

        machines = self._call_iswow64process2(self._process_handle)
        if machines is not None:
            return machines[0] == IMAGE_FILE_MACHINE_I386

        is_wow64 = wintypes.BOOL(0)
        if hasattr(self._kernel32, "IsWow64Process"):
            self._kernel32.IsWow64Process(self._process_handle, ctypes.byref(is_wow64))
            return bool(is_wow64.value)

        raise ToolError(_ERR_WOW64_UNAVAILABLE)

    def _pid_is_wow64(self, target_pid: int) -> bool:
        """Return True when the given PID runs under WOW64.

        Opens a fresh ``OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)``
        handle for ``target_pid``, queries ``IsWow64Process2`` (with the
        legacy ``IsWow64Process`` fallback), then closes the handle. This
        is the per-target-pid analogue of :meth:`_target_is_wow64` for
        callers that operate on processes other than the attached one
        (for example, ``get_threads(target_pid)`` enumerating threads of
        a different PID).

        Args:
            target_pid: PID of the process to query.

        Returns:
            bool: ``True`` when the target process is a 32-bit x86 binary
                on a 64-bit host; ``False`` if not, or if the query fails.
        """
        if self._kernel32 is None:
            return False

        inherit_handle = False
        handle: int = self._kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            inherit_handle,
            target_pid,
        )
        if not handle:
            return False

        try:
            machines = self._call_iswow64process2(handle)
            if machines is not None:
                return machines[0] == IMAGE_FILE_MACHINE_I386

            is_wow64 = wintypes.BOOL(0)
            if hasattr(self._kernel32, "IsWow64Process"):
                self._kernel32.IsWow64Process(handle, ctypes.byref(is_wow64))
                return bool(is_wow64.value)
        finally:
            self._kernel32.CloseHandle(handle)

        return False

    def _walk_stack_native(self, thread_handle: int) -> list[dict[str, object]]:
        """Walk a native AMD64 thread stack via ``StackWalk64``.

        Args:
            thread_handle: Suspended thread handle with
                ``THREAD_GET_CONTEXT`` access.

        Returns:
            list[dict[str, object]]: Resolved stack frames.

        Raises:
            ToolError: If kernel32/dbghelp are not available, no process
                is attached, or ``GetThreadContext`` fails.
        """
        if self._kernel32 is None or self._dbghelp is None or self._process_handle is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        ctx = CONTEXT64()
        ctx.ContextFlags = CONTEXT_ALL
        if not self._kernel32.GetThreadContext(thread_handle, ctypes.byref(ctx)):
            raise ToolError(_ERR_CONTEXT_GET_FAILED)

        frame = STACKFRAME64()
        ctypes.memset(ctypes.byref(frame), 0, ctypes.sizeof(frame))
        frame.AddrPC.Offset = ctx.Rip
        frame.AddrPC.Mode = 3
        frame.AddrFrame.Offset = ctx.Rbp
        frame.AddrFrame.Mode = 3
        frame.AddrStack.Offset = ctx.Rsp
        frame.AddrStack.Mode = 3

        return self._iterate_stack_frames(
            IMAGE_FILE_MACHINE_AMD64,
            thread_handle,
            frame,
            ctypes.byref(ctx),
        )

    def _walk_stack_wow64(self, thread_handle: int) -> list[dict[str, object]]:
        """Walk a WOW64 (32-bit on 64-bit) thread stack.

        Uses ``Wow64GetThreadContext`` to fetch the I386 register state
        visible from inside the WOW64 subsystem and invokes
        ``StackWalk64`` with ``IMAGE_FILE_MACHINE_I386``.

        Args:
            thread_handle: Suspended thread handle with
                ``THREAD_GET_CONTEXT`` access.

        Returns:
            list[dict[str, object]]: Resolved stack frames.

        Raises:
            ToolError: If kernel32/dbghelp are not available, no process
                is attached, ``Wow64GetThreadContext`` is not exported,
                or the context fetch fails.
        """
        if self._kernel32 is None or self._dbghelp is None or self._process_handle is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        wow64_get_ctx = getattr(self._kernel32, "Wow64GetThreadContext", None)
        if wow64_get_ctx is None:
            raise ToolError(_ERR_CONTEXT_GET_FAILED)

        wow64_get_ctx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        wow64_get_ctx.restype = wintypes.BOOL

        ctx32 = WOW64_CONTEXT()
        ctx32.ContextFlags = CONTEXT_I386_ALL
        if not wow64_get_ctx(thread_handle, ctypes.byref(ctx32)):
            raise ToolError(_ERR_CONTEXT_GET_FAILED)

        frame = STACKFRAME64()
        ctypes.memset(ctypes.byref(frame), 0, ctypes.sizeof(frame))
        frame.AddrPC.Offset = ctx32.Eip
        frame.AddrPC.Mode = 3
        frame.AddrFrame.Offset = ctx32.Ebp
        frame.AddrFrame.Mode = 3
        frame.AddrStack.Offset = ctx32.Esp
        frame.AddrStack.Mode = 3

        return self._iterate_stack_frames(
            IMAGE_FILE_MACHINE_I386,
            thread_handle,
            frame,
            ctypes.byref(ctx32),
        )

    def _iterate_stack_frames(
        self,
        machine_type: int,
        thread_handle: int,
        frame: STACKFRAME64,
        context_ref: object,
    ) -> list[dict[str, object]]:
        """Iterate ``StackWalk64`` until unwind stops or max frames hit.

        Args:
            machine_type: ``IMAGE_FILE_MACHINE_*`` constant selecting the
                native-vs-WOW64 code path.
            thread_handle: Suspended thread handle being walked.
            frame: Seeded ``STACKFRAME64`` describing the top frame.
            context_ref: ``ctypes.byref`` reference to the context
                structure appropriate for ``machine_type``.

        Returns:
            list[dict[str, object]]: Resolved stack frames with symbol
                and module information where available.
        """
        if self._dbghelp is None or self._process_handle is None:
            return []

        frames: list[dict[str, object]] = []
        max_frames = 256

        for idx in range(max_frames):
            if not self._dbghelp.StackWalk64(
                machine_type,
                self._process_handle,
                thread_handle,
                ctypes.byref(frame),
                context_ref,
                None,
                None,
                None,
                None,
            ):
                break

            pc = frame.AddrPC.Offset
            if pc == 0:
                break

            sym_name = self._resolve_symbol(pc)
            module_name = self._resolve_module(pc)

            frames.append({
                "index": idx,
                "address": pc,
                "return_address": frame.AddrReturn.Offset,
                "frame_pointer": frame.AddrFrame.Offset,
                "symbol_name": sym_name[0],
                "module_name": module_name,
                "displacement": sym_name[1],
            })

        return frames

    def _resolve_symbol(self, pc: int) -> tuple[str, int]:
        """Resolve a PC to a symbol name + displacement via ``SymFromAddr``.

        Args:
            pc: Program counter / instruction pointer to resolve.

        Returns:
            tuple[str, int]: ``(symbol_name, displacement_from_symbol)``.
                ``symbol_name`` is the empty string when resolution fails.
        """
        if self._dbghelp is None or self._process_handle is None:
            return "", 0

        sym_from_addr = self._dbghelp.SymFromAddr
        sym_from_addr.argtypes = [
            wintypes.HANDLE,
            ctypes.c_ulonglong,
            ctypes.POINTER(ctypes.c_ulonglong),
            ctypes.c_void_p,
        ]
        sym_from_addr.restype = wintypes.BOOL

        displacement = ctypes.c_ulonglong(0)
        sym_header_size = ctypes.sizeof(SYMBOL_INFO) - ctypes.sizeof(ctypes.c_char * 1024) + ctypes.sizeof(ctypes.c_char)
        sym_buf_size = sym_header_size + _MAX_SYM_NAME * ctypes.sizeof(ctypes.c_char)
        sym_buf = (ctypes.c_char * sym_buf_size)()
        sym_ptr = ctypes.cast(sym_buf, ctypes.POINTER(SYMBOL_INFO))
        sym_ptr[0].SizeOfStruct = sym_header_size
        sym_ptr[0].MaxNameLen = _MAX_SYM_NAME

        if sym_from_addr(
            self._process_handle,
            ctypes.c_ulonglong(pc),
            ctypes.byref(displacement),
            sym_buf,
        ):
            name_len = min(sym_ptr[0].NameLen, _MAX_SYM_NAME)
            raw_name: bytes = bytes(sym_buf[sym_header_size : sym_header_size + name_len])
            return raw_name.rstrip(b"\x00").decode("utf-8", errors="ignore"), displacement.value
        return "", 0

    def _resolve_module(self, pc: int) -> str:
        """Resolve a PC to the owning module name via ``SymGetModuleInfo64``.

        Args:
            pc: Program counter / instruction pointer to resolve.

        Returns:
            str: Module name, or the empty string when resolution fails.
        """
        if self._dbghelp is None or self._process_handle is None:
            return ""

        sym_get_mod = self._dbghelp.SymGetModuleInfo64
        sym_get_mod.argtypes = [
            wintypes.HANDLE,
            ctypes.c_ulonglong,
            ctypes.POINTER(IMAGEHLP_MODULE64),
        ]
        sym_get_mod.restype = wintypes.BOOL

        mod_info = IMAGEHLP_MODULE64()
        mod_info.SizeOfStruct = ctypes.sizeof(IMAGEHLP_MODULE64)
        if sym_get_mod(
            self._process_handle,
            ctypes.c_ulonglong(pc),
            ctypes.byref(mod_info),
        ):
            raw_name: bytes = bytes(mod_info.ModuleName)
            return raw_name.rstrip(b"\x00").decode("utf-8", errors="ignore")
        return ""

    # ------------------------------------------------------------------
    # SEH chain
    # ------------------------------------------------------------------

    async def get_seh_chain(self, tid: int) -> list[dict[str, object]]:
        """Get the SEH exception handler chain for a thread.

        Reads the TEB to get the initial exception list pointer, then
        traverses the linked list of EXCEPTION_REGISTRATION_RECORD
        structures via ReadProcessMemory.

        Args:
            tid: Thread ID.

        Returns:
            list[dict[str, object]]: List of SEH handler dicts.

        Raises:
            ToolError: If operation fails.
        """
        _logger.debug("process_get_seh_chain_started", tid=tid)
        if self._process_handle is None:
            _logger.error("process_not_attached", operation="get_seh_chain")
            raise ToolError(_ERR_NOT_ATTACHED)

        if not self._target_is_wow64() and self._kernel32 is not None:
            target_is_64bit = self._target_is_64bit(self._process_handle)
            if target_is_64bit:
                raise ToolError(_ERR_SEH_NOT_APPLICABLE_X64)

        teb = await self.read_teb(tid)
        seh_frame_addr = teb.get("seh_frame")
        if not isinstance(seh_frame_addr, int) or seh_frame_addr == 0:
            return []

        chain: list[dict[str, object]] = []
        current = seh_frame_addr
        ptr_size = struct.calcsize("P")
        max_depth = 256

        for _ in range(max_depth):
            if current in {0, _SEH_TERMINAL_64, _SEH_TERMINAL_32}:
                break

            try:
                record_data = self._sync_read_memory(current, ptr_size * 2)
            except ToolError:
                _logger.warning("seh_chain_read_failed", address=hex(current))
                break

            if ptr_size == _PTR_SIZE_64:
                next_ptr, handler = struct.unpack("<QQ", record_data)
            else:
                next_ptr, handler = struct.unpack("<II", record_data)

            chain.append({
                "address": current,
                "handler_address": handler,
                "next": next_ptr,
            })

            current = next_ptr

        return chain

    # ------------------------------------------------------------------
    # Mitigation policies
    # ------------------------------------------------------------------

    async def get_mitigation_policies(self, pid: int | None = None) -> dict[str, object]:
        """Query process mitigation policies (DEP, ASLR, CFG, etc.).

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            dict[str, object]: Dict of policy name to status/flags.

        Raises:
            ToolError: If operation fails.
        """
        _logger.debug("process_get_mitigation_policies_started", pid=pid)
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="get_mitigation_policies")
            raise ToolError(_ERR_KERNEL32_NA)

        target_pid = pid or self._attached_pid
        close_handle = False
        proc_handle: int | None = None

        if target_pid is not None and target_pid != self._attached_pid:
            inherit_handle = False
            proc_handle = self._kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, inherit_handle, target_pid)
            close_handle = True
        elif self._process_handle is not None:
            proc_handle = self._process_handle
        else:
            proc_handle = self._kernel32.GetCurrentProcess()

        if not proc_handle:
            raise ToolError(_ERR_OPEN_FAILED)

        try:
            policies: dict[str, object] = {}
            policy_queries: list[tuple[str, int, type[ctypes.Structure]]] = [
                ("DEP", ProcessDEPPolicy, PROCESS_MITIGATION_DEP_POLICY),
                ("ASLR", ProcessASLRPolicy, PROCESS_MITIGATION_ASLR_POLICY),
                ("DynamicCode", ProcessDynamicCodePolicy, PROCESS_MITIGATION_DYNAMIC_CODE_POLICY),
                ("StrictHandleCheck", ProcessStrictHandleCheckPolicy, PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY),
                ("SystemCallDisable", ProcessSystemCallDisablePolicy, PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY),
                ("CFG", ProcessControlFlowGuardPolicy, PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY),
                ("BinarySignature", ProcessSignaturePolicy, PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY),
                ("FontDisable", ProcessFontDisablePolicy, PROCESS_MITIGATION_FONT_DISABLE_POLICY),
                ("ImageLoad", ProcessImageLoadPolicy, PROCESS_MITIGATION_IMAGE_LOAD_POLICY),
            ]

            get_policy = getattr(self._kernel32, "GetProcessMitigationPolicy", None)
            if get_policy is None:
                return {"error": "GetProcessMitigationPolicy not available"}

            for name, policy_class, struct_type in policy_queries:
                policy = struct_type()
                try:
                    if get_policy(proc_handle, policy_class, ctypes.byref(policy), ctypes.sizeof(policy)):
                        flags_val = int(getattr(policy, "Flags", 0))
                        policies[name] = self._decode_mitigation_flags(name, flags_val, policy)
                    else:
                        policies[name] = {"enabled": False, "error": "query failed"}
                except (OSError, ctypes.ArgumentError):
                    policies[name] = {"enabled": False, "error": "not supported"}

            return policies
        finally:
            if close_handle and proc_handle:
                self._kernel32.CloseHandle(proc_handle)

    @staticmethod
    def _decode_mitigation_flags(
        policy_name: str,
        flags_val: int,
        policy_struct: ctypes.Structure,
    ) -> dict[str, object]:
        """Decode a mitigation policy's ``Flags`` DWORD into named bitfields.

        Each Win32 mitigation policy has its own bit-position layout
        (see :data:`_MITIGATION_FLAG_NAMES`). This helper expands
        ``flags_val`` into the per-bit booleans Microsoft documents,
        plus a top-level ``enabled`` field that reflects the *primary*
        bit for that policy (e.g. ``Enable`` for DEP,
        ``EnableControlFlowGuard`` for CFG). The full ``flags`` integer
        and any reserved-bit residue are also surfaced so callers can
        observe Microsoft additions that post-date this code.

        Args:
            policy_name: Logical policy key (e.g. ``"DEP"``, ``"ASLR"``).
            flags_val: Raw ``Flags`` DWORD returned by
                ``GetProcessMitigationPolicy``.
            policy_struct: The populated policy structure. Used to read
                policy-specific extra fields (e.g. DEP's ``Permanent``).

        Returns:
            dict[str, object]: Decoded policy fields. Always contains
            ``enabled`` (bool), ``flags`` (raw int),
            ``flags_hex`` (hex string), and one boolean per documented
            bit. ``reserved`` carries any bits the layout does not name.
        """
        bit_names = _MITIGATION_FLAG_NAMES.get(policy_name, ())
        decoded: dict[str, object] = {
            "flags": flags_val,
            "flags_hex": f"0x{flags_val:08X}",
        }
        consumed_mask = 0
        for bit_index, field_name in enumerate(bit_names):
            decoded[field_name] = bool(flags_val & (1 << bit_index))
            consumed_mask |= 1 << bit_index

        residue = flags_val & ~consumed_mask
        if residue:
            decoded["reserved"] = residue

        primary_field = _MITIGATION_PRIMARY_FLAG.get(policy_name)
        if primary_field is not None:
            decoded["enabled"] = bool(decoded.get(primary_field))
        else:
            decoded["enabled"] = bool(flags_val)

        if policy_name == "DEP":
            decoded["Permanent"] = bool(getattr(policy_struct, "Permanent", 0))

        return decoded

    # ------------------------------------------------------------------
    # High-level enumeration helpers (named-API aliases)
    # ------------------------------------------------------------------

    async def enumerate_system_processes(self) -> list[dict[str, object]]:
        """Enumerate all running processes and return dict-formatted records.

        Returns:
            list[dict[str, object]]: List of dicts with ``pid``, ``name``,
                ``parent_pid``, and ``thread_count`` fields.

        Raises:
            ToolError: If enumeration fails.
        """
        _logger.debug("enumerate_system_processes_started")
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        self._kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        snapshot: int = self._kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot == INVALID_HANDLE_VALUE:
            raise ToolError(_ERR_SNAPSHOT_FAILED)

        results: list[dict[str, object]] = []
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

        try:
            if not self._kernel32.Process32First(snapshot, ctypes.byref(entry)):
                error_code: int = ctypes.get_last_error()
                if error_code != _ERROR_NO_MORE_FILES:
                    msg = _ERR_SNAPSHOT_FAILED + f" (Process32First: {error_code})"
                    raise ToolError(msg)
                return results
            while True:
                results.append({
                    "pid": entry.th32ProcessID,
                    "name": entry.szExeFile.decode("utf-8", errors="ignore"),
                    "parent_pid": entry.th32ParentProcessID,
                    "thread_count": entry.cntThreads,
                })
                if not self._kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                    break
        finally:
            self._kernel32.CloseHandle(snapshot)

        return results

    async def enumerate_handles(self, pid: int | None = None) -> list[dict[str, object]]:
        """Enumerate open handles for a process.

        Uses ``NtQuerySystemInformation`` with ``SystemExtendedHandleInformation``.
        Each entry exposes the raw ``object_type_index`` numeric field.

        Args:
            pid: Process ID to filter on. Returns all handles when ``None``.

        Returns:
            list[dict[str, object]]: List of handle dicts with keys
                ``pid``, ``handle_value``, ``object_type_index``,
                ``granted_access``, ``object_address``.

        Raises:
            ToolError: If ntdll is unavailable or the query fails.
        """
        _logger.debug("enumerate_handles_started", pid=pid)
        if self._ntdll is None:
            raise ToolError(_ERR_NTDLL_NA)
        buffer, num_handles, entry_size = self._query_extended_handles_buffer()
        header_size = ctypes.sizeof(ctypes.c_void_p) * 2
        handles: list[dict[str, object]] = []
        for i in range(num_handles):
            entry_ptr = ctypes.cast(
                ctypes.byref(buffer, header_size + i * entry_size),
                ctypes.POINTER(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX),
            )
            entry = entry_ptr.contents

            entry_pid = entry.UniqueProcessId
            if not isinstance(entry_pid, int):
                continue
            if pid is not None and entry_pid != pid:
                continue

            handles.append({
                "pid": entry_pid,
                "handle_value": entry.HandleValue or 0,
                "object_type_index": entry.ObjectTypeIndex,
                "granted_access": entry.GrantedAccess,
                "object_address": entry.Object or 0,
            })

        return handles

    async def enumerate_heaps(self, pid: int | None = None) -> list[dict[str, object]]:
        """Enumerate process heaps with per-heap block details.

        Uses ``Toolhelp32Snapshot`` to walk the heap list and each heap's
        blocks via ``Heap32First`` / ``Heap32Next``.

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            list[dict[str, object]]: List of heap dicts with ``id``, ``flags``,
                and ``blocks`` (list of block dicts with ``address``, ``size``,
                ``flags``).

        Raises:
            ToolError: If operation fails.
        """
        _logger.debug("enumerate_heaps_started", pid=pid)
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        target_pid = pid or self._attached_pid
        if target_pid is None:
            raise ToolError(_ERR_NO_PROCESS)

        self._kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        snapshot: int = self._kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, target_pid)
        if snapshot == INVALID_HANDLE_VALUE:
            _logger.warning("heap_snapshot_failed", pid=target_pid, error_code=ctypes.get_last_error())
            return []

        heaps: list[dict[str, object]] = []
        hl = HEAPLIST32()
        hl.dwSize = ctypes.sizeof(HEAPLIST32)

        heap32first = getattr(self._kernel32, "Heap32First", None)
        heap32next = getattr(self._kernel32, "Heap32Next", None)

        try:
            if self._kernel32.Heap32ListFirst(snapshot, ctypes.byref(hl)):
                while True:
                    blocks: list[dict[str, object]] = []
                    if heap32first is not None and heap32next is not None:
                        he = HEAPENTRY32()
                        he.dwSize = ctypes.sizeof(HEAPENTRY32)
                        if heap32first(ctypes.byref(he), target_pid, ctypes.c_size_t(hl.th32HeapID)):
                            while True:
                                blocks.append({
                                    "address": he.dwAddress,
                                    "size": he.dwBlockSize,
                                    "flags": he.dwFlags,
                                })
                                he.dwSize = ctypes.sizeof(HEAPENTRY32)
                                if not heap32next(ctypes.byref(he)):
                                    break

                    heaps.append({
                        "id": hl.th32HeapID,
                        "flags": hl.dwFlags,
                        "blocks": blocks,
                    })
                    hl.dwSize = ctypes.sizeof(HEAPLIST32)
                    if not self._kernel32.Heap32ListNext(snapshot, ctypes.byref(hl)):
                        break
        finally:
            self._kernel32.CloseHandle(snapshot)

        return heaps

    async def enumerate_services(self, *, active: bool = False) -> list[dict[str, object]]:
        """Enumerate Windows services.

        Args:
            active: When ``True`` limit results to services that are
                currently running.

        Returns:
            list[dict[str, object]]: List of service information dicts.

        Raises:
            ToolError: If the SCM cannot be opened.
        """
        _logger.debug("enumerate_services_started", active=active)
        if self._advapi32 is None:
            raise ToolError(_ERR_ADVAPI32_NA)

        scm = self._advapi32.OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE)
        if not scm:
            raise ToolError(_ERR_SCM_OPEN_FAILED)

        state_filter = SERVICE_ACTIVE if active else SERVICE_STATE_ALL

        try:
            bytes_needed = wintypes.DWORD(0)
            services_returned = wintypes.DWORD(0)
            resume_handle = wintypes.DWORD(0)

            self._advapi32.EnumServicesStatusExW(
                scm,
                0,
                SERVICE_WIN32,
                state_filter,
                None,
                0,
                ctypes.byref(bytes_needed),
                ctypes.byref(services_returned),
                ctypes.byref(resume_handle),
                None,
            )

            buf_size = bytes_needed.value
            if buf_size == 0:
                return []

            buffer = ctypes.create_string_buffer(buf_size)
            if not self._advapi32.EnumServicesStatusExW(
                scm,
                0,
                SERVICE_WIN32,
                state_filter,
                buffer,
                buf_size,
                ctypes.byref(bytes_needed),
                ctypes.byref(services_returned),
                ctypes.byref(resume_handle),
                None,
            ):
                raise ToolError(_ERR_ENUM_SVC)

            return self._parse_service_entries(buffer, services_returned.value, None)
        finally:
            self._advapi32.CloseServiceHandle(scm)

    async def time_thread_wait(self, tid: int, timeout_ms: int = 0) -> dict[str, object]:
        """Wait on a thread handle and measure elapsed time.

        Opens the thread with ``OpenThread``, calls ``WaitForSingleObject``
        with the given timeout, records elapsed microseconds, and returns a
        structured result.

        Args:
            tid: Thread ID to wait on.
            timeout_ms: Wait timeout in milliseconds (0 = return immediately).

        Returns:
            dict[str, object]: Dict with keys ``result`` (``"signaled"``,
                ``"timeout"``, ``"failed"``, or ``"other_<code>"``),
                and ``elapsed_us`` (int microseconds).

        Raises:
            ToolError: If the thread cannot be opened.
        """
        _logger.debug("time_thread_wait_started", tid=tid, timeout_ms=timeout_ms)
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        inherit_handle = False
        handle: int = self._kernel32.OpenThread(THREAD_QUERY_INFORMATION, inherit_handle, tid)
        if not handle:
            error_code: int = ctypes.get_last_error()
            msg = _ERR_THREAD_OPEN_FAILED + f" (tid={tid}, error={error_code})"
            raise ToolError(msg)

        try:
            start = time.perf_counter()
            wait_result: int = self._kernel32.WaitForSingleObject(handle, timeout_ms)
            elapsed_us = int((time.perf_counter() - start) * 1_000_000)

            if wait_result == WAIT_OBJECT_0:
                result_str = "signaled"
            elif wait_result == WAIT_TIMEOUT:
                result_str = "timeout"
            elif wait_result == WAIT_FAILED:
                result_str = "failed"
            else:
                result_str = f"other_{wait_result}"

            return {"result": result_str, "elapsed_us": elapsed_us}
        finally:
            self._kernel32.CloseHandle(handle)

    async def duplicate_token(self, pid: int) -> int:
        """Duplicate the primary token of a process.

        Opens the process, opens its token, and calls
        ``DuplicateTokenEx`` to produce a new primary token. The caller
        is responsible for closing the returned handle via
        ``kernel32.CloseHandle``.

        Args:
            pid: Process ID whose token to duplicate.

        Returns:
            int: Handle value of the duplicated token.

        Raises:
            ToolError: If the process or token cannot be opened, or
                duplication fails.
        """
        _logger.debug("duplicate_token_started", pid=pid)
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)
        if self._advapi32 is None:
            raise ToolError(_ERR_ADVAPI32_NA)

        inherit_handle = False
        proc_handle: int = self._kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, inherit_handle, pid)
        if not proc_handle:
            raise ToolError(_ERR_OPEN_FAILED)

        try:
            token_handle = wintypes.HANDLE()
            if not self._advapi32.OpenProcessToken(
                proc_handle,
                TOKEN_DUPLICATE | TOKEN_QUERY,
                ctypes.byref(token_handle),
            ):
                raise ToolError(_ERR_ACCESS_HANDLE_OPEN)

            try:
                dup_handle = wintypes.HANDLE()
                security_impersonation = 2
                token_primary = 1
                if not self._advapi32.DuplicateTokenEx(
                    token_handle,
                    TOKEN_ALL_ACCESS,
                    None,
                    security_impersonation,
                    token_primary,
                    ctypes.byref(dup_handle),
                ):
                    msg = "DuplicateTokenEx failed"
                    raise ToolError(msg)

                dup_value = dup_handle.value
                if dup_value is None:
                    msg = "DuplicateTokenEx returned null handle"
                    raise ToolError(msg)
                return dup_value
            finally:
                self._kernel32.CloseHandle(token_handle)
        finally:
            self._kernel32.CloseHandle(proc_handle)

    async def remove_privilege(self, pid: int, privilege_name: str) -> bool:
        """Remove a privilege from the primary token of a process.

        Args:
            pid: Process ID.
            privilege_name: Name of the privilege to remove (e.g.
                ``"SeShutdownPrivilege"``).

        Returns:
            bool: ``True`` if the privilege was successfully removed,
                ``False`` if it was not present or the operation was not
                applicable.

        Raises:
            ToolError: If the process or token cannot be opened.
        """
        _logger.debug("remove_privilege_started", pid=pid, privilege_name=privilege_name)
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)
        if self._advapi32 is None:
            raise ToolError(_ERR_ADVAPI32_NA)

        inherit_handle = False
        proc_handle: int = self._kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, inherit_handle, pid)
        if not proc_handle:
            raise ToolError(_ERR_OPEN_FAILED)

        try:
            token_handle = wintypes.HANDLE()
            if not self._advapi32.OpenProcessToken(
                proc_handle,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                ctypes.byref(token_handle),
            ):
                raise ToolError(_ERR_ACCESS_HANDLE_OPEN)

            try:
                luid = LUID()
                if not self._advapi32.LookupPrivilegeValueW(None, privilege_name, ctypes.byref(luid)):
                    return False

                tp = TOKEN_PRIVILEGES()
                tp.PrivilegeCount = 1
                tp.Privileges[0].Luid = luid
                tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED

                disable_all = wintypes.BOOL(0)
                self._advapi32.AdjustTokenPrivileges(
                    token_handle,
                    disable_all,
                    ctypes.byref(tp),
                    ctypes.sizeof(TOKEN_PRIVILEGES),
                    None,
                    None,
                )

                last_error: int = ctypes.get_last_error()
                return last_error != ERROR_NOT_ALL_ASSIGNED
            finally:
                self._kernel32.CloseHandle(token_handle)
        finally:
            self._kernel32.CloseHandle(proc_handle)

    async def decommit_memory(self, pid: int, address: int, size: int) -> bool:
        """Decommit a region of committed memory in a process.

        Calls ``VirtualFreeEx`` with ``MEM_DECOMMIT`` to release physical
        storage for the region without releasing the virtual address range.

        Args:
            pid: Process ID.
            address: Base address of the region to decommit.
            size: Size of the region in bytes.

        Returns:
            bool: ``True`` if decommit succeeded.

        Raises:
            ToolError: If kernel32 is unavailable or the process cannot
                be opened.
        """
        _logger.debug("decommit_memory_started", pid=pid, address=address, size=size)
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        close_handle = False
        proc_handle: int | None = None

        if pid == self._attached_pid and self._process_handle is not None:
            proc_handle = self._process_handle
        else:
            inherit_handle = False
            proc_handle = self._kernel32.OpenProcess(PROCESS_VM_OPERATION, inherit_handle, pid)
            close_handle = True

        if not proc_handle:
            raise ToolError(_ERR_OPEN_FAILED)

        try:
            result: bool = bool(self._kernel32.VirtualFreeEx(proc_handle, address, size, MEM_DECOMMIT))
            if not result:
                _logger.warning("decommit_memory_failed", pid=pid, address=address, error_code=ctypes.get_last_error())
            return result
        finally:
            if close_handle and proc_handle:
                self._kernel32.CloseHandle(proc_handle)

    async def read_registry(self, hive: str, key_path: str, value_name: str) -> dict[str, object]:
        r"""Read a registry value using explicit hive, key path, and value name.

        Returns standard Windows registry type names (e.g. ``"REG_SZ"``,
        ``"REG_DWORD"``) in the ``"type"`` field, unlike the lower-level
        :meth:`reg_read_value` which uses abbreviated names.

        Args:
            hive: Registry hive abbreviation (``"HKLM"``, ``"HKCU"``,
                ``"HKCR"``, ``"HKU"``, ``"HKCC"`` or the corresponding
                ``HKEY_*`` long form).
            key_path: Subkey path within the hive (e.g.
                ``r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"``).
            value_name: Name of the registry value to read.

        Returns:
            dict[str, object]: Dict with ``"type"`` (Windows REG_* name string)
                and ``"data"`` fields.

        Raises:
            ToolError: If the hive is unknown, the key cannot be opened,
                or the value cannot be read.
        """
        _logger.debug("read_registry_started", hive=hive, key_path=key_path, value_name=value_name)
        if self._advapi32 is None:
            raise ToolError(_ERR_ADVAPI32_NA)

        full_path = f"{hive}\\{key_path}"
        root_key, subpath = self._parse_registry_path(full_path)
        hkey = wintypes.HKEY()

        if self._advapi32.RegOpenKeyExW(root_key, subpath, 0, KEY_QUERY_VALUE, ctypes.byref(hkey)) != 0:
            msg = _ERR_REG_KEY_OPEN + full_path
            raise ToolError(msg)

        try:
            raw, vtype = self._reg_query_value_grow(hkey, value_name)
            type_name = _REG_TYPE_NAMES.get(vtype, f"REG_UNKNOWN_{vtype}")

            if vtype in {_REG_TYPE_SZ, _REG_TYPE_EXPAND_SZ}:
                decoded = raw.decode("utf-16-le", errors="ignore").rstrip("\x00")
                return {"type": type_name, "data": decoded}
            if vtype == _REG_TYPE_DWORD:
                return {"type": type_name, "data": struct.unpack_from("<I", raw)[0]}
            if vtype == _REG_TYPE_QWORD:
                return {"type": type_name, "data": struct.unpack_from("<Q", raw)[0]}
            return {"type": type_name, "data": raw.hex()}
        finally:
            self._advapi32.RegCloseKey(hkey)

    async def detect_kernel_debugger(self, pid: int) -> bool:
        """Detect whether a kernel debugger port is attached to a process.

        Queries ``NtQueryInformationProcess`` with ``ProcessDebugPort``
        (class 7). A non-zero port value indicates a debugger.

        Args:
            pid: Process ID to query.

        Returns:
            bool: ``True`` if a kernel debugger port is detected.

        Raises:
            ToolError: If the process cannot be opened or the query fails.
        """
        _logger.debug("detect_kernel_debugger_started", pid=pid)
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)
        if self._ntdll is None:
            raise ToolError(_ERR_NTDLL_NA)

        inherit_handle = False
        proc_handle: int = self._kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, inherit_handle, pid)
        if not proc_handle:
            error_code: int = ctypes.get_last_error()
            msg = _ERR_OPEN_FAILED + f" (pid={pid}, error={error_code})"
            raise ToolError(msg)

        try:
            debug_port = ctypes.c_void_p(0)
            return_length = wintypes.ULONG(0)
            status: int = self._ntdll.NtQueryInformationProcess(
                proc_handle,
                ProcessDebugPort,
                ctypes.byref(debug_port),
                ctypes.sizeof(debug_port),
                ctypes.byref(return_length),
            )
            if status < 0:
                msg = _ERR_NTQUERY_PROC + f"{status & 0xFFFFFFFF:08X}"
                raise ToolError(msg)
            return bool(debug_port.value)
        finally:
            self._kernel32.CloseHandle(proc_handle)

    async def get_mitigation_policy(self, pid: int | None = None) -> dict[str, object]:
        """Query process mitigation policies with a simplified key schema.

        Returns a flat dict suitable for structured analysis consumers.
        Delegates to the full policy query and remaps the result.

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            dict[str, object]: Dict with at least the keys ``dep``, ``aslr``,
                ``cfg``, and ``sehop_via_options_mask``.

        Raises:
            ToolError: If operation fails.
        """
        _logger.debug("get_mitigation_policy_started", pid=pid)
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        full = await self.get_mitigation_policies(pid)
        empty_policy: dict[str, object] = {}

        dep_flags: dict[str, object] = cast("dict[str, object]", full.get("DEP")) if isinstance(full.get("DEP"), dict) else empty_policy
        aslr_flags: dict[str, object] = cast("dict[str, object]", full.get("ASLR")) if isinstance(full.get("ASLR"), dict) else empty_policy
        cfg_flags: dict[str, object] = cast("dict[str, object]", full.get("CFG")) if isinstance(full.get("CFG"), dict) else empty_policy

        target_pid = pid or self._attached_pid
        close_handle = False
        proc_handle: int | None = None

        no_inherit: int = 0
        if target_pid is not None and target_pid != self._attached_pid:
            proc_handle = self._kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, no_inherit, target_pid)
            close_handle = True
        elif self._process_handle is not None:
            proc_handle = self._process_handle
        else:
            proc_handle = self._kernel32.GetCurrentProcess()

        sehop_mask: int = 0
        if proc_handle:
            try:
                mask_buf = (ctypes.c_ulonglong * 2)()
                get_policy = getattr(self._kernel32, "GetProcessMitigationPolicy", None)
                if get_policy is not None and get_policy(
                    proc_handle,
                    ProcessMitigationOptionsMask,
                    ctypes.byref(mask_buf),
                    ctypes.sizeof(mask_buf),
                ):
                    sehop_mask = mask_buf[0]
            except (OSError, ctypes.ArgumentError):
                sehop_mask = 0
            finally:
                if close_handle and proc_handle:
                    self._kernel32.CloseHandle(proc_handle)
        elif close_handle and proc_handle:
            self._kernel32.CloseHandle(proc_handle)

        return {
            "dep": dep_flags.get("enabled", False),
            "aslr": aslr_flags.get("enabled", False),
            "cfg": cfg_flags.get("enabled", False),
            "sehop_via_options_mask": sehop_mask,
        }

    async def get_extension_policy(self, pid: int | None = None) -> dict[str, object]:
        """Query the extension-point disable mitigation policy for a process.

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            dict[str, object]: Dict with ``disable_extension_points`` bool.

        Raises:
            ToolError: If operation fails.
        """
        _logger.debug("get_extension_policy_started", pid=pid)
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        target_pid = pid or self._attached_pid
        close_handle = False
        proc_handle: int | None = None

        if target_pid is not None and target_pid != self._attached_pid:
            inherit_handle = False
            proc_handle = self._kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, inherit_handle, target_pid)
            close_handle = True
        elif self._process_handle is not None:
            proc_handle = self._process_handle
        else:
            proc_handle = self._kernel32.GetCurrentProcess()

        if not proc_handle:
            raise ToolError(_ERR_OPEN_FAILED)

        try:
            policy_buf = ctypes.c_ulong(0)
            get_policy = getattr(self._kernel32, "GetProcessMitigationPolicy", None)
            disabled = False
            if get_policy is not None:
                try:
                    if get_policy(
                        proc_handle,
                        ProcessExtensionPointDisablePolicy,
                        ctypes.byref(policy_buf),
                        ctypes.sizeof(policy_buf),
                    ):
                        disabled = bool(policy_buf.value & 1)
                except (OSError, ctypes.ArgumentError):
                    disabled = False
            return {"disable_extension_points": disabled}
        finally:
            if close_handle and proc_handle:
                self._kernel32.CloseHandle(proc_handle)

    # ------------------------------------------------------------------
    # Environment variables
    # ------------------------------------------------------------------

    async def get_environment(self, pid: int | None = None) -> dict[str, str]:
        """Read environment variables from process PEB.

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            dict[str, str]: Dict of environment variable name to value.

        Raises:
            ToolError: If operation fails.
        """
        _logger.debug("process_get_environment_started", pid=pid)
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="get_environment")
            raise ToolError(_ERR_KERNEL32_NA)
        if self._ntdll is None:
            _logger.error("ntdll_unavailable", operation="get_environment")
            raise ToolError(_ERR_NTDLL_NA)

        peb_info = await self.read_peb(pid)
        params_addr = peb_info.get("process_parameters_address")
        if not isinstance(params_addr, int) or params_addr == 0:
            return {}

        close_handle = False
        proc_handle: int | None = None
        target_pid = pid or self._attached_pid

        if target_pid is not None and target_pid != self._attached_pid:
            inherit_handle = False
            proc_handle = self._kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                inherit_handle,
                target_pid,
            )
            close_handle = True
        elif self._process_handle is not None:
            proc_handle = self._process_handle
        else:
            raise ToolError(_ERR_NOT_ATTACHED)

        if not proc_handle:
            raise ToolError(_ERR_OPEN_FAILED)

        try:
            return self._read_env_block(proc_handle, params_addr)
        finally:
            if close_handle and proc_handle:
                self._kernel32.CloseHandle(proc_handle)

    def _read_env_block(self, proc_handle: int, params_addr: int) -> dict[str, str]:
        """Read and parse the environment block from process parameters.

        Reads the full ``RTL_USER_PROCESS_PARAMETERS`` header to obtain
        both the ``Environment`` pointer and ``EnvironmentSize`` field,
        then reads the entire environment block without capping at 64 KiB.

        Args:
            proc_handle: Open process handle with VM_READ access.
            params_addr: Address of RTL_USER_PROCESS_PARAMETERS.

        Returns:
            dict[str, str]: Parsed environment variables.

        Raises:
            ToolError: If kernel32 is not available or WOW64 detection
                is unavailable.
        """
        _logger.debug("process_read_env_block_started", params_addr=hex(params_addr))
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="_read_env_block")
            raise ToolError(_ERR_KERNEL32_NA)

        target_is_64bit = self._target_is_64bit(proc_handle)
        params_read_size = _PARAMS_READ_SIZE_X64 if target_is_64bit else _PARAMS_READ_SIZE_X86
        params_data = ctypes.create_string_buffer(params_read_size)
        bytes_read = ctypes.c_size_t()
        if not self._kernel32.ReadProcessMemory(
            proc_handle,
            ctypes.c_void_p(params_addr),
            params_data,
            params_read_size,
            ctypes.byref(bytes_read),
        ):
            return {}

        raw = params_data.raw[: bytes_read.value]
        env_ptr, env_size = self._extract_env_pointer(raw, target_is_64bit=target_is_64bit)
        if env_ptr == 0:
            return {}

        read_size = env_size if env_size > 0 else 0x8000
        env_buffer = ctypes.create_string_buffer(read_size)
        if not self._kernel32.ReadProcessMemory(
            proc_handle,
            ctypes.c_void_p(env_ptr),
            env_buffer,
            read_size,
            ctypes.byref(bytes_read),
        ):
            return {}

        env_str = env_buffer.raw[: bytes_read.value].decode("utf-16-le", errors="ignore")
        env_vars: dict[str, str] = {}
        for line in env_str.split("\x00"):
            if "=" in line and not line.startswith("="):
                key, _, value = line.partition("=")
                env_vars[key] = value

        return env_vars

    @staticmethod
    def _extract_env_pointer(
        raw: bytes,
        *,
        target_is_64bit: bool = True,
    ) -> tuple[int, int]:
        """Extract environment pointer and size from process parameters.

        Reads ``RTL_USER_PROCESS_PARAMETERS.Environment`` and
        ``RTL_USER_PROCESS_PARAMETERS.EnvironmentSize`` at their
        architecture-correct offsets. EnvironmentSize is a ``SIZE_T``
        (uint64 on x64, uint32 on x86).

        Args:
            raw: Raw RTL_USER_PROCESS_PARAMETERS bytes (must span at
                least through EnvironmentSize: 0x3F8 bytes on x64,
                0x294 bytes on x86).
            target_is_64bit: ``True`` when the inspected structure
                belongs to a 64-bit process; ``False`` for i386 /
                WOW64 32-bit processes.

        Returns:
            tuple[int, int]: ``(env_ptr, env_size)`` where ``env_ptr``
                is the virtual address of the environment block and
                ``env_size`` is its byte length (zero when the field
                could not be read).
        """
        if target_is_64bit:
            env_ptr = struct.unpack_from("<Q", raw, _ENV_POINTER_OFFSET_X64)[0] if len(raw) >= _ENV_POINTER_OFFSET_X64 + 8 else 0
            env_size_end = _ENV_SIZE_OFFSET_X64 + 8
            env_size = struct.unpack_from("<Q", raw, _ENV_SIZE_OFFSET_X64)[0] if len(raw) >= env_size_end else 0
        else:
            env_ptr = struct.unpack_from("<I", raw, _ENV_POINTER_OFFSET_X86)[0] if len(raw) >= _ENV_POINTER_OFFSET_X86 + 4 else 0
            env_size_end = _ENV_SIZE_OFFSET_X86 + 4
            env_size = struct.unpack_from("<I", raw, _ENV_SIZE_OFFSET_X86)[0] if len(raw) >= env_size_end else 0

        return env_ptr, env_size

    # ------------------------------------------------------------------
    # Named pipe operations
    # ------------------------------------------------------------------

    async def pipe_connect(self, pipe_name: str, timeout_ms: int = 5000) -> int:
        r"""Connect to a named pipe.

        Args:
            pipe_name: Pipe name (e.g. \\.\pipe\MyPipe).
            timeout_ms: Timeout in milliseconds.

        Returns:
            int: Pipe handle value.

        Raises:
            ToolError: If connection fails.
        """
        _logger.debug("process_pipe_connect_started", pipe_name=pipe_name, timeout_ms=timeout_ms)
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="pipe_connect")
            raise ToolError(_ERR_KERNEL32_NA)

        self._kernel32.WaitNamedPipeW(pipe_name, timeout_ms)

        self._kernel32.CreateFileW.restype = wintypes.HANDLE
        handle: int = self._kernel32.CreateFileW(
            pipe_name,
            0xC0000000,
            0,
            None,
            3,
            0,
            None,
        )

        if handle in {INVALID_HANDLE_VALUE, 0}:
            _logger.error("pipe_connect_failed", pipe_name=pipe_name)
            raise ToolError(_ERR_PIPE_CONNECT_FAILED)

        _logger.info("pipe_connected", pipe_name=pipe_name, handle=handle)
        return handle

    async def pipe_read(self, handle: int, size: int) -> str:
        """Read data from a named pipe handle.

        Args:
            handle: Pipe handle.
            size: Bytes to read.

        Returns:
            str: Hex string of data read.

        Raises:
            ToolError: If read fails.
        """
        _logger.debug("process_pipe_read_started", handle=handle, size=size)
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="pipe_read")
            raise ToolError(_ERR_KERNEL32_NA)

        buffer = ctypes.create_string_buffer(size)
        bytes_read = wintypes.DWORD(0)

        if not self._kernel32.ReadFile(handle, buffer, size, ctypes.byref(bytes_read), None):
            _logger.error("pipe_read_failed", handle=handle, size=size)
            raise ToolError(_ERR_READ_FAILED)

        return buffer.raw[: bytes_read.value].hex()

    async def pipe_write(self, handle: int, data: bytes) -> int:
        """Write data to a named pipe handle.

        Args:
            handle: Pipe handle.
            data: Bytes to write.

        Returns:
            int: Bytes written.

        Raises:
            ToolError: If write fails.
        """
        _logger.debug("process_pipe_write_started", handle=handle, data_size=len(data))
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="pipe_write")
            raise ToolError(_ERR_KERNEL32_NA)

        bytes_written = wintypes.DWORD(0)
        if not self._kernel32.WriteFile(handle, data, len(data), ctypes.byref(bytes_written), None):
            _logger.error("pipe_write_failed", handle=handle, data_size=len(data))
            raise ToolError(_ERR_WRITE_FAILED)

        return bytes_written.value

    async def pipe_close(self, handle: int) -> bool:
        """Close a named pipe handle.

        Args:
            handle: Pipe handle.

        Returns:
            bool: True if closed successfully.

        Raises:
            ToolError: If kernel32 is unavailable or CloseHandle fails.
        """
        _logger.debug("process_pipe_close_started", handle=handle)
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="pipe_close")
            raise ToolError(_ERR_KERNEL32_NA)
        self._kernel32.CloseHandle.restype = wintypes.BOOL
        result: int = self._kernel32.CloseHandle(handle)
        if not result:
            _logger.error("pipe_close_failed", handle=handle)
            raise ToolError(_ERR_PIPE_CLOSE_FAILED)
        return True

    # ------------------------------------------------------------------
    # COM object enumeration
    # ------------------------------------------------------------------

    async def enumerate_com_servers(self, pid: int | None = None) -> list[dict[str, str]]:
        r"""Enumerate COM servers loaded in a process.

        Cross-references loaded DLLs against HKCR\CLSID registry entries.

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            list[dict[str, str]]: List of COM server dicts.

        Raises:
            ToolError: If advapi32 is not available.
        """
        _logger.debug("process_enumerate_com_servers_started", pid=pid)
        if self._advapi32 is None:
            _logger.error("advapi32_unavailable", operation="enumerate_com_servers")
            raise ToolError(_ERR_ADVAPI32_NA)
        modules = await self.get_modules(pid)
        dll_names = {m.name.lower(): str(m.path) for m in modules}
        return await asyncio.to_thread(self._enumerate_com_servers_sync, dll_names)

    def _enumerate_com_servers_sync(self, dll_names: dict[str, str]) -> list[dict[str, str]]:
        r"""Perform the blocking HKCR\CLSID registry walk synchronously.

        Intended to be called from :meth:`enumerate_com_servers` via
        ``asyncio.to_thread`` to avoid blocking the event loop.

        Args:
            dll_names: Map of lowercase DLL basename to loaded path.

        Returns:
            list[dict[str, str]]: Matched COM server entries.

        Raises:
            ToolError: If advapi32 is not available.
        """
        if self._advapi32 is None:
            _logger.error("advapi32_unavailable", operation="_enumerate_com_servers_sync")
            raise ToolError(_ERR_ADVAPI32_NA)

        clsid_key = wintypes.HKEY()
        result: int = self._advapi32.RegOpenKeyExW(
            HKEY_CLASSES_ROOT,
            "CLSID",
            0,
            KEY_READ,
            ctypes.byref(clsid_key),
        )
        if result != 0:
            _logger.warning("clsid_key_open_failed", result=result)
            return []

        try:
            return self._scan_clsid_entries(clsid_key, dll_names)
        finally:
            self._advapi32.RegCloseKey(clsid_key)

    def _scan_clsid_entries(
        self,
        clsid_key: wintypes.HKEY,
        dll_names: dict[str, str],
    ) -> list[dict[str, str]]:
        r"""Scan CLSID registry entries for server key matches.

        Args:
            clsid_key: Open HKCR\CLSID registry key handle.
            dll_names: Map of lowercase DLL basename to loaded path.

        Returns:
            list[dict[str, str]]: Matched COM server entries.

        Raises:
            ToolError: If advapi32 is not available.
        """
        if self._advapi32 is None:
            _logger.error("advapi32_unavailable", operation="_scan_clsid_entries")
            raise ToolError(_ERR_ADVAPI32_NA)

        com_servers: list[dict[str, str]] = []
        index = 0
        name_buf = ctypes.create_unicode_buffer(256)
        name_size = wintypes.DWORD(256)

        while True:
            name_size.value = 256
            result: int = self._advapi32.RegEnumKeyExW(
                clsid_key,
                index,
                name_buf,
                ctypes.byref(name_size),
                None,
                None,
                None,
                None,
            )
            if result != 0:
                break

            clsid_str = name_buf.value
            entries = self._check_inproc_server(clsid_key, clsid_str)
            for entry in entries:
                dll_basename = Path(entry["path"]).name.lower() if entry["path"] else ""
                if dll_basename in dll_names:
                    com_servers.append({
                        "clsid": clsid_str,
                        "server_type": entry["server_type"],
                        "dll_path": entry["path"],
                        "loaded_path": dll_names[dll_basename],
                    })
            index += 1

        return com_servers

    def _check_inproc_server(
        self,
        clsid_key: wintypes.HKEY,
        clsid_str: str,
    ) -> list[dict[str, str]]:
        r"""Check a CLSID for all server registration keys.

        Walks InprocServer, InprocServer32, Inproc, LocalServer, and
        LocalServer32 sub-keys under the given CLSID and returns the
        default value path for each key that exists and has a non-empty
        default value.

        Args:
            clsid_key: Open HKCR\CLSID registry key handle.
            clsid_str: CLSID string (e.g. ``{xxxxxxxx-...}``).

        Returns:
            list[dict[str, str]]: List of ``{server_type, path}`` dicts,
            one per registered server sub-key that resolved to a non-empty
            path.

        Raises:
            ToolError: If advapi32 is not available.
        """
        if self._advapi32 is None:
            _logger.error("advapi32_unavailable", operation="_check_inproc_server")
            raise ToolError(_ERR_ADVAPI32_NA)

        server_key_names = (
            "Inproc",
            "InprocServer",
            "InprocServer32",
            "LocalServer",
            "LocalServer32",
        )
        results: list[dict[str, str]] = []

        for key_name in server_key_names:
            server_key = wintypes.HKEY()
            sub_path = f"{clsid_str}\\{key_name}"
            if (
                self._advapi32.RegOpenKeyExW(
                    clsid_key,
                    sub_path,
                    0,
                    KEY_QUERY_VALUE,
                    ctypes.byref(server_key),
                )
                != 0
            ):
                continue

            val_buf = ctypes.create_unicode_buffer(520)
            val_size = wintypes.DWORD(520 * 2)
            val_type = wintypes.DWORD(0)

            if (
                self._advapi32.RegQueryValueExW(
                    server_key,
                    None,
                    None,
                    ctypes.byref(val_type),
                    val_buf,
                    ctypes.byref(val_size),
                )
                == 0
            ):
                path = val_buf.value
                if path:
                    results.append({"server_type": key_name, "path": path})

            self._advapi32.RegCloseKey(server_key)

        return results

    # ------------------------------------------------------------------
    # .NET CLR detection
    # ------------------------------------------------------------------

    async def detect_dotnet(self, pid: int | None = None) -> dict[str, object]:
        """Detect .NET CLR presence and version in a process.

        For each module loaded in the target process, reads the PE
        IMAGE_COR20_HEADER (COM Descriptor) data directory entry
        (index 14) from the module's image in process memory.  A
        non-zero RVA in that directory indicates the module is a managed
        assembly.  The ``#~`` / ``#-`` stream StorageHeader version
        string is then read from the .NET MetaData root to obtain the
        exact framework version (e.g. ``"v4.0.30319"``).

        When process memory cannot be read (e.g. the bridge is not
        attached and the process cannot be opened with VM-read rights),
        the method falls back to CLR DLL name heuristics so that the
        caller always receives a usable result.

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            dict[str, object]: Dict containing:

            - ``managed`` (``bool``): ``True`` if any loaded module
              carries a non-zero COM Descriptor directory entry.
            - ``version`` (``str | None``): Framework version string
              from the MetaData StorageHeader (e.g. ``"v4.0.30319"``),
              or a heuristic string derived from CLR DLL names when the
              MetaData stream cannot be read, or ``None`` for native
              processes.
            - ``clr_loaded`` (``bool``): Alias for ``managed``; kept for
              backward compatibility.
            - ``clr_version`` (``str | None``): Alias for ``version``; kept
              for backward compatibility.
            - ``runtime_dlls`` (``list[str]``): CLR runtime DLL basenames
              found in the module list.
        """
        _logger.debug("process_detect_dotnet_started", pid=pid)
        modules = await self.get_modules(pid)

        clr_dll_names = {
            "mscoree.dll",
            "clr.dll",
            "coreclr.dll",
            "clrjit.dll",
            "mscorwks.dll",
            "mscorjit.dll",
            "mscorlib.dll",
            "hostfxr.dll",
            "hostpolicy.dll",
            "system.private.corelib.dll",
        }

        found_dlls: list[str] = [mod.name.lower() for mod in modules if mod.name.lower() in clr_dll_names]

        proc_handle, owned_handle = self._open_process_for_vm_read(pid)
        managed = False
        metadata_version: str | None = None

        if proc_handle is not None:
            try:
                for mod in modules:
                    result = self._read_cor20_version(proc_handle, mod.base_address)
                    if result is not None:
                        managed = True
                        metadata_version = result
                        break
            finally:
                if owned_handle and self._kernel32 is not None:
                    self._kernel32.CloseHandle(proc_handle)

        if not managed and found_dlls:
            managed = True

        if managed and metadata_version is None:
            if "coreclr.dll" in found_dlls or "system.private.corelib.dll" in found_dlls:
                metadata_version = ".NET Core/5+"
            elif "clr.dll" in found_dlls:
                metadata_version = ".NET Framework 4.x"
            elif "mscorwks.dll" in found_dlls:
                metadata_version = ".NET Framework 2.x/3.x"
            elif "mscoree.dll" in found_dlls:
                metadata_version = ".NET Framework"

        return {
            "managed": managed,
            "version": metadata_version,
            "clr_loaded": managed,
            "clr_version": metadata_version,
            "runtime_dlls": found_dlls,
        }

    def _open_process_for_vm_read(self, pid: int | None) -> tuple[int | None, bool]:
        """Open a process handle with VM-read rights.

        Reuses the already-open handle when the target PID matches the
        currently attached process.  Opens a new handle otherwise and
        returns ``owned=True`` so the caller knows to close it.

        Args:
            pid: Process ID to open.  When ``None``, uses
                ``_attached_pid``.

        Returns:
            tuple[int | None, bool]: ``(handle, owned)`` where ``handle``
            is a process handle suitable for ``ReadProcessMemory`` (or
            ``None`` when unavailable) and ``owned`` is ``True`` when
            the caller is responsible for closing the handle.
        """
        if self._kernel32 is None:
            return None, False
        target_pid = pid or self._attached_pid
        if target_pid is None:
            return None, False
        if target_pid == self._attached_pid and self._process_handle is not None:
            return self._process_handle, False
        handle: int = self._kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            0,
            target_pid,
        )
        if not handle:
            _logger.warning("dotnet_process_open_failed", pid=target_pid)
            return None, False
        return handle, True

    @staticmethod
    def _parse_pe_com_descriptor(data: bytes) -> tuple[int, list[dict[str, int | str]]] | None:
        """Parse PE headers from a raw byte buffer and return the COM descriptor RVA.

        Args:
            data: Raw bytes from the start of a PE image (at least
                ``_DOTNET_MIN_HEADER_READ`` bytes).

        Returns:
            tuple[int, list[dict[str, int | str]]] | None: ``(com_rva,
            sections)`` on success, or ``None`` when the image is not a
            valid PE or has no COM Descriptor directory entry.
        """
        try:
            nt_offset = read_dos_e_lfanew(data)
            if nt_offset <= 0 or len(data) < nt_offset + 4:
                return None
            if data[nt_offset : nt_offset + 4] != PE_SIGNATURE:
                return None
            _, num_sections, size_of_optional_header, _ = unpack_coff_header(data, nt_offset + 4)
            is_pe64 = is_pe64_optional_header(data, nt_offset + PE_OPTIONAL_HEADER_OFFSET)
            dd_off = get_data_directory_offset(nt_offset, is_pe64=is_pe64, entry_index=_PE_DATA_DIR_COM_DESCRIPTOR)
            if dd_off + 8 > len(data):
                return None
            com_rva, com_size = read_data_directory_entry(data, dd_off)
            if com_rva == 0 or com_size == 0:
                return None
            sections_off = nt_offset + PE_OPTIONAL_HEADER_OFFSET + size_of_optional_header
            sections = list(iterate_section_headers(data, sections_off, num_sections))
        except struct.error:
            return None
        return com_rva, sections

    def _read_cor20_version(self, proc_handle: int, base_address: int) -> str | None:
        """Read the .NET MetaData version string from a module image.

        Reads the module's PE headers from process memory, locates the
        COM Descriptor (COR20) data directory entry (index 14), then
        follows the MetaData RVA to read the StorageHeader version
        string.

        Args:
            proc_handle: Open process handle with VM-read rights.
            base_address: Module base address in the target process.

        Returns:
            str | None: MetaData StorageHeader version string (e.g.
            ``"v4.0.30319"``), or ``None`` when the module is not
            managed or the headers cannot be parsed.
        """
        if self._kernel32 is None:
            return None
        header_buf = ctypes.create_string_buffer(_DOTNET_MIN_HEADER_READ)
        bytes_read = ctypes.c_size_t()
        if not self._kernel32.ReadProcessMemory(
            proc_handle,
            ctypes.c_void_p(base_address),
            header_buf,
            _DOTNET_MIN_HEADER_READ,
            ctypes.byref(bytes_read),
        ):
            return None
        data = header_buf.raw[: bytes_read.value]
        if len(data) < PE_OPTIONAL_HEADER_OFFSET + 4:
            return None
        parsed = self._parse_pe_com_descriptor(data)
        if parsed is None:
            return None
        com_rva, sections_list = parsed
        cor20_buf = ctypes.create_string_buffer(_DOTNET_COR20_HEADER_SIZE)
        cor20_read = ctypes.c_size_t()
        if (
            not self._kernel32.ReadProcessMemory(
                proc_handle,
                ctypes.c_void_p(base_address + com_rva),
                cor20_buf,
                _DOTNET_COR20_HEADER_SIZE,
                ctypes.byref(cor20_read),
            )
            or cor20_read.value < _DOTNET_COR20_HEADER_SIZE
        ):
            return None
        try:
            meta_rva = int(struct.unpack_from("<I", cor20_buf.raw, 8)[0])
        except struct.error:
            return None
        if meta_rva == 0:
            return None
        return self._read_metadata_version(proc_handle, base_address, meta_rva, sections_list)

    def _read_metadata_version(
        self,
        proc_handle: int,
        base_address: int,
        meta_rva: int,
        sections: list[dict[str, int | str]],
    ) -> str | None:
        """Read the version string from a .NET MetaData root.

        Translates ``meta_rva`` to a virtual address via the section table
        for on-disk-layout images; falls back to treating the RVA as a
        direct virtual offset relative to ``base_address`` for
        loader-mapped in-memory images where virtual address equals RVA.

        Reads the ECMA-335 CLI MetaData root header and extracts the
        null-terminated version string stored at offset 16.

        Args:
            proc_handle: Open process handle with VM-read rights.
            base_address: Module base address in the target process.
            meta_rva: Relative Virtual Address of the MetaData root.
            sections: Section header dicts as returned by
                :func:`~intellicrack.bridges._pe_format.iterate_section_headers`.

        Returns:
            str | None: Version string (e.g. ``"v4.0.30319"``), or
            ``None`` when the signature is invalid or the read fails.
        """
        if self._kernel32 is None:
            return None
        file_off = rva_to_file_offset(sections, meta_rva)
        meta_va = base_address + (file_off if file_off is not None else meta_rva)
        meta_buf = ctypes.create_string_buffer(_DOTNET_METADATA_VERSION_MAX + 20)
        bytes_read = ctypes.c_size_t()
        if not self._kernel32.ReadProcessMemory(
            proc_handle,
            ctypes.c_void_p(meta_va),
            meta_buf,
            _DOTNET_METADATA_VERSION_MAX + _DOTNET_METADATA_MIN_SIZE,
            ctypes.byref(bytes_read),
        ):
            return None
        meta_data = meta_buf.raw[: bytes_read.value]
        if len(meta_data) < _DOTNET_METADATA_MIN_SIZE:
            return None
        try:
            signature = int(struct.unpack_from("<I", meta_data, 0)[0])
            if signature != _DOTNET_METADATA_SIGNATURE:
                return None
            version_length = int(struct.unpack_from("<I", meta_data, 12)[0])
            if version_length == 0 or version_length > _DOTNET_METADATA_VERSION_MAX:
                return None
            version_bytes = meta_data[16 : 16 + version_length]
            version_str = version_bytes.split(b"\x00", 1)[0].decode("ascii", errors="replace").strip()
        except struct.error:
            return None
        else:
            return version_str or None

    # ------------------------------------------------------------------
    # Driver communication
    # ------------------------------------------------------------------

    async def device_open(self, device_path: str) -> int:
        r"""Open a device driver path for IOCTL communication.

        Args:
            device_path: Device path (e.g. \\.\MyDriver).

        Returns:
            int: Device handle value.

        Raises:
            ToolError: If open fails.
        """
        _logger.debug("process_device_open_started", device_path=device_path)
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="device_open")
            raise ToolError(_ERR_KERNEL32_NA)

        self._kernel32.CreateFileW.restype = wintypes.HANDLE
        handle: int = self._kernel32.CreateFileW(
            device_path,
            0xC0000000,
            0,
            None,
            3,
            0,
            None,
        )

        if handle in {INVALID_HANDLE_VALUE, 0}:
            _logger.error("device_open_failed", device_path=device_path)
            raise ToolError(_ERR_DEVICE_OPEN_FAILED)

        _logger.info("device_opened", device_path=device_path, handle=handle)
        return handle

    async def device_ioctl(
        self,
        handle: int,
        ioctl_code: int,
        input_data: str | None = None,
        output_size: int = 4096,
    ) -> str:
        """Send an IOCTL to an open device handle.

        Args:
            handle: Device handle.
            ioctl_code: IOCTL control code.
            input_data: Hex string input data (e.g. ``"deadbeef"``), or
                ``None`` for no input buffer.
            output_size: Expected output buffer size.

        Returns:
            str: Hex string of output data.

        Raises:
            ValueError: If input_data is not a valid hex string.
            ToolError: If kernel32 is unavailable or IOCTL fails.
        """
        _logger.info(
            "process_device_ioctl_started",
            handle=handle,
            ioctl_code=hex(ioctl_code),
            output_size=output_size,
        )
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="device_ioctl")
            raise ToolError(_ERR_KERNEL32_NA)

        input_bytes: bytes | None = None
        if input_data is not None:
            if not re.fullmatch(r"[0-9a-fA-F]*", input_data):
                _logger.error("device_ioctl_invalid_hex", input_data=input_data)
                raise ValueError(_ERR_INVALID_HEX)
            input_bytes = bytes.fromhex(input_data)

        output_buffer = ctypes.create_string_buffer(output_size)
        bytes_returned = wintypes.DWORD(0)

        input_buf: bytes | None = input_bytes
        input_len: int = len(input_bytes) if input_bytes is not None else 0

        if not self._kernel32.DeviceIoControl(
            handle,
            ioctl_code,
            input_buf,
            input_len,
            output_buffer,
            output_size,
            ctypes.byref(bytes_returned),
            None,
        ):
            _logger.error("device_ioctl_failed", handle=handle, ioctl_code=hex(ioctl_code))
            raise ToolError(_ERR_IOCTL_FAILED)

        return output_buffer.raw[: bytes_returned.value].hex()

    async def device_close(self, handle: int) -> bool:
        """Close a device handle.

        Args:
            handle: Device handle.

        Returns:
            bool: True if closed successfully.

        Raises:
            ToolError: If kernel32 is unavailable or CloseHandle fails.
        """
        _logger.debug("process_device_close_started", handle=handle)
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="device_close")
            raise ToolError(_ERR_KERNEL32_NA)
        self._kernel32.CloseHandle.restype = wintypes.BOOL
        result: int = self._kernel32.CloseHandle(handle)
        if not result:
            _logger.error("device_close_failed", handle=handle)
            raise ToolError(_ERR_DEVICE_CLOSE_FAILED)
        return True

    # ------------------------------------------------------------------
    # Job object management
    # ------------------------------------------------------------------

    async def get_job_info(self, pid: int | None = None) -> dict[str, object]:
        """Query job object information for a process.

        Reports whether the target is in a job object and, when Windows
        exposes a handle to that job (e.g. the job was created with
        ``OBJ_INHERIT`` or a name the caller can open), queries both
        ``JobObjectBasicLimitInformation`` and
        ``JobObjectExtendedLimitInformation`` via
        ``QueryInformationJobObject`` to surface limit flags, memory
        caps, affinity, priority class, active-process limit, and
        per-process / per-job timing limits.

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            dict[str, object]: Dict with ``in_job`` and, when accessible,
                ``basic_limits``, ``extended_limits``, and ``io_counters``
                sub-dicts populated from the job object's information
                classes.

        Raises:
            ToolError: If kernel32 is not available or the target
                process cannot be opened.
        """
        _logger.debug("process_get_job_info_started", pid=pid)
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="get_job_info")
            raise ToolError(_ERR_KERNEL32_NA)

        target_pid = pid or self._attached_pid
        close_handle = False
        proc_handle: int | None = None

        if target_pid is not None and target_pid != self._attached_pid:
            inherit_handle = False
            proc_handle = self._kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, inherit_handle, target_pid)
            close_handle = True
        elif self._process_handle is not None:
            proc_handle = self._process_handle
        else:
            proc_handle = self._kernel32.GetCurrentProcess()

        if not proc_handle:
            raise ToolError(_ERR_OPEN_FAILED)

        try:
            is_in_job = wintypes.BOOL(0)
            self._kernel32.IsProcessInJob(proc_handle, None, ctypes.byref(is_in_job))

            result: dict[str, object] = {"in_job": bool(is_in_job.value)}

            if is_in_job.value:
                result.update(self._query_job_details(proc_handle))

            return result
        finally:
            if close_handle and proc_handle:
                self._kernel32.CloseHandle(proc_handle)

    def _query_job_details(self, proc_handle: int) -> dict[str, object]:
        """Query basic/extended job limits for a process in a job object.

        Attempts to obtain a queryable handle to the anonymous job the
        target is assigned to. When the job cannot be re-opened (the
        common case for anonymous jobs) the function returns the empty
        dict so the caller still reports ``in_job=True`` without
        speculative fields. When a handle is obtained,
        ``JobObjectBasicLimitInformation`` and
        ``JobObjectExtendedLimitInformation`` are queried and their
        fields exposed as two sub-dicts.

        Args:
            proc_handle: Open process handle with at least
                ``PROCESS_QUERY_INFORMATION`` rights.

        Returns:
            dict[str, object]: ``basic_limits``, ``extended_limits``, and
                ``io_counters`` sub-dicts, or an empty dict if the job
                cannot be opened or queried.
        """
        if self._kernel32 is None:
            return {}

        job_handle = self._acquire_queryable_job_handle(proc_handle)
        if job_handle is None:
            return {}

        try:
            return self._read_job_information(job_handle)
        finally:
            self._kernel32.CloseHandle(job_handle)

    def _acquire_queryable_job_handle(self, proc_handle: int) -> int | None:
        """Acquire a ``JOB_OBJECT_QUERY``-right handle to a process's job.

        Anonymous jobs (the overwhelmingly common case on modern
        Windows) cannot be re-opened via ``OpenJobObjectW`` because they
        have no name. This implementation enumerates the system handle
        table via ``NtQuerySystemInformation(SystemExtendedHandleInformation)``,
        filters to entries owned by the *target* process whose
        ``ObjectTypeIndex`` resolves to ``"Job"`` through the cached
        type map, opens the source process with ``PROCESS_DUP_HANDLE``
        rights, and uses ``DuplicateHandle`` with
        ``JOB_OBJECT_QUERY`` to clone the job handle into the calling
        process. The cloned handle is returned to the caller, who is
        responsible for closing it.

        Args:
            proc_handle: Open handle to the target process. Used to
                derive the target PID via ``GetProcessId``.

        Returns:
            int | None: Duplicated job object handle owned by the
            calling process, or ``None`` if no queryable job handle
            could be located (e.g. ntdll/kernel32 unavailable, target
            owns no job handle, or duplication denied).
        """
        if self._kernel32 is None or self._ntdll is None:
            return None

        target_pid = self._get_target_pid_for_handle(proc_handle)
        if target_pid == 0:
            return None

        job_indices = self._lookup_job_type_indices()
        if not job_indices:
            return None

        return self._duplicate_job_handle_from_target(target_pid, job_indices)

    def _get_target_pid_for_handle(self, proc_handle: int) -> int:
        """Return the PID owning ``proc_handle`` via ``GetProcessId``.

        Args:
            proc_handle: Open process handle.

        Returns:
            int: PID, or 0 if ``GetProcessId`` is unavailable or fails.
        """
        if self._kernel32 is None:
            return 0
        get_pid = getattr(self._kernel32, "GetProcessId", None)
        if get_pid is None:
            return 0
        get_pid.argtypes = [wintypes.HANDLE]
        get_pid.restype = wintypes.DWORD
        return int(get_pid(proc_handle) or 0)

    def _lookup_job_type_indices(self) -> set[int]:
        """Build/refresh the handle type cache and return job-type indices.

        Returns:
            set[int]: All ``ObjectTypeIndex`` values whose name is
            ``"Job"`` in the system handle type map. Empty if the map
            cannot be built.
        """
        if not self._handle_type_cache:
            self._build_handle_type_map()
        type_map = self._handle_type_cache
        if not type_map:
            return set()
        return {idx for idx, name in type_map.items() if name.lower() == "job"}

    def _duplicate_job_handle_from_target(
        self,
        target_pid: int,
        job_indices: set[int],
    ) -> int | None:
        """Duplicate the first matching job handle from ``target_pid``.

        Opens the target process with ``PROCESS_DUP_HANDLE`` rights,
        scans the system handle table for an entry whose owning PID
        matches and whose type index is in ``job_indices``, and uses
        ``DuplicateHandle`` to clone the handle into the calling
        process with ``JOB_OBJECT_QUERY`` rights.

        Args:
            target_pid: PID whose job handle to clone.
            job_indices: Object-type index values that map to ``Job``.

        Returns:
            int | None: Duplicated handle on success, ``None`` if the
            target process cannot be opened, the handle table cannot
            be queried, or no matching entry could be duplicated.
        """
        if self._kernel32 is None:
            return None
        open_process = getattr(self._kernel32, "OpenProcess", None)
        duplicate_handle = getattr(self._kernel32, "DuplicateHandle", None)
        close_handle = getattr(self._kernel32, "CloseHandle", None)
        if open_process is None or duplicate_handle is None or close_handle is None:
            return None

        try:
            buffer, num_handles, entry_size = self._query_extended_handles_buffer()
        except ToolError:
            return None

        open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        open_process.restype = wintypes.HANDLE
        duplicate_handle.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.HANDLE),
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        duplicate_handle.restype = wintypes.BOOL
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL

        inherit = wintypes.BOOL(0)
        source_proc = open_process(PROCESS_DUP_HANDLE, inherit, target_pid)
        if not source_proc:
            return None

        try:
            return self._scan_handles_for_duplicate(
                buffer,
                num_handles,
                entry_size,
                target_pid,
                job_indices,
                source_proc,
                duplicate_handle,
            )
        finally:
            close_handle(source_proc)

    def _scan_handles_for_duplicate(
        self,
        buffer: ctypes.Array[ctypes.c_char],
        num_handles: int,
        entry_size: int,
        target_pid: int,
        job_indices: set[int],
        source_proc: int,
        duplicate_handle: Callable[..., int],
    ) -> int | None:
        """Iterate handle entries and attempt one ``DuplicateHandle`` clone.

        Args:
            buffer: Raw handle-table buffer from
                ``NtQuerySystemInformation``.
            num_handles: Number of entries in the buffer.
            entry_size: ``sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)``.
            target_pid: PID whose handles to consider.
            job_indices: Type-index values that match ``Job``.
            source_proc: Open ``PROCESS_DUP_HANDLE`` handle to the
                target process.
            duplicate_handle: ``kernel32.DuplicateHandle`` callable.

        Returns:
            int | None: Duplicated handle on success, ``None`` if no
            entry could be cloned.
        """
        if self._kernel32 is None:
            return None
        header_size = ctypes.sizeof(ctypes.c_void_p) * 2
        current_proc = self._kernel32.GetCurrentProcess()
        for i in range(num_handles):
            entry_ptr = ctypes.cast(
                ctypes.byref(buffer, header_size + i * entry_size),
                ctypes.POINTER(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX),
            )
            entry = entry_ptr.contents

            entry_pid = entry.UniqueProcessId
            if not isinstance(entry_pid, int) or entry_pid != target_pid:
                continue
            if entry.ObjectTypeIndex not in job_indices:
                continue

            source_handle_value = entry.HandleValue
            if not isinstance(source_handle_value, int) or source_handle_value == 0:
                continue

            duplicated = wintypes.HANDLE(0)
            inherit_handle = wintypes.BOOL(0)
            options = wintypes.DWORD(0)
            if duplicate_handle(
                source_proc,
                wintypes.HANDLE(source_handle_value),
                current_proc,
                ctypes.byref(duplicated),
                _JOB_QUERY_INFORMATION,
                inherit_handle,
                options,
            ):
                handle_int = int(duplicated.value or 0)
                if handle_int:
                    return handle_int
        return None

    def _read_job_information(self, job_handle: int) -> dict[str, object]:
        """Read basic + extended limit info from a job handle.

        Args:
            job_handle: Handle to a job object with ``JOB_OBJECT_QUERY``
                access.

        Returns:
            dict[str, object]: Sub-dicts keyed ``basic_limits``,
                ``extended_limits``, and ``io_counters``. Sub-dicts are
                populated only for information classes that succeed;
                ``QueryInformationJobObject`` failures are logged at
                debug level and the corresponding key is omitted.
        """
        if self._kernel32 is None:
            return {}

        query = getattr(self._kernel32, "QueryInformationJobObject", None)
        if query is None:
            return {}

        query.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        query.restype = wintypes.BOOL

        result: dict[str, object] = {}

        basic = JOBOBJECT_BASIC_LIMIT_INFORMATION()
        returned = wintypes.DWORD(0)
        if query(
            job_handle,
            JobObjectBasicLimitInformation,
            ctypes.byref(basic),
            ctypes.sizeof(basic),
            ctypes.byref(returned),
        ):
            result["basic_limits"] = self._basic_limit_to_dict(basic)

        extended = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        if query(
            job_handle,
            JobObjectExtendedLimitInformation,
            ctypes.byref(extended),
            ctypes.sizeof(extended),
            ctypes.byref(returned),
        ):
            result["extended_limits"] = self._extended_limit_to_dict(extended)
            result["io_counters"] = self._io_counters_to_dict(extended.IoInfo)

        return result

    @staticmethod
    def _basic_limit_to_dict(basic: JOBOBJECT_BASIC_LIMIT_INFORMATION) -> dict[str, int]:
        """Convert a ``JOBOBJECT_BASIC_LIMIT_INFORMATION`` to a dict.

        Args:
            basic: Populated basic limit information structure.

        Returns:
            dict[str, int]: Field-by-field copy of the structure.
        """
        return {
            "per_process_user_time_limit": basic.PerProcessUserTimeLimit,
            "per_job_user_time_limit": basic.PerJobUserTimeLimit,
            "limit_flags": basic.LimitFlags,
            "minimum_working_set_size": basic.MinimumWorkingSetSize,
            "maximum_working_set_size": basic.MaximumWorkingSetSize,
            "active_process_limit": basic.ActiveProcessLimit,
            "affinity": basic.Affinity,
            "priority_class": basic.PriorityClass,
            "scheduling_class": basic.SchedulingClass,
        }

    @classmethod
    def _extended_limit_to_dict(
        cls,
        extended: JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    ) -> dict[str, object]:
        """Convert a ``JOBOBJECT_EXTENDED_LIMIT_INFORMATION`` to a dict.

        Args:
            extended: Populated extended limit information structure.

        Returns:
            dict[str, object]: Nested dict with basic limits and
                memory-limit fields.
        """
        return {
            "basic_limits": cls._basic_limit_to_dict(extended.BasicLimitInformation),
            "process_memory_limit": extended.ProcessMemoryLimit,
            "job_memory_limit": extended.JobMemoryLimit,
            "peak_process_memory_used": extended.PeakProcessMemoryUsed,
            "peak_job_memory_used": extended.PeakJobMemoryUsed,
        }

    @staticmethod
    def _io_counters_to_dict(io: IO_COUNTERS) -> dict[str, int]:
        """Convert an ``IO_COUNTERS`` struct to a dict.

        Args:
            io: Populated ``IO_COUNTERS`` instance.

        Returns:
            dict[str, int]: I/O operation and transfer counters.
        """
        return {
            "read_operation_count": io.ReadOperationCount,
            "write_operation_count": io.WriteOperationCount,
            "other_operation_count": io.OtherOperationCount,
            "read_transfer_count": io.ReadTransferCount,
            "write_transfer_count": io.WriteTransferCount,
            "other_transfer_count": io.OtherTransferCount,
        }

    # ------------------------------------------------------------------
    # GDI / User objects
    # ------------------------------------------------------------------

    async def get_gui_resources(self, pid: int | None = None) -> dict[str, int]:
        """Get GDI and User object counts for a process.

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            dict[str, int]: Dict with gdi_objects and user_objects counts.

        Raises:
            ToolError: If operation fails.
        """
        _logger.debug("process_get_gui_resources_started", pid=pid)
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="get_gui_resources")
            raise ToolError(_ERR_KERNEL32_NA)
        if self._user32 is None:
            _logger.error("user32_unavailable", operation="get_gui_resources")
            raise ToolError(_ERR_USER32_NA)

        target_pid = pid or self._attached_pid
        close_handle = False
        proc_handle: int | None = None

        if target_pid is not None and target_pid != self._attached_pid:
            inherit_handle = False
            proc_handle = self._kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, inherit_handle, target_pid)
            close_handle = True
        elif self._process_handle is not None:
            proc_handle = self._process_handle
        else:
            proc_handle = self._kernel32.GetCurrentProcess()

        if not proc_handle:
            raise ToolError(_ERR_OPEN_FAILED)

        try:
            gdi_count: int = self._user32.GetGuiResources(proc_handle, GR_GDIOBJECTS)
            user_count: int = self._user32.GetGuiResources(proc_handle, GR_USEROBJECTS)

            return {
                "gdi_objects": gdi_count,
                "user_objects": user_count,
            }
        finally:
            if close_handle and proc_handle:
                self._kernel32.CloseHandle(proc_handle)

    # ------------------------------------------------------------------
    # Registry access
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_registry_path(key_path: str) -> tuple[int, str]:
        r"""Parse a registry path into root key handle and subpath.

        Args:
            key_path: Registry path like HKLM\SOFTWARE\...

        Returns:
            tuple[int, str]: Root key handle and subpath string.

        Raises:
            ToolError: If root key prefix is invalid.
        """
        root_map: dict[str, int] = {
            "HKLM": HKEY_LOCAL_MACHINE,
            "HKEY_LOCAL_MACHINE": HKEY_LOCAL_MACHINE,
            "HKCU": HKEY_CURRENT_USER,
            "HKEY_CURRENT_USER": HKEY_CURRENT_USER,
            "HKCR": HKEY_CLASSES_ROOT,
            "HKEY_CLASSES_ROOT": HKEY_CLASSES_ROOT,
            "HKU": HKEY_USERS,
            "HKEY_USERS": HKEY_USERS,
            "HKCC": HKEY_CURRENT_CONFIG,
            "HKEY_CURRENT_CONFIG": HKEY_CURRENT_CONFIG,
        }

        parts = key_path.split("\\", 1)
        root_name = parts[0].upper()
        root_key = root_map.get(root_name)
        if root_key is None:
            msg = _ERR_INVALID_REG_ROOT + root_name
            raise ToolError(msg)

        subpath = parts[1] if len(parts) > 1 else ""
        return root_key, subpath

    async def reg_read_value(self, key_path: str, value_name: str) -> dict[str, object]:
        r"""Read a registry value.

        Args:
            key_path: Registry key path (e.g. HKLM\SOFTWARE\...).
            value_name: Value name to read.

        Returns:
            dict[str, object]: Dict with type and data fields.

        Raises:
            ToolError: If operation fails.
        """
        _logger.debug("process_reg_read_value_started", key_path=key_path, value_name=value_name)
        if self._advapi32 is None:
            _logger.error("advapi32_unavailable", operation="reg_read_value")
            raise ToolError(_ERR_ADVAPI32_NA)

        root_key, subpath = self._parse_registry_path(key_path)
        hkey = wintypes.HKEY()

        if self._advapi32.RegOpenKeyExW(root_key, subpath, 0, KEY_QUERY_VALUE, ctypes.byref(hkey)) != 0:
            msg = _ERR_REG_KEY_OPEN + key_path
            raise ToolError(msg)

        try:
            raw, vtype = self._reg_query_value_grow(hkey, value_name)

            if vtype in {_REG_TYPE_SZ, _REG_TYPE_EXPAND_SZ}:
                decoded = raw.decode("utf-16-le", errors="ignore").rstrip("\x00")
                return {"type": "string", "data": decoded}
            if vtype == _REG_TYPE_DWORD:
                return {"type": "dword", "data": struct.unpack_from("<I", raw)[0]}
            if vtype == _REG_TYPE_QWORD:
                return {"type": "qword", "data": struct.unpack_from("<Q", raw)[0]}
            return {"type": f"raw({vtype})", "data": raw.hex()}
        finally:
            self._advapi32.RegCloseKey(hkey)

    async def reg_enum_keys(self, key_path: str) -> list[str]:
        """Enumerate subkeys of a registry key.

        Args:
            key_path: Registry key path.

        Returns:
            list[str]: List of subkey name strings.

        Raises:
            ToolError: If operation fails.
        """
        _logger.debug("process_reg_enum_keys_started", key_path=key_path)
        if self._advapi32 is None:
            _logger.error("advapi32_unavailable", operation="reg_enum_keys")
            raise ToolError(_ERR_ADVAPI32_NA)

        root_key, subpath = self._parse_registry_path(key_path)
        hkey = wintypes.HKEY()

        if self._advapi32.RegOpenKeyExW(root_key, subpath, 0, KEY_ENUMERATE_SUB_KEYS, ctypes.byref(hkey)) != 0:
            msg = _ERR_REG_KEY_OPEN + key_path
            raise ToolError(msg)

        try:
            keys: list[str] = []
            index = 0
            name_buf = ctypes.create_unicode_buffer(256)
            name_size = wintypes.DWORD(256)

            while True:
                name_size.value = 256
                result: int = self._advapi32.RegEnumKeyExW(
                    hkey,
                    index,
                    name_buf,
                    ctypes.byref(name_size),
                    None,
                    None,
                    None,
                    None,
                )
                if result != 0:
                    break
                keys.append(name_buf.value)
                index += 1

            return keys
        finally:
            self._advapi32.RegCloseKey(hkey)

    async def reg_enum_values(self, key_path: str) -> list[str]:
        """Enumerate values under a registry key.

        Args:
            key_path: Registry key path.

        Returns:
            list[str]: List of value name strings.

        Raises:
            ToolError: If operation fails.
        """
        _logger.debug("process_reg_enum_values_started", key_path=key_path)
        if self._advapi32 is None:
            _logger.error("advapi32_unavailable", operation="reg_enum_values")
            raise ToolError(_ERR_ADVAPI32_NA)

        root_key, subpath = self._parse_registry_path(key_path)
        hkey = wintypes.HKEY()

        if self._advapi32.RegOpenKeyExW(root_key, subpath, 0, KEY_QUERY_VALUE, ctypes.byref(hkey)) != 0:
            msg = _ERR_REG_KEY_OPEN + key_path
            raise ToolError(msg)

        try:
            values: list[str] = []
            index = 0
            name_buf = ctypes.create_unicode_buffer(16384)
            name_size = wintypes.DWORD(16384)

            while True:
                name_size.value = 16384
                result: int = self._advapi32.RegEnumValueW(
                    hkey,
                    index,
                    name_buf,
                    ctypes.byref(name_size),
                    None,
                    None,
                    None,
                    None,
                )
                if result != 0:
                    break
                values.append(name_buf.value)
                index += 1

            return values
        finally:
            self._advapi32.RegCloseKey(hkey)

    # ------------------------------------------------------------------
    # Section object mapping
    # ------------------------------------------------------------------

    async def create_section(self, size: int, section_name: str | None = None) -> int:
        """Create a named section (file mapping) object.

        Wraps ``CreateFileMappingW`` and inspects ``GetLastError`` so the
        caller can distinguish a name collision from other failures. When
        a named section is requested and the kernel reports
        ``ERROR_ALREADY_EXISTS``, the duplicate handle returned by the
        API is closed and a ``ToolError`` carrying
        ``details["code"] == "SECTION_NAME_COLLISION"`` is raised so the
        caller can react (e.g., generate a fresh name) rather than
        silently sharing an existing backing object. Successfully
        created handles are tracked in ``self._section_handles`` so they
        can be released on :meth:`shutdown`.

        Args:
            size: Section size in bytes.
            section_name: Optional section name. Anonymous sections (name
                ``None``) cannot collide and never raise the collision
                variant.

        Returns:
            int: Section handle value.

        Raises:
            ToolError: If creation fails. ``details["code"]`` is
                ``"SECTION_NAME_COLLISION"`` when the failure was a
                duplicate name, otherwise ``"SECTION_CREATE_FAILED"``.
        """
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        self._kernel32.CreateFileMappingW.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPCWSTR,
        ]
        self._kernel32.CreateFileMappingW.restype = wintypes.HANDLE
        self._kernel32.GetLastError.argtypes = []
        self._kernel32.GetLastError.restype = wintypes.DWORD
        self._kernel32.SetLastError.argtypes = [wintypes.DWORD]
        self._kernel32.SetLastError.restype = None

        high = (size >> 32) & 0xFFFFFFFF
        low = size & 0xFFFFFFFF

        self._kernel32.SetLastError(0)
        handle_raw = self._kernel32.CreateFileMappingW(
            wintypes.HANDLE(-1),
            None,
            PAGE_READWRITE,
            high,
            low,
            section_name,
        )
        handle: int = int(handle_raw) if handle_raw else 0
        last_error: int = int(self._kernel32.GetLastError())

        if not handle:
            _logger.error(
                "section_create_failed",
                size=size,
                section_name=section_name,
                last_error=last_error,
            )
            raise ToolError(
                _ERR_SECTION_CREATE,
                error_code=last_error or None,
                details={"code": _CODE_SECTION_CREATE_FAILED, "last_error": last_error},
            )

        if last_error == _ERROR_ALREADY_EXISTS and section_name is not None:
            self._kernel32.CloseHandle(handle)
            _logger.warning(
                "section_name_collision",
                section_name=section_name,
                size=size,
            )
            raise ToolError(
                _ERR_SECTION_NAME_COLLISION,
                error_code=_ERROR_ALREADY_EXISTS,
                details={"code": _CODE_SECTION_NAME_COLLISION, "section_name": section_name},
            )

        self._section_handles[handle] = section_name or ""
        _logger.info("section_created", handle=handle, size=size, section_name=section_name)
        return handle

    async def map_section(self, handle: int, size: int) -> int:
        """Map a section into the current process address space.

        Mapped views are tracked in ``self._section_views`` keyed by
        their base address so :meth:`unmap_section` can find the owning
        section handle and so :meth:`shutdown` can release any views the
        caller forgot.

        Args:
            handle: Section handle.
            size: Size to map.

        Returns:
            int: Mapped base address.

        Raises:
            ToolError: If mapping fails.
        """
        _logger.debug("process_map_section_started", handle=handle, size=size)
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="map_section")
            raise ToolError(_ERR_KERNEL32_NA)

        address: int = cast(
            "int",
            self._kernel32.MapViewOfFile(
                handle,
                0xF001F,
                0,
                0,
                size,
            ),
        )

        if not address:
            _logger.error("section_map_failed", handle=handle, size=size)
            raise ToolError(_ERR_SECTION_MAP)

        self._section_views[address] = handle
        return address

    async def unmap_section(self, base_address: int) -> bool:
        """Unmap a previously mapped section view from the current process.

        Releases the view and, if the originating section handle is
        tracked in ``self._section_handles`` (i.e., the section was
        created via :meth:`create_section` rather than imported from
        outside), closes the section handle as well so a single
        ``unmap_section`` call leaves no kernel objects leaked. Prefers
        ``UnmapViewOfFile2`` from kernel32 when available (Windows 10
        1709+); falls back to ``UnmapViewOfFile`` otherwise.

        Args:
            base_address: Mapped base address returned from
                :meth:`map_section`.

        Returns:
            bool: True on successful unmap.

        Raises:
            ToolError: If kernel32 is unavailable, the address is not a
                tracked mapping, or the underlying unmap call fails.
                ``details["code"]`` is ``"SECTION_NOT_MAPPED"`` for
                tracking misses and ``"SECTION_UNMAP_FAILED"`` for API
                failures.
        """
        _logger.debug("process_unmap_section_started", base_address=hex(base_address))
        if self._kernel32 is None:
            _logger.error("kernel32_unavailable", operation="unmap_section")
            raise ToolError(_ERR_KERNEL32_NA)

        section_handle = self._section_views.get(base_address)
        if section_handle is None:
            _logger.warning(
                "section_unmap_unknown_base",
                base_address=hex(base_address),
            )
            raise ToolError(
                _ERR_SECTION_NOT_MAPPED,
                details={"code": _CODE_SECTION_NOT_MAPPED, "base_address": base_address},
            )

        ctypes.set_last_error(0)
        unmap_view_of_file2 = getattr(self._kernel32, "UnmapViewOfFile2", None)
        if unmap_view_of_file2 is not None:
            current_process = self._kernel32.GetCurrentProcess()
            result = unmap_view_of_file2(current_process, ctypes.c_void_p(base_address), 0)
        else:
            result = self._kernel32.UnmapViewOfFile(ctypes.c_void_p(base_address))
        last_error = ctypes.get_last_error()

        if not result:
            _logger.error(
                "section_unmap_failed",
                base_address=hex(base_address),
                last_error=last_error,
            )
            raise ToolError(
                _ERR_SECTION_UNMAP,
                error_code=last_error or None,
                details={"code": _CODE_SECTION_UNMAP_FAILED, "last_error": last_error},
            )

        del self._section_views[base_address]
        if section_handle in self._section_handles:
            self._kernel32.CloseHandle(section_handle)
            del self._section_handles[section_handle]

        _logger.info(
            "section_unmapped",
            base_address=hex(base_address),
            section_handle=section_handle,
        )
        return True

    # ------------------------------------------------------------------
    # TLS slot access
    # ------------------------------------------------------------------

    async def get_tls_values(self, tid: int, max_slots: int = 64) -> list[dict[str, object]]:
        """Read static TLS slot values for a thread.

        Reads the static TLS array directly from the TEB: TEB+0x1480 on
        x64 (64 slots of 8 bytes each) or TEB+0xE10 on x86 (64 slots of
        4 bytes each). When ``max_slots`` exceeds
        ``TLS_STATIC_SLOT_COUNT``, also reads expansion slots via the
        TlsExpansionSlots pointer at TEB+0x1780 (x64 only).

        Args:
            tid: Thread ID.
            max_slots: Maximum TLS slots to read.

        Returns:
            list[dict[str, object]]: List of TLS slot dicts with index and value.
        """
        _logger.debug("process_get_tls_values_started", tid=tid, max_slots=max_slots)

        teb = await self.read_teb(tid)
        tls_array_addr = teb.get("tls_array_base")
        if not isinstance(tls_array_addr, int) or tls_array_addr == 0:
            return []

        is_x64 = (tls_array_addr & ~0xFFFFFFFF) != 0 or struct.calcsize("P") == _PTR_SIZE_64
        ptr_size = 8 if is_x64 else 4
        fmt = "<Q" if is_x64 else "<I"
        static_count = min(max_slots, TLS_STATIC_SLOT_COUNT)
        static_read_size = static_count * ptr_size

        try:
            static_data = self._sync_read_memory(tls_array_addr, static_read_size)
        except ToolError:
            _logger.warning("tls_static_read_failed", tid=tid, address=hex(tls_array_addr), size=static_read_size)
            return []

        slots: list[dict[str, object]] = []
        for i in range(min(static_count, len(static_data) // ptr_size)):
            value = struct.unpack_from(fmt, static_data, i * ptr_size)[0]
            if value != 0:
                slots.append({"index": i, "value": value})

        if max_slots > TLS_STATIC_SLOT_COUNT and is_x64:
            teb_addr = teb.get("teb_address")
            if isinstance(teb_addr, int) and teb_addr != 0:
                await self._append_tls_expansion_slots(slots, teb_addr, max_slots, tid, fmt, ptr_size)

        return slots

    async def _append_tls_expansion_slots(
        self,
        slots: list[dict[str, object]],
        teb_addr: int,
        max_slots: int,
        tid: int,
        fmt: str,
        ptr_size: int,
    ) -> None:
        """Read TLS expansion slots and append non-zero entries to ``slots``.

        Args:
            slots: Accumulator list to extend in-place.
            teb_addr: Base address of the TEB for this thread.
            max_slots: Upper bound on total slots (including static 64).
            tid: Thread ID (for warning log context only).
            fmt: ``struct`` format string (``"<Q"`` or ``"<I"``).
            ptr_size: Pointer size in bytes (8 or 4).
        """
        exp_ptr_addr = teb_addr + _TLS_EXPANSION_OFFSET_X64
        try:
            exp_ptr_data = self._sync_read_memory(exp_ptr_addr, 8)
            exp_ptr = struct.unpack_from("<Q", exp_ptr_data, 0)[0]
            if exp_ptr == 0:
                return
            expansion_count = min(max_slots - TLS_STATIC_SLOT_COUNT, 1024)
            expansion_read_size = expansion_count * ptr_size
            try:
                exp_data = self._sync_read_memory(exp_ptr, expansion_read_size)
                for j in range(min(expansion_count, len(exp_data) // ptr_size)):
                    value = struct.unpack_from(fmt, exp_data, j * ptr_size)[0]
                    if value != 0:
                        slots.append({"index": TLS_STATIC_SLOT_COUNT + j, "value": value})
            except ToolError:
                _logger.warning("tls_expansion_read_failed", tid=tid, address=hex(exp_ptr))
        except ToolError:
            _logger.warning("tls_expansion_ptr_read_failed", tid=tid, address=hex(exp_ptr_addr))

    # ------------------------------------------------------------------
    # Fiber enumeration
    # ------------------------------------------------------------------

    async def get_fiber_data(self, tid: int) -> dict[str, object]:
        """Read fiber data pointer for a thread.

        Args:
            tid: Thread ID.

        Returns:
            dict[str, object]: Dict with fiber_data address.
        """
        _logger.debug("process_get_fiber_data_started", tid=tid)
        teb = await self.read_teb(tid)
        fiber_data = teb.get("fiber_data")

        return {
            "fiber_data": fiber_data if isinstance(fiber_data, int) else 0,
            "has_fiber": isinstance(fiber_data, int) and fiber_data != 0,
        }

    # ------------------------------------------------------------------
    # NtQuerySystemInformation bridge
    # ------------------------------------------------------------------

    async def query_system_info(self, info_class: int, buffer_size: int = 65536) -> bytes:
        """Raw NtQuerySystemInformation bridge with auto-growing buffer.

        Args:
            info_class: SystemInformationClass value.
            buffer_size: Initial buffer size.

        Returns:
            bytes: Raw output buffer.

        Raises:
            ToolError: If operation fails.
        """
        _logger.debug("process_query_system_info_started", info_class=info_class, buffer_size=buffer_size)
        if self._ntdll is None:
            _logger.error("ntdll_unavailable", operation="query_system_info")
            raise ToolError(_ERR_NTDLL_NA)

        current_size = buffer_size
        grow_statuses = {
            _STATUS_INFO_LENGTH_MISMATCH,
            _STATUS_BUFFER_OVERFLOW,
            _STATUS_BUFFER_TOO_SMALL,
        }

        while current_size <= _NTQUERY_BUF_MAX:
            buffer = ctypes.create_string_buffer(current_size)
            return_length = wintypes.ULONG(0)

            status: int = self._ntdll.NtQuerySystemInformation(
                info_class,
                buffer,
                current_size,
                ctypes.byref(return_length),
            )

            if status in grow_statuses:
                hint = return_length.value
                next_size = max(current_size * 2, hint or 0)
                if next_size <= current_size:
                    next_size = current_size * 2
                current_size = next_size
                continue

            if status < 0:
                msg = _ERR_NTQUERY_SYS + f"{status & 0xFFFFFFFF:08X}"
                raise ToolError(msg)

            return buffer.raw[: return_length.value]

        raise ToolError(_ERR_NTQUERY_SYS_BUF_MAX)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _reg_query_value_grow(
        self,
        hkey: wintypes.HKEY,
        value_name: str,
    ) -> tuple[bytes, int]:
        """Read a registry value, growing the buffer on ``ERROR_MORE_DATA``.

        Loops until ``RegQueryValueExW`` either succeeds (return code 0)
        or fails with a non-recoverable error. On ``ERROR_MORE_DATA``
        the buffer is reallocated using the kernel-supplied required
        size (or doubled, whichever is larger) and the call is retried.
        Retries are bounded by :data:`_REG_GROWTH_RETRY_LIMIT` and the
        absolute cap :data:`_REG_MAX_BUF_SIZE` so a malicious or
        runaway value cannot exhaust memory.

        Args:
            hkey: Open registry key handle.
            value_name: Name of the value to read.

        Returns:
            tuple[bytes, int]: ``(raw_value_bytes, value_type)`` where
            ``raw_value_bytes`` is the populated portion of the buffer
            and ``value_type`` is the Win32 ``REG_*`` integer.

        Raises:
            ToolError: If ``advapi32`` is unavailable, the value
                exceeds :data:`_REG_MAX_BUF_SIZE`, the retry limit is
                hit, or the kernel returns a non-``ERROR_MORE_DATA``
                failure.
        """
        if self._advapi32 is None:
            raise ToolError(_ERR_ADVAPI32_NA)

        buf_size = _REG_INITIAL_BUF_SIZE
        data_buf = ctypes.create_string_buffer(buf_size)
        data_size = wintypes.DWORD(buf_size)
        val_type = wintypes.DWORD(0)
        attempts = 0
        while True:
            data_size.value = buf_size
            rc: int = self._advapi32.RegQueryValueExW(
                hkey,
                value_name,
                None,
                ctypes.byref(val_type),
                data_buf,
                ctypes.byref(data_size),
            )
            if rc == 0:
                return data_buf.raw[: data_size.value], val_type.value
            if rc == _ERROR_MORE_DATA:
                required = data_size.value
                if required <= buf_size:
                    required = buf_size * 2
                if required > _REG_MAX_BUF_SIZE:
                    raise ToolError(_ERR_REG_VALUE_TOO_LARGE + value_name)
                attempts += 1
                if attempts > _REG_GROWTH_RETRY_LIMIT:
                    raise ToolError(_ERR_REG_VALUE_TOO_LARGE + value_name)
                buf_size = required
                data_buf = ctypes.create_string_buffer(buf_size)
                continue
            msg = _ERR_REG_VALUE_READ + value_name + f" (rc={rc})"
            raise ToolError(msg)

    @staticmethod
    def _prot_from_string(protection: str) -> int:
        """Convert a protection string to Win32 PAGE_* constant.

        Args:
            protection: Protection string like 'rwx', 'rw', 'rx', 'r', 'x'.

        Returns:
            int: Win32 PAGE_* protection value.
        """
        prot_map: dict[str, int] = {
            "rwx": PAGE_EXECUTE_READWRITE,
            "rx": PAGE_EXECUTE_READ,
            "rw": PAGE_READWRITE,
            "r": PAGE_READONLY,
            "x": PAGE_EXECUTE,
        }
        return prot_map.get(protection, PAGE_EXECUTE_READWRITE)
