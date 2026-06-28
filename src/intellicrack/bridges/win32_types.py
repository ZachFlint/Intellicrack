# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Shared Win32 ctypes structures, constants, and DLL helpers.

Pure type definitions and constant values for Win32 API interop. Used by ProcessBridge and other bridge modules that need direct Windows API
access. Contains no business logic.
"""

from __future__ import annotations

import ctypes
import functools
import sys
from ctypes import wintypes
from typing import ClassVar, Final, TypedDict

from intellicrack.core.logging import get_logger


_logger = get_logger(__name__)

_IS_WINDOWS: Final[bool] = sys.platform == "win32"


def _compute_invalid_handle_value() -> int:
    """Compute the platform-correct ``INVALID_HANDLE_VALUE`` constant.

    Uses ``wintypes.HANDLE(-1).value`` on Windows so the bit pattern matches
    what the kernel returns from APIs like ``CreateFileW`` and
    ``CreateToolhelp32Snapshot``. On 64-bit Python this yields
    ``0xFFFFFFFFFFFFFFFF``; on 32-bit Python this yields ``0xFFFFFFFF``.
    Falls back to the 32-bit DWORD-mask value on non-Windows platforms where
    the constant is unused.

    Returns:
        int: ``0xFFFFFFFFFFFFFFFF`` on 64-bit Windows, ``0xFFFFFFFF`` on
        32-bit Windows or non-Windows hosts.
    """
    if _IS_WINDOWS:
        value = wintypes.HANDLE(-1).value
        if value is not None:
            return value
    return 0xFFFFFFFF


INVALID_HANDLE_VALUE: Final[int] = _compute_invalid_handle_value()

# ---------------------------------------------------------------------------
# Process access rights
# ---------------------------------------------------------------------------
PROCESS_ALL_ACCESS: Final[int] = 0x1F0FFF
PROCESS_QUERY_INFORMATION: Final[int] = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION: Final[int] = 0x1000
PROCESS_VM_READ: Final[int] = 0x0010
PROCESS_VM_WRITE: Final[int] = 0x0020
PROCESS_VM_OPERATION: Final[int] = 0x0008
PROCESS_TERMINATE: Final[int] = 0x0001
PROCESS_SUSPEND_RESUME: Final[int] = 0x0800
PROCESS_CREATE_THREAD: Final[int] = 0x0002
PROCESS_DUP_HANDLE: Final[int] = 0x0040

# ---------------------------------------------------------------------------
# Standard access rights
# ---------------------------------------------------------------------------
SYNCHRONIZE: Final[int] = 0x00100000

# ---------------------------------------------------------------------------
# Thread access rights
# ---------------------------------------------------------------------------
THREAD_QUERY_INFORMATION: Final[int] = 0x0040
THREAD_QUERY_LIMITED_INFORMATION: Final[int] = 0x0800
THREAD_SUSPEND_RESUME: Final[int] = 0x0002
THREAD_GET_CONTEXT: Final[int] = 0x0008
THREAD_SET_CONTEXT: Final[int] = 0x0010
THREAD_ALL_ACCESS: Final[int] = 0x1F03FF

# ---------------------------------------------------------------------------
# Toolhelp32 snapshot flags
# ---------------------------------------------------------------------------
TH32CS_SNAPHEAPLIST: Final[int] = 0x00000001
TH32CS_SNAPPROCESS: Final[int] = 0x00000002
TH32CS_SNAPTHREAD: Final[int] = 0x00000004
TH32CS_SNAPMODULE: Final[int] = 0x00000008
TH32CS_SNAPMODULE32: Final[int] = 0x00000010
TH32CS_SNAPALL: Final[int] = 0x0000001F

# ---------------------------------------------------------------------------
# Memory constants
# ---------------------------------------------------------------------------
MEM_COMMIT: Final[int] = 0x1000
MEM_RESERVE: Final[int] = 0x2000
MEM_DECOMMIT: Final[int] = 0x4000
MEM_RELEASE: Final[int] = 0x8000
MEM_FREE: Final[int] = 0x10000
MEM_PRIVATE: Final[int] = 0x20000
MEM_MAPPED: Final[int] = 0x40000
MEM_IMAGE: Final[int] = 0x1000000

# ---------------------------------------------------------------------------
# Page protection constants
# ---------------------------------------------------------------------------
PAGE_NOACCESS: Final[int] = 0x01
PAGE_READONLY: Final[int] = 0x02
PAGE_READWRITE: Final[int] = 0x04
PAGE_WRITECOPY: Final[int] = 0x08
PAGE_EXECUTE: Final[int] = 0x10
PAGE_EXECUTE_READ: Final[int] = 0x20
PAGE_EXECUTE_READWRITE: Final[int] = 0x40
PAGE_EXECUTE_WRITECOPY: Final[int] = 0x80
PAGE_GUARD: Final[int] = 0x100

# ---------------------------------------------------------------------------
# Token access rights
# ---------------------------------------------------------------------------
TOKEN_QUERY: Final[int] = 0x0008
TOKEN_ADJUST_PRIVILEGES: Final[int] = 0x0020
TOKEN_DUPLICATE: Final[int] = 0x0002
TOKEN_ALL_ACCESS: Final[int] = 0xF01FF

SE_PRIVILEGE_ENABLED: Final[int] = 0x00000002
SE_PRIVILEGE_REMOVED: Final[int] = 0x00000004

ERROR_NOT_ALL_ASSIGNED: Final[int] = 1300

# ---------------------------------------------------------------------------
# NtDll information classes
# ---------------------------------------------------------------------------
SystemProcessInformation: Final[int] = 5
SystemHandleInformation: Final[int] = 16
SystemExtendedHandleInformation: Final[int] = 64

ProcessBasicInformation: Final[int] = 0
ProcessDebugPort: Final[int] = 7
ProcessWow64Information: Final[int] = 26

ThreadBasicInformation: Final[int] = 0
ThreadQuerySetWin32StartAddress: Final[int] = 9

# ---------------------------------------------------------------------------
# Context flags (AMD64)
# ---------------------------------------------------------------------------
CONTEXT_AMD64: Final[int] = 0x00100000
CONTEXT_CONTROL: Final[int] = CONTEXT_AMD64 | 0x01
CONTEXT_INTEGER: Final[int] = CONTEXT_AMD64 | 0x02
CONTEXT_SEGMENTS: Final[int] = CONTEXT_AMD64 | 0x04
CONTEXT_FLOATING_POINT: Final[int] = CONTEXT_AMD64 | 0x08
CONTEXT_DEBUG_REGISTERS: Final[int] = CONTEXT_AMD64 | 0x10
CONTEXT_FULL: Final[int] = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT
CONTEXT_ALL: Final[int] = CONTEXT_FULL | CONTEXT_SEGMENTS | CONTEXT_DEBUG_REGISTERS

# Context flags (i386)
CONTEXT_I386: Final[int] = 0x00010000
CONTEXT_I386_CONTROL: Final[int] = CONTEXT_I386 | 0x01
CONTEXT_I386_INTEGER: Final[int] = CONTEXT_I386 | 0x02
CONTEXT_I386_SEGMENTS: Final[int] = CONTEXT_I386 | 0x04
CONTEXT_I386_FLOATING_POINT: Final[int] = CONTEXT_I386 | 0x08
CONTEXT_I386_DEBUG_REGISTERS: Final[int] = CONTEXT_I386 | 0x10
CONTEXT_I386_FULL: Final[int] = CONTEXT_I386_CONTROL | CONTEXT_I386_INTEGER | CONTEXT_I386_SEGMENTS
CONTEXT_I386_ALL: Final[int] = CONTEXT_I386_FULL | CONTEXT_I386_FLOATING_POINT | CONTEXT_I386_DEBUG_REGISTERS

# ---------------------------------------------------------------------------
# PE / IMAGE_FILE_HEADER machine types (used by IsWow64Process2 and StackWalk64)
# ---------------------------------------------------------------------------
IMAGE_FILE_MACHINE_UNKNOWN: Final[int] = 0x0000
IMAGE_FILE_MACHINE_I386: Final[int] = 0x014C
IMAGE_FILE_MACHINE_AMD64: Final[int] = 0x8664
IMAGE_FILE_MACHINE_ARM: Final[int] = 0x01C0
IMAGE_FILE_MACHINE_ARM64: Final[int] = 0xAA64
IMAGE_FILE_MACHINE_ARMNT: Final[int] = 0x01C4
IMAGE_FILE_MACHINE_IA64: Final[int] = 0x0200

# ---------------------------------------------------------------------------
# PE header layout offsets (DOS / NT / OptionalHeader navigation)
# ---------------------------------------------------------------------------
PE_HEADER_OFFSET: Final[int] = 0x3C
"""Offset of the ``e_lfanew`` field inside the DOS header pointing to the NT headers."""

PE_MAGIC_OFFSET: Final[int] = 0x40
"""Byte immediately following the ``e_lfanew`` field (4-byte little-endian)."""

NT_HEADERS_OPTIONAL_OFFSET: Final[int] = 0x18
"""Offset from the NT headers signature to the start of the OptionalHeader."""

# ---------------------------------------------------------------------------
# SCM constants
# ---------------------------------------------------------------------------
SC_MANAGER_ENUMERATE_SERVICE: Final[int] = 0x0004
SC_MANAGER_ALL_ACCESS: Final[int] = 0xF003F
SERVICE_WIN32: Final[int] = 0x00000030
SERVICE_STATE_ALL: Final[int] = 0x00000003
SERVICE_ACTIVE: Final[int] = 0x00000001
SERVICE_INACTIVE: Final[int] = 0x00000002

# ---------------------------------------------------------------------------
# Mitigation policy constants
# ---------------------------------------------------------------------------
ProcessDEPPolicy: Final[int] = 0
ProcessASLRPolicy: Final[int] = 1
ProcessDynamicCodePolicy: Final[int] = 2
ProcessStrictHandleCheckPolicy: Final[int] = 3
ProcessSystemCallDisablePolicy: Final[int] = 4
ProcessMitigationOptionsMask: Final[int] = 5
ProcessExtensionPointDisablePolicy: Final[int] = 6
ProcessControlFlowGuardPolicy: Final[int] = 7
ProcessSignaturePolicy: Final[int] = 8
ProcessFontDisablePolicy: Final[int] = 9
ProcessImageLoadPolicy: Final[int] = 10

# ---------------------------------------------------------------------------
# Wait / synchronisation constants
# ---------------------------------------------------------------------------
INFINITE: Final[int] = 0xFFFFFFFF
WAIT_OBJECT_0: Final[int] = 0x00000000
WAIT_TIMEOUT: Final[int] = 0x00000102
WAIT_FAILED: Final[int] = 0xFFFFFFFF

# ---------------------------------------------------------------------------
# Generic file/object access rights (CreateFileW, CreateNamedPipeW, etc.)
# ---------------------------------------------------------------------------
GENERIC_READ: Final[int] = 0x80000000
GENERIC_WRITE: Final[int] = 0x40000000

# ---------------------------------------------------------------------------
# CreateFileW disposition values
# ---------------------------------------------------------------------------
OPEN_EXISTING: Final[int] = 3

# ---------------------------------------------------------------------------
# Pipe constants
# ---------------------------------------------------------------------------
PIPE_ACCESS_DUPLEX: Final[int] = 0x00000003
PIPE_READMODE_BYTE: Final[int] = 0x00000000
PIPE_WAIT: Final[int] = 0x00000000
NMPWAIT_WAIT_FOREVER: Final[int] = 0xFFFFFFFF
NMPWAIT_USE_DEFAULT_WAIT: Final[int] = 0x00000000

# ---------------------------------------------------------------------------
# RTL_USER_PROCESS_PARAMETERS command-line offsets
# ---------------------------------------------------------------------------
CMD_LINE_OFFSET_32: Final[int] = 0x40
CMD_LINE_OFFSET_64: Final[int] = 0x70

# ---------------------------------------------------------------------------
# Registry constants
# ---------------------------------------------------------------------------
HKEY_CLASSES_ROOT: Final[int] = 0x80000000
HKEY_CURRENT_USER: Final[int] = 0x80000001
HKEY_LOCAL_MACHINE: Final[int] = 0x80000002
HKEY_USERS: Final[int] = 0x80000003
HKEY_CURRENT_CONFIG: Final[int] = 0x80000005
KEY_READ: Final[int] = 0x20019
KEY_ENUMERATE_SUB_KEYS: Final[int] = 0x0008
KEY_QUERY_VALUE: Final[int] = 0x0001
REG_SZ: Final[int] = 1
REG_EXPAND_SZ: Final[int] = 2
REG_BINARY: Final[int] = 3
REG_DWORD: Final[int] = 4
REG_QWORD: Final[int] = 11
REG_MULTI_SZ: Final[int] = 7

# ---------------------------------------------------------------------------
# GUI resource types
# ---------------------------------------------------------------------------
GR_GDIOBJECTS: Final[int] = 0
GR_USEROBJECTS: Final[int] = 1

# ---------------------------------------------------------------------------
# Job object info classes
# ---------------------------------------------------------------------------
JobObjectBasicLimitInformation: Final[int] = 2
JobObjectExtendedLimitInformation: Final[int] = 9

# ---------------------------------------------------------------------------
# Thread state values (from SYSTEM_THREAD_INFORMATION)
# ---------------------------------------------------------------------------
THREAD_STATE_INITIALIZED: Final[int] = 0
THREAD_STATE_READY: Final[int] = 1
THREAD_STATE_RUNNING: Final[int] = 2
THREAD_STATE_STANDBY: Final[int] = 3
THREAD_STATE_TERMINATED: Final[int] = 4
THREAD_STATE_WAITING: Final[int] = 5
THREAD_STATE_TRANSITION: Final[int] = 6
THREAD_STATE_DEFERRED_READY: Final[int] = 7

THREAD_STATE_NAMES: Final[dict[int, str]] = {
    THREAD_STATE_INITIALIZED: "initialized",
    THREAD_STATE_READY: "ready",
    THREAD_STATE_RUNNING: "running",
    THREAD_STATE_STANDBY: "standby",
    THREAD_STATE_TERMINATED: "terminated",
    THREAD_STATE_WAITING: "waiting",
    THREAD_STATE_TRANSITION: "transition",
    THREAD_STATE_DEFERRED_READY: "deferred_ready",
}

# ---------------------------------------------------------------------------
# Toolhelp32 Structures
# ---------------------------------------------------------------------------


class PROCESSENTRY32(ctypes.Structure):
    """Windows PROCESSENTRY32 structure for process snapshot enumeration."""

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
        ("szExeFile", ctypes.c_char * 260),
    ]


class THREADENTRY32(ctypes.Structure):
    """Windows THREADENTRY32 structure for thread snapshot enumeration."""

    _fields_: ClassVar = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


class MODULEENTRY32(ctypes.Structure):
    """Windows MODULEENTRY32 structure for module snapshot enumeration."""

    _fields_: ClassVar = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", ctypes.c_char * 256),
        ("szExePath", ctypes.c_char * 260),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    """Windows MEMORY_BASIC_INFORMATION structure for virtual memory queries."""

    _fields_: ClassVar = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


MemoryBasicInformation = MEMORY_BASIC_INFORMATION


# ---------------------------------------------------------------------------
# Process memory counters
# ---------------------------------------------------------------------------


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    """Windows PROCESS_MEMORY_COUNTERS structure from psapi."""

    _fields_: ClassVar = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


# ---------------------------------------------------------------------------
# Token / privilege structures
# ---------------------------------------------------------------------------


class LUID(ctypes.Structure):
    """Windows LUID structure for privilege identification."""

    _fields_: ClassVar = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", wintypes.LONG),
    ]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    """Windows LUID_AND_ATTRIBUTES structure for privilege state."""

    _fields_: ClassVar = [
        ("Luid", LUID),
        ("Attributes", wintypes.DWORD),
    ]


class TOKEN_PRIVILEGES(ctypes.Structure):
    """Windows TOKEN_PRIVILEGES structure for privilege adjustment."""

    _fields_: ClassVar = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]


# ---------------------------------------------------------------------------
# NtDll process / thread information structures
# ---------------------------------------------------------------------------


class UNICODE_STRING(ctypes.Structure):
    """Windows UNICODE_STRING structure from ntdll."""

    _fields_: ClassVar = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.c_wchar_p),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    """NtQueryInformationProcess result for ProcessBasicInformation."""

    _fields_: ClassVar = [
        ("ExitStatus", ctypes.c_long),
        ("PebBaseAddress", ctypes.c_void_p),
        ("AffinityMask", ctypes.c_size_t),
        ("BasePriority", ctypes.c_long),
        ("UniqueProcessId", ctypes.c_void_p),
        ("InheritedFromUniqueProcessId", ctypes.c_void_p),
    ]


class THREAD_BASIC_INFORMATION(ctypes.Structure):
    """NtQueryInformationThread result for ThreadBasicInformation."""

    _fields_: ClassVar = [
        ("ExitStatus", ctypes.c_long),
        ("TebBaseAddress", ctypes.c_void_p),
        ("ClientId_UniqueProcess", ctypes.c_void_p),
        ("ClientId_UniqueThread", ctypes.c_void_p),
        ("AffinityMask", ctypes.c_size_t),
        ("Priority", ctypes.c_long),
        ("BasePriority", ctypes.c_long),
    ]


# ---------------------------------------------------------------------------
# Handle information structures (NtQuerySystemInformation)
# ---------------------------------------------------------------------------


class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
    """Single handle entry from SystemExtendedHandleInformation."""

    _fields_: ClassVar = [
        ("Object", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_void_p),
        ("HandleValue", ctypes.c_void_p),
        ("GrantedAccess", wintypes.ULONG),
        ("CreatorBackTraceIndex", wintypes.USHORT),
        ("ObjectTypeIndex", wintypes.USHORT),
        ("HandleAttributes", wintypes.ULONG),
        ("Reserved", wintypes.ULONG),
    ]


class SYSTEM_HANDLE_INFORMATION_EX(ctypes.Structure):
    """Header for SystemExtendedHandleInformation result buffer."""

    _fields_: ClassVar = [
        ("NumberOfHandles", ctypes.c_void_p),
        ("Reserved", ctypes.c_void_p),
        ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * 1),
    ]


# ---------------------------------------------------------------------------
# Heap structures (Toolhelp32)
# ---------------------------------------------------------------------------


class HEAPLIST32(ctypes.Structure):
    """Windows HEAPLIST32 structure for heap snapshot enumeration."""

    _fields_: ClassVar = [
        ("dwSize", ctypes.c_size_t),
        ("th32ProcessID", wintypes.DWORD),
        ("th32HeapID", ctypes.c_size_t),
        ("dwFlags", wintypes.DWORD),
    ]


class HEAPENTRY32(ctypes.Structure):
    """Windows HEAPENTRY32 structure for heap block enumeration."""

    _fields_: ClassVar = [
        ("dwSize", ctypes.c_size_t),
        ("hHandle", wintypes.HANDLE),
        ("dwAddress", ctypes.c_size_t),
        ("dwBlockSize", ctypes.c_size_t),
        ("dwFlags", wintypes.DWORD),
        ("dwLockCount", wintypes.DWORD),
        ("dwResvd", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32HeapID", ctypes.c_size_t),
    ]


# ---------------------------------------------------------------------------
# Thread context structures (AMD64 / i386)
# ---------------------------------------------------------------------------


class M128A(ctypes.Structure):
    """128-bit register value for XMM/SSE context."""

    _fields_: ClassVar = [
        ("Low", ctypes.c_ulonglong),
        ("High", ctypes.c_longlong),
    ]


class CONTEXT64(ctypes.Structure):
    """AMD64 CONTEXT structure for GetThreadContext/SetThreadContext."""

    _fields_: ClassVar = [
        ("P1Home", ctypes.c_ulonglong),
        ("P2Home", ctypes.c_ulonglong),
        ("P3Home", ctypes.c_ulonglong),
        ("P4Home", ctypes.c_ulonglong),
        ("P5Home", ctypes.c_ulonglong),
        ("P6Home", ctypes.c_ulonglong),
        ("ContextFlags", wintypes.DWORD),
        ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD),
        ("SegDs", wintypes.WORD),
        ("SegEs", wintypes.WORD),
        ("SegFs", wintypes.WORD),
        ("SegGs", wintypes.WORD),
        ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        ("Dr0", ctypes.c_ulonglong),
        ("Dr1", ctypes.c_ulonglong),
        ("Dr2", ctypes.c_ulonglong),
        ("Dr3", ctypes.c_ulonglong),
        ("Dr6", ctypes.c_ulonglong),
        ("Dr7", ctypes.c_ulonglong),
        ("Rax", ctypes.c_ulonglong),
        ("Rcx", ctypes.c_ulonglong),
        ("Rdx", ctypes.c_ulonglong),
        ("Rbx", ctypes.c_ulonglong),
        ("Rsp", ctypes.c_ulonglong),
        ("Rbp", ctypes.c_ulonglong),
        ("Rsi", ctypes.c_ulonglong),
        ("Rdi", ctypes.c_ulonglong),
        ("R8", ctypes.c_ulonglong),
        ("R9", ctypes.c_ulonglong),
        ("R10", ctypes.c_ulonglong),
        ("R11", ctypes.c_ulonglong),
        ("R12", ctypes.c_ulonglong),
        ("R13", ctypes.c_ulonglong),
        ("R14", ctypes.c_ulonglong),
        ("R15", ctypes.c_ulonglong),
        ("Rip", ctypes.c_ulonglong),
        ("FltSave", ctypes.c_byte * 512),
        ("VectorRegister", M128A * 26),
        ("VectorControl", ctypes.c_ulonglong),
        ("DebugControl", ctypes.c_ulonglong),
        ("LastBranchToRip", ctypes.c_ulonglong),
        ("LastBranchFromRip", ctypes.c_ulonglong),
        ("LastExceptionToRip", ctypes.c_ulonglong),
        ("LastExceptionFromRip", ctypes.c_ulonglong),
    ]


class FLOATING_SAVE_AREA(ctypes.Structure):
    """I386 FLOATING_SAVE_AREA structure."""

    _fields_: ClassVar = [
        ("ControlWord", wintypes.DWORD),
        ("StatusWord", wintypes.DWORD),
        ("TagWord", wintypes.DWORD),
        ("ErrorOffset", wintypes.DWORD),
        ("ErrorSelector", wintypes.DWORD),
        ("DataOffset", wintypes.DWORD),
        ("DataSelector", wintypes.DWORD),
        ("RegisterArea", ctypes.c_byte * 80),
        ("Spare0", wintypes.DWORD),
    ]


class CONTEXT32(ctypes.Structure):
    """I386 CONTEXT structure for 32-bit thread context."""

    _fields_: ClassVar = [
        ("ContextFlags", wintypes.DWORD),
        ("Dr0", wintypes.DWORD),
        ("Dr1", wintypes.DWORD),
        ("Dr2", wintypes.DWORD),
        ("Dr3", wintypes.DWORD),
        ("Dr6", wintypes.DWORD),
        ("Dr7", wintypes.DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", wintypes.DWORD),
        ("SegFs", wintypes.DWORD),
        ("SegEs", wintypes.DWORD),
        ("SegDs", wintypes.DWORD),
        ("Edi", wintypes.DWORD),
        ("Esi", wintypes.DWORD),
        ("Ebx", wintypes.DWORD),
        ("Edx", wintypes.DWORD),
        ("Ecx", wintypes.DWORD),
        ("Eax", wintypes.DWORD),
        ("Ebp", wintypes.DWORD),
        ("Eip", wintypes.DWORD),
        ("SegCs", wintypes.DWORD),
        ("EFlags", wintypes.DWORD),
        ("Esp", wintypes.DWORD),
        ("SegSs", wintypes.DWORD),
    ]


WOW64_CONTEXT = CONTEXT32
"""WOW64 thread context alias.

The WOW64 subsystem exposes the same I386 CONTEXT layout under the name
``WOW64_CONTEXT`` for use with ``Wow64GetThreadContext`` /
``Wow64SetThreadContext`` against 32-bit threads hosted inside a 64-bit
process. The layout is identical to :class:`CONTEXT32`, so aliasing keeps
the Win32 types surface minimal while making call sites self-documenting.
"""

# ---------------------------------------------------------------------------
# DbgHelp stack walk structures
# ---------------------------------------------------------------------------


class ADDRESS64(ctypes.Structure):
    """DbgHelp ADDRESS64 structure for stack walking."""

    _fields_: ClassVar = [
        ("Offset", ctypes.c_ulonglong),
        ("Segment", wintypes.WORD),
        ("Mode", wintypes.DWORD),
    ]


class STACKFRAME64(ctypes.Structure):
    """DbgHelp STACKFRAME64 structure for stack frame enumeration."""

    _fields_: ClassVar = [
        ("AddrPC", ADDRESS64),
        ("AddrReturn", ADDRESS64),
        ("AddrFrame", ADDRESS64),
        ("AddrStack", ADDRESS64),
        ("AddrBStore", ADDRESS64),
        ("FuncTableEntry", ctypes.c_void_p),
        ("Params", ctypes.c_ulonglong * 4),
        ("Far", wintypes.BOOL),
        ("Virtual", wintypes.BOOL),
        ("Reserved", ctypes.c_ulonglong * 3),
        ("KdHelp", ctypes.c_byte * 128),
    ]


class SYMBOL_INFO(ctypes.Structure):
    """DbgHelp SYMBOL_INFO structure for symbol resolution."""

    _fields_: ClassVar = [
        ("SizeOfStruct", wintypes.ULONG),
        ("TypeIndex", wintypes.ULONG),
        ("Reserved", ctypes.c_ulonglong * 2),
        ("Index", wintypes.ULONG),
        ("Size", wintypes.ULONG),
        ("ModBase", ctypes.c_ulonglong),
        ("Flags", wintypes.ULONG),
        ("Value", ctypes.c_ulonglong),
        ("Address", ctypes.c_ulonglong),
        ("Register", wintypes.ULONG),
        ("Scope", wintypes.ULONG),
        ("Tag", wintypes.ULONG),
        ("NameLen", wintypes.ULONG),
        ("MaxNameLen", wintypes.ULONG),
        ("Name", ctypes.c_char * 1024),
    ]


# ---------------------------------------------------------------------------
# SEH chain structure
# ---------------------------------------------------------------------------


class EXCEPTION_REGISTRATION_RECORD(ctypes.Structure):
    """SEH exception registration record (linked list node)."""


EXCEPTION_REGISTRATION_RECORD._fields_ = [
    ("Next", ctypes.POINTER(EXCEPTION_REGISTRATION_RECORD)),
    ("Handler", ctypes.c_void_p),
]


# ---------------------------------------------------------------------------
# Service structures
# ---------------------------------------------------------------------------


class SERVICE_STATUS_PROCESS(ctypes.Structure):
    """Windows SERVICE_STATUS_PROCESS structure from advapi32."""

    _fields_: ClassVar = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwServiceFlags", wintypes.DWORD),
    ]


class ENUM_SERVICE_STATUS_PROCESSW(ctypes.Structure):
    """Windows ENUM_SERVICE_STATUS_PROCESSW structure for service enumeration."""

    _fields_: ClassVar = [
        ("lpServiceName", wintypes.LPWSTR),
        ("lpDisplayName", wintypes.LPWSTR),
        ("ServiceStatusProcess", SERVICE_STATUS_PROCESS),
    ]


# ---------------------------------------------------------------------------
# Job object structures
# ---------------------------------------------------------------------------


class IO_COUNTERS(ctypes.Structure):
    """Windows IO_COUNTERS structure for job object info."""

    _fields_: ClassVar = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    """Windows JOBOBJECT_BASIC_LIMIT_INFORMATION structure."""

    _fields_: ClassVar = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    """Windows JOBOBJECT_EXTENDED_LIMIT_INFORMATION structure."""

    _fields_: ClassVar = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


# ---------------------------------------------------------------------------
# Mitigation policy structures
# ---------------------------------------------------------------------------


class PROCESS_MITIGATION_DEP_POLICY(ctypes.Structure):
    """DEP mitigation policy flags."""

    _fields_: ClassVar = [
        ("Flags", wintypes.DWORD),
        ("Permanent", wintypes.BOOLEAN),
    ]


class PROCESS_MITIGATION_ASLR_POLICY(ctypes.Structure):
    """ASLR mitigation policy flags."""

    _fields_: ClassVar = [
        ("Flags", wintypes.DWORD),
    ]


class PROCESS_MITIGATION_DYNAMIC_CODE_POLICY(ctypes.Structure):
    """Dynamic code mitigation policy flags."""

    _fields_: ClassVar = [
        ("Flags", wintypes.DWORD),
    ]


class PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY(ctypes.Structure):
    """Strict handle check mitigation policy flags."""

    _fields_: ClassVar = [
        ("Flags", wintypes.DWORD),
    ]


class PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY(ctypes.Structure):
    """System call disable mitigation policy flags."""

    _fields_: ClassVar = [
        ("Flags", wintypes.DWORD),
    ]


class PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY(ctypes.Structure):
    """Control Flow Guard mitigation policy flags."""

    _fields_: ClassVar = [
        ("Flags", wintypes.DWORD),
    ]


class PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY(ctypes.Structure):
    """Binary signature mitigation policy flags."""

    _fields_: ClassVar = [
        ("Flags", wintypes.DWORD),
    ]


class PROCESS_MITIGATION_IMAGE_LOAD_POLICY(ctypes.Structure):
    """Image load mitigation policy flags."""

    _fields_: ClassVar = [
        ("Flags", wintypes.DWORD),
    ]


class PROCESS_MITIGATION_FONT_DISABLE_POLICY(ctypes.Structure):
    """Font disable mitigation policy flags."""

    _fields_: ClassVar = [
        ("Flags", wintypes.DWORD),
    ]


# ---------------------------------------------------------------------------
# DLL handle helpers
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def get_kernel32() -> ctypes.WinDLL:
    """Cached handle to kernel32.dll.

    Returns:
        ctypes.WinDLL: Handle to kernel32.dll.

    Raises:
        OSError: If kernel32.dll cannot be loaded.
    """
    _logger.debug("dll_cache_miss_loading", dll_name="kernel32")
    try:
        return ctypes.windll.kernel32
    except OSError:
        _logger.exception("dll_load_failed", dll_name="kernel32")
        raise


@functools.lru_cache(maxsize=1)
def get_ntdll() -> ctypes.WinDLL:
    """Cached handle to ntdll.dll.

    Returns:
        ctypes.WinDLL: Handle to ntdll.dll.

    Raises:
        OSError: If ntdll.dll cannot be loaded.
    """
    _logger.debug("dll_cache_miss_loading", dll_name="ntdll")
    try:
        return ctypes.WinDLL("ntdll")
    except OSError:
        _logger.exception("dll_load_failed", dll_name="ntdll")
        raise


@functools.lru_cache(maxsize=1)
def get_advapi32() -> ctypes.WinDLL:
    """Cached handle to advapi32.dll.

    Returns:
        ctypes.WinDLL: Handle to advapi32.dll.

    Raises:
        OSError: If advapi32.dll cannot be loaded.
    """
    _logger.debug("dll_cache_miss_loading", dll_name="advapi32")
    try:
        return ctypes.WinDLL("advapi32")
    except OSError:
        _logger.exception("dll_load_failed", dll_name="advapi32")
        raise


@functools.lru_cache(maxsize=1)
def get_user32() -> ctypes.WinDLL:
    """Cached handle to user32.dll.

    Returns:
        ctypes.WinDLL: Handle to user32.dll.

    Raises:
        OSError: If user32.dll cannot be loaded.
    """
    _logger.debug("dll_cache_miss_loading", dll_name="user32")
    try:
        return ctypes.WinDLL("user32")
    except OSError:
        _logger.exception("dll_load_failed", dll_name="user32")
        raise


@functools.lru_cache(maxsize=1)
def get_dbghelp() -> ctypes.WinDLL:
    """Cached handle to dbghelp.dll.

    Returns:
        ctypes.WinDLL: Handle to dbghelp.dll.

    Raises:
        OSError: If dbghelp.dll cannot be loaded.
    """
    _logger.debug("dll_cache_miss_loading", dll_name="dbghelp")
    try:
        return ctypes.WinDLL("dbghelp")
    except OSError:
        _logger.exception("dll_load_failed", dll_name="dbghelp")
        raise


@functools.lru_cache(maxsize=1)
def get_psapi() -> ctypes.WinDLL:
    """Cached handle to psapi.dll.

    Returns:
        ctypes.WinDLL: Handle to psapi.dll.

    Raises:
        OSError: If psapi.dll cannot be loaded.
    """
    _logger.debug("dll_cache_miss_loading", dll_name="psapi")
    try:
        return ctypes.windll.psapi
    except OSError:
        _logger.exception("dll_load_failed", dll_name="psapi")
        raise


class MemoryProtectionFlags(TypedDict):
    """Decoded Win32 page protection flags.

    Captures the structured access bits behind a ``PAGE_*`` constant so
    callers can reason about each capability without parsing a string.

    Attributes:
        read: True when the region is readable.
        write: True when the region is writable.
        execute: True when the region is executable.
        copy_on_write: True when ``PAGE_WRITECOPY`` semantics apply.
        guard: True when ``PAGE_GUARD`` is set.
        raw: The original ``PAGE_*`` value for round-tripping.
    """

    read: bool
    write: bool
    execute: bool
    copy_on_write: bool
    guard: bool
    raw: int


_STATE_TABLE: Final[dict[int, str]] = {
    MEM_COMMIT: "committed",
    MEM_RESERVE: "reserved",
    MEM_FREE: "free",
}

_MEM_TYPE_TABLE: Final[dict[int, str]] = {
    MEM_PRIVATE: "private",
    MEM_MAPPED: "mapped",
    MEM_IMAGE: "image",
}

_PROT_FLAG_TABLE: Final[dict[int, tuple[bool, bool, bool, bool]]] = {
    PAGE_NOACCESS: (False, False, False, False),
    PAGE_READONLY: (True, False, False, False),
    PAGE_READWRITE: (True, True, False, False),
    PAGE_WRITECOPY: (True, True, False, True),
    PAGE_EXECUTE: (False, False, True, False),
    PAGE_EXECUTE_READ: (True, False, True, False),
    PAGE_EXECUTE_READWRITE: (True, True, True, False),
    PAGE_EXECUTE_WRITECOPY: (True, True, True, True),
}


def decode_protection(prot: int) -> MemoryProtectionFlags:
    """Decode a Win32 memory protection constant into structured flags.

    Splits the raw ``PAGE_*`` value into its individual access bits so
    bridges can preserve the semantics of WriteCopy, Guard, and the
    underlying R/W/X capabilities without dropping information through
    a string round-trip.

    Args:
        prot: Win32 ``PAGE_*`` protection value (may include modifier
            bits like ``PAGE_GUARD``).

    Returns:
        MemoryProtectionFlags: Decoded flags including the original
        raw value. Unknown base protections leave every access flag
        cleared and emit a debug log entry.
    """
    base_prot = prot & 0xFF
    if base_prot in _PROT_FLAG_TABLE:
        read, write, execute, cow = _PROT_FLAG_TABLE[base_prot]
    else:
        read = write = execute = cow = False
        _logger.debug("unknown_memory_protection", prot=hex(prot), base=hex(base_prot))
    return MemoryProtectionFlags(
        read=read,
        write=write,
        execute=execute,
        copy_on_write=cow,
        guard=bool(prot & PAGE_GUARD),
        raw=prot,
    )


def protection_to_string(prot: int) -> str:
    """Convert a Win32 memory protection constant to a human-readable string.

    Thin formatter built on top of :func:`decode_protection`; preserves
    the legacy ``rwx``/``rw-c``/``+G`` rendering used by ``MemoryRegion``
    and the audit log fields. Use :func:`decode_protection` directly
    when you need to branch on individual access bits.

    Args:
        prot: Win32 ``PAGE_*`` protection value.

    Returns:
        str: Protection string like ``rwx``, ``r--``, ``rw-c``, ``+G``.
    """
    base_prot = prot & 0xFF
    if base_prot not in _PROT_FLAG_TABLE:
        result = "???"
    else:
        flags = decode_protection(prot)
        read = "r" if flags["read"] else "-"
        write = "w" if flags["write"] else "-"
        execute = "x" if flags["execute"] else "-"
        cow = "c" if flags["copy_on_write"] else ""
        result = f"{read}{write}{execute}{cow}"
    if prot & PAGE_GUARD:
        result += "+G"
    return result


def state_to_string(state: int) -> str:
    """Convert a Win32 memory state constant to a human-readable string.

    Recognised values render the canonical lowercase label. Unknown
    values render ``"unknown(0x...)"`` and emit a debug log so the
    offending state cannot vanish silently into a generic bucket.

    Args:
        state: Win32 ``MEM_*`` state value.

    Returns:
        str: State label such as ``committed``, ``reserved``, ``free``,
        or ``unknown(0x...)`` for unrecognised values.
    """
    if state in _STATE_TABLE:
        return _STATE_TABLE[state]
    _logger.debug("unknown_memory_state", state=hex(state))
    return f"unknown(0x{state:x})"


def mem_type_to_string(mem_type: int) -> str:
    """Convert a Win32 memory type constant to a human-readable string.

    Recognised values render the canonical lowercase label. Unknown
    values render ``"unknown(0x...)"`` and emit a debug log so the
    offending type cannot vanish silently into a generic bucket.

    Args:
        mem_type: Win32 ``MEM_*`` type value.

    Returns:
        str: Type label such as ``private``, ``mapped``, ``image``, or
        ``unknown(0x...)`` for unrecognised values.
    """
    if mem_type in _MEM_TYPE_TABLE:
        return _MEM_TYPE_TABLE[mem_type]
    _logger.debug("unknown_memory_type", mem_type=hex(mem_type))
    return f"unknown(0x{mem_type:x})"
