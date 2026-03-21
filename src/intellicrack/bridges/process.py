# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Process control bridge for Windows process manipulation.

This module provides direct process control capabilities including
memory access, thread manipulation, and module enumeration using
Windows API.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path
from typing import Literal, cast, override

from ..core.logging import get_logger
from ..core.types import (
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
from .base import BridgeCapabilities, BridgeState, ToolBridgeBase


_logger = get_logger("bridges.process")

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
_ERR_LOADLIB_ADDR = "LoadLibraryA address failed"
_ERR_REMOTE_THREAD = "remote thread creation failed"

_MAX_MEMORY_ADDRESS = 0x7FFFFFFFFFFF
_WILDCARD_PATTERNS = {"??", "?"}

ProcessAccessRights = Literal[
    "all",
    "query",
    "read",
    "write",
    "terminate",
    "suspend",
]


class PROCESSENTRY32(ctypes.Structure):
    """Windows PROCESSENTRY32 structure."""

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
        ("szExeFile", ctypes.c_char * 260),
    ]


class THREADENTRY32(ctypes.Structure):
    """Windows THREADENTRY32 structure."""

    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


class MODULEENTRY32(ctypes.Structure):
    """Windows MODULEENTRY32 structure."""

    _fields_ = [
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


class MemoryBasicInformation(ctypes.Structure):
    """Windows MEMORY_BASIC_INFORMATION structure."""

    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


MEMORY_BASIC_INFORMATION = MemoryBasicInformation


class ProcessBridge(ToolBridgeBase):
    """Bridge for Windows process control.

    Provides direct process manipulation including memory access,
    thread control, and module enumeration.

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

    PROCESS_ALL_ACCESS = 0x1F0FFF
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_TERMINATE = 0x0001
    PROCESS_SUSPEND_RESUME = 0x0800

    TH32CS_SNAPPROCESS = 0x00000002
    TH32CS_SNAPTHREAD = 0x00000004
    TH32CS_SNAPMODULE = 0x00000008
    TH32CS_SNAPMODULE32 = 0x00000010

    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    MEM_RELEASE = 0x8000

    PAGE_NOACCESS = 0x01
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40

    def __init__(self) -> None:
        super().__init__()
        self._attached_pid: int | None = None
        self._process_handle: int | None = None
        self._kernel32: ctypes.WinDLL | None = None
        self._psapi: ctypes.WinDLL | None = None
        self._capabilities = BridgeCapabilities(
            supports_memory_access=True,
            supports_debugging=False,
            supported_architectures=["x86", "x86_64"],
            supported_formats=["pe"],
        )

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
            description="Windows process control - memory access, thread manipulation, module enumeration",
            functions=[
                ToolFunction(
                    name="process.list",
                    description="List all running processes",
                    parameters=[
                        ToolParameter(
                            name="filter_name",
                            type="string",
                            description="Optional name filter",
                            required=False,
                        ),
                    ],
                    returns="List of ProcessInfo objects",
                ),
                ToolFunction(
                    name="process.open",
                    description="Open a process for manipulation",
                    parameters=[
                        ToolParameter(
                            name="pid",
                            type="integer",
                            description="Process ID",
                            required=True,
                        ),
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
                ToolFunction(
                    name="process.close",
                    description="Close the current process handle",
                    parameters=[],
                    returns="Success status",
                ),
                ToolFunction(
                    name="process.terminate",
                    description="Terminate a process",
                    parameters=[
                        ToolParameter(
                            name="pid",
                            type="integer",
                            description="Process ID (uses current if not specified)",
                            required=False,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="process.suspend",
                    description="Suspend all threads of a process",
                    parameters=[
                        ToolParameter(
                            name="pid",
                            type="integer",
                            description="Process ID (uses current if not specified)",
                            required=False,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="process.resume",
                    description="Resume all threads of a process",
                    parameters=[
                        ToolParameter(
                            name="pid",
                            type="integer",
                            description="Process ID (uses current if not specified)",
                            required=False,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="process.read_memory",
                    description="Read memory from process",
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
                    returns="Hex string of memory contents",
                ),
                ToolFunction(
                    name="process.write_memory",
                    description="Write memory to process",
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
                    returns="Bytes written",
                ),
                ToolFunction(
                    name="process.allocate",
                    description="Allocate memory in process",
                    parameters=[
                        ToolParameter(
                            name="size",
                            type="integer",
                            description="Size to allocate",
                            required=True,
                        ),
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
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Address to free",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="process.protect",
                    description="Change memory protection",
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
                            description="Region size",
                            required=True,
                        ),
                        ToolParameter(
                            name="protection",
                            type="string",
                            description="New protection (rwx, rw, rx, r)",
                            required=True,
                        ),
                    ],
                    returns="Previous protection",
                ),
                ToolFunction(
                    name="process.get_modules",
                    description="Get loaded modules",
                    parameters=[
                        ToolParameter(
                            name="pid",
                            type="integer",
                            description="Process ID (uses current if not specified)",
                            required=False,
                        ),
                    ],
                    returns="List of ModuleInfo objects",
                ),
                ToolFunction(
                    name="process.get_threads",
                    description="Get process threads",
                    parameters=[
                        ToolParameter(
                            name="pid",
                            type="integer",
                            description="Process ID (uses current if not specified)",
                            required=False,
                        ),
                    ],
                    returns="List of ThreadInfo objects",
                ),
                ToolFunction(
                    name="process.get_memory_map",
                    description="Get process memory map",
                    parameters=[],
                    returns="List of MemoryRegion objects",
                ),
                ToolFunction(
                    name="process.search_pattern",
                    description="Search for byte pattern in memory",
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
                    name="process.inject_dll",
                    description="Inject a DLL into the process",
                    parameters=[
                        ToolParameter(
                            name="dll_path",
                            type="string",
                            description="Path to DLL file",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="process.get_process_info",
                    description="Get detailed process information",
                    parameters=[
                        ToolParameter(
                            name="pid",
                            type="integer",
                            description="Process ID (uses current if not specified)",
                            required=False,
                        ),
                    ],
                    returns="Process info or None if not found",
                ),
            ],
        )

    async def initialize(self, tool_path: Path | None = None) -> None:
        """Initialize the process bridge.

        Args:
            tool_path: Not used for process bridge.
        """
        del tool_path
        try:
            self._kernel32 = ctypes.windll.kernel32
            self._psapi = ctypes.windll.psapi
            self._state = BridgeState(
                connected=True,
                tool_running=True,
                binary_loaded=False,
                process_attached=False,
                target_path=None,
                target_pid=None,
                last_error=None,
            )
            _logger.info("process_bridge_initialized", bridge="process")
        except Exception as e:
            _logger.exception("process_bridge_init_failed", bridge="process")
            self._state = BridgeState(
                connected=False,
                tool_running=False,
                binary_loaded=False,
                process_attached=False,
                target_path=None,
                target_pid=None,
                last_error=str(e),
            )

    async def shutdown(self) -> None:
        """Shutdown and cleanup resources."""
        await self.close()
        self._kernel32 = None
        self._psapi = None
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

        snapshot = self._kernel32.CreateToolhelp32Snapshot(
            self.TH32CS_SNAPPROCESS,
            0,
        )

        if snapshot == -1:
            raise ToolError(_ERR_SNAPSHOT_FAILED)

        processes: list[ProcessInfo] = []
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

        try:
            if self._kernel32.Process32First(snapshot, ctypes.byref(entry)):
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
                            )
                        )

                    if not self._kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                        break

        finally:
            self._kernel32.CloseHandle(snapshot)

        return processes

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

        access_map = {
            "all": self.PROCESS_ALL_ACCESS,
            "query": self.PROCESS_QUERY_INFORMATION,
            "read": self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_READ,
            "write": self.PROCESS_VM_WRITE | self.PROCESS_VM_OPERATION,
            "terminate": self.PROCESS_TERMINATE,
            "suspend": self.PROCESS_SUSPEND_RESUME,
        }

        access_rights = access_map.get(access, self.PROCESS_ALL_ACCESS)

        handle = self._kernel32.OpenProcess(access_rights, False, pid)

        if not handle:
            raise ToolError(_ERR_OPEN_FAILED)

        self._attached_pid = pid
        self._process_handle = handle

        self._state.connected = True
        self._state.tool_running = True
        self._state.process_attached = True
        self._state.target_pid = pid

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

        self._state.connected = True
        self._state.tool_running = True
        self._state.process_attached = False
        self._state.target_pid = None

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
            handle = self._kernel32.OpenProcess(self.PROCESS_TERMINATE, False, pid)
            if not handle:
                raise ToolError(_ERR_OPEN_FAILED)
            close_handle = True
        else:
            if self._process_handle is None:
                raise ToolError(_ERR_NOT_ATTACHED)
            handle = self._process_handle
            close_handle = False

        try:
            result = self._kernel32.TerminateProcess(handle, 1)
            if not result:
                raise ToolError(_ERR_TERMINATE_FAILED)

            _logger.info("process_terminated", pid=pid or self._attached_pid)
            return True

        finally:
            if close_handle:
                self._kernel32.CloseHandle(handle)
            else:
                await self.close()

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

        for thread in threads:
            if handle := self._kernel32.OpenThread(0x0002, False, thread.tid):
                self._kernel32.SuspendThread(handle)
                self._kernel32.CloseHandle(handle)

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

        for thread in threads:
            if handle := self._kernel32.OpenThread(0x0002, False, thread.tid):
                self._kernel32.ResumeThread(handle)
                self._kernel32.CloseHandle(handle)

        _logger.info("process_resumed", pid=target_pid, thread_count=len(threads))
        return True

    async def read_memory(self, address: int, size: int) -> bytes:
        """Read memory from process.

        Args:
            address: Memory address.
            size: Bytes to read.

        Returns:
            bytes: Memory contents.

        Raises:
            ToolError: If read fails.
        """
        _logger.debug("memory_read_starting", address=hex(address), size=size)
        if self._process_handle is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        if self._kernel32 is None:
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
        raise ToolError(_ERR_READ_FAILED)

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

    async def allocate(
        self,
        size: int,
        protection: str = "rwx",
    ) -> int:
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

        prot_map = {
            "rwx": self.PAGE_EXECUTE_READWRITE,
            "rx": self.PAGE_EXECUTE_READ,
            "rw": self.PAGE_READWRITE,
            "r": self.PAGE_READONLY,
            "x": self.PAGE_EXECUTE,
        }

        prot = prot_map.get(protection, self.PAGE_EXECUTE_READWRITE)

        address: int = cast(
            "int",
            self._kernel32.VirtualAllocEx(
                self._process_handle,
                0,
                size,
                self.MEM_COMMIT | self.MEM_RESERVE,
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
            self.MEM_RELEASE,
        )

        if not result:
            raise ToolError(_ERR_FREE_FAILED)

        _logger.info("memory_freed", address=hex(address))
        return True

    async def protect(
        self,
        address: int,
        size: int,
        protection: str,
    ) -> str:
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

        prot_map = {
            "rwx": self.PAGE_EXECUTE_READWRITE,
            "rx": self.PAGE_EXECUTE_READ,
            "rw": self.PAGE_READWRITE,
            "r": self.PAGE_READONLY,
            "x": self.PAGE_EXECUTE,
        }

        new_prot = prot_map.get(protection, self.PAGE_EXECUTE_READWRITE)
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

        rev_prot_map = {v: k for k, v in prot_map.items()}
        old_prot_str = rev_prot_map.get(old_prot.value, "unknown")

        _logger.info("memory_protection_changed", address=hex(address), old_protection=old_prot_str, new_protection=protection)
        return old_prot_str

    async def get_modules(self, pid: int | None = None) -> list[ModuleInfo]:
        """Get loaded modules.

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            list[ModuleInfo]: List of modules.

        Raises:
            ToolError: If operation fails.
        """
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        target_pid = pid or self._attached_pid
        if target_pid is None:
            raise ToolError(_ERR_NO_PROCESS)

        snapshot = self._kernel32.CreateToolhelp32Snapshot(
            self.TH32CS_SNAPMODULE | self.TH32CS_SNAPMODULE32,
            target_pid,
        )

        if snapshot == -1:
            error_code = ctypes.get_last_error()
            _logger.error("module_snapshot_failed", pid=target_pid, error_code=error_code)
            return []

        modules: list[ModuleInfo] = []
        entry = MODULEENTRY32()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32)

        try:
            if self._kernel32.Module32First(snapshot, ctypes.byref(entry)):
                while True:
                    base_addr = (
                        ctypes.cast(
                            entry.modBaseAddr,
                            ctypes.c_void_p,
                        ).value
                        or 0
                    )

                    modules.append(
                        ModuleInfo(
                            name=entry.szModule.decode("utf-8", errors="ignore"),
                            path=Path(entry.szExePath.decode("utf-8", errors="ignore")),
                            base_address=base_addr,
                            size=entry.modBaseSize,
                            entry_point=0,
                        )
                    )

                    if not self._kernel32.Module32Next(snapshot, ctypes.byref(entry)):
                        break

        finally:
            self._kernel32.CloseHandle(snapshot)

        return modules

    async def get_threads(self, pid: int | None = None) -> list[ThreadInfo]:
        """Get process threads.

        Args:
            pid: Process ID (uses current if not specified).

        Returns:
            list[ThreadInfo]: List of threads.

        Raises:
            ToolError: If operation fails.
        """
        if self._kernel32 is None:
            raise ToolError(_ERR_KERNEL32_NA)

        target_pid = pid or self._attached_pid
        if target_pid is None:
            raise ToolError(_ERR_NO_PROCESS)

        snapshot = self._kernel32.CreateToolhelp32Snapshot(
            self.TH32CS_SNAPTHREAD,
            0,
        )

        if snapshot == -1:
            error_code = ctypes.get_last_error()
            _logger.error("thread_snapshot_failed", error_code=error_code)
            return []

        threads: list[ThreadInfo] = []
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(THREADENTRY32)

        try:
            if self._kernel32.Thread32First(snapshot, ctypes.byref(entry)):
                while True:
                    if entry.th32OwnerProcessID == target_pid:
                        threads.append(
                            ThreadInfo(
                                tid=entry.th32ThreadID,
                                start_address=0,
                                state="unknown",
                                priority=entry.tpBasePri,
                            )
                        )

                    if not self._kernel32.Thread32Next(snapshot, ctypes.byref(entry)):
                        break

        finally:
            self._kernel32.CloseHandle(snapshot)

        return threads

    async def get_memory_map(self) -> list[MemoryRegion]:
        """Get process memory map.

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

            if mbi.State == self.MEM_COMMIT:
                prot_map = {
                    self.PAGE_NOACCESS: "---",
                    self.PAGE_READONLY: "r--",
                    self.PAGE_READWRITE: "rw-",
                    self.PAGE_EXECUTE: "--x",
                    self.PAGE_EXECUTE_READ: "r-x",
                    self.PAGE_EXECUTE_READWRITE: "rwx",
                }

                state_map = {
                    0x1000: "committed",
                    0x2000: "reserved",
                    0x10000: "free",
                }

                type_map = {
                    0x20000: "private",
                    0x40000: "mapped",
                    0x1000000: "image",
                }

                regions.append(
                    MemoryRegion(
                        base_address=mbi.BaseAddress or 0,
                        size=mbi.RegionSize,
                        protection=prot_map.get(mbi.Protect, "???"),
                        state=state_map.get(mbi.State, "unknown"),
                        type=type_map.get(mbi.Type, "unknown"),
                        module_name=None,
                    )
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

        regions = await self.get_memory_map()
        matches: list[int] = []

        for region in regions:
            if "r" not in region.protection:
                continue

            if start_address and region.base_address + region.size < start_address:
                continue
            if end_address and region.base_address > end_address:
                continue

            try:
                chunk_size = min(region.size, 0x100000)
                data = await self.read_memory(region.base_address, chunk_size)

                for i in range(len(data) - len(pattern_bytes) + 1):
                    match = not any(pb is not None and data[i + j] != pb for j, pb in enumerate(pattern_bytes))
                    if match:
                        matches.append(region.base_address + i)

            except ToolError as e:
                _logger.warning("pattern_search_failed", error=str(e))
                continue

        return matches

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

        dll_path_resolved = Path(dll_path).resolve()
        if not dll_path_resolved.exists():
            raise ToolError(_ERR_DLL_NOT_FOUND)

        dll_path_bytes = str(dll_path_resolved).encode("utf-8") + b"\x00"

        remote_mem = await self.allocate(len(dll_path_bytes), "rw")

        try:
            await self.write_memory(remote_mem, dll_path_bytes)

            kernel32_handle = self._kernel32.GetModuleHandleW("kernel32.dll")
            if not kernel32_handle:
                raise ToolError(_ERR_KERNEL32_HANDLE)

            load_library_addr = self._kernel32.GetProcAddress(
                kernel32_handle,
                b"LoadLibraryA",
            )
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

            self._kernel32.WaitForSingleObject(thread_handle, 5000)
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
