# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Frida instrumentation bridge for dynamic analysis.

This module provides runtime instrumentation capabilities using Frida for function hooking, memory manipulation, and process control.
"""

from __future__ import annotations

import asyncio
import base64
import json
import sys
import tempfile
import threading
import time
import uuid
from json import JSONDecodeError
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
    FridaApplicationInfo,
    FridaDeviceInfo,
    FridaProcessEntry,
    HookInfo,
    ImportInfo,
    InstructionInfo,
    MemoryRegion,
    ModuleInfo,
    StalkerEvent,
    StalkerTrace,
    SymbolInfo,
    SystemCallResult,
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
_ERR_RESUME_FAILED = "failed to resume process"
_ERR_DETACH_FAILED = "failed to detach from process"
_ERR_UNKNOWN_CANCELLABLE = "unknown cancellable token"
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
_ERR_SCRIPT_NOT_FOUND = "script not found"
_ERR_RPC_FAILED = "RPC call failed"
_ERR_PATCH_FAILED = "code patching failed"
_ERR_STRING_ALLOC_FAILED = "string allocation failed"
_ERR_MODULE_LOAD_FAILED = "module loading failed"
_ERR_EXCEPTION_HANDLER_FAILED = "exception handler setup failed"
_ERR_INJECT_FAILED = "library injection failed"
_ERR_OBJC_UNAVAILABLE = "Objective-C runtime not available"
_ERR_JAVA_UNAVAILABLE = "Java runtime not available"
_ERR_CMODULE_FAILED = "CModule compilation failed"
_ERR_KERNEL_UNAVAILABLE = "Kernel API not available"
_ERR_SOCKET_FAILED = "socket operation failed"
_ERR_FILE_FAILED = "file operation failed"
_ERR_SQLITE_FAILED = "SQLite operation failed"
_ERR_CODE_WRITER_FAILED = "code writing failed"
_ERR_COMPILE_FAILED = "TypeScript compilation failed"
_ERR_MONITOR_FAILED = "file monitoring failed"
_ERR_PROBE_FAILED = "call probe operation failed"
_ERR_INVALID_JSON_MESSAGE = "invalid JSON message"
_ERR_INVALID_PROTECTION = "invalid memory protection flags"

_VALID_NATIVE_TYPES: frozenset[str] = frozenset({
    "void",
    "int",
    "uint",
    "long",
    "ulong",
    "float",
    "double",
    "pointer",
    "int8",
    "uint8",
    "int16",
    "uint16",
    "int32",
    "uint32",
    "int64",
    "uint64",
    "bool",
    "size_t",
    "ssize_t",
})
_VALID_CALLING_CONVENTIONS: frozenset[str] = frozenset({
    "default",
    "sysv",
    "stdcall",
    "thiscall",
    "fastcall",
    "mscdecl",
    "win64",
})
_VALID_STRING_ENCODINGS: frozenset[str] = frozenset({"utf8", "ansi", "utf16"})
_VALID_BACKTRACER_TYPES: frozenset[str] = frozenset({"accurate", "fuzzy"})
_VALID_RESOLVER_TYPES: frozenset[str] = frozenset({"module", "objc", "swift"})
_VALID_CODE_ARCHITECTURES: frozenset[str] = frozenset({"x86", "arm", "arm64", "thumb", "mips"})
_VALID_PROTECTION_FLAGS: frozenset[str] = frozenset({
    "---",
    "r--",
    "-w-",
    "--x",
    "rw-",
    "r-x",
    "-wx",
    "rwx",
})
_VALID_SOCKET_FAMILIES: frozenset[str] = frozenset({"ipv4", "ipv6", "unix"})
_SCAN_CONTEXT_BYTES: int = 16
_PATCH_CODE_PROBE_SIZE: int = 4096
_ASCII_PRINTABLE_MIN: int = 0x20
_ASCII_PRINTABLE_MAX: int = 0x7E
_ASCII_DEL: int = 0x7F
_CODE_WRITER_MAP: dict[str, str] = {
    "x86": "X86Writer",
    "arm": "ArmWriter",
    "arm64": "Arm64Writer",
    "thumb": "ThumbWriter",
    "mips": "MipsWriter",
}


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
        description="Call a function in the target process with typed arguments",
        parameters=[
            ToolParameter(name="address", type="integer", description="Function address", required=True),
            ToolParameter(name="args", type="array", description="Function arguments (integers)", required=False),
            ToolParameter(name="return_type", type="string", description="Return type (default 'pointer')", required=False),
            ToolParameter(name="arg_types", type="array", description="Argument types list", required=False),
            ToolParameter(
                name="calling_convention",
                type="string",
                description="Calling convention",
                required=False,
                enum=["default", "sysv", "stdcall", "thiscall", "fastcall", "mscdecl", "win64"],
            ),
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
            ToolParameter(
                name="resolver_type",
                type="string",
                description="Resolver type",
                required=False,
                enum=["module", "objc", "swift"],
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
            ToolParameter(
                name="calling_convention",
                type="string",
                description="Calling convention for the replacement",
                required=False,
                enum=["default", "sysv", "stdcall", "thiscall", "fastcall", "mscdecl", "win64"],
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
    ToolFunction(
        name="frida.post_message",
        description="Send a message from Python to a running Frida script",
        parameters=[
            ToolParameter(name="script_id", type="string", description="ID of the target script", required=True),
            ToolParameter(name="message", type="string", description="JSON message to send", required=True),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.eternalize_script",
        description="Make a script persistent without Python reference (survives detach)",
        parameters=[
            ToolParameter(name="script_id", type="string", description="ID of the script to eternalize", required=True),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.rpc_call",
        description="Call an RPC-exported function in a running script",
        parameters=[
            ToolParameter(name="script_id", type="string", description="ID of the target script", required=True),
            ToolParameter(name="method_name", type="string", description="Name of the exported method", required=True),
            ToolParameter(name="args", type="array", description="Arguments for the RPC call", required=False),
        ],
        returns="Return value from the RPC call",
    ),
    ToolFunction(
        name="frida.create_cancellable",
        description="Create a Frida cancellation token for long-running operations",
        parameters=[],
        returns="Cancellable ID",
    ),
    ToolFunction(
        name="frida.cancel",
        description="Cancel a long-running operation via its cancellation token",
        parameters=[
            ToolParameter(name="cancellable_id", type="string", description="ID of the cancellable to trigger", required=True),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.patch_code",
        description="Patch code at an address using Memory.patchCode with cache flush",
        parameters=[
            ToolParameter(name="address", type="integer", description="Address to patch", required=True),
            ToolParameter(name="hex_data", type="string", description="Hex-encoded bytes to write", required=True),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.allocate_string",
        description="Allocate a string in the target process memory",
        parameters=[
            ToolParameter(name="value", type="string", description="String value to allocate", required=True),
            ToolParameter(
                name="encoding",
                type="string",
                description="String encoding",
                required=False,
                enum=["utf8", "ansi", "utf16"],
            ),
        ],
        returns="Address of the allocated string",
    ),
    ToolFunction(
        name="frida.enumerate_symbols",
        description="List all symbols in a module including debug symbols",
        parameters=[
            ToolParameter(name="module_name", type="string", description="Name of the module", required=True),
        ],
        returns="List of SymbolInfo objects",
    ),
    ToolFunction(
        name="frida.load_module",
        description="Load a shared library into the target process",
        parameters=[
            ToolParameter(name="path", type="string", description="Path to the library file", required=True),
        ],
        returns="ModuleInfo for the loaded module",
    ),
    ToolFunction(
        name="frida.find_module_by_address",
        description="Find which module contains a given address",
        parameters=[
            ToolParameter(name="address", type="integer", description="Address to look up", required=True),
        ],
        returns="ModuleInfo or null if not found",
    ),
    ToolFunction(
        name="frida.find_functions_matching",
        description="Find functions matching a glob pattern via DebugSymbol",
        parameters=[
            ToolParameter(name="pattern", type="string", description="Glob pattern to match", required=True),
        ],
        returns="List of SymbolInfo for matching functions",
    ),
    ToolFunction(
        name="frida.disassemble_instruction",
        description="Disassemble a single instruction at an address",
        parameters=[
            ToolParameter(name="address", type="integer", description="Address to disassemble", required=True),
        ],
        returns="InstructionInfo with mnemonic, operands, size",
    ),
    ToolFunction(
        name="frida.get_backtrace",
        description="Get a stack backtrace with optional context",
        parameters=[
            ToolParameter(name="context_address", type="integer", description="CPU context address", required=False),
            ToolParameter(
                name="backtracer",
                type="string",
                description="Backtracer type",
                required=False,
                enum=["accurate", "fuzzy"],
            ),
        ],
        returns="List of SymbolInfo for backtrace frames",
    ),
    ToolFunction(
        name="frida.set_exception_handler",
        description="Install a process-wide exception handler",
        parameters=[],
        returns="Script ID for the exception handler",
    ),
    ToolFunction(
        name="frida.revert_hook",
        description="Revert a function hook using Interceptor.revert()",
        parameters=[
            ToolParameter(name="target", type="string", description="Function target to revert", required=True),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.flush_interceptor",
        description="Flush Interceptor inline caches to apply pending changes",
        parameters=[],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.call_system_function",
        description="Call a system function capturing errno and GetLastError",
        parameters=[
            ToolParameter(name="address", type="integer", description="Function address", required=True),
            ToolParameter(name="args", type="array", description="Function arguments (integers)", required=False),
            ToolParameter(name="return_type", type="string", description="Return type (default 'pointer')", required=False),
            ToolParameter(name="arg_types", type="array", description="Argument types list", required=False),
            ToolParameter(
                name="calling_convention",
                type="string",
                description="Calling convention",
                required=False,
                enum=["default", "sysv", "stdcall", "thiscall", "fastcall", "mscdecl", "win64"],
            ),
        ],
        returns="SystemCallResult with value, errno, lastError",
    ),
    ToolFunction(
        name="frida.stalker_add_call_probe",
        description="Add a Stalker call probe at an address",
        parameters=[
            ToolParameter(name="address", type="integer", description="Address to probe", required=True),
            ToolParameter(name="callback_code", type="string", description="JS callback code for the probe", required=True),
        ],
        returns="Probe ID",
    ),
    ToolFunction(
        name="frida.stalker_remove_call_probe",
        description="Remove a Stalker call probe",
        parameters=[
            ToolParameter(name="probe_id", type="string", description="ID of the probe to remove", required=True),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.enumerate_applications",
        description="List all installed applications on the device",
        parameters=[],
        returns="List of FridaApplicationInfo",
    ),
    ToolFunction(
        name="frida.inject_library_file",
        description="Inject a shared library file into a process",
        parameters=[
            ToolParameter(name="pid", type="integer", description="Target process ID", required=True),
            ToolParameter(name="path", type="string", description="Path to the library", required=True),
            ToolParameter(name="entrypoint", type="string", description="Entrypoint function name", required=True),
            ToolParameter(name="data", type="string", description="String data to pass to entrypoint", required=True),
        ],
        returns="Injection ID",
    ),
    ToolFunction(
        name="frida.inject_library_blob",
        description="Inject a library from raw bytes into a process",
        parameters=[
            ToolParameter(name="pid", type="integer", description="Target process ID", required=True),
            ToolParameter(name="blob_hex", type="string", description="Hex-encoded library bytes", required=True),
            ToolParameter(name="entrypoint", type="string", description="Entrypoint function name", required=True),
            ToolParameter(name="data", type="string", description="String data to pass to entrypoint", required=True),
        ],
        returns="Injection ID",
    ),
    ToolFunction(
        name="frida.objc_enumerate_classes",
        description="Enumerate all Objective-C classes in the process",
        parameters=[],
        returns="List of class name strings",
    ),
    ToolFunction(
        name="frida.objc_enumerate_protocols",
        description="Enumerate all Objective-C protocols in the process",
        parameters=[],
        returns="List of protocol name strings",
    ),
    ToolFunction(
        name="frida.objc_enumerate_loaded_classes",
        description="Enumerate loaded Objective-C classes with optional pattern filter",
        parameters=[
            ToolParameter(name="pattern", type="string", description="Optional glob pattern to filter", required=False),
        ],
        returns="List of class name strings",
    ),
    ToolFunction(
        name="frida.objc_choose",
        description="Find live instances of an Objective-C class on the heap",
        parameters=[
            ToolParameter(name="class_name", type="string", description="ObjC class name", required=True),
            ToolParameter(name="limit", type="integer", description="Max instances to return (default 100)", required=False),
        ],
        returns="List of instance addresses",
    ),
    ToolFunction(
        name="frida.objc_get_class_methods",
        description="Get all methods of an Objective-C class",
        parameters=[
            ToolParameter(name="class_name", type="string", description="ObjC class name", required=True),
        ],
        returns="List of method selector strings",
    ),
    ToolFunction(
        name="frida.objc_hook_method",
        description="Hook an Objective-C method",
        parameters=[
            ToolParameter(name="class_name", type="string", description="ObjC class name", required=True),
            ToolParameter(name="method_name", type="string", description="Method selector", required=True),
            ToolParameter(name="on_enter", type="string", description="JS onEnter code", required=False),
            ToolParameter(name="on_leave", type="string", description="JS onLeave code", required=False),
        ],
        returns="Hook ID",
    ),
    ToolFunction(
        name="frida.java_enumerate_loaded_classes",
        description="Enumerate loaded Java classes with optional pattern filter",
        parameters=[
            ToolParameter(name="pattern", type="string", description="Optional glob pattern", required=False),
        ],
        returns="List of class name strings",
    ),
    ToolFunction(
        name="frida.java_choose",
        description="Find live instances of a Java class on the heap",
        parameters=[
            ToolParameter(name="class_name", type="string", description="Fully qualified Java class name", required=True),
            ToolParameter(name="limit", type="integer", description="Max instances to return (default 100)", required=False),
        ],
        returns="List of instance descriptions",
    ),
    ToolFunction(
        name="frida.java_use",
        description="Get class wrapper with method info for a Java class",
        parameters=[
            ToolParameter(name="class_name", type="string", description="Fully qualified Java class name", required=True),
        ],
        returns="Class info with method names",
    ),
    ToolFunction(
        name="frida.java_hook_method",
        description="Hook a Java method with optional overload specification",
        parameters=[
            ToolParameter(name="class_name", type="string", description="Fully qualified Java class name", required=True),
            ToolParameter(name="method_name", type="string", description="Method name to hook", required=True),
            ToolParameter(name="overloads", type="array", description="Overload type signatures", required=False),
            ToolParameter(name="on_enter", type="string", description="JS onEnter code", required=False),
            ToolParameter(name="on_leave", type="string", description="JS onLeave code", required=False),
        ],
        returns="Hook ID",
    ),
    ToolFunction(
        name="frida.java_deoptimize",
        description="Force Java runtime to deoptimize all code for reliable hooking",
        parameters=[],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.create_cmodule",
        description="Compile and load inline C code via Frida CModule",
        parameters=[
            ToolParameter(name="code", type="string", description="C source code", required=True),
            ToolParameter(name="symbols", type="object", description="Symbol name->address mappings", required=False),
        ],
        returns="Script ID for the CModule",
    ),
    ToolFunction(
        name="frida.kernel_enumerate_modules",
        description="Enumerate kernel modules",
        parameters=[],
        returns="List of ModuleInfo for kernel modules",
    ),
    ToolFunction(
        name="frida.kernel_enumerate_ranges",
        description="Enumerate kernel memory ranges",
        parameters=[
            ToolParameter(name="protection", type="string", description="Protection filter (default '---')", required=False),
        ],
        returns="List of memory ranges",
    ),
    ToolFunction(
        name="frida.kernel_read",
        description="Read kernel memory",
        parameters=[
            ToolParameter(name="address", type="integer", description="Kernel address to read", required=True),
            ToolParameter(name="size", type="integer", description="Number of bytes", required=True),
        ],
        returns="Hex string of kernel memory",
    ),
    ToolFunction(
        name="frida.kernel_write",
        description="Write to kernel memory",
        parameters=[
            ToolParameter(name="address", type="integer", description="Kernel address to write", required=True),
            ToolParameter(name="hex_data", type="string", description="Hex-encoded bytes to write", required=True),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.kernel_alloc",
        description="Allocate kernel memory",
        parameters=[
            ToolParameter(name="size", type="integer", description="Size in bytes", required=True),
        ],
        returns="Address of allocated kernel memory",
    ),
    ToolFunction(
        name="frida.kernel_protect",
        description="Change kernel memory protection",
        parameters=[
            ToolParameter(name="address", type="integer", description="Kernel address", required=True),
            ToolParameter(name="size", type="integer", description="Size in bytes", required=True),
            ToolParameter(name="protection", type="string", description="New protection flags", required=True),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.socket_listen",
        description="Create a listening socket in the target process",
        parameters=[
            ToolParameter(name="port", type="integer", description="Port to listen on", required=True),
            ToolParameter(name="family", type="string", description="Address family (ipv4/ipv6/unix)", required=False),
        ],
        returns="Script ID for the listener",
    ),
    ToolFunction(
        name="frida.socket_connect",
        description="Connect a socket in the target process",
        parameters=[
            ToolParameter(name="host", type="string", description="Host to connect to", required=True),
            ToolParameter(name="port", type="integer", description="Port to connect to", required=True),
            ToolParameter(name="family", type="string", description="Address family", required=False),
        ],
        returns="Connection information",
    ),
    ToolFunction(
        name="frida.socket_type",
        description="Get socket type for a file descriptor",
        parameters=[
            ToolParameter(name="handle", type="integer", description="File descriptor/handle", required=True),
        ],
        returns="Socket type string",
    ),
    ToolFunction(
        name="frida.socket_local_address",
        description="Get local address of a socket",
        parameters=[
            ToolParameter(name="handle", type="integer", description="File descriptor/handle", required=True),
        ],
        returns="Socket address info",
    ),
    ToolFunction(
        name="frida.socket_peer_address",
        description="Get peer address of a connected socket",
        parameters=[
            ToolParameter(name="handle", type="integer", description="File descriptor/handle", required=True),
        ],
        returns="Socket address info",
    ),
    ToolFunction(
        name="frida.file_read_target",
        description="Read a file on the target device",
        parameters=[
            ToolParameter(name="path", type="string", description="File path on target", required=True),
        ],
        returns="Hex-encoded file contents",
    ),
    ToolFunction(
        name="frida.file_write_target",
        description="Write data to a file on the target device",
        parameters=[
            ToolParameter(name="path", type="string", description="File path on target", required=True),
            ToolParameter(name="hex_data", type="string", description="Hex-encoded data to write", required=True),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.sqlite_open",
        description="Open a SQLite database on the target device",
        parameters=[
            ToolParameter(name="path", type="string", description="Database file path on target", required=True),
        ],
        returns="Script ID for the database session",
    ),
    ToolFunction(
        name="frida.sqlite_exec",
        description="Execute SQL on an open SQLite database",
        parameters=[
            ToolParameter(name="script_id", type="string", description="Database session script ID", required=True),
            ToolParameter(name="sql", type="string", description="SQL statement to execute", required=True),
        ],
        returns="Query results as list of rows",
    ),
    ToolFunction(
        name="frida.sqlite_dump",
        description="Dump all tables from a SQLite database",
        parameters=[
            ToolParameter(name="path", type="string", description="Database file path on target", required=True),
        ],
        returns="SQL dump text",
    ),
    ToolFunction(
        name="frida.write_code",
        description="Write machine code instructions at an address",
        parameters=[
            ToolParameter(name="address", type="integer", description="Target address", required=True),
            ToolParameter(
                name="architecture",
                type="string",
                description="Target architecture",
                required=True,
                enum=["x86", "arm", "arm64", "thumb", "mips"],
            ),
            ToolParameter(name="instructions", type="array", description="List of instruction method calls", required=True),
        ],
        returns="Number of bytes written",
    ),
    ToolFunction(
        name="frida.cloak_add_thread",
        description="Hide a thread from other tools via Frida Cloak",
        parameters=[
            ToolParameter(name="thread_id", type="integer", description="Thread ID to cloak", required=True),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.cloak_remove_thread",
        description="Uncloak a previously cloaked thread",
        parameters=[
            ToolParameter(name="thread_id", type="integer", description="Thread ID to uncloak", required=True),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.cloak_add_range",
        description="Hide a memory range from other tools via Frida Cloak",
        parameters=[
            ToolParameter(name="address", type="integer", description="Start address", required=True),
            ToolParameter(name="size", type="integer", description="Size in bytes", required=True),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.cloak_remove_range",
        description="Uncloak a previously cloaked memory range",
        parameters=[
            ToolParameter(name="address", type="integer", description="Start address", required=True),
            ToolParameter(name="size", type="integer", description="Size in bytes", required=True),
        ],
        returns="Success status",
    ),
    ToolFunction(
        name="frida.compile_typescript",
        description="Compile TypeScript source to JavaScript using Frida compiler",
        parameters=[
            ToolParameter(name="source", type="string", description="TypeScript source code or entry path", required=True),
            ToolParameter(name="project_root", type="string", description="Project root for imports", required=False),
        ],
        returns="Compiled JavaScript source",
    ),
    ToolFunction(
        name="frida.monitor_path",
        description="Monitor a file path for changes on the target device",
        parameters=[
            ToolParameter(name="path", type="string", description="Path to monitor", required=True),
        ],
        returns="Monitor ID",
    ),
    ToolFunction(
        name="frida.stop_monitor",
        description="Stop a file monitor",
        parameters=[
            ToolParameter(name="monitor_id", type="string", description="ID of the monitor to stop", required=True),
        ],
        returns="Success status",
    ),
]


def _write_typescript_tempfile(source: str) -> Path:
    """Write TypeScript source to a temporary ``.ts`` file.

    Creates a named temporary file with a ``.ts`` suffix that survives
    the handle close so the Frida compiler can open it by path. The
    caller is responsible for deleting the returned path.

    Args:
        source: TypeScript source code to persist.

    Returns:
        Path: Filesystem path to the temporary file.
    """
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".ts",
        delete=False,
        encoding="utf-8",
    ) as temp_file:
        temp_file.write(source)
        return Path(temp_file.name)


class FridaBridge(InstrumentationBridge):
    """Bridge for Frida dynamic instrumentation.

    Provides function hooking, memory manipulation, and script execution capabilities using the Frida framework. Instances own the device
    and session slots, the script and hook registries, the message-handler dispatch state, process identifier tracking for attach/spawn,
    stalker and child-gating bookkeeping, crash and allocation caches, cancellable references, and the declared dynamic-analysis
    capabilities advertised to the orchestrator.
    """

    def __init__(self) -> None:
        """Initialize the FridaBridge instance."""
        super().__init__()
        self._device: frida.core.Device | None = None
        self._session: frida.core.Session | None = None
        self._scripts: dict[str, frida.core.Script] = {}
        self._hooks: dict[str, HookInfo] = {}
        self._message_handler: Callable[[dict[str, object]], None] | None = None
        self._message_handler_lock: threading.Lock = threading.Lock()
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
        self._cancellables: dict[str, frida.Cancellable] = {}
        self._call_probes: dict[str, str] = {}
        self._exception_handler_script: str | None = None
        self._file_monitors: dict[str, object] = {}
        self._capabilities = BridgeCapabilities(
            supports_dynamic_analysis=True,
            supports_patching=True,
            supports_scripting=True,
            supports_memory_access=True,
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

        for monitor_id, monitor_obj in list(self._file_monitors.items()):
            try:
                disable_fn = getattr(monitor_obj, "disable", None)
                if callable(disable_fn):
                    await asyncio.to_thread(disable_fn)
            except Exception:
                _logger.exception("file_monitor_disable_failed", monitor_id=monitor_id)
        self._file_monitors.clear()

        for probe_id, probe_script_id in list(self._call_probes.items()):
            try:
                await self._unload_script(probe_script_id)
            except Exception:
                _logger.exception("call_probe_unload_failed", probe_id=probe_id)
        self._call_probes.clear()

        if self._exception_handler_script is not None:
            try:
                await self._unload_script(self._exception_handler_script)
            except Exception:
                _logger.exception("exception_handler_unload_failed")
            self._exception_handler_script = None

        self._cancellables.clear()

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

    async def attach(self, pid: int, *, cancellable_id: str | None = None) -> None:
        """Attach to a running process.

        Args:
            pid: Process ID to attach to.
            cancellable_id: Optional cancellation token identifier returned by
                :meth:`create_cancellable`. When supplied, the token is passed
                through to the underlying Frida call so callers can abort the
                attach with :meth:`cancel`.

        Raises:
            ToolError: If attachment fails.
        """
        if self._device is None:
            await self.initialize()

        device = self._device
        if device is None:
            raise ToolError(_ERR_DEVICE_FAILED)

        cancellable = self._resolve_cancellable(cancellable_id)

        try:
            self._session = await asyncio.to_thread(
                self._attach_with_cancellable,
                device,
                pid,
                cancellable,
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
        *,
        cancellable_id: str | None = None,
    ) -> int:
        """Spawn a new process with Frida instrumentation.

        Args:
            path: Path to executable.
            args: Command line arguments.
            cancellable_id: Optional cancellation token identifier returned by
                :meth:`create_cancellable`. When supplied, the token is passed
                through to the underlying Frida spawn and attach calls so the
                caller can abort the operation via :meth:`cancel`.

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

        cancellable = self._resolve_cancellable(cancellable_id)

        spawn_argv: list[str | bytes] = [str(path)]
        if args:
            spawn_argv.extend(args)

        try:
            pid: int = await asyncio.to_thread(
                self._spawn_with_cancellable,
                device,
                str(path),
                spawn_argv,
                cancellable,
            )
        except Exception as e:
            _logger.warning("frida_spawn_failed", path=str(path), error=str(e))
            raise ToolError(_ERR_ATTACH_FAILED) from e

        try:
            self._session = await asyncio.to_thread(
                self._attach_with_cancellable,
                device,
                pid,
                cancellable,
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
            raise ToolError(_ERR_RESUME_FAILED) from e

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
            raise ToolError(_ERR_DETACH_FAILED) from e

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

        self._validate_protection(protection)

        _logger.debug("memory_regions_enumerating", protection=protection)
        escaped_protection = self._escape_js_string(protection)
        script_code = (
            f"var ranges = Process.enumerateRanges('{escaped_protection}" + "');\n"
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

    async def scan_memory(
        self,
        pattern: bytes,
        *,
        module_name: str | None = None,
    ) -> list[MemorySearchResult]:
        """Scan process memory for a pattern across all readable pages.

        Args:
            pattern: Byte pattern to search for.
            module_name: Optional module name to limit scan scope.

        Returns:
            list[MemorySearchResult]: List of matches with context.

        Raises:
            ToolError: If scan fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        _logger.debug("memory_scan_starting", pattern_length=len(pattern), module_name=module_name)
        hex_pattern = " ".join(f"{b:02x}" for b in pattern)

        if module_name is not None:
            escaped_module = self._escape_js_string(module_name)
            range_source = (
                f"var mod = Process.findModuleByName('{escaped_module}');\n"
                "var ranges = mod ? [{ base: mod.base, size: mod.size, "
                "protection: 'r-x' }] : [];\n"
            )
        else:
            range_source = "var ranges = Process.enumerateRanges('---');\n"

        script_code = f"""
        {range_source}
        var results = [];
        ranges.forEach(function(range) {{
            if (range.protection.indexOf('r') === -1) return;
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

        matches = await self._build_scan_results(
            scan_data=result.get("data", []),
            hex_pattern=hex_pattern,
            pattern_len=len(pattern),
        )

        _logger.debug("memory_scan_completed", matches=len(matches))
        return matches

    async def _build_scan_results(
        self,
        *,
        scan_data: object,
        hex_pattern: str,
        pattern_len: int,
    ) -> list[MemorySearchResult]:
        """Build ``MemorySearchResult`` entries with base64 context windows.

        Reads ``_SCAN_CONTEXT_BYTES`` bytes before and after each match and
        base64-encodes them. Missing context from unreadable pages is returned
        as an empty string.

        Args:
            scan_data: Raw match list from the Frida scan script.
            hex_pattern: The space-separated hex representation of the pattern.
            pattern_len: Length of the search pattern in bytes.

        Returns:
            list[MemorySearchResult]: Parsed matches with base64 context.
        """
        matches: list[MemorySearchResult] = []
        if not isinstance(scan_data, list):
            return matches
        for raw_match in cast("list[object]", scan_data):
            if not isinstance(raw_match, dict):
                continue
            m = cast("dict[str, object]", raw_match)
            addr_str = str(m.get("address", "0"))
            addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
            context_before_b64 = await self._read_scan_context(
                address=max(0, addr - _SCAN_CONTEXT_BYTES),
                size=min(addr, _SCAN_CONTEXT_BYTES),
                log_key="scan_context_before_read_failed",
            )
            context_after_b64 = await self._read_scan_context(
                address=addr + pattern_len,
                size=_SCAN_CONTEXT_BYTES,
                log_key="scan_context_after_read_failed",
            )
            matches.append(
                MemorySearchResult(
                    address=addr,
                    matched_bytes=hex_pattern,
                    context_before=context_before_b64,
                    context_after=context_after_b64,
                ),
            )
        return matches

    async def _read_scan_context(
        self,
        *,
        address: int,
        size: int,
        log_key: str,
    ) -> str:
        """Read ``size`` bytes from ``address`` and return base64 or empty on failure.

        Args:
            address: Start address to read.
            size: Number of bytes to read.
            log_key: Structured-logging event name for failed reads.

        Returns:
            str: Base64-encoded bytes, or empty string if the read fails.
        """
        if size <= 0:
            return ""
        try:
            data = await self.read_memory(address, size)
        except ToolError:
            _logger.debug(log_key, address=hex(address), size=size)
            return ""
        return base64.b64encode(data).decode("ascii")

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

        escaped_module = self._escape_js_string(module_name)
        script_code = f"""
        var mod = Process.findModuleByName('{escaped_module}');
        if (!mod) {{
            send({{ type: 'exports', moduleFound: false, data: [] }});
        }} else {{
            var exports = mod.enumerateExports();
            var result = exports.map(function(e) {{
                return {{
                    name: e.name,
                    type: e.type,
                    address: e.address.toString()
                }};
            }});
            send({{ type: 'exports', moduleFound: true, data: result }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(_ERR_EXPORT_NOT_FOUND)

        if result.get("moduleFound") is False:
            raise ToolError(
                _ERR_MODULE_NOT_FOUND,
                details={"module": module_name},
            )

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
        on_message, event = self._make_payload_waiter(messages, self._dispatch_message)

        script.on("message", on_message)
        await asyncio.to_thread(script.load)

        try:
            await asyncio.wait_for(event.wait(), timeout=5.0)
        except TimeoutError as e:
            await asyncio.to_thread(script.unload)
            _logger.warning("hook_attach_timeout", target=target)
            raise ToolError(_ERR_HOOK_FAILED) from e

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
            elif msg["type"] == "error":
                await asyncio.to_thread(script.unload)
                description = msg.get("description", "")
                _logger.warning("hook_attach_failed", target=target, description=description)
                raise ToolError(_ERR_HOOK_FAILED, details={"reason": str(description)})

        if address is None:
            await asyncio.to_thread(script.unload)
            _logger.warning("hook_attach_no_ack", target=target)
            raise ToolError(_ERR_HOOK_FAILED)

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
            """Forward persistent script messages to the bridge dispatcher.

            Args:
                message: Message payload emitted by the persistent script.
                data: Optional binary payload attached to the message.
            """
            del data
            self._dispatch_message(dict(cast("dict[str, object]", message)))

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
        *,
        return_type: str = "pointer",
        arg_types: Sequence[str] | None = None,
        calling_convention: str = "default",
    ) -> int:
        """Call a function in the target process with typed arguments.

        Args:
            address: Function address.
            args: Function arguments.
            return_type: NativeFunction return type (default 'pointer').
            arg_types: Per-argument type list; defaults to 'pointer' for each.
            calling_convention: Calling convention (default 'default').

        Returns:
            int: Function return value.

        Raises:
            ToolError: If call fails or types are invalid.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        if return_type not in _VALID_NATIVE_TYPES:
            raise ToolError(_ERR_CALL_FAILED, details={"reason": f"invalid return type: {return_type}"})
        if calling_convention not in _VALID_CALLING_CONVENTIONS:
            raise ToolError(_ERR_CALL_FAILED, details={"reason": f"invalid calling convention: {calling_convention}"})

        args_list = list(args) if args else []
        resolved_arg_types: list[str] = []
        if arg_types is not None:
            for at in arg_types:
                if at not in _VALID_NATIVE_TYPES:
                    raise ToolError(_ERR_CALL_FAILED, details={"reason": f"invalid arg type: {at}"})
                resolved_arg_types.append(at)
        else:
            resolved_arg_types = ["pointer"] * len(args_list)

        _logger.debug("function_calling", address=hex(address), arg_count=len(args_list))
        arg_types_js = ", ".join(f"'{t}'" for t in resolved_arg_types)
        args_code = ", ".join(f"ptr({a})" for a in args_list)

        cc_part = ""
        if calling_convention != "default":
            cc_part = f", '{calling_convention}'"

        if return_type == "void":
            extract_js = "send({ type: 'call_result', value: 0 });"
        elif return_type in {"float", "double"}:
            extract_js = "send({ type: 'call_result', value: result });"
        else:
            extract_js = "send({ type: 'call_result', value: result.toInt32() });"

        script_code = f"""
        var func = new NativeFunction(ptr({address}), '{return_type}', [{arg_types_js}]{cc_part});
        var result = func({args_code});
        {extract_js}
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
        *,
        cancellable_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute a script and wait for result.

        Args:
            script_code: JavaScript code to execute.
            max_wait: Maximum seconds to wait for a response.
            cancellable_id: Optional cancellation token identifier returned by
                :meth:`create_cancellable`. When supplied, the token is
                forwarded to ``Session.create_script`` so the compilation
                step can be aborted via :meth:`cancel`.

        Returns:
            dict[str, Any]: Script result as dictionary.

        Raises:
            ToolError: If not attached to a process.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        cancellable = self._resolve_cancellable(cancellable_id)

        result: dict[str, Any] = {}
        event = asyncio.Event()
        loop = asyncio.get_running_loop()

        def on_message(message: ScriptMessage, data: bytes | None) -> None:
            """Capture the first send/error response and release the waiter.

            Args:
                message: Message payload emitted by the Frida script.
                data: Optional binary payload attached to the message.
            """
            if message["type"] == "send":
                payload = message.get("payload", {})
                if isinstance(payload, dict):
                    result.update(dict(cast("dict[str, object]", payload).items()))
                    if data:
                        result["data"] = list(data)
            elif message["type"] == "error":
                result["error"] = message["description"]
            else:
                return
            loop.call_soon_threadsafe(event.set)

        script = await asyncio.to_thread(
            self._create_script_with_cancellable,
            self._session,
            script_code,
            cancellable,
        )
        script.on("message", on_message)
        await asyncio.to_thread(script.load)

        try:
            await asyncio.wait_for(event.wait(), timeout=max_wait)
        except TimeoutError:
            _logger.warning("frida_script_execution_timeout", max_wait=max_wait)
            result["error"] = "Script execution timed out"

        await asyncio.to_thread(script.unload)

        return result

    @staticmethod
    def _make_payload_waiter(
        messages: list[ScriptMessage],
        dispatch: Callable[[dict[str, object]], None],
    ) -> tuple[
        Callable[[ScriptMessage, bytes | None], None],
        asyncio.Event,
    ]:
        """Build a Frida ``on_message`` callback that wakes on send/error only.

        The returned callback buffers every message and forwards it to the
        provided dispatcher, but only releases the event when a ``send`` or
        ``error`` payload is observed. This lets callers await the first real
        script response without relying on a fixed sleep.

        Args:
            messages: Mutable buffer that will receive every message for
                later inspection.
            dispatch: Bridge-wide dispatcher invoked for each message so
                external subscribers still observe the traffic.

        Returns:
            tuple[Callable[[ScriptMessage, bytes | None], None], asyncio.Event]:
                Pair of the ``on_message`` callback and the event set when a
                ``send`` or ``error`` message arrives.
        """
        event = asyncio.Event()
        loop = asyncio.get_running_loop()

        def on_message(message: ScriptMessage, data: bytes | None) -> None:
            """Buffer messages and release the waiter on send/error payloads.

            Args:
                message: Message payload emitted by the Frida script.
                data: Optional binary payload attached to the message.
            """
            del data
            messages.append(message)
            dispatch(dict(cast("dict[str, object]", message)))
            msg_type = message["type"]
            if msg_type in {"send", "error"}:
                loop.call_soon_threadsafe(event.set)

        return on_message, event

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
        with self._message_handler_lock:
            self._message_handler = handler
        _logger.debug("message_handler_set")

    def _dispatch_message(self, message: dict[str, object]) -> None:
        """Dispatch a message to the registered handler in a thread-safe manner.

        Reads the handler reference under a lock so that Frida's internal
        C callback thread never races with ``set_message_handler``.

        Args:
            message: Frida message dictionary.
        """
        with self._message_handler_lock:
            handler = self._message_handler
        if handler is not None:
            handler(message)

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

        escaped_module = self._escape_js_string(module_name)
        script_code = f"""
        var mod = Process.findModuleByName('{escaped_module}');
        if (!mod) {{
            send({{ type: 'imports', moduleFound: false, data: [] }});
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
            send({{ type: 'imports', moduleFound: true, data: result }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)

        if "error" in result:
            raise ToolError(_ERR_IMPORT_NOT_FOUND)

        if result.get("moduleFound") is False:
            raise ToolError(
                _ERR_MODULE_NOT_FOUND,
                details={"module": module_name},
            )

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

        is_windows = sys.platform == "win32"
        if is_windows:
            script_code = """
            var k32 = Process.findModuleByName('kernel32.dll');
            var getPrio = null;
            var openThread = null;
            var closeHandle = null;
            if (k32) {
                try {
                    getPrio = new NativeFunction(
                        k32.getExportByName('GetThreadPriority'),
                        'int',
                        ['pointer']
                    );
                    openThread = new NativeFunction(
                        k32.getExportByName('OpenThread'),
                        'pointer',
                        ['uint32', 'int', 'uint32']
                    );
                    closeHandle = new NativeFunction(
                        k32.getExportByName('CloseHandle'),
                        'int',
                        ['pointer']
                    );
                } catch (e) {
                    getPrio = null;
                }
            }
            var THREAD_QUERY_LIMITED_INFORMATION = 0x0800;
            var threads = Process.enumerateThreads();
            var result = threads.map(function(t) {
                var prio = 0;
                if (getPrio && openThread && closeHandle) {
                    try {
                        var h = openThread(THREAD_QUERY_LIMITED_INFORMATION, 0, t.id);
                        if (!h.isNull()) {
                            prio = getPrio(h);
                            closeHandle(h);
                        }
                    } catch (eInner) {
                        prio = 0;
                    }
                }
                return {
                    id: t.id,
                    state: t.state,
                    pc: t.context.pc.toString(),
                    currentPc: t.context.pc.toString(),
                    priority: prio
                };
            });
            send({ type: 'threads', data: result });
            """
        else:
            script_code = """
            var threads = Process.enumerateThreads();
            var result = threads.map(function(t) {
                return {
                    id: t.id,
                    state: t.state,
                    pc: t.context.pc.toString(),
                    currentPc: t.context.pc.toString(),
                    priority: 0
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
                current_pc_val = t.get("currentPc", t.get("pc", "0"))
                pc_str = str(current_pc_val)
                pc = int(pc_str, 16) if pc_str.startswith("0x") else int(pc_str)
                prio_val = t.get("priority", 0)
                priority = int(prio_val) if isinstance(prio_val, (int, float)) else 0
                threads.append(
                    ThreadInfo(
                        tid=int(tid_val) if isinstance(tid_val, (int, float)) else 0,
                        start_address=pc,
                        state=str(state_val) if state_val else "waiting",
                        priority=priority,
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
        on_message, event = self._make_payload_waiter(messages, self._dispatch_message)

        script.on("message", on_message)
        await asyncio.to_thread(script.load)
        try:
            await asyncio.wait_for(event.wait(), timeout=5.0)
        except TimeoutError as e:
            await asyncio.to_thread(script.unload)
            _logger.warning("allocate_memory_timeout", size=size)
            raise ToolError(_ERR_ALLOC_FAILED) from e

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

        self._validate_protection(protection)

        escaped_protection = self._escape_js_string(protection)
        script_code = f"""
        try {{
            Memory.protect(ptr({address}), {size}, '{escaped_protection}');
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

        escaped_module = self._escape_js_string(module_name)
        script_code = f"""
        var mod = Process.findModuleByName('{escaped_module}');
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

        escaped_name = self._escape_js_string(name)
        script_code = f"""
        var addrs = DebugSymbol.findFunctionsNamed('{escaped_name}');
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

    async def resolve_api(
        self,
        query: str,
        *,
        resolver_type: str = "module",
    ) -> list[ApiResolverMatch]:
        """Resolve API functions using Frida's ApiResolver.

        Args:
            query: Query pattern (e.g., 'exports:*!CreateFile*').
            resolver_type: Resolver type ('module', 'objc', or 'swift').

        Returns:
            list[ApiResolverMatch]: List of matching API names and addresses.

        Raises:
            ToolError: If resolution fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        if resolver_type not in _VALID_RESOLVER_TYPES:
            raise ToolError(_ERR_RESOLVE_FAILED, details={"reason": f"invalid resolver type: {resolver_type}"})

        escaped_query = self._escape_js_string(query)
        script_code = f"""
        var resolver = new ApiResolver('{resolver_type}');
        var matches = resolver.enumerateMatches('{escaped_query}');
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

    async def replace_function(
        self,
        target: str,
        replacement_code: str,
        *,
        calling_convention: str = "default",
    ) -> HookInfo:
        """Replace a function implementation with custom code.

        Args:
            target: Function name (module!func) or hex address.
            replacement_code: JavaScript body defining the NativeCallback.
            calling_convention: Calling convention for the replacement.

        Returns:
            HookInfo: Hook information for the replacement.

        Raises:
            ToolError: If replacement fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        if calling_convention not in _VALID_CALLING_CONVENTIONS:
            raise ToolError(_ERR_REPLACE_FAILED, details={"reason": f"invalid calling convention: {calling_convention}"})

        hook_id = str(uuid.uuid4())[:8]
        addr_resolve = self._resolve_target_js(target)

        cc_comment = f"// calling_convention: {calling_convention}" if calling_convention != "default" else ""
        script_code = f"""
        {cc_comment}
        var targetAddr = {addr_resolve};
        var replacement = {replacement_code};
        Interceptor.replace(targetAddr, replacement);
        send({{ type: 'replaced', address: targetAddr.toString() }});
        """

        script = await asyncio.to_thread(self._session.create_script, script_code)

        messages: list[ScriptMessage] = []
        on_message, event = self._make_payload_waiter(messages, self._dispatch_message)

        script.on("message", on_message)
        await asyncio.to_thread(script.load)
        try:
            await asyncio.wait_for(event.wait(), timeout=5.0)
        except TimeoutError as e:
            await asyncio.to_thread(script.unload)
            _logger.warning("replace_function_timeout", target=target)
            raise ToolError(_ERR_REPLACE_FAILED) from e

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

    async def enumerate_processes(self) -> list[FridaProcessEntry]:
        """List all running processes on the device.

        Does not require an active session attachment.

        Returns:
            list[FridaProcessEntry]: List of process entries with pid and name.

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
        return [FridaProcessEntry(pid=proc.pid, name=proc.name) for proc in processes]

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

    @staticmethod
    def _validate_protection(protection: str) -> None:
        """Validate that ``protection`` uses a supported Frida rwx triplet.

        Args:
            protection: Protection string such as ``'r-x'`` or ``'rwx'``.

        Raises:
            ToolError: If ``protection`` is not a member of
                ``_VALID_PROTECTION_FLAGS``.
        """
        if protection not in _VALID_PROTECTION_FLAGS:
            raise ToolError(
                _ERR_INVALID_PROTECTION,
                details={"reason": f"invalid protection flags: {protection}"},
            )

    @staticmethod
    def _validate_socket_family(family: str) -> None:
        """Validate that ``family`` is a supported Frida socket family.

        Args:
            family: Socket family identifier such as ``'ipv4'``.

        Raises:
            ToolError: If ``family`` is not a member of
                ``_VALID_SOCKET_FAMILIES``.
        """
        if family not in _VALID_SOCKET_FAMILIES:
            raise ToolError(
                _ERR_SOCKET_FAILED,
                details={"reason": f"invalid socket family: {family}"},
            )

    @staticmethod
    def _escape_js_string(value: str) -> str:
        """Escape a Python string for safe embedding in JavaScript string literals.

        Escapes characters that are unsafe in single-quoted, double-quoted, and
        template-literal JavaScript contexts. All non-ASCII and control characters
        are converted to their four-digit hexadecimal unicode escapes so the
        resulting literal is ASCII-only and cannot terminate or escape any
        enclosing context.

        Args:
            value: The raw string to escape.

        Returns:
            str: Escaped string safe to embed inside JS string literals using
            single quotes, double quotes, or backticks.
        """
        out: list[str] = []
        for ch in value:
            code = ord(ch)
            if ch == "\\":
                out.append("\\\\")
            elif ch == "'":
                out.append("\\'")
            elif ch == '"':
                out.append('\\"')
            elif ch == "`":
                out.append("\\`")
            elif ch == "$":
                out.append("\\$")
            elif ch == "\n":
                out.append("\\n")
            elif ch == "\r":
                out.append("\\r")
            elif ch == "\t":
                out.append("\\t")
            elif ch == "\b":
                out.append("\\b")
            elif ch == "\f":
                out.append("\\f")
            elif ch == "\v":
                out.append("\\v")
            elif ch == "\0":
                out.append("\\u0000")
            elif code < _ASCII_PRINTABLE_MIN or code == _ASCII_DEL or code > _ASCII_PRINTABLE_MAX:
                out.append("\\u" + format(code, "04x"))
            else:
                out.append(ch)
        return "".join(out)

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
        started_event = asyncio.Event()
        load_loop = asyncio.get_running_loop()
        start_status: dict[str, object] = {}

        def on_stalker_message(message: ScriptMessage, data: bytes | None) -> None:
            """Parse Stalker batch payloads and forward messages downstream.

            When a ``stalker_batch`` message arrives, the nested event list
            is decoded and stored against the followed thread identifier.
            The waiter is released once ``stalker_started`` or any ``error``
            message is observed. All messages are forwarded to the bridge
            dispatcher.

            Args:
                message: Message payload emitted by the Stalker script.
                data: Optional binary payload attached to the message.
            """
            del data
            if message["type"] == "send":
                payload = message.get("payload", {})
                if isinstance(payload, dict):
                    payload_dict = cast("dict[str, object]", payload)
                    inner_type = payload_dict.get("type")
                    if inner_type == "stalker_batch":
                        raw_evts = payload_dict.get("events")
                        if isinstance(raw_evts, list):
                            self._parse_stalker_batch(captured_tid, cast("list[object]", raw_evts))
                    elif inner_type == "stalker_started":
                        start_status["started"] = True
                        load_loop.call_soon_threadsafe(started_event.set)
            elif message["type"] == "error":
                start_status["error"] = message["description"]
                load_loop.call_soon_threadsafe(started_event.set)
            self._dispatch_message(dict(cast("dict[str, object]", message)))

        script.on("message", on_stalker_message)
        try:
            await asyncio.to_thread(script.load)
        except Exception as e:
            _logger.warning("stalker_load_failed", thread_id=effective_tid, error=str(e))
            raise ToolError(_ERR_STALKER_FAILED) from e

        try:
            await asyncio.wait_for(started_event.wait(), timeout=5.0)
        except TimeoutError as e:
            await asyncio.to_thread(script.unload)
            _logger.warning("stalker_start_timeout", thread_id=effective_tid)
            raise ToolError(_ERR_STALKER_FAILED) from e

        if "error" in start_status:
            await asyncio.to_thread(script.unload)
            _logger.warning(
                "stalker_start_failed",
                thread_id=effective_tid,
                description=start_status.get("error", ""),
            )
            raise ToolError(_ERR_STALKER_FAILED, details={"reason": str(start_status.get("error", ""))})

        if not start_status.get("started"):
            await asyncio.to_thread(script.unload)
            _logger.warning("stalker_not_started", thread_id=effective_tid)
            raise ToolError(_ERR_STALKER_FAILED)

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
            """Record a newly spawned child process reported by the device.

            Extracts identifying attributes from the Frida ``Child`` object,
            appends a ``ChildProcessInfo`` record to the gated-children
            list, and publishes a ``child_added`` dispatch message.

            Args:
                child: Frida ``Child`` object describing the new process.
            """
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
            self._dispatch_message({
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
            """Capture a crash report emitted by the Frida device.

            Builds a ``CrashInfo`` record from the attributes of the crash
            object, appends it to the in-memory crash log, and publishes a
            ``process_crashed`` dispatch message for downstream consumers.

            Args:
                crash: Frida ``Crash`` object describing the failure.
            """
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
            self._dispatch_message({
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

    @staticmethod
    async def enumerate_devices() -> list[FridaDeviceInfo]:
        """List all available Frida devices.

        Returns:
            list[FridaDeviceInfo]: List of device information.
        """
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

    async def post_message(self, script_id: str, message: str) -> bool:
        """Send a message from Python to a running Frida script.

        Args:
            script_id: ID of the target script.
            message: JSON-encoded message string.

        Returns:
            bool: True if the message was posted successfully.

        Raises:
            ToolError: If the script is not found or message is invalid JSON.
        """
        if script_id not in self._scripts:
            raise ToolError(_ERR_SCRIPT_NOT_FOUND)

        script = self._scripts[script_id]
        try:
            parsed = json.loads(message)
        except (JSONDecodeError, TypeError) as e:
            _logger.warning("post_message_invalid_json", script_id=script_id, error=str(e))
            raise ToolError(_ERR_INVALID_JSON_MESSAGE) from e
        await asyncio.to_thread(script.post, parsed)
        _logger.debug("message_posted", script_id=script_id)
        return True

    async def eternalize_script(self, script_id: str) -> bool:
        """Make a script persistent without a Python reference.

        The script will survive even after the Python side disconnects.

        Args:
            script_id: ID of the script to eternalize.

        Returns:
            bool: True if the script was eternalized successfully.

        Raises:
            ToolError: If the script is not found.
        """
        if script_id not in self._scripts:
            raise ToolError(_ERR_SCRIPT_NOT_FOUND)

        script = self._scripts[script_id]
        await asyncio.to_thread(script.eternalize)
        del self._scripts[script_id]
        _logger.info("script_eternalized", script_id=script_id)
        return True

    async def rpc_call(
        self,
        script_id: str,
        method_name: str,
        args: Sequence[object] | None = None,
    ) -> object:
        """Call an RPC-exported function in a running script.

        Args:
            script_id: ID of the target script.
            method_name: Name of the exported method.
            args: Arguments for the RPC call.

        Returns:
            object: Return value from the RPC call.

        Raises:
            ToolError: If the script is not found or the call fails.
        """
        if script_id not in self._scripts:
            raise ToolError(_ERR_SCRIPT_NOT_FOUND)

        script = self._scripts[script_id]
        args_list = list(args) if args else []
        rpc_method: object = getattr(script.exports_sync, method_name)
        if not callable(rpc_method):
            raise ToolError(_ERR_RPC_FAILED, details={"reason": f"'{method_name}' is not callable"})
        try:
            result: object = await asyncio.to_thread(rpc_method, *args_list)
        except Exception as e:
            _logger.warning("rpc_call_failed", script_id=script_id, method=method_name, error=str(e))
            raise ToolError(_ERR_RPC_FAILED) from e
        else:
            _logger.debug("rpc_call_complete", method=method_name)
            return result

    async def create_cancellable(self) -> str:
        """Create a Frida cancellation token for long-running operations.

        Returns:
            str: Cancellable ID for later cancellation.
        """
        cancellable = frida.Cancellable()
        cancellable_id = str(uuid.uuid4())[:8]
        self._cancellables[cancellable_id] = cancellable
        _logger.debug("cancellable_created", cancellable_id=cancellable_id)
        return cancellable_id

    async def cancel(self, cancellable_id: str) -> bool:
        """Cancel a long-running operation via its cancellation token.

        Args:
            cancellable_id: ID of the cancellable to trigger.

        Returns:
            bool: True if cancelled successfully, False if not found.
        """
        cancellable = self._cancellables.pop(cancellable_id, None)
        if cancellable is None:
            return False
        cancellable.cancel()
        _logger.info("operation_cancelled", cancellable_id=cancellable_id)
        return True

    def _resolve_cancellable(self, cancellable_id: str | None) -> frida.Cancellable | None:
        """Look up a cancellation token by identifier.

        Args:
            cancellable_id: Identifier returned from :meth:`create_cancellable`,
                or ``None`` if no token is requested.

        Returns:
            frida.Cancellable | None: The registered token, or ``None`` when
                no identifier was supplied.

        Raises:
            ToolError: If ``cancellable_id`` is provided but unknown.
        """
        if cancellable_id is None:
            return None
        cancellable = self._cancellables.get(cancellable_id)
        if cancellable is None:
            raise ToolError(
                _ERR_UNKNOWN_CANCELLABLE,
                details={"cancellable_id": cancellable_id},
            )
        return cancellable

    @staticmethod
    def _attach_with_cancellable(
        device: frida.core.Device,
        pid: int,
        cancellable: frida.Cancellable | None,
    ) -> frida.core.Session:
        """Invoke ``Device.attach`` honoring an optional cancellation token.

        Args:
            device: Frida device to attach through.
            pid: Target process identifier.
            cancellable: Optional cancellation token; passed as a keyword
                argument to Frida when provided.

        Returns:
            frida.core.Session: The attached Frida session.
        """
        attach_fn = cast("Callable[..., frida.core.Session]", device.attach)
        if cancellable is not None:
            return attach_fn(pid, cancellable=cancellable)
        return attach_fn(pid)

    @staticmethod
    def _spawn_with_cancellable(
        device: frida.core.Device,
        program: str,
        argv: Sequence[str | bytes],
        cancellable: frida.Cancellable | None,
    ) -> int:
        """Invoke ``Device.spawn`` honoring an optional cancellation token.

        Args:
            device: Frida device to spawn on.
            program: Path to the executable.
            argv: Argument vector for the spawned process.
            cancellable: Optional cancellation token; passed as a keyword
                argument to Frida when provided.

        Returns:
            int: PID of the spawned process.
        """
        spawn_fn = cast("Callable[..., int]", device.spawn)
        if cancellable is not None:
            return spawn_fn(program, argv=list(argv), cancellable=cancellable)
        return spawn_fn(program, argv=list(argv))

    @staticmethod
    def _create_script_with_cancellable(
        session: frida.core.Session,
        source: str,
        cancellable: frida.Cancellable | None,
    ) -> frida.core.Script:
        """Invoke ``Session.create_script`` honoring an optional cancellation token.

        Args:
            session: Frida session that will own the script.
            source: JavaScript source to compile.
            cancellable: Optional cancellation token; passed as a keyword
                argument to Frida when provided.

        Returns:
            frida.core.Script: The created Frida script.
        """
        create_fn = cast("Callable[..., frida.core.Script]", session.create_script)
        if cancellable is not None:
            return create_fn(source, cancellable=cancellable)
        return create_fn(source)

    async def patch_code(self, address: int, hex_data: str) -> bool:
        """Patch code at an address using Memory.patchCode with instruction cache flush.

        Args:
            address: Address to patch.
            hex_data: Hex-encoded bytes to write.

        Returns:
            bool: True if the code was patched successfully.

        Raises:
            ToolError: If not attached or patching fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        byte_values = bytes.fromhex(hex_data.replace(" ", ""))
        hex_array = ", ".join(f"0x{b:02x}" for b in byte_values)
        size = len(byte_values)

        script_code = f"""
        try {{
            var bytes = [{hex_array}];
            Memory.patchCode(ptr({address}), {size}, function(code) {{
                code.writeByteArray(bytes);
            }});
            send({{ type: 'patch', success: true }});
        }} catch (e) {{
            send({{ type: 'patch', success: false, error: e.message }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result or not result.get("success", False):
            raise ToolError(_ERR_PATCH_FAILED)

        _logger.info("code_patched", address=hex(address), size=size)
        return True

    async def allocate_string(self, value: str, encoding: str = "utf8") -> int:
        """Allocate a string in the target process memory.

        Uses a persistent script to prevent garbage collection.

        Args:
            value: String value to allocate.
            encoding: String encoding ('utf8', 'ansi', or 'utf16').

        Returns:
            int: Address of the allocated string.

        Raises:
            ToolError: If not attached, encoding is invalid, or allocation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        if encoding not in _VALID_STRING_ENCODINGS:
            raise ToolError(_ERR_STRING_ALLOC_FAILED, details={"reason": f"invalid encoding: {encoding}"})

        escaped = self._escape_js_string(value)
        alloc_fn_map = {"utf8": "allocUtf8String", "ansi": "allocAnsiString", "utf16": "allocUtf16String"}
        alloc_fn = alloc_fn_map[encoding]

        script_code = f"""
        var str = Memory.{alloc_fn}('{escaped}');
        send({{ type: 'string_alloc', address: str.toString() }});
        """

        script_id = str(uuid.uuid4())[:8]
        script = await asyncio.to_thread(self._session.create_script, script_code)

        messages: list[ScriptMessage] = []
        on_message, event = self._make_payload_waiter(messages, self._dispatch_message)

        script.on("message", on_message)
        await asyncio.to_thread(script.load)
        try:
            await asyncio.wait_for(event.wait(), timeout=5.0)
        except TimeoutError as e:
            await asyncio.to_thread(script.unload)
            _logger.warning("allocate_string_timeout", encoding=encoding)
            raise ToolError(_ERR_STRING_ALLOC_FAILED) from e

        addr: int = 0
        for msg in messages:
            if msg["type"] == "send":
                payload = msg.get("payload", {})
                if isinstance(payload, dict):
                    payload_dict = cast("dict[str, object]", payload)
                    if payload_dict.get("type") == "string_alloc":
                        addr_str = str(payload_dict.get("address", "0"))
                        addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
            elif msg["type"] == "error":
                await asyncio.to_thread(script.unload)
                raise ToolError(_ERR_STRING_ALLOC_FAILED)

        if addr == 0:
            await asyncio.to_thread(script.unload)
            raise ToolError(_ERR_STRING_ALLOC_FAILED)

        self._scripts[script_id] = script
        self._alloc_scripts[addr] = script_id
        _logger.info("string_allocated", address=hex(addr), encoding=encoding)
        return addr

    async def enumerate_symbols(self, module_name: str) -> list[SymbolInfo]:
        """List all symbols in a module including debug symbols.

        Args:
            module_name: Name of the module.

        Returns:
            list[SymbolInfo]: List of symbol information.

        Raises:
            ToolError: If not attached or enumeration fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        escaped = self._escape_js_string(module_name)
        script_code = f"""
        var mod = Process.findModuleByName('{escaped}');
        if (!mod) {{
            send({{ type: 'symbols', data: [] }});
        }} else {{
            var syms = mod.enumerateSymbols();
            var result = syms.map(function(s) {{
                return {{
                    name: s.name,
                    address: s.address.toString(),
                    isGlobal: s.isGlobal,
                    type: s.type
                }};
            }});
            send({{ type: 'symbols', data: result }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result:
            raise ToolError(_ERR_ENUMERATE_FAILED)

        symbols: list[SymbolInfo] = []
        sym_data = result.get("data", [])
        if isinstance(sym_data, list):
            for raw_sym in cast("list[object]", sym_data):
                if not isinstance(raw_sym, dict):
                    continue
                s = cast("dict[str, object]", raw_sym)
                addr_str = str(s.get("address", "0"))
                addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                symbols.append(
                    SymbolInfo(
                        name=str(s.get("name", "")),
                        address=addr,
                        module_name=module_name,
                        file_name=None,
                        line_number=None,
                    ),
                )

        _logger.debug("symbols_enumerated", module=module_name, count=len(symbols))
        return symbols

    async def load_module(self, path: str) -> ModuleInfo:
        """Load a shared library into the target process.

        Args:
            path: Path to the library file.

        Returns:
            ModuleInfo: Information about the loaded module.

        Raises:
            ToolError: If not attached or loading fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        escaped = self._escape_js_string(path)
        script_code = f"""
        try {{
            var mod = Module.load('{escaped}');
            send({{ type: 'module_loaded', name: mod.name, path: mod.path, base: mod.base.toString(), size: mod.size }});
        }} catch (e) {{
            send({{ type: 'module_load_error', error: e.message }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result or result.get("type") == "module_load_error":
            raise ToolError(_ERR_MODULE_LOAD_FAILED)

        base_str = str(result.get("base", "0"))
        base = int(base_str, 16) if base_str.startswith("0x") else int(base_str)
        size_val = result.get("size", 0)

        _logger.info("module_loaded", path=path, base=hex(base))
        return ModuleInfo(
            name=str(result.get("name", "")),
            path=Path(str(result.get("path", path))),
            base_address=base,
            size=int(size_val) if isinstance(size_val, (int, float)) else 0,
            entry_point=0,
        )

    async def find_module_by_address(self, address: int) -> ModuleInfo | None:
        """Find which module contains a given address.

        Args:
            address: Address to look up.

        Returns:
            ModuleInfo | None: Module information or None if not found.

        Raises:
            ToolError: If not attached.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = f"""
        var mod = Process.findModuleByAddress(ptr({address}));
        if (mod) {{
            send({{ type: 'module', name: mod.name, path: mod.path, base: mod.base.toString(), size: mod.size }});
        }} else {{
            send({{ type: 'module', name: null }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result or result.get("name") is None:
            return None

        base_str = str(result.get("base", "0"))
        base = int(base_str, 16) if base_str.startswith("0x") else int(base_str)
        size_val = result.get("size", 0)

        return ModuleInfo(
            name=str(result.get("name", "")),
            path=Path(str(result.get("path", ""))),
            base_address=base,
            size=int(size_val) if isinstance(size_val, (int, float)) else 0,
            entry_point=0,
        )

    async def find_functions_matching(self, pattern: str) -> list[SymbolInfo]:
        """Find functions matching a glob pattern via DebugSymbol.

        Args:
            pattern: Glob pattern to match function names.

        Returns:
            list[SymbolInfo]: List of matching symbol information.

        Raises:
            ToolError: If not attached or search fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        escaped = self._escape_js_string(pattern)
        script_code = f"""
        var addrs = DebugSymbol.findFunctionsMatching('{escaped}');
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
                symbols.append(
                    SymbolInfo(
                        name=str(s.get("name", "")),
                        address=addr,
                        module_name=str(s.get("moduleName")) if s.get("moduleName") else None,
                        file_name=str(s.get("fileName")) if s.get("fileName") else None,
                        line_number=int(cast("int | float", s["lineNumber"])) if isinstance(s.get("lineNumber"), (int, float)) else None,
                    ),
                )

        _logger.debug("functions_matching", pattern=pattern, count=len(symbols))
        return symbols

    async def disassemble_instruction(self, address: int) -> InstructionInfo:
        """Disassemble a single instruction at an address.

        Args:
            address: Address to disassemble.

        Returns:
            InstructionInfo: Disassembled instruction details.

        Raises:
            ToolError: If not attached or disassembly fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = f"""
        try {{
            var insn = Instruction.parse(ptr({address}));
            send({{
                type: 'instruction',
                address: insn.address.toString(),
                next: insn.next.toString(),
                size: insn.size,
                mnemonic: insn.mnemonic,
                opStr: insn.opStr,
                string: insn.toString()
            }});
        }} catch (e) {{
            send({{ type: 'instruction_error', error: e.message }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result or result.get("type") == "instruction_error":
            raise ToolError(_ERR_RESOLVE_FAILED)

        addr_str = str(result.get("address", str(address)))
        insn_addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
        next_str = str(result.get("next", "0"))
        next_addr = int(next_str, 16) if next_str.startswith("0x") else int(next_str)
        size_val = result.get("size", 0)

        return InstructionInfo(
            address=insn_addr,
            next_address=next_addr,
            size=int(size_val) if isinstance(size_val, (int, float)) else 0,
            mnemonic=str(result.get("mnemonic", "")),
            op_str=str(result.get("opStr", "")),
            string=str(result.get("string", "")),
        )

    async def get_backtrace(
        self,
        context_address: int | None = None,
        backtracer: str = "accurate",
    ) -> list[SymbolInfo]:
        """Get a stack backtrace with optional context.

        Args:
            context_address: CPU context address (None for current).
            backtracer: Backtracer type ('accurate' or 'fuzzy').

        Returns:
            list[SymbolInfo]: List of backtrace frame symbols.

        Raises:
            ToolError: If not attached or backtrace fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        if backtracer not in _VALID_BACKTRACER_TYPES:
            raise ToolError(_ERR_RESOLVE_FAILED, details={"reason": f"invalid backtracer: {backtracer}"})

        bt_type = "Backtracer.ACCURATE" if backtracer == "accurate" else "Backtracer.FUZZY"
        ctx_js = f"ptr({context_address})" if context_address is not None else "NULL"

        script_code = f"""
        var bt = Thread.backtrace({ctx_js}, {bt_type});
        var result = bt.map(function(addr) {{
            var sym = DebugSymbol.fromAddress(addr);
            return {{
                name: sym.name,
                address: addr.toString(),
                moduleName: sym.moduleName,
                fileName: sym.fileName,
                lineNumber: sym.lineNumber
            }};
        }});
        send({{ type: 'backtrace', data: result }});
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result:
            raise ToolError(_ERR_RESOLVE_FAILED)

        frames: list[SymbolInfo] = []
        bt_data = result.get("data", [])
        if isinstance(bt_data, list):
            for raw_frame in cast("list[object]", bt_data):
                if not isinstance(raw_frame, dict):
                    continue
                f = cast("dict[str, object]", raw_frame)
                addr_str = str(f.get("address", "0"))
                addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                frames.append(
                    SymbolInfo(
                        name=str(f.get("name", "")),
                        address=addr,
                        module_name=str(f.get("moduleName")) if f.get("moduleName") else None,
                        file_name=str(f.get("fileName")) if f.get("fileName") else None,
                        line_number=int(cast("int | float", f["lineNumber"])) if isinstance(f.get("lineNumber"), (int, float)) else None,
                    ),
                )

        _logger.debug("backtrace_captured", frame_count=len(frames))
        return frames

    async def set_exception_handler(self) -> str:
        """Install a process-wide exception handler.

        Returns:
            str: Script ID for the exception handler.

        Raises:
            ToolError: If not attached or handler setup fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        if self._exception_handler_script is not None:
            return self._exception_handler_script

        script_code = """
        Process.setExceptionHandler(function(details) {
            send({
                type: 'exception',
                exType: details.type,
                address: details.address.toString(),
                context: details.context ? details.context.pc.toString() : null,
                nativeContext: details.nativeContext ? details.nativeContext.toString() : null
            });
            return false;
        });
        send({ type: 'exception_handler_installed' });
        """

        script_id = str(uuid.uuid4())[:8]
        try:
            script = await asyncio.to_thread(self._session.create_script, script_code)
        except Exception as e:
            raise ToolError(_ERR_EXCEPTION_HANDLER_FAILED) from e

        def on_message(message: ScriptMessage, data: bytes | None) -> None:
            """Forward exception-handler messages to the bridge dispatcher.

            Args:
                message: Message payload emitted by the exception handler.
                data: Optional binary payload attached to the message.
            """
            del data
            self._dispatch_message(dict(cast("dict[str, object]", message)))

        script.on("message", on_message)
        await asyncio.to_thread(script.load)

        self._scripts[script_id] = script
        self._exception_handler_script = script_id
        _logger.info("exception_handler_installed", script_id=script_id)
        return script_id

    async def revert_hook(self, target: str) -> bool:
        """Revert a function hook using Interceptor.revert.

        Args:
            target: Function target to revert.

        Returns:
            bool: True if the hook was reverted successfully.

        Raises:
            ToolError: If not attached or revert fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        addr_resolve = self._resolve_target_js(target)
        script_code = f"""
        try {{
            var targetAddr = {addr_resolve};
            Interceptor.revert(targetAddr);
            send({{ type: 'reverted', success: true }});
        }} catch (e) {{
            send({{ type: 'reverted', success: false, error: e.message }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result or not result.get("success", False):
            raise ToolError(_ERR_HOOK_FAILED)

        _logger.info("hook_reverted", target=target)
        return True

    async def flush_interceptor(self) -> bool:
        """Flush Interceptor inline caches to apply pending changes.

        Returns:
            bool: True if flush succeeded.

        Raises:
            ToolError: If not attached or flush fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = """
        Interceptor.flush();
        send({ type: 'flushed', success: true });
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result:
            raise ToolError(_ERR_HOOK_FAILED)

        _logger.debug("interceptor_flushed")
        return True

    async def call_system_function(
        self,
        address: int,
        args: Sequence[int] | None = None,
        *,
        return_type: str = "pointer",
        arg_types: Sequence[str] | None = None,
        calling_convention: str = "default",
    ) -> SystemCallResult:
        """Call a system function capturing errno and GetLastError.

        Args:
            address: Function address.
            args: Function arguments.
            return_type: NativeFunction return type.
            arg_types: Per-argument type list.
            calling_convention: Calling convention.

        Returns:
            SystemCallResult: Result with value, errno, and last_error.

        Raises:
            ToolError: If not attached, types are invalid, or call fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        if return_type not in _VALID_NATIVE_TYPES:
            raise ToolError(_ERR_CALL_FAILED, details={"reason": f"invalid return type: {return_type}"})
        if calling_convention not in _VALID_CALLING_CONVENTIONS:
            raise ToolError(_ERR_CALL_FAILED, details={"reason": f"invalid calling convention: {calling_convention}"})

        args_list = list(args) if args else []
        resolved_arg_types: list[str] = []
        if arg_types is not None:
            for at in arg_types:
                if at not in _VALID_NATIVE_TYPES:
                    raise ToolError(_ERR_CALL_FAILED, details={"reason": f"invalid arg type: {at}"})
                resolved_arg_types.append(at)
        else:
            resolved_arg_types = ["pointer"] * len(args_list)

        arg_types_js = ", ".join(f"'{t}'" for t in resolved_arg_types)
        args_code = ", ".join(f"ptr({a})" for a in args_list)
        cc_part = f", '{calling_convention}'" if calling_convention != "default" else ""

        script_code = f"""
        var func = new SystemFunction(ptr({address}), '{return_type}', [{arg_types_js}]{cc_part});
        var result = func({args_code});
        send({{
            type: 'syscall_result',
            value: result.value.toInt32 ? result.value.toInt32() : result.value,
            errno: result.errno || 0,
            lastError: result.lastError || 0
        }});
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result:
            raise ToolError(_ERR_CALL_FAILED)

        value_raw = result.get("value", 0)
        value = int(value_raw) if isinstance(value_raw, (int, float)) else 0
        errno_raw = result.get("errno", 0)
        errno_val = int(errno_raw) if isinstance(errno_raw, (int, float)) else 0
        last_err_raw = result.get("lastError", 0)
        last_err = int(last_err_raw) if isinstance(last_err_raw, (int, float)) else 0

        return SystemCallResult(value=value, errno=errno_val, last_error=last_err)

    async def stalker_add_call_probe(self, address: int, callback_code: str) -> str:
        """Add a Stalker call probe at an address.

        Args:
            address: Address to probe.
            callback_code: JavaScript callback code for the probe.

        Returns:
            str: Probe ID for later removal.

        Raises:
            ToolError: If not attached or probe installation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        probe_id = str(uuid.uuid4())[:8]
        script_code = f"""
        var probeId = Stalker.addCallProbe(ptr({address}), function(args) {{
            {callback_code}
        }});
        send({{ type: 'probe_added', probeId: probeId }});
        """

        script_id = str(uuid.uuid4())[:8]
        try:
            script = await asyncio.to_thread(self._session.create_script, script_code)
        except Exception as e:
            raise ToolError(_ERR_PROBE_FAILED) from e

        def on_message(message: ScriptMessage, data: bytes | None) -> None:
            """Forward call-probe messages to the bridge dispatcher.

            Args:
                message: Message payload emitted by the call probe.
                data: Optional binary payload attached to the message.
            """
            del data
            self._dispatch_message(dict(cast("dict[str, object]", message)))

        script.on("message", on_message)
        await asyncio.to_thread(script.load)

        self._scripts[script_id] = script
        self._call_probes[probe_id] = script_id
        _logger.info("call_probe_added", probe_id=probe_id, address=hex(address))
        return probe_id

    async def stalker_remove_call_probe(self, probe_id: str) -> bool:
        """Remove a Stalker call probe.

        Args:
            probe_id: ID of the probe to remove.

        Returns:
            bool: True if removed successfully, False if not found.
        """
        script_id = self._call_probes.pop(probe_id, None)
        if script_id is None:
            return False

        await self._unload_script(script_id)
        _logger.info("call_probe_removed", probe_id=probe_id)
        return True

    async def enumerate_applications(self) -> list[FridaApplicationInfo]:
        """List all installed applications on the device.

        Returns:
            list[FridaApplicationInfo]: List of application information.

        Raises:
            ToolError: If device is not available.
        """
        if self._device is None:
            await self.initialize()

        device = self._device
        if device is None:
            raise ToolError(_ERR_NO_DEVICE)

        apps = await asyncio.to_thread(device.enumerate_applications)
        _logger.debug("applications_enumerated", count=len(apps))
        return [
            FridaApplicationInfo(
                identifier=str(getattr(app, "identifier", "")),
                name=str(getattr(app, "name", "")),
                pid=int(getattr(app, "pid", 0)),
            )
            for app in apps
        ]

    async def inject_library_file(self, pid: int, path: str, entrypoint: str, data: str) -> int:
        """Inject a shared library file into a process.

        Args:
            pid: Target process ID.
            path: Path to the library.
            entrypoint: Entrypoint function name.
            data: String data to pass to the entrypoint.

        Returns:
            int: Injection ID.

        Raises:
            ToolError: If device is not available or injection fails.
        """
        if self._device is None:
            raise ToolError(_ERR_NO_DEVICE)

        try:
            inject_id: int = await asyncio.to_thread(
                self._device.inject_library_file,
                pid,
                path,
                entrypoint,
                data,
            )
        except Exception as e:
            _logger.warning("library_inject_file_failed", pid=pid, path=path, error=str(e))
            raise ToolError(_ERR_INJECT_FAILED) from e

        _logger.info("library_injected_file", pid=pid, path=path, inject_id=inject_id)
        return inject_id

    async def inject_library_blob(self, pid: int, blob_hex: str, entrypoint: str, data: str) -> int:
        """Inject a library from raw bytes into a process.

        Args:
            pid: Target process ID.
            blob_hex: Hex-encoded library bytes.
            entrypoint: Entrypoint function name.
            data: String data to pass to the entrypoint.

        Returns:
            int: Injection ID.

        Raises:
            ToolError: If device is not available or injection fails.
        """
        if self._device is None:
            raise ToolError(_ERR_NO_DEVICE)

        blob_bytes = bytes.fromhex(blob_hex.replace(" ", ""))
        try:
            inject_id: int = await asyncio.to_thread(
                self._device.inject_library_blob,
                pid,
                blob_bytes,
                entrypoint,
                data,
            )
        except Exception as e:
            _logger.warning("library_inject_blob_failed", pid=pid, error=str(e))
            raise ToolError(_ERR_INJECT_FAILED) from e

        _logger.info("library_injected_blob", pid=pid, inject_id=inject_id)
        return inject_id

    async def objc_enumerate_classes(self) -> list[str]:
        """Enumerate all Objective-C classes in the process.

        Returns:
            list[str]: List of class name strings.

        Raises:
            ToolError: If not attached or ObjC runtime is unavailable.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = """
        if (!ObjC.available) {
            send({ type: 'objc_error', error: 'Objective-C runtime not available' });
        } else {
            send({ type: 'objc_classes', data: Object.keys(ObjC.classes) });
        }
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result or result.get("type") == "objc_error":
            raise ToolError(_ERR_OBJC_UNAVAILABLE)

        data = result.get("data", [])
        return [str(c) for c in cast("list[object]", data)] if isinstance(data, list) else []

    async def objc_enumerate_protocols(self) -> list[str]:
        """Enumerate all Objective-C protocols in the process.

        Returns:
            list[str]: List of protocol name strings.

        Raises:
            ToolError: If not attached or ObjC runtime is unavailable.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = """
        if (!ObjC.available) {
            send({ type: 'objc_error', error: 'Objective-C runtime not available' });
        } else {
            send({ type: 'objc_protocols', data: Object.keys(ObjC.protocols) });
        }
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result or result.get("type") == "objc_error":
            raise ToolError(_ERR_OBJC_UNAVAILABLE)

        data = result.get("data", [])
        return [str(p) for p in cast("list[object]", data)] if isinstance(data, list) else []

    async def objc_enumerate_loaded_classes(self, pattern: str | None = None) -> list[str]:
        """Enumerate loaded Objective-C classes with optional pattern filter.

        Args:
            pattern: Optional glob pattern to filter class names.

        Returns:
            list[str]: List of class name strings.

        Raises:
            ToolError: If not attached or ObjC runtime is unavailable.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        if pattern is not None:
            escaped = self._escape_js_string(pattern)
            filter_js = f"""
            var regex = new RegExp('{escaped}'.replace(/\\*/g, '.*'));
            """
            match_js = "if (regex.test(name)) classes.push(name);"
        else:
            filter_js = ""
            match_js = "classes.push(name);"

        script_code = f"""
        if (!ObjC.available) {{
            send({{ type: 'objc_error', error: 'Objective-C runtime not available' }});
        }} else {{
            var classes = [];
            {filter_js}
            ObjC.enumerateLoadedClasses({{
                onMatch: function(name) {{
                    {match_js}
                }},
                onComplete: function() {{
                    send({{ type: 'objc_loaded_classes', data: classes }});
                }}
            }});
        }}
        """

        result = await self._execute_script_and_wait(script_code, max_wait=15.0)
        if "error" in result or result.get("type") == "objc_error":
            raise ToolError(_ERR_OBJC_UNAVAILABLE)

        data = result.get("data", [])
        return [str(c) for c in cast("list[object]", data)] if isinstance(data, list) else []

    async def objc_choose(self, class_name: str, limit: int = 100) -> list[int]:
        """Find live instances of an Objective-C class on the heap.

        Args:
            class_name: ObjC class name to search for.
            limit: Maximum number of instances to return.

        Returns:
            list[int]: List of instance addresses.

        Raises:
            ToolError: If not attached or ObjC runtime is unavailable.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        escaped = self._escape_js_string(class_name)
        script_code = f"""
        if (!ObjC.available) {{
            send({{ type: 'objc_error', error: 'Objective-C runtime not available' }});
        }} else {{
            var instances = [];
            var count = 0;
            ObjC.choose(ObjC.classes['{escaped}'], {{
                onMatch: function(instance) {{
                    if (count >= {limit}) return 'stop';
                    instances.push(instance.handle.toString());
                    count++;
                }},
                onComplete: function() {{
                    send({{ type: 'objc_choose', data: instances }});
                }}
            }});
        }}
        """

        result = await self._execute_script_and_wait(script_code, max_wait=15.0)
        if "error" in result or result.get("type") == "objc_error":
            raise ToolError(_ERR_OBJC_UNAVAILABLE)

        data = result.get("data", [])
        addresses: list[int] = []
        if isinstance(data, list):
            for raw_addr in cast("list[object]", data):
                addr_str = str(raw_addr)
                addresses.append(int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str))
        return addresses

    async def objc_get_class_methods(self, class_name: str) -> list[str]:
        """Get all methods of an Objective-C class.

        Args:
            class_name: ObjC class name.

        Returns:
            list[str]: List of method selector strings.

        Raises:
            ToolError: If not attached or ObjC runtime is unavailable.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        escaped = self._escape_js_string(class_name)
        script_code = f"""
        if (!ObjC.available) {{
            send({{ type: 'objc_error', error: 'Objective-C runtime not available' }});
        }} else {{
            var cls = ObjC.classes['{escaped}'];
            if (!cls) {{
                send({{ type: 'objc_methods', data: [] }});
            }} else {{
                send({{ type: 'objc_methods', data: cls.$ownMethods }});
            }}
        }}
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result or result.get("type") == "objc_error":
            raise ToolError(_ERR_OBJC_UNAVAILABLE)

        data = result.get("data", [])
        return [str(m) for m in cast("list[object]", data)] if isinstance(data, list) else []

    async def objc_hook_method(
        self,
        class_name: str,
        method_name: str,
        on_enter: str | None = None,
        on_leave: str | None = None,
    ) -> HookInfo:
        """Attach a hook to an Objective-C method.

        Args:
            class_name: ObjC class name.
            method_name: Method selector to hook.
            on_enter: JavaScript code for method entry.
            on_leave: JavaScript code for method exit.

        Returns:
            HookInfo: Hook information for the installed hook.

        Raises:
            ToolError: If not attached or ObjC runtime is unavailable.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        hook_id = str(uuid.uuid4())[:8]
        escaped_cls = self._escape_js_string(class_name)
        escaped_method = self._escape_js_string(method_name)

        script_code = f"""
        if (!ObjC.available) {{
            send({{ type: 'objc_error', error: 'Objective-C runtime not available' }});
        }} else {{
            var cls = ObjC.classes['{escaped_cls}'];
            var impl = cls['{escaped_method}'].implementation;
            Interceptor.attach(impl, {{
                onEnter: function(args) {{
                    {on_enter or "console.log('[ObjC] ' + args[0] + ' ' + args[1]);"}
                }},
                onLeave: function(retval) {{
                    {on_leave or ""}
                }}
            }});
            send({{ type: 'objc_hooked', address: impl.toString() }});
        }}
        """

        script = await asyncio.to_thread(self._session.create_script, script_code)
        messages: list[ScriptMessage] = []
        on_message, event = self._make_payload_waiter(messages, self._dispatch_message)

        script.on("message", on_message)
        await asyncio.to_thread(script.load)
        try:
            await asyncio.wait_for(event.wait(), timeout=5.0)
        except TimeoutError as e:
            await asyncio.to_thread(script.unload)
            _logger.warning("objc_hook_timeout", class_name=class_name, method=method_name)
            raise ToolError(_ERR_HOOK_FAILED) from e

        address: int | None = None
        for msg in messages:
            if msg["type"] == "send":
                payload = msg.get("payload", {})
                if isinstance(payload, dict):
                    payload_dict = cast("dict[str, object]", payload)
                    if payload_dict.get("type") == "objc_error":
                        await asyncio.to_thread(script.unload)
                        raise ToolError(_ERR_OBJC_UNAVAILABLE)
                    if payload_dict.get("type") == "objc_hooked":
                        addr_val = payload_dict.get("address", "0")
                        if isinstance(addr_val, str):
                            address = int(addr_val, 16) if addr_val.startswith("0x") else int(addr_val)
            elif msg["type"] == "error":
                await asyncio.to_thread(script.unload)
                raise ToolError(_ERR_HOOK_FAILED)

        self._scripts[hook_id] = script
        target_str = f"{class_name}.{method_name}"
        hook_info = HookInfo(id=hook_id, target=target_str, address=address, script_id=hook_id, active=True)
        self._hooks[hook_id] = hook_info
        _logger.info("objc_method_hooked", class_name=class_name, method=method_name)
        return hook_info

    async def java_enumerate_loaded_classes(self, pattern: str | None = None) -> list[str]:
        """Enumerate loaded Java classes with optional pattern filter.

        Args:
            pattern: Optional glob pattern to filter class names.

        Returns:
            list[str]: List of fully qualified class name strings.

        Raises:
            ToolError: If not attached or Java runtime is unavailable.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        if pattern is not None:
            escaped = self._escape_js_string(pattern)
            filter_js = f"var regex = new RegExp('{escaped}'.replace(/\\\\*/g, '.*'));"
            match_js = "if (regex.test(name)) classes.push(name);"
        else:
            filter_js = ""
            match_js = "classes.push(name);"

        script_code = f"""
        if (!Java.available) {{
            send({{ type: 'java_error', error: 'Java runtime not available' }});
        }} else {{
            Java.perform(function() {{
                var classes = [];
                {filter_js}
                Java.enumerateLoadedClasses({{
                    onMatch: function(name) {{
                        {match_js}
                    }},
                    onComplete: function() {{
                        send({{ type: 'java_classes', data: classes }});
                    }}
                }});
            }});
        }}
        """

        result = await self._execute_script_and_wait(script_code, max_wait=15.0)
        if "error" in result or result.get("type") == "java_error":
            raise ToolError(_ERR_JAVA_UNAVAILABLE)

        data = result.get("data", [])
        return [str(c) for c in cast("list[object]", data)] if isinstance(data, list) else []

    async def java_choose(self, class_name: str, limit: int = 100) -> list[str]:
        """Find live instances of a Java class on the heap.

        Args:
            class_name: Fully qualified Java class name.
            limit: Maximum number of instances to return.

        Returns:
            list[str]: List of instance description strings.

        Raises:
            ToolError: If not attached or Java runtime is unavailable.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        escaped = self._escape_js_string(class_name)
        script_code = f"""
        if (!Java.available) {{
            send({{ type: 'java_error', error: 'Java runtime not available' }});
        }} else {{
            Java.perform(function() {{
                var instances = [];
                var count = 0;
                Java.choose('{escaped}', {{
                    onMatch: function(instance) {{
                        if (count >= {limit}) return 'stop';
                        instances.push(instance.toString());
                        count++;
                    }},
                    onComplete: function() {{
                        send({{ type: 'java_choose', data: instances }});
                    }}
                }});
            }});
        }}
        """

        result = await self._execute_script_and_wait(script_code, max_wait=15.0)
        if "error" in result or result.get("type") == "java_error":
            raise ToolError(_ERR_JAVA_UNAVAILABLE)

        data = result.get("data", [])
        return [str(inst) for inst in cast("list[object]", data)] if isinstance(data, list) else []

    async def java_use(self, class_name: str) -> dict[str, object]:
        """Get class wrapper with method info for a Java class.

        Args:
            class_name: Fully qualified Java class name.

        Returns:
            dict[str, object]: Class info with method names and field info.

        Raises:
            ToolError: If not attached or Java runtime is unavailable.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        escaped = self._escape_js_string(class_name)
        script_code = f"""
        if (!Java.available) {{
            send({{ type: 'java_error', error: 'Java runtime not available' }});
        }} else {{
            Java.perform(function() {{
                var cls = Java.use('{escaped}');
                var methods = [];
                var clsProto = cls.class;
                var declaredMethods = clsProto.getDeclaredMethods();
                for (var i = 0; i < declaredMethods.length; i++) {{
                    methods.push(declaredMethods[i].getName());
                }}
                send({{ type: 'java_use', className: '{escaped}', methods: methods }});
            }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result or result.get("type") == "java_error":
            raise ToolError(_ERR_JAVA_UNAVAILABLE)

        return dict(result)

    async def java_hook_method(
        self,
        class_name: str,
        method_name: str,
        overloads: Sequence[str] | None = None,
        on_enter: str | None = None,
        on_leave: str | None = None,
    ) -> HookInfo:
        """Attach a hook to a Java method with optional overload specification.

        Args:
            class_name: Fully qualified Java class name.
            method_name: Method name to hook.
            overloads: Optional overload type signatures.
            on_enter: JavaScript code for method entry.
            on_leave: JavaScript code for method exit.

        Returns:
            HookInfo: Hook information for the installed hook.

        Raises:
            ToolError: If not attached or Java runtime is unavailable.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        hook_id = str(uuid.uuid4())[:8]
        escaped_cls = self._escape_js_string(class_name)
        escaped_method = self._escape_js_string(method_name)

        if overloads:
            overload_args = ", ".join(f"'{self._escape_js_string(o)}'" for o in overloads)
            overload_js = f".overload({overload_args})"
        else:
            overload_js = ""

        script_code = f"""
        if (!Java.available) {{
            send({{ type: 'java_error', error: 'Java runtime not available' }});
        }} else {{
            Java.perform(function() {{
                var cls = Java.use('{escaped_cls}');
                var target = cls['{escaped_method}']{overload_js};
                var original = target.implementation;
                target.implementation = function() {{
                    var args = arguments;
                    {on_enter or "console.log('[Java] ' + this.toString());"}
                    var retval = original
                        ? original.apply(this, args)
                        : this['{escaped_method}'].apply(this, args);
                    {on_leave or ""}
                    return retval;
                }};
                send({{ type: 'java_hooked', className: '{escaped_cls}', method: '{escaped_method}' }});
            }});
        }}
        """

        script = await asyncio.to_thread(self._session.create_script, script_code)
        messages: list[ScriptMessage] = []
        on_message, event = self._make_payload_waiter(messages, self._dispatch_message)

        script.on("message", on_message)
        await asyncio.to_thread(script.load)
        try:
            await asyncio.wait_for(event.wait(), timeout=5.0)
        except TimeoutError as e:
            await asyncio.to_thread(script.unload)
            _logger.warning("java_hook_timeout", class_name=class_name, method=method_name)
            raise ToolError(_ERR_HOOK_FAILED) from e

        for msg in messages:
            if msg["type"] == "send":
                payload = msg.get("payload", {})
                if isinstance(payload, dict):
                    payload_dict = cast("dict[str, object]", payload)
                    if payload_dict.get("type") == "java_error":
                        await asyncio.to_thread(script.unload)
                        raise ToolError(_ERR_JAVA_UNAVAILABLE)
            elif msg["type"] == "error":
                await asyncio.to_thread(script.unload)
                raise ToolError(_ERR_HOOK_FAILED)

        self._scripts[hook_id] = script
        target_str = f"{class_name}.{method_name}"
        hook_info = HookInfo(id=hook_id, target=target_str, address=None, script_id=hook_id, active=True)
        self._hooks[hook_id] = hook_info
        _logger.info("java_method_hooked", class_name=class_name, method=method_name)
        return hook_info

    async def java_deoptimize(self) -> bool:
        """Force Java runtime to deoptimize all code for reliable hooking.

        Returns:
            bool: True if deoptimization succeeded.

        Raises:
            ToolError: If not attached or Java runtime is unavailable.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = """
        if (!Java.available) {
            send({ type: 'java_error', error: 'Java runtime not available' });
        } else {
            Java.perform(function() {
                Java.deoptimizeEverything();
                send({ type: 'java_deoptimized', success: true });
            });
        }
        """

        result = await self._execute_script_and_wait(script_code, max_wait=30.0)
        if "error" in result or result.get("type") == "java_error":
            raise ToolError(_ERR_JAVA_UNAVAILABLE)

        _logger.info("java_deoptimized")
        return True

    async def create_cmodule(self, code: str, symbols: dict[str, int] | None = None) -> str:
        """Compile and load inline C code via Frida CModule.

        Args:
            code: C source code to compile.
            symbols: Optional symbol name-to-address mappings.

        Returns:
            str: Script ID for the CModule session.

        Raises:
            ToolError: If not attached or compilation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        escaped_code = self._escape_js_string(code)
        symbols_js = "null"
        if symbols:
            sym_entries = ", ".join(f"'{k}': ptr({v})" for k, v in symbols.items())
            symbols_js = f"{{ {sym_entries} }}"

        script_code = f"""
        try {{
            var syms = {symbols_js};
            var cm = syms ? new CModule('{escaped_code}', syms) : new CModule('{escaped_code}');
            send({{ type: 'cmodule_loaded', success: true }});
        }} catch (e) {{
            send({{ type: 'cmodule_error', error: e.message }});
        }}
        """

        script_id = str(uuid.uuid4())[:8]
        script = await asyncio.to_thread(self._session.create_script, script_code)
        messages: list[ScriptMessage] = []
        on_message, event = self._make_payload_waiter(messages, self._dispatch_message)

        script.on("message", on_message)
        await asyncio.to_thread(script.load)
        try:
            await asyncio.wait_for(event.wait(), timeout=5.0)
        except TimeoutError as e:
            await asyncio.to_thread(script.unload)
            _logger.warning("cmodule_load_timeout")
            raise ToolError(_ERR_CMODULE_FAILED) from e

        for msg in messages:
            if msg["type"] == "send":
                payload = msg.get("payload", {})
                if isinstance(payload, dict):
                    payload_dict = cast("dict[str, object]", payload)
                    if payload_dict.get("type") == "cmodule_error":
                        await asyncio.to_thread(script.unload)
                        raise ToolError(_ERR_CMODULE_FAILED, details={"reason": str(payload_dict.get("error", ""))})
            elif msg["type"] == "error":
                await asyncio.to_thread(script.unload)
                raise ToolError(_ERR_CMODULE_FAILED)

        self._scripts[script_id] = script
        _logger.info("cmodule_loaded", script_id=script_id)
        return script_id

    async def kernel_enumerate_modules(self) -> list[ModuleInfo]:
        """Enumerate kernel modules.

        Returns:
            list[ModuleInfo]: List of kernel module information.

        Raises:
            ToolError: If not attached or Kernel API is unavailable.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = """
        if (!Kernel.available) {
            send({ type: 'kernel_error', error: 'Kernel API not available' });
        } else {
            var mods = Kernel.enumerateModules();
            var result = mods.map(function(m) {
                return { name: m.name, base: m.base.toString(), size: m.size };
            });
            send({ type: 'kernel_modules', data: result });
        }
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result or result.get("type") == "kernel_error":
            raise ToolError(_ERR_KERNEL_UNAVAILABLE)

        modules: list[ModuleInfo] = []
        mod_data = result.get("data", [])
        if isinstance(mod_data, list):
            for raw_mod in cast("list[object]", mod_data):
                if not isinstance(raw_mod, dict):
                    continue
                m = cast("dict[str, object]", raw_mod)
                base_str = str(m.get("base", "0"))
                base = int(base_str, 16) if base_str.startswith("0x") else int(base_str)
                size_val = m.get("size", 0)
                modules.append(
                    ModuleInfo(
                        name=str(m.get("name", "")),
                        path=Path(),
                        base_address=base,
                        size=int(size_val) if isinstance(size_val, (int, float)) else 0,
                        entry_point=0,
                    ),
                )
        return modules

    async def kernel_enumerate_ranges(self, protection: str = "---") -> list[MemoryRegion]:
        """Enumerate kernel memory ranges.

        Args:
            protection: Protection filter (default '---' for all).

        Returns:
            list[MemoryRegion]: List of kernel memory regions.

        Raises:
            ToolError: If not attached or Kernel API is unavailable.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        self._validate_protection(protection)

        escaped_protection = self._escape_js_string(protection)
        script_code = f"""
        if (!Kernel.available) {{
            send({{ type: 'kernel_error', error: 'Kernel API not available' }});
        }} else {{
            var ranges = Kernel.enumerateRanges('{escaped_protection}');
            var result = ranges.map(function(r) {{
                return {{ base: r.base.toString(), size: r.size, protection: r.protection }};
            }});
            send({{ type: 'kernel_ranges', data: result }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result or result.get("type") == "kernel_error":
            raise ToolError(_ERR_KERNEL_UNAVAILABLE)

        regions: list[MemoryRegion] = []
        range_data = result.get("data", [])
        if isinstance(range_data, list):
            for raw_r in cast("list[object]", range_data):
                if not isinstance(raw_r, dict):
                    continue
                r = cast("dict[str, object]", raw_r)
                base_str = str(r.get("base", "0"))
                base = int(base_str, 16) if base_str.startswith("0x") else int(base_str)
                size_val = r.get("size", 0)
                regions.append(
                    MemoryRegion(
                        base_address=base,
                        size=int(size_val) if isinstance(size_val, (int, float)) else 0,
                        protection=str(r.get("protection", "")),
                        state="MEM_COMMIT",
                        type="MEM_PRIVATE",
                        module_name=None,
                    ),
                )
        return regions

    async def kernel_read(self, address: int, size: int) -> str:
        """Read kernel memory.

        Args:
            address: Kernel address to read.
            size: Number of bytes to read.

        Returns:
            str: Hex string of kernel memory contents.

        Raises:
            ToolError: If not attached or Kernel API is unavailable.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = f"""
        if (!Kernel.available) {{
            send({{ type: 'kernel_error', error: 'Kernel API not available' }});
        }} else {{
            var data = Kernel.readByteArray(ptr({address}), {size});
            send({{ type: 'kernel_read' }}, data);
        }}
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result or result.get("type") == "kernel_error":
            raise ToolError(_ERR_KERNEL_UNAVAILABLE)

        read_data = result.get("data")
        if isinstance(read_data, (bytes, bytearray)):
            return bytes(read_data).hex()
        if isinstance(read_data, list):
            return bytes(cast("list[int]", read_data)).hex()
        raise ToolError(_ERR_KERNEL_UNAVAILABLE)

    async def kernel_write(self, address: int, hex_data: str) -> bool:
        """Write to kernel memory.

        Args:
            address: Kernel address to write.
            hex_data: Hex-encoded bytes to write.

        Returns:
            bool: True if write succeeded.

        Raises:
            ToolError: If not attached or Kernel API is unavailable.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        byte_values = bytes.fromhex(hex_data.replace(" ", ""))
        hex_array = ", ".join(f"0x{b:02x}" for b in byte_values)

        script_code = f"""
        if (!Kernel.available) {{
            send({{ type: 'kernel_error', error: 'Kernel API not available' }});
        }} else {{
            Kernel.writeByteArray(ptr({address}), [{hex_array}]);
            send({{ type: 'kernel_written', success: true }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result or result.get("type") == "kernel_error":
            raise ToolError(_ERR_KERNEL_UNAVAILABLE)
        return True

    async def kernel_alloc(self, size: int) -> int:
        """Allocate kernel memory.

        Args:
            size: Size in bytes to allocate.

        Returns:
            int: Address of allocated kernel memory.

        Raises:
            ToolError: If not attached or Kernel API is unavailable.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = f"""
        if (!Kernel.available) {{
            send({{ type: 'kernel_error', error: 'Kernel API not available' }});
        }} else {{
            var block = Kernel.alloc({size});
            send({{ type: 'kernel_alloc', address: block.toString() }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result or result.get("type") == "kernel_error":
            raise ToolError(_ERR_KERNEL_UNAVAILABLE)

        addr_str = str(result.get("address", "0"))
        return int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)

    async def kernel_protect(self, address: int, size: int, protection: str) -> bool:
        """Change kernel memory protection.

        Args:
            address: Kernel address.
            size: Size in bytes.
            protection: New protection flags.

        Returns:
            bool: True if protection was changed.

        Raises:
            ToolError: If not attached or Kernel API is unavailable.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        self._validate_protection(protection)

        escaped_protection = self._escape_js_string(protection)
        script_code = f"""
        if (!Kernel.available) {{
            send({{ type: 'kernel_error', error: 'Kernel API not available' }});
        }} else {{
            Kernel.protect(ptr({address}), {size}, '{escaped_protection}');
            send({{ type: 'kernel_protected', success: true }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result or result.get("type") == "kernel_error":
            raise ToolError(_ERR_KERNEL_UNAVAILABLE)
        return True

    async def socket_listen(self, port: int, family: str = "ipv4") -> str:
        """Create a listening socket in the target process.

        Args:
            port: Port to listen on.
            family: Address family ('ipv4', 'ipv6', 'unix').

        Returns:
            str: Script ID for the listener session.

        Raises:
            ToolError: If not attached or socket operation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        self._validate_socket_family(family)

        escaped_family = self._escape_js_string(family)
        script_code = f"""
        try {{
            var listener = Socket.listen({{
                family: '{escaped_family}',
                port: {port}
            }});
            send({{ type: 'socket_listen', success: true, port: {port} }});
        }} catch (e) {{
            send({{ type: 'socket_error', error: e.message }});
        }}
        """

        script_id = str(uuid.uuid4())[:8]
        script = await asyncio.to_thread(self._session.create_script, script_code)

        def on_message(message: ScriptMessage, data: bytes | None) -> None:
            """Forward socket-listener messages to the bridge dispatcher.

            Args:
                message: Message payload emitted by the listener script.
                data: Optional binary payload attached to the message.
            """
            del data
            self._dispatch_message(dict(cast("dict[str, object]", message)))

        script.on("message", on_message)
        await asyncio.to_thread(script.load)

        self._scripts[script_id] = script
        _logger.info("socket_listening", port=port, family=family)
        return script_id

    async def socket_connect(self, host: str, port: int, family: str = "ipv4") -> dict[str, object]:
        """Connect a socket in the target process.

        Args:
            host: Host to connect to.
            port: Port to connect to.
            family: Address family.

        Returns:
            dict[str, object]: Connection information.

        Raises:
            ToolError: If not attached or socket operation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        self._validate_socket_family(family)

        escaped_host = self._escape_js_string(host)
        escaped_family = self._escape_js_string(family)
        script_code = f"""
        try {{
            var conn = Socket.connect({{
                family: '{escaped_family}',
                host: '{escaped_host}',
                port: {port}
            }});
            send({{ type: 'socket_connected', host: '{escaped_host}', port: {port} }});
        }} catch (e) {{
            send({{ type: 'socket_error', error: e.message }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result or result.get("type") == "socket_error":
            raise ToolError(_ERR_SOCKET_FAILED)
        return dict(result)

    async def socket_type(self, handle: int) -> str:
        """Get socket type for a file descriptor.

        Args:
            handle: File descriptor/handle.

        Returns:
            str: Socket type string.

        Raises:
            ToolError: If not attached or socket operation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = f"""
        try {{
            var type = Socket.type({handle});
            send({{ type: 'socket_type', value: type }});
        }} catch (e) {{
            send({{ type: 'socket_error', error: e.message }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result or result.get("type") == "socket_error":
            raise ToolError(_ERR_SOCKET_FAILED)
        return str(result.get("value", ""))

    async def socket_local_address(self, handle: int) -> dict[str, object]:
        """Get local address of a socket.

        Args:
            handle: File descriptor/handle.

        Returns:
            dict[str, object]: Socket address information.

        Raises:
            ToolError: If not attached or socket operation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = f"""
        try {{
            var addr = Socket.localAddress({handle});
            send({{ type: 'socket_addr', data: addr }});
        }} catch (e) {{
            send({{ type: 'socket_error', error: e.message }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result or result.get("type") == "socket_error":
            raise ToolError(_ERR_SOCKET_FAILED)
        data = result.get("data")
        return dict(cast("dict[str, object]", data)) if isinstance(data, dict) else {}

    async def socket_peer_address(self, handle: int) -> dict[str, object]:
        """Get peer address of a connected socket.

        Args:
            handle: File descriptor/handle.

        Returns:
            dict[str, object]: Socket peer address information.

        Raises:
            ToolError: If not attached or socket operation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = f"""
        try {{
            var addr = Socket.peerAddress({handle});
            send({{ type: 'socket_addr', data: addr }});
        }} catch (e) {{
            send({{ type: 'socket_error', error: e.message }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result or result.get("type") == "socket_error":
            raise ToolError(_ERR_SOCKET_FAILED)
        data = result.get("data")
        return dict(cast("dict[str, object]", data)) if isinstance(data, dict) else {}

    async def file_read_target(self, path: str) -> str:
        """Read a file on the target device.

        Args:
            path: File path on the target.

        Returns:
            str: Hex-encoded file contents.

        Raises:
            ToolError: If not attached or file operation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        escaped = self._escape_js_string(path)
        script_code = f"""
        try {{
            var f = new File('{escaped}', 'rb');
            var data = f.readBytes(-1);
            f.close();
            send({{ type: 'file_read' }}, data);
        }} catch (e) {{
            send({{ type: 'file_error', error: e.message }});
        }}
        """

        result = await self._execute_script_and_wait(script_code, max_wait=10.0)
        if "error" in result or result.get("type") == "file_error":
            raise ToolError(_ERR_FILE_FAILED)

        read_data = result.get("data")
        if isinstance(read_data, (bytes, bytearray)):
            return bytes(read_data).hex()
        if isinstance(read_data, list):
            return bytes(cast("list[int]", read_data)).hex()
        raise ToolError(_ERR_FILE_FAILED)

    async def file_write_target(self, path: str, hex_data: str) -> bool:
        """Write data to a file on the target device.

        Args:
            path: File path on the target.
            hex_data: Hex-encoded data to write.

        Returns:
            bool: True if write succeeded.

        Raises:
            ToolError: If not attached or file operation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        byte_values = bytes.fromhex(hex_data.replace(" ", ""))
        hex_array = ", ".join(f"0x{b:02x}" for b in byte_values)
        escaped = self._escape_js_string(path)

        script_code = f"""
        try {{
            var f = new File('{escaped}', 'wb');
            f.write([{hex_array}]);
            f.close();
            send({{ type: 'file_written', success: true }});
        }} catch (e) {{
            send({{ type: 'file_error', error: e.message }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result or result.get("type") == "file_error":
            raise ToolError(_ERR_FILE_FAILED)
        return True

    async def sqlite_open(self, path: str) -> str:
        """Open a SQLite database on the target device.

        Args:
            path: Database file path on the target.

        Returns:
            str: Script ID for the database session (use with sqlite_exec).

        Raises:
            ToolError: If not attached or database cannot be opened.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        escaped = self._escape_js_string(path)
        script_code = f"""
        try {{
            var db = SqliteDatabase.open('{escaped}');
            rpc.exports = {{
                exec: function(sql) {{
                    return db.exec(sql);
                }},
                dump: function() {{
                    return db.dump();
                }},
                close: function() {{
                    db.close();
                }}
            }};
            send({{ type: 'sqlite_opened', success: true }});
        }} catch (e) {{
            send({{ type: 'sqlite_error', error: e.message }});
        }}
        """

        script_id = str(uuid.uuid4())[:8]
        script = await asyncio.to_thread(self._session.create_script, script_code)
        messages: list[ScriptMessage] = []
        on_message, event = self._make_payload_waiter(messages, self._dispatch_message)

        script.on("message", on_message)
        await asyncio.to_thread(script.load)
        try:
            await asyncio.wait_for(event.wait(), timeout=5.0)
        except TimeoutError as e:
            await asyncio.to_thread(script.unload)
            _logger.warning("sqlite_open_timeout", path=path)
            raise ToolError(_ERR_SQLITE_FAILED) from e

        opened = False
        for msg in messages:
            if msg["type"] == "send":
                payload = msg.get("payload", {})
                if isinstance(payload, dict):
                    payload_dict = cast("dict[str, object]", payload)
                    inner_type = payload_dict.get("type")
                    if inner_type == "sqlite_error":
                        await asyncio.to_thread(script.unload)
                        raise ToolError(_ERR_SQLITE_FAILED, details={"reason": str(payload_dict.get("error", ""))})
                    if inner_type == "sqlite_opened":
                        opened = True
            elif msg["type"] == "error":
                await asyncio.to_thread(script.unload)
                raise ToolError(_ERR_SQLITE_FAILED)

        if not opened:
            await asyncio.to_thread(script.unload)
            _logger.warning("sqlite_open_no_ack", path=path)
            raise ToolError(_ERR_SQLITE_FAILED)

        self._scripts[script_id] = script
        _logger.info("sqlite_database_opened", path=path, script_id=script_id)
        return script_id

    async def sqlite_exec(self, script_id: str, sql: str) -> object:
        """Execute SQL on an open SQLite database.

        Args:
            script_id: Database session script ID from sqlite_open.
            sql: SQL statement to execute.

        Returns:
            object: Query results as returned by the database.

        Raises:
            ToolError: If the script is not found or query fails.
        """
        if script_id not in self._scripts:
            raise ToolError(_ERR_SCRIPT_NOT_FOUND)

        script = self._scripts[script_id]
        try:
            result: object = await asyncio.to_thread(script.exports_sync.exec, sql)
        except Exception as e:
            _logger.warning("sqlite_exec_failed", script_id=script_id, error=str(e))
            raise ToolError(_ERR_SQLITE_FAILED) from e
        else:
            return result

    async def sqlite_dump(self, path: str) -> str:
        """Dump all tables from a SQLite database.

        Args:
            path: Database file path on the target.

        Returns:
            str: SQL dump text.

        Raises:
            ToolError: If not attached or dump fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        escaped = self._escape_js_string(path)
        script_code = f"""
        try {{
            var db = SqliteDatabase.open('{escaped}');
            var dump = db.dump();
            db.close();
            send({{ type: 'sqlite_dump', data: dump }});
        }} catch (e) {{
            send({{ type: 'sqlite_error', error: e.message }});
        }}
        """

        result = await self._execute_script_and_wait(script_code, max_wait=30.0)
        if "error" in result or result.get("type") == "sqlite_error":
            raise ToolError(_ERR_SQLITE_FAILED)
        return str(result.get("data", ""))

    async def write_code(self, address: int, architecture: str, instructions: list[str]) -> int:
        """Write machine code instructions at an address using architecture-specific writers.

        Args:
            address: Target address to write code.
            architecture: Target architecture ('x86', 'arm', 'arm64', 'thumb', 'mips').
            instructions: List of writer method call strings (e.g., 'putNop', 'putRet').

        Returns:
            int: Number of bytes written.

        Raises:
            ToolError: If not attached, architecture is invalid, or write fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        if architecture not in _VALID_CODE_ARCHITECTURES:
            raise ToolError(_ERR_CODE_WRITER_FAILED, details={"reason": f"invalid architecture: {architecture}"})

        writer_class = _CODE_WRITER_MAP[architecture]
        probe_insn_calls = "\n            ".join(f"wProbe.{insn}();" for insn in instructions)
        insn_calls = "\n            ".join(f"w.{insn}();" for insn in instructions)

        script_code = f"""
        try {{
            var probeBuf = Memory.alloc({_PATCH_CODE_PROBE_SIZE});
            var wProbe = new {writer_class}(probeBuf, {{ pc: ptr({address}) }});
            {probe_insn_calls}
            wProbe.flush();
            var probedSize = wProbe.offset;
            if (probedSize <= 0) {{
                send({{
                    type: 'code_write_error',
                    error: 'probe produced no bytes'
                }});
            }} else if (probedSize > {_PATCH_CODE_PROBE_SIZE}) {{
                send({{
                    type: 'code_write_error',
                    error: 'probe size ' + probedSize + ' exceeds probe buffer'
                }});
            }} else {{
                var bytesWritten = 0;
                Memory.patchCode(ptr({address}), probedSize, function(code) {{
                    var w = new {writer_class}(code, {{ pc: ptr({address}) }});
                    {insn_calls}
                    w.flush();
                    bytesWritten = w.offset;
                }});
                send({{ type: 'code_written', size: bytesWritten }});
            }}
        }} catch (e) {{
            send({{ type: 'code_write_error', error: e.message }});
        }}
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result or result.get("type") == "code_write_error":
            raise ToolError(_ERR_CODE_WRITER_FAILED)

        size_val = result.get("size", 0)
        written = int(size_val) if isinstance(size_val, (int, float)) else 0
        _logger.info("code_written", address=hex(address), architecture=architecture, size=written)
        return written

    async def cloak_add_thread(self, thread_id: int) -> bool:
        """Hide a thread from other tools via Frida Cloak.

        Args:
            thread_id: Thread ID to cloak.

        Returns:
            bool: True if the thread was cloaked.

        Raises:
            ToolError: If not attached or operation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = f"""
        Cloak.addThread({thread_id});
        send({{ type: 'cloaked', success: true }});
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result:
            raise ToolError(_ERR_HOOK_FAILED)
        _logger.debug("thread_cloaked", thread_id=thread_id)
        return True

    async def cloak_remove_thread(self, thread_id: int) -> bool:
        """Uncloak a previously cloaked thread.

        Args:
            thread_id: Thread ID to uncloak.

        Returns:
            bool: True if the thread was uncloaked.

        Raises:
            ToolError: If not attached or operation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = f"""
        Cloak.removeThread({thread_id});
        send({{ type: 'uncloaked', success: true }});
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result:
            raise ToolError(_ERR_HOOK_FAILED)
        _logger.debug("thread_uncloaked", thread_id=thread_id)
        return True

    async def cloak_add_range(self, address: int, size: int) -> bool:
        """Hide a memory range from other tools via Frida Cloak.

        Args:
            address: Start address of the range.
            size: Size of the range in bytes.

        Returns:
            bool: True if the range was cloaked.

        Raises:
            ToolError: If not attached or operation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = f"""
        Cloak.addRange({{ base: ptr({address}), size: {size} }});
        send({{ type: 'range_cloaked', success: true }});
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result:
            raise ToolError(_ERR_HOOK_FAILED)
        _logger.debug("range_cloaked", address=hex(address), size=size)
        return True

    async def cloak_remove_range(self, address: int, size: int) -> bool:
        """Uncloak a previously cloaked memory range.

        Args:
            address: Start address of the range.
            size: Size of the range in bytes.

        Returns:
            bool: True if the range was uncloaked.

        Raises:
            ToolError: If not attached or operation fails.
        """
        if self._session is None:
            raise ToolError(_ERR_NOT_ATTACHED)

        script_code = f"""
        Cloak.removeRange({{ base: ptr({address}), size: {size} }});
        send({{ type: 'range_uncloaked', success: true }});
        """

        result = await self._execute_script_and_wait(script_code)
        if "error" in result:
            raise ToolError(_ERR_HOOK_FAILED)
        _logger.debug("range_uncloaked", address=hex(address), size=size)
        return True

    @staticmethod
    async def compile_typescript(source: str, project_root: str | None = None) -> str:
        """Compile TypeScript source to JavaScript using Frida compiler.

        Accepts either a path to an existing entry file or raw TypeScript
        source. When raw source is provided it is written to a temporary
        ``.ts`` file so the compiler can resolve it as an entrypoint; the
        temp file is removed on all exit paths.

        Args:
            source: TypeScript source code or path to an entry file.
            project_root: Optional project root directory for imports.

        Returns:
            str: Compiled JavaScript source code.

        Raises:
            ToolError: If compilation fails.
        """
        source_path = Path(source)
        is_path: bool = await asyncio.to_thread(source_path.is_file)

        temp_path: Path | None = None
        try:
            if is_path:
                entrypoint = str(source_path)
            else:
                temp_path = await asyncio.to_thread(_write_typescript_tempfile, source)
                entrypoint = str(temp_path)

            try:
                compiler = frida.Compiler()
                if project_root is not None:
                    compiled: str = await asyncio.to_thread(
                        compiler.build,
                        entrypoint,
                        project_root=project_root,
                    )
                else:
                    compiled = await asyncio.to_thread(compiler.build, entrypoint)
            except Exception as e:
                _logger.warning("typescript_compile_failed", error=str(e))
                raise ToolError(_ERR_COMPILE_FAILED) from e
        finally:
            if temp_path is not None:
                try:
                    await asyncio.to_thread(temp_path.unlink)
                except OSError as cleanup_error:
                    _logger.debug(
                        "typescript_tempfile_cleanup_failed",
                        path=str(temp_path),
                        error=str(cleanup_error),
                    )

        _logger.info("typescript_compiled", output_size=len(compiled))
        return compiled

    async def monitor_path(self, path: str) -> str:
        """Monitor a file path for changes on the target device.

        Args:
            path: Path to monitor for changes.

        Returns:
            str: Monitor ID for later stopping.

        Raises:
            ToolError: If monitoring setup fails.
        """
        monitor_id = str(uuid.uuid4())[:8]

        try:
            monitor = frida.FileMonitor(path)
        except Exception as e:
            _logger.warning("file_monitor_create_failed", path=path, error=str(e))
            raise ToolError(_ERR_MONITOR_FAILED) from e

        def on_change(changed_path: str, other_path: str | None, event_type: str) -> None:
            """Forward file-monitor change events to the bridge dispatcher.

            Args:
                changed_path: Path that triggered the change event.
                other_path: Secondary path for rename events, if any.
                event_type: The kind of filesystem change that occurred.
            """
            self._dispatch_message({
                "type": "send",
                "payload": {
                    "type": "file_changed",
                    "monitor_id": monitor_id,
                    "path": changed_path,
                    "other_path": other_path,
                    "event": event_type,
                },
            })

        monitor.on("change", on_change)

        try:
            await asyncio.to_thread(monitor.enable)
        except Exception as e:
            _logger.warning("file_monitor_enable_failed", path=path, error=str(e))
            raise ToolError(_ERR_MONITOR_FAILED) from e

        self._file_monitors[monitor_id] = monitor
        _logger.info("file_monitor_started", monitor_id=monitor_id, path=path)
        return monitor_id

    async def stop_monitor(self, monitor_id: str) -> bool:
        """Stop a file monitor.

        Args:
            monitor_id: ID of the monitor to stop.

        Returns:
            bool: True if stopped successfully, False if not found.
        """
        monitor = self._file_monitors.pop(monitor_id, None)
        if monitor is None:
            return False

        disable_fn = getattr(monitor, "disable", None)
        if callable(disable_fn):
            await asyncio.to_thread(disable_fn)
        _logger.info("file_monitor_stopped", monitor_id=monitor_id)
        return True
