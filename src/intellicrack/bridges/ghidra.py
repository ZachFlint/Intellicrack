# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Ghidra bridge for static analysis and decompilation.

This module provides integration with Ghidra for advanced static analysis, decompilation, and reverse engineering capabilities using
ghidra_bridge.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import importlib.util
import json
import re
import socket
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, cast

from intellicrack.bridges.base import (
    BridgeCapabilities,
    BridgeState,
    DisassemblyLine,
    StaticAnalysisBridge,
)
from intellicrack.core._subprocess import PIPE, Popen
from intellicrack.core.logging import get_logger
from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.core.types import (
    BinaryInfo,
    CrossReference,
    DataTypeInfo,
    ExportInfo,
    FunctionInfo,
    ImportInfo,
    ParameterInfo,
    SectionInfo,
    StringInfo,
    ToolDefinition,
    ToolError,
    ToolFunction,
    ToolName,
    ToolParameter,
    VariableInfo,
)


_logger = get_logger("bridges.ghidra")

_RemoteExecFunc = Callable[[str], object]

_MIN_HEADER_SIZE = 4
_PE_POINTER_OFFSET = 0x3C
_PE_POINTER_END = 0x40
_PE_HEADER_MIN = 6
_PE_MAGIC = b"PE\x00\x00"
_MZ_MAGIC = b"MZ"
_ELF_MAGIC = b"\x7fELF"
_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
}
_ELF_CLASS_64 = 2
_MIN_ELF_HEADER = 64
_MACHINE_AMD64 = 0x8664
_MACHINE_I386 = 0x14C
_JAVA_SIGNED_THRESHOLD = 127


class GhidraBridge(StaticAnalysisBridge):
    """Bridge for Ghidra reverse engineering suite.

    Provides advanced static analysis and decompilation capabilities
    using the ghidra_bridge Python interface.

    Attributes:
        DEFAULT_PORT: TCP port for the ghidra_bridge RPC connection.
        DECOMPILE_TIMEOUT_SECONDS: Timeout for Ghidra decompilation in seconds.
    """

    DEFAULT_PORT = 4768
    DECOMPILE_TIMEOUT_SECONDS: int = 60

    def __init__(self) -> None:
        super().__init__()
        self._ghidra_path: Path | None = None
        self._bridge: object | None = None
        self._process: Popen[bytes] | None = None
        self._binary_path: Path | None = None
        self._project_path: Path | None = None
        self._port: int = self.DEFAULT_PORT
        self._bridge_script_path: Path | None = None
        self._capabilities = BridgeCapabilities(
            supports_static_analysis=True,
            supports_decompilation=True,
            supports_scripting=True,
            supported_architectures=["x86", "x86_64", "arm", "arm64", "mips", "ppc", "sparc"],
            supported_formats=["pe", "elf", "macho", "raw", "coff"],
        )

    @property
    def ghidra_path(self) -> Path | None:
        """Get the Ghidra installation path.

        Returns:
            Path | None: Path to Ghidra installation, or None if not set.
        """
        return self._ghidra_path

    @ghidra_path.setter
    def ghidra_path(self, value: Path | None) -> None:
        """Set the Ghidra installation path.

        Args:
            value: Path to Ghidra installation directory, or None.
        """
        self._ghidra_path = value

    @property
    def project_path(self) -> Path | None:
        """Get the active Ghidra project path.

        Returns:
            Path | None: Path to the active Ghidra project, or None if no project is open.
        """
        return self._project_path

    @property
    def name(self) -> ToolName:
        """Get the tool's name.

        Returns:
            ToolName: ToolName.GHIDRA
        """
        return ToolName.GHIDRA

    @property
    def tool_definition(self) -> ToolDefinition:
        """Get tool definition for LLM function calling.

        Returns:
            ToolDefinition: ToolDefinition with all available functions.
        """
        return ToolDefinition(
            tool_name=ToolName.GHIDRA,
            description="Ghidra static analysis - decompilation, disassembly, cross-references",
            functions=[
                ToolFunction(
                    name="ghidra.load_binary",
                    description="Load a binary file into Ghidra for analysis",
                    parameters=[
                        ToolParameter(
                            name="path",
                            type="string",
                            description="Path to the binary file",
                            required=True,
                        ),
                    ],
                    returns="BinaryInfo object with file details",
                ),
                ToolFunction(
                    name="ghidra.analyze",
                    description="Run full Ghidra analysis on loaded binary",
                    parameters=[],
                    returns="Analysis completion status",
                ),
                ToolFunction(
                    name="ghidra.get_functions",
                    description="Get list of all functions in the binary",
                    parameters=[
                        ToolParameter(
                            name="filter_pattern",
                            type="string",
                            description="Optional regex pattern to filter function names",
                            required=False,
                        ),
                    ],
                    returns="List of FunctionInfo objects",
                ),
                ToolFunction(
                    name="ghidra.decompile",
                    description="Decompile a function to C pseudocode",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Address of the function to decompile",
                            required=True,
                        ),
                    ],
                    returns="Decompiled C code as string",
                ),
                ToolFunction(
                    name="ghidra.disassemble",
                    description="Get disassembly at an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Start address for disassembly",
                            required=True,
                        ),
                        ToolParameter(
                            name="count",
                            type="integer",
                            description="Number of instructions to disassemble",
                            required=False,
                            default=20,
                        ),
                    ],
                    returns="Disassembly text",
                ),
                ToolFunction(
                    name="ghidra.get_xrefs_to",
                    description="Get all cross-references pointing to an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Target address",
                            required=True,
                        ),
                    ],
                    returns="List of CrossReference objects",
                ),
                ToolFunction(
                    name="ghidra.get_xrefs_from",
                    description="Get all cross-references from an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Source address",
                            required=True,
                        ),
                    ],
                    returns="List of CrossReference objects",
                ),
                ToolFunction(
                    name="ghidra.search_strings",
                    description="Search for strings in the binary",
                    parameters=[
                        ToolParameter(
                            name="pattern",
                            type="string",
                            description="Regex pattern to match",
                            required=True,
                        ),
                        ToolParameter(
                            name="encoding",
                            type="string",
                            description="String encoding to filter",
                            required=False,
                            default="ascii",
                            enum=["ascii", "utf-16", "utf-16-le", "utf-16-be", "utf-32"],
                        ),
                    ],
                    returns="List of StringInfo objects",
                ),
                ToolFunction(
                    name="ghidra.search_bytes",
                    description="Search for a byte pattern in the binary",
                    parameters=[
                        ToolParameter(
                            name="hex_pattern",
                            type="string",
                            description="Hex string pattern (e.g., '48 8B 05 ?? ?? ?? ??')",
                            required=True,
                        ),
                    ],
                    returns="List of addresses where pattern found",
                ),
                ToolFunction(
                    name="ghidra.rename_function",
                    description="Rename a function",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Function address",
                            required=True,
                        ),
                        ToolParameter(
                            name="new_name",
                            type="string",
                            description="New function name",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="ghidra.add_comment",
                    description="Add a comment at an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Address for comment",
                            required=True,
                        ),
                        ToolParameter(
                            name="comment",
                            type="string",
                            description="Comment text",
                            required=True,
                        ),
                        ToolParameter(
                            name="comment_type",
                            type="string",
                            description="Type: EOL, PRE, POST, PLATE",
                            required=False,
                            default="EOL",
                            enum=["EOL", "PRE", "POST", "PLATE"],
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="ghidra.get_imports",
                    description="Get all imported functions",
                    parameters=[],
                    returns="List of ImportInfo objects",
                ),
                ToolFunction(
                    name="ghidra.get_exports",
                    description="Get all exported functions",
                    parameters=[],
                    returns="List of ExportInfo objects",
                ),
                ToolFunction(
                    name="ghidra.get_data_type",
                    description="Get data type at an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Address to check",
                            required=True,
                        ),
                    ],
                    returns="Data type information",
                ),
                ToolFunction(
                    name="ghidra.set_data_type",
                    description="Set data type at an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Address to set type",
                            required=True,
                        ),
                        ToolParameter(
                            name="data_type",
                            type="string",
                            description="Data type name",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="ghidra.start_headless",
                    description="Start Ghidra in headless mode with bridge",
                    parameters=[
                        ToolParameter(
                            name="project_dir",
                            type="string",
                            description="Directory for Ghidra project",
                            required=True,
                        ),
                        ToolParameter(
                            name="project_name",
                            type="string",
                            description="Name of the project",
                            required=False,
                            default="intellicrack",
                        ),
                    ],
                    returns="None",
                ),
                ToolFunction(
                    name="ghidra.get_function",
                    description="Get function at a specific address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Function address",
                            required=True,
                        ),
                    ],
                    returns="FunctionInfo or None if not found",
                ),
                ToolFunction(
                    name="ghidra.execute_script",
                    description="Execute arbitrary Jython script in Ghidra's JVM context. Gives access to all Ghidra APIs.",
                    parameters=[
                        ToolParameter(
                            name="code",
                            type="string",
                            description="Jython code to execute in Ghidra",
                            required=True,
                        ),
                    ],
                    returns="Script execution result",
                ),
                ToolFunction(
                    name="ghidra.set_label",
                    description="Create or modify a label at an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address for the label", required=True),
                        ToolParameter(name="name", type="string", description="Label name", required=True),
                    ],
                    returns="Label creation result",
                ),
                ToolFunction(
                    name="ghidra.get_labels",
                    description="Get labels near an address within a radius",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Center address", required=True),
                        ToolParameter(name="radius", type="integer", description="Search radius in bytes", required=False, default=256),
                    ],
                    returns="List of labels with addresses",
                ),
                ToolFunction(
                    name="ghidra.create_bookmark",
                    description="Create an analysis bookmark at an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address to bookmark", required=True),
                        ToolParameter(name="category", type="string", description="Bookmark category", required=True),
                        ToolParameter(name="comment", type="string", description="Bookmark comment", required=True),
                        ToolParameter(
                            name="bookmark_type",
                            type="string",
                            description="Bookmark type",
                            required=False,
                            default="Note",
                            enum=["Note", "Analysis", "Error", "Warning", "Info"],
                        ),
                    ],
                    returns="Bookmark creation result",
                ),
                ToolFunction(
                    name="ghidra.get_bookmarks",
                    description="List bookmarks, optionally filtered by category",
                    parameters=[
                        ToolParameter(name="category", type="string", description="Filter by category", required=False),
                    ],
                    returns="List of bookmarks",
                ),
                ToolFunction(
                    name="ghidra.create_function",
                    description="Define a new function at an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Entry point address", required=True),
                        ToolParameter(name="name", type="string", description="Function name (auto-generated if omitted)", required=False),
                    ],
                    returns="Created function info",
                ),
                ToolFunction(
                    name="ghidra.delete_function",
                    description="Remove function definition at an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Function entry point", required=True),
                    ],
                    returns="Deletion result",
                ),
                ToolFunction(
                    name="ghidra.edit_function_signature",
                    description="Modify function return type, calling convention, or name",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Function entry point", required=True),
                        ToolParameter(name="return_type", type="string", description="New return type", required=False),
                        ToolParameter(name="calling_convention", type="string", description="New calling convention", required=False),
                        ToolParameter(name="name", type="string", description="New function name", required=False),
                    ],
                    returns="Updated function info",
                ),
                ToolFunction(
                    name="ghidra.set_function_variable_type",
                    description="Change the data type of a local variable in a function",
                    parameters=[
                        ToolParameter(name="func_address", type="integer", description="Function entry address", required=True),
                        ToolParameter(name="var_name", type="string", description="Variable name", required=True),
                        ToolParameter(name="new_type", type="string", description="New data type", required=True),
                    ],
                    returns="Variable retype result",
                ),
                ToolFunction(
                    name="ghidra.define_structure",
                    description="Define a new struct data type with named fields",
                    parameters=[
                        ToolParameter(name="name", type="string", description="Structure name", required=True),
                        ToolParameter(
                            name="fields",
                            type="array",
                            description="List of {name, type, size} field definitions",
                            required=True,
                        ),
                    ],
                    returns="Structure definition result",
                ),
                ToolFunction(
                    name="ghidra.get_structures",
                    description="List defined structures, optionally filtered by name",
                    parameters=[
                        ToolParameter(name="filter_name", type="string", description="Substring filter for struct names", required=False),
                    ],
                    returns="List of structure definitions",
                ),
                ToolFunction(
                    name="ghidra.apply_structure_at",
                    description="Apply a defined structure type at a memory address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address to apply struct", required=True),
                        ToolParameter(name="struct_name", type="string", description="Name of the structure type", required=True),
                    ],
                    returns="Application result",
                ),
                ToolFunction(
                    name="ghidra.get_memory_map",
                    description="Get all memory blocks with addresses, sizes, and permissions",
                    parameters=[],
                    returns="List of memory block info",
                ),
                ToolFunction(
                    name="ghidra.get_call_graph",
                    description="Get function call graph from an address to a specified depth",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Root function address", required=True),
                        ToolParameter(
                            name="depth",
                            type="integer",
                            description="Maximum call depth to traverse",
                            required=False,
                            default=2,
                        ),
                    ],
                    returns="Call graph tree structure",
                ),
                ToolFunction(
                    name="ghidra.get_segments",
                    description="Get program segments with detailed permissions and attributes",
                    parameters=[],
                    returns="List of segment info",
                ),
                ToolFunction(
                    name="ghidra.get_program_info",
                    description="Get program metadata: language, compiler, endianness, address size, image base",
                    parameters=[],
                    returns="Program information dict",
                ),
                ToolFunction(
                    name="ghidra.write_bytes",
                    description="Patch bytes at an address in the program",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address to write at", required=True),
                        ToolParameter(
                            name="data",
                            type="string",
                            description="Hex string of bytes (e.g. '90 90 90' or '909090')",
                            required=True,
                        ),
                    ],
                    returns="Write result with bytes written",
                ),
                ToolFunction(
                    name="ghidra.undo",
                    description="Undo the last change in Ghidra",
                    parameters=[],
                    returns="Undo result",
                ),
                ToolFunction(
                    name="ghidra.redo",
                    description="Redo the last undone change in Ghidra",
                    parameters=[],
                    returns="Redo result",
                ),
                ToolFunction(
                    name="ghidra.read_bytes",
                    description="Read bytes from an address in the program",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address to read from", required=True),
                        ToolParameter(name="length", type="integer", description="Number of bytes to read", required=True),
                    ],
                    returns="Dict with address, hex string, bytes list, and length",
                ),
                ToolFunction(
                    name="ghidra.get_pcode",
                    description="Get P-code IR operations for the function at an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address within the function", required=True),
                        ToolParameter(
                            name="max_ops",
                            type="integer",
                            description="Maximum P-code ops to return",
                            required=False,
                            default=500,
                        ),
                    ],
                    returns="Dict with function name and list of P-code operations",
                ),
                ToolFunction(
                    name="ghidra.get_basic_blocks",
                    description="Get basic block structure of the function at an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address within the function", required=True),
                        ToolParameter(
                            name="max_blocks",
                            type="integer",
                            description="Maximum blocks to return",
                            required=False,
                            default=100,
                        ),
                    ],
                    returns="Dict with function name and list of basic blocks",
                ),
                ToolFunction(
                    name="ghidra.get_slice",
                    description="Compute a backward or forward program slice from an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Slice origin address", required=True),
                        ToolParameter(
                            name="direction",
                            type="string",
                            description="Slice direction",
                            required=False,
                            default="backward",
                            enum=["backward", "forward"],
                        ),
                    ],
                    returns="Dict with slice addresses and P-code ops",
                ),
                ToolFunction(
                    name="ghidra.get_callers",
                    description="Get all functions that call the function at the given address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Callee function address", required=True),
                    ],
                    returns="List of caller dicts with caller_address, caller_function, call_site, ref_type",
                ),
                ToolFunction(
                    name="ghidra.get_register_value",
                    description="Get the context-tracked register value at an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address to query", required=True),
                        ToolParameter(name="register", type="string", description="Register name (e.g. EAX, RSP)", required=True),
                    ],
                    returns="Dict with address, register name, value, and has_value flag",
                ),
                ToolFunction(
                    name="ghidra.import_debug_info",
                    description="Import debug symbols from a PDB or DWARF file",
                    parameters=[
                        ToolParameter(name="path", type="string", description="Path to .pdb or .debug file", required=True),
                    ],
                    returns="Dict with path, success, and debug info type",
                ),
                ToolFunction(
                    name="ghidra.add_reference",
                    description="Add a memory reference between two addresses",
                    parameters=[
                        ToolParameter(name="from_addr", type="integer", description="Source address", required=True),
                        ToolParameter(name="to_addr", type="integer", description="Destination address", required=True),
                        ToolParameter(
                            name="ref_type",
                            type="string",
                            description="Reference type",
                            required=False,
                            default="DATA",
                            enum=["DATA", "READ", "WRITE", "CALL", "UNCONDITIONAL_JUMP", "CONDITIONAL_JUMP"],
                        ),
                    ],
                    returns="Dict with from, to, type, and success",
                ),
                ToolFunction(
                    name="ghidra.delete_reference",
                    description="Delete a memory reference between two addresses",
                    parameters=[
                        ToolParameter(name="from_addr", type="integer", description="Source address", required=True),
                        ToolParameter(name="to_addr", type="integer", description="Destination address", required=True),
                    ],
                    returns="Dict with from, to, and success",
                ),
                ToolFunction(
                    name="ghidra.get_relocations",
                    description="Get all relocations from the program relocation table",
                    parameters=[],
                    returns="List of relocation dicts with address, type, symbol, and values",
                ),
                ToolFunction(
                    name="ghidra.create_namespace",
                    description="Create a namespace in the Ghidra symbol table",
                    parameters=[
                        ToolParameter(name="name", type="string", description="Namespace name", required=True),
                        ToolParameter(name="parent", type="string", description="Parent namespace path", required=False),
                    ],
                    returns="Dict with name, path, and success",
                ),
                ToolFunction(
                    name="ghidra.get_namespaces",
                    description="List all namespaces defined in the program",
                    parameters=[],
                    returns="List of namespace dicts with name and path",
                ),
                ToolFunction(
                    name="ghidra.create_equate",
                    description="Create an equate (named constant) and attach it to an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address of the scalar operand", required=True),
                        ToolParameter(name="value", type="integer", description="Numeric value of the equate", required=True),
                        ToolParameter(name="name", type="string", description="Equate name", required=True),
                    ],
                    returns="Dict with name, value, address, and success",
                ),
                ToolFunction(
                    name="ghidra.get_equates",
                    description="List all equates defined in the program",
                    parameters=[],
                    returns="List of equate dicts with name, value, and reference count",
                ),
                ToolFunction(
                    name="ghidra.search_symbols",
                    description="Search symbols by name pattern with optional type filter",
                    parameters=[
                        ToolParameter(name="name", type="string", description="Symbol name pattern", required=True),
                        ToolParameter(
                            name="symbol_type",
                            type="string",
                            description="Symbol type filter (e.g. FUNCTION, LABEL)",
                            required=False,
                        ),
                    ],
                    returns="List of symbol dicts with name, address, type, and namespace",
                ),
                ToolFunction(
                    name="ghidra.get_stack_frame",
                    description="Get stack frame layout for the function at an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address within the function", required=True),
                    ],
                    returns="Dict with function name, frame_size, and list of stack variables",
                ),
                ToolFunction(
                    name="ghidra.get_function_body",
                    description="Get address ranges, thunk status, and size for a function",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address within the function", required=True),
                    ],
                    returns="Dict with name, address, is_thunk, thunked_function, ranges, and total_size",
                ),
                ToolFunction(
                    name="ghidra.get_call_tree",
                    description="Get recursive call tree for callees, callers, or both",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Root function address", required=True),
                        ToolParameter(
                            name="direction",
                            type="string",
                            description="Tree direction",
                            required=False,
                            default="callees",
                            enum=["callees", "callers", "both"],
                        ),
                        ToolParameter(name="depth", type="integer", description="Maximum recursion depth", required=False, default=3),
                    ],
                    returns="Recursive call tree dict",
                ),
                ToolFunction(
                    name="ghidra.get_calling_conventions",
                    description="List all calling conventions defined in the compiler spec",
                    parameters=[],
                    returns="List of calling convention name strings",
                ),
                ToolFunction(
                    name="ghidra.get_instruction_flow",
                    description="Get control flow information for a single instruction",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Instruction address", required=True),
                    ],
                    returns="Dict with address, mnemonic, flow_type, fall_through, and flows",
                ),
                ToolFunction(
                    name="ghidra.create_data_type",
                    description="Create a new data type (enum, union, typedef, or function_def) in the type manager",
                    parameters=[
                        ToolParameter(name="category", type="string", description="Category path (e.g. /MyTypes)", required=True),
                        ToolParameter(name="name", type="string", description="Data type name", required=True),
                        ToolParameter(
                            name="type_kind",
                            type="string",
                            description="Kind of data type to create",
                            required=True,
                            enum=["enum", "union", "typedef", "function_def"],
                        ),
                        ToolParameter(
                            name="fields",
                            type="array",
                            description="Field definitions for enum/union (list of {name, value/type, size} dicts)",
                            required=False,
                        ),
                    ],
                    returns="Dict with name, kind, size, and success",
                ),
                ToolFunction(
                    name="ghidra.create_data",
                    description="Create a data item at an address using a named data type",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address to create data at", required=True),
                        ToolParameter(name="data_type", type="string", description="Data type name", required=True),
                    ],
                    returns="Dict with address, type, size, and success",
                ),
                ToolFunction(
                    name="ghidra.configure_analysis",
                    description="Enable or disable a Ghidra analyzer and optionally set options",
                    parameters=[
                        ToolParameter(name="analyzer_name", type="string", description="Analyzer name", required=True),
                        ToolParameter(name="enabled", type="boolean", description="Enable or disable the analyzer", required=True),
                        ToolParameter(name="options", type="object", description="Analyzer option overrides", required=False),
                    ],
                    returns="Dict with analyzer, enabled, and success",
                ),
                ToolFunction(
                    name="ghidra.set_decompiler_options",
                    description="Configure decompiler simplification style or instruction limit",
                    parameters=[
                        ToolParameter(name="simplification", type="string", description="Simplification style name", required=False),
                        ToolParameter(
                            name="max_instructions",
                            type="integer",
                            description="Maximum instructions per function",
                            required=False,
                        ),
                    ],
                    returns="Dict with simplification, max_instructions, and success",
                ),
                ToolFunction(
                    name="ghidra.create_memory_block",
                    description="Create a new initialized memory block",
                    parameters=[
                        ToolParameter(name="name", type="string", description="Block name", required=True),
                        ToolParameter(name="start", type="integer", description="Start address", required=True),
                        ToolParameter(name="size", type="integer", description="Block size in bytes", required=True),
                        ToolParameter(
                            name="permissions",
                            type="string",
                            description="Permission string (r/w/x combinations)",
                            required=False,
                            default="r",
                        ),
                    ],
                    returns="Dict with name, start, size, permissions, and success",
                ),
                ToolFunction(
                    name="ghidra.get_comments",
                    description="Get all comments in an address range",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Start address", required=True),
                        ToolParameter(
                            name="range_size",
                            type="integer",
                            description="Number of bytes to scan",
                            required=False,
                            default=256,
                        ),
                    ],
                    returns="List of comment dicts with address, type, and comment text",
                ),
                ToolFunction(
                    name="ghidra.get_all_comments",
                    description="Get all comments in the entire program",
                    parameters=[],
                    returns="List of comment dicts with address, type, and comment text",
                ),
                ToolFunction(
                    name="ghidra.get_program_tree",
                    description="Get the program tree module/fragment hierarchy",
                    parameters=[],
                    returns="Dict with trees list containing module and fragment names",
                ),
                ToolFunction(
                    name="ghidra.get_properties",
                    description="Get user-defined properties stored at an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address to query", required=True),
                    ],
                    returns="Dict with address and properties map",
                ),
                ToolFunction(
                    name="ghidra.diff_programs",
                    description="Compare the current program with another program file",
                    parameters=[
                        ToolParameter(
                            name="other_program_path",
                            type="string",
                            description="Path to the other program file",
                            required=True,
                        ),
                    ],
                    returns="Dict with difference count and details",
                ),
                ToolFunction(
                    name="ghidra.set_color",
                    description="Set a background color on a code unit at an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address to colorize", required=True),
                        ToolParameter(name="color", type="integer", description="RGB color as integer (0xRRGGBB)", required=True),
                    ],
                    returns="Dict with address, color, and success",
                ),
                ToolFunction(
                    name="ghidra.set_program_metadata",
                    description="Set program name and/or image base address",
                    parameters=[
                        ToolParameter(name="name", type="string", description="New program name", required=False),
                        ToolParameter(name="image_base", type="integer", description="New image base address", required=False),
                    ],
                    returns="Dict with name, image_base, and success",
                ),
                ToolFunction(
                    name="ghidra.execute_script_with_params",
                    description="Execute Jython code with a JSON params dict injected as a local variable",
                    parameters=[
                        ToolParameter(name="code", type="string", description="Jython code to execute", required=True),
                        ToolParameter(name="params", type="object", description="Parameters injected as 'params' variable", required=False),
                    ],
                    returns="String result of the script",
                ),
                ToolFunction(
                    name="ghidra.manage_thunks",
                    description="Query thunk status and resolved target for a function",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Function address", required=True),
                    ],
                    returns="Dict with address, is_thunk, thunked_function, and thunked_address",
                ),
                ToolFunction(
                    name="ghidra.manage_external_references",
                    description="Get external (imported) references from an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address to query", required=True),
                    ],
                    returns="List of external reference dicts with address, external_name, library, and type",
                ),
                ToolFunction(
                    name="ghidra.add_external_function",
                    description="Add an external function to the external symbol table",
                    parameters=[
                        ToolParameter(name="library", type="string", description="Library name", required=True),
                        ToolParameter(name="name", type="string", description="Function name", required=True),
                        ToolParameter(name="address", type="integer", description="Optional address to link to", required=False),
                    ],
                    returns="Dict with library, name, address, and success",
                ),
                ToolFunction(
                    name="ghidra.create_overlay_space",
                    description="Create a new overlay address space",
                    parameters=[
                        ToolParameter(name="name", type="string", description="Overlay space name", required=True),
                    ],
                    returns="Dict with name and success",
                ),
            ],
        )

    def set_port(self, port: int) -> None:
        """Set the bridge server port.

        Args:
            port: TCP port for the ghidra_bridge RPC connection.
        """
        self._port = port

    async def initialize(self, tool_path: Path | None = None) -> None:
        """Initialize the Ghidra bridge.

        Args:
            tool_path: Path to Ghidra installation.

        Raises:
            ToolError: If ghidra_bridge is not installed or connection fails.
        """
        if tool_path is not None:
            self._ghidra_path = tool_path
        self.state = BridgeState(
            connected=False,
            tool_running=False,
            binary_loaded=False,
            process_attached=False,
            target_path=None,
            target_pid=None,
            last_error=None,
        )

        try:
            ghidra_bridge_mod = importlib.import_module("ghidra_bridge")
            bridge_cls = cast("Callable[..., object]", ghidra_bridge_mod.GhidraBridge)

            self._bridge = await asyncio.to_thread(
                bridge_cls,
                namespace=None,
                connect_to_host="127.0.0.1",
                connect_to_port=self._port,
            )
            self.state.connected = True
            self.state.tool_running = True
            _logger.info("ghidra_bridge_connected", port=self._port)

        except ImportError as imp_err:
            _logger.warning("ghidra_bridge_not_installed", bridge="ghidra")
            self._bridge = None
            self.state.connected = False
            self.state.tool_running = False
            error_message = "ghidra_bridge package not installed"
            raise ToolError(error_message) from imp_err

        except Exception as exc:
            _logger.exception("ghidra_connect_failed", error=str(exc))
            self._bridge = None
            self.state.connected = False
            self.state.tool_running = False
            self.state.last_error = str(exc)
            error_message = f"Failed to connect to Ghidra: {exc}"
            raise ToolError(error_message) from exc

    async def shutdown(self) -> None:
        """Shutdown Ghidra and cleanup resources."""
        if self._process is not None:
            pid = self._process.pid
            process_manager = ProcessManager.get_instance()

            self._process.terminate()
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(self._process.wait),
                    timeout=10,
                )
            except TimeoutError:
                _logger.warning("ghidra_process_terminate_timeout", pid=pid)
                self._process.kill()
                await asyncio.to_thread(self._process.wait)

            process_manager.unregister(pid)
            self._process = None

        if self._bridge_script_path is not None:
            try:
                if await asyncio.to_thread(self._bridge_script_path.exists):
                    await asyncio.to_thread(self._bridge_script_path.unlink, missing_ok=True)
                parent = self._bridge_script_path.parent
                parent_children = await asyncio.to_thread(lambda: list(parent.iterdir()))
                if await asyncio.to_thread(parent.exists) and not any(parent_children):
                    await asyncio.to_thread(parent.rmdir)
            except OSError as e:
                _logger.debug(
                    "bridge_script_cleanup_failed",
                    error=str(e),
                )
            self._bridge_script_path = None

        self._bridge = None
        self._binary_path = None
        project_path_str = str(self._project_path) if self._project_path is not None else None
        self._project_path = None
        await super().shutdown()
        _logger.info("ghidra_bridge_shutdown", bridge="ghidra", project_path=project_path_str)

    async def is_available(self) -> bool:
        """Check if Ghidra is available.

        Returns:
            bool: True if Ghidra can be used.
        """
        if self._ghidra_path is None:
            return False
        return importlib.util.find_spec("ghidra_bridge") is not None

    async def start_headless(
        self,
        project_dir: Path,
        project_name: str = "intellicrack",
    ) -> None:
        """Start Ghidra in headless mode with bridge.

        Args:
            project_dir: Directory for Ghidra project.
            project_name: Name of the project.

        Raises:
            ToolError: If Ghidra cannot be started.
        """
        if self._ghidra_path is None:
            error_message = "Ghidra path not set"
            raise ToolError(error_message)

        ghidra_run = self._ghidra_path / "support" / "analyzeHeadless.bat"
        if not await asyncio.to_thread(ghidra_run.exists):
            ghidra_run = self._ghidra_path / "support" / "analyzeHeadless"

        if not await asyncio.to_thread(ghidra_run.exists):
            error_message = f"Ghidra headless script not found: {ghidra_run}"
            raise ToolError(error_message)

        await asyncio.to_thread(project_dir.mkdir, parents=True, exist_ok=True)
        self._project_path = project_dir / project_name

        bridge_script = self._create_bridge_script()

        cmd = [
            str(ghidra_run),
            str(project_dir),
            project_name,
            "-scriptPath",
            str(bridge_script.parent),
            "-postScript",
            bridge_script.name,
        ]

        _logger.info("ghidra_headless_starting", command=" ".join(cmd))

        def _start_process() -> Popen[bytes]:
            return Popen(
                cmd,
                stdout=PIPE,
                stderr=PIPE,
            )

        self._process = await asyncio.to_thread(_start_process)

        process_manager = ProcessManager.get_instance()
        process_manager.register(
            self._process,
            name="ghidra-headless",
            process_type=ProcessType.EXTERNAL_TOOL,
            metadata={"project": project_name, "project_dir": str(project_dir)},
            cleanup_callback=self.shutdown,
        )

        await self._wait_for_bridge_port()

        try:
            ghidra_bridge_mod = importlib.import_module("ghidra_bridge")
            bridge_cls = cast("Callable[..., object]", ghidra_bridge_mod.GhidraBridge)

            self._bridge = await asyncio.to_thread(
                bridge_cls,
                namespace=None,
                connect_to_host="127.0.0.1",
                connect_to_port=self._port,
            )
            self.state.connected = True
            self.state.tool_running = True
            _logger.info("ghidra_headless_connected", port=self._port)
        except Exception as e:
            _logger.warning("ghidra_connect_failed", port=self._port, error=str(e))
            error_message = f"Failed to connect to Ghidra: {e}"
            self.state.last_error = error_message
            raise ToolError(error_message) from e

    async def _wait_for_bridge_port(
        self,
        timeout_seconds: int = 60,
        poll_interval: float = 2.0,
    ) -> None:
        """Poll until the Ghidra bridge port is accepting connections.

        Args:
            timeout_seconds: Maximum seconds to wait before raising.
            poll_interval: Seconds between connection attempts.

        Raises:
            ToolError: If the process exits or the timeout is exceeded.
        """
        elapsed = 0.0
        attempt = 0

        while elapsed < timeout_seconds:
            attempt += 1

            if self._process is not None and self._process.poll() is not None:
                rc = self._process.returncode
                msg = f"Ghidra process exited prematurely with code {rc}"
                raise ToolError(msg)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            try:
                result = await asyncio.to_thread(sock.connect_ex, ("127.0.0.1", self._port))
                if result == 0:
                    _logger.info(
                        "ghidra_bridge_port_ready",
                        port=self._port,
                        attempts=attempt,
                    )
                    return
            finally:
                sock.close()

            _logger.debug(
                "ghidra_bridge_port_polling",
                port=self._port,
                attempt=attempt,
                elapsed=elapsed,
            )
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        msg = f"Ghidra bridge port {self._port} not ready after {timeout_seconds}s ({attempt} attempts)"
        raise ToolError(msg)

    def _create_bridge_script(self) -> Path:
        """Create the Ghidra bridge startup script.

        Returns:
            Path: Path to the created script.
        """
        script_content = f"""
# @category: IntelliCrack
# Start ghidra_bridge server

import ghidra_bridge_server
ghidra_bridge_server.GhidraBridgeServer(
    server_host="127.0.0.1",
    server_port={self._port},
).start()
"""
        script_dir = Path(tempfile.gettempdir()) / "intellicrack_ghidra"
        script_dir.mkdir(exist_ok=True)

        script_path = script_dir / "start_bridge.py"
        script_path.write_text(script_content)
        self._bridge_script_path = script_path

        return script_path

    def create_bridge_script(self) -> Path:
        """Create the Ghidra bridge startup script.

        Returns:
            Path: Path to the created script.
        """
        return self._create_bridge_script()

    @property
    def bridge_script_path(self) -> Path | None:
        """Get the current bridge script path.

        Returns:
            Path | None: Path to the bridge script or None.
        """
        return self._bridge_script_path

    async def load_binary(self, path: Path) -> BinaryInfo:
        """Load a binary file into Ghidra.

        Args:
            path: Path to the binary file.

        Returns:
            BinaryInfo: BinaryInfo with file details.

        Raises:
            ToolError: If load fails.
        """
        if not await asyncio.to_thread(path.exists):
            error_message = f"File not found: {path}"
            raise ToolError(error_message)

        self._binary_path = await asyncio.to_thread(path.resolve)

        if self._bridge is not None:
            try:
                safe_path = json.dumps(path.as_posix())
                await self._execute_remote(
                    f"prog = importFile(java.io.File({safe_path}))\nif prog is not None:\n    state.setCurrentProgram(prog)\n",
                )
            except Exception:
                _logger.exception("ghidra_remote_import_failed", binary_path=str(path))

        data = await asyncio.to_thread(path.read_bytes)
        md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()

        file_type = self._detect_format(data)
        arch, is_64 = self._detect_architecture(data)

        self.state.connected = True
        self.state.tool_running = True
        self.state.binary_loaded = True
        self.state.target_path = self._binary_path

        _logger.info("binary_loaded", path=path.name)

        entry_point = 0
        sections: list[SectionInfo] = []
        imports: list[ImportInfo] = []
        exports: list[ExportInfo] = []

        if self._bridge is not None:
            try:
                entry_point, sections, imports, exports = await self._extract_binary_metadata()
            except Exception:
                _logger.exception("ghidra_metadata_extraction_failed", binary_path=str(path))

        return BinaryInfo(
            path=self._binary_path,
            name=path.name,
            size=len(data),
            md5=md5,
            sha256=sha256,
            file_type=file_type,
            architecture=arch,
            is_64bit=is_64,
            entry_point=entry_point,
            sections=sections,
            imports=imports,
            exports=exports,
        )

    async def _extract_binary_metadata(
        self,
    ) -> tuple[int, list[SectionInfo], list[ImportInfo], list[ExportInfo]]:
        """Extract entry point, sections, imports, and exports from Ghidra.

        Returns:
            tuple[int, list[SectionInfo], list[ImportInfo], list[ExportInfo]]: Tuple of (entry_point, sections, imports, exports).
        """
        if self._bridge is None:
            return 0, [], [], []

        _logger.debug("ghidra_metadata_extraction_started")
        result = await self._execute_remote(
            """
import math

metadata = {
    'entry_point': 0,
    'sections': [],
    'imports': [],
    'exports': [],
}

try:
    entry = currentProgram.getEntryPoint()
    if entry is not None:
        metadata['entry_point'] = entry.getOffset()

    memory = currentProgram.getMemory()
    blocks = memory.getBlocks()

    for block in blocks:
        start = block.getStart()
        size = block.getSize()
        flags = 0
        if block.isRead():
            flags |= 0x1
        if block.isWrite():
            flags |= 0x2
        if block.isExecute():
            flags |= 0x4

        entropy = 0.0
        if block.isInitialized() and size > 0:
            counts = [0] * 256
            chunk_size = 0x10000
            offset = 0

            while offset < size:
                to_read = min(chunk_size, size - offset)
                data = memory.getBytes(start.add(offset), to_read)
                for b in data:
                    counts[b & 0xFF] += 1
                offset += to_read

            total = float(size)
            ent = 0.0
            for c in counts:
                if c:
                    p = c / total
                    ent -= p * math.log(p, 2)
            entropy = ent

        metadata['sections'].append({
            'name': block.getName(),
            'virtual_address': start.getOffset(),
            'virtual_size': size,
            'raw_size': size,
            'characteristics': flags,
            'entropy': float(entropy),
        })

    st = currentProgram.getSymbolTable()

    for sym in st.getExternalSymbols():
        parent = sym.getParentSymbol()
        dll_name = str(parent.getName()) if parent else ''
        metadata['imports'].append({
            'dll': dll_name,
            'function': sym.getName(),
            'address': sym.getAddress().getOffset(),
        })

    ordinal = 0
    for sym in st.getAllSymbols(True):
        if sym.isExternalEntryPoint():
            metadata['exports'].append({
                'name': sym.getName(),
                'address': sym.getAddress().getOffset(),
                'ordinal': ordinal,
            })
            ordinal += 1
except Exception as e:
    metadata['extraction_errors'] = metadata.get('extraction_errors', [])
    metadata['extraction_errors'].append(str(e))

metadata
            """,
        )

        if not isinstance(result, dict):
            return 0, [], [], []

        result_dict = cast("dict[str, Any]", result)
        entry_point = int(result_dict.get("entry_point", 0))

        sections_data = cast("list[dict[str, Any]]", result_dict.get("sections", []))
        sections = [
            SectionInfo(
                name=str(s.get("name", "")),
                virtual_address=int(s.get("virtual_address", 0)),
                virtual_size=int(s.get("virtual_size", 0)),
                raw_size=int(s.get("raw_size", 0)),
                characteristics=int(s.get("characteristics", 0)),
                entropy=float(s.get("entropy", 0.0)),
            )
            for s in sections_data
        ]

        imports_data = cast("list[dict[str, Any]]", result_dict.get("imports", []))
        imports = [
            ImportInfo(
                dll=str(i.get("dll", "")),
                function=str(i.get("function", "")),
                ordinal=None,
                address=int(i.get("address", 0)),
            )
            for i in imports_data
        ]

        exports_data = cast("list[dict[str, Any]]", result_dict.get("exports", []))
        exports = [
            ExportInfo(
                name=str(exp.get("name", "")),
                ordinal=int(exp.get("ordinal", 0)),
                address=int(exp.get("address", 0)),
            )
            for exp in exports_data
        ]

        _logger.debug(
            "ghidra_metadata_extraction_completed",
            section_count=len(sections),
            import_count=len(imports),
            export_count=len(exports),
        )
        return entry_point, sections, imports, exports

    @staticmethod
    def _detect_format(data: bytes) -> str:
        """Detect binary format.

        Args:
            data: Binary data.

        Returns:
            str: Format string.
        """
        if len(data) < _MIN_HEADER_SIZE:
            return "raw"

        if data[:2] == _MZ_MAGIC:
            return "pe"
        if data[:4] == _ELF_MAGIC:
            return "elf"
        return "macho" if data[:4] in _MACHO_MAGICS else "raw"

    @staticmethod
    def _detect_architecture(data: bytes) -> tuple[str, bool]:
        """Detect CPU architecture.

        Args:
            data: Binary data.

        Returns:
            tuple[str, bool]: Tuple of (architecture, is_64bit).
        """
        if len(data) < _MIN_ELF_HEADER:
            return "unknown", False

        if data[:2] == _MZ_MAGIC and len(data) > _PE_POINTER_END:
            pe_offset = int.from_bytes(
                data[_PE_POINTER_OFFSET:_PE_POINTER_END],
                "little",
            )
            if len(data) > pe_offset + _PE_HEADER_MIN:
                machine = int.from_bytes(
                    data[pe_offset + 4 : pe_offset + 6],
                    "little",
                )
                if machine == _MACHINE_AMD64:
                    return "x86_64", True
                if machine == _MACHINE_I386:
                    return "x86", False

        if data[:4] == _ELF_MAGIC:
            return ("x86_64", True) if data[4] == _ELF_CLASS_64 else ("x86", False)
        return "unknown", False

    async def analyze(self) -> None:
        """Run full Ghidra analysis.

        Raises:
            ToolError: If Ghidra is not connected or analysis fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            await self._execute_remote("analyzeAll(currentProgram)")
            _logger.info("ghidra_analysis_complete", bridge="ghidra")
        except Exception as e:
            _logger.warning("ghidra_analysis_failed", error=str(e))
            error_message = f"Analysis failed: {e}"
            raise ToolError(error_message) from e

    async def get_functions(
        self,
        filter_pattern: str | None = None,
    ) -> list[FunctionInfo]:
        """Get all analyzed functions.

        Args:
            filter_pattern: Optional regex to filter names.

        Returns:
            list[FunctionInfo]: List of function information.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote("""
                functions = []
                fm = currentProgram.getFunctionManager()
                for func in fm.getFunctions(True):
                    functions.append({
                        'name': func.getName(),
                        'address': func.getEntryPoint().getOffset(),
                        'size': func.getBody().getNumAddresses(),
                        'calling_convention': func.getCallingConventionName(),
                        'return_type': str(func.getReturnType()),
                    })
                functions
            """)

            pattern = re.compile(filter_pattern) if filter_pattern else None
            functions: list[FunctionInfo] = []

            result_list = cast("list[dict[str, Any]]", result) if result else []
            for f in result_list:
                name = str(f.get("name", ""))
                if pattern and not pattern.search(name):
                    continue

                functions.append(
                    FunctionInfo(
                        name=name,
                        address=int(f.get("address", 0)),
                        size=int(f.get("size", 0)),
                        calling_convention=str(f.get("calling_convention", "unknown")),
                        return_type=str(f.get("return_type", "unknown")),
                        parameters=[],
                        local_variables=[],
                        decompiled_code=None,
                        disassembly=None,
                    ),
                )

        except Exception:
            _logger.exception("get_functions_failed", filter_pattern=filter_pattern)
            return []

        return functions

    async def get_function(self, address: int) -> FunctionInfo | None:
        """Get function at a specific address.

        Args:
            address: Function address.

        Returns:
            FunctionInfo | None: Function info or None if not found.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(f"""
                addr = toAddr({address})
                func = getFunctionContaining(addr)
                if func is not None:
                    params = []
                    for param in func.getParameters():
                        params.append({{
                            'name': param.getName(),
                            'type': str(param.getDataType()),
                        }})
                    vars = []
                    for var in func.getLocalVariables():
                        vars.append({{
                            'name': var.getName(),
                            'type': str(var.getDataType()),
                            'offset': var.getStackOffset(),
                        }})
                    {{
                        'name': func.getName(),
                        'address': func.getEntryPoint().getOffset(),
                        'size': func.getBody().getNumAddresses(),
                        'calling_convention': func.getCallingConventionName(),
                        'return_type': str(func.getReturnType()),
                        'parameters': params,
                        'variables': vars,
                    }}
                else:
                    None
            """)

            if result is None:
                return None

            result_dict = cast("dict[str, Any]", result)

            params = [
                ParameterInfo(
                    name=str(p.get("name", "")),
                    type=str(p.get("type", "unknown")),
                    size=0,
                    location="unknown",
                )
                for p in cast("list[dict[str, Any]]", result_dict.get("parameters", []))
            ]

            variables = [
                VariableInfo(
                    name=str(v.get("name", "")),
                    type=str(v.get("type", "unknown")),
                    offset=int(v.get("offset", 0)),
                    size=0,
                )
                for v in cast("list[dict[str, Any]]", result_dict.get("variables", []))
            ]

            return FunctionInfo(
                name=str(result_dict.get("name", "")),
                address=int(result_dict.get("address", 0)),
                size=int(result_dict.get("size", 0)),
                calling_convention=str(result_dict.get("calling_convention", "unknown")),
                return_type=str(result_dict.get("return_type", "unknown")),
                parameters=params,
                local_variables=variables,
                decompiled_code=None,
                disassembly=None,
            )

        except Exception:
            _logger.exception("get_function_failed", address=hex(address))
            return None

    async def decompile(self, address: int) -> str:
        """Decompile function at address.

        Args:
            address: Function address.

        Returns:
            str: Decompiled C pseudocode.

        Raises:
            ToolError: If decompilation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(f"""
                from ghidra.app.decompiler import DecompInterface

                ifc = DecompInterface()
                ifc.openProgram(currentProgram)

                addr = toAddr({address})
                func = getFunctionContaining(addr)

                if func is not None:
                    results = ifc.decompileFunction(func, {self.DECOMPILE_TIMEOUT_SECONDS}, monitor)
                    if results.decompileCompleted():
                        results.getDecompiledFunction().getC()
                    else:
                        "Decompilation failed"
                else:
                    "Function not found"
            """)

            return str(result) if result else "Decompilation failed"

        except Exception as e:
            _logger.warning("ghidra_decompilation_failed", error=str(e))
            error_message = f"Decompilation failed: {e}"
            raise ToolError(error_message) from e

    async def disassemble(
        self,
        address: int,
        count: int = 20,
    ) -> list[DisassemblyLine]:
        """Disassemble instructions at address.

        Args:
            address: Start address.
            count: Number of instructions.

        Returns:
            list[DisassemblyLine]: List of disassembly lines.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(f"""
                instructions = []
                addr = toAddr({address})
                listing = currentProgram.getListing()

                for i in range({count}):
                    instr = listing.getInstructionAt(addr)
                    if instr is None:
                        break
                    instructions.append({{
                        'address': addr.getOffset(),
                        'bytes': ' '.join('%02X' % b for b in instr.getBytes()),
                        'mnemonic': instr.getMnemonicString(),
                        'operands': ', '.join(
                            instr.getDefaultOperandRepresentation(j)
                            for j in range(instr.getNumOperands())
                        ),
                    }})
                    addr = instr.getNext().getAddress() if instr.getNext() else None
                    if addr is None:
                        break

                instructions
            """)

            result_list = cast("list[dict[str, Any]]", result) if result else []
            return [
                DisassemblyLine(
                    address=int(i.get("address", 0)),
                    bytes_str=str(i.get("bytes", "")),
                    mnemonic=str(i.get("mnemonic", "")),
                    operands=str(i.get("operands", "")),
                    comment=None,
                )
                for i in result_list
            ]

        except Exception:
            _logger.exception("disassembly_failed", address=hex(address), count=count)
            return []

    async def get_xrefs_to(self, address: int) -> list[CrossReference]:
        """Get cross-references to an address.

        Args:
            address: Target address.

        Returns:
            list[CrossReference]: List of cross-references.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(f"""
                xrefs = []
                addr = toAddr({address})

                for ref in getReferencesTo(addr):
                    xrefs.append({{
                        'from': ref.getFromAddress().getOffset(),
                        'to': addr.getOffset(),
                        'type': str(ref.getReferenceType()),
                    }})

                xrefs
            """)

            result_list = cast("list[dict[str, Any]]", result) if result else []
            return [
                CrossReference(
                    from_address=int(x.get("from", 0)),
                    to_address=int(x.get("to", 0)),
                    ref_type="call" if str(x.get("type", "")).startswith("CALL") else "data",
                    from_function=None,
                    to_function=None,
                )
                for x in result_list
            ]

        except Exception:
            _logger.exception("get_xrefs_to_failed", address=hex(address))
            return []

    async def get_xrefs_from(self, address: int) -> list[CrossReference]:
        """Get cross-references from an address.

        Args:
            address: Source address.

        Returns:
            list[CrossReference]: List of cross-references.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(f"""
                xrefs = []
                addr = toAddr({address})

                for ref in getReferencesFrom(addr):
                    xrefs.append({{
                        'from': addr.getOffset(),
                        'to': ref.getToAddress().getOffset(),
                        'type': str(ref.getReferenceType()),
                    }})

                xrefs
            """)

            result_list = cast("list[dict[str, Any]]", result) if result else []
            return [
                CrossReference(
                    from_address=int(x.get("from", 0)),
                    to_address=int(x.get("to", 0)),
                    ref_type="call" if str(x.get("type", "")).startswith("CALL") else "data",
                    from_function=None,
                    to_function=None,
                )
                for x in result_list
            ]

        except Exception:
            _logger.exception("get_xrefs_from_failed", address=hex(address))
            return []

    async def search_strings(self, pattern: str, encoding: str = "ascii") -> list[StringInfo]:
        """Search for strings matching pattern.

        Args:
            pattern: Regex pattern.
            encoding: String encoding to filter (ascii, utf-16, utf-16-le, utf-16-be, utf-32).

        Returns:
            list[StringInfo]: List of matching strings.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        encoding_filter = json.dumps(encoding)
        try:
            result = await self._execute_remote(f"""
                import re
                strings = []
                pattern = re.compile({json.dumps(pattern)}, re.IGNORECASE)
                enc_filter = {encoding_filter}

                for string in currentProgram.getListing().getDefinedData(True):
                    if string.hasStringValue():
                        type_name = string.getDataType().getName().lower()
                        if enc_filter in ('utf-16', 'utf-16-le', 'utf-16-be'):
                            if 'unicode' not in type_name and 'utf16' not in type_name and 'utf-16' not in type_name:
                                continue
                        elif enc_filter == 'utf-32':
                            if 'utf32' not in type_name and 'utf-32' not in type_name:
                                continue
                        elif enc_filter == 'ascii':
                            if 'unicode' in type_name or 'utf' in type_name:
                                continue
                        value = string.getValue()
                        if value and pattern.search(str(value)):
                            strings.append({{
                                'address': string.getAddress().getOffset(),
                                'value': str(value),
                                'type_name': type_name,
                            }})

                strings
            """)

            normalized_encoding: Literal["ascii", "utf-8", "utf-16le", "utf-16be"] = (
                "ascii" if encoding == "ascii"
                else "utf-8" if encoding in {"utf-8", "utf8"}
                else "utf-16le" if encoding in {"utf-16", "utf-16-le", "utf-16le"}
                else "utf-16be" if encoding in {"utf-16-be", "utf-16be"}
                else "ascii"
            )
            result_list = cast("list[dict[str, Any]]", result) if result else []
            return [
                StringInfo(
                    address=int(s.get("address", 0)),
                    value=str(s.get("value", "")),
                    encoding=normalized_encoding,
                    section="",
                )
                for s in result_list
            ]

        except Exception:
            _logger.exception("string_search_failed", pattern=pattern)
            return []

    async def search_bytes(
        self,
        pattern: bytes | str | None = None,
        *,
        hex_pattern: str | None = None,
    ) -> list[int]:
        """Search for a byte pattern in the binary, with optional wildcard mask support.

        Args:
            pattern: Bytes to find (exact match) or hex string pattern.
            hex_pattern: Hex string with optional '??' wildcards (e.g. '48 8B ?? ?? ?? ??').

        Returns:
            list[int]: List of addresses where the pattern was found.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("byte_search_starting", has_hex_pattern=hex_pattern is not None)

        if hex_pattern is not None:
            raw_hex = hex_pattern
        elif isinstance(pattern, str):
            raw_hex = pattern
        else:
            raw_hex = None

        if raw_hex is not None:
            clean = raw_hex.strip()
            tokens = clean.split() if " " in clean else [clean[i : i + 2] for i in range(0, len(clean), 2)]

            byte_vals: list[int] = []
            mask_vals: list[int] = []
            for tok in tokens:
                if tok in {"??", "?"}:
                    b = 0x00
                    m = 0x00
                else:
                    b = int(tok, 16)
                    m = 0xFF
                bj = (b - 256) if b > _JAVA_SIGNED_THRESHOLD else b
                mj = (m - 256) if m > _JAVA_SIGNED_THRESHOLD else m
                byte_vals.append(bj)
                mask_vals.append(mj)

            byte_arr_str = ", ".join(str(v) for v in byte_vals)
            mask_arr_str = ", ".join(str(v) for v in mask_vals)

            try:
                result = await self._execute_remote(f"""
                    from jarray import array
                    addresses = []
                    memory = currentProgram.getMemory()
                    start = memory.getMinAddress()
                    end = memory.getMaxAddress()
                    byte_arr = array([{byte_arr_str}], 'b')
                    mask_arr = array([{mask_arr_str}], 'b')
                    found = memory.findBytes(start, end, byte_arr, mask_arr, True, monitor)
                    while found is not None:
                        addresses.append(found.getOffset())
                        found = memory.findBytes(found.add(1), end, byte_arr, mask_arr, True, monitor)
                    addresses
                """)
                if isinstance(result, list):
                    return [int(addr) for addr in cast("list[int | float | str]", result)]
            except Exception:
                _logger.exception("byte_search_failed_hex", pattern_length=len(tokens))
            return []

        raw_bytes = pattern if isinstance(pattern, bytes) else b""
        try:
            byte_list_str = ", ".join(str(b) for b in raw_bytes)
            result = await self._execute_remote(f"""
                addresses = []
                memory = currentProgram.getMemory()
                start = memory.getMinAddress()
                end = memory.getMaxAddress()
                searcher = memory.findBytes(start, end, [{byte_list_str}], None, True, monitor)
                while searcher is not None:
                    addresses.append(searcher.getOffset())
                    searcher = memory.findBytes(searcher.add(1), end, [{byte_list_str}], None, True, monitor)
                addresses
            """)
            if isinstance(result, list):
                return [int(addr) for addr in cast("list[int | float | str]", result)]
        except Exception:
            _logger.exception("byte_search_failed", pattern_length=len(raw_bytes))
        return []

    async def rename_function(self, address: int, new_name: str) -> bool:
        """Rename a function.

        Args:
            address: Function address.
            new_name: New name.

        Returns:
            bool: True if renamed.

        Raises:
            ToolError: If operation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            await self._execute_remote(f"""
                from ghidra.program.model.symbol import SourceType

                addr = toAddr({address})
                func = getFunctionContaining(addr)
                if func is not None:
                    func.setName({json.dumps(new_name)}, SourceType.USER_DEFINED)
            """)

        except Exception as e:
            _logger.warning("ghidra_rename_failed", address=hex(address), error=str(e))
            error_message = f"Rename failed: {e}"
            raise ToolError(error_message) from e

        _logger.info("function_renamed", address=hex(address), new_name=new_name)
        return True

    async def add_comment(
        self,
        address: int,
        comment: str,
        comment_type: str = "EOL",
    ) -> bool:
        """Add a comment at an address.

        Args:
            address: Address.
            comment: Comment text.
            comment_type: Type of comment.

        Returns:
            bool: True if added.

        Raises:
            ToolError: If operation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        comment_map = {
            "EOL": "CodeUnit.EOL_COMMENT",
            "PRE": "CodeUnit.PRE_COMMENT",
            "POST": "CodeUnit.POST_COMMENT",
            "PLATE": "CodeUnit.PLATE_COMMENT",
        }
        ghidra_type = comment_map.get(comment_type, "CodeUnit.EOL_COMMENT")

        try:
            await self._execute_remote(f"""
                from ghidra.program.model.listing import CodeUnit

                addr = toAddr({address})
                cu = currentProgram.getListing().getCodeUnitAt(addr)
                if cu is not None:
                    cu.setComment({ghidra_type}, {json.dumps(comment)})
            """)

        except Exception as e:
            _logger.warning("ghidra_add_comment_failed", address=hex(address), error=str(e))
            error_message = f"Add comment failed: {e}"
            raise ToolError(error_message) from e

        _logger.info("comment_added", address=hex(address))
        return True

    async def get_imports(self) -> list[ImportInfo]:
        """Get imported functions.

        Returns:
            list[ImportInfo]: List of imports.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote("""
                imports = []
                st = currentProgram.getSymbolTable()

                for sym in st.getExternalSymbols():
                    imports.append({
                        'dll': str(sym.getParentSymbol().getName()) if sym.getParentSymbol() else '',
                        'function': sym.getName(),
                        'address': sym.getAddress().getOffset(),
                    })

                imports
            """)

            result_list = cast("list[dict[str, Any]]", result) if result else []
            return [
                ImportInfo(
                    dll=str(i.get("dll", "")),
                    function=str(i.get("function", "")),
                    ordinal=None,
                    address=int(i.get("address", 0)),
                )
                for i in result_list
            ]

        except Exception:
            _logger.exception("get_imports_failed", binary_path=str(self._binary_path))
            return []

    async def get_exports(self) -> list[ExportInfo]:
        """Get exported functions.

        Returns:
            list[ExportInfo]: List of exports.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote("""
                exports = []
                st = currentProgram.getSymbolTable()

                for sym in st.getAllSymbols(True):
                    if sym.isExternalEntryPoint():
                        exports.append({
                            'name': sym.getName(),
                            'address': sym.getAddress().getOffset(),
                        })

                exports
            """)

            result_list = cast("list[dict[str, Any]]", result) if result else []
            return [
                ExportInfo(
                    name=str(e.get("name", "")),
                    ordinal=idx,
                    address=int(e.get("address", 0)),
                )
                for idx, e in enumerate(result_list)
            ]

        except Exception:
            _logger.exception("get_exports_failed", binary_path=str(self._binary_path))
            return []

    async def get_data_type(self, address: int) -> DataTypeInfo | None:
        """Get data type at address via Ghidra DataTypeManager.

        Args:
            address: Address to check.

        Returns:
            DataTypeInfo | None: DataTypeInfo if data is defined, otherwise None.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(f"""
                from ghidra.program.model.data import Pointer, Array

                addr = toAddr({address})
                data = currentProgram.getListing().getDataAt(addr)
                if data is None:
                    None
                else:
                    dt = data.getDataType()
                    is_pointer = isinstance(dt, Pointer)
                    is_array = isinstance(dt, Array)
                    base_type = None
                    array_length = None
                    if is_pointer:
                        base_type = str(dt.getDataType())
                    if is_array:
                        base_type = str(dt.getDataType())
                        array_length = int(dt.getNumElements())
                    {{
                        'address': data.getAddress().getOffset(),
                        'name': dt.getName(),
                        'category': dt.getCategoryPath().getPath(),
                        'size': int(dt.getLength()) if dt.getLength() >= 0 else 0,
                        'is_pointer': bool(is_pointer),
                        'is_array': bool(is_array),
                        'array_length': array_length,
                        'base_type': base_type,
                    }}
            """)

            if result is None or not isinstance(result, dict):
                return None

            result_dict = cast("dict[str, Any]", result)
            return DataTypeInfo(
                address=int(result_dict.get("address", address)),
                name=str(result_dict.get("name", "")),
                category=str(result_dict.get("category", "")),
                size=int(result_dict.get("size", 0)),
                is_pointer=bool(result_dict.get("is_pointer", False)),
                is_array=bool(result_dict.get("is_array", False)),
                array_length=(int(result_dict["array_length"]) if result_dict.get("array_length") is not None else None),
                base_type=(str(result_dict["base_type"]) if result_dict.get("base_type") is not None else None),
            )

        except Exception:
            _logger.exception("get_data_type_failed", address=hex(address))
            return None

    async def set_data_type(self, address: int, data_type: str) -> bool:
        """Set data type at an address.

        Args:
            address: Address to set type.
            data_type: Data type name.

        Returns:
            bool: True if the data type was applied.

        Raises:
            ToolError: If setting the data type fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        data_type_literal = json.dumps(data_type)

        try:
            result = await self._execute_remote(f"""
                from ghidra.app.util.parser import DataTypeParser

                addr = toAddr({address})
                listing = currentProgram.getListing()
                dtm = currentProgram.getDataTypeManager()
                parser = DataTypeParser(dtm)
                parsed = parser.parse({data_type_literal})

                if parsed is None:
                    False
                else:
                    existing = listing.getDataAt(addr)
                    if existing is not None:
                        listing.clearCodeUnits(addr, addr, False)
                    listing.createData(addr, parsed)
                    True
            """)
            return bool(result)

        except Exception as e:
            _logger.warning("ghidra_set_data_type_failed", address=hex(address), error=str(e))
            error_message = f"Failed to set data type: {e}"
            raise ToolError(error_message) from e

    async def execute_script(self, code: str) -> str:
        """Execute arbitrary Jython script in Ghidra's JVM context.

        Args:
            code: Jython code to execute.

        Returns:
            str: String representation of the script result.
        """
        _logger.debug("script_executing", code_length=len(code))
        result = await self._execute_remote(code)
        return str(result) if result is not None else ""

    async def set_label(self, address: int, name: str) -> dict[str, Any]:
        """Create or modify a label at an address.

        Args:
            address: Address for the label.
            name: Label name.

        Returns:
            dict[str, Any]: Dict with address, name, and success status.

        Raises:
            ToolError: If Ghidra is not connected or operation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("label_setting", address=hex(address), label_name=name)
        await self._execute_remote(f"""
            from ghidra.program.model.symbol import SourceType
            addr = toAddr({address})
            st = currentProgram.getSymbolTable()
            st.createLabel(addr, {json.dumps(name)}, SourceType.USER_DEFINED)
        """)
        return {"address": hex(address), "name": name, "success": True}

    async def get_labels(self, address: int, radius: int = 0x100) -> list[dict[str, Any]]:
        """Get labels near an address within a radius.

        Args:
            address: Center address.
            radius: Search radius in bytes.

        Returns:
            list[dict[str, Any]]: List of label dicts with name, address, and type fields.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(f"""
                labels = []
                start = toAddr({address} - {radius})
                end = toAddr({address} + {radius})
                it = currentProgram.getSymbolTable().getSymbolIterator(start, True)
                while it.hasNext():
                    sym = it.next()
                    if sym.getAddress().compareTo(end) > 0:
                        break
                    labels.append({{
                        'name': sym.getName(),
                        'address': sym.getAddress().getOffset(),
                        'type': str(sym.getSymbolType()),
                    }})
                labels
            """)
            return cast("list[dict[str, Any]]", result) if result else []
        except Exception:
            _logger.exception("get_labels_failed", address=hex(address))
            return []

    async def create_bookmark(
        self,
        address: int,
        category: str,
        comment: str,
        bookmark_type: str = "Note",
    ) -> dict[str, Any]:
        """Create an analysis bookmark at an address.

        Args:
            address: Address to bookmark.
            category: Bookmark category.
            comment: Bookmark comment text.
            bookmark_type: Bookmark type (Note, Analysis, Error, Warning, Info).

        Returns:
            dict[str, Any]: Dict with address, category, comment, bookmark_type, and success status.

        Raises:
            ToolError: If Ghidra is not connected or operation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("bookmark_creating", address=hex(address), category=category, bookmark_type=bookmark_type)
        await self._execute_remote(f"""
            bm = currentProgram.getBookmarkManager()
            bm.setBookmark(toAddr({address}), {json.dumps(bookmark_type)}, {json.dumps(category)}, {json.dumps(comment)})
        """)
        return {"address": hex(address), "category": category, "comment": comment, "bookmark_type": bookmark_type, "success": True}

    async def get_bookmarks(self, category: str | None = None) -> list[dict[str, Any]]:
        """List bookmarks, optionally filtered by category.

        Args:
            category: Optional category filter.

        Returns:
            list[dict[str, Any]]: List of bookmark dicts with address, category, and comment.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        cat_filter = json.dumps(category) if category else "None"
        try:
            result = await self._execute_remote(f"""
                bookmarks = []
                bm = currentProgram.getBookmarkManager()
                cat_filter = {cat_filter}
                it = bm.getBookmarksIterator()
                while it.hasNext():
                    bk = it.next()
                    if cat_filter is None or bk.getCategory() == cat_filter:
                        bookmarks.append({{
                            'address': bk.getAddress().getOffset(),
                            'category': bk.getCategory(),
                            'comment': bk.getComment(),
                            'type': bk.getTypeString(),
                        }})
                bookmarks
            """)
            return cast("list[dict[str, Any]]", result) if result else []
        except Exception:
            _logger.exception("get_bookmarks_failed")
            return []

    async def create_function(self, address: int, name: str | None = None) -> dict[str, Any]:
        """Define a new function at an address.

        Args:
            address: Entry point address.
            name: Optional function name.

        Returns:
            dict[str, Any]: Dict with function info including address and name.

        Raises:
            ToolError: If Ghidra is not connected or function creation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.info("function_creating", address=hex(address), func_name=name)
        name_arg = json.dumps(name) if name else "None"
        try:
            result = await self._execute_remote(f"""
                addr = toAddr({address})
                func = createFunction(addr, {name_arg})
                if func is not None:
                    {{'name': func.getName(), 'address': func.getEntryPoint().getOffset(), 'size': func.getBody().getNumAddresses()}}
                else:
                    None
            """)
        except Exception as e:
            error_message = f"Create function failed: {e}"
            raise ToolError(error_message) from e

        if result is None:
            error_message = f"Failed to create function at {hex(address)}"
            raise ToolError(error_message)
        return cast("dict[str, Any]", result)

    async def delete_function(self, address: int) -> dict[str, Any]:
        """Remove function definition at an address.

        Args:
            address: Function entry point address.

        Returns:
            dict[str, Any]: Dict with address and success status.

        Raises:
            ToolError: If Ghidra is not connected or deletion fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.info("function_deleting", address=hex(address))
        try:
            await self._execute_remote(f"""
                addr = toAddr({address})
                fm = currentProgram.getFunctionManager()
                func = fm.getFunctionAt(addr)
                if func is not None:
                    fm.removeFunction(func.getEntryPoint())
            """)
            return {"address": hex(address), "success": True}
        except Exception as e:
            error_message = f"Delete function failed: {e}"
            raise ToolError(error_message) from e

    async def edit_function_signature(
        self,
        address: int,
        return_type: str | None = None,
        calling_convention: str | None = None,
        name: str | None = None,
    ) -> dict[str, Any]:
        """Modify function return type, calling convention, or name.

        Args:
            address: Function entry point.
            return_type: New return type string.
            calling_convention: New calling convention.
            name: New function name.

        Returns:
            dict[str, Any]: Dict with updated function information.

        Raises:
            ToolError: If Ghidra is not connected or modification fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.info("function_signature_editing", address=hex(address), new_name=name, return_type=return_type)
        rt_literal = json.dumps(return_type) if return_type else "None"
        cc_literal = json.dumps(calling_convention) if calling_convention else "None"
        name_literal = json.dumps(name) if name else "None"

        try:
            result = await self._execute_remote(f"""
                from ghidra.program.model.symbol import SourceType
                from ghidra.app.util.parser import DataTypeParser

                addr = toAddr({address})
                func = getFunctionContaining(addr)
                if func is None:
                    None
                else:
                    rt = {rt_literal}
                    cc = {cc_literal}
                    nm = {name_literal}

                    if rt is not None:
                        dtm = currentProgram.getDataTypeManager()
                        parser = DataTypeParser(dtm)
                        parsed = parser.parse(rt)
                        if parsed is not None:
                            func.setReturnType(parsed, SourceType.USER_DEFINED)

                    if cc is not None:
                        func.setCallingConvention(cc)

                    if nm is not None:
                        func.setName(nm, SourceType.USER_DEFINED)

                    {{
                        'name': func.getName(),
                        'address': func.getEntryPoint().getOffset(),
                        'return_type': str(func.getReturnType()),
                        'calling_convention': func.getCallingConventionName(),
                    }}
            """)
        except Exception as e:
            error_message = f"Edit function signature failed: {e}"
            raise ToolError(error_message) from e

        if result is None:
            error_message = f"No function at {hex(address)}"
            raise ToolError(error_message)
        return cast("dict[str, Any]", result)

    async def set_function_variable_type(self, func_address: int, var_name: str, new_type: str) -> dict[str, Any]:
        """Change the data type of a local variable in a function.

        Args:
            func_address: Function entry address.
            var_name: Name of the variable to retype.
            new_type: New data type name.

        Returns:
            dict[str, Any]: Dict with variable name, new type, and success status.

        Raises:
            ToolError: If Ghidra is not connected or retype fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("variable_type_setting", func_address=hex(func_address), var_name=var_name, new_type=new_type)
        try:
            result = await self._execute_remote(f"""
                from ghidra.program.model.symbol import SourceType
                from ghidra.app.util.parser import DataTypeParser

                addr = toAddr({func_address})
                func = getFunctionContaining(addr)
                found = False
                if func is not None:
                    dtm = currentProgram.getDataTypeManager()
                    parser = DataTypeParser(dtm)
                    parsed = parser.parse({json.dumps(new_type)})
                    if parsed is not None:
                        for var in func.getAllVariables():
                            if var.getName() == {json.dumps(var_name)}:
                                var.setDataType(parsed, SourceType.USER_DEFINED)
                                found = True
                                break
                found
            """)
        except Exception as e:
            error_message = f"Set variable type failed: {e}"
            raise ToolError(error_message) from e

        if not result:
            error_message = f"Variable {var_name!r} not found in function at {hex(func_address)}"
            raise ToolError(error_message)
        return {"var_name": var_name, "new_type": new_type, "success": True}

    async def define_structure(self, name: str, fields: list[dict[str, Any]]) -> dict[str, Any]:
        """Define a new struct data type with named fields.

        Args:
            name: Structure name.
            fields: List of field definitions, each with 'name', 'type', and 'size' keys.

        Returns:
            dict[str, Any]: Dict with structure name, size, and field count.

        Raises:
            ToolError: If Ghidra is not connected or definition fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.info("structure_defining", struct_name=name, field_count=len(fields))
        fields_json = json.dumps(fields)
        try:
            result = await self._execute_remote(f"""
                import json as _json
                from ghidra.program.model.data import StructureDataType, CategoryPath

                fields_data = _json.loads({json.dumps(fields_json)})
                struct = StructureDataType(CategoryPath.ROOT, {json.dumps(name)}, 0)

                type_map = {{
                    'byte': currentProgram.getDataTypeManager().getDataType('/byte'),
                    'word': currentProgram.getDataTypeManager().getDataType('/word'),
                    'dword': currentProgram.getDataTypeManager().getDataType('/dword'),
                    'qword': currentProgram.getDataTypeManager().getDataType('/qword'),
                    'float': currentProgram.getDataTypeManager().getDataType('/float'),
                    'double': currentProgram.getDataTypeManager().getDataType('/double'),
                    'char': currentProgram.getDataTypeManager().getDataType('/char'),
                    'pointer': currentProgram.getDataTypeManager().getDataType('/pointer'),
                }}

                for f in fields_data:
                    ft = type_map.get(f.get('type', 'byte'))
                    if ft is None:
                        from ghidra.app.util.parser import DataTypeParser
                        parser = DataTypeParser(currentProgram.getDataTypeManager())
                        ft = parser.parse(f.get('type', 'byte'))
                    if ft is not None:
                        struct.add(ft, f.get('size', ft.getLength()), f.get('name', ''), '')

                dtm = currentProgram.getDataTypeManager()
                added = dtm.addDataType(struct, None)
                {{'name': added.getName(), 'size': added.getLength(), 'field_count': added.getNumComponents()}}
            """)
            return cast("dict[str, Any]", result) if result else {"name": name, "success": False}
        except Exception as e:
            error_message = f"Define structure failed: {e}"
            raise ToolError(error_message) from e

    async def get_structures(self, filter_name: str | None = None) -> list[dict[str, Any]]:
        """List defined structures, optionally filtered by name.

        Args:
            filter_name: Optional substring filter for structure names.

        Returns:
            list[dict[str, Any]]: List of structure dicts with name, size, and field_count.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        name_filter = json.dumps(filter_name) if filter_name else "None"
        try:
            result = await self._execute_remote(f"""
                structs = []
                name_filter = {name_filter}
                it = currentProgram.getDataTypeManager().getAllStructures()
                while it.hasNext():
                    s = it.next()
                    if name_filter is None or name_filter.lower() in s.getName().lower():
                        structs.append({{
                            'name': s.getName(),
                            'size': s.getLength(),
                            'field_count': s.getNumComponents(),
                            'path': str(s.getCategoryPath()),
                        }})
                structs
            """)
            return cast("list[dict[str, Any]]", result) if result else []
        except Exception:
            _logger.exception("get_structures_failed")
            return []

    async def apply_structure_at(self, address: int, struct_name: str) -> dict[str, Any]:
        """Apply a defined structure type at a memory address.

        Args:
            address: Address to apply the structure at.
            struct_name: Name of the structure type.

        Returns:
            dict[str, Any]: Dict with address, struct_name, and success status.

        Raises:
            ToolError: If Ghidra is not connected or application fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("structure_applying", address=hex(address), struct_name=struct_name)
        try:
            result = await self._execute_remote(f"""
                addr = toAddr({address})
                dtm = currentProgram.getDataTypeManager()
                struct_type = None
                it = dtm.getAllStructures()
                while it.hasNext():
                    s = it.next()
                    if s.getName() == {json.dumps(struct_name)}:
                        struct_type = s
                        break
                if struct_type is not None:
                    listing = currentProgram.getListing()
                    existing = listing.getDataAt(addr)
                    if existing is not None:
                        listing.clearCodeUnits(addr, addr.add(struct_type.getLength() - 1), False)
                    listing.createData(addr, struct_type)
                    True
                else:
                    False
            """)
        except Exception as e:
            error_message = f"Apply structure failed: {e}"
            raise ToolError(error_message) from e

        if not result:
            error_message = f"Structure {struct_name!r} not found"
            raise ToolError(error_message)
        return {"address": hex(address), "struct_name": struct_name, "success": True}

    async def get_memory_map(self) -> list[dict[str, Any]]:
        """Get all memory blocks with addresses, sizes, and permissions.

        Returns:
            list[dict[str, Any]]: List of memory block dicts.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote("""
                blocks = []
                for block in getMemory().getBlocks():
                    blocks.append({
                        'name': block.getName(),
                        'start': block.getStart().getOffset(),
                        'end': block.getEnd().getOffset(),
                        'size': block.getSize(),
                        'read': block.isRead(),
                        'write': block.isWrite(),
                        'execute': block.isExecute(),
                        'initialized': block.isInitialized(),
                        'volatile': block.isVolatile(),
                    })
                blocks
            """)
            return cast("list[dict[str, Any]]", result) if result else []
        except Exception:
            _logger.exception("get_memory_map_failed")
            return []

    async def get_call_graph(self, address: int, depth: int = 2) -> dict[str, Any]:
        """Get function call graph from an address to a specified depth.

        Args:
            address: Root function address.
            depth: Maximum call depth to traverse.

        Returns:
            dict[str, Any]: Dict with call graph tree structure containing callers and callees.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(f"""
                from ghidra.program.model.symbol import RefType

                def build_graph(func_addr, max_depth, current_depth, visited):
                    if current_depth >= max_depth or func_addr in visited:
                        return None
                    visited.add(func_addr)
                    func = getFunctionAt(func_addr)
                    if func is None:
                        return None

                    callees = []
                    for ref in getReferencesFrom(func.getEntryPoint()):
                        if ref.getReferenceType().isCall():
                            target = ref.getToAddress()
                            target_func = getFunctionAt(target)
                            if target_func is not None:
                                child = build_graph(target_func.getEntryPoint(), max_depth, current_depth + 1, visited)
                                callees.append({{
                                    'name': target_func.getName(),
                                    'address': target_func.getEntryPoint().getOffset(),
                                    'callees': child.get('callees', []) if child else [],
                                }})

                    body = func.getBody()
                    addr_iter = body.getAddresses(True)
                    while addr_iter.hasNext():
                        a = addr_iter.next()
                        for ref in getReferencesFrom(a):
                            if ref.getReferenceType().isCall():
                                target = ref.getToAddress()
                                target_func = getFunctionAt(target)
                                if target_func is not None and target_func.getEntryPoint().getOffset() not in [c.get('address') for c in callees]:
                                    child = build_graph(target_func.getEntryPoint(), max_depth, current_depth + 1, visited)
                                    callees.append({{
                                        'name': target_func.getName(),
                                        'address': target_func.getEntryPoint().getOffset(),
                                        'callees': child.get('callees', []) if child else [],
                                    }})

                    return {{
                        'name': func.getName(),
                        'address': func.getEntryPoint().getOffset(),
                        'callees': callees,
                    }}

                root_addr = toAddr({address})
                root_func = getFunctionContaining(root_addr)
                if root_func is not None:
                    build_graph(root_func.getEntryPoint(), {depth}, 0, set())
                else:
                    None
            """)
            if result is None:
                return {"address": hex(address), "callees": [], "callers": []}
            return cast("dict[str, Any]", result)
        except Exception:
            _logger.exception("get_call_graph_failed", address=hex(address))
            return {"address": hex(address), "callees": [], "callers": []}

    async def get_segments(self) -> list[dict[str, Any]]:
        """Get program segments with detailed permissions and attributes.

        Returns:
            list[dict[str, Any]]: List of segment dicts with name, addresses, permissions, and source info.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote("""
                segments = []
                for block in getMemory().getBlocks():
                    segments.append({
                        'name': block.getName(),
                        'start': block.getStart().getOffset(),
                        'end': block.getEnd().getOffset(),
                        'size': block.getSize(),
                        'read': block.isRead(),
                        'write': block.isWrite(),
                        'execute': block.isExecute(),
                        'initialized': block.isInitialized(),
                        'volatile': block.isVolatile(),
                        'type': str(block.getType()),
                        'source_name': block.getSourceName(),
                        'comment': block.getComment() if block.getComment() else '',
                    })
                segments
            """)
            return cast("list[dict[str, Any]]", result) if result else []
        except Exception:
            _logger.exception("get_segments_failed")
            return []

    async def get_program_info(self) -> dict[str, Any]:
        """Get program metadata including language, compiler, and layout info.

        Returns:
            dict[str, Any]: Dict with language, compiler, endianness, pointer_size, image_base,
            and executable_format.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote("""
                lang = currentProgram.getLanguage()
                cs = currentProgram.getCompilerSpec()
                {
                    'name': currentProgram.getName(),
                    'language': str(lang.getLanguageID()),
                    'language_description': str(lang.getLanguageDescription()),
                    'compiler': str(cs.getCompilerSpecID()),
                    'endianness': str(lang.isBigEndian() and 'big' or 'little'),
                    'pointer_size': lang.getDefaultSpace().getPointerSize(),
                    'address_size': lang.getDefaultSpace().getSize(),
                    'image_base': currentProgram.getImageBase().getOffset(),
                    'executable_format': currentProgram.getExecutableFormat(),
                    'executable_path': currentProgram.getExecutablePath(),
                    'num_functions': currentProgram.getFunctionManager().getFunctionCount(),
                    'num_symbols': currentProgram.getSymbolTable().getNumSymbols(),
                }
            """)
            return cast("dict[str, Any]", result) if result else {}
        except Exception:
            _logger.exception("get_program_info_failed")
            return {}

    async def write_bytes(self, address: int, data: str) -> dict[str, Any]:
        """Patch bytes at an address in the program.

        Args:
            address: Address to write at.
            data: Hex string of bytes (e.g. '90 90 90' or '909090').

        Returns:
            dict[str, Any]: Dict with address and bytes_written count.

        Raises:
            ToolError: If Ghidra is not connected or write fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("bytes_writing", address=hex(address), data_length=len(data.replace(" ", "")) // 2)
        clean_hex = data.replace(" ", "")
        byte_values = [int(clean_hex[i : i + 2], 16) for i in range(0, len(clean_hex), 2)]
        byte_list_str = ", ".join(str(b) for b in byte_values)

        try:
            await self._execute_remote(f"""
                from jarray import array
                addr = toAddr({address})
                data = array([{byte_list_str}], 'b')
                currentProgram.getMemory().setBytes(addr, data)
            """)
            return {"address": hex(address), "bytes_written": len(byte_values), "success": True}
        except Exception as e:
            error_message = f"Write bytes failed: {e}"
            raise ToolError(error_message) from e

    async def read_bytes(self, address: int, length: int) -> dict[str, Any]:
        """Read bytes from an address in the program.

        Args:
            address: Address to read from.
            length: Number of bytes to read.

        Returns:
            dict[str, Any]: Dict with address, hex string, bytes list, and length.

        Raises:
            ToolError: If Ghidra is not connected or read fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("bytes_reading", address=hex(address), length=length)
        try:
            result = await self._execute_remote(f"""
                from jarray import zeros
                addr = toAddr({address})
                buf = zeros({length}, 'b')
                currentProgram.getMemory().getBytes(addr, buf)
                result = []
                for b in buf:
                    result.append((b + 256) % 256)
                {{'address': addr.getOffset(), 'bytes': result}}
            """)
            result_dict = cast("dict[str, Any]", result) if isinstance(result, dict) else {}
            addr_int = int(result_dict.get("address", address))
            byte_list = [int(b) for b in cast("list[int]", result_dict.get("bytes", []))]
            return {
                "address": hex(addr_int),
                "hex": " ".join(f"{b:02X}" for b in byte_list),
                "bytes": byte_list,
                "length": len(byte_list),
            }
        except Exception as e:
            error_message = f"Read bytes failed: {e}"
            raise ToolError(error_message) from e

    async def undo(self) -> dict[str, Any]:
        """Undo the last change in Ghidra.

        Returns:
            dict[str, Any]: Dict with success status.

        Raises:
            ToolError: If Ghidra is not connected or undo fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("undo_requested")
        try:
            result = await self._execute_remote("""
                currentProgram.undo()
                True
            """)
            _logger.debug("undo_performed", success=bool(result))
            return {"success": bool(result)}
        except Exception as e:
            error_message = f"Undo failed: {e}"
            raise ToolError(error_message) from e

    async def redo(self) -> dict[str, Any]:
        """Redo the last undone change in Ghidra.

        Returns:
            dict[str, Any]: Dict with success status.

        Raises:
            ToolError: If Ghidra is not connected or redo fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("redo_requested")
        try:
            result = await self._execute_remote("""
                currentProgram.redo()
                True
            """)
            _logger.debug("redo_performed", success=bool(result))
            return {"success": bool(result)}
        except Exception as e:
            error_message = f"Redo failed: {e}"
            raise ToolError(error_message) from e

    async def get_pcode(self, address: int, max_ops: int = 500) -> dict[str, Any]:
        """Get P-code IR operations for the function at an address.

        Args:
            address: Address within the function to decompile.
            max_ops: Maximum number of P-code ops to return.

        Returns:
            dict[str, Any]: Dict with function name and list of P-code operation dicts.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("pcode_fetching", address=hex(address), max_ops=max_ops)
        try:
            result = await self._execute_remote(f"""
                from ghidra.app.decompiler import DecompInterface

                ifc = DecompInterface()
                ifc.openProgram(currentProgram)
                addr = toAddr({address})
                func = getFunctionContaining(addr)
                if func is None:
                    {{'function': None, 'pcode_ops': []}}
                else:
                    res = ifc.decompileFunction(func, 60, monitor)
                    if not res.decompileCompleted():
                        {{'function': func.getName(), 'pcode_ops': []}}
                    else:
                        hfunc = res.getHighFunction()
                        ops = []
                        count = 0
                        op_iter = hfunc.getPcodeOps()
                        while op_iter.hasNext() and count < {max_ops}:
                            op = op_iter.next()
                            out_vn = op.getOutput()
                            if out_vn is not None:
                                out_dict = {{
                                    'space': out_vn.getAddress().getAddressSpace().getName(),
                                    'offset': out_vn.getAddress().getOffset(),
                                    'size': out_vn.getSize(),
                                }}
                            else:
                                out_dict = None
                            inputs = []
                            for i in range(op.getNumInputs()):
                                ivn = op.getInput(i)
                                inputs.append({{
                                    'space': ivn.getAddress().getAddressSpace().getName(),
                                    'offset': ivn.getAddress().getOffset(),
                                    'size': ivn.getSize(),
                                }})
                            ops.append({{
                                'address': op.getSeqnum().getTarget().getOffset(),
                                'opcode': int(op.getOpcode()),
                                'mnemonic': op.getMnemonic(),
                                'output': out_dict,
                                'inputs': inputs,
                            }})
                            count += 1
                        {{'function': func.getName(), 'pcode_ops': ops}}
            """)
            return cast("dict[str, Any]", result) if isinstance(result, dict) else {"function": None, "pcode_ops": []}
        except Exception:
            _logger.exception("get_pcode_failed", address=hex(address))
            return {"function": None, "pcode_ops": []}

    async def get_basic_blocks(self, address: int, max_blocks: int = 100) -> dict[str, Any]:
        """Get basic block structure of the function at an address.

        Args:
            address: Address within the function.
            max_blocks: Maximum number of blocks to return.

        Returns:
            dict[str, Any]: Dict with function name and list of basic block dicts.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("basic_blocks_fetching", address=hex(address), max_blocks=max_blocks)
        try:
            result = await self._execute_remote(f"""
                from ghidra.program.model.block import BasicBlockModel

                addr = toAddr({address})
                func = getFunctionContaining(addr)
                if func is None:
                    {{'function': None, 'blocks': []}}
                else:
                    bbm = BasicBlockModel(currentProgram)
                    blocks = []
                    count = 0
                    it = bbm.getCodeBlocksContaining(addr, monitor)
                    func_body = func.getBody()
                    addr_iter = func_body.getAddressRanges()
                    block_set = []
                    while addr_iter.hasNext() and count < {max_blocks}:
                        rng = addr_iter.next()
                        blk_it = bbm.getCodeBlocksContaining(rng.getMinAddress(), monitor)
                        while blk_it.hasNext() and count < {max_blocks}:
                            blk = blk_it.next()
                            src_addrs = []
                            src_it = blk.getSources(monitor)
                            while src_it.hasNext():
                                src_ref = src_it.next()
                                src_addrs.append(src_ref.getSourceAddress().getOffset())
                            dst_addrs = []
                            dst_it = blk.getDestinations(monitor)
                            while dst_it.hasNext():
                                dst_ref = dst_it.next()
                                dst_addrs.append(dst_ref.getDestinationAddress().getOffset())
                            blk_start = blk.getMinAddress().getOffset()
                            if blk_start not in [b.get('start') for b in blocks]:
                                blocks.append({{
                                    'start': blk_start,
                                    'end': blk.getMaxAddress().getOffset(),
                                    'sources': src_addrs,
                                    'destinations': dst_addrs,
                                }})
                                count += 1
                    {{'function': func.getName(), 'blocks': blocks}}
            """)
            return cast("dict[str, Any]", result) if isinstance(result, dict) else {"function": None, "blocks": []}
        except Exception:
            _logger.exception("get_basic_blocks_failed", address=hex(address))
            return {"function": None, "blocks": []}

    async def get_slice(self, address: int, direction: str = "backward") -> dict[str, Any]:
        """Compute a backward or forward program slice from an address.

        Args:
            address: Slice origin address.
            direction: Slice direction, either 'backward' or 'forward'.

        Returns:
            dict[str, Any]: Dict with address, direction, slice_addresses, and slice_pcode_ops.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("slice_computing", address=hex(address), direction=direction)
        direction_literal = json.dumps(direction)
        try:
            result = await self._execute_remote(f"""
                from ghidra.app.decompiler import DecompInterface

                ifc = DecompInterface()
                ifc.openProgram(currentProgram)
                addr = toAddr({address})
                func = getFunctionContaining(addr)
                if func is None:
                    {{'address': {address}, 'direction': {direction_literal}, 'slice_addresses': [], 'slice_pcode_ops': []}}
                else:
                    res = ifc.decompileFunction(func, 60, monitor)
                    if not res.decompileCompleted():
                        {{'address': {address}, 'direction': {direction_literal}, 'slice_addresses': [], 'slice_pcode_ops': []}}
                    else:
                        hfunc = res.getHighFunction()
                        target_op = None
                        op_iter = hfunc.getPcodeOps(addr)
                        if op_iter.hasNext():
                            target_op = op_iter.next()

                        slice_ops = []
                        visited_keys = set()

                        def collect_backward(op, depth):
                            if op is None or depth > 50:
                                return
                            key = str(op.getSeqnum())
                            if key in visited_keys:
                                return
                            visited_keys.add(key)
                            slice_ops.append({{
                                'address': op.getSeqnum().getTarget().getOffset(),
                                'opcode': int(op.getOpcode()),
                                'mnemonic': op.getMnemonic(),
                            }})
                            for i in range(op.getNumInputs()):
                                vn = op.getInput(i)
                                if vn is not None:
                                    def_op = vn.getDef()
                                    if def_op is not None:
                                        collect_backward(def_op, depth + 1)

                        def collect_forward(op, depth):
                            if op is None or depth > 50:
                                return
                            key = str(op.getSeqnum())
                            if key in visited_keys:
                                return
                            visited_keys.add(key)
                            slice_ops.append({{
                                'address': op.getSeqnum().getTarget().getOffset(),
                                'opcode': int(op.getOpcode()),
                                'mnemonic': op.getMnemonic(),
                            }})
                            out_vn = op.getOutput()
                            if out_vn is not None:
                                desc_iter = out_vn.getDescendants()
                                while desc_iter.hasNext():
                                    collect_forward(desc_iter.next(), depth + 1)

                        if {direction_literal} == 'backward':
                            collect_backward(target_op, 0)
                        else:
                            collect_forward(target_op, 0)

                        slice_addrs = list(set(op['address'] for op in slice_ops))
                        {{'address': {address}, 'direction': {direction_literal}, 'slice_addresses': slice_addrs, 'slice_pcode_ops': slice_ops}}
            """)
            return (
                cast("dict[str, Any]", result)
                if isinstance(result, dict)
                else {"address": hex(address), "direction": direction, "slice_addresses": [], "slice_pcode_ops": []}
            )
        except Exception:
            _logger.exception("get_slice_failed", address=hex(address))
            return {"address": hex(address), "direction": direction, "slice_addresses": [], "slice_pcode_ops": []}

    async def get_callers(self, address: int) -> list[dict[str, Any]]:
        """Get all functions that call the function at the given address.

        Args:
            address: Callee function address.

        Returns:
            list[dict[str, Any]]: List of caller dicts with caller_address, caller_function, call_site, and ref_type.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("callers_fetching", address=hex(address))
        try:
            result = await self._execute_remote(f"""
                callers = []
                addr = toAddr({address})
                for ref in getReferencesTo(addr):
                    if ref.getReferenceType().isCall():
                        from_addr = ref.getFromAddress()
                        caller_func = getFunctionContaining(from_addr)
                        callers.append({{
                            'caller_address': caller_func.getEntryPoint().getOffset() if caller_func else None,
                            'caller_function': caller_func.getName() if caller_func else None,
                            'call_site': from_addr.getOffset(),
                            'ref_type': str(ref.getReferenceType()),
                        }})
                callers
            """)
            return cast("list[dict[str, Any]]", result) if result else []
        except Exception:
            _logger.exception("get_callers_failed", address=hex(address))
            return []

    async def get_register_value(self, address: int, register: str) -> dict[str, Any]:
        """Get the context-tracked register value at an address.

        Args:
            address: Address to query.
            register: Register name (e.g. EAX, RSP).

        Returns:
            dict[str, Any]: Dict with address, register name, value, and has_value flag.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("register_value_fetching", address=hex(address), register=register)
        register_literal = json.dumps(register)
        try:
            result = await self._execute_remote(f"""
                addr = toAddr({address})
                ctx = currentProgram.getProgramContext()
                reg = ctx.getRegister({register_literal})
                if reg is None:
                    {{'address': {address}, 'register': {register_literal}, 'value': None, 'has_value': False}}
                else:
                    val = ctx.getRegisterValue(reg, addr)
                    if val is None:
                        {{'address': {address}, 'register': {register_literal}, 'value': None, 'has_value': False}}
                    else:
                        uval = val.getUnsignedValue()
                        {{'address': {address}, 'register': {register_literal}, 'value': int(uval) if uval is not None else None, 'has_value': uval is not None}}
            """)
            return (
                cast("dict[str, Any]", result)
                if isinstance(result, dict)
                else {"address": hex(address), "register": register, "value": None, "has_value": False}
            )
        except Exception:
            _logger.exception("get_register_value_failed", address=hex(address), register=register)
            return {"address": hex(address), "register": register, "value": None, "has_value": False}

    async def import_debug_info(self, path: str) -> dict[str, Any]:
        """Import debug symbols from a PDB or DWARF file.

        Args:
            path: Path to the .pdb or .debug file.

        Returns:
            dict[str, Any]: Dict with path, success, and debug info type.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.info("debug_info_importing", path=path)
        path_literal = json.dumps(path)
        try:
            result = await self._execute_remote(f"""
                import os as _os
                debug_path = {path_literal}
                ext = _os.path.splitext(debug_path)[1].lower()
                success = False
                debug_type = 'unknown'

                if ext == '.pdb':
                    debug_type = 'pdb'
                    try:
                        from ghidra.app.plugin.core.analysis import PdbAnalyzer
                        from ghidra.util.task import TaskMonitor
                        opts = currentProgram.getOptions('Analyzers')
                        opts.setString('PDB Universal/Apply PDB File', debug_path)
                        mgr = currentProgram.getUsrPropertyManager()
                        from ghidra.app.services import AutoAnalysisManager
                        aam = AutoAnalysisManager.getAnalysisManager(currentProgram)
                        aam.reAnalyzeAll(None)
                        success = True
                    except Exception as _e:
                        success = False
                elif ext in ('.debug', '.dwarf', '.dbg'):
                    debug_type = 'dwarf'
                    try:
                        from ghidra.app.services import AutoAnalysisManager
                        aam = AutoAnalysisManager.getAnalysisManager(currentProgram)
                        aam.reAnalyzeAll(None)
                        success = True
                    except Exception as _e:
                        success = False

                {{'path': debug_path, 'success': success, 'type': debug_type}}
            """)
            return cast("dict[str, Any]", result) if isinstance(result, dict) else {"path": path, "success": False, "type": "unknown"}
        except Exception:
            _logger.exception("import_debug_info_failed", path=path)
            return {"path": path, "success": False, "type": "unknown"}

    async def add_reference(self, from_addr: int, to_addr: int, ref_type: str = "DATA") -> dict[str, Any]:
        """Add a memory reference between two addresses.

        Args:
            from_addr: Source address.
            to_addr: Destination address.
            ref_type: Reference type string (DATA, READ, WRITE, CALL, UNCONDITIONAL_JUMP, CONDITIONAL_JUMP).

        Returns:
            dict[str, Any]: Dict with from, to, type, and success.

        Raises:
            ToolError: If Ghidra is not connected or operation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("reference_adding", from_addr=hex(from_addr), to_addr=hex(to_addr), ref_type=ref_type)
        ref_type_literal = json.dumps(ref_type)
        try:
            await self._execute_remote(f"""
                from ghidra.program.model.symbol import RefType, SourceType

                from_address = toAddr({from_addr})
                to_address = toAddr({to_addr})
                ref_type_str = {ref_type_literal}

                ref_type_map = {{
                    'DATA': RefType.DATA,
                    'READ': RefType.READ,
                    'WRITE': RefType.WRITE,
                    'CALL': RefType.UNCONDITIONAL_CALL,
                    'UNCONDITIONAL_JUMP': RefType.UNCONDITIONAL_JUMP,
                    'CONDITIONAL_JUMP': RefType.CONDITIONAL_JUMP,
                }}
                rt = ref_type_map.get(ref_type_str, RefType.DATA)
                refMgr = currentProgram.getReferenceManager()
                refMgr.addMemoryReference(from_address, to_address, rt, SourceType.USER_DEFINED, 0)
            """)
            return {"from": hex(from_addr), "to": hex(to_addr), "type": ref_type, "success": True}
        except Exception as e:
            error_message = f"Add reference failed: {e}"
            raise ToolError(error_message) from e

    async def delete_reference(self, from_addr: int, to_addr: int) -> dict[str, Any]:
        """Delete a memory reference between two addresses.

        Args:
            from_addr: Source address.
            to_addr: Destination address.

        Returns:
            dict[str, Any]: Dict with from, to, and success.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("reference_deleting", from_addr=hex(from_addr), to_addr=hex(to_addr))
        try:
            result = await self._execute_remote(f"""
                from_address = toAddr({from_addr})
                to_address = toAddr({to_addr})
                refMgr = currentProgram.getReferenceManager()
                refs = refMgr.getReferencesFrom(from_address)
                deleted = False
                for ref in refs:
                    if ref.getToAddress().equals(to_address):
                        refMgr.delete(ref)
                        deleted = True
                        break
                deleted
            """)
            return {"from": hex(from_addr), "to": hex(to_addr), "success": bool(result)}
        except Exception:
            _logger.exception("delete_reference_failed", from_addr=hex(from_addr), to_addr=hex(to_addr))
            return {"from": hex(from_addr), "to": hex(to_addr), "success": False}

    async def get_relocations(self) -> list[dict[str, Any]]:
        """Get all relocations from the program relocation table.

        Returns:
            list[dict[str, Any]]: List of relocation dicts with address, type, symbol, and values.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote("""
                relocations = []
                reloc_table = currentProgram.getRelocationTable()
                it = reloc_table.getRelocations()
                while it.hasNext():
                    reloc = it.next()
                    sym_name = reloc.getSymbolName() if reloc.getSymbolName() else ''
                    vals = list(reloc.getValues()) if reloc.getValues() else []
                    relocations.append({
                        'address': reloc.getAddress().getOffset(),
                        'type': int(reloc.getType()),
                        'symbol': sym_name,
                        'values': vals,
                    })
                relocations
            """)
            return cast("list[dict[str, Any]]", result) if result else []
        except Exception:
            _logger.exception("get_relocations_failed")
            return []

    async def create_namespace(self, name: str, parent: str | None = None) -> dict[str, Any]:
        """Create a namespace in the Ghidra symbol table.

        Args:
            name: Namespace name.
            parent: Parent namespace path, or None for global.

        Returns:
            dict[str, Any]: Dict with name, path, and success.

        Raises:
            ToolError: If Ghidra is not connected or operation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("namespace_creating", namespace_name=name, parent=parent)
        parent_literal = json.dumps(parent) if parent else "None"
        try:
            result = await self._execute_remote(f"""
                from ghidra.program.model.symbol import SourceType

                st = currentProgram.getSymbolTable()
                parent_path = {parent_literal}
                if parent_path is not None:
                    parent_ns = st.getNamespace(parent_path, currentProgram.getGlobalNamespace())
                    if parent_ns is None:
                        parent_ns = currentProgram.getGlobalNamespace()
                else:
                    parent_ns = currentProgram.getGlobalNamespace()

                ns = st.createNameSpace(parent_ns, {json.dumps(name)}, SourceType.USER_DEFINED)
                {{'name': ns.getName(), 'path': ns.getName(True), 'success': True}}
            """)
            return cast("dict[str, Any]", result) if isinstance(result, dict) else {"name": name, "path": name, "success": False}
        except Exception as e:
            error_message = f"Create namespace failed: {e}"
            raise ToolError(error_message) from e

    async def get_namespaces(self) -> list[dict[str, Any]]:
        """List all namespaces defined in the program.

        Returns:
            list[dict[str, Any]]: List of namespace dicts with name and path.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote("""
                from ghidra.program.model.symbol import SymbolType

                namespaces = []
                st = currentProgram.getSymbolTable()
                for sym in st.getAllSymbols(True):
                    if sym.getSymbolType() == SymbolType.NAMESPACE:
                        namespaces.append({
                            'name': sym.getName(),
                            'path': sym.getName(True),
                        })
                namespaces
            """)
            return cast("list[dict[str, Any]]", result) if result else []
        except Exception:
            _logger.exception("get_namespaces_failed")
            return []

    async def create_equate(self, address: int, value: int, name: str) -> dict[str, Any]:
        """Create an equate (named constant) and attach it to an address.

        Args:
            address: Address of the scalar operand.
            value: Numeric value of the equate.
            name: Equate name.

        Returns:
            dict[str, Any]: Dict with name, value, address, and success.

        Raises:
            ToolError: If Ghidra is not connected or operation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("equate_creating", equate_name=name, value=value, address=hex(address))
        try:
            await self._execute_remote(f"""
                addr = toAddr({address})
                eqTable = currentProgram.getEquateTable()
                existing = eqTable.getEquate({json.dumps(name)})
                if existing is None:
                    eq = eqTable.createEquate({json.dumps(name)}, {value})
                else:
                    eq = existing
                eq.addReference(addr, 0)
            """)
            return {"name": name, "value": value, "address": hex(address), "success": True}
        except Exception as e:
            error_message = f"Create equate failed: {e}"
            raise ToolError(error_message) from e

    async def get_equates(self) -> list[dict[str, Any]]:
        """List all equates defined in the program.

        Returns:
            list[dict[str, Any]]: List of equate dicts with name, value, and reference count.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote("""
                equates = []
                eqTable = currentProgram.getEquateTable()
                it = eqTable.getEquates()
                while it.hasNext():
                    eq = it.next()
                    equates.append({
                        'name': eq.getName(),
                        'value': int(eq.getValue()),
                        'references': eq.getReferenceCount(),
                    })
                equates
            """)
            return cast("list[dict[str, Any]]", result) if result else []
        except Exception:
            _logger.exception("get_equates_failed")
            return []

    async def search_symbols(self, name: str, symbol_type: str | None = None) -> list[dict[str, Any]]:
        """Search symbols by name pattern with optional type filter.

        Args:
            name: Symbol name pattern.
            symbol_type: Optional symbol type filter (e.g. FUNCTION, LABEL).

        Returns:
            list[dict[str, Any]]: List of symbol dicts with name, address, type, and namespace.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        type_filter_literal = json.dumps(symbol_type) if symbol_type else "None"
        try:
            result = await self._execute_remote(f"""
                st = currentProgram.getSymbolTable()
                type_filter = {type_filter_literal}
                symbols = []
                it = st.getSymbolIterator({json.dumps(name)}, True)
                while it.hasNext():
                    sym = it.next()
                    sym_type_str = str(sym.getSymbolType())
                    if type_filter is not None and sym_type_str != type_filter:
                        continue
                    symbols.append({{
                        'name': sym.getName(),
                        'address': sym.getAddress().getOffset(),
                        'type': sym_type_str,
                        'namespace': sym.getParentNamespace().getName() if sym.getParentNamespace() else '',
                    }})
                symbols
            """)
            return cast("list[dict[str, Any]]", result) if result else []
        except Exception:
            _logger.exception("search_symbols_failed", symbol_name=name)
            return []

    async def get_stack_frame(self, address: int) -> dict[str, Any]:
        """Get stack frame layout for the function at an address.

        Args:
            address: Address within the function.

        Returns:
            dict[str, Any]: Dict with function name, frame_size, and list of stack variable dicts.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("stack_frame_fetching", address=hex(address))
        try:
            result = await self._execute_remote(f"""
                addr = toAddr({address})
                func = getFunctionContaining(addr)
                if func is None:
                    {{'function': None, 'frame_size': 0, 'variables': []}}
                else:
                    frame = func.getStackFrame()
                    vars = []
                    for v in frame.getStackVariables():
                        vars.append({{
                            'name': v.getName(),
                            'offset': v.getStackOffset(),
                            'size': v.getLength(),
                            'type': str(v.getDataType()),
                        }})
                    {{'function': func.getName(), 'frame_size': frame.getFrameSize(), 'variables': vars}}
            """)
            return cast("dict[str, Any]", result) if isinstance(result, dict) else {"function": None, "frame_size": 0, "variables": []}
        except Exception:
            _logger.exception("get_stack_frame_failed", address=hex(address))
            return {"function": None, "frame_size": 0, "variables": []}

    async def get_function_body(self, address: int) -> dict[str, Any]:
        """Get address ranges, thunk status, and size for a function.

        Args:
            address: Address within the function.

        Returns:
            dict[str, Any]: Dict with name, address, is_thunk, thunked_function, ranges, and total_size.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("function_body_fetching", address=hex(address))
        try:
            result = await self._execute_remote(f"""
                addr = toAddr({address})
                func = getFunctionContaining(addr)
                if func is None:
                    {{'name': None, 'address': {address}, 'is_thunk': False, 'thunked_function': None, 'ranges': [], 'total_size': 0}}
                else:
                    is_thunk = func.isThunk()
                    thunked_name = None
                    if is_thunk:
                        thunked = func.getThunkedFunction(False)
                        if thunked is not None:
                            thunked_name = thunked.getName()
                    body = func.getBody()
                    ranges = []
                    addr_ranges = body.getAddressRanges()
                    while addr_ranges.hasNext():
                        rng = addr_ranges.next()
                        ranges.append({{'start': rng.getMinAddress().getOffset(), 'end': rng.getMaxAddress().getOffset()}})
                    total = body.getNumAddresses()
                    {{'name': func.getName(), 'address': func.getEntryPoint().getOffset(), 'is_thunk': bool(is_thunk), 'thunked_function': thunked_name, 'ranges': ranges, 'total_size': total}}
            """)
            return (
                cast("dict[str, Any]", result)
                if isinstance(result, dict)
                else {"name": None, "address": hex(address), "is_thunk": False, "thunked_function": None, "ranges": [], "total_size": 0}
            )
        except Exception:
            _logger.exception("get_function_body_failed", address=hex(address))
            return {"name": None, "address": hex(address), "is_thunk": False, "thunked_function": None, "ranges": [], "total_size": 0}

    async def get_call_tree(self, address: int, direction: str = "callees", depth: int = 3) -> dict[str, Any]:
        """Get recursive call tree for callees, callers, or both.

        Args:
            address: Root function address.
            direction: Tree direction: 'callees', 'callers', or 'both'.
            depth: Maximum recursion depth.

        Returns:
            dict[str, Any]: Recursive call tree dict with function, address, direction, and children.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("call_tree_building", address=hex(address), direction=direction, depth=depth)
        direction_literal = json.dumps(direction)
        try:
            result = await self._execute_remote(f"""
                def get_callee_tree(func, max_depth, cur_depth, visited):
                    if cur_depth >= max_depth or func.getEntryPoint().getOffset() in visited:
                        return {{'function': func.getName(), 'address': func.getEntryPoint().getOffset(), 'children': []}}
                    visited.add(func.getEntryPoint().getOffset())
                    children = []
                    body = func.getBody()
                    addr_iter = body.getAddresses(True)
                    seen = set()
                    while addr_iter.hasNext():
                        a = addr_iter.next()
                        for ref in getReferencesFrom(a):
                            if ref.getReferenceType().isCall():
                                t = ref.getToAddress()
                                tf = getFunctionAt(t)
                                if tf is not None and t.getOffset() not in seen:
                                    seen.add(t.getOffset())
                                    children.append(get_callee_tree(tf, max_depth, cur_depth + 1, set(visited)))
                    return {{'function': func.getName(), 'address': func.getEntryPoint().getOffset(), 'children': children}}

                def get_caller_tree(func, max_depth, cur_depth, visited):
                    if cur_depth >= max_depth or func.getEntryPoint().getOffset() in visited:
                        return {{'function': func.getName(), 'address': func.getEntryPoint().getOffset(), 'children': []}}
                    visited.add(func.getEntryPoint().getOffset())
                    children = []
                    seen = set()
                    for ref in getReferencesTo(func.getEntryPoint()):
                        if ref.getReferenceType().isCall():
                            cf = getFunctionContaining(ref.getFromAddress())
                            if cf is not None and cf.getEntryPoint().getOffset() not in seen:
                                seen.add(cf.getEntryPoint().getOffset())
                                children.append(get_caller_tree(cf, max_depth, cur_depth + 1, set(visited)))
                    return {{'function': func.getName(), 'address': func.getEntryPoint().getOffset(), 'children': children}}

                addr = toAddr({address})
                func = getFunctionContaining(addr)
                direction = {direction_literal}
                if func is None:
                    {{'function': None, 'address': {address}, 'direction': direction, 'children': []}}
                else:
                    if direction == 'callees':
                        get_callee_tree(func, {depth}, 0, set())
                    elif direction == 'callers':
                        get_caller_tree(func, {depth}, 0, set())
                    else:
                        callees = get_callee_tree(func, {depth}, 0, set())
                        callers = get_caller_tree(func, {depth}, 0, set())
                        {{'function': func.getName(), 'address': func.getEntryPoint().getOffset(), 'direction': direction, 'callees': callees.get('children', []), 'callers': callers.get('children', [])}}
            """)
            return (
                cast("dict[str, Any]", result)
                if isinstance(result, dict)
                else {"function": None, "address": hex(address), "direction": direction, "children": []}
            )
        except Exception:
            _logger.exception("get_call_tree_failed", address=hex(address))
            return {"function": None, "address": hex(address), "direction": direction, "children": []}

    async def get_calling_conventions(self) -> list[str]:
        """List all calling conventions defined in the compiler spec.

        Returns:
            list[str]: List of calling convention name strings.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote("""
                cs = currentProgram.getCompilerSpec()
                conventions = [str(cc.getName()) for cc in cs.getCallingConventions()]
                conventions
            """)
        except Exception:
            _logger.exception("get_calling_conventions_failed")
            return []
        else:
            if isinstance(result, list):
                return [str(c) for c in cast("list[object]", result)]
            return []

    async def get_instruction_flow(self, address: int) -> dict[str, Any]:
        """Get control flow information for a single instruction.

        Args:
            address: Instruction address.

        Returns:
            dict[str, Any]: Dict with address, mnemonic, flow_type, fall_through, and flows.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("instruction_flow_fetching", address=hex(address))
        try:
            result = await self._execute_remote(f"""
                addr = toAddr({address})
                listing = currentProgram.getListing()
                instr = listing.getInstructionAt(addr)
                if instr is None:
                    {{'address': {address}, 'mnemonic': None, 'flow_type': None, 'fall_through': None, 'flows': []}}
                else:
                    ft = instr.getFallThrough()
                    flows = [f.getOffset() for f in (instr.getFlows() or [])]
                    {{'address': addr.getOffset(), 'mnemonic': instr.getMnemonicString(), 'flow_type': str(instr.getFlowType()), 'fall_through': ft.getOffset() if ft is not None else None, 'flows': flows}}
            """)
            return (
                cast("dict[str, Any]", result)
                if isinstance(result, dict)
                else {"address": hex(address), "mnemonic": None, "flow_type": None, "fall_through": None, "flows": []}
            )
        except Exception:
            _logger.exception("get_instruction_flow_failed", address=hex(address))
            return {"address": hex(address), "mnemonic": None, "flow_type": None, "fall_through": None, "flows": []}

    async def create_data_type(
        self,
        category: str,
        name: str,
        type_kind: str,
        fields: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Create a new data type in the type manager.

        Args:
            category: Category path (e.g. /MyTypes).
            name: Data type name.
            type_kind: Kind of data type: enum, union, typedef, or function_def.
            fields: Field definitions for enum/union (list of dicts with name and value/type/size).

        Returns:
            dict[str, Any]: Dict with name, kind, size, and success.

        Raises:
            ToolError: If Ghidra is not connected or type creation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.info("data_type_creating", type_name=name, type_kind=type_kind, category=category)
        fields_json = json.dumps(fields or [])
        try:
            result = await self._execute_remote(f"""
                import json as _json
                from ghidra.program.model.data import CategoryPath, EnumDataType, UnionDataType, TypedefDataType

                cat_path = CategoryPath({json.dumps(category)})
                dtm = currentProgram.getDataTypeManager()
                type_kind = {json.dumps(type_kind)}
                fields_data = _json.loads({json.dumps(fields_json)})
                created = None

                if type_kind == 'enum':
                    enum_dt = EnumDataType(cat_path, {json.dumps(name)}, 4)
                    for f in fields_data:
                        enum_dt.add(f.get('name', ''), int(f.get('value', 0)))
                    created = dtm.addDataType(enum_dt, None)
                elif type_kind == 'union':
                    union_dt = UnionDataType(cat_path, {json.dumps(name)})
                    for f in fields_data:
                        from ghidra.app.util.parser import DataTypeParser
                        parser = DataTypeParser(dtm)
                        ft = parser.parse(f.get('type', 'byte'))
                        if ft is not None:
                            union_dt.add(ft, f.get('size', ft.getLength()), f.get('name', ''), '')
                    created = dtm.addDataType(union_dt, None)
                elif type_kind == 'typedef':
                    base_name = fields_data[0].get('type', 'dword') if fields_data else 'dword'
                    from ghidra.app.util.parser import DataTypeParser
                    parser = DataTypeParser(dtm)
                    base_dt = parser.parse(base_name)
                    if base_dt is not None:
                        typedef_dt = TypedefDataType(cat_path, {json.dumps(name)}, base_dt)
                        created = dtm.addDataType(typedef_dt, None)
                elif type_kind == 'function_def':
                    from ghidra.program.model.data import FunctionDefinitionDataType
                    func_def = FunctionDefinitionDataType(cat_path, {json.dumps(name)})
                    created = dtm.addDataType(func_def, None)

                if created is not None:
                    {{'name': created.getName(), 'kind': type_kind, 'size': int(created.getLength()), 'success': True}}
                else:
                    {{'name': {json.dumps(name)}, 'kind': type_kind, 'size': 0, 'success': False}}
            """)
            return (
                cast("dict[str, Any]", result)
                if isinstance(result, dict)
                else {"name": name, "kind": type_kind, "size": 0, "success": False}
            )
        except Exception as e:
            error_message = f"Create data type failed: {e}"
            raise ToolError(error_message) from e

    async def create_data(self, address: int, data_type: str) -> dict[str, Any]:
        """Create a data item at an address using a named data type.

        Args:
            address: Address to create data at.
            data_type: Data type name.

        Returns:
            dict[str, Any]: Dict with address, type, size, and success.

        Raises:
            ToolError: If Ghidra is not connected or creation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("data_creating", address=hex(address), data_type=data_type)
        try:
            result = await self._execute_remote(f"""
                from ghidra.app.util.parser import DataTypeParser

                addr = toAddr({address})
                listing = currentProgram.getListing()
                dtm = currentProgram.getDataTypeManager()
                parser = DataTypeParser(dtm)
                parsed = parser.parse({json.dumps(data_type)})
                if parsed is None:
                    {{'address': {address}, 'type': {json.dumps(data_type)}, 'size': 0, 'success': False}}
                else:
                    existing = listing.getDataAt(addr)
                    if existing is not None:
                        listing.clearCodeUnits(addr, addr.add(parsed.getLength() - 1), False)
                    created = listing.createData(addr, parsed)
                    {{'address': addr.getOffset(), 'type': {json.dumps(data_type)}, 'size': int(created.getLength()), 'success': True}}
            """)
            return (
                cast("dict[str, Any]", result)
                if isinstance(result, dict)
                else {"address": hex(address), "type": data_type, "size": 0, "success": False}
            )
        except Exception as e:
            error_message = f"Create data failed: {e}"
            raise ToolError(error_message) from e

    async def configure_analysis(
        self,
        analyzer_name: str,
        *,
        enabled: bool,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Enable or disable a Ghidra analyzer and optionally set options.

        Args:
            analyzer_name: Analyzer name.
            enabled: Whether to enable or disable the analyzer.
            options: Optional dict of analyzer option overrides.

        Returns:
            dict[str, Any]: Dict with analyzer, enabled, and success.

        Raises:
            ToolError: If Ghidra is not connected or configuration fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.info("analysis_configuring", analyzer=analyzer_name, enabled=enabled)
        options_json = json.dumps(options or {})
        enabled_str = "True" if enabled else "False"
        try:
            result = await self._execute_remote(f"""
                import json as _json
                from ghidra.app.services import AutoAnalysisManager

                aam = AutoAnalysisManager.getAnalysisManager(currentProgram)
                analyzer_name = {json.dumps(analyzer_name)}
                options_data = _json.loads({json.dumps(options_json)})
                found = False
                for analyzer in aam.getAnalyzers():
                    if analyzer.getName() == analyzer_name:
                        found = True
                        analyzer.setEnabled({enabled_str})
                        opts = currentProgram.getOptions('Analyzers')
                        for key, val in options_data.items():
                            if isinstance(val, bool):
                                opts.setBoolean(analyzer_name + '.' + key, val)
                            elif isinstance(val, int):
                                opts.setInt(analyzer_name + '.' + key, val)
                            else:
                                opts.setString(analyzer_name + '.' + key, str(val))
                        break
                {{'analyzer': analyzer_name, 'enabled': {enabled_str}, 'success': found}}
            """)
            return (
                cast("dict[str, Any]", result)
                if isinstance(result, dict)
                else {"analyzer": analyzer_name, "enabled": enabled, "success": False}
            )
        except Exception as e:
            error_message = f"Configure analysis failed: {e}"
            raise ToolError(error_message) from e

    async def set_decompiler_options(
        self,
        simplification: str | None = None,
        max_instructions: int | None = None,
    ) -> dict[str, Any]:
        """Configure decompiler simplification style or instruction limit.

        Args:
            simplification: Simplification style name (e.g. 'normalize', 'jumptable').
            max_instructions: Maximum instructions per function for decompiler.

        Returns:
            dict[str, Any]: Dict with simplification, max_instructions, and success.

        Raises:
            ToolError: If Ghidra is not connected or configuration fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("decompiler_options_setting", simplification=simplification, max_instructions=max_instructions)
        simp_literal = json.dumps(simplification) if simplification else "None"
        max_instr_literal = str(max_instructions) if max_instructions is not None else "None"
        try:
            result = await self._execute_remote(f"""
                from ghidra.app.decompiler import DecompInterface, DecompileOptions

                ifc = DecompInterface()
                ifc.openProgram(currentProgram)
                opts = ifc.getOptions()
                simp = {simp_literal}
                max_instr = {max_instr_literal}
                if simp is not None:
                    opts.setSimplificationStyle(simp)
                if max_instr is not None:
                    opts.setMaxInstructions(max_instr)
                ifc.setOptions(opts)
                {{'simplification': simp, 'max_instructions': max_instr, 'success': True}}
            """)
            return (
                cast("dict[str, Any]", result)
                if isinstance(result, dict)
                else {"simplification": simplification, "max_instructions": max_instructions, "success": False}
            )
        except Exception as e:
            error_message = f"Set decompiler options failed: {e}"
            raise ToolError(error_message) from e

    async def create_memory_block(
        self,
        name: str,
        start: int,
        size: int,
        permissions: str = "r",
    ) -> dict[str, Any]:
        """Create a new initialized memory block.

        Args:
            name: Block name.
            start: Start address.
            size: Block size in bytes.
            permissions: Permission string using r/w/x characters.

        Returns:
            dict[str, Any]: Dict with name, start, size, permissions, and success.

        Raises:
            ToolError: If Ghidra is not connected or block creation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.info("memory_block_creating", block_name=name, start=hex(start), size=size, permissions=permissions)
        try:
            result = await self._execute_remote(f"""
                memory = currentProgram.getMemory()
                addr = toAddr({start})
                block = memory.createInitializedBlock({json.dumps(name)}, addr, {size}, 0, monitor, False)
                perms = {json.dumps(permissions)}
                block.setRead('r' in perms)
                block.setWrite('w' in perms)
                block.setExecute('x' in perms)
                {{'name': block.getName(), 'start': block.getStart().getOffset(), 'size': block.getSize(), 'permissions': perms, 'success': True}}
            """)
            return (
                cast("dict[str, Any]", result)
                if isinstance(result, dict)
                else {"name": name, "start": hex(start), "size": size, "permissions": permissions, "success": False}
            )
        except Exception as e:
            error_message = f"Create memory block failed: {e}"
            raise ToolError(error_message) from e

    async def get_comments(self, address: int, range_size: int = 0x100) -> list[dict[str, Any]]:
        """Get all comments in an address range.

        Args:
            address: Start address.
            range_size: Number of bytes to scan.

        Returns:
            list[dict[str, Any]]: List of comment dicts with address, type, and comment text.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(f"""
                from ghidra.program.model.listing import CodeUnit

                start = toAddr({address})
                end = toAddr({address} + {range_size})
                listing = currentProgram.getListing()
                comments = []
                cu_iter = listing.getCodeUnits(start, end, True)
                comment_types = [
                    ('EOL', CodeUnit.EOL_COMMENT),
                    ('PRE', CodeUnit.PRE_COMMENT),
                    ('POST', CodeUnit.POST_COMMENT),
                    ('PLATE', CodeUnit.PLATE_COMMENT),
                    ('REPEATABLE', CodeUnit.REPEATABLE_COMMENT),
                ]
                while cu_iter.hasNext():
                    cu = cu_iter.next()
                    for type_name, type_const in comment_types:
                        text = cu.getComment(type_const)
                        if text:
                            comments.append({{
                                'address': cu.getAddress().getOffset(),
                                'type': type_name,
                                'comment': text,
                            }})
                comments
            """)
            return cast("list[dict[str, Any]]", result) if result else []
        except Exception:
            _logger.exception("get_comments_failed", address=hex(address))
            return []

    async def get_all_comments(self) -> list[dict[str, Any]]:
        """Get all comments in the entire program.

        Returns:
            list[dict[str, Any]]: List of comment dicts with address, type, and comment text.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote("""
                from ghidra.program.model.listing import CodeUnit

                listing = currentProgram.getListing()
                comments = []
                comment_types = [
                    ('EOL', CodeUnit.EOL_COMMENT),
                    ('PRE', CodeUnit.PRE_COMMENT),
                    ('POST', CodeUnit.POST_COMMENT),
                    ('PLATE', CodeUnit.PLATE_COMMENT),
                    ('REPEATABLE', CodeUnit.REPEATABLE_COMMENT),
                ]
                cu_iter = listing.getCodeUnits(True)
                while cu_iter.hasNext():
                    cu = cu_iter.next()
                    for type_name, type_const in comment_types:
                        text = cu.getComment(type_const)
                        if text:
                            comments.append({
                                'address': cu.getAddress().getOffset(),
                                'type': type_name,
                                'comment': text,
                            })
                comments
            """)
            return cast("list[dict[str, Any]]", result) if result else []
        except Exception:
            _logger.exception("get_all_comments_failed")
            return []

    async def get_program_tree(self) -> dict[str, Any]:
        """Get the program tree module and fragment hierarchy.

        Returns:
            dict[str, Any]: Dict with trees list containing module and fragment information.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote("""
                listing = currentProgram.getListing()
                tree_names = list(listing.getTreeNames())
                trees = []
                for tree_name in tree_names:
                    root_module = listing.getRootModule(tree_name)
                    modules = []
                    if root_module is not None:
                        for child in root_module.getChildren():
                            child_name = child.getName()
                            modules.append({'name': child_name, 'type': str(child.getClass().getSimpleName())})
                    trees.append({'name': tree_name, 'modules': modules})
                {'trees': trees}
            """)
            return cast("dict[str, Any]", result) if isinstance(result, dict) else {"trees": []}
        except Exception:
            _logger.exception("get_program_tree_failed")
            return {"trees": []}

    async def get_properties(self, address: int) -> dict[str, Any]:
        """Get user-defined properties stored at an address.

        Args:
            address: Address to query.

        Returns:
            dict[str, Any]: Dict with address and properties map.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("properties_fetching", address=hex(address))
        try:
            result = await self._execute_remote(f"""
                addr = toAddr({address})
                upm = currentProgram.getUsrPropertyManager()
                props = {{}}
                prop_names = list(upm.propertyNames())
                for prop_name in prop_names:
                    map_obj = upm.getPropertyMap(prop_name)
                    if map_obj is not None and map_obj.hasProperty(addr):
                        try:
                            props[prop_name] = str(map_obj.getObject(addr))
                        except Exception:
                            try:
                                props[prop_name] = bool(map_obj.getBoolean(addr))
                            except Exception:
                                props[prop_name] = None
                {{'address': {address}, 'properties': props}}
            """)
            return cast("dict[str, Any]", result) if isinstance(result, dict) else {"address": hex(address), "properties": {}}
        except Exception:
            _logger.exception("get_properties_failed", address=hex(address))
            return {"address": hex(address), "properties": {}}

    async def diff_programs(self, other_program_path: str) -> dict[str, Any]:
        """Compare the current program with another program file.

        Args:
            other_program_path: Path to the other program file.

        Returns:
            dict[str, Any]: Dict with difference count and details list.

        Raises:
            ToolError: If Ghidra is not connected or comparison fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.info("program_diffing", other_path=other_program_path)
        try:
            result = await self._execute_remote(f"""
                import java.io.File as JFile
                from ghidra.program.util import ProgramDiff, ProgramDiffFilter

                other_file = JFile({json.dumps(other_program_path)})
                other_prog = importFile(other_file)
                details = []
                differences = 0
                if other_prog is not None:
                    diff = ProgramDiff(currentProgram, other_prog)
                    diff_filter = ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS)
                    diff_set = diff.getDifferences(diff_filter, monitor)
                    if diff_set is not None:
                        addr_iter = diff_set.getAddresses(True)
                        while addr_iter.hasNext() and differences < 1000:
                            a = addr_iter.next()
                            details.append({{'address': a.getOffset()}})
                            differences += 1
                {{'differences': differences, 'details': details}}
            """)
            return cast("dict[str, Any]", result) if isinstance(result, dict) else {"differences": 0, "details": []}
        except Exception:
            _logger.exception("diff_programs_failed", other_path=other_program_path)
            return {"differences": 0, "details": []}

    async def set_color(self, address: int, color: int) -> dict[str, Any]:
        """Set a background color on a code unit at an address.

        Args:
            address: Address to colorize.
            color: RGB color as integer (0xRRGGBB).

        Returns:
            dict[str, Any]: Dict with address, color, and success.

        Raises:
            ToolError: If Ghidra is not connected or operation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("color_setting", address=hex(address), color=hex(color))
        try:
            await self._execute_remote(f"""
                import java.awt.Color as JColor

                addr = toAddr({address})
                listing = currentProgram.getListing()
                cu = listing.getCodeUnitAt(addr)
                if cu is not None:
                    r = ({color} >> 16) & 0xFF
                    g = ({color} >> 8) & 0xFF
                    b = {color} & 0xFF
                    col = JColor(r, g, b)
                    cu.setBackgroundColor(col)
            """)
            return {"address": hex(address), "color": hex(color), "success": True}
        except Exception as e:
            error_message = f"Set color failed: {e}"
            raise ToolError(error_message) from e

    async def set_program_metadata(
        self,
        name: str | None = None,
        image_base: int | None = None,
    ) -> dict[str, Any]:
        """Set program name and/or image base address.

        Args:
            name: New program name, or None to leave unchanged.
            image_base: New image base address, or None to leave unchanged.

        Returns:
            dict[str, Any]: Dict with name, image_base, and success.

        Raises:
            ToolError: If Ghidra is not connected or operation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.info("program_metadata_setting", prog_name=name, image_base=image_base)
        name_literal = json.dumps(name) if name else "None"
        image_base_literal = str(image_base) if image_base is not None else "None"
        try:
            await self._execute_remote(f"""
                new_name = {name_literal}
                new_base = {image_base_literal}
                if new_name is not None:
                    currentProgram.setName(new_name)
                if new_base is not None:
                    currentProgram.setImageBase(toAddr(new_base), True)
            """)
            return {"name": name, "image_base": hex(image_base) if image_base is not None else None, "success": True}
        except Exception as e:
            error_message = f"Set program metadata failed: {e}"
            raise ToolError(error_message) from e

    async def execute_script_with_params(self, code: str, params: dict[str, Any] | None = None) -> str:
        """Execute Jython code with a JSON params dict injected as a local variable.

        Args:
            code: Jython code to execute in Ghidra.
            params: Parameters injected as the 'params' variable in the script.

        Returns:
            str: String result of script execution.
        """
        _logger.debug("parameterized_script_executing", code_length=len(code))
        params_json = json.dumps(params or {})
        injected = f"import json as _json\nparams = _json.loads({json.dumps(params_json)})\n{code}"
        result = await self._execute_remote(injected)
        return str(result) if result is not None else ""

    async def manage_thunks(self, address: int) -> dict[str, Any]:
        """Query thunk status and resolved target for a function.

        Args:
            address: Function address.

        Returns:
            dict[str, Any]: Dict with address, is_thunk, thunked_function, and thunked_address.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("thunk_managing", address=hex(address))
        try:
            result = await self._execute_remote(f"""
                addr = toAddr({address})
                func = getFunctionContaining(addr)
                if func is None:
                    {{'address': {address}, 'is_thunk': False, 'thunked_function': None, 'thunked_address': None}}
                else:
                    is_thunk = func.isThunk()
                    thunked_name = None
                    thunked_addr = None
                    if is_thunk:
                        thunked = func.getThunkedFunction(False)
                        if thunked is not None:
                            thunked_name = thunked.getName()
                            thunked_addr = thunked.getEntryPoint().getOffset()
                    {{'address': func.getEntryPoint().getOffset(), 'is_thunk': bool(is_thunk), 'thunked_function': thunked_name, 'thunked_address': thunked_addr}}
            """)
            return (
                cast("dict[str, Any]", result)
                if isinstance(result, dict)
                else {"address": hex(address), "is_thunk": False, "thunked_function": None, "thunked_address": None}
            )
        except Exception:
            _logger.exception("manage_thunks_failed", address=hex(address))
            return {"address": hex(address), "is_thunk": False, "thunked_function": None, "thunked_address": None}

    async def manage_external_references(self, address: int) -> list[dict[str, Any]]:
        """Get external (imported) references from an address.

        Args:
            address: Address to query.

        Returns:
            list[dict[str, Any]]: List of external reference dicts with address, external_name, library, and type.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("external_references_fetching", address=hex(address))
        try:
            result = await self._execute_remote(f"""
                addr = toAddr({address})
                ext_refs = []
                for ref in getReferencesFrom(addr):
                    if ref.isExternalReference():
                        ext_loc = ref.getExternalLocation()
                        lib_name = ''
                        if ext_loc is not None:
                            lib = ext_loc.getLibraryName()
                            lib_name = str(lib) if lib else ''
                        ext_refs.append({{
                            'address': addr.getOffset(),
                            'external_name': ext_loc.getLabel() if ext_loc is not None else '',
                            'library': lib_name,
                            'type': str(ref.getReferenceType()),
                        }})
                ext_refs
            """)
            return cast("list[dict[str, Any]]", result) if result else []
        except Exception:
            _logger.exception("manage_external_references_failed", address=hex(address))
            return []

    async def add_external_function(self, library: str, name: str, address: int | None = None) -> dict[str, Any]:
        """Add an external function to the external symbol table.

        Args:
            library: Library name.
            name: Function name.
            address: Optional address to link the external function to.

        Returns:
            dict[str, Any]: Dict with library, name, address, and success.

        Raises:
            ToolError: If Ghidra is not connected or operation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.info("external_function_adding", library=library, func_name=name)
        addr_literal = str(address) if address is not None else "None"
        try:
            result = await self._execute_remote(f"""
                from ghidra.program.model.symbol import SourceType

                extMgr = currentProgram.getExternalManager()
                addr_val = {addr_literal}
                mem_addr = toAddr(addr_val) if addr_val is not None else None
                ext_loc = extMgr.addExtFunction({json.dumps(library)}, {json.dumps(name)}, mem_addr, SourceType.USER_DEFINED)
                {{'library': {json.dumps(library)}, 'name': {json.dumps(name)}, 'address': addr_val, 'success': ext_loc is not None}}
            """)
            return (
                cast("dict[str, Any]", result)
                if isinstance(result, dict)
                else {"library": library, "name": name, "address": address, "success": False}
            )
        except Exception as e:
            error_message = f"Add external function failed: {e}"
            raise ToolError(error_message) from e

    async def create_overlay_space(self, name: str) -> dict[str, Any]:
        """Create a new overlay address space.

        Args:
            name: Overlay space name.

        Returns:
            dict[str, Any]: Dict with name and success.

        Raises:
            ToolError: If Ghidra is not connected or creation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.info("overlay_space_creating", overlay_name=name)
        try:
            result = await self._execute_remote(f"""
                memory = currentProgram.getMemory()
                default_space = currentProgram.getAddressFactory().getDefaultAddressSpace()
                overlay_space = memory.createOverlayAddressSpace({json.dumps(name)}, default_space)
                {{'name': overlay_space.getName() if overlay_space is not None else {json.dumps(name)}, 'success': overlay_space is not None}}
            """)
            return cast("dict[str, Any]", result) if isinstance(result, dict) else {"name": name, "success": False}
        except Exception as e:
            error_message = f"Create overlay space failed: {e}"
            raise ToolError(error_message) from e

    async def _execute_remote(self, code: str) -> object:
        """Execute code on the Ghidra bridge.

        Args:
            code: Python code to execute.

        Returns:
            object: Result of execution.

        Raises:
            ToolError: If execution fails.
        """
        if self._bridge is None:
            error_message = "Ghidra bridge not connected"
            raise ToolError(error_message)

        remote_exec_attr = getattr(self._bridge, "remote_exec", None)
        if remote_exec_attr is None:
            error_message = "Ghidra bridge missing remote_exec"
            raise ToolError(error_message)
        remote_exec = cast("_RemoteExecFunc", remote_exec_attr)

        try:
            return await asyncio.to_thread(
                remote_exec,
                code,
            )
        except Exception as e:
            _logger.exception("ghidra_remote_exec_failed", error=str(e))
            error_message = f"Remote execution failed: {e}"
            raise ToolError(error_message) from e
