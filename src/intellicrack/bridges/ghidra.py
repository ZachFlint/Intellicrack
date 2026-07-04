# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Ghidra bridge for static analysis and decompilation.

This module provides integration with Ghidra for advanced static analysis, decompilation, and reverse engineering capabilities using
ghidra_bridge.
"""

from __future__ import annotations

import ast
import asyncio
import hashlib
import importlib
import importlib.util
import itertools
import json
import os
import re
import socket
import string
import tempfile
import textwrap
import threading
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any, Literal, cast

from intellicrack.bridges.base import (
    BridgeCapabilities,
    BridgeState,
    DisassemblyLine,
    StaticAnalysisBridge,
)
from intellicrack.bridges.pe_format import (
    detect_format,
    detect_format_and_arch,
)
from intellicrack.core.logging import get_logger
from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.core.subprocess_compat import CREATE_NO_WINDOW, PIPE, Popen
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


_logger = get_logger(__name__)

_RemoteExecFunc = Callable[[str], object]
_RemoteEvalFunc = Callable[[str], object]

_JAVA_SIGNED_THRESHOLD = 127
_JAVA_SIGNED_RANGE = 256
_ARCH_64_POINTER_BYTES = 8
_HEX_TOKEN_LENGTH = 2
_BOOKMARK_READBACK_PAIR_LEN = 2

_RESULT_SENTINEL_BASE = "_intellicrack_ghidra_result_"

_remote_call_counter: itertools.count[int] = itertools.count(1)

_BRIDGE_SCRIPT_LOCK = threading.Lock()
_BRIDGE_SCRIPT_PREFIX = "intellicrack_ghidra_"
_BRIDGE_SCRIPT_NAME = "start_bridge.py"
_HEADLESS_ENV_BLOCKLIST = (
    "GHIDRA_HOME",
    "GHIDRA_INSTALL_DIR",
    "GHIDRA_PROJECT_DIR",
    "GHIDRA_BRIDGE_PORT",
    "GHIDRA_BRIDGE_HOST",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JAVA_OPTIONS",
    "MAVEN_OPTS",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PYTHONIOENCODING",
)


def prepare_remote_script(code: str) -> tuple[str, str | None]:
    """Dedent a Jython script and rewrite any trailing expression as a sentinel assignment.

    The Ghidra bridge transports user scripts to a remote Jython
    interpreter where they are run via Python's :func:`exec`, which
    discards the value of any trailing expression statement. This
    helper rewrites such scripts so the trailing expression value is
    preserved on the remote interpreter as a uniquely named global
    variable, suitable for retrieval via a follow-up ``remote_eval``.

    Args:
        code: Jython source as authored at the call site.

    Returns:
        tuple[str, str | None]: Tuple of (rewritten Jython source,
        sentinel variable name or ``None`` when there is no trailing
        expression to capture).

    Raises:
        ToolError: If the Jython source fails to parse.
    """
    dedented = textwrap.dedent(code).strip("\n")
    if not dedented.strip():
        return "", None

    try:
        tree = ast.parse(dedented, mode="exec")
    except SyntaxError as exc:
        error_message = f"Failed to parse remote script: {exc}"
        raise ToolError(error_message) from exc

    if not tree.body:
        return dedented, None

    last_stmt = tree.body[-1]
    if not isinstance(last_stmt, ast.Expr):
        return dedented, None

    sentinel = f"{_RESULT_SENTINEL_BASE}{next(_remote_call_counter)}"
    assign_node = ast.Assign(
        targets=[ast.Name(id=sentinel, ctx=ast.Store())],
        value=last_stmt.value,
    )
    ast.copy_location(assign_node, last_stmt)
    ast.fix_missing_locations(assign_node)
    tree.body[-1] = assign_node
    rewritten_source = ast.unparse(tree)
    return rewritten_source, sentinel


_ERR_NOT_CONNECTED = "Ghidra not connected"
_ERR_IMPORT_FILE_FAILED = "Failed to import binary into Ghidra"
_ERR_FILE_NOT_FOUND = "File not found"
_ERR_WRITE_VERIFICATION_FAILED = "Write verification failed: readback does not match written bytes"
_ERR_FUNCTION_NOT_FOUND = "Function not found at address"
_ERR_BOOKMARK_NOT_FOUND = "Bookmark not found"
_ERR_LABEL_NOT_FOUND = "Label not found"
_ERR_DEBUG_IMPORT_FAILED = "Debug info import failed"
_ERR_UNSUPPORTED_DEBUG_FORMAT = "Unsupported debug info file format"
_ERR_DEBUG_PATH_INVALID = "Debug info file path invalid"
_ERR_DEBUG_PATH_NOT_FOUND = "Debug info file not found"
_ERR_DEBUG_PATH_NOT_FILE = "Debug info path is not a regular file"


_XRefRefType = Literal["call", "jump", "data", "read", "write"]


def _map_ghidra_ref_type(raw_type: str) -> _XRefRefType:
    """Map a Ghidra ``RefType`` string to the canonical xref taxonomy.

    Ghidra's ``ghidra.program.model.symbol.RefType`` exposes a rich set of
    reference flavours such as ``UNCONDITIONAL_CALL``, ``COMPUTED_CALL``,
    ``CONDITIONAL_JUMP``, ``COMPUTED_JUMP``, ``READ``, ``WRITE``, ``DATA``,
    ``READ_WRITE``, ``READ_IND``, ``WRITE_IND``, ``PARAM``, and
    ``EXTERNAL_REF``. This helper preserves call/jump/read/write
    distinctions instead of collapsing every non-call entry to ``"data"``.

    Args:
        raw_type: The string returned by Ghidra's ``RefType.toString()``.

    Returns:
        _XRefRefType: One of ``"call"``, ``"jump"``, ``"data"``, ``"read"``,
        or ``"write"``.
    """
    upper = raw_type.upper()
    if "CALL" in upper:
        return "call"
    if "JUMP" in upper or upper == "FLOW" or upper.endswith("_FLOW"):
        return "jump"
    if "WRITE" in upper:
        return "write"
    return "read" if "READ" in upper else "data"


def _resolve_debug_info_path(path: str) -> Path:
    r"""Canonicalise and validate a debug-info path before passing it to Ghidra.

    Resolves the supplied path with ``Path.resolve(strict=True)`` to reject
    non-existent paths and to defeat traversal sequences such as
    ``..\..\Windows\System32``. Refuses paths that resolve to anything
    other than a regular file (directories, devices, symlink loops).

    Args:
        path: Untrusted, possibly-relative path supplied by the caller.

    Returns:
        Path: Absolute, normalised filesystem path that is guaranteed to
        exist and to refer to a regular file at the moment of the check.

    Raises:
        ToolError: If ``path`` is empty, cannot be resolved, does not
            exist, or does not refer to a regular file.
    """
    if not path or not path.strip():
        raise ToolError(_ERR_DEBUG_PATH_INVALID)

    candidate = Path(path)
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        msg = f"{_ERR_DEBUG_PATH_NOT_FOUND}: {path}"
        raise ToolError(msg) from exc
    except OSError as exc:
        msg = f"{_ERR_DEBUG_PATH_INVALID}: {path}: {exc}"
        raise ToolError(msg) from exc

    if not resolved.is_file():
        msg = f"{_ERR_DEBUG_PATH_NOT_FILE}: {resolved}"
        raise ToolError(msg)

    return resolved


class _GhidraBridgeBase(StaticAnalysisBridge):
    """Bridge for Ghidra reverse engineering suite.

    Provides advanced static analysis and decompilation capabilities
    using the ghidra_bridge Python interface. Instances own slots for
    the Ghidra installation path, the active ``ghidra_bridge`` RPC
    object, the spawned headless process handle, the tracked binary and
    project paths, the RPC port (defaulting to ``DEFAULT_PORT``), the
    deployed bridge script path, and the advertised static-analysis
    ``BridgeCapabilities``.

    Attributes:
        DEFAULT_PORT: TCP port for the ghidra_bridge RPC connection.
        DECOMPILE_TIMEOUT_SECONDS: Timeout for Ghidra decompilation in seconds.
    """

    DEFAULT_PORT = 4768
    DECOMPILE_TIMEOUT_SECONDS: int = 60

    def __init__(self) -> None:
        """Initialize the GhidraBridge instance."""
        super().__init__()
        self._ghidra_path: Path | None = None
        self._bridge: object | None = None
        self._process: Popen[bytes] | None = None
        self._binary_path: Path | None = None
        self._project_path: Path | None = None
        self._port: int = self.DEFAULT_PORT
        self._bridge_script_path: Path | None = None
        self._decompiler_simplification: str | None = None
        self._decompiler_max_instructions: int | None = None
        self._decompiler_options_extra: dict[str, Any] = {}
        self._stderr_drain_thread: threading.Thread | None = None
        self._stdout_drain_thread: threading.Thread | None = None
        self._stderr_buffer: list[str] = []
        self._stderr_buffer_lock = threading.Lock()
        self._capabilities = BridgeCapabilities(
            supports_static_analysis=True,
            supports_decompilation=True,
            supports_patching=False,
            supports_scripting=True,
            supported_architectures=[
                "x86",
                "x86_64",
                "arm",
                "arm64",
                "mips",
                "mips64",
                "ppc",
                "ppc64",
                "sparc",
                "riscv",
                "riscv64",
            ],
            supported_formats=["pe", "elf", "macho", "raw", "coff"],
        )
        _logger.info("ghidra_bridge_initialized", port=self._port)

    @property
    def ghidra_path(self) -> Path | None:
        """The Ghidra installation path.

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
        _logger.info("ghidra_path_set", path=str(value) if value is not None else None)
        self._ghidra_path = value

    @property
    def project_path(self) -> Path | None:
        """The active Ghidra project path.

        Returns:
            Path | None: Path to the active Ghidra project, or None if no project is open.
        """
        return self._project_path

    @property
    def name(self) -> ToolName:
        """Tool name identifier.

        Returns:
            ToolName: ToolName.GHIDRA
        """
        return ToolName.GHIDRA

    @property
    def tool_definition(self) -> ToolDefinition:
        """Tool definition for LLM function calling.

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
                            required=False,
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
                            items_type="object",
                            item_properties=[
                                ToolParameter(name="name", type="string", description="Field name", required=True),
                                ToolParameter(
                                    name="type",
                                    type="string",
                                    description="Field data type (e.g. dword, char, pointer)",
                                    required=True,
                                ),
                                ToolParameter(name="size", type="integer", description="Field size in bytes", required=False),
                            ],
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
                            items_type="object",
                            item_properties=[
                                ToolParameter(name="name", type="string", description="Member name", required=True),
                                ToolParameter(name="value", type="integer", description="Enum member value", required=False),
                                ToolParameter(
                                    name="type",
                                    type="string",
                                    description="Member or base data type for union/typedef",
                                    required=False,
                                ),
                                ToolParameter(
                                    name="size",
                                    type="integer",
                                    description="Member size in bytes for union",
                                    required=False,
                                ),
                            ],
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
                        ToolParameter(
                            name="extra",
                            type="object",
                            description="Additional key/value decompiler options merged into the persisted configuration",
                            required=False,
                        ),
                    ],
                    returns="Dict with simplification, max_instructions, extra, and success",
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
                    name="ghidra.remove_memory_block",
                    description="Remove a memory block from the program",
                    parameters=[
                        ToolParameter(name="name", type="string", description="Name of the memory block to remove", required=True),
                    ],
                    returns="Dict with name and success",
                ),
                ToolFunction(
                    name="ghidra.split_memory_block",
                    description="Split a memory block into two blocks at an address",
                    parameters=[
                        ToolParameter(name="name", type="string", description="Name of the memory block to split", required=True),
                        ToolParameter(
                            name="split_address",
                            type="integer",
                            description="Address at which to split the block (start of the new second block)",
                            required=True,
                        ),
                    ],
                    returns="Dict with name, split_address, and success",
                ),
                ToolFunction(
                    name="ghidra.join_memory_blocks",
                    description="Join two contiguous memory blocks into one",
                    parameters=[
                        ToolParameter(name="name1", type="string", description="Name of the first (lower-addressed) block", required=True),
                        ToolParameter(
                            name="name2",
                            type="string",
                            description="Name of the second (higher-addressed) block",
                            required=True,
                        ),
                    ],
                    returns="Dict with the joined block name and success",
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
                    name="ghidra.edit_program_tree",
                    description="Create a module/fragment in a program tree, or move an existing child under a new parent",
                    parameters=[
                        ToolParameter(name="tree_name", type="string", description="Name of the program tree to modify", required=True),
                        ToolParameter(
                            name="operation",
                            type="string",
                            description="Operation to perform",
                            required=True,
                            enum=["create_module", "create_fragment", "move_child"],
                        ),
                        ToolParameter(
                            name="parent_module",
                            type="string",
                            description="Name of the module that will contain the child",
                            required=True,
                        ),
                        ToolParameter(
                            name="child_name",
                            type="string",
                            description="Name of the module/fragment to create or move",
                            required=True,
                        ),
                    ],
                    returns="Dict with tree_name, operation, child_name, and success",
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
                    name="ghidra.get_thunk_info",
                    description="Query thunk status and resolved target for a function",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Function address", required=True),
                    ],
                    returns="Dict with address, is_thunk, thunked_function, and thunked_address",
                ),
                ToolFunction(
                    name="ghidra.get_external_references",
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
                ToolFunction(
                    name="ghidra.add_bookmark",
                    description="Add a bookmark at an address (explicit mutator)",
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
                    returns="Dict with address, category, comment, bookmark_type, and success",
                ),
                ToolFunction(
                    name="ghidra.remove_bookmark",
                    description="Remove a bookmark at an address, optionally matching category and/or bookmark_type",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address of bookmark to remove", required=True),
                        ToolParameter(name="category", type="string", description="Optional category filter", required=False),
                        ToolParameter(name="bookmark_type", type="string", description="Optional type filter", required=False),
                    ],
                    returns="Dict with address, removed count, and success",
                ),
                ToolFunction(
                    name="ghidra.add_label",
                    description="Add a label at an address (explicit mutator)",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address for the label", required=True),
                        ToolParameter(name="name", type="string", description="Label name", required=True),
                        ToolParameter(name="primary", type="boolean", description="Set label as primary", required=False, default=False),
                    ],
                    returns="Dict with address, name, primary, and success",
                ),
                ToolFunction(
                    name="ghidra.remove_label",
                    description="Remove a named label at an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address of the label", required=True),
                        ToolParameter(name="name", type="string", description="Label name to remove", required=True),
                    ],
                    returns="Dict with address, name, and success",
                ),
                ToolFunction(
                    name="ghidra.add_thunk",
                    description="Mark a function as a thunk for a target function",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Thunk function address", required=True),
                        ToolParameter(
                            name="thunked_address",
                            type="integer",
                            description="Target (thunked) function address",
                            required=True,
                        ),
                    ],
                    returns="Dict with address, thunked_address, and success",
                ),
                ToolFunction(
                    name="ghidra.remove_thunk",
                    description="Clear thunk status from a function",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Thunk function address", required=True),
                    ],
                    returns="Dict with address and success",
                ),
                ToolFunction(
                    name="ghidra.add_external_reference",
                    description="Add an external reference from an address to a named external function",
                    parameters=[
                        ToolParameter(name="from_addr", type="integer", description="Source address", required=True),
                        ToolParameter(name="library", type="string", description="External library name", required=True),
                        ToolParameter(name="name", type="string", description="External function name", required=True),
                    ],
                    returns="Dict with from_addr, library, name, and success",
                ),
                ToolFunction(
                    name="ghidra.remove_external_reference",
                    description="Remove external references from an address",
                    parameters=[
                        ToolParameter(name="from_addr", type="integer", description="Source address", required=True),
                    ],
                    returns="Dict with from_addr, removed count, and success",
                ),
            ],
        )

    def set_port(self, port: int) -> None:
        """Set the bridge server port.

        Args:
            port: TCP port for the ghidra_bridge RPC connection.
        """
        _logger.info("ghidra_set_port_started", port=port)
        self._port = port

    def attach_remote_bridge(self, bridge_client: object) -> None:
        """Attach an externally constructed ``ghidra_bridge`` client.

        Provides an explicit seam for callers that already own a live
        ``ghidra_bridge`` RPC client (for example, when sharing a
        long-lived headless server across tools, or when supplying a
        compatible double for deterministic testing). The client must
        expose ``remote_exec`` and ``remote_eval`` methods matching the
        upstream :class:`jfx_bridge.bridge.BridgeClient` contract; both
        are invoked through :meth:`_execute_remote` for every Jython
        script the bridge dispatches.

        Args:
            bridge_client: Object exposing ``remote_exec(code: str)`` and
                ``remote_eval(expr: str)`` matching the upstream
                ``ghidra_bridge`` client semantics.
        """
        self._bridge = bridge_client
        self.state.connected = True
        self.state.tool_running = True
        _logger.info("ghidra_bridge_attached", port=self._port)

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

        except ImportError as imp_err:
            _logger.warning("ghidra_bridge_module_missing", bridge="ghidra")
            self._bridge = None
            self.state.connected = False
            self.state.tool_running = False
            self.state.last_error = "ghidra_bridge package not installed"
            self._publish_tool_state()
            error_message = "ghidra_bridge package not installed"
            raise ToolError(error_message) from imp_err

        except Exception as exc:
            _logger.exception("ghidra_connect_failed")
            self._bridge = None
            self.state.connected = False
            self.state.tool_running = False
            self.state.last_error = str(exc)
            self._publish_tool_state()
            error_message = f"Failed to connect to Ghidra: {exc}"
            raise ToolError(error_message) from exc

        else:
            self.state.connected = True
            self.state.tool_running = True
            self._publish_tool_state()
            _logger.info("ghidra_bridge_connected", port=self._port)

    async def _join_drain_threads(self, join_seconds: float = 5.0) -> None:
        """Wait for stdout/stderr drain threads to terminate.

        Args:
            join_seconds: Maximum seconds to wait per thread.
        """
        for attr_name in ("_stderr_drain_thread", "_stdout_drain_thread"):
            thread: threading.Thread | None = getattr(self, attr_name)
            if thread is None:
                continue
            await asyncio.to_thread(thread.join, join_seconds)
            setattr(self, attr_name, None)

    @staticmethod
    def _close_bridge_client(bridge: object) -> None:
        """Close the active ghidra_bridge RPC client socket.

        Args:
            bridge: The ``ghidra_bridge.GhidraBridge`` (``BridgeClient``) instance.
        """
        client = getattr(bridge, "client", None)
        if client is None:
            return

        sock = getattr(client, "sock", None)
        if sock is not None:
            try:
                sock.close()
            except OSError:
                _logger.warning("ghidra_bridge_socket_close_failed", exc_info=True)

        comms_thread = getattr(client, "comms_thread", None)
        if comms_thread is not None:
            try:
                comms_thread.join(timeout=2.0)
            except RuntimeError:
                _logger.debug("ghidra_bridge_comms_join_failed", exc_info=True)

    @staticmethod
    def _cleanup_bridge_script(script_path: Path) -> None:
        """Remove a bridge script and its parent tempdir under a global lock.

        Args:
            script_path: Path to the deployed bridge script.
        """
        with _BRIDGE_SCRIPT_LOCK:
            try:
                script_path.unlink(missing_ok=True)
            except OSError:
                _logger.exception("bridge_script_unlink_failed")
                return

            parent = script_path.parent
            try:
                parent.rmdir()
            except FileNotFoundError:
                _logger.warning("bridge_script_parent_already_absent", parent=str(parent))
            except OSError:
                _logger.warning("bridge_script_parent_not_empty", parent=str(parent))

    async def is_available(self) -> bool:
        """Check if Ghidra is available.

        Returns:
            bool: True if Ghidra can be used.
        """
        _logger.info("ghidra_is_available_started", ghidra_path=str(self._ghidra_path) if self._ghidra_path else None)
        if self._ghidra_path is None:
            return False
        return importlib.util.find_spec("ghidra_bridge") is not None

    async def start_headless(
        self,
        project_dir: Path,
        project_name: str = "intellicrack",
    ) -> None:
        """Start Ghidra in headless mode with the long-running bridge server.

        The launcher selects the platform-appropriate ``analyzeHeadless`` entry
        point (``analyzeHeadless.bat`` on Windows, ``analyzeHeadless`` on POSIX),
        deploys an UTF-8 bridge script under a unique temporary directory, and
        spawns the JVM with ``cwd`` set to the Ghidra ``support`` directory,
        ``creationflags=CREATE_NO_WINDOW`` on Windows, and a scrubbed environment
        that strips Ghidra/Java/Python overrides which can hijack the JVM. The
        deployed script invokes ``GhidraBridgeServer.run_server`` with
        ``background=False`` so the JVM is kept alive after the post-script
        returns. Stdout and stderr are drained continuously by background
        threads to prevent pipe-buffer deadlock during ``_wait_for_bridge_port``.

        Args:
            project_dir: Directory for Ghidra project.
            project_name: Name of the project.

        Raises:
            ToolError: If Ghidra cannot be started, the headless script is
                missing for the current platform, the bridge port never opens,
                or the RPC client cannot connect.
        """
        if self._ghidra_path is None:
            error_message = "Ghidra path not set"
            raise ToolError(error_message)

        ghidra_run = await asyncio.to_thread(self._resolve_headless_executable, self._ghidra_path)

        await asyncio.to_thread(project_dir.mkdir, parents=True, exist_ok=True)
        self._project_path = project_dir / project_name

        bridge_script = await asyncio.to_thread(self._create_bridge_script)

        cmd = [
            str(ghidra_run),
            str(project_dir),
            project_name,
            "-scriptPath",
            str(bridge_script.parent),
            "-postScript",
            bridge_script.name,
        ]

        env = self._scrubbed_environment()
        cwd = str(ghidra_run.parent)
        creation_flags = CREATE_NO_WINDOW if os.name == "nt" else 0

        _logger.info(
            "ghidra_headless_starting",
            command=" ".join(cmd),
            cwd=cwd,
            creation_flags=creation_flags,
        )

        def _start_process() -> Popen[bytes]:
            """Launch the Ghidra headless analyzer subprocess.

            Wraps the blocking ``Popen`` construction so it can be executed
            on a worker thread via ``asyncio.to_thread``.

            Returns:
                Popen[bytes]: Handle for the spawned Ghidra headless process.
            """
            return Popen(
                cmd,
                stdout=PIPE,
                stderr=PIPE,
                cwd=cwd,
                env=env,
                creationflags=creation_flags,
            )

        self._process = await asyncio.to_thread(_start_process)

        self._start_drain_threads(self._process)

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
        except Exception as e:
            _logger.warning("ghidra_connect_failed", port=self._port, error=str(e))
            error_message = f"Failed to connect to Ghidra: {e}"
            self.state.last_error = error_message
            raise ToolError(error_message) from e
        else:
            self.state.connected = True
            self.state.tool_running = True
            _logger.info("ghidra_headless_connected", port=self._port)

    @staticmethod
    def _resolve_headless_executable(ghidra_path: Path) -> Path:
        """Resolve the platform-appropriate ``analyzeHeadless`` executable.

        Args:
            ghidra_path: Root directory of the Ghidra installation.

        Returns:
            Path: Path to the resolved ``analyzeHeadless`` launcher.

        Raises:
            ToolError: If the launcher does not exist for the current platform.
        """
        support = ghidra_path / "support"
        candidate = support / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")

        if not candidate.exists():
            _logger.warning("ghidra_headless_executable_missing", candidate=str(candidate))
            error_message = f"Ghidra headless script not found for this platform: {candidate}"
            raise ToolError(error_message)

        return candidate

    @staticmethod
    def _scrubbed_environment() -> dict[str, str]:
        """Build a copy of the current environment with hijack-prone variables removed.

        Strips Ghidra-specific ``GHIDRA_*`` variables, Java tunables that the
        JVM honours unconditionally (``JAVA_TOOL_OPTIONS``, ``_JAVA_OPTIONS``),
        and Python interpreter overrides that can leak into the launched JVM.

        Returns:
            dict[str, str]: A scrubbed environment dictionary suitable for
                passing as ``env=`` to ``subprocess.Popen``.
        """
        env = dict(os.environ)
        for key in _HEADLESS_ENV_BLOCKLIST:
            env.pop(key, None)
        return env

    def _start_drain_threads(self, process: Popen[bytes]) -> None:
        """Spawn background threads that drain stdout/stderr to prevent pipe deadlock.

        Args:
            process: The headless subprocess whose pipes need draining.
        """
        with self._stderr_buffer_lock:
            self._stderr_buffer = []

        if process.stderr is not None:
            self._stderr_drain_thread = threading.Thread(
                target=self._drain_stream,
                args=(process.stderr, "stderr", self._buffer_stderr_line),
                name="ghidra-stderr-drain",
                daemon=True,
            )
            self._stderr_drain_thread.start()

        if process.stdout is not None:
            self._stdout_drain_thread = threading.Thread(
                target=self._drain_stream,
                args=(process.stdout, "stdout", None),
                name="ghidra-stdout-drain",
                daemon=True,
            )
            self._stdout_drain_thread.start()

    def _buffer_stderr_line(self, line: str) -> None:
        """Append one stderr line to the captured buffer under the lock.

        Args:
            line: Decoded stderr line with trailing whitespace stripped.
        """
        with self._stderr_buffer_lock:
            self._stderr_buffer.append(line)

    @staticmethod
    def _drain_stream(
        stream: IO[bytes],
        stream_name: str,
        on_line: Callable[[str], None] | None,
    ) -> None:
        """Continuously read ``stream`` line-by-line and forward to the debug log.

        Args:
            stream: The subprocess pipe to drain.
            stream_name: Stream identifier (``"stderr"`` / ``"stdout"``)
                attached to log records as a structured field.
            on_line: Optional callback invoked for each non-empty decoded line
                (used by the stderr drainer to buffer for diagnostics).
        """

        def read_loop() -> None:
            for raw_line in iter(stream.readline, b""):
                line = raw_line.decode("utf-8", errors="replace").rstrip()
                if not line:
                    continue
                if on_line is not None:
                    on_line(line)
                _logger.debug("ghidra_headless_pipe_line", stream=stream_name, line=line)

        try:
            read_loop()
        except (OSError, ValueError):
            _logger.warning("ghidra_pipe_drain_terminated", stream=stream_name, exc_info=True)
        finally:
            try:
                stream.close()
            except OSError:
                _logger.warning("ghidra_pipe_close_failed", stream=stream_name, exc_info=True)

    def _captured_stderr_tail(self, max_lines: int = 40) -> str:
        """Return the last ``max_lines`` of buffered stderr output.

        Args:
            max_lines: Maximum number of trailing lines to return.

        Returns:
            str: Joined stderr output for diagnostic messages.
        """
        with self._stderr_buffer_lock:
            tail = self._stderr_buffer[-max_lines:]
        return "\n".join(tail)

    def _format_with_stderr_tail(self, message: str) -> str:
        """Append the captured stderr tail (if any) to a diagnostic message.

        Args:
            message: The base diagnostic message.

        Returns:
            str: ``message`` with the stderr tail appended when output exists.
        """
        tail = self._captured_stderr_tail()
        return f"{message}\nstderr tail:\n{tail}" if tail else message

    async def _wait_for_bridge_port(
        self,
        timeout_seconds: int = 60,
        poll_interval: float = 2.0,
    ) -> None:
        """Poll until the Ghidra bridge port is accepting connections.

        Concurrent stdout/stderr drain threads spawned by
        ``_start_drain_threads`` keep the OS pipe buffers from filling, so
        Ghidra never blocks on a full stderr pipe while we poll. Captured
        stderr lines are surfaced in raised ``ToolError`` messages.

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
                msg = self._format_with_stderr_tail(f"Ghidra process exited prematurely with code {rc}")
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

        msg = self._format_with_stderr_tail(
            f"Ghidra bridge port {self._port} not ready after {timeout_seconds}s ({attempt} attempts)",
        )
        raise ToolError(msg)

    def _create_bridge_script(self) -> Path:
        """Create the Ghidra bridge startup script in a unique temporary directory.

        Writes the bridge script under a per-instance ``tempfile.mkdtemp`` so
        concurrent ``start_headless`` invocations do not race over a single
        shared file. The script is written with explicit ``utf-8`` encoding
        and the write is verified by reading the file back and comparing the
        on-disk size to the rendered content size before logging success.

        The deployed script invokes ``ghidra_bridge_server.GhidraBridgeServer``
        ``run_server`` with ``background=False`` (the real upstream API),
        which keeps the JVM alive after the post-script returns. Calling the
        non-existent constructor + ``start()`` previously crashed Ghidra at
        boot with ``TypeError: object() takes no parameters``.

        Returns:
            Path: Path to the verified-on-disk bridge script.

        Raises:
            ToolError: If the script directory cannot be created, the script
                cannot be written, or post-write verification fails.
        """
        script_content = (
            "# @category: IntelliCrack\n"
            "# Start ghidra_bridge server (long-running) so JVM stays alive\n"
            "# after analyzeHeadless finishes the post-script.\n"
            "import ghidra_bridge_server\n"
            "ghidra_bridge_server.GhidraBridgeServer.run_server(\n"
            '    server_host="127.0.0.1",\n'
            f"    server_port={self._port},\n"
            "    background=False,\n"
            ")\n"
        )

        with _BRIDGE_SCRIPT_LOCK:
            try:
                script_dir = Path(tempfile.mkdtemp(prefix=_BRIDGE_SCRIPT_PREFIX))
            except OSError as exc:
                _logger.exception("ghidra_bridge_script_dir_create_failed")
                msg = f"Failed to create ghidra bridge script directory: {exc}"
                raise ToolError(msg) from exc

            script_path = script_dir / _BRIDGE_SCRIPT_NAME
            _logger.info(
                "ghidra_bridge_script_writing",
                script_path=str(script_path),
                content_size=len(script_content),
            )

            try:
                script_path.write_text(script_content, encoding="utf-8")
            except OSError as exc:
                _logger.exception("ghidra_bridge_script_write_failed", script_path=str(script_path))
                msg = f"Failed to write ghidra bridge script {script_path}: {exc}"
                raise ToolError(msg) from exc

            try:
                on_disk = script_path.read_text(encoding="utf-8")
            except OSError as exc:
                _logger.exception("ghidra_bridge_script_readback_failed", script_path=str(script_path))
                msg = f"Failed to verify ghidra bridge script {script_path}: {exc}"
                raise ToolError(msg) from exc

            if on_disk != script_content:
                _logger.error(
                    "ghidra_bridge_script_verify_mismatch",
                    script_path=str(script_path),
                    expected_size=len(script_content),
                    actual_size=len(on_disk),
                )
                msg = f"Ghidra bridge script verification failed at {script_path}"
                raise ToolError(msg)

            _logger.info(
                "file_written",
                path=str(script_path),
                data_size=len(on_disk),
            )
            self._bridge_script_path = script_path

        return script_path

    def create_bridge_script(self) -> Path:
        """Create the Ghidra bridge startup script.

        Returns:
            Path: Path to the created script.
        """
        _logger.info("ghidra_create_bridge_script_started")
        return self._create_bridge_script()

    @property
    def bridge_script_path(self) -> Path | None:
        """The current bridge script path.

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
            ToolError: If the file does not exist, if the remote importFile
                call fails, if Ghidra reports that no program was produced,
                or if metadata extraction from the loaded program fails.
        """
        if not await asyncio.to_thread(path.exists):
            error_message = f"{_ERR_FILE_NOT_FOUND}: {path}"
            raise ToolError(error_message)

        self._binary_path = await asyncio.to_thread(path.resolve)

        if self._bridge is not None:
            safe_path = json.dumps(path.as_posix())
            try:
                import_result = await self._execute_remote(
                    "import java.io.File as _JFile\n"
                    f"prog = importFile(_JFile({safe_path}))\n"
                    "if prog is None:\n"
                    "    {'imported': False}\n"
                    "else:\n"
                    "    state.setCurrentProgram(prog)\n"
                    "    {'imported': True, 'name': prog.getName()}\n",
                )
            except ToolError:
                _logger.exception("ghidra_remote_import_failed", binary_path=str(path))
                raise
            except Exception as exc:
                _logger.exception("ghidra_remote_import_failed", binary_path=str(path))
                msg = f"{_ERR_IMPORT_FILE_FAILED}: {exc}"
                raise ToolError(msg) from exc

            if not isinstance(import_result, dict) or not bool(
                cast("dict[str, Any]", import_result).get("imported", False),
            ):
                msg = f"{_ERR_IMPORT_FILE_FAILED}: Ghidra returned no program for {path}"
                raise ToolError(msg)

        data = await asyncio.to_thread(path.read_bytes)
        sha256 = hashlib.sha256(data).hexdigest()

        file_type = self._detect_format(data)
        arch, is_64 = await self._resolve_architecture(data)

        entry_point = 0
        sections: list[SectionInfo] = []
        imports: list[ImportInfo] = []
        exports: list[ExportInfo] = []

        if self._bridge is not None:
            try:
                entry_point, sections, imports, exports = await self._extract_binary_metadata()
            except Exception as exc:
                _logger.exception("ghidra_metadata_extraction_failed", binary_path=str(path))
                self.state.binary_loaded = False
                self.state.target_path = None
                self.state.last_error = str(exc)
                msg = f"Ghidra metadata extraction failed: {exc}"
                raise ToolError(msg) from exc

        self.state.connected = True
        self.state.tool_running = True
        self.state.binary_loaded = True
        self.state.target_path = self._binary_path

        _logger.info("binary_loaded", path=path.name)

        return BinaryInfo(
            path=self._binary_path,
            name=path.name,
            size=len(data),
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
        """Detect binary format from magic bytes.

        Delegates to :func:`detect_format` in ``bridges/pe_format`` for
        the shared magic-byte comparison.

        Args:
            data: Binary data.

        Returns:
            str: Format string (``"pe"``, ``"elf"``, ``"macho"``,
            ``"zip"``, or ``"raw"``).
        """
        return detect_format(data)

    @staticmethod
    def _detect_architecture(data: bytes) -> tuple[str, bool]:
        """Detect CPU architecture from raw header bytes.

        Covers PE (x86, x86_64, ARM, ARM64, IA64, MIPS, PPC, RISC-V),
        ELF (x86, x86_64, ARM, AArch64, MIPS, PPC/PPC64, RISC-V), and
        Mach-O (x86, x86_64, ARM, ARM64, PPC/PPC64) binaries.
        Delegates to :func:`detect_format_and_arch` in
        ``bridges/pe_format`` (which itself uses
        :func:`pe_machine_to_arch` for the canonical
        ``IMAGE_FILE_MACHINE_*`` table) and discards the format component
        to preserve the historical ``(arch, is_64bit)`` shape.

        Args:
            data: Binary data.

        Returns:
            tuple[str, bool]: Tuple of (architecture, is_64bit).
        """
        _fmt, arch, is_64bit = detect_format_and_arch(data)
        return arch, is_64bit

    async def _query_ghidra_arch(self) -> tuple[str, bool] | None:
        """Query the active Ghidra program for its architecture via RPC.

        Returns:
            tuple[str, bool] | None: Tuple of (architecture name, is_64bit),
            or None if Ghidra is not connected or if the query fails.
        """
        if self._bridge is None:
            return None
        try:
            result = await self._execute_remote(
                "lang = currentProgram.getLanguage()\n"
                "proc = str(lang.getProcessor()) if lang is not None else ''\n"
                "psize = int(lang.getDefaultSpace().getPointerSize()) if lang is not None else 0\n"
                "{'processor': proc, 'pointer_size': psize}\n",
            )
        except ToolError:
            _logger.warning("ghidra_arch_query_tool_error")
            return None
        except Exception:
            _logger.exception("ghidra_arch_query_failed")
            return None
        if not isinstance(result, dict):
            return None
        arch_info = cast("dict[str, Any]", result)
        processor = str(arch_info.get("processor", "")).lower()
        pointer_size = int(arch_info.get("pointer_size", 0))
        is_64 = pointer_size >= _ARCH_64_POINTER_BYTES
        if processor in {"", "unknown"}:
            return None
        if "x86" in processor or "intel" in processor:
            return ("x86_64", True) if is_64 else ("x86", False)
        if "aarch64" in processor or ("arm" in processor and is_64):
            return "arm64", True
        if "arm" in processor:
            return "arm", False
        if "mips" in processor:
            return ("mips64", True) if is_64 else ("mips", False)
        if "powerpc" in processor or "ppc" in processor:
            return ("ppc64", True) if is_64 else ("ppc", False)
        if "riscv" in processor or "risc-v" in processor:
            return ("riscv64", True) if is_64 else ("riscv", False)
        if "sparc" in processor:
            return ("sparc64", True) if is_64 else ("sparc", False)
        return processor, is_64

    async def _resolve_architecture(self, data: bytes) -> tuple[str, bool]:
        """Resolve architecture by combining header parsing with a Ghidra query.

        Args:
            data: Binary data.

        Returns:
            tuple[str, bool]: Tuple of (architecture, is_64bit).
        """
        header_arch, header_is_64 = self._detect_architecture(data)
        if header_arch == "unknown":
            queried = await self._query_ghidra_arch()
            if queried is not None:
                return queried
        return header_arch, header_is_64

    async def analyze(self) -> None:
        """Run full Ghidra analysis and block until every analyser pass completes.

        ``GhidraScript.analyzeAll`` only schedules pending analyses; it
        does not wait for the asynchronous analyzers to finish. Callers
        that immediately query symbols/functions afterwards observe a
        partially-analysed program. This implementation invokes
        ``analyzeAll`` and then blocks on
        ``AutoAnalysisManager.waitForAnalysis`` so the method only
        returns once Ghidra reports the program fully analysed.

        Raises:
            ToolError: If Ghidra is not connected or analysis fails.
        """
        if self._bridge is None:
            _logger.error("ghidra_not_connected")
            error_message = _ERR_NOT_CONNECTED
            raise ToolError(error_message)

        _logger.info("ghidra_analysis_started", bridge="ghidra")
        analyze_script = textwrap.dedent(
            """
            from ghidra.app.plugin.core.analysis import AutoAnalysisManager
            analyzeAll(currentProgram)
            mgr = AutoAnalysisManager.getAnalysisManager(currentProgram)
            mgr.waitForAnalysis(None, monitor)
            """,
        )
        try:
            await self._execute_remote(analyze_script)
        except ToolError:
            _logger.warning("ghidra_analysis_failed", phase="wait_for_analysis")
            raise
        except Exception as exc:
            _logger.warning("ghidra_analysis_failed", phase="wait_for_analysis", error=str(exc))
            error_message = f"Analysis failed: {exc}"
            raise ToolError(error_message) from exc

        _logger.info(
            "ghidra_analysis_complete",
            bridge="ghidra",
            phase="wait_for_analysis_returned",
        )

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
        _logger.info("ghidra_get_functions_started", filter_pattern=filter_pattern)
        if self._bridge is None:
            _logger.error("ghidra_not_connected", operation="get_functions")
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(
                """
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
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_functions_failed", filter_pattern=filter_pattern)
            error_message = f"Get functions failed: {exc}"
            raise ToolError(error_message) from exc

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

        return functions

    async def get_function(self, address: int) -> FunctionInfo | None:
        """Get function at a specific address.

        Args:
            address: Function address.

        Returns:
            FunctionInfo | None: Function info or None if not found.

        Raises:
            ToolError: If Ghidra is not connected or the remote call fails.
        """
        _logger.debug("ghidra_get_function_started", address=hex(address))
        if self._bridge is None:
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(
                f"""
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
                    _func_info = {{
                        'name': func.getName(),
                        'address': func.getEntryPoint().getOffset(),
                        'size': func.getBody().getNumAddresses(),
                        'calling_convention': func.getCallingConventionName(),
                        'return_type': str(func.getReturnType()),
                        'parameters': params,
                        'variables': vars,
                    }}
                else:
                    _func_info = None
                _func_info
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_function_failed", address=hex(address))
            error_message = f"Get function failed: {exc}"
            raise ToolError(error_message) from exc

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

    async def decompile(self, address: int) -> str:
        """Decompile function at address.

        Applies the bridge-level decompiler configuration (set via
        :meth:`set_decompiler_options`) to the ``DecompInterface``
        before invoking decompilation. The decompiler outcome is
        captured in module-level Jython variables on the bridge server,
        then read back through ``remote_eval`` so the client can
        distinguish "function not found", decompiler failure, and
        success - and raise :class:`ToolError` instead of returning an
        opaque "Decompilation failed" sentinel string.

        Args:
            address: Function address.

        Returns:
            str: Decompiled C pseudocode.

        Raises:
            ToolError: If Ghidra is not connected, no function exists at
                ``address``, decompilation does not complete, or the
                remote call fails.
        """
        _logger.debug("ghidra_decompile_started", address=hex(address))
        if self._bridge is None:
            raise ToolError(_ERR_NOT_CONNECTED)

        simp_literal = json.dumps(self._decompiler_simplification) if self._decompiler_simplification is not None else "None"
        max_instr_literal = str(self._decompiler_max_instructions) if self._decompiler_max_instructions is not None else "None"
        extra_literal = json.dumps(self._decompiler_options_extra)
        try:
            result = await self._execute_remote(
                f"""
                import json as _json
                from ghidra.app.decompiler import DecompInterface

                ifc = DecompInterface()
                ifc.openProgram(currentProgram)
                opts = ifc.getOptions()
                simp = {simp_literal}
                max_instr = {max_instr_literal}
                extra_data = _json.loads({json.dumps(extra_literal)})
                if simp is not None:
                    opts.setSimplificationStyle(simp)
                if max_instr is not None:
                    opts.setMaxInstructions(max_instr)
                for key, value in extra_data.items():
                    try:
                        if hasattr(opts, 'setOption'):
                            opts.setOption(key, str(value))
                    except Exception:
                        pass
                ifc.setOptions(opts)

                addr = toAddr({address})
                func = getFunctionContaining(addr)

                if func is None:
                    _decompile_outcome = {{'status': 'function_not_found', 'code': None, 'error': None}}
                else:
                    results = ifc.decompileFunction(func, {self.DECOMPILE_TIMEOUT_SECONDS}, monitor)
                    if results.decompileCompleted():
                        _decompile_outcome = {{
                            'status': 'ok',
                            'code': results.getDecompiledFunction().getC(),
                            'error': None,
                        }}
                    else:
                        _decompile_outcome = {{
                            'status': 'decompile_failed',
                            'code': None,
                            'error': str(results.getErrorMessage()) if results.getErrorMessage() else None,
                        }}
                _decompile_outcome
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.warning("ghidra_decompilation_failed", address=hex(address), error=str(exc))
            msg = f"Decompilation failed: {exc}"
            raise ToolError(msg) from exc

        if not isinstance(result, dict):
            msg = "Decompilation failed: unexpected response from Ghidra"
            raise ToolError(msg)

        outcome = cast("dict[str, Any]", result)
        status = str(outcome.get("status", ""))
        if status == "ok":
            code = outcome.get("code")
            if not isinstance(code, str) or not code:
                msg = "Decompilation produced empty output"
                raise ToolError(msg)
            return code
        if status == "function_not_found":
            msg = f"{_ERR_FUNCTION_NOT_FOUND}: {hex(address)}"
            raise ToolError(msg)
        error_detail = outcome.get("error")
        msg = f"Decompilation failed at {hex(address)}: {error_detail or 'unknown error'}"
        raise ToolError(msg)

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
            ToolError: If Ghidra is not connected or the remote call fails.
        """
        _logger.debug("ghidra_disassemble_started", address=hex(address), count=count)
        if self._bridge is None:
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(
                f"""
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
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("disassembly_failed", address=hex(address), count=count)
            error_message = f"Disassembly failed at {hex(address)}: {exc}"
            raise ToolError(error_message) from exc

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

    async def get_xrefs_to(self, address: int) -> list[CrossReference]:
        """Get cross-references to an address.

        Args:
            address: Target address.

        Returns:
            list[CrossReference]: List of cross-references.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        _logger.debug("ghidra_get_xrefs_to_started", address=hex(address))
        if self._bridge is None:
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(
                f"""
                xrefs = []
                addr = toAddr({address})

                for ref in getReferencesTo(addr):
                    from_addr = ref.getFromAddress()
                    from_func = getFunctionContaining(from_addr)
                    to_func = getFunctionContaining(addr)
                    xrefs.append({{
                        'from': from_addr.getOffset(),
                        'to': addr.getOffset(),
                        'type': str(ref.getReferenceType()),
                        'from_function': from_func.getName() if from_func is not None else None,
                        'to_function': to_func.getName() if to_func is not None else None,
                    }})

                xrefs
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_xrefs_to_failed", address=hex(address))
            error_message = f"Get xrefs to failed at {hex(address)}: {exc}"
            raise ToolError(error_message) from exc

        result_list = cast("list[dict[str, Any]]", result) if result else []
        return [self._build_cross_reference(x) for x in result_list]

    async def get_xrefs_from(self, address: int) -> list[CrossReference]:
        """Get cross-references from an address.

        Args:
            address: Source address.

        Returns:
            list[CrossReference]: List of cross-references.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        _logger.debug("ghidra_get_xrefs_from_started", address=hex(address))
        if self._bridge is None:
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(
                f"""
                xrefs = []
                addr = toAddr({address})

                for ref in getReferencesFrom(addr):
                    to_addr = ref.getToAddress()
                    from_func = getFunctionContaining(addr)
                    to_func = getFunctionContaining(to_addr)
                    xrefs.append({{
                        'from': addr.getOffset(),
                        'to': to_addr.getOffset(),
                        'type': str(ref.getReferenceType()),
                        'from_function': from_func.getName() if from_func is not None else None,
                        'to_function': to_func.getName() if to_func is not None else None,
                    }})

                xrefs
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_xrefs_from_failed", address=hex(address))
            error_message = f"Get xrefs from failed at {hex(address)}: {exc}"
            raise ToolError(error_message) from exc

        result_list = cast("list[dict[str, Any]]", result) if result else []
        return [self._build_cross_reference(x) for x in result_list]

    @staticmethod
    def _build_cross_reference(payload: dict[str, Any]) -> CrossReference:
        """Construct a ``CrossReference`` from a Ghidra xref payload.

        Preserves the full reference taxonomy returned by Ghidra (call,
        jump, read, write, data) and surfaces ``from_function`` /
        ``to_function`` enrichment captured by the remote script.

        Args:
            payload: Dict produced by the remote Jython script with keys
                ``from``, ``to``, ``type``, ``from_function``, and
                ``to_function``.

        Returns:
            CrossReference: Populated cross-reference instance.
        """
        from_function_raw = payload.get("from_function")
        to_function_raw = payload.get("to_function")
        from_function = str(from_function_raw) if from_function_raw is not None else None
        to_function = str(to_function_raw) if to_function_raw is not None else None
        return CrossReference(
            from_address=int(payload.get("from", 0)),
            to_address=int(payload.get("to", 0)),
            ref_type=_map_ghidra_ref_type(str(payload.get("type", ""))),
            from_function=from_function,
            to_function=to_function,
        )

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
        _logger.debug("ghidra_search_strings_started", pattern=pattern, encoding=encoding)
        if self._bridge is None:
            _logger.error("ghidra_not_connected")
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        encoding_filter = json.dumps(encoding)
        try:
            result = await self._execute_remote(
                f"""
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
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("string_search_failed", pattern=pattern)
            error_message = f"String search failed for {pattern!r}: {exc}"
            raise ToolError(error_message) from exc

        normalized_encoding: Literal["ascii", "utf-8", "utf-16le", "utf-16be"] = (
            "ascii"
            if encoding == "ascii"
            else "utf-8"
            if encoding in {"utf-8", "utf8"}
            else "utf-16le"
            if encoding in {"utf-16", "utf-16-le", "utf-16le"}
            else "utf-16be"
            if encoding in {"utf-16-be", "utf-16be"}
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

    @staticmethod
    def _parse_hex_search_pattern(raw_hex: str) -> tuple[list[int], list[int]]:
        """Parse a wildcarded hex pattern into Java-signed byte/mask arrays.

        Splits the input on whitespace when any whitespace is present,
        otherwise reads two-hex-digit tokens. ``??`` / ``?`` tokens
        produce a ``(0x00, 0x00)`` byte/mask pair; everything else must
        be exactly two hex digits and is converted to a ``(byte,
        0xFF)`` pair. The returned values are folded into the
        ``-128..127`` signed range Ghidra's ``jarray`` requires.

        Args:
            raw_hex: User-supplied hex pattern, optionally with ``??``
                wildcards.

        Returns:
            tuple[list[int], list[int]]: ``(byte_vals, mask_vals)``
            both already sign-folded for the remote ``jarray('b')``
            constructor.

        Raises:
            ToolError: If ``raw_hex`` is empty after trimming or
                contains a token that is neither ``??`` / ``?`` nor a
                pair of hex digits.
        """
        clean = raw_hex.strip()
        if not clean:
            _logger.warning("byte_search_invalid_hex", reason="empty")
            msg = "Hex pattern is empty"
            raise ToolError(msg)

        tokens = clean.split() if " " in clean else [clean[i : i + 2] for i in range(0, len(clean), 2)]
        byte_vals: list[int] = []
        mask_vals: list[int] = []
        for tok in tokens:
            if tok in {"??", "?"}:
                b = 0x00
                m = 0x00
            else:
                if len(tok) != _HEX_TOKEN_LENGTH or any(ch not in string.hexdigits for ch in tok):
                    _logger.warning("byte_search_invalid_hex", token=tok)
                    msg = f"Malformed hex token in pattern: {tok!r}"
                    raise ToolError(msg)
                b = int(tok, 16)
                m = 0xFF
            bj = (b - 256) if b > _JAVA_SIGNED_THRESHOLD else b
            mj = (m - 256) if m > _JAVA_SIGNED_THRESHOLD else m
            byte_vals.append(bj)
            mask_vals.append(mj)
        return byte_vals, mask_vals

    async def search_bytes(
        self,
        pattern: bytes | str | None = None,
        *,
        hex_pattern: str | None = None,
    ) -> list[int]:
        """Search for a byte pattern in the binary, with optional wildcard mask support.

        Hex tokens are validated before being shipped to Ghidra: any
        token that is not ``??`` / ``?`` and does not parse as a single
        byte (``00``..``FF``) raises :class:`ToolError`. Empty hex input
        also raises ``ToolError`` because an empty needle would
        otherwise match every byte in the program.

        Args:
            pattern: Bytes to find (exact match) or hex string pattern.
            hex_pattern: Hex string with optional '??' wildcards (e.g. '48 8B ?? ?? ?? ??').

        Returns:
            list[int]: List of addresses where the pattern was found.

        Raises:
            ToolError: If Ghidra is not connected, the supplied hex
                pattern is empty, or it contains malformed tokens.
        """
        if self._bridge is None:
            _logger.error("ghidra_not_connected")
            error_message = _ERR_NOT_CONNECTED
            raise ToolError(error_message)

        _logger.debug("byte_search_starting", has_hex_pattern=hex_pattern is not None)

        if hex_pattern is not None:
            raw_hex = hex_pattern
        elif isinstance(pattern, str):
            raw_hex = pattern
        else:
            raw_hex = None

        if raw_hex is not None:
            byte_vals, mask_vals = self._parse_hex_search_pattern(raw_hex)
            byte_arr_str = ", ".join(str(v) for v in byte_vals)
            mask_arr_str = ", ".join(str(v) for v in mask_vals)

            try:
                result = await self._execute_remote(
                    f"""
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
                    """,
                )
            except ToolError:
                raise
            except Exception as exc:
                _logger.exception("byte_search_failed_hex", pattern_length=len(byte_vals))
                error_message = f"Byte search (hex/wildcard) failed: {exc}"
                raise ToolError(error_message) from exc

            if not isinstance(result, list):
                return []
            return [int(addr) for addr in cast("list[int | float | str]", result)]

        raw_bytes = pattern if isinstance(pattern, bytes) else b""
        try:
            byte_list_str = ", ".join(str(b) for b in raw_bytes)
            result = await self._execute_remote(
                f"""
                addresses = []
                memory = currentProgram.getMemory()
                start = memory.getMinAddress()
                end = memory.getMaxAddress()
                searcher = memory.findBytes(start, end, [{byte_list_str}], None, True, monitor)
                while searcher is not None:
                    addresses.append(searcher.getOffset())
                    searcher = memory.findBytes(searcher.add(1), end, [{byte_list_str}], None, True, monitor)
                addresses
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("byte_search_failed", pattern_length=len(raw_bytes))
            error_message = f"Byte search failed: {exc}"
            raise ToolError(error_message) from exc

        if not isinstance(result, list):
            return []
        return [int(addr) for addr in cast("list[int | float | str]", result)]

    async def rename_function(self, address: int, new_name: str) -> bool:
        """Rename a function.

        After ``Function.setName`` returns, the bridge re-queries the
        function at ``address`` via ``remote_eval`` and verifies that
        ``getName()`` matches ``new_name``. This catches the previous
        failure mode where ``setName`` rejected an invalid name (empty
        string, namespace conflict, identifier clash) but the bridge
        still reported success.

        Args:
            address: Function address.
            new_name: New name.

        Returns:
            bool: True if renamed.

        Raises:
            ToolError: If Ghidra is not connected, no function exists
                at ``address``, the rename call fails, or the readback
                does not show the new name.
        """
        if self._bridge is None:
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = _ERR_NOT_CONNECTED
            raise ToolError(error_message)

        try:
            await self._execute_remote(
                textwrap.dedent(
                    f"""
                    from ghidra.program.model.symbol import SourceType

                    addr = toAddr({address})
                    func = getFunctionContaining(addr)
                    if func is None:
                        raise RuntimeError('No function at ' + str(addr))
                    func.setName({json.dumps(new_name)}, SourceType.USER_DEFINED)
                    """,
                ),
            )
        except ToolError:
            raise
        except Exception as e:
            _logger.warning("ghidra_rename_failed", address=hex(address), error=str(e))
            error_message = f"Rename failed: {e}"
            raise ToolError(error_message) from e

        try:
            readback = await self._execute_remote_eval(
                f"(lambda f: f.getName() if f is not None else None)(getFunctionContaining(toAddr({address})))",
            )
        except ToolError:
            raise
        except Exception as e:
            _logger.warning("ghidra_rename_readback_failed", address=hex(address), error=str(e))
            error_message = f"Rename readback failed: {e}"
            raise ToolError(error_message) from e

        observed = None if readback is None else str(readback)
        if observed != new_name:
            _logger.error(
                "ghidra_rename_verification_failed",
                address=hex(address),
                expected_name=new_name,
                observed_name=observed,
            )
            msg = f"Rename verification failed at {hex(address)}: expected {new_name!r}, observed {observed!r}"
            raise ToolError(msg)

        _logger.info("function_renamed", address=hex(address), new_name=new_name)
        return True

    async def add_comment(
        self,
        address: int,
        comment: str,
        comment_type: str = "EOL",
    ) -> bool:
        """Add a comment at an address.

        After issuing ``CodeUnit.setComment`` the bridge re-queries the
        same comment slot via ``remote_eval`` and verifies the stored
        value matches ``comment``. This catches the previous failure
        mode where the address resolved to a code unit boundary that
        Ghidra silently dropped the comment on, or where no code unit
        existed at all.

        Args:
            address: Address.
            comment: Comment text.
            comment_type: Type of comment.

        Returns:
            bool: True if added.

        Raises:
            ToolError: If Ghidra is not connected, no code unit exists
                at ``address``, the write fails, or the readback does
                not match the requested comment.
        """
        if self._bridge is None:
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = _ERR_NOT_CONNECTED
            raise ToolError(error_message)

        comment_map = {
            "EOL": "CodeUnit.EOL_COMMENT",
            "PRE": "CodeUnit.PRE_COMMENT",
            "POST": "CodeUnit.POST_COMMENT",
            "PLATE": "CodeUnit.PLATE_COMMENT",
            "REPEATABLE": "CodeUnit.REPEATABLE_COMMENT",
        }
        ghidra_type = comment_map.get(comment_type)
        if ghidra_type is None:
            _logger.error("ghidra_unknown_comment_type", address=hex(address), comment_type=comment_type)
            error_message = f"Unknown comment_type {comment_type!r}: must be one of {sorted(comment_map)}"
            raise ToolError(error_message)

        try:
            await self._execute_remote(
                textwrap.dedent(
                    f"""
                    from ghidra.program.model.listing import CodeUnit

                    addr = toAddr({address})
                    cu = currentProgram.getListing().getCodeUnitAt(addr)
                    if cu is None:
                        raise RuntimeError('No code unit at ' + str(addr))
                    cu.setComment({ghidra_type}, {json.dumps(comment)})
                    """,
                ),
            )
        except ToolError:
            raise
        except Exception as e:
            _logger.warning("ghidra_add_comment_failed", address=hex(address), error=str(e))
            error_message = f"Add comment failed: {e}"
            raise ToolError(error_message) from e

        try:
            readback = await self._execute_remote_eval(
                textwrap.dedent(
                    f"""
                    (lambda cu: cu.getComment({ghidra_type}) if cu is not None else None)(
                        currentProgram.getListing().getCodeUnitAt(toAddr({address}))
                    )
                    """,
                ),
            )
        except ToolError:
            raise
        except Exception as e:
            _logger.warning("ghidra_add_comment_readback_failed", address=hex(address), error=str(e))
            error_message = f"Add comment readback failed: {e}"
            raise ToolError(error_message) from e

        observed = "" if readback is None else str(readback)
        if observed != comment:
            _logger.error(
                "ghidra_add_comment_verification_failed",
                address=hex(address),
                comment_type=comment_type,
                expected_length=len(comment),
                observed_length=len(observed),
            )
            msg = f"Comment verification failed at {hex(address)}: comment did not round-trip"
            raise ToolError(msg)

        _logger.info("comment_added", address=hex(address), comment_type=comment_type)
        return True

    async def get_imports(self) -> list[ImportInfo]:
        """Get imported functions.

        Returns:
            list[ImportInfo]: List of imports.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        _logger.debug("ghidra_get_imports_started")
        if self._bridge is None:
            _logger.error("ghidra_not_connected")
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(
                """
                imports = []
                st = currentProgram.getSymbolTable()

                for sym in st.getExternalSymbols():
                    imports.append({
                        'dll': str(sym.getParentSymbol().getName()) if sym.getParentSymbol() else '',
                        'function': sym.getName(),
                        'address': sym.getAddress().getOffset(),
                    })

                imports
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_imports_failed", binary_path=str(self._binary_path))
            error_message = f"Get imports failed: {exc}"
            raise ToolError(error_message) from exc

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

    async def get_exports(self) -> list[ExportInfo]:
        """Get exported functions.

        Returns:
            list[ExportInfo]: List of exports.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        _logger.debug("ghidra_get_exports_started")
        if self._bridge is None:
            _logger.error("ghidra_not_connected")
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(
                """
                exports = []
                st = currentProgram.getSymbolTable()

                for sym in st.getAllSymbols(True):
                    if sym.isExternalEntryPoint():
                        exports.append({
                            'name': sym.getName(),
                            'address': sym.getAddress().getOffset(),
                        })

                exports
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_exports_failed", binary_path=str(self._binary_path))
            error_message = f"Get exports failed: {exc}"
            raise ToolError(error_message) from exc

        result_list = cast("list[dict[str, Any]]", result) if result else []
        return [
            ExportInfo(
                name=str(e.get("name", "")),
                ordinal=idx,
                address=int(e.get("address", 0)),
            )
            for idx, e in enumerate(result_list)
        ]

    async def get_data_type(self, address: int) -> DataTypeInfo | None:
        """Get data type at address via Ghidra DataTypeManager.

        Args:
            address: Address to check.

        Returns:
            DataTypeInfo | None: DataTypeInfo if data is defined, otherwise None.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        _logger.debug("ghidra_get_data_type_started", address=hex(address))
        if self._bridge is None:
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(
                f"""
                from ghidra.program.model.data import Pointer, Array

                addr = toAddr({address})
                data = currentProgram.getListing().getDataAt(addr)
                if data is None:
                    _dt_payload = None
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
                    _dt_payload = {{
                        'address': data.getAddress().getOffset(),
                        'name': dt.getName(),
                        'category': dt.getCategoryPath().getPath(),
                        'size': int(dt.getLength()) if dt.getLength() >= 0 else 0,
                        'is_pointer': bool(is_pointer),
                        'is_array': bool(is_array),
                        'array_length': array_length,
                        'base_type': base_type,
                    }}
                _dt_payload
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_data_type_failed", address=hex(address))
            error_message = f"Get data type failed at {hex(address)}: {exc}"
            raise ToolError(error_message) from exc

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
            _logger.error("ghidra_not_connected", address=hex(address))
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

        After issuing ``createLabel`` the bridge re-queries
        ``SymbolTable.getSymbols(addr)`` via ``remote_eval`` and verifies
        that the requested name appears among the labels actually
        attached to ``address``. This catches the previous failure mode
        where ``createLabel`` rejected an invalid name (empty string,
        duplicate primary label, etc.) but the bridge still reported
        ``success: True``.

        Args:
            address: Address for the label.
            name: Label name.

        Returns:
            dict[str, Any]: Dict with address, name, and success status.

        Raises:
            ToolError: If Ghidra is not connected, the create call
                fails, or the readback does not include ``name`` among
                the symbols at ``address``.
        """
        if self._bridge is None:
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = _ERR_NOT_CONNECTED
            raise ToolError(error_message)

        _logger.debug("label_setting", address=hex(address), label_name=name)
        try:
            await self._execute_remote(
                textwrap.dedent(
                    f"""
                    from ghidra.program.model.symbol import SourceType
                    addr = toAddr({address})
                    st = currentProgram.getSymbolTable()
                    st.createLabel(addr, {json.dumps(name)}, SourceType.USER_DEFINED)
                    """,
                ),
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.warning("ghidra_set_label_failed", address=hex(address), label_name=name, error=str(exc))
            error_message = f"Set label failed: {exc}"
            raise ToolError(error_message) from exc

        try:
            readback = await self._execute_remote_eval(
                f"[s.getName() for s in currentProgram.getSymbolTable().getSymbols(toAddr({address}))]",
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.warning("ghidra_set_label_readback_failed", address=hex(address), error=str(exc))
            error_message = f"Set label readback failed: {exc}"
            raise ToolError(error_message) from exc

        names = [str(item) for item in cast("list[Any]", readback)] if isinstance(readback, list) else []
        if name not in names:
            _logger.error(
                "ghidra_set_label_verification_failed",
                address=hex(address),
                expected_name=name,
                observed_names=names,
            )
            msg = f"Label verification failed at {hex(address)}: expected {name!r}, observed {names!r}"
            raise ToolError(msg)

        _logger.info("ghidra_label_set_verified", address=hex(address), label_name=name)
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
        _logger.debug("ghidra_get_labels_started", address=hex(address), radius=radius)
        if self._bridge is None:
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(
                f"""
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
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_labels_failed", address=hex(address))
            error_message = f"Get labels failed at {hex(address)}: {exc}"
            raise ToolError(error_message) from exc

        return cast("list[dict[str, Any]]", result) if result else []

    async def _execute_remote(self, code: str) -> object:
        """Execute Jython code on the Ghidra bridge and return any trailing expression value.

        Dedents the supplied code via :func:`textwrap.dedent` so call-site
        indentation does not propagate into the remote ``exec()`` payload.
        Parses the dedented script with :mod:`ast`; if the final top-level
        statement is an :class:`ast.Expr`, rewrites it into an assignment to
        a unique sentinel variable and dispatches the rewritten script via
        the underlying ``ghidra_bridge`` ``remote_exec`` channel. The
        sentinel is then read back via ``remote_eval`` so the caller
        receives the expression value Jython produced.

        Scripts that have no trailing expression (purely side-effect
        statements such as ``analyzeAll(currentProgram)``) execute via
        ``remote_exec`` only and return ``None``.

        Args:
            code: Jython source to execute on the Ghidra side. May be a
                single expression, a multi-statement block, or a
                multi-statement block ending in a value-producing
                expression.

        Returns:
            object: Deserialized result of the trailing expression, or
            ``None`` when the script has no trailing expression.

        Raises:
            ToolError: If the bridge is not connected, the underlying
                ``ghidra_bridge`` client is missing the required RPC
                primitives, the Jython source fails to parse on the
                client, or the remote execution / evaluation raises.
        """
        if self._bridge is None:
            error_message = "Ghidra bridge not connected"
            raise ToolError(error_message)

        remote_exec_attr = getattr(self._bridge, "remote_exec", None)
        if remote_exec_attr is None:
            error_message = "Ghidra bridge missing remote_exec"
            raise ToolError(error_message)
        remote_eval_attr = getattr(self._bridge, "remote_eval", None)
        if remote_eval_attr is None:
            error_message = "Ghidra bridge missing remote_eval"
            raise ToolError(error_message)
        remote_exec = cast("_RemoteExecFunc", remote_exec_attr)
        remote_eval = cast("_RemoteEvalFunc", remote_eval_attr)

        exec_source, sentinel = prepare_remote_script(code)

        try:
            await asyncio.to_thread(remote_exec, exec_source)
        except Exception as exc:
            _logger.exception("ghidra_remote_exec_failed")
            error_message = f"Remote execution failed: {exc}"
            raise ToolError(error_message) from exc

        if sentinel is None:
            return None

        try:
            return await asyncio.to_thread(remote_eval, sentinel)
        except Exception as exc:
            _logger.exception("ghidra_remote_eval_failed", sentinel=sentinel)
            error_message = f"Remote evaluation failed: {exc}"
            raise ToolError(error_message) from exc

    async def _execute_remote_eval(self, expression: str) -> object:
        """Evaluate a single Jython expression remotely and return its value.

        ``remote_eval`` ships a single expression to the bridge server and
        returns the evaluated result, in contrast to ``remote_exec`` which
        always returns ``None``. This is the canonical primitive for
        readback verification: after a write, issue an eval that reads the
        property back so the client can compare it to the requested value.

        The expression is dedented before transmission so callers can
        embed multi-line conditional expressions inside f-strings without
        triggering ``IndentationError`` on the remote ``compile``.

        Args:
            expression: A single Jython expression evaluated on the
                Ghidra bridge server. Must not be a statement.

        Returns:
            object: The value the expression evaluates to on the server.

        Raises:
            ToolError: If the bridge is not connected, the bridge runtime
                does not expose ``remote_eval``, or the server raises
                while evaluating.
        """
        if self._bridge is None:
            raise ToolError(_ERR_NOT_CONNECTED)

        remote_eval_attr = getattr(self._bridge, "remote_eval", None)
        if remote_eval_attr is None:
            error_message = "Ghidra bridge missing remote_eval"
            raise ToolError(error_message)
        remote_eval = cast("_RemoteEvalFunc", remote_eval_attr)

        dedented = textwrap.dedent(expression).strip()
        try:
            return await asyncio.to_thread(remote_eval, dedented)
        except Exception as exc:
            _logger.exception("ghidra_remote_eval_failed")
            error_message = f"Remote eval failed: {exc}"
            raise ToolError(error_message) from exc


class _GhidraBridgeAnalysisMixin(_GhidraBridgeBase):
    """Bookmark, structure, symbol, and program-metadata surface for the Ghidra bridge."""

    async def create_bookmark(
        self,
        address: int,
        category: str,
        comment: str,
        bookmark_type: str = "Note",
    ) -> dict[str, Any]:
        """Create an analysis bookmark at an address.

        After ``BookmarkManager.setBookmark`` returns, the bridge
        re-queries ``getBookmarks(addr, type)`` via ``remote_eval`` and
        verifies the requested ``category`` and ``comment`` round-trip.

        Args:
            address: Address to bookmark.
            category: Bookmark category.
            comment: Bookmark comment text.
            bookmark_type: Bookmark type (Note, Analysis, Error, Warning, Info).

        Returns:
            dict[str, Any]: Dict with address, category, comment, bookmark_type, and success status.

        Raises:
            ToolError: If Ghidra is not connected, the bookmark write
                fails, or the readback does not include the requested
                ``(category, comment)`` for ``bookmark_type``.
        """
        if self._bridge is None:
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = _ERR_NOT_CONNECTED
            raise ToolError(error_message)

        _logger.debug("bookmark_creating", address=hex(address), category=category, bookmark_type=bookmark_type)
        try:
            await self._execute_remote(
                textwrap.dedent(
                    f"""
                    bm = currentProgram.getBookmarkManager()
                    bm.setBookmark(toAddr({address}), {json.dumps(bookmark_type)}, {json.dumps(category)}, {json.dumps(comment)})
                    """,
                ),
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.warning("ghidra_create_bookmark_failed", address=hex(address), error=str(exc))
            error_message = f"Create bookmark failed: {exc}"
            raise ToolError(error_message) from exc

        try:
            readback = await self._execute_remote_eval(
                f"[(b.getCategory(), b.getComment()) "
                f"for b in currentProgram.getBookmarkManager().getBookmarks("
                f"toAddr({address}), {json.dumps(bookmark_type)})]",
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.warning("ghidra_create_bookmark_readback_failed", address=hex(address), error=str(exc))
            error_message = f"Create bookmark readback failed: {exc}"
            raise ToolError(error_message) from exc

        pairs: list[tuple[str, str]] = []
        if isinstance(readback, list):
            for entry in cast("list[Any]", readback):
                if not isinstance(entry, list | tuple):
                    continue
                seq = cast("list[Any] | tuple[Any, ...]", entry)
                if len(seq) < _BOOKMARK_READBACK_PAIR_LEN:
                    continue
                pairs.append((str(seq[0]), str(seq[1])))
        if (category, comment) not in pairs:
            _logger.error(
                "ghidra_create_bookmark_verification_failed",
                address=hex(address),
                bookmark_type=bookmark_type,
                expected_category=category,
                observed=pairs,
            )
            msg = f"Bookmark verification failed at {hex(address)}: ({category!r}, {comment!r}) not in {pairs!r}"
            raise ToolError(msg)

        _logger.info(
            "ghidra_bookmark_created_verified",
            address=hex(address),
            category=category,
            bookmark_type=bookmark_type,
        )
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
        _logger.debug("ghidra_get_bookmarks_started", category=category)
        if self._bridge is None:
            _logger.error("ghidra_not_connected")
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        cat_filter = json.dumps(category) if category else "None"
        try:
            result = await self._execute_remote(
                f"""
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
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_bookmarks_failed")
            error_message = f"Get bookmarks failed: {exc}"
            raise ToolError(error_message) from exc

        return cast("list[dict[str, Any]]", result) if result else []

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
            _logger.error("ghidra_not_connected", address=hex(address))
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
            _logger.warning("ghidra_create_function_failed", address=hex(address), error=str(e))
            error_message = f"Create function failed: {e}"
            raise ToolError(error_message) from e

        if result is None:
            error_message = f"Failed to create function at {hex(address)}"
            raise ToolError(error_message)
        return cast("dict[str, Any]", result)

    async def delete_function(self, address: int) -> dict[str, Any]:
        """Remove function definition at an address.

        Raises ``ToolError`` when no function is defined at the given
        address so callers never silently observe a no-op.

        Args:
            address: Function entry point address.

        Returns:
            dict[str, Any]: Dict with address, name of the deleted
            function, and success status.

        Raises:
            ToolError: If Ghidra is not connected, if no function exists
                at the address, or if deletion fails.
        """
        if self._bridge is None:
            raise ToolError(_ERR_NOT_CONNECTED)

        _logger.info("function_deleting", address=hex(address))
        try:
            result = await self._execute_remote(f"""
                addr = toAddr({address})
                fm = currentProgram.getFunctionManager()
                func = fm.getFunctionAt(addr)
                if func is None:
                    {{'exists': False, 'name': None, 'removed': False}}
                else:
                    name = func.getName()
                    tx_id = currentProgram.startTransaction('intellicrack.delete_function')
                    removed = False
                    try:
                        removed = bool(fm.removeFunction(func.getEntryPoint()))
                    finally:
                        currentProgram.endTransaction(tx_id, removed)
                    {{'exists': True, 'name': name, 'removed': removed}}
            """)
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("ghidra_delete_function_failed", address=hex(address))
            msg = f"Delete function failed: {exc}"
            raise ToolError(msg) from exc

        info = cast("dict[str, Any]", result) if isinstance(result, dict) else {}
        if not bool(info.get("exists", False)):
            msg = f"{_ERR_FUNCTION_NOT_FOUND}: {hex(address)}"
            raise ToolError(msg)
        if not bool(info.get("removed", False)):
            msg = f"Delete function failed: Ghidra refused removal at {hex(address)}"
            raise ToolError(msg)
        return {
            "address": hex(address),
            "name": str(info.get("name", "")),
            "success": True,
        }

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
            _logger.error("ghidra_not_connected", address=hex(address))
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
            _logger.warning(
                "ghidra_edit_function_signature_failed",
                address=hex(address),
                new_name=name,
                return_type=return_type,
                calling_convention=calling_convention,
                error=str(e),
            )
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
            _logger.error("ghidra_not_connected")
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
            _logger.warning(
                "ghidra_set_function_variable_type_failed",
                func_address=hex(func_address),
                var_name=var_name,
                new_type=new_type,
                error=str(e),
            )
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
            _logger.error("ghidra_not_connected")
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
            _logger.warning("ghidra_define_structure_failed", struct_name=name, error=str(e))
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
        _logger.debug("ghidra_get_structures_started", filter_name=filter_name)
        if self._bridge is None:
            _logger.error("ghidra_not_connected")
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        name_filter = json.dumps(filter_name) if filter_name else "None"
        try:
            result = await self._execute_remote(
                f"""
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
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_structures_failed")
            error_message = f"Get structures failed: {exc}"
            raise ToolError(error_message) from exc

        return cast("list[dict[str, Any]]", result) if result else []

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
            _logger.error("ghidra_not_connected", address=hex(address))
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
            _logger.warning(
                "ghidra_apply_structure_at_failed",
                address=hex(address),
                struct_name=struct_name,
                error=str(e),
            )
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
        _logger.debug("ghidra_get_memory_map_started")
        if self._bridge is None:
            _logger.error("ghidra_not_connected")
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(
                """
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
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_memory_map_failed")
            error_message = f"Get memory map failed: {exc}"
            raise ToolError(error_message) from exc

        return cast("list[dict[str, Any]]", result) if result else []

    async def get_call_graph(self, address: int, depth: int = 2) -> dict[str, Any]:
        """Get function call graph rooted at an address in both directions.

        Recursively traverses call references both outward (callees)
        and inward (callers) from the function containing the given
        address up to ``depth`` levels. Each direction is returned as
        a tree so the caller can walk the full bidirectional call
        relationship.

        Args:
            address: Root function address (or any address inside the
                root function).
            depth: Maximum recursion depth in each direction.

        Returns:
            dict[str, Any]: Dict with the root function name and
            address, plus ``callees`` and ``callers`` tree lists.

        Raises:
            ToolError: If Ghidra is not connected or the RPC fails.
        """
        _logger.debug("ghidra_get_call_graph_started", address=hex(address), depth=depth)
        if self._bridge is None:
            raise ToolError(_ERR_NOT_CONNECTED)

        try:
            result = await self._execute_remote(
                f"""
                def collect_callees(func, cur_depth, max_depth, visited):
                    offset = func.getEntryPoint().getOffset()
                    if cur_depth >= max_depth or offset in visited:
                        return {{'name': func.getName(), 'address': offset, 'callees': []}}
                    visited = set(visited)
                    visited.add(offset)
                    callees = []
                    seen_targets = set()
                    for target_func in func.getCalledFunctions(monitor):
                        if target_func is None:
                            continue
                        target_offset = target_func.getEntryPoint().getOffset()
                        if target_offset in seen_targets:
                            continue
                        seen_targets.add(target_offset)
                        callees.append(collect_callees(target_func, cur_depth + 1, max_depth, visited))
                    return {{'name': func.getName(), 'address': offset, 'callees': callees}}

                def collect_callers(func, cur_depth, max_depth, visited):
                    offset = func.getEntryPoint().getOffset()
                    if cur_depth >= max_depth or offset in visited:
                        return {{'name': func.getName(), 'address': offset, 'callers': []}}
                    visited = set(visited)
                    visited.add(offset)
                    callers = []
                    seen_sources = set()
                    for caller_func in func.getCallingFunctions(monitor):
                        if caller_func is None:
                            continue
                        caller_offset = caller_func.getEntryPoint().getOffset()
                        if caller_offset in seen_sources:
                            continue
                        seen_sources.add(caller_offset)
                        callers.append(collect_callers(caller_func, cur_depth + 1, max_depth, visited))
                    return {{'name': func.getName(), 'address': offset, 'callers': callers}}

                root_addr = toAddr({address})
                root_func = getFunctionContaining(root_addr)
                if root_func is None:
                    _call_graph_payload = None
                else:
                    callee_tree = collect_callees(root_func, 0, {depth}, set())
                    caller_tree = collect_callers(root_func, 0, {depth}, set())
                    _call_graph_payload = {{
                        'name': root_func.getName(),
                        'address': root_func.getEntryPoint().getOffset(),
                        'callees': callee_tree.get('callees', []),
                        'callers': caller_tree.get('callers', []),
                    }}
                _call_graph_payload
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("ghidra_get_call_graph_failed", address=hex(address))
            msg = f"Get call graph failed: {exc}"
            raise ToolError(msg) from exc

        if result is None:
            msg = f"{_ERR_FUNCTION_NOT_FOUND}: {hex(address)}"
            raise ToolError(msg)
        graph = cast("dict[str, Any]", result)
        return {
            "name": str(graph.get("name", "")),
            "address": int(graph.get("address", address)),
            "callees": cast("list[dict[str, Any]]", graph.get("callees", [])),
            "callers": cast("list[dict[str, Any]]", graph.get("callers", [])),
        }

    async def get_segments(self) -> list[dict[str, Any]]:
        """Get program segments with detailed permissions and attributes.

        Returns:
            list[dict[str, Any]]: List of segment dicts with name, addresses, permissions, and source info.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        _logger.debug("ghidra_get_segments_started")
        if self._bridge is None:
            _logger.error("ghidra_not_connected")
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(
                """
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
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_segments_failed")
            error_message = f"Get segments failed: {exc}"
            raise ToolError(error_message) from exc

        return cast("list[dict[str, Any]]", result) if result else []

    async def get_program_info(self) -> dict[str, Any]:
        """Get program metadata including language, compiler, and layout info.

        Returns:
            dict[str, Any]: Dict with language, compiler, endianness, pointer_size, image_base,
            and executable_format.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        _logger.debug("ghidra_get_program_info_started")
        if self._bridge is None:
            _logger.error("ghidra_not_connected")
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(
                """
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
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_program_info_failed")
            error_message = f"Get program info failed: {exc}"
            raise ToolError(error_message) from exc

        return cast("dict[str, Any]", result) if result else {}

    async def write_bytes(self, address: int, data: str) -> dict[str, Any]:
        """Patch bytes at an address in the program.

        Opens a Ghidra transaction, sign-folds every byte to the signed
        ``-128..127`` range Jython's ``jarray`` requires, writes via
        ``Memory.setBytes``, then reads the bytes back and compares them
        to the requested payload. The transaction is committed only when
        the readback matches; otherwise it is rolled back and a
        ``ToolError`` is raised.

        Args:
            address: Address to write at.
            data: Hex string of bytes (e.g. '90 90 90' or '909090').

        Returns:
            dict[str, Any]: Dict with address, bytes_written count,
            verified flag, and success.

        Raises:
            ToolError: If Ghidra is not connected, the hex input is
                malformed, the write fails, or readback verification
                fails.
        """
        if self._bridge is None:
            raise ToolError(_ERR_NOT_CONNECTED)

        clean_hex = data.replace(" ", "").replace(",", "")
        if not clean_hex or len(clean_hex) % 2 != 0:
            msg = f"Invalid hex payload: {data!r}"
            raise ToolError(msg)
        try:
            unsigned_bytes = [int(clean_hex[i : i + 2], 16) for i in range(0, len(clean_hex), 2)]
        except ValueError as exc:
            _logger.warning("ghidra_write_bytes_invalid_hex", error=str(exc))
            msg = f"Invalid hex payload: {exc}"
            raise ToolError(msg) from exc

        _logger.debug("bytes_writing", address=hex(address), data_length=len(unsigned_bytes))

        signed_bytes = [(b - _JAVA_SIGNED_RANGE) if b > _JAVA_SIGNED_THRESHOLD else b for b in unsigned_bytes]
        expected_list = list(unsigned_bytes)
        byte_list_str = ", ".join(str(b) for b in signed_bytes)
        length = len(unsigned_bytes)

        try:
            result = await self._execute_remote(f"""
                from jarray import array, zeros

                addr = toAddr({address})
                memory = currentProgram.getMemory()
                payload = array([{byte_list_str}], 'b')
                expected_length = {length}

                tx_id = currentProgram.startTransaction('intellicrack.write_bytes')
                commit_ok = False
                readback_hex = ''
                readback_bytes = []
                write_error = None
                try:
                    try:
                        memory.setBytes(addr, payload)
                    except Exception as _write_exc:
                        write_error = str(_write_exc)

                    buf = zeros(expected_length, 'b')
                    try:
                        memory.getBytes(addr, buf)
                        readback_bytes = [((b + 256) % 256) for b in buf]
                        readback_hex = ''.join('%02X' % v for v in readback_bytes)
                    except Exception as _read_exc:
                        if write_error is None:
                            write_error = str(_read_exc)

                    commit_ok = write_error is None
                finally:
                    currentProgram.endTransaction(tx_id, commit_ok)

                {{
                    'write_error': write_error,
                    'readback_bytes': readback_bytes,
                    'readback_hex': readback_hex,
                    'committed': commit_ok,
                }}
            """)
        except ToolError:
            _logger.exception("ghidra_write_bytes_rpc_failed", address=hex(address))
            raise
        except Exception as exc:
            _logger.exception("ghidra_write_bytes_failed", address=hex(address))
            msg = f"Write bytes failed: {exc}"
            raise ToolError(msg) from exc

        write_info = cast("dict[str, Any]", result) if isinstance(result, dict) else {}
        if write_error := write_info.get("write_error"):
            msg = f"Write bytes failed: {write_error}"
            raise ToolError(msg)

        readback = [int(b) & 0xFF for b in cast("list[int]", write_info.get("readback_bytes", []))]
        if readback != expected_list:
            _logger.error(
                "ghidra_write_bytes_verification_mismatch",
                address=hex(address),
                expected_length=length,
                readback_length=len(readback),
            )
            raise ToolError(_ERR_WRITE_VERIFICATION_FAILED)

        _logger.info(
            "ghidra_write_bytes_verified",
            address=hex(address),
            bytes_written=length,
        )
        return {
            "address": hex(address),
            "bytes_written": length,
            "verified": True,
            "success": True,
        }

    async def read_bytes(self, address: int, length: int) -> dict[str, Any]:
        """Read bytes from an address in the program.

        Args:
            address: Address to read from.
            length: Number of bytes to read.

        Returns:
            dict[str, Any]: Dict with address, hex string, bytes list, and length.

        Raises:
            ToolError: If Ghidra is not connected, the read returns no
                payload, or the remote call fails.
        """
        if self._bridge is None:
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("bytes_reading", address=hex(address), length=length)
        try:
            result = await self._execute_remote(
                f"""
                from jarray import zeros
                addr = toAddr({address})
                buf = zeros({length}, 'b')
                currentProgram.getMemory().getBytes(addr, buf)
                _read_bytes_payload = [((b + 256) % 256) for b in buf]
                {{'address': addr.getOffset(), 'bytes': _read_bytes_payload}}
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("read_bytes_failed", address=hex(address), length=length)
            error_message = f"Read bytes failed: {exc}"
            raise ToolError(error_message) from exc

        if not isinstance(result, dict):
            error_message = f"Read bytes returned no payload at {hex(address)}"
            raise ToolError(error_message)

        result_dict = cast("dict[str, Any]", result)
        addr_int = int(result_dict.get("address", address))
        byte_list = [int(b) & 0xFF for b in cast("list[int]", result_dict.get("bytes", []))]
        if len(byte_list) != length:
            error_message = f"Read bytes truncated at {hex(address)}: requested {length}, got {len(byte_list)}"
            raise ToolError(error_message)
        return {
            "address": hex(addr_int),
            "hex": " ".join(f"{b:02X}" for b in byte_list),
            "bytes": byte_list,
            "length": len(byte_list),
        }

    async def undo(self) -> dict[str, Any]:
        """Undo the last change in Ghidra.

        Returns:
            dict[str, Any]: Dict with success status.

        Raises:
            ToolError: If Ghidra is not connected or undo fails.
        """
        if self._bridge is None:
            _logger.error("ghidra_not_connected")
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("undo_requested")
        try:
            script = "currentProgram.undo()\nTrue"
            result = await self._execute_remote(script)
            _logger.debug("undo_performed", success=bool(result))
            return {"success": bool(result)}
        except Exception as e:
            _logger.warning("ghidra_undo_failed", error=str(e))
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
            _logger.error("ghidra_not_connected")
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("redo_requested")
        try:
            result = await self._execute_remote(
                """currentProgram.redo() True."""
                                                 ,
            )
            _logger.debug("redo_performed", success=bool(result))
            return {"success": bool(result)}
        except Exception as e:
            _logger.warning("ghidra_redo_failed", error=str(e))
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
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("pcode_fetching", address=hex(address), max_ops=max_ops)
        try:
            result = await self._execute_remote(
                f"""
                from ghidra.app.decompiler import DecompInterface

                ifc = DecompInterface()
                ifc.openProgram(currentProgram)
                addr = toAddr({address})
                func = getFunctionContaining(addr)
                if func is None:
                    _pcode_payload = {{'function': None, 'pcode_ops': []}}
                else:
                    res = ifc.decompileFunction(func, 60, monitor)
                    if not res.decompileCompleted():
                        _pcode_payload = {{'function': func.getName(), 'pcode_ops': []}}
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
                        _pcode_payload = {{'function': func.getName(), 'pcode_ops': ops}}
                _pcode_payload
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_pcode_failed", address=hex(address))
            error_message = f"Get pcode failed at {hex(address)}: {exc}"
            raise ToolError(error_message) from exc

        if not isinstance(result, dict):
            error_message = f"Get pcode returned no payload at {hex(address)}"
            raise ToolError(error_message)
        return cast("dict[str, Any]", result)

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
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("basic_blocks_fetching", address=hex(address), max_blocks=max_blocks)
        try:
            result = await self._execute_remote(
                f"""
                from ghidra.program.model.block import BasicBlockModel

                addr = toAddr({address})
                func = getFunctionContaining(addr)
                if func is None:
                    _bb_payload = {{'function': None, 'blocks': []}}
                else:
                    bbm = BasicBlockModel(currentProgram)
                    blocks = []
                    count = 0
                    func_body = func.getBody()
                    addr_iter = func_body.getAddressRanges()
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
                    _bb_payload = {{'function': func.getName(), 'blocks': blocks}}
                _bb_payload
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_basic_blocks_failed", address=hex(address))
            error_message = f"Get basic blocks failed at {hex(address)}: {exc}"
            raise ToolError(error_message) from exc

        if not isinstance(result, dict):
            error_message = f"Get basic blocks returned no payload at {hex(address)}"
            raise ToolError(error_message)
        return cast("dict[str, Any]", result)

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
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("slice_computing", address=hex(address), direction=direction)
        direction_literal = json.dumps(direction)
        try:
            result = await self._execute_remote(
                f"""
                from ghidra.app.decompiler import DecompInterface

                ifc = DecompInterface()
                ifc.openProgram(currentProgram)
                addr = toAddr({address})
                func = getFunctionContaining(addr)
                _slice_payload = None
                if func is None:
                    _slice_payload = {{'address': {address}, 'direction': {direction_literal}, 'slice_addresses': [], 'slice_pcode_ops': []}}
                else:
                    res = ifc.decompileFunction(func, 60, monitor)
                    if not res.decompileCompleted():
                        _slice_payload = {{'address': {address}, 'direction': {direction_literal}, 'slice_addresses': [], 'slice_pcode_ops': []}}
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
                        _slice_payload = {{'address': {address}, 'direction': {direction_literal}, 'slice_addresses': slice_addrs, 'slice_pcode_ops': slice_ops}}
                _slice_payload
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_slice_failed", address=hex(address))
            error_message = f"Get slice failed at {hex(address)}: {exc}"
            raise ToolError(error_message) from exc

        if not isinstance(result, dict):
            error_message = f"Get slice returned no payload at {hex(address)}"
            raise ToolError(error_message)
        return cast("dict[str, Any]", result)

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
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("callers_fetching", address=hex(address))
        try:
            result = await self._execute_remote(
                f"""
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
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_callers_failed", address=hex(address))
            error_message = f"Get callers failed at {hex(address)}: {exc}"
            raise ToolError(error_message) from exc

        return cast("list[dict[str, Any]]", result) if result else []

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
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("register_value_fetching", address=hex(address), register=register)
        register_literal = json.dumps(register)
        try:
            result = await self._execute_remote(
                f"""
                addr = toAddr({address})
                ctx = currentProgram.getProgramContext()
                reg = ctx.getRegister({register_literal})
                if reg is None:
                    _reg_payload = {{'address': {address}, 'register': {register_literal}, 'value': None, 'has_value': False}}
                else:
                    val = ctx.getRegisterValue(reg, addr)
                    if val is None:
                        _reg_payload = {{'address': {address}, 'register': {register_literal}, 'value': None, 'has_value': False}}
                    else:
                        uval = val.getUnsignedValue()
                        _reg_payload = {{'address': {address}, 'register': {register_literal}, 'value': int(uval) if uval is not None else None, 'has_value': uval is not None}}
                _reg_payload
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_register_value_failed", address=hex(address), register=register)
            error_message = f"Get register value failed at {hex(address)} for {register}: {exc}"
            raise ToolError(error_message) from exc

        if not isinstance(result, dict):
            error_message = f"Get register value returned no payload at {hex(address)}"
            raise ToolError(error_message)
        return cast("dict[str, Any]", result)

    async def import_debug_info(self, path: str) -> dict[str, Any]:
        """Import debug symbols from a PDB or DWARF file.

        Dispatches to Ghidra's real ``PdbAnalyzer`` / ``PdbUniversalAnalyzer``
        for ``.pdb`` inputs and ``DWARFExternalDebugFilesPlugin`` /
        ``DWARFAnalyzer`` for DWARF-bearing files (``.debug``, ``.dbg``,
        ``.dwarf``, ``.so``, ``.dylib``, ``.o``, ``.elf``). The import
        runs inside a Ghidra transaction and is rolled back if the
        analyzer raises. The supplied path is canonicalised with
        ``Path.resolve(strict=True)`` and verified to exist as a regular
        file before any value is forwarded to Ghidra to defeat path
        traversal sequences and dangling references.

        Args:
            path: Path to a ``.pdb`` file or to a DWARF-bearing debug file.

        Returns:
            dict[str, Any]: Dict with path, success flag, debug info
            type, analyzer name used, and any error text returned by
            Ghidra.

        Raises:
            ToolError: If Ghidra is not connected, if ``path`` is empty,
                cannot be resolved, does not exist, is not a regular file,
                if the file extension is not recognised, or if the Ghidra
                analyzer raises.
        """
        if self._bridge is None:
            raise ToolError(_ERR_NOT_CONNECTED)

        resolved_path = await asyncio.to_thread(_resolve_debug_info_path, path)

        ext = resolved_path.suffix.lower()
        if ext == ".pdb":
            debug_type = "pdb"
        elif ext in {".debug", ".dwarf", ".dbg", ".so", ".dylib", ".o", ".elf"}:
            debug_type = "dwarf"
        else:
            msg = f"{_ERR_UNSUPPORTED_DEBUG_FORMAT}: {resolved_path}"
            raise ToolError(msg)

        canonical_path = str(resolved_path)
        _logger.info("debuginfo_importing", path=canonical_path, debug_type=debug_type)
        path_literal = json.dumps(canonical_path)
        try:
            result = await self._execute_remote(f"""
                import java.io.File as _JFile
                from ghidra.util.task import ConsoleTaskMonitor

                debug_path = {path_literal}
                debug_type = {json.dumps(debug_type)}
                success = False
                analyzer_used = ''
                error_msg = None

                tx_id = currentProgram.startTransaction('intellicrack.import_debug_info')
                commit_ok = False
                try:
                    tm = ConsoleTaskMonitor()
                    if debug_type == 'pdb':
                        try:
                            from ghidra.app.util.bin.format.pdb import PdbParser
                            from ghidra.app.util.pdb import PdbProgramAttributes
                            from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer
                            analyzer = PdbUniversalAnalyzer()
                            analyzer_used = 'PdbUniversalAnalyzer'
                            opts = currentProgram.getOptions('Analyzers')
                            opts.setString('PDB Universal.Symbol File', debug_path)
                            success = bool(analyzer.added(currentProgram, currentProgram.getMemory(), tm, None))
                        except Exception as _pdb_univ_exc:
                            try:
                                from ghidra.app.plugin.core.analysis import PdbAnalyzer
                                analyzer = PdbAnalyzer()
                                analyzer_used = 'PdbAnalyzer'
                                opts = currentProgram.getOptions('Analyzers')
                                opts.setString('PDB.Symbol File', debug_path)
                                success = bool(analyzer.added(currentProgram, currentProgram.getMemory(), tm, None))
                            except Exception as _pdb_exc:
                                error_msg = 'pdb_univ=' + str(_pdb_univ_exc) + ' pdb=' + str(_pdb_exc)
                    else:
                        try:
                            from ghidra.app.util.bin.format.dwarf4.next import DWARFImportOptions, DWARFProgram
                            from ghidra.app.util.bin.format.dwarf4.next.sectionprovider import (
                                BaseSectionProvider,
                                DSymSectionProvider,
                                ExternalDebugFileSectionProvider,
                            )
                            analyzer_used = 'DWARFProgram'
                            debug_file = _JFile(debug_path)
                            opts_dwarf = DWARFImportOptions()
                            provider = None
                            try:
                                provider = ExternalDebugFileSectionProvider(debug_file, currentProgram)
                            except Exception:
                                try:
                                    provider = DSymSectionProvider(debug_file, currentProgram)
                                except Exception:
                                    provider = BaseSectionProvider(currentProgram)
                            dwarf_prog = DWARFProgram(currentProgram, opts_dwarf, tm, provider)
                            try:
                                dwarf_prog.checkPreconditions(tm)
                                from ghidra.app.util.bin.format.dwarf4.next import DWARFParser
                                parser = DWARFParser(dwarf_prog, currentProgram.getDataTypeManager(), tm)
                                parser.parse()
                                success = True
                            finally:
                                dwarf_prog.close()
                        except Exception as _dwarf_next_exc:
                            try:
                                from ghidra.app.plugin.core.analysis import DWARFAnalyzer
                                analyzer = DWARFAnalyzer()
                                analyzer_used = 'DWARFAnalyzer'
                                success = bool(analyzer.added(currentProgram, currentProgram.getMemory(), tm, None))
                            except Exception as _dwarf_exc:
                                error_msg = 'dwarf_next=' + str(_dwarf_next_exc) + ' dwarf=' + str(_dwarf_exc)
                    commit_ok = success
                finally:
                    currentProgram.endTransaction(tx_id, commit_ok)

                {{
                    'path': debug_path,
                    'success': bool(success),
                    'type': debug_type,
                    'analyzer': analyzer_used,
                    'error': error_msg,
                }}
            """)
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("ghidra_import_debug_info_failed", path=canonical_path)
            msg = f"{_ERR_DEBUG_IMPORT_FAILED}: {exc}"
            raise ToolError(msg) from exc

        info = cast("dict[str, Any]", result) if isinstance(result, dict) else {}
        success = bool(info.get("success", False))
        response: dict[str, Any] = {
            "path": str(info.get("path", canonical_path)),
            "success": success,
            "type": str(info.get("type", debug_type)),
            "analyzer": str(info.get("analyzer", "")),
            "error": info.get("error"),
        }
        if not success:
            err = info.get("error") or "unknown error"
            msg = f"{_ERR_DEBUG_IMPORT_FAILED}: {err}"
            raise ToolError(msg)
        return response

    async def add_reference(self, from_addr: int, to_addr: int, ref_type: str = "DATA") -> dict[str, Any]:
        """Add a memory reference between two addresses.

        After ``ReferenceManager.addMemoryReference`` returns, the
        bridge re-queries ``getReferencesFrom(from_addr)`` via
        ``remote_eval`` and verifies a reference targeting ``to_addr``
        is present. This catches the previous failure mode where the
        write call succeeded but Ghidra silently rejected the
        ``RefType``/``SourceType`` combination.

        Args:
            from_addr: Source address.
            to_addr: Destination address.
            ref_type: Reference type string (DATA, READ, WRITE, CALL, UNCONDITIONAL_JUMP, CONDITIONAL_JUMP).

        Returns:
            dict[str, Any]: Dict with from, to, type, and success.

        Raises:
            ToolError: If Ghidra is not connected, the write fails, or
                the readback does not include a reference from
                ``from_addr`` targeting ``to_addr``.
        """
        if self._bridge is None:
            _logger.error("ghidra_not_connected")
            error_message = _ERR_NOT_CONNECTED
            raise ToolError(error_message)

        _logger.debug("reference_adding", from_addr=hex(from_addr), to_addr=hex(to_addr), ref_type=ref_type)
        ref_type_literal = json.dumps(ref_type)
        try:
            await self._execute_remote(
                textwrap.dedent(
                    f"""
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
                    """,
                ),
            )
        except ToolError:
            raise
        except Exception as e:
            _logger.warning("ghidra_add_reference_failed", from_addr=hex(from_addr), to_addr=hex(to_addr), error=str(e))
            error_message = f"Add reference failed: {e}"
            raise ToolError(error_message) from e

        try:
            readback = await self._execute_remote_eval(
                f"[r.getToAddress().getOffset() for r in currentProgram.getReferenceManager().getReferencesFrom(toAddr({from_addr}))]",
            )
        except ToolError:
            raise
        except Exception as e:
            _logger.warning("ghidra_add_reference_readback_failed", from_addr=hex(from_addr), error=str(e))
            error_message = f"Add reference readback failed: {e}"
            raise ToolError(error_message) from e

        targets: list[int] = []
        if isinstance(readback, list):
            for offset in cast("list[Any]", readback):
                try:
                    targets.append(int(offset))
                except (TypeError, ValueError):
                    continue
        if to_addr not in targets:
            _logger.error(
                "ghidra_add_reference_verification_failed",
                from_addr=hex(from_addr),
                to_addr=hex(to_addr),
                observed_targets=[hex(t) for t in targets],
            )
            msg = f"Reference verification failed: {hex(from_addr)} -> {hex(to_addr)} not present in {[hex(t) for t in targets]!r}"
            raise ToolError(msg)

        _logger.info(
            "ghidra_reference_added_verified",
            from_addr=hex(from_addr),
            to_addr=hex(to_addr),
            ref_type=ref_type,
        )
        return {"from": hex(from_addr), "to": hex(to_addr), "type": ref_type, "success": True}

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
            _logger.error("ghidra_not_connected")
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("reference_deleting", from_addr=hex(from_addr), to_addr=hex(to_addr))
        try:
            result = await self._execute_remote(
                f"""
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
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("delete_reference_failed", from_addr=hex(from_addr), to_addr=hex(to_addr))
            error_message = f"Delete reference {hex(from_addr)} -> {hex(to_addr)} failed: {exc}"
            raise ToolError(error_message) from exc

        return {"from": hex(from_addr), "to": hex(to_addr), "success": bool(result)}

    async def get_relocations(self) -> list[dict[str, Any]]:
        """Get all relocations from the program relocation table.

        Returns:
            list[dict[str, Any]]: List of relocation dicts with address, type, symbol, and values.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        _logger.debug("ghidra_get_relocations_started")
        if self._bridge is None:
            _logger.error("ghidra_not_connected")
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(
                """
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
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_relocations_failed")
            error_message = f"Get relocations failed: {exc}"
            raise ToolError(error_message) from exc

        return cast("list[dict[str, Any]]", result) if result else []

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
            _logger.error("ghidra_not_connected")
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
            _logger.warning("ghidra_create_namespace_failed", namespace_name=name, parent=parent, error=str(e))
            error_message = f"Create namespace failed: {e}"
            raise ToolError(error_message) from e

    async def get_namespaces(self) -> list[dict[str, Any]]:
        """List all namespaces defined in the program.

        Returns:
            list[dict[str, Any]]: List of namespace dicts with name and path.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        _logger.debug("ghidra_get_namespaces_started")
        if self._bridge is None:
            _logger.error("ghidra_not_connected")
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(
                """
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
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_namespaces_failed")
            error_message = f"Get namespaces failed: {exc}"
            raise ToolError(error_message) from exc

        return cast("list[dict[str, Any]]", result) if result else []

    async def create_equate(self, address: int, value: int, name: str) -> dict[str, Any]:
        """Create an equate (named constant) and attach it to an address.

        After ``EquateTable.createEquate`` and ``Equate.addReference``
        return, the bridge re-queries the equate by name via
        ``remote_eval`` and verifies that the stored value matches
        ``value`` and that ``address`` appears in the equate's
        reference set.

        Args:
            address: Address of the scalar operand.
            value: Numeric value of the equate.
            name: Equate name.

        Returns:
            dict[str, Any]: Dict with name, value, address, and success.

        Raises:
            ToolError: If Ghidra is not connected, the create call
                fails, or the readback shows the equate was not
                persisted with ``value`` and a reference at
                ``address``.
        """
        if self._bridge is None:
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = _ERR_NOT_CONNECTED
            raise ToolError(error_message)

        _logger.debug("equate_creating", equate_name=name, value=value, address=hex(address))
        try:
            await self._execute_remote(
                textwrap.dedent(
                    f"""
                    addr = toAddr({address})
                    eqTable = currentProgram.getEquateTable()
                    existing = eqTable.getEquate({json.dumps(name)})
                    if existing is None:
                        eq = eqTable.createEquate({json.dumps(name)}, {value})
                    else:
                        eq = existing
                    eq.addReference(addr, 0)
                    """,
                ),
            )
        except ToolError:
            raise
        except Exception as e:
            _logger.warning("ghidra_create_equate_failed", equate_name=name, address=hex(address), error=str(e))
            error_message = f"Create equate failed: {e}"
            raise ToolError(error_message) from e

        try:
            readback = await self._execute_remote_eval(
                textwrap.dedent(
                    f"""
                    (lambda eq: None if eq is None else {{
                        'value': long(eq.getValue()),
                        'addresses': [r.getAddress().getOffset() for r in eq.getReferences()],
                    }})(currentProgram.getEquateTable().getEquate({json.dumps(name)}))
                    """,
                ),
            )
        except ToolError:
            raise
        except Exception as e:
            _logger.warning("ghidra_create_equate_readback_failed", equate_name=name, error=str(e))
            error_message = f"Create equate readback failed: {e}"
            raise ToolError(error_message) from e

        info = cast("dict[str, Any]", readback) if isinstance(readback, dict) else None
        if info is None:
            _logger.error("ghidra_create_equate_verification_failed", equate_name=name, reason="missing")
            msg = f"Equate verification failed: equate {name!r} not found after create"
            raise ToolError(msg)
        observed_value = int(info.get("value", 0))
        observed_addrs = [int(a) for a in cast("list[Any]", info.get("addresses", [])) if isinstance(a, int | float)]
        if observed_value != value or address not in observed_addrs:
            _logger.error(
                "ghidra_create_equate_verification_failed",
                equate_name=name,
                expected_value=value,
                observed_value=observed_value,
                expected_address=hex(address),
                observed_addresses=[hex(a) for a in observed_addrs],
            )
            msg = (
                f"Equate verification failed for {name!r}: "
                f"expected value={value} address={hex(address)}, "
                f"observed value={observed_value} addresses={[hex(a) for a in observed_addrs]!r}"
            )
            raise ToolError(msg)

        _logger.info("ghidra_equate_created_verified", equate_name=name, value=value, address=hex(address))
        return {"name": name, "value": value, "address": hex(address), "success": True}

    async def get_equates(self) -> list[dict[str, Any]]:
        """List all equates defined in the program.

        Returns:
            list[dict[str, Any]]: List of equate dicts with name, value, and reference count.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        _logger.debug("ghidra_get_equates_started")
        if self._bridge is None:
            _logger.error("ghidra_not_connected")
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(
                """
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
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_equates_failed")
            error_message = f"Get equates failed: {exc}"
            raise ToolError(error_message) from exc

        return cast("list[dict[str, Any]]", result) if result else []

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
        _logger.debug("ghidra_search_symbols_started", symbol_name=name, symbol_type=symbol_type)
        if self._bridge is None:
            _logger.error("ghidra_not_connected")
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        type_filter_literal = json.dumps(symbol_type) if symbol_type else "None"
        try:
            result = await self._execute_remote(
                f"""
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
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("search_symbols_failed", symbol_name=name)
            error_message = f"Search symbols failed for {name!r}: {exc}"
            raise ToolError(error_message) from exc

        return cast("list[dict[str, Any]]", result) if result else []

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
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("stack_frame_fetching", address=hex(address))
        try:
            result = await self._execute_remote(
                f"""
                addr = toAddr({address})
                func = getFunctionContaining(addr)
                if func is None:
                    _sf_payload = {{'function': None, 'frame_size': 0, 'variables': []}}
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
                    _sf_payload = {{'function': func.getName(), 'frame_size': frame.getFrameSize(), 'variables': vars}}
                _sf_payload
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_stack_frame_failed", address=hex(address))
            error_message = f"Get stack frame failed at {hex(address)}: {exc}"
            raise ToolError(error_message) from exc

        if not isinstance(result, dict):
            error_message = f"Get stack frame returned no payload at {hex(address)}"
            raise ToolError(error_message)
        return cast("dict[str, Any]", result)


class GhidraBridge(_GhidraBridgeAnalysisMixin):
    """Bridge for Ghidra reverse engineering suite.

    Composed from the ``_GhidraBridgeBase`` core class together with topical mixin classes that inherit linearly so cross-references resolve
    through normal MRO. Each mixin groups one surface area (core lifecycle and binary loading, bookmarking and structure editing, call-tree
    analysis and references) so no single class definition exceeds the public method limit. The final class exposes the full Ghidra feature
    set including call-tree exploration, decompiler configuration, program metadata, external references, thunk handling, and bookmark/label
    management.
    """

    async def shutdown(self) -> None:
        """Shutdown Ghidra and cleanup resources.

        Closes the active ghidra_bridge RPC client (preventing socket leaks), terminates the headless subprocess, joins the stdout/stderr
        drain threads, and removes the bridge script under a process-wide lock to prevent races with concurrent ``start_headless``
        invocations.
        """
        if self._bridge is not None:
            await asyncio.to_thread(self._close_bridge_client, self._bridge)
            self._bridge = None

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

        await self._join_drain_threads()

        if self._bridge_script_path is not None:
            await asyncio.to_thread(self._cleanup_bridge_script, self._bridge_script_path)
            self._bridge_script_path = None

        self._binary_path = None
        project_path_str = str(self._project_path) if self._project_path is not None else None
        self._project_path = None
        await super().shutdown()
        _logger.info("ghidra_bridge_shutdown", bridge="ghidra", project_path=project_path_str)

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
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("function_body_fetching", address=hex(address))
        try:
            result = await self._execute_remote(
                f"""
                addr = toAddr({address})
                func = getFunctionContaining(addr)
                if func is None:
                    _fb_payload = {{'name': None, 'address': {address}, 'is_thunk': False, 'thunked_function': None, 'ranges': [], 'total_size': 0}}
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
                    _fb_payload = {{'name': func.getName(), 'address': func.getEntryPoint().getOffset(), 'is_thunk': bool(is_thunk), 'thunked_function': thunked_name, 'ranges': ranges, 'total_size': total}}
                _fb_payload
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_function_body_failed", address=hex(address))
            error_message = f"Get function body failed at {hex(address)}: {exc}"
            raise ToolError(error_message) from exc

        if not isinstance(result, dict):
            error_message = f"Get function body returned no payload at {hex(address)}"
            raise ToolError(error_message)
        return cast("dict[str, Any]", result)

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
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("call_tree_building", address=hex(address), direction=direction, depth=depth)
        direction_literal = json.dumps(direction)
        try:
            result = await self._execute_remote(
                f"""
                def get_callee_tree(func, max_depth, cur_depth, visited):
                    if cur_depth >= max_depth or func.getEntryPoint().getOffset() in visited:
                        return {{'function': func.getName(), 'address': func.getEntryPoint().getOffset(), 'children': []}}
                    visited.add(func.getEntryPoint().getOffset())
                    children = []
                    seen = set()
                    for tf in func.getCalledFunctions(monitor):
                        if tf is None:
                            continue
                        toff = tf.getEntryPoint().getOffset()
                        if toff in seen:
                            continue
                        seen.add(toff)
                        children.append(get_callee_tree(tf, max_depth, cur_depth + 1, set(visited)))
                    return {{'function': func.getName(), 'address': func.getEntryPoint().getOffset(), 'children': children}}

                def get_caller_tree(func, max_depth, cur_depth, visited):
                    if cur_depth >= max_depth or func.getEntryPoint().getOffset() in visited:
                        return {{'function': func.getName(), 'address': func.getEntryPoint().getOffset(), 'children': []}}
                    visited.add(func.getEntryPoint().getOffset())
                    children = []
                    seen = set()
                    for cf in func.getCallingFunctions(monitor):
                        if cf is None:
                            continue
                        coff = cf.getEntryPoint().getOffset()
                        if coff in seen:
                            continue
                        seen.add(coff)
                        children.append(get_caller_tree(cf, max_depth, cur_depth + 1, set(visited)))
                    return {{'function': func.getName(), 'address': func.getEntryPoint().getOffset(), 'children': children}}

                addr = toAddr({address})
                func = getFunctionContaining(addr)
                direction = {direction_literal}
                if func is None:
                    _ct_payload = {{'function': None, 'address': {address}, 'direction': direction, 'children': []}}
                elif direction == 'callees':
                    _ct_payload = get_callee_tree(func, {depth}, 0, set())
                elif direction == 'callers':
                    _ct_payload = get_caller_tree(func, {depth}, 0, set())
                else:
                    callees = get_callee_tree(func, {depth}, 0, set())
                    callers = get_caller_tree(func, {depth}, 0, set())
                    _ct_payload = {{
                        'function': func.getName(),
                        'address': func.getEntryPoint().getOffset(),
                        'direction': direction,
                        'callees': callees.get('children', []),
                        'callers': callers.get('children', []),
                    }}
                _ct_payload
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_call_tree_failed", address=hex(address))
            error_message = f"Get call tree failed at {hex(address)}: {exc}"
            raise ToolError(error_message) from exc

        if not isinstance(result, dict):
            error_message = f"Get call tree returned no payload at {hex(address)}"
            raise ToolError(error_message)
        return cast("dict[str, Any]", result)

    async def get_calling_conventions(self) -> list[str]:
        """List all calling conventions defined in the compiler spec.

        Returns:
            list[str]: List of calling convention name strings.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        _logger.debug("ghidra_get_calling_conventions_started")
        if self._bridge is None:
            _logger.error("ghidra_not_connected")
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(
                """
                cs = currentProgram.getCompilerSpec()
                conventions = [str(cc.getName()) for cc in cs.getCallingConventions()]
                conventions
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_calling_conventions_failed")
            error_message = f"Get calling conventions failed: {exc}"
            raise ToolError(error_message) from exc

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
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("instruction_flow_fetching", address=hex(address))
        try:
            result = await self._execute_remote(
                f"""
                addr = toAddr({address})
                listing = currentProgram.getListing()
                instr = listing.getInstructionAt(addr)
                if instr is None:
                    _if_payload = {{'address': {address}, 'mnemonic': None, 'flow_type': None, 'fall_through': None, 'flows': []}}
                else:
                    ft = instr.getFallThrough()
                    flows = [f.getOffset() for f in (instr.getFlows() or [])]
                    _if_payload = {{'address': addr.getOffset(), 'mnemonic': instr.getMnemonicString(), 'flow_type': str(instr.getFlowType()), 'fall_through': ft.getOffset() if ft is not None else None, 'flows': flows}}
                _if_payload
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_instruction_flow_failed", address=hex(address))
            error_message = f"Get instruction flow failed at {hex(address)}: {exc}"
            raise ToolError(error_message) from exc

        if not isinstance(result, dict):
            error_message = f"Get instruction flow returned no payload at {hex(address)}"
            raise ToolError(error_message)
        return cast("dict[str, Any]", result)

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
            _logger.error("ghidra_not_connected")
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

                result_dict = None
                if created is not None:
                    result_dict = {{'name': created.getName(), 'kind': type_kind, 'size': int(created.getLength()), 'success': True}}
                else:
                    result_dict = {{'name': {json.dumps(name)}, 'kind': type_kind, 'size': 0, 'success': False}}
                result_dict
            """)
            return (
                cast("dict[str, Any]", result)
                if isinstance(result, dict)
                else {"name": name, "kind": type_kind, "size": 0, "success": False}
            )
        except Exception as e:
            _logger.warning(
                "ghidra_create_data_type_failed",
                type_name=name,
                type_kind=type_kind,
                category=category,
                error=str(e),
            )
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
            _logger.error("ghidra_not_connected", address=hex(address))
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
                result_dict = None
                if parsed is None:
                    result_dict = {{'address': {address}, 'type': {json.dumps(data_type)}, 'size': 0, 'success': False}}
                else:
                    existing = listing.getDataAt(addr)
                    if existing is not None:
                        listing.clearCodeUnits(addr, addr.add(parsed.getLength() - 1), False)
                    created = listing.createData(addr, parsed)
                    result_dict = {{'address': addr.getOffset(), 'type': {json.dumps(data_type)}, 'size': int(created.getLength()), 'success': True}}
                result_dict
            """)
            return (
                cast("dict[str, Any]", result)
                if isinstance(result, dict)
                else {"address": hex(address), "type": data_type, "size": 0, "success": False}
            )
        except Exception as e:
            _logger.warning("ghidra_create_data_failed", address=hex(address), data_type=data_type, error=str(e))
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
            _logger.error("ghidra_not_connected")
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
            _logger.warning("ghidra_configure_analysis_failed", analyzer=analyzer_name, enabled=enabled, error=str(e))
            error_message = f"Configure analysis failed: {e}"
            raise ToolError(error_message) from e

    async def set_decompiler_options(
        self,
        simplification: str | None = None,
        max_instructions: int | None = None,
        *,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Configure decompiler simplification style and/or instruction limit.

        Stores supplied values on the bridge instance so subsequent
        decompilation calls reuse the same configuration for the life
        of the session, or until overwritten by another call to this
        method. Passing ``None`` for a value leaves the previously
        stored value in place. Additional key/value options can be
        supplied via ``extra`` and are persisted and applied verbatim
        to ``DecompileOptions.setOption`` when present.

        Args:
            simplification: Simplification style name (e.g. 'normalize',
                'jumptable', 'decompile'). When ``None`` the currently
                stored value is preserved.
            max_instructions: Maximum instructions per function for
                decompiler. When ``None`` the currently stored value is
                preserved.
            extra: Optional dict of additional key/value decompiler
                options. Keys and values are merged into the persisted
                configuration and then applied to Ghidra.

        Returns:
            dict[str, Any]: Dict with simplification, max_instructions,
            extra options, and success.

        Raises:
            ToolError: If Ghidra is not connected or configuration fails.
        """
        if self._bridge is None:
            raise ToolError(_ERR_NOT_CONNECTED)

        if simplification is not None:
            self._decompiler_simplification = simplification
        if max_instructions is not None:
            self._decompiler_max_instructions = max_instructions
        if extra is not None:
            self._decompiler_options_extra.update(extra)

        effective_simp = self._decompiler_simplification
        effective_max = self._decompiler_max_instructions
        effective_extra = dict(self._decompiler_options_extra)

        _logger.debug(
            "decompiler_options_setting",
            simplification=effective_simp,
            max_instructions=effective_max,
            extra_keys=list(effective_extra.keys()),
        )
        simp_literal = json.dumps(effective_simp) if effective_simp is not None else "None"
        max_instr_literal = str(effective_max) if effective_max is not None else "None"
        extra_literal = json.dumps(effective_extra)
        try:
            result = await self._execute_remote(f"""
                import json as _json
                from ghidra.app.decompiler import DecompInterface

                ifc = DecompInterface()
                ifc.openProgram(currentProgram)
                opts = ifc.getOptions()
                simp = {simp_literal}
                max_instr = {max_instr_literal}
                extra_data = _json.loads({json.dumps(extra_literal)})
                applied_extra = {{}}
                if simp is not None:
                    opts.setSimplificationStyle(simp)
                if max_instr is not None:
                    opts.setMaxInstructions(max_instr)
                for key, value in extra_data.items():
                    try:
                        if hasattr(opts, 'setOption'):
                            opts.setOption(key, str(value))
                            applied_extra[key] = value
                    except Exception:
                        pass
                ifc.setOptions(opts)
                {{
                    'simplification': simp,
                    'max_instructions': max_instr,
                    'extra': applied_extra,
                    'success': True,
                }}
            """)
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("ghidra_set_decompiler_options_failed")
            msg = f"Set decompiler options failed: {exc}"
            raise ToolError(msg) from exc

        response = cast("dict[str, Any]", result) if isinstance(result, dict) else {}
        return {
            "simplification": effective_simp,
            "max_instructions": effective_max,
            "extra": cast("dict[str, Any]", response.get("extra", effective_extra)),
            "success": bool(response.get("success", False)),
        }

    @property
    def decompiler_options(self) -> dict[str, Any]:
        """The persisted decompiler options configured on this bridge.

        Returns:
            dict[str, Any]: Dict with simplification, max_instructions,
            and a copy of the extra options map.
        """
        return {
            "simplification": self._decompiler_simplification,
            "max_instructions": self._decompiler_max_instructions,
            "extra": dict(self._decompiler_options_extra),
        }

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
            _logger.error("ghidra_not_connected", size=size)
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
            _logger.warning("ghidra_create_memory_block_failed", block_name=name, start=hex(start), error=str(e))
            error_message = f"Create memory block failed: {e}"
            raise ToolError(error_message) from e

    async def remove_memory_block(self, name: str) -> dict[str, Any]:
        """Remove a memory block from the program.

        Args:
            name: Name of the memory block to remove.

        Returns:
            dict[str, Any]: Dict with name and success.

        Raises:
            ToolError: If Ghidra is not connected, no block with
                ``name`` exists, or the removal fails.
        """
        if self._bridge is None:
            raise ToolError(_ERR_NOT_CONNECTED)

        _logger.info("memory_block_removing", block_name=name)
        try:
            result = await self._execute_remote(f"""
                memory = currentProgram.getMemory()
                block = memory.getBlock({json.dumps(name)})
                found = block is not None
                ok = False
                tx_id = currentProgram.startTransaction('intellicrack.remove_memory_block')
                try:
                    if found:
                        memory.removeBlock(block, monitor)
                        ok = True
                finally:
                    currentProgram.endTransaction(tx_id, ok)
                {{'found': found, 'ok': ok}}
            """)
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("ghidra_remove_memory_block_failed", block_name=name)
            msg = f"Remove memory block failed: {exc}"
            raise ToolError(msg) from exc

        info = cast("dict[str, Any]", result) if isinstance(result, dict) else {}
        if not bool(info.get("found", False)):
            msg = f"Memory block not found: {name!r}"
            raise ToolError(msg)
        if not bool(info.get("ok", False)):
            msg = f"Remove memory block failed: {name!r}"
            raise ToolError(msg)
        return {"name": name, "success": True}

    async def split_memory_block(self, name: str, split_address: int) -> dict[str, Any]:
        """Split a memory block into two blocks at an address.

        The original block is truncated to end just before
        ``split_address``, and a new block covering the remainder is
        created by Ghidra's ``Memory.split``.

        Args:
            name: Name of the memory block to split.
            split_address: Address at which to split the block. This
                address becomes the start of the new (second) block.

        Returns:
            dict[str, Any]: Dict with name, split_address, and success.

        Raises:
            ToolError: If Ghidra is not connected, no block with
                ``name`` exists, ``split_address`` is not inside the
                block, or the split fails.
        """
        if self._bridge is None:
            raise ToolError(_ERR_NOT_CONNECTED)

        _logger.info("memory_block_splitting", block_name=name, split_address=hex(split_address))
        try:
            result = await self._execute_remote(f"""
                memory = currentProgram.getMemory()
                block = memory.getBlock({json.dumps(name)})
                found = block is not None
                in_range = found and block.contains(toAddr({split_address}))
                ok = False
                tx_id = currentProgram.startTransaction('intellicrack.split_memory_block')
                try:
                    if in_range:
                        memory.split(block, toAddr({split_address}))
                        ok = True
                finally:
                    currentProgram.endTransaction(tx_id, ok)
                {{'found': found, 'in_range': in_range, 'ok': ok}}
            """)
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("ghidra_split_memory_block_failed", block_name=name, split_address=hex(split_address))
            msg = f"Split memory block failed: {exc}"
            raise ToolError(msg) from exc

        info = cast("dict[str, Any]", result) if isinstance(result, dict) else {}
        if not bool(info.get("found", False)):
            msg = f"Memory block not found: {name!r}"
            raise ToolError(msg)
        if not bool(info.get("in_range", False)):
            msg = f"Split address {hex(split_address)} is not inside block {name!r}"
            raise ToolError(msg)
        if not bool(info.get("ok", False)):
            msg = f"Split memory block failed: {name!r} at {hex(split_address)}"
            raise ToolError(msg)
        return {"name": name, "split_address": hex(split_address), "success": True}

    async def join_memory_blocks(self, name1: str, name2: str) -> dict[str, Any]:
        """Join two contiguous memory blocks into one.

        Args:
            name1: Name of the first (lower-addressed) memory block.
            name2: Name of the second (higher-addressed) memory block.

        Returns:
            dict[str, Any]: Dict with the joined block name and success.

        Raises:
            ToolError: If Ghidra is not connected, either block does
                not exist, or the join fails (e.g. blocks are not
                contiguous or compatible).
        """
        if self._bridge is None:
            raise ToolError(_ERR_NOT_CONNECTED)

        _logger.info("memory_blocks_joining", block_name_1=name1, block_name_2=name2)
        try:
            result = await self._execute_remote(f"""
                memory = currentProgram.getMemory()
                block1 = memory.getBlock({json.dumps(name1)})
                block2 = memory.getBlock({json.dumps(name2)})
                found1 = block1 is not None
                found2 = block2 is not None
                joined_name = None
                ok = False
                tx_id = currentProgram.startTransaction('intellicrack.join_memory_blocks')
                try:
                    if found1 and found2:
                        joined = memory.join(block1, block2)
                        joined_name = joined.getName()
                        ok = True
                finally:
                    currentProgram.endTransaction(tx_id, ok)
                {{'found1': found1, 'found2': found2, 'joined_name': joined_name, 'ok': ok}}
            """)
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("ghidra_join_memory_blocks_failed", block_name_1=name1, block_name_2=name2)
            msg = f"Join memory blocks failed: {exc}"
            raise ToolError(msg) from exc

        info = cast("dict[str, Any]", result) if isinstance(result, dict) else {}
        if not bool(info.get("found1", False)):
            msg = f"Memory block not found: {name1!r}"
            raise ToolError(msg)
        if not bool(info.get("found2", False)):
            msg = f"Memory block not found: {name2!r}"
            raise ToolError(msg)
        if not bool(info.get("ok", False)):
            msg = f"Join memory blocks failed: {name1!r} + {name2!r}"
            raise ToolError(msg)
        return {"name": info.get("joined_name", name1), "success": True}

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
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(
                f"""
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
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_comments_failed", address=hex(address))
            error_message = f"Get comments failed at {hex(address)}: {exc}"
            raise ToolError(error_message) from exc

        return cast("list[dict[str, Any]]", result) if result else []

    async def get_all_comments(self) -> list[dict[str, Any]]:
        """Get all comments in the entire program.

        Returns:
            list[dict[str, Any]]: List of comment dicts with address, type, and comment text.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        _logger.debug("ghidra_get_all_comments_started")
        if self._bridge is None:
            _logger.error("ghidra_not_connected")
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(
                """
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
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_all_comments_failed")
            error_message = f"Get all comments failed: {exc}"
            raise ToolError(error_message) from exc

        return cast("list[dict[str, Any]]", result) if result else []

    async def get_program_tree(self) -> dict[str, Any]:
        """Get the program tree module and fragment hierarchy.

        Recursively walks every module under every root, returning the
        complete tree of submodules and fragments, plus each fragment's
        address ranges so callers can navigate the layout without
        issuing additional RPC calls. A depth cap prevents runaway
        recursion on pathological inputs.

        Returns:
            dict[str, Any]: Dict with ``trees`` list. Each tree has
            ``name`` and ``root`` (recursive module node). A module
            node has ``name``, ``type`` ("module"), and ``children``.
            A fragment node has ``name``, ``type`` ("fragment"), and
            ``ranges`` (list of ``{start, end}`` offsets).

        Raises:
            ToolError: If Ghidra is not connected or the RPC fails.
        """
        _logger.debug("ghidra_get_program_tree_started")
        if self._bridge is None:
            raise ToolError(_ERR_NOT_CONNECTED)

        try:
            result = await self._execute_remote(
                """
                from ghidra.program.model.listing import ProgramFragment, ProgramModule

                MAX_DEPTH = 64

                def build_fragment(frag):
                    ranges = []
                    try:
                        rng_iter = frag.getAddressRanges()
                        while rng_iter.hasNext():
                            rng = rng_iter.next()
                            ranges.append({
                                'start': rng.getMinAddress().getOffset(),
                                'end': rng.getMaxAddress().getOffset(),
                            })
                    except Exception:
                        ranges = []
                    return {
                        'name': frag.getName(),
                        'type': 'fragment',
                        'ranges': ranges,
                    }

                def build_module(module, depth, visited):
                    key = id(module)
                    if depth >= MAX_DEPTH or key in visited:
                        return {
                            'name': module.getName(),
                            'type': 'module',
                            'children': [],
                            'truncated': True,
                        }
                    visited = set(visited)
                    visited.add(key)
                    children = []
                    for child in module.getChildren():
                        if isinstance(child, ProgramFragment):
                            children.append(build_fragment(child))
                        elif isinstance(child, ProgramModule):
                            children.append(build_module(child, depth + 1, visited))
                        else:
                            children.append({
                                'name': child.getName(),
                                'type': str(child.getClass().getSimpleName()),
                            })
                    return {
                        'name': module.getName(),
                        'type': 'module',
                        'children': children,
                    }

                listing = currentProgram.getListing()
                tree_names = list(listing.getTreeNames())
                trees = []
                for tree_name in tree_names:
                    root_module = listing.getRootModule(tree_name)
                    if root_module is None:
                        trees.append({'name': tree_name, 'root': None})
                        continue
                    trees.append({'name': tree_name, 'root': build_module(root_module, 0, set())})
                {'trees': trees}
            """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("ghidra_get_program_tree_failed")
            msg = f"Get program tree failed: {exc}"
            raise ToolError(msg) from exc

        if isinstance(result, dict):
            return cast("dict[str, Any]", result)
        return {"trees": []}

    async def edit_program_tree(
        self,
        tree_name: str,
        operation: str,
        parent_module: str,
        child_name: str,
    ) -> dict[str, Any]:
        """Create or reparent a module/fragment in a program tree.

        Wraps ``ProgramModule.createModule``, ``ProgramModule.createFragment``,
        and ``ProgramModule.moveChild`` to give write access to the
        program tree hierarchy that :meth:`get_program_tree` only reads.

        Args:
            tree_name: Name of the program tree to modify (as returned
                by ``get_program_tree``'s ``trees[].name``).
            operation: One of ``create_module``, ``create_fragment``,
                or ``move_child``. ``create_module``/``create_fragment``
                create ``child_name`` as a new child of
                ``parent_module``. ``move_child`` moves the existing
                child named ``child_name`` so it becomes a direct
                child of ``parent_module`` (removed from its previous
                parent).
            parent_module: Name of the existing module that will
                contain (or already contains, for ``move_child``) the
                child.
            child_name: Name of the module/fragment to create or move.

        Returns:
            dict[str, Any]: Dict with tree_name, operation, child_name,
            and success.

        Raises:
            ToolError: If Ghidra is not connected, ``operation`` is
                unrecognized, the tree or parent module does not
                exist, or the mutation fails.
        """
        if self._bridge is None:
            raise ToolError(_ERR_NOT_CONNECTED)

        valid_operations = {"create_module", "create_fragment", "move_child"}
        if operation not in valid_operations:
            msg = f"Unknown operation {operation!r}: must be one of {sorted(valid_operations)}"
            raise ToolError(msg)

        _logger.info(
            "program_tree_editing",
            tree_name=tree_name,
            operation=operation,
            parent_module=parent_module,
            child_name=child_name,
        )
        try:
            result = await self._execute_remote(f"""
                listing = currentProgram.getListing()
                root = listing.getRootModule({json.dumps(tree_name)})
                tree_found = root is not None
                parent = None
                if tree_found:
                    parent = root if root.getName() == {json.dumps(parent_module)} else root.getModule({json.dumps(parent_module)})
                parent_found = parent is not None
                operation = {json.dumps(operation)}
                ok = False
                tx_id = currentProgram.startTransaction('intellicrack.edit_program_tree')
                try:
                    if parent_found:
                        if operation == 'create_module':
                            parent.createModule({json.dumps(child_name)})
                            ok = True
                        elif operation == 'create_fragment':
                            parent.createFragment({json.dumps(child_name)})
                            ok = True
                        elif operation == 'move_child':
                            child = root.getModule({json.dumps(child_name)})
                            if child is None:
                                child = root.getFragment({json.dumps(child_name)})
                            if child is not None:
                                parent.moveChild({json.dumps(child_name)}, 0)
                                ok = True
                finally:
                    currentProgram.endTransaction(tx_id, ok)
                {{'tree_found': tree_found, 'parent_found': parent_found, 'ok': ok}}
            """)
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception(
                "ghidra_edit_program_tree_failed",
                tree_name=tree_name,
                operation=operation,
            )
            msg = f"Edit program tree failed: {exc}"
            raise ToolError(msg) from exc

        info = cast("dict[str, Any]", result) if isinstance(result, dict) else {}
        if not bool(info.get("tree_found", False)):
            msg = f"Program tree not found: {tree_name!r}"
            raise ToolError(msg)
        if not bool(info.get("parent_found", False)):
            msg = f"Parent module not found: {parent_module!r} in tree {tree_name!r}"
            raise ToolError(msg)
        if not bool(info.get("ok", False)):
            msg = f"Edit program tree failed: {operation} {child_name!r} under {parent_module!r}"
            raise ToolError(msg)
        return {
            "tree_name": tree_name,
            "operation": operation,
            "child_name": child_name,
            "success": True,
        }

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
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("properties_fetching", address=hex(address))
        try:
            result = await self._execute_remote(
                f"""
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
                _props_payload = {{'address': {address}, 'properties': props}}
                _props_payload
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_properties_failed", address=hex(address))
            error_message = f"Get properties failed at {hex(address)}: {exc}"
            raise ToolError(error_message) from exc

        if not isinstance(result, dict):
            error_message = f"Get properties returned no payload at {hex(address)}"
            raise ToolError(error_message)
        return cast("dict[str, Any]", result)

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
            _logger.error("ghidra_not_connected")
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.info("program_diffing", other_path=other_program_path)
        try:
            result = await self._execute_remote(
                f"""
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
                _diff_payload = {{'differences': differences, 'details': details}}
                _diff_payload
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("diff_programs_failed", other_path=other_program_path)
            error_message = f"Diff programs failed: {exc}"
            raise ToolError(error_message) from exc

        if not isinstance(result, dict):
            error_message = "Diff programs returned no payload"
            raise ToolError(error_message)
        return cast("dict[str, Any]", result)

    async def set_color(self, address: int, color: int) -> dict[str, Any]:
        """Set a background color on a code unit at an address.

        Uses Ghidra's ``ColorizingService`` when available so the color
        participates in Ghidra's persistent colorization store, falling
        back to an ``IntPropertyMap`` entry in the user property manager
        so the color survives reload even when no colorizing service is
        registered.

        In headless mode (``SystemUtilities.isInHeadlessMode()`` true),
        the ``IntPropertyMap`` fallback has no visual effect and no
        consumer in the Ghidra UI - it would be a silent no-op. This
        method therefore raises :class:`ToolError` when the
        ``ColorizingService`` is not available *and* the bridge is
        running headless, instead of returning ``success: True``.

        Args:
            address: Address to colorize.
            color: RGB color as integer (0xRRGGBB).

        Returns:
            dict[str, Any]: Dict with address, color, backend used, and success.

        Raises:
            ToolError: If Ghidra is not connected, neither colorization
                backend can persist the color, or the bridge is running
                headless without an interactive ``ColorizingService``.
        """
        if self._bridge is None:
            raise ToolError(_ERR_NOT_CONNECTED)

        _logger.debug("color_setting", address=hex(address), color=hex(color))
        try:
            result = await self._execute_remote(
                textwrap.dedent(
                    f"""
                    import java.awt.Color as JColor
                    from ghidra.framework import SystemUtilities

                    addr = toAddr({address})
                    color_int = {color}
                    r = (color_int >> 16) & 0xFF
                    g = (color_int >> 8) & 0xFF
                    b = color_int & 0xFF
                    col = JColor(r, g, b)
                    backend = 'none'
                    applied = False
                    error_msg = None
                    is_headless = bool(SystemUtilities.isInHeadlessMode())

                    tx_id = currentProgram.startTransaction('intellicrack.set_color')
                    commit_ok = False
                    try:
                        try:
                            from ghidra.app.plugin.core.colorizer import ColorizingService
                            svc = None
                            try:
                                tool_obj = state.getTool()
                                if tool_obj is not None:
                                    svc = tool_obj.getService(ColorizingService)
                            except Exception:
                                svc = None
                            if svc is not None:
                                svc.setBackgroundColor(addr, addr, col)
                                backend = 'colorizing_service'
                                applied = True
                        except Exception as _svc_exc:
                            error_msg = str(_svc_exc)

                        if not applied:
                            if is_headless:
                                error_msg = (
                                    'set_color requires an interactive Ghidra ColorizingService; '
                                    'IntPropertyMap fallback has no visual effect in headless mode'
                                )
                            else:
                                try:
                                    upm = currentProgram.getUsrPropertyManager()
                                    prop_name = 'IntellicrackColorMap'
                                    prop_map = upm.getIntPropertyMap(prop_name)
                                    if prop_map is None:
                                        prop_map = upm.createIntPropertyMap(prop_name)
                                    prop_map.add(addr, color_int & 0xFFFFFF)
                                    backend = 'int_property_map'
                                    applied = True
                                    error_msg = None
                                except Exception as _map_exc:
                                    if error_msg is None:
                                        error_msg = str(_map_exc)

                        commit_ok = applied
                    finally:
                        currentProgram.endTransaction(tx_id, commit_ok)

                    {{'applied': applied, 'backend': backend, 'error': error_msg, 'headless': is_headless}}
                    """,
                ),
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("ghidra_set_color_failed", address=hex(address))
            msg = f"Set color failed: {exc}"
            raise ToolError(msg) from exc

        info = cast("dict[str, Any]", result) if isinstance(result, dict) else {}
        if not bool(info.get("applied", False)):
            err = info.get("error") or "color could not be persisted"
            _logger.warning(
                "ghidra_set_color_unapplied",
                address=hex(address),
                headless=bool(info.get("headless", False)),
                error=str(err),
            )
            msg = f"Set color failed: {err}"
            raise ToolError(msg)

        return {
            "address": hex(address),
            "color": hex(color),
            "backend": str(info.get("backend", "unknown")),
            "success": True,
        }

    async def set_program_metadata(
        self,
        name: str | None = None,
        image_base: int | None = None,
    ) -> dict[str, Any]:
        """Set program name and/or image base address.

        After ``Program.setName`` / ``Program.setImageBase`` return, the
        bridge re-queries ``getName()`` and ``getImageBase().getOffset()``
        via ``remote_eval`` and verifies each requested change is
        observable on the live program.

        Args:
            name: New program name, or None to leave unchanged.
            image_base: New image base address, or None to leave unchanged.

        Returns:
            dict[str, Any]: Dict with name, image_base, and success.

        Raises:
            ToolError: If Ghidra is not connected, the write fails, or
                the readback does not reflect the requested changes.
        """
        if self._bridge is None:
            _logger.error("ghidra_not_connected")
            error_message = _ERR_NOT_CONNECTED
            raise ToolError(error_message)

        _logger.info("program_metadata_setting", prog_name=name, image_base=image_base)
        name_literal = json.dumps(name) if name else "None"
        image_base_literal = str(image_base) if image_base is not None else "None"
        try:
            await self._execute_remote(
                textwrap.dedent(
                    f"""
                    new_name = {name_literal}
                    new_base = {image_base_literal}
                    if new_name is not None:
                        currentProgram.setName(new_name)
                    if new_base is not None:
                        currentProgram.setImageBase(toAddr(new_base), True)
                    """,
                ),
            )
        except ToolError:
            raise
        except Exception as e:
            _logger.warning("ghidra_set_program_metadata_failed", prog_name=name, error=str(e))
            error_message = f"Set program metadata failed: {e}"
            raise ToolError(error_message) from e

        try:
            readback = await self._execute_remote_eval(
                "{'name': currentProgram.getName(), 'image_base': currentProgram.getImageBase().getOffset()}",
            )
        except ToolError:
            raise
        except Exception as e:
            _logger.warning("ghidra_set_program_metadata_readback_failed", error=str(e))
            error_message = f"Set program metadata readback failed: {e}"
            raise ToolError(error_message) from e

        info = cast("dict[str, Any]", readback) if isinstance(readback, dict) else {}
        observed_name = str(info.get("name", "")) if info else ""
        observed_base = int(info.get("image_base", 0)) if info else 0
        if name is not None and observed_name != name:
            _logger.error(
                "ghidra_set_program_metadata_verification_failed",
                expected_name=name,
                observed_name=observed_name,
            )
            msg = f"Program name verification failed: expected {name!r}, observed {observed_name!r}"
            raise ToolError(msg)
        if image_base is not None and observed_base != image_base:
            _logger.error(
                "ghidra_set_program_metadata_verification_failed",
                expected_image_base=hex(image_base),
                observed_image_base=hex(observed_base),
            )
            msg = f"Program image base verification failed: expected {hex(image_base)}, observed {hex(observed_base)}"
            raise ToolError(msg)

        _logger.info(
            "ghidra_program_metadata_set_verified",
            prog_name=observed_name,
            image_base=hex(observed_base),
        )
        return {"name": name, "image_base": hex(image_base) if image_base is not None else None, "success": True}

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

    async def get_thunk_info(self, address: int) -> dict[str, Any]:
        """Query thunk status and resolved target for a function.

        Args:
            address: Function address.

        Returns:
            dict[str, Any]: Dict with address, is_thunk, thunked_function, and thunked_address.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("thunk_info_fetching", address=hex(address))
        try:
            result = await self._execute_remote(
                f"""
                addr = toAddr({address})
                func = getFunctionContaining(addr)
                if func is None:
                    _ti_payload = {{'address': {address}, 'is_thunk': False, 'thunked_function': None, 'thunked_address': None}}
                else:
                    is_thunk = func.isThunk()
                    thunked_name = None
                    thunked_addr = None
                    if is_thunk:
                        thunked = func.getThunkedFunction(False)
                        if thunked is not None:
                            thunked_name = thunked.getName()
                            thunked_addr = thunked.getEntryPoint().getOffset()
                    _ti_payload = {{'address': func.getEntryPoint().getOffset(), 'is_thunk': bool(is_thunk), 'thunked_function': thunked_name, 'thunked_address': thunked_addr}}
                _ti_payload
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_thunk_info_failed", address=hex(address))
            error_message = f"Get thunk info failed at {hex(address)}: {exc}"
            raise ToolError(error_message) from exc

        if not isinstance(result, dict):
            error_message = f"Get thunk info returned no payload at {hex(address)}"
            raise ToolError(error_message)
        return cast("dict[str, Any]", result)

    async def get_external_references(self, address: int) -> list[dict[str, Any]]:
        """Get external (imported) references from an address.

        Args:
            address: Address to query.

        Returns:
            list[dict[str, Any]]: List of external reference dicts with address, external_name, library, and type.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            _logger.error("ghidra_not_connected", address=hex(address))
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("external_references_fetching", address=hex(address))
        try:
            result = await self._execute_remote(
                f"""
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
                """,
            )
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("get_external_references_failed", address=hex(address))
            error_message = f"Get external references failed at {hex(address)}: {exc}"
            raise ToolError(error_message) from exc

        return cast("list[dict[str, Any]]", result) if result else []

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
            address_repr = hex(address) if address is not None else "None"
            _logger.error("ghidra_not_connected", address=address_repr)
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
            _logger.warning(
                "ghidra_add_external_function_failed",
                library=library,
                func_name=name,
                address=hex(address) if address is not None else None,
                error=str(e),
            )
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
            raise ToolError(_ERR_NOT_CONNECTED)

        _logger.info("overlay_space_creating", overlay_name=name)
        try:
            result = await self._execute_remote(f"""
                memory = currentProgram.getMemory()
                default_space = currentProgram.getAddressFactory().getDefaultAddressSpace()
                overlay_space = memory.createOverlayAddressSpace({json.dumps(name)}, default_space)
                {{'name': overlay_space.getName() if overlay_space is not None else {json.dumps(name)}, 'success': overlay_space is not None}}
            """)
            return cast("dict[str, Any]", result) if isinstance(result, dict) else {"name": name, "success": False}
        except ToolError:
            raise
        except Exception as exc:
            _logger.warning("ghidra_create_overlay_space_failed", overlay_name=name, error=str(exc))
            msg = f"Create overlay space failed: {exc}"
            raise ToolError(msg) from exc

    async def add_bookmark(
        self,
        address: int,
        category: str,
        comment: str,
        bookmark_type: str = "Note",
    ) -> dict[str, Any]:
        """Add a bookmark at an address (explicit mutator alias).

        Mirrors :meth:`create_bookmark` while wrapping the call in a
        Ghidra transaction so the mutation can be rolled back if the
        bookmark manager rejects the request.

        Args:
            address: Address to bookmark.
            category: Bookmark category.
            comment: Bookmark comment text.
            bookmark_type: Bookmark type (Note, Analysis, Error, Warning, Info).

        Returns:
            dict[str, Any]: Dict with address, category, comment,
            bookmark_type, and success.

        Raises:
            ToolError: If Ghidra is not connected or the RPC fails.
        """
        if self._bridge is None:
            raise ToolError(_ERR_NOT_CONNECTED)

        _logger.debug(
            "bookmark_adding",
            address=hex(address),
            category=category,
            bookmark_type=bookmark_type,
        )
        try:
            result = await self._execute_remote(f"""
                bm = currentProgram.getBookmarkManager()
                tx_id = currentProgram.startTransaction('intellicrack.add_bookmark')
                created = False
                try:
                    mark = bm.setBookmark(
                        toAddr({address}),
                        {json.dumps(bookmark_type)},
                        {json.dumps(category)},
                        {json.dumps(comment)},
                    )
                    created = mark is not None
                finally:
                    currentProgram.endTransaction(tx_id, created)
                {{'created': created}}
            """)
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("ghidra_add_bookmark_failed", address=hex(address))
            msg = f"Add bookmark failed: {exc}"
            raise ToolError(msg) from exc

        info = cast("dict[str, Any]", result) if isinstance(result, dict) else {}
        if not bool(info.get("created", False)):
            msg = f"Add bookmark failed at {hex(address)}"
            raise ToolError(msg)
        return {
            "address": hex(address),
            "category": category,
            "comment": comment,
            "bookmark_type": bookmark_type,
            "success": True,
        }

    async def remove_bookmark(
        self,
        address: int,
        category: str | None = None,
        bookmark_type: str | None = None,
    ) -> dict[str, Any]:
        """Remove one or more bookmarks at an address.

        When ``category`` and/or ``bookmark_type`` are provided, only
        bookmarks matching those fields are removed. When both are
        ``None``, every bookmark at the address is removed.

        Args:
            address: Address whose bookmarks should be removed.
            category: Optional category filter.
            bookmark_type: Optional type filter.

        Returns:
            dict[str, Any]: Dict with address, number of bookmarks
            removed, and success.

        Raises:
            ToolError: If Ghidra is not connected, the RPC fails, or
                no matching bookmark existed.
        """
        if self._bridge is None:
            raise ToolError(_ERR_NOT_CONNECTED)

        _logger.debug(
            "bookmark_removing",
            address=hex(address),
            category=category,
            bookmark_type=bookmark_type,
        )
        category_literal = json.dumps(category) if category else "None"
        type_literal = json.dumps(bookmark_type) if bookmark_type else "None"
        try:
            result = await self._execute_remote(f"""
                bm = currentProgram.getBookmarkManager()
                addr = toAddr({address})
                cat_filter = {category_literal}
                type_filter = {type_literal}
                removed = 0
                tx_id = currentProgram.startTransaction('intellicrack.remove_bookmark')
                try:
                    existing = bm.getBookmarks(addr)
                    for bk in list(existing):
                        if cat_filter is not None and bk.getCategory() != cat_filter:
                            continue
                        if type_filter is not None and bk.getTypeString() != type_filter:
                            continue
                        bm.removeBookmark(bk)
                        removed += 1
                finally:
                    currentProgram.endTransaction(tx_id, removed > 0)
                {{'removed': removed}}
            """)
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("ghidra_remove_bookmark_failed", address=hex(address))
            msg = f"Remove bookmark failed: {exc}"
            raise ToolError(msg) from exc

        info = cast("dict[str, Any]", result) if isinstance(result, dict) else {}
        removed = int(info.get("removed", 0))
        if removed <= 0:
            msg = f"{_ERR_BOOKMARK_NOT_FOUND}: {hex(address)}"
            raise ToolError(msg)
        return {"address": hex(address), "removed": removed, "success": True}

    async def add_label(
        self,
        address: int,
        name: str,
        *,
        primary: bool = False,
    ) -> dict[str, Any]:
        """Add a new label at an address.

        Args:
            address: Address for the label.
            name: Label name.
            primary: When ``True`` the label is marked primary.

        Returns:
            dict[str, Any]: Dict with address, name, primary flag, and success.

        Raises:
            ToolError: If Ghidra is not connected or the label cannot be created.
        """
        if self._bridge is None:
            raise ToolError(_ERR_NOT_CONNECTED)

        _logger.debug("label_adding", address=hex(address), label_name=name, primary=primary)
        primary_literal = "True" if primary else "False"
        try:
            result = await self._execute_remote(f"""
                from ghidra.program.model.symbol import SourceType
                addr = toAddr({address})
                st = currentProgram.getSymbolTable()
                primary_flag = {primary_literal}
                created = False
                tx_id = currentProgram.startTransaction('intellicrack.add_label')
                try:
                    sym = st.createLabel(addr, {json.dumps(name)}, SourceType.USER_DEFINED)
                    if sym is not None:
                        created = True
                        if primary_flag:
                            sym.setPrimary()
                finally:
                    currentProgram.endTransaction(tx_id, created)
                {{'created': created}}
            """)
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("ghidra_add_label_failed", address=hex(address))
            msg = f"Add label failed: {exc}"
            raise ToolError(msg) from exc

        info = cast("dict[str, Any]", result) if isinstance(result, dict) else {}
        if not bool(info.get("created", False)):
            msg = f"Add label failed: Ghidra refused label {name!r} at {hex(address)}"
            raise ToolError(msg)
        return {
            "address": hex(address),
            "name": name,
            "primary": primary,
            "success": True,
        }

    async def remove_label(self, address: int, name: str) -> dict[str, Any]:
        """Remove a named label at an address.

        Args:
            address: Address whose label should be removed.
            name: Label name to remove.

        Returns:
            dict[str, Any]: Dict with address, name, and success.

        Raises:
            ToolError: If Ghidra is not connected, the RPC fails, or
                the label is not found.
        """
        if self._bridge is None:
            raise ToolError(_ERR_NOT_CONNECTED)

        _logger.debug("label_removing", address=hex(address), label_name=name)
        try:
            result = await self._execute_remote(f"""
                addr = toAddr({address})
                st = currentProgram.getSymbolTable()
                target_name = {json.dumps(name)}
                removed = False
                tx_id = currentProgram.startTransaction('intellicrack.remove_label')
                try:
                    symbols = list(st.getSymbols(addr))
                    for sym in symbols:
                        if sym.getName() == target_name:
                            if sym.delete():
                                removed = True
                            break
                finally:
                    currentProgram.endTransaction(tx_id, removed)
                {{'removed': removed}}
            """)
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("ghidra_remove_label_failed", address=hex(address))
            msg = f"Remove label failed: {exc}"
            raise ToolError(msg) from exc

        info = cast("dict[str, Any]", result) if isinstance(result, dict) else {}
        if not bool(info.get("removed", False)):
            msg = f"{_ERR_LABEL_NOT_FOUND}: {name!r} at {hex(address)}"
            raise ToolError(msg)
        return {"address": hex(address), "name": name, "success": True}

    async def add_thunk(self, address: int, thunked_address: int) -> dict[str, Any]:
        """Mark a function as a thunk forwarding to another function.

        Args:
            address: Address of the thunk function.
            thunked_address: Address of the target (thunked) function.

        Returns:
            dict[str, Any]: Dict with address, thunked_address, and success.

        Raises:
            ToolError: If Ghidra is not connected, either function
                does not exist, or the operation fails.
        """
        if self._bridge is None:
            raise ToolError(_ERR_NOT_CONNECTED)

        _logger.info("thunk_adding", address=hex(address), thunked_address=hex(thunked_address))
        try:
            result = await self._execute_remote(f"""
                fm = currentProgram.getFunctionManager()
                thunk_func = fm.getFunctionAt(toAddr({address}))
                target_func = fm.getFunctionAt(toAddr({thunked_address}))
                ok = False
                found_thunk = thunk_func is not None
                found_target = target_func is not None
                tx_id = currentProgram.startTransaction('intellicrack.add_thunk')
                try:
                    if found_thunk and found_target:
                        thunk_func.setThunkedFunction(target_func)
                        ok = True
                finally:
                    currentProgram.endTransaction(tx_id, ok)
                {{'ok': ok, 'thunk_found': found_thunk, 'target_found': found_target}}
            """)
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("ghidra_add_thunk_failed", address=hex(address))
            msg = f"Add thunk failed: {exc}"
            raise ToolError(msg) from exc

        info = cast("dict[str, Any]", result) if isinstance(result, dict) else {}
        if not bool(info.get("thunk_found", False)):
            msg = f"{_ERR_FUNCTION_NOT_FOUND}: {hex(address)}"
            raise ToolError(msg)
        if not bool(info.get("target_found", False)):
            msg = f"{_ERR_FUNCTION_NOT_FOUND}: {hex(thunked_address)}"
            raise ToolError(msg)
        if not bool(info.get("ok", False)):
            msg = f"Add thunk failed at {hex(address)}"
            raise ToolError(msg)
        return {
            "address": hex(address),
            "thunked_address": hex(thunked_address),
            "success": True,
        }

    async def remove_thunk(self, address: int) -> dict[str, Any]:
        """Clear the thunk relationship on a function.

        Args:
            address: Address of the thunk function.

        Returns:
            dict[str, Any]: Dict with address and success.

        Raises:
            ToolError: If Ghidra is not connected, the function does
                not exist, or the function is not a thunk.
        """
        if self._bridge is None:
            raise ToolError(_ERR_NOT_CONNECTED)

        _logger.info("thunk_removing", address=hex(address))
        try:
            result = await self._execute_remote(f"""
                fm = currentProgram.getFunctionManager()
                func = fm.getFunctionAt(toAddr({address}))
                found = func is not None
                was_thunk = found and func.isThunk()
                ok = False
                tx_id = currentProgram.startTransaction('intellicrack.remove_thunk')
                try:
                    if was_thunk:
                        func.setThunkedFunction(None)
                        ok = True
                finally:
                    currentProgram.endTransaction(tx_id, ok)
                {{'found': found, 'was_thunk': was_thunk, 'ok': ok}}
            """)
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("ghidra_remove_thunk_failed", address=hex(address))
            msg = f"Remove thunk failed: {exc}"
            raise ToolError(msg) from exc

        info = cast("dict[str, Any]", result) if isinstance(result, dict) else {}
        if not bool(info.get("found", False)):
            msg = f"{_ERR_FUNCTION_NOT_FOUND}: {hex(address)}"
            raise ToolError(msg)
        if not bool(info.get("was_thunk", False)):
            msg = f"Function at {hex(address)} is not a thunk"
            raise ToolError(msg)
        if not bool(info.get("ok", False)):
            msg = f"Remove thunk failed at {hex(address)}"
            raise ToolError(msg)
        return {"address": hex(address), "success": True}

    async def add_external_reference(
        self,
        from_addr: int,
        library: str,
        name: str,
    ) -> dict[str, Any]:
        """Add an external reference from an address to a named symbol.

        Args:
            from_addr: Source address of the external reference.
            library: External library name.
            name: External function or symbol name.

        Returns:
            dict[str, Any]: Dict with from_addr, library, name, and success.

        Raises:
            ToolError: If Ghidra is not connected or the reference cannot be added.
        """
        if self._bridge is None:
            raise ToolError(_ERR_NOT_CONNECTED)

        _logger.info(
            "external_reference_adding",
            from_addr=hex(from_addr),
            library=library,
            external_name=name,
        )
        try:
            result = await self._execute_remote(f"""
                from ghidra.program.model.symbol import RefType, SourceType

                src = toAddr({from_addr})
                refMgr = currentProgram.getReferenceManager()
                ok = False
                tx_id = currentProgram.startTransaction('intellicrack.add_external_reference')
                try:
                    ref = refMgr.addExternalReference(
                        src,
                        {json.dumps(library)},
                        {json.dumps(name)},
                        None,
                        SourceType.USER_DEFINED,
                        0,
                        RefType.DATA,
                    )
                    ok = ref is not None
                finally:
                    currentProgram.endTransaction(tx_id, ok)
                {{'ok': ok}}
            """)
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception("ghidra_add_external_reference_failed", from_addr=hex(from_addr))
            msg = f"Add external reference failed: {exc}"
            raise ToolError(msg) from exc

        info = cast("dict[str, Any]", result) if isinstance(result, dict) else {}
        if not bool(info.get("ok", False)):
            msg = f"Add external reference failed at {hex(from_addr)}"
            raise ToolError(msg)
        return {
            "from_addr": hex(from_addr),
            "library": library,
            "name": name,
            "success": True,
        }

    async def remove_external_reference(self, from_addr: int) -> dict[str, Any]:
        """Remove every external reference originating from an address.

        Args:
            from_addr: Source address whose external references should be removed.

        Returns:
            dict[str, Any]: Dict with from_addr, removed count, and success.

        Raises:
            ToolError: If Ghidra is not connected, the RPC fails, or
                no external references were present at the address.
        """
        if self._bridge is None:
            raise ToolError(_ERR_NOT_CONNECTED)

        _logger.info("external_reference_removing", from_addr=hex(from_addr))
        try:
            result = await self._execute_remote(f"""
                src = toAddr({from_addr})
                refMgr = currentProgram.getReferenceManager()
                removed = 0
                tx_id = currentProgram.startTransaction('intellicrack.remove_external_reference')
                try:
                    for ref in list(refMgr.getReferencesFrom(src)):
                        if ref.isExternalReference():
                            refMgr.delete(ref)
                            removed += 1
                finally:
                    currentProgram.endTransaction(tx_id, removed > 0)
                {{'removed': removed}}
            """)
        except ToolError:
            raise
        except Exception as exc:
            _logger.exception(
                "ghidra_remove_external_reference_failed",
                from_addr=hex(from_addr),
            )
            msg = f"Remove external reference failed: {exc}"
            raise ToolError(msg) from exc

        info = cast("dict[str, Any]", result) if isinstance(result, dict) else {}
        removed = int(info.get("removed", 0))
        if removed <= 0:
            msg = f"No external references found at {hex(from_addr)}"
            raise ToolError(msg)
        return {"from_addr": hex(from_addr), "removed": removed, "success": True}
