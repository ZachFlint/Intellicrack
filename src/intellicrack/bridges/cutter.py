# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Cutter/Rizin bridge for static and dynamic analysis.

This module provides integration with Cutter/Rizin for disassembly, analysis, and debugging capabilities using r2pipe (wire-compatible with
Rizin's pipe protocol).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Literal, cast, override

import r2pipe

from intellicrack.bridges.base import (
    BridgeCapabilities,
    BridgeState,
    DisassemblyLine,
    StaticAnalysisBridge,
)
from intellicrack.core.logging import get_logger
from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.core.types import (
    BinaryInfo,
    BlockInfo,
    ClassInfo,
    CommentInfo,
    CrossReference,
    ExportInfo,
    FlagInfo,
    FunctionInfo,
    GadgetInfo,
    HeaderInfo,
    ImportInfo,
    LibraryInfo,
    ParameterInfo,
    RelocationInfo,
    ResourceInfo,
    SectionInfo,
    SegmentInfo,
    StringInfo,
    SymbolInfo,
    ToolDefinition,
    ToolError,
    ToolFunction,
    ToolName,
    ToolParameter,
    VariableInfo,
    VtableInfo,
)


__all__ = ["CutterBridge", "is_rizin_64bit", "validate_r2_argument"]

XRefType = Literal["call", "jump", "data", "read", "write"]
StringEncoding = Literal["ascii", "utf-8", "utf-16le", "utf-16be"]

_logger = get_logger(__name__)

_ERR_FILE_NOT_FOUND = "file not found"
_ERR_LOAD_FAILED = "failed to load binary"
_ERR_NO_BINARY = "no binary loaded"
_ERR_NOT_ANALYZED = "binary not analyzed"
_ERR_CMD_FAILED = "command execution failed"
_ERR_TOOL_NOT_AVAILABLE = "cutter not available"
_ERR_DECOMPILE_NA = "decompilation not available"
_ERR_ASSEMBLE_FAILED = "failed to assemble instruction"
_ERR_CMD_TIMEOUT = "cutter command timed out"
_ERR_INVALID_R2_INPUT = "input contains rizin command-control characters"
_ERR_JSON_PARSE_FAILED = "failed to parse rizin JSON output"
_BITS_64 = 64
R2_COMMAND_TIMEOUT: float = 60.0

_RZ_64BIT_ARCHES: frozenset[str] = frozenset(
    {
        "x86_64",
        "amd64",
        "x64",
        "aarch64",
        "arm64",
        "ppc64",
        "powerpc64",
        "mips64",
        "riscv64",
        "sparc64",
        "alpha",
        "ia64",
        "loongarch64",
    },
)

_RZ_64BIT_CLASS_TOKENS: frozenset[str] = frozenset(
    {
        "elf64",
        "pe32+",
        "pe64",
        "mach-o-64",
        "mach064",
        "macho64",
        "te64",
    },
)

_RZ_COMMAND_CONTROL_CHARS: frozenset[str] = frozenset({";", "\n", "\r", "@", "|", "~", "`", ">", "<", "$", "#"})


def is_rizin_64bit(bits: int, arch: str, file_class: str) -> bool:
    """Determine whether a rizin-reported binary is 64-bit.

    Rizin's ``ij`` output exposes a binary's word width through three
    overlapping fields. ``bin.bits`` is the most direct, but several
    formats (notably PE32+ and split debug variants) leave it set to a
    32-bit value while the architecture or container class still
    indicates 64-bit. Combining the three sources matches what Cutter
    itself does when classifying loaded binaries.

    Args:
        bits: ``bin.bits`` value reported by rizin (0 if missing).
        arch: ``bin.arch`` value reported by rizin (e.g. ``x86``,
            ``x86_64``, ``arm``, ``arm64``).
        file_class: ``bin.class`` value reported by rizin
            (e.g. ``ELF64``, ``PE32+``, ``MACH064``).

    Returns:
        bool: ``True`` when any of the three sources indicates 64-bit
        word size.
    """
    if bits == _BITS_64:
        return True
    if arch.lower() in _RZ_64BIT_ARCHES:
        return True
    normalized_class = file_class.lower().replace(" ", "").replace("_", "")
    return any(token in normalized_class for token in _RZ_64BIT_CLASS_TOKENS)


def validate_r2_argument(value: str, *, field: str) -> str:
    """Reject raw user input that would inject rizin command-control characters.

    Rizin parses ``;`` as a command separator, ``@`` as a temporary
    seek, ``|`` as a shell pipe, ``~`` as the internal grep operator,
    backticks as nested-command substitution, ``>`` as redirection,
    and treats ``$`` / ``#`` as variable / comment prefixes. Forwarding
    untrusted user input directly into command strings allows
    arbitrary rizin commands to run in the analysed session, including
    file writes through ``wx`` or process spawning through ``!``.

    Args:
        value: Caller-supplied text destined for an rizin command line.
        field: Name of the parameter being validated, used in the
            raised error message.

    Returns:
        str: The unmodified ``value`` when safe to forward.

    Raises:
        ToolError: When ``value`` contains a rizin command-control
            character or starts with ``!`` (shell escape).
    """
    if value.startswith("!"):
        msg = f"{_ERR_INVALID_R2_INPUT}: {field} must not start with '!'"
        raise ToolError(msg)
    if any(ch in _RZ_COMMAND_CONTROL_CHARS for ch in value):
        msg = f"{_ERR_INVALID_R2_INPUT}: {field}"
        raise ToolError(msg)
    return value


def _get_str(data: dict[str, Any], key: str, default: str = "") -> str:
    """Get a string value from a dictionary with type safety.

    Args:
        data: Dictionary to get value from.
        key: Key to look up.
        default: Default value if key not found or not a string.

    Returns:
        str: String value or default.
    """
    val = data.get(key, default)
    return val if isinstance(val, str) else default


def _get_int(data: dict[str, Any], key: str, default: int = 0) -> int:
    """Get an integer value from a dictionary with type safety.

    Args:
        data: Dictionary to get value from.
        key: Key to look up.
        default: Default value if key not found or not an int.

    Returns:
        int: Integer value or default.
    """
    val = data.get(key, default)
    return val if isinstance(val, int) else default


def _get_float(data: dict[str, Any], key: str, default: float = 0.0) -> float:
    """Get a float value from a dictionary with type safety.

    Args:
        data: Dictionary to get value from.
        key: Key to look up.
        default: Default value if key not found or not a float.

    Returns:
        float: Float value or default.
    """
    val = data.get(key, default)
    return float(val) if isinstance(val, (int, float)) else default


def _get_dict(data: dict[str, Any], key: str) -> dict[str, Any]:
    """Get a nested dictionary from a dictionary with type safety.

    Args:
        data: Dictionary to get value from.
        key: Key to look up.

    Returns:
        dict[str, Any]: Dictionary value or empty dict.
    """
    val = data.get(key)
    return cast("dict[str, Any]", val) if isinstance(val, dict) else {}


def _get_optional_str(data: dict[str, Any], key: str) -> str | None:
    """Get an optional string value from a dictionary.

    Args:
        data: Dictionary to get value from.
        key: Key to look up.

    Returns:
        str | None: String value or None.
    """
    val = data.get(key)
    return val if isinstance(val, str) else None


def _get_optional_int(data: dict[str, Any], key: str) -> int | None:
    """Get an optional integer value from a dictionary.

    Args:
        data: Dictionary to get value from.
        key: Key to look up.

    Returns:
        int | None: Integer value or None.
    """
    val = data.get(key)
    return val if isinstance(val, int) else None


def _get_list(data: dict[str, Any], key: str) -> list[Any]:
    """Get a list value from a dictionary with type safety.

    Args:
        data: Dictionary to get value from.
        key: Key to look up.

    Returns:
        list[Any]: List value or empty list.
    """
    val = data.get(key)
    return cast("list[Any]", val) if isinstance(val, list) else []


def _tf(
    name: str,
    description: str,
    parameters: list[ToolParameter],
    returns: str,
) -> ToolFunction:
    """Create a ToolFunction with the cutter prefix.

    Args:
        name: Method name (without 'cutter.' prefix).
        description: Function description.
        parameters: List of ToolParameter objects.
        returns: Return value description.

    Returns:
        ToolFunction: Complete tool function definition.
    """
    return ToolFunction(
        name=f"cutter.{name}",
        description=description,
        parameters=parameters,
        returns=returns,
    )


def _tp(
    name: str,
    tp_type: str,
    description: str,
    *,
    required: bool = True,
    enum: list[str] | None = None,
    default: str | float | bool | None = None,
) -> ToolParameter:
    """Create a ToolParameter with common defaults.

    Args:
        name: Parameter name.
        tp_type: JSON Schema type.
        description: Parameter description.
        required: Whether the parameter is required.
        enum: Allowed values list.
        default: Default value.

    Returns:
        ToolParameter: Parameter definition.
    """
    return ToolParameter(
        name=name,
        type=tp_type,
        description=description,
        required=required,
        enum=enum,
        default=default,
    )


def _build_tool_functions() -> list[ToolFunction]:
    """Build the complete list of tool functions for the CutterBridge.

    Returns:
        list[ToolFunction]: All tool function definitions.
    """
    return [
        _tf(
            "load_binary",
            "Load a binary file into Cutter/Rizin",
            [
                _tp("path", "string", "Path to the binary file"),
            ],
            "BinaryInfo object with file details",
        ),
        _tf(
            "analyze",
            "Run full analysis on the loaded binary",
            [
                _tp(
                    "level",
                    "string",
                    "Analysis level: quick, normal, deep",
                    required=False,
                    default="normal",
                    enum=["quick", "normal", "deep"],
                ),
            ],
            "Analysis completion status",
        ),
        _tf(
            "get_functions",
            "Get list of all functions",
            [
                _tp("filter_pattern", "string", "Optional regex to filter function names", required=False),
            ],
            "List of FunctionInfo objects",
        ),
        _tf(
            "decompile",
            "Decompile a function to pseudocode",
            [
                _tp("address", "integer", "Function address to decompile"),
            ],
            "Decompiled C-like pseudocode",
        ),
        _tf(
            "disassemble",
            "Disassemble instructions at an address",
            [
                _tp("address", "integer", "Start address"),
                _tp("count", "integer", "Number of instructions", required=False, default=20),
            ],
            "Disassembly listing",
        ),
        _tf(
            "get_xrefs_to",
            "Get cross-references to an address",
            [
                _tp("address", "integer", "Target address"),
            ],
            "List of cross-references",
        ),
        _tf(
            "get_xrefs_from",
            "Get cross-references from an address",
            [
                _tp("address", "integer", "Source address"),
            ],
            "List of cross-references",
        ),
        _tf(
            "search_strings",
            "Search for strings in the binary",
            [
                _tp("pattern", "string", "String or regex pattern"),
            ],
            "List of matching strings",
        ),
        _tf(
            "search_bytes",
            "Search for byte pattern",
            [
                _tp("pattern", "string", "Hex pattern (e.g., '48 8B 05 00')"),
            ],
            "List of addresses",
        ),
        _tf("get_imports", "Get imported functions", [], "List of imports"),
        _tf("get_exports", "Get exported functions", [], "List of exports"),
        _tf("get_sections", "Get binary sections", [], "List of sections"),
        _tf(
            "rename_function",
            "Rename a function",
            [
                _tp("address", "integer", "Function address"),
                _tp("new_name", "string", "New function name"),
            ],
            "Success status",
        ),
        _tf(
            "add_comment",
            "Add a comment at an address",
            [
                _tp("address", "integer", "Address for comment"),
                _tp("comment", "string", "Comment text"),
            ],
            "Success status",
        ),
        _tf(
            "write_bytes",
            "Write bytes at an address",
            [
                _tp("address", "integer", "Address to write at"),
                _tp("hex_data", "string", "Hex bytes to write"),
            ],
            "Success status",
        ),
        _tf(
            "execute_command",
            "Execute raw Rizin command",
            [
                _tp("command", "string", "Rizin command to execute"),
            ],
            "Command output",
        ),
        _tf(
            "get_function",
            "Get function at a specific address",
            [
                _tp("address", "integer", "Function address"),
            ],
            "FunctionInfo or None if not found",
        ),
        _tf(
            "search_bytes_wildcard",
            "Search for byte pattern with wildcards",
            [
                _tp("hex_pattern", "string", "Hex pattern like '48 8B ?? ??'"),
            ],
            "List of addresses where pattern found",
        ),
        _tf(
            "assemble_at",
            "Assemble instruction at address",
            [
                _tp("address", "integer", "Target address"),
                _tp("instruction", "string", "Assembly instruction to assemble"),
            ],
            "Assembled instruction as a Python bytes object (raw machine code).",
        ),
        _tf(
            "seek",
            "Seek to a specific address in the binary",
            [
                _tp("address", "integer", "Target address"),
            ],
            "Output of seek command",
        ),
        _tf(
            "get_function_address",
            "Get address of a function by name",
            [
                _tp("name", "string", "Function name to look up"),
            ],
            "Address of function or None if not found",
        ),
        _tf(
            "get_function_graph",
            "Get function control flow graph data",
            [
                _tp("address", "integer", "Function address to graph"),
            ],
            "List of basic block dictionaries",
        ),
        _tf("get_all_strings", "Get all strings from the binary including non-data sections", [], "List of StringInfo objects"),
        _tf("get_symbols", "Get all symbols from the binary", [], "List of SymbolInfo objects"),
        _tf("get_libraries", "Get linked libraries from the binary", [], "List of LibraryInfo objects"),
        _tf("get_headers", "Get binary header field information", [], "List of HeaderInfo objects"),
        _tf("get_debug_info", "Get debug information from the binary", [], "Debug information dictionary"),
        _tf("get_classes", "Get class information from the binary", [], "List of ClassInfo objects"),
        _tf("get_relocations", "Get relocation table entries", [], "List of RelocationInfo objects"),
        _tf("get_resources", "Get embedded resources from the binary", [], "List of ResourceInfo objects"),
        _tf(
            "search_rop_gadgets",
            "Search for ROP gadgets in the binary",
            [
                _tp("pattern", "string", "Optional pattern to filter gadgets", required=False),
            ],
            "List of GadgetInfo objects",
        ),
        _tf("get_callgraph", "Get the function call graph", [], "List of callgraph edge dictionaries"),
        _tf("get_vtables", "Get virtual function tables", [], "List of VtableInfo objects"),
        _tf("get_syscalls", "Get syscall information", [], "List of syscall dictionaries"),
        _tf(
            "read_bytes",
            "Read raw bytes from the binary",
            [
                _tp("address", "integer", "Address to read from"),
                _tp("count", "integer", "Number of bytes to read"),
            ],
            "Raw bytes from the binary",
        ),
        _tf(
            "save_binary",
            "Save the binary with all cached patches applied",
            [
                _tp("path", "string", "Output file path (None for original)", required=False),
            ],
            "Success status",
        ),
        _tf("get_comments", "Get all comments/annotations", [], "List of CommentInfo objects"),
        _tf("get_flags", "Get all flags/labels from the binary", [], "List of FlagInfo objects"),
        _tf(
            "add_flag",
            "Add a named flag at an address",
            [
                _tp("name", "string", "Flag name"),
                _tp("size", "integer", "Size covered by the flag"),
                _tp("address", "integer", "Address for the flag"),
            ],
            "Success status",
        ),
        _tf(
            "resolve_flag",
            "Resolve a flag name from an address",
            [
                _tp("address", "integer", "Address to resolve"),
            ],
            "Flag name or None",
        ),
        _tf("get_types", "Get all defined types from analysis", [], "List of type definition dictionaries"),
        _tf("get_structs", "Get all struct definitions", [], "List of struct dictionaries"),
        _tf("get_unions", "Get all union definitions", [], "List of union dictionaries"),
        _tf("get_enums", "Get all enum definitions", [], "List of enum dictionaries"),
        _tf("get_typedefs", "Get all typedef definitions", [], "List of typedef dictionaries"),
        _tf("get_function_types", "Get all function type signatures", [], "List of function type dictionaries"),
        _tf(
            "import_c_header",
            "Import C header type definitions",
            [
                _tp("header_text", "string", "C header source text to parse"),
            ],
            "Success status",
        ),
        _tf(
            "esil_eval",
            "Evaluate an ESIL expression",
            [
                _tp("expression", "string", "ESIL expression to evaluate"),
            ],
            "Evaluation result",
        ),
        _tf(
            "esil_step",
            "Step the ESIL emulator forward",
            [
                _tp("count", "integer", "Number of steps to take", required=False, default=1),
            ],
            "Step output",
        ),
        _tf(
            "esil_emulate_function",
            "Emulate a function using ESIL",
            [
                _tp("address", "integer", "Function address to emulate"),
            ],
            "Emulation output",
        ),
        _tf("esil_init_memory", "Initialize ESIL emulation memory stack", [], "Success status"),
        _tf(
            "esil_set_pc",
            "Set the ESIL program counter",
            [
                _tp("address", "integer", "Address to set the PC to"),
            ],
            "Success status",
        ),
        _tf("get_zignatures", "Get all zignatures (function signatures)", [], "List of zignature dictionaries"),
        _tf(
            "generate_zignatures",
            "Generate zignatures from analyzed functions",
            [
                _tp("address", "integer", "Specific function address (optional)", required=False),
            ],
            "Success status",
        ),
        _tf(
            "add_zignature",
            "Add a zignature definition",
            [
                _tp("name", "string", "Zignature name"),
                _tp("zigdata", "string", "Zignature data string"),
            ],
            "Success status",
        ),
        _tf("search_zignatures", "Search for matching zignatures", [], "List of match dictionaries"),
        _tf(
            "save_project",
            "Save the current analysis as a Rizin project",
            [
                _tp("name", "string", "Project name"),
            ],
            "Success status",
        ),
        _tf(
            "open_project",
            "Open an existing Rizin project",
            [
                _tp("name", "string", "Project name"),
            ],
            "Success status",
        ),
        _tf("list_projects", "List available Rizin projects", [], "List of project names"),
        _tf(
            "get_config",
            "Get a Rizin configuration value",
            [
                _tp("key", "string", "Configuration key name"),
            ],
            "Configuration value",
        ),
        _tf(
            "set_config",
            "Set a Rizin configuration value",
            [
                _tp("key", "string", "Configuration key name"),
                _tp("value", "string", "Value to set"),
            ],
            "Success status",
        ),
        _tf(
            "write_xor",
            "XOR bytes at an address with a key",
            [
                _tp("address", "integer", "Start address"),
                _tp("length", "integer", "Number of bytes to XOR"),
                _tp("key", "integer", "XOR key value"),
            ],
            "Success status",
        ),
        _tf(
            "write_add",
            "Add a value to bytes at an address",
            [
                _tp("address", "integer", "Start address"),
                _tp("length", "integer", "Number of bytes"),
                _tp("value", "integer", "Value to add"),
            ],
            "Success status",
        ),
        _tf(
            "write_sub",
            "Subtract a value from bytes at an address",
            [
                _tp("address", "integer", "Start address"),
                _tp("length", "integer", "Number of bytes"),
                _tp("value", "integer", "Value to subtract"),
            ],
            "Success status",
        ),
        _tf(
            "write_from_file",
            "Write file contents to an address",
            [
                _tp("file_path", "string", "Path to file to read from"),
                _tp("address", "integer", "Destination address"),
            ],
            "Success status",
        ),
        _tf(
            "write_to_file",
            "Write bytes from an address to a file",
            [
                _tp("file_path", "string", "Output file path"),
                _tp("size", "integer", "Number of bytes to write"),
                _tp("address", "integer", "Source address"),
            ],
            "Success status",
        ),
        _tf(
            "write_value",
            "Write a numeric value at an address",
            [
                _tp("address", "integer", "Destination address"),
                _tp("value", "integer", "Value to write"),
                _tp("size", "integer", "Value size in bytes (1, 2, 4, or 8)", required=False, default=4),
            ],
            "Success status",
        ),
        _tf(
            "write_string",
            "Write a string at an address",
            [
                _tp("address", "integer", "Destination address"),
                _tp("text", "string", "String text to write"),
            ],
            "Success status",
        ),
        _tf(
            "search_string_live",
            "Search for a string in binary content",
            [
                _tp("text", "string", "String text to search for"),
            ],
            "List of addresses",
        ),
        _tf(
            "search_assembly_pattern",
            "Search for an assembly instruction pattern",
            [
                _tp("pattern", "string", "Assembly pattern to search for"),
            ],
            "List of addresses",
        ),
        _tf("search_crypto_constants", "Search for known cryptographic constants", [], "List of crypto constant matches"),
        _tf("search_magic", "Search for magic signatures in the binary", [], "List of magic matches"),
        _tf(
            "search_value",
            "Search for a numeric value in the binary",
            [
                _tp("value", "integer", "Value to search for"),
                _tp("size", "integer", "Value size in bytes (1, 2, 4, or 8)", required=False, default=4),
            ],
            "List of addresses",
        ),
        _tf(
            "compare_bytes",
            "Compare bytes at an address with given hex data",
            [
                _tp("hex_data", "string", "Hex string to compare against"),
                _tp("address", "integer", "Address to compare at"),
            ],
            "Comparison output",
        ),
        _tf(
            "compare_disassembly",
            "Compare disassembly at an address with another file",
            [
                _tp("file_path", "string", "Path to file to compare against"),
                _tp("address", "integer", "Address to compare at"),
            ],
            "Comparison output",
        ),
        _tf("get_segments", "Get binary segment information", [], "List of SegmentInfo objects"),
        _tf(
            "hexdump",
            "Get hex dump of bytes at an address",
            [
                _tp("address", "integer", "Start address"),
                _tp("length", "integer", "Number of bytes to dump", required=False, default=256),
            ],
            "Formatted hex dump text",
        ),
        _tf(
            "hexdump_words",
            "Get word-sized hex dump at an address",
            [
                _tp("address", "integer", "Start address"),
                _tp("length", "integer", "Number of bytes to dump", required=False, default=256),
            ],
            "Formatted word hex dump text",
        ),
        _tf(
            "disassemble_function",
            "Disassemble a complete function",
            [
                _tp("address", "integer", "Function address"),
            ],
            "Full function disassembly text",
        ),
        _tf(
            "get_basic_blocks",
            "Get basic blocks for a function",
            [
                _tp("address", "integer", "Function address"),
            ],
            "List of BlockInfo objects",
        ),
    ]


class CutterBridge(StaticAnalysisBridge):
    """Bridge for Cutter/Rizin reverse engineering framework.

    Provides static analysis, disassembly, and debugging capabilities using the r2pipe interface. Instances own the r2pipe connection, the
    tracked binary and tool paths, the analysis-state flags, the registered Rizin process identifier, and the declared
    ``BridgeCapabilities`` that describe the static-analysis features this bridge exposes to the orchestrator.
    """

    def __init__(self) -> None:
        """Initialize the CutterBridge instance."""
        super().__init__()
        self._r2: Any = None
        self._tool_path: Path | None = None
        self._binary_path: Path | None = None
        self._analyzed: bool = False
        self._r2_pid: int | None = None
        self._capabilities = BridgeCapabilities(
            supports_static_analysis=True,
            supports_dynamic_analysis=True,
            supports_decompilation=True,
            supports_debugging=False,
            supports_patching=True,
            supports_scripting=True,
            supported_architectures=["x86", "x86_64", "arm", "arm64", "mips", "ppc"],
            supported_formats=["pe", "elf", "macho", "raw"],
        )
        _logger.info(
            "cutter_bridge_initialized",
            supported_architectures=self._capabilities.supported_architectures,
            supported_formats=self._capabilities.supported_formats,
        )

    @property
    def r2(self) -> r2pipe.open | None:
        """Access the r2pipe connection instance.

        Returns:
            r2pipe.open | None: The r2pipe connection or None if not connected.
        """
        return self._r2

    @r2.setter
    def r2(self, value: r2pipe.open | None) -> None:
        """Set the r2pipe connection instance.

        Args:
            value: The r2pipe connection instance or None.
        """
        _logger.debug("r2_connection_set", has_connection=value is not None)
        self._r2 = value

    async def r2_cmd(self, command: str) -> str:
        """Execute an r2 command and return a guaranteed string result.

        Delegates to the internal ``_r2_cmd`` method which raises
        ``ToolError`` on failure.

        Args:
            command: The r2 command to execute.

        Returns:
            str: Command output as string, empty string if None.
        """
        _logger.debug("r2_cmd_started", command=command)
        return await self._r2_cmd(command)

    async def _r2_cmd(self, command: str) -> str:
        """Execute an r2 command and return a guaranteed string result.

        Args:
            command: The r2 command to execute.

        Returns:
            str: Command output as string, empty string if None.

        Raises:
            ToolError: If r2 is not connected or command times out.
        """
        if self._r2 is None:
            _logger.warning("_r2_cmd_without_binary", command=command)
            raise ToolError(_ERR_NO_BINARY)
        timeout = R2_COMMAND_TIMEOUT
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(self._r2.cmd, command),
                timeout=timeout,
            )
        except TimeoutError:
            _logger.warning(
                "r2_command_timeout",
                command=command,
                timeout=timeout,
            )
            msg = f"{_ERR_CMD_TIMEOUT} after {timeout}s: {command}"
            raise ToolError(msg) from None
        except (OSError, RuntimeError, ValueError) as e:
            _logger.warning("r2_command_failed", command=command, error=str(e))
            msg = f"{_ERR_CMD_FAILED}: {command}"
            raise ToolError(msg) from e
        return "" if result is None else result

    @property
    def name(self) -> ToolName:
        """Get the tool's name.

        Returns:
            ToolName: ToolName.CUTTER
        """
        return ToolName.CUTTER

    @property
    def tool_definition(self) -> ToolDefinition:
        """Get tool definition for LLM function calling.

        Returns:
            ToolDefinition: ToolDefinition with all available functions.
        """
        return ToolDefinition(
            tool_name=ToolName.CUTTER,
            description="Cutter/Rizin reverse engineering - disassembly, analysis, patching",
            functions=_build_tool_functions(),
        )

    async def initialize(self, tool_path: Path | None = None) -> None:
        """Initialize the Cutter bridge.

        Args:
            tool_path: Optional path to Cutter/Rizin installation.

        Raises:
            ToolError: If Rizin/radare2 is not available.
        """
        if tool_path is not None:
            self._tool_path = tool_path
            is_file = await asyncio.to_thread(tool_path.is_file)
            tool_dir = str(tool_path.parent) if is_file else str(tool_path)
            current_path = os.environ.get("PATH", "")
            if tool_dir not in current_path:
                os.environ["PATH"] = tool_dir + os.pathsep + current_path

        if not await self.is_available():
            raise ToolError(_ERR_TOOL_NOT_AVAILABLE)

        self.state = BridgeState(
            connected=True,
            tool_running=True,
            binary_loaded=False,
            process_attached=False,
            target_path=None,
            target_pid=None,
            last_error=None,
        )
        _logger.info("cutter_bridge_initialized", bridge="cutter")

    async def shutdown(self) -> None:
        """Shutdown Cutter bridge and cleanup resources.

        Wraps every reference-releasing step in ``try/finally`` so ``super().shutdown()`` is guaranteed to run even when an intermediate
        cleanup step raises. Without the guarantee a ``ProcessManager`` failure would leave the base ``BridgeState`` marked
        ``connected=True`` after the bridge had released its rizin handle, presenting observers with a stuck-alive state.
        """
        try:
            if self._r2 is not None:
                try:
                    await asyncio.to_thread(self._r2.quit)
                except (OSError, RuntimeError) as e:
                    _logger.warning("cutter_close_failed", error=str(e))
                finally:
                    self.r2 = None

            if self._r2_pid is not None:
                try:
                    process_manager = ProcessManager.get_instance()
                    process_manager.unregister_external_pid(self._r2_pid)
                except (OSError, RuntimeError, ValueError, KeyError) as e:
                    _logger.warning("cutter_unregister_pid_failed", pid=self._r2_pid, error=str(e))
                finally:
                    self._r2_pid = None

            self._binary_path = None
            self._analyzed = False
        finally:
            await super().shutdown()
            _logger.info("cutter_bridge_shutdown", bridge="cutter")

    @override
    async def is_available(self) -> bool:
        """Check if Cutter/Rizin is available.

        Returns:
            bool: True if Cutter/Rizin can be used.
        """
        has_in_path = shutil.which("rizin") is not None or shutil.which("radare2") is not None
        has_stored = self._tool_path is not None and self._tool_path.exists()
        if not (has_in_path or has_stored):
            _logger.debug("cutter_not_in_path")
            return False

        r2: Any = None
        try:
            r2 = await asyncio.to_thread(r2pipe.open, "-")
            version: str | None = await asyncio.to_thread(r2.cmd, "?V")
        except (OSError, RuntimeError, ValueError) as e:
            _logger.warning(
                "cutter_availability_check_failed",
                error=str(e),
                error_type=type(e).__name__,
            )
            return False
        else:
            return bool(version)
        finally:
            if r2 is not None:
                try:
                    await asyncio.to_thread(r2.quit)
                except (OSError, RuntimeError) as e:
                    _logger.warning("cutter_cleanup_failed", error=str(e))

    async def _close_existing_r2(self) -> None:
        """Close existing Rizin session and unregister process."""
        if self._r2 is not None:
            _logger.debug("r2_session_closing")
            try:
                await asyncio.to_thread(self._r2.quit)
            except (OSError, RuntimeError, ValueError) as e:
                _logger.warning("r2_session_close_failed", error=str(e))
            finally:
                self.r2 = None
            if self._r2_pid is not None:
                process_manager = ProcessManager.get_instance()
                process_manager.unregister_external_pid(self._r2_pid)
                self._r2_pid = None

    def _register_rizin_process(self, path: Path) -> None:
        """Register Rizin process with process manager.

        Args:
            path: Path to the binary being analyzed.
        """
        if not hasattr(self._r2, "_child"):
            return

        child: object = getattr(self._r2, "_child", None)
        if child is None or not hasattr(child, "pid"):
            return

        pid_val: object = getattr(child, "pid", None)
        if not isinstance(pid_val, int):
            return

        self._r2_pid = pid_val
        process_manager = ProcessManager.get_instance()
        process_manager.register_external_pid(
            self._r2_pid,
            name=f"cutter-rizin-{path.name}",
            process_type=ProcessType.EXTERNAL_TOOL,
            metadata={"binary": str(path)},
        )
        _logger.debug("cutter_process_registered", pid=self._r2_pid)

    async def _extract_hashes(self) -> tuple[str, str]:
        """Extract MD5 and SHA256 hashes from loaded binary.

        Returns:
            tuple[str, str]: Tuple of (md5, sha256) hash strings.
        """
        hashes = await self._cmd_json("itj")
        md5 = ""
        sha256 = ""
        for h in hashes:
            hash_type = _get_str(h, "type")
            if hash_type == "md5":
                md5 = _get_str(h, "hash")
            elif hash_type == "sha256":
                sha256 = _get_str(h, "hash")
        _logger.debug("binary_hashes_extracted")
        return md5, sha256

    async def _extract_binary_metadata(self) -> tuple[str, str, int, int]:
        """Extract binary metadata from Rizin.

        Returns:
            tuple[str, str, int, int]: Tuple of (file_type, arch, bits, entry_point).
        """
        info_list = await self._cmd_json("ij")
        info = info_list[0] if info_list else {}

        bin_info = _get_dict(info, "bin")
        file_type = _get_str(bin_info, "class", "unknown")
        arch = _get_str(bin_info, "arch", "unknown")
        bits = _get_int(bin_info, "bits", 32)
        entry = _get_int(bin_info, "entry", 0)

        _logger.debug("binary_metadata_extracted", file_type=file_type, arch=arch)
        return file_type, arch, bits, entry

    async def load_binary(self, path: Path | str) -> BinaryInfo:
        """Load a binary file into Cutter/Rizin.

        Args:
            path: Path to the binary file.

        Returns:
            BinaryInfo: BinaryInfo with file details.

        Raises:
            ToolError: If load fails.
        """
        if isinstance(path, str):
            path = Path(path)
        if not await asyncio.to_thread(path.exists):
            raise ToolError(_ERR_FILE_NOT_FOUND)

        if not await self.is_available():
            raise ToolError(_ERR_TOOL_NOT_AVAILABLE)

        try:
            await self._close_existing_r2()

            self.r2 = await asyncio.to_thread(r2pipe.open, str(path), ["-2"])
            self._binary_path = await asyncio.to_thread(path.resolve)
            self._analyzed = False

            self._register_rizin_process(path)

            file_type, arch, bits, entry = await self._extract_binary_metadata()
            await self._r2_cmd("e io.cache=true")
            _, sha256 = await self._extract_hashes()

            sections = await self._get_sections_internal()
            imports = await self._get_imports_internal()
            exports = await self._get_exports_internal()

            self.state.connected = True
            self.state.tool_running = True
            self.state.binary_loaded = True
            self.state.target_path = self._binary_path
            self._publish_tool_state()

            _logger.info("binary_loaded", path=path.name, file_type=file_type, arch=arch, bits=bits)

            return BinaryInfo(
                path=self._binary_path,
                name=path.name,
                size=(await asyncio.to_thread(path.stat)).st_size,
                sha256=sha256,
                file_type=file_type.lower(),
                architecture=arch,
                is_64bit=is_rizin_64bit(bits, arch, file_type),
                entry_point=entry,
                sections=sections,
                imports=imports,
                exports=exports,
            )

        except (OSError, RuntimeError, ValueError) as e:
            _logger.warning("binary_load_failed", path=str(self._binary_path), error=str(e))
            raise ToolError(_ERR_LOAD_FAILED) from e

    async def analyze(self, level: str = "normal") -> None:
        """Run analysis on the loaded binary.

        Args:
            level: Analysis level (quick, normal, deep).

        Raises:
            ToolError: If analysis fails.
        """
        if self._r2 is None:
            _logger.warning("analyze_without_binary", level=level)
            raise ToolError(_ERR_NO_BINARY)

        cmd_map = {
            "quick": "aa",
            "normal": "aaa",
            "deep": "aaaa",
        }
        cmd = cmd_map.get(level, "aaa")

        _logger.info("analysis_starting", level=level)
        await self._r2_cmd(cmd)
        self._analyzed = True
        _logger.info("analysis_complete", bridge="cutter", level=level)

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
            ToolError: If operation fails.
        """
        if self._r2 is None:
            _logger.warning("get_functions_without_binary", filter_pattern=filter_pattern)
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            _logger.warning("get_functions_without_analysis", filter_pattern=filter_pattern)
            raise ToolError(_ERR_NOT_ANALYZED)

        funcs = await self._cmd_json("aflj")

        result: list[FunctionInfo] = []
        pattern = re.compile(filter_pattern) if filter_pattern else None

        for f in funcs:
            name = _get_str(f, "name")
            if pattern and not pattern.search(name):
                continue

            result.append(
                FunctionInfo(
                    name=name,
                    address=_get_int(f, "offset"),
                    size=_get_int(f, "size"),
                    calling_convention=_get_str(f, "cc", "unknown"),
                    return_type="unknown",
                    parameters=[],
                    local_variables=[],
                    decompiled_code=None,
                    disassembly=None,
                ),
            )

        _logger.debug("functions_queried", filter_pattern=filter_pattern, result_count=len(result))
        return result

    async def get_function(self, address: int) -> FunctionInfo | None:
        """Get function at a specific address.

        Variable size and storage location are computed from the
        rizin ``afvj`` payload rather than hard-coded. The previous
        implementation reported every parameter as ``size=0`` and
        ``location="stack"`` regardless of what rizin actually
        produced, which mis-classified register-resident arguments
        (``afvj.reg``) and stripped any size information rizin had
        already inferred.

        Args:
            address: Function address.

        Returns:
            FunctionInfo | None: Function info or None if not found.

        Raises:
            ToolError: If operation fails.
        """
        if self._r2 is None:
            _logger.warning("get_function_without_binary", address=hex(address))
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            _logger.warning("get_function_without_analysis", address=hex(address))
            raise ToolError(_ERR_NOT_ANALYZED)

        await self._r2_cmd(f"s {address}")
        func_info = await self._cmd_json("afij")

        if not func_info:
            _logger.debug("function_queried", address=hex(address), found=False)
            return None

        f = func_info[0]

        vars_data_list = await self._cmd_json("afvj")
        vars_data = vars_data_list[0] if vars_data_list else {}
        word_size = self._word_size_bytes(f)

        params: list[ParameterInfo] = []
        locals_list: list[VariableInfo] = []

        for storage in ("sp", "bp", "reg"):
            location = "register" if storage == "reg" else "stack"
            for raw_var in _get_list(vars_data, storage):
                if not isinstance(raw_var, dict):
                    continue
                var = cast("dict[str, Any]", raw_var)
                var_name = _get_str(var, "name")
                var_type = _get_str(var, "type", "unknown")
                ref_data = _get_dict(var, "ref")
                var_offset = _get_int(ref_data, "offset")
                computed_size = _get_optional_int(var, "size")
                if computed_size is None:
                    computed_size = self._size_for_type(var_type, word_size)

                if _get_str(var, "kind") == "arg":
                    var_location = _get_str(ref_data, "base") or location
                    params.append(
                        ParameterInfo(
                            name=var_name,
                            type=var_type,
                            size=computed_size,
                            location=var_location,
                        ),
                    )
                else:
                    locals_list.append(
                        VariableInfo(
                            name=var_name,
                            type=var_type,
                            offset=var_offset,
                            size=computed_size,
                        ),
                    )

        _logger.debug("function_queried", address=hex(address), found=True)
        return FunctionInfo(
            name=_get_str(f, "name"),
            address=_get_int(f, "offset"),
            size=_get_int(f, "size"),
            calling_convention=_get_str(f, "cc", "unknown"),
            return_type=_get_str(f, "type", "unknown"),
            parameters=params,
            local_variables=locals_list,
            decompiled_code=None,
            disassembly=None,
        )

    @staticmethod
    def _word_size_bytes(func_info: dict[str, Any]) -> int:
        """Return the word size implied by a rizin ``afij`` entry.

        Args:
            func_info: One element of the ``afij`` payload.

        Returns:
            int: 8 when the function entry advertises a 64-bit word
            size, otherwise 4.
        """
        bits = _get_optional_int(func_info, "bits") or 0
        if bits >= _BITS_64:
            return 8
        return 4

    @staticmethod
    def _size_for_type(type_str: str, word_size: int) -> int:
        """Best-effort C-type-name to size-in-bytes mapping.

        Inspects the textual type name rizin returns in ``afvj`` to
        infer a byte size. Pointer types (``*``) and platform-sized
        types (``size_t``, ``intptr_t``, etc.) follow ``word_size``.
        Width-encoded names (``int32_t``, ``uint64_t``) are returned
        verbatim. Recognised C scalars fall back to platform-typical
        sizes used by both x86 and x86-64 ABIs. Unrecognised types
        yield ``0`` so callers can detect that no information was
        available.

        Args:
            type_str: Type name as reported by rizin (may be empty).
            word_size: Pointer/word width in bytes for the loaded
                binary (4 or 8).

        Returns:
            int: Inferred size in bytes, or 0 when unknown.
        """
        if not type_str:
            return 0
        normalized = type_str.strip().lower()
        if "*" in normalized:
            return word_size
        for token, size in (
            ("int8", 1),
            ("uint8", 1),
            ("int16", 2),
            ("uint16", 2),
            ("int32", 4),
            ("uint32", 4),
            ("int64", 8),
            ("uint64", 8),
        ):
            if token in normalized:
                return size
        if normalized in {"size_t", "ssize_t", "intptr_t", "uintptr_t", "ptrdiff_t"}:
            return word_size
        if normalized in {"char", "int8_t", "uint8_t", "bool", "_bool"}:
            return 1
        if normalized in {"short", "int16_t", "uint16_t", "wchar_t"}:
            return 2
        if normalized in {"int", "uint", "unsigned int", "float"}:
            return 4
        if normalized in {"long", "unsigned long"}:
            return word_size
        if normalized in {"long long", "unsigned long long", "double", "int64_t", "uint64_t"}:
            return 8
        return 0

    async def decompile(self, address: int) -> str:
        """Decompile function at address.

        Args:
            address: Function address.

        Returns:
            str: Decompiled C-like pseudocode.

        Raises:
            ToolError: If decompilation fails.
        """
        if self._r2 is None:
            _logger.warning("decompile_without_binary", address=hex(address))
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            _logger.warning("decompile_without_analysis", address=hex(address))
            raise ToolError(_ERR_NOT_ANALYZED)

        _logger.debug("decompile_requested", address=hex(address))
        await self._r2_cmd(f"s {address}")
        result = await self._r2_cmd("pdc")

        if not result or "Cannot" in result:
            result = await self._r2_cmd("pdg")

        if not result or "Cannot" in result:
            raise ToolError(_ERR_DECOMPILE_NA)

        return result

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
            ToolError: If disassembly fails.
        """
        if self._r2 is None:
            _logger.warning("disassemble_without_binary", address=hex(address), count=count)
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            _logger.warning("disassemble_without_analysis", address=hex(address), count=count)
            raise ToolError(_ERR_NOT_ANALYZED)

        _logger.debug("disassemble_requested", address=hex(address), count=count)
        await self._r2_cmd(f"s {address}")
        insns = await self._cmd_json(f"pdj {count}")

        result: list[DisassemblyLine] = []
        for insn in insns:
            hex_bytes = _get_str(insn, "bytes")
            opcode = _get_str(insn, "opcode")
            opcode_parts = opcode.split() if opcode else []
            mnemonic = opcode_parts[0] if opcode_parts else ""
            operands = " ".join(opcode_parts[1:]) if len(opcode_parts) > 1 else ""
            result.append(
                DisassemblyLine(
                    address=_get_int(insn, "offset"),
                    bytes_str=hex_bytes,
                    mnemonic=mnemonic,
                    operands=operands,
                    comment=_get_optional_str(insn, "comment"),
                ),
            )

        return result

    async def get_xrefs_to(self, address: int) -> list[CrossReference]:
        """Get cross-references to an address.

        Args:
            address: Target address.

        Returns:
            list[CrossReference]: List of cross-references.

        Raises:
            ToolError: If operation fails.
        """
        if self._r2 is None:
            _logger.warning("get_xrefs_to_without_binary", address=hex(address))
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            _logger.warning("get_xrefs_to_without_analysis", address=hex(address))
            raise ToolError(_ERR_NOT_ANALYZED)

        xrefs = await self._cmd_json(f"axtj @ {address}")

        result: list[CrossReference] = []
        for x in xrefs:
            ref_type = _get_str(x, "type")
            xref_type: XRefType
            if ref_type == "CALL":
                xref_type = "call"
            elif ref_type in {"JMP", "CJMP"}:
                xref_type = "jump"
            else:
                xref_type = "data"

            result.append(
                CrossReference(
                    from_address=_get_int(x, "from"),
                    to_address=address,
                    ref_type=xref_type,
                    from_function=_get_optional_str(x, "fcn_name"),
                    to_function=None,
                ),
            )

        _logger.debug("xrefs_to_queried", address=hex(address), result_count=len(result))
        return result

    async def get_xrefs_from(self, address: int) -> list[CrossReference]:
        """Get cross-references from an address.

        Args:
            address: Source address.

        Returns:
            list[CrossReference]: List of cross-references.

        Raises:
            ToolError: If operation fails.
        """
        if self._r2 is None:
            _logger.warning("get_xrefs_from_without_binary", address=hex(address))
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            _logger.warning("get_xrefs_from_without_analysis", address=hex(address))
            raise ToolError(_ERR_NOT_ANALYZED)

        xrefs = await self._cmd_json(f"axfj @ {address}")

        result: list[CrossReference] = []
        for x in xrefs:
            ref_type = _get_str(x, "type")
            xref_type: XRefType
            if ref_type == "CALL":
                xref_type = "call"
            elif ref_type in {"JMP", "CJMP"}:
                xref_type = "jump"
            else:
                xref_type = "data"

            result.append(
                CrossReference(
                    from_address=address,
                    to_address=_get_int(x, "ref"),
                    ref_type=xref_type,
                    from_function=None,
                    to_function=_get_optional_str(x, "fcn_name"),
                ),
            )

        _logger.debug("xrefs_from_queried", address=hex(address), result_count=len(result))
        return result

    async def search_strings(self, pattern: str) -> list[StringInfo]:
        """Search for strings matching pattern.

        Rizin's ``izj`` (data-section strings) listing is produced by
        the binary loader and does not require analysis, so the
        previous ``_analyzed`` precondition was unnecessarily
        restrictive -- callers were forced to pay for a full ``aaa``
        pass even though string extraction only needs the parsed file
        structure.

        Args:
            pattern: Regex pattern to match.

        Returns:
            list[StringInfo]: List of matching strings.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("search_strings_without_binary", pattern=pattern)
            raise ToolError(_ERR_NO_BINARY)

        strings = await self._cmd_json("izj")

        regex = re.compile(pattern, re.IGNORECASE)
        result: list[StringInfo] = []

        for s in strings:
            string_val = _get_str(s, "string")
            if regex.search(string_val):
                raw_encoding = _get_str(s, "type", "ascii")
                encoding: StringEncoding
                if raw_encoding == "utf-16be":
                    encoding = "utf-16be"
                elif raw_encoding == "utf-8":
                    encoding = "utf-8"
                elif raw_encoding in {"wide", "utf-16le"}:
                    encoding = "utf-16le"
                else:
                    encoding = "ascii"

                result.append(
                    StringInfo(
                        address=_get_int(s, "vaddr"),
                        value=string_val,
                        encoding=encoding,
                        section=_get_str(s, "section"),
                    ),
                )

        _logger.debug("string_search_completed", pattern=pattern, result_count=len(result))
        return result

    async def search_bytes(self, pattern: bytes | str) -> list[int]:
        """Search for byte pattern.

        Args:
            pattern: Byte sequence or hex string (e.g. '48 8B 05').

        Returns:
            list[int]: List of addresses.

        Raises:
            ToolError: If search fails.
        """
        if self._r2 is None:
            _logger.warning("search_bytes_without_binary", pattern=pattern)
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            _logger.warning("search_bytes_without_analysis", pattern=pattern)
            raise ToolError(_ERR_NOT_ANALYZED)

        clean_hex = pattern.hex() if isinstance(pattern, bytes) else pattern.replace(" ", "")
        results = await self._cmd_json(f"/xj {clean_hex}")

        addrs = [_get_int(r, "offset") for r in results]
        _logger.debug("byte_search_completed", result_count=len(addrs))
        return addrs

    async def search_bytes_wildcard(self, hex_pattern: str) -> list[int]:
        """Search for byte pattern with wildcards.

        Args:
            hex_pattern: Hex pattern like '48 8B ?? ??'.

        Returns:
            list[int]: List of addresses.

        Raises:
            ToolError: If search fails.
        """
        if self._r2 is None:
            _logger.warning("search_bytes_wildcard_without_binary", hex_pattern=hex_pattern)
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            _logger.warning("search_bytes_wildcard_without_analysis", hex_pattern=hex_pattern)
            raise ToolError(_ERR_NOT_ANALYZED)

        clean_pattern = hex_pattern.replace(" ", "").replace("??", "..")
        results = await self._cmd_json(f"/xj {clean_pattern}")

        addrs = [_get_int(r, "offset") for r in results]
        _logger.debug("wildcard_byte_search_completed", hex_pattern=hex_pattern, result_count=len(addrs))
        return addrs

    async def _get_sections_internal(self) -> list[SectionInfo]:
        """Get section information.

        Returns:
            list[SectionInfo]: List of section info.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("_get_sections_internal_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        sections = await self._cmd_json("iSj")

        return [
            SectionInfo(
                name=_get_str(s, "name"),
                virtual_address=_get_int(s, "vaddr"),
                virtual_size=_get_int(s, "vsize"),
                raw_size=_get_int(s, "size"),
                characteristics=_get_int(s, "perm"),
                entropy=_get_float(s, "entropy"),
            )
            for s in sections
        ]

    async def _get_imports_internal(self) -> list[ImportInfo]:
        """Get import information.

        Returns:
            list[ImportInfo]: List of import info.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("_get_imports_internal_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        imports = await self._cmd_json("iij")

        return [
            ImportInfo(
                dll=_get_str(i, "lib"),
                function=_get_str(i, "name"),
                ordinal=_get_optional_int(i, "ordinal"),
                address=_get_int(i, "plt"),
            )
            for i in imports
        ]

    async def _get_exports_internal(self) -> list[ExportInfo]:
        """Get export information.

        Returns:
            list[ExportInfo]: List of export info.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("_get_exports_internal_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        exports = await self._cmd_json("iEj")

        result: list[ExportInfo] = [
            ExportInfo(
                name=_get_str(e, "name"),
                ordinal=_get_int(e, "ordinal", idx),
                address=_get_int(e, "vaddr"),
            )
            for idx, e in enumerate(exports)
        ]
        return result

    async def get_imports(self) -> list[ImportInfo]:
        """Get imported functions.

        Rizin's ``iij`` (import) listing is populated by the binary
        loader, not by analysis, so the result does not depend on
        :attr:`_analyzed`. The previous behaviour of silently returning
        ``[]`` when analysis hadn't been run hid real imports from
        callers that reasonably skip ``aaa``.

        Returns:
            list[ImportInfo]: List of import information.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_imports_without_binary")
            raise ToolError(_ERR_NO_BINARY)
        result = await self._get_imports_internal()
        _logger.debug("imports_queried", result_count=len(result))
        return result

    async def get_exports(self) -> list[ExportInfo]:
        """Get exported functions.

        Rizin's ``iEj`` listing comes from the binary loader and is
        available immediately after ``load_binary``; analysis is not
        required. The previous behaviour of silently returning ``[]``
        before analysis made exports invisible to callers that did not
        run ``aaa`` first.

        Returns:
            list[ExportInfo]: List of export information.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_exports_without_binary")
            raise ToolError(_ERR_NO_BINARY)
        result = await self._get_exports_internal()
        _logger.debug("exports_queried", result_count=len(result))
        return result

    async def get_sections(self) -> list[SectionInfo]:
        """Get binary section information.

        Rizin's ``iSj`` (sections) listing reflects the parsed binary
        layout produced by the loader, so it does not require an
        analysis pass. The previous behaviour of silently returning
        ``[]`` until ``analyze()`` ran hid section metadata from
        legitimate callers.

        Returns:
            list[SectionInfo]: List of section info.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_sections_without_binary")
            raise ToolError(_ERR_NO_BINARY)
        result = await self._get_sections_internal()
        _logger.debug("sections_queried", result_count=len(result))
        return result

    async def rename_function(self, address: int, new_name: str) -> bool:
        """Rename a function.

        Args:
            address: Function address.
            new_name: New function name.

        Returns:
            bool: True if rename succeeded.

        Raises:
            ToolError: If operation fails.
        """
        if self._r2 is None:
            _logger.warning("rename_function_without_binary", address=hex(address), new_name=new_name)
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            _logger.warning("rename_function_without_analysis", address=hex(address), new_name=new_name)
            raise ToolError(_ERR_NOT_ANALYZED)

        await self._r2_cmd(f"afn {new_name} @ {address}")
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
            address: Address for comment.
            comment: Comment text.
            comment_type: Type of comment (EOL, function, unique).

        Returns:
            bool: True if comment was added.

        Raises:
            ToolError: If operation fails.
        """
        if self._r2 is None:
            _logger.warning("add_comment_without_binary", address=hex(address), comment=comment)
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            _logger.warning("add_comment_without_analysis", address=hex(address), comment=comment)
            raise ToolError(_ERR_NOT_ANALYZED)

        r2_cmd_map: dict[str, str] = {
            "function": "CCf",
            "unique": "CCu",
        }
        cmd_prefix = r2_cmd_map.get(comment_type.lower(), "CC")
        escaped = comment.replace('"', '\\"')
        await self._r2_cmd(f'{cmd_prefix} "{escaped}" @ {address}')
        _logger.info("comment_added", address=hex(address), comment_type=comment_type)
        return True

    async def write_bytes(self, address: int, hex_data: str) -> bool:
        """Write bytes at an address.

        Args:
            address: Address to write at.
            hex_data: Hex string of bytes to write (e.g. '90909090').

        Returns:
            bool: True on success.

        Raises:
            ToolError: If write fails.
        """
        if self._r2 is None:
            _logger.warning("write_bytes_without_binary", address=hex(address), hex_data=hex_data)
            raise ToolError(_ERR_NO_BINARY)

        clean_hex = hex_data.replace(" ", "")
        await self._r2_cmd(f"wx {clean_hex} @ {address}")
        _logger.info("bytes_written", length=len(clean_hex) // 2, address=hex(address))
        return True

    async def assemble_at(self, address: int, instruction: str) -> bytes:
        """Assemble an instruction and commit it at ``address``.

        Validates the assembly first via rizin's ``pa`` (dry-run
        encoding) so the returned ``bytes`` are guaranteed to match
        what gets written, then commits a single ``wx <hex>`` write at
        ``address``. The previous implementation issued both ``wa`` and
        ``wx``, which produced two writes for the same instruction;
        ``wx`` is preferred over ``wa`` because it accepts the
        already-validated hex output without re-running the assembler
        and avoids any drift between the dry-run encoding and the
        committed bytes.

        Args:
            address: Target address.
            instruction: Assembly instruction.

        Returns:
            bytes: The exact bytes written at ``address``.

        Raises:
            ToolError: If the dry-run assembly fails or returns a
                non-hex result.
        """
        if self._r2 is None:
            _logger.warning("assemble_at_without_binary", address=hex(address), instruction=instruction)
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            _logger.warning("assemble_at_without_analysis", address=hex(address), instruction=instruction)
            raise ToolError(_ERR_NOT_ANALYZED)

        dry_run = await self._r2_cmd(f"pa {instruction} @ {address}")

        if not dry_run or not dry_run.strip() or "Cannot" in dry_run:
            raise ToolError(_ERR_ASSEMBLE_FAILED)

        assembled_hex = dry_run.strip()

        try:
            assembled_bytes = bytes.fromhex(assembled_hex)
        except ValueError as exc:
            raise ToolError(_ERR_ASSEMBLE_FAILED) from exc

        await self._r2_cmd(f"wx {assembled_hex} @ {address}")

        _logger.info("instruction_assembled", instruction=instruction, address=hex(address))
        return assembled_bytes

    async def execute_command(self, command: str) -> str:
        """Execute raw Rizin command.

        Args:
            command: Rizin command to execute.

        Returns:
            str: Command output.
        """
        _logger.debug("raw_command_executed", command=command)
        return await self._r2_cmd(command)

    async def _cmd_json(self, command: str) -> list[dict[str, Any]]:
        """Execute command and parse JSON output.

        Args:
            command: Command to execute.

        Returns:
            list[dict[str, Any]]: Parsed JSON as list of dicts. An empty
            list is only returned when the command produced an empty
            response (which rizin uses to indicate ``no results``); a
            response that fails to parse as JSON is treated as a
            command-execution failure and surfaces as ``ToolError``.

        Raises:
            ToolError: If no binary is loaded or the command output
                cannot be decoded as JSON.
        """
        if self._r2 is None:
            _logger.warning("cmd_json_without_binary", command=command)
            raise ToolError(_ERR_NO_BINARY)

        result = await self._r2_cmd(command)

        if not result or not result.strip():
            return []

        try:
            parsed = json.loads(result)
        except json.JSONDecodeError as exc:
            _logger.warning(
                "json_parse_failed",
                command=command,
                error=str(exc),
                response_prefix=result[:120],
            )
            msg = f"{_ERR_JSON_PARSE_FAILED}: {command}"
            raise ToolError(msg) from exc
        if isinstance(parsed, list):
            return cast("list[dict[str, Any]]", parsed)
        return [cast("dict[str, Any]", parsed)] if isinstance(parsed, dict) else []

    async def seek(self, address: int) -> str:
        """Seek to a specific address.

        Args:
            address: Target address.

        Returns:
            str: Output of seek command.
        """
        _logger.debug("seek_to_address", address=hex(address))
        return await self.execute_command(f"s {address}")

    async def get_function_graph(self, address: int) -> list[dict[str, Any]]:
        """Get function control flow graph data for graph rendering.

        Args:
            address: Address of the function to graph.

        Returns:
            list[dict[str, Any]]: List of basic block dictionaries from r2 agj output.

        Raises:
            ToolError: If no binary is loaded or command fails.
        """
        if self._r2 is None:
            _logger.warning("function_graph_without_binary", address=hex(address))
            raise ToolError(_ERR_NO_BINARY)

        _logger.debug("function_graph_queried", address=hex(address))
        result = await self._cmd_json(f"agj @ {hex(address)}")
        if result:
            first = result[0]
            if "blocks" in first:
                blocks = first["blocks"]
                if isinstance(blocks, list):
                    return cast("list[dict[str, Any]]", blocks)
            return result
        return []

    async def get_function_address(self, name: str) -> int | None:
        """Get address of a function by name.

        Resolves ``name`` directly through rizin's ``afij <name>``
        command, which returns the function info entry for the named
        symbol when one exists. The previous implementation enumerated
        every analysed function through ``get_functions`` and filtered
        the result in Python, paying a full ``aflj`` round-trip on
        every call.

        Args:
            name: Function name. Empty names are rejected; names
                containing rizin command-control characters are also
                rejected to avoid command injection.

        Returns:
            int | None: Address of function or ``None`` if no symbol
            with that exact name resolves.

        Raises:
            ToolError: If no binary is loaded, the binary has not been
                analysed, or ``name`` is empty/invalid.
        """
        if self._r2 is None:
            _logger.warning("get_function_address_without_binary", function_name=name)
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            _logger.warning("get_function_address_without_analysis", function_name=name)
            raise ToolError(_ERR_NOT_ANALYZED)
        if not name:
            msg = "get_function_address: name must not be empty"
            raise ToolError(msg)

        validate_r2_argument(name, field="get_function_address name")
        _logger.debug("get_function_address_started", function_name=name)

        info = await self._cmd_json(f"afij {name}")
        if not info:
            return None

        entry = info[0]
        resolved_name = _get_str(entry, "name")
        if resolved_name != name:
            return None
        return _get_optional_int(entry, "offset")

    async def get_all_strings(self) -> list[StringInfo]:
        """Get all strings from the binary including non-data sections.

        Returns:
            list[StringInfo]: List of all string information.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_all_strings_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        strings = await self._cmd_json("izzj")
        result: list[StringInfo] = []
        for s in strings:
            raw_encoding = _get_str(s, "type", "ascii")
            encoding: StringEncoding
            if raw_encoding == "utf-16be":
                encoding = "utf-16be"
            elif raw_encoding == "utf-8":
                encoding = "utf-8"
            elif raw_encoding in {"wide", "utf-16le"}:
                encoding = "utf-16le"
            else:
                encoding = "ascii"
            result.append(
                StringInfo(
                    address=_get_int(s, "vaddr"),
                    value=_get_str(s, "string"),
                    encoding=encoding,
                    section=_get_str(s, "section"),
                ),
            )
        _logger.debug("all_strings_queried", result_count=len(result))
        return result

    async def get_symbols(self) -> list[SymbolInfo]:
        """Get all symbols from the binary.

        Returns:
            list[SymbolInfo]: List of symbol information.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_symbols_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        symbols = await self._cmd_json("isj")
        result: list[SymbolInfo] = [
            SymbolInfo(
                name=_get_str(s, "name"),
                address=_get_int(s, "vaddr"),
                module_name=_get_optional_str(s, "libname") or "",
                file_name=None,
                line_number=None,
            )
            for s in symbols
        ]
        _logger.debug("symbols_queried", result_count=len(result))
        return result

    async def get_libraries(self) -> list[LibraryInfo]:
        """Get linked libraries from the binary.

        Returns:
            list[LibraryInfo]: List of library information.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_libraries_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        raw = await self._r2_cmd("ilj")
        result: list[LibraryInfo] = []
        if raw.strip():
            try:
                parsed_raw = json.loads(raw)
            except json.JSONDecodeError:
                _logger.exception("libraries_json_parse_failed")
                return result
            if isinstance(parsed_raw, list):
                lib_list = cast("list[Any]", parsed_raw)
                for lib_entry in lib_list:
                    if isinstance(lib_entry, str):
                        result.append(LibraryInfo(name=lib_entry))
                    elif isinstance(lib_entry, dict):
                        lib_dict = cast("dict[str, Any]", lib_entry)
                        result.append(LibraryInfo(name=_get_str(lib_dict, "name")))
        _logger.debug("libraries_queried", result_count=len(result))
        return result

    async def get_headers(self) -> list[HeaderInfo]:
        """Get binary header field information.

        Returns:
            list[HeaderInfo]: List of header field information.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_headers_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        headers = await self._cmd_json("ihj")
        result: list[HeaderInfo] = [
            HeaderInfo(
                name=_get_str(h, "name"),
                value=str(h.get("value", "")),
                address=_get_int(h, "paddr"),
            )
            for h in headers
        ]
        _logger.debug("headers_queried", result_count=len(result))
        return result

    async def get_debug_info(self) -> dict[str, Any]:
        """Get debug information from the binary.

        Returns:
            dict[str, Any]: Debug information dictionary.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_debug_info_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        result = await self._cmd_json("iDj")
        _logger.debug("binary_debug_info_queried")
        return result[0] if result else {}

    async def get_classes(self) -> list[ClassInfo]:
        """Get class information from the binary.

        Methods and fields rizin reports under ``icj`` are normalised
        into uniformly-shaped dictionaries -- every method gets
        ``name``, ``address``, ``flags``, ``type``; every field gets
        ``name``, ``offset``, ``size``, ``type``. The previous
        implementation forwarded rizin's raw entries, leaving callers
        to deal with rizin's varying key spellings (``addr`` vs
        ``vaddr``, ``offset`` vs ``paddr``) and inconsistently-typed
        values.

        Returns:
            list[ClassInfo]: List of class information.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_classes_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        classes = await self._cmd_json("icj")
        result: list[ClassInfo] = [
            ClassInfo(
                name=_get_str(c, "classname", _get_str(c, "name")),
                address=_get_int(c, "addr", _get_int(c, "vaddr")),
                methods=self._normalize_class_methods(_get_list(c, "methods")),
                fields=self._normalize_class_fields(_get_list(c, "fields")),
            )
            for c in classes
        ]
        _logger.debug("classes_queried", result_count=len(result))
        return result

    @staticmethod
    def _normalize_class_methods(raw_methods: list[Any]) -> list[dict[str, Any]]:
        """Normalise rizin ``icj`` method entries.

        Args:
            raw_methods: Raw ``methods`` list from a single rizin
                ``icj`` class entry.

        Returns:
            list[dict[str, Any]]: One dictionary per method with keys
            ``name``, ``address``, ``flags`` and ``type``.
        """
        normalized: list[dict[str, Any]] = []
        for entry in raw_methods:
            if not isinstance(entry, dict):
                continue
            method = cast("dict[str, Any]", entry)
            method_type = _get_str(method, "type")
            normalized.append(
                {
                    "name": _get_str(method, "name"),
                    "address": _get_int(method, "addr", _get_int(method, "vaddr")),
                    "flags": _get_str(method, "flags") or method_type,
                    "type": method_type,
                },
            )
        return normalized

    @staticmethod
    def _normalize_class_fields(raw_fields: list[Any]) -> list[dict[str, Any]]:
        """Normalise rizin ``icj`` field entries.

        Args:
            raw_fields: Raw ``fields`` list from a single rizin
                ``icj`` class entry.

        Returns:
            list[dict[str, Any]]: One dictionary per field with keys
            ``name``, ``offset``, ``size`` and ``type``.
        """
        normalized: list[dict[str, Any]] = []
        for entry in raw_fields:
            if not isinstance(entry, dict):
                continue
            field_entry = cast("dict[str, Any]", entry)
            normalized.append(
                {
                    "name": _get_str(field_entry, "name"),
                    "offset": _get_int(
                        field_entry,
                        "offset",
                        _get_int(field_entry, "paddr", _get_int(field_entry, "addr")),
                    ),
                    "size": _get_int(field_entry, "size"),
                    "type": _get_str(field_entry, "type"),
                },
            )
        return normalized

    async def get_relocations(self) -> list[RelocationInfo]:
        """Get relocation table entries from the binary.

        Returns:
            list[RelocationInfo]: List of relocation information.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_relocations_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        relocs = await self._cmd_json("iRj")
        result: list[RelocationInfo] = [
            RelocationInfo(
                name=_get_str(r, "name"),
                address=_get_int(r, "paddr"),
                type=_get_str(r, "type"),
                vaddr=_get_int(r, "vaddr"),
            )
            for r in relocs
        ]
        _logger.debug("relocations_queried", result_count=len(result))
        return result

    async def get_resources(self) -> list[ResourceInfo]:
        """Get embedded resources from the binary.

        Resource enumeration is performed via rizin's ``irj`` command.
        Errors raised by the underlying command (timeouts, JSON parse
        failures, missing-binary checks) are propagated to the caller
        as ``ToolError`` rather than being swallowed and reported as
        an empty list, so genuine failures are not silently hidden
        behind a ``no resources`` outcome.

        Returns:
            list[ResourceInfo]: List of resource information.

        Raises:
            ToolError: If no binary is loaded or the ``irj`` command
                fails.
        """
        if self._r2 is None:
            _logger.warning("get_resources_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        resources = await self._cmd_json("irj")
        result: list[ResourceInfo] = [
            ResourceInfo(
                name=_get_str(r, "name"),
                address=_get_int(r, "paddr"),
                size=_get_int(r, "size"),
                type=_get_str(r, "type"),
                language=_get_str(r, "language"),
            )
            for r in resources
        ]
        _logger.debug("resources_queried", result_count=len(result))
        return result

    async def search_rop_gadgets(self, pattern: str = "") -> list[GadgetInfo]:
        """Search for ROP gadgets in the binary.

        Args:
            pattern: Optional pattern to filter gadgets.

        Returns:
            list[GadgetInfo]: List of ROP gadget information.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("search_rop_gadgets_without_binary", pattern=pattern)
            raise ToolError(_ERR_NO_BINARY)

        cmd = f"/Rj {pattern}" if pattern else "/Rj"
        gadgets = await self._cmd_json(cmd)
        result: list[GadgetInfo] = [
            GadgetInfo(
                address=_get_int(g, "addr", _get_int(g, "offset")),
                instructions=_get_str(g, "opcodes", _get_str(g, "opcode")),
                size=_get_int(g, "size"),
            )
            for g in gadgets
        ]
        _logger.debug("rop_gadgets_searched", pattern=pattern, result_count=len(result))
        return result

    async def get_callgraph(self) -> list[dict[str, Any]]:
        """Get the function call graph.

        Returns:
            list[dict[str, Any]]: List of callgraph edge dictionaries.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_callgraph_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        result = await self._cmd_json("agcj")
        _logger.debug("callgraph_queried", edge_count=len(result))
        return result

    async def get_vtables(self) -> list[VtableInfo]:
        """Get virtual function tables from the binary.

        Returns:
            list[VtableInfo]: List of vtable information.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_vtables_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        vtables = await self._cmd_json("avj")
        result: list[VtableInfo] = [
            VtableInfo(
                address=_get_int(v, "offset"),
                methods=_get_list(v, "methods"),
                name=_get_str(v, "classname", _get_str(v, "name")),
            )
            for v in vtables
        ]
        _logger.debug("vtables_queried", result_count=len(result))
        return result

    async def get_syscalls(self) -> list[dict[str, Any]]:
        """Get syscall information from the binary.

        Returns:
            list[dict[str, Any]]: List of syscall dictionaries.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_syscalls_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        result = await self._cmd_json("asj")
        _logger.debug("syscalls_queried", result_count=len(result))
        return result

    async def read_bytes(self, address: int, count: int) -> bytes:
        """Read raw bytes from the binary at an address.

        Args:
            address: Address to read from.
            count: Number of bytes to read.

        Returns:
            bytes: Raw bytes read from the binary.

        Raises:
            ToolError: If no binary is loaded or read fails.
        """
        if self._r2 is None:
            _logger.warning("read_bytes_without_binary", address=hex(address), count=count)
            raise ToolError(_ERR_NO_BINARY)

        result = await self._r2_cmd(f"p8 {count} @ {address}")
        hex_str = result.strip()
        if not hex_str:
            return b""
        _logger.debug("bytes_read", address=hex(address), count=count)
        return bytes.fromhex(hex_str)

    async def save_binary(self, path: str | None = None) -> bool:
        """Save the binary with all cached patches applied.

        Uses rizin's ``wcf <file>`` (write cache to file) command so the
        full IO image -- original bytes plus every cached patch produced
        by ``io.cache=true`` -- is written to ``path``. The previously
        used ``wtf`` command emits only the current block (default
        256 bytes) and is therefore unsuitable for saving a patched
        binary in its entirety.

        Args:
            path: Output file path. If ``None``, overwrites the
                originally loaded binary.

        Returns:
            bool: ``True`` when ``wcf`` accepted the request.

        Raises:
            ToolError: If no binary is loaded, no original path is
                tracked when ``path`` is ``None``, or rizin reports a
                save failure.
        """
        if self._r2 is None:
            _logger.warning("save_binary_without_binary", path=str(path))
            raise ToolError(_ERR_NO_BINARY)

        if path is None:
            if self._binary_path is None:
                _logger.warning("save_binary_no_default_target")
                raise ToolError(_ERR_NO_BINARY)
            target = str(self._binary_path)
        else:
            target = path

        validate_r2_argument(target, field="save_binary path")
        result = await self._r2_cmd(f"wcf {target}")
        if "error" in result.lower() or "cannot" in result.lower() or "fail" in result.lower():
            _logger.warning("binary_save_failed", path=target, response=result.strip())
            msg = f"failed to save binary to {target}: {result.strip()}"
            raise ToolError(msg)
        _logger.info("binary_saved", path=target)
        return True

    async def get_comments(self) -> list[CommentInfo]:
        """Get all comments/annotations in the binary.

        Returns:
            list[CommentInfo]: List of comment information.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_comments_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        comments = await self._cmd_json("CCj")
        result: list[CommentInfo] = [
            CommentInfo(
                address=_get_int(c, "offset"),
                text=_get_str(c, "name", _get_str(c, "comment")),
                comment_type=_get_str(c, "type", "inline"),
            )
            for c in comments
        ]
        _logger.debug("comments_queried", result_count=len(result))
        return result

    async def get_flags(self) -> list[FlagInfo]:
        """Get all flags/labels from the binary.

        Returns:
            list[FlagInfo]: List of flag information.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_flags_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        flags = await self._cmd_json("fj")
        result: list[FlagInfo] = [
            FlagInfo(
                name=_get_str(f, "name"),
                address=_get_int(f, "offset"),
                size=_get_int(f, "size"),
            )
            for f in flags
        ]
        _logger.debug("flags_queried", result_count=len(result))
        return result

    async def add_flag(self, name: str, size: int, address: int) -> bool:
        """Add a named flag at an address.

        Args:
            name: Flag name.
            size: Size covered by the flag.
            address: Address for the flag.

        Returns:
            bool: True if flag was added.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("add_flag_without_binary", flag_name=name, size=size, address=hex(address))
            raise ToolError(_ERR_NO_BINARY)

        await self._r2_cmd(f"f {name} {size} @ {address}")
        _logger.info("flag_added", flag_name=name, address=hex(address))
        return True

    async def resolve_flag(self, address: int) -> str | None:
        """Resolve a flag name from an address.

        Uses rizin's ``fdj`` (flag-distance JSON) command and parses the
        structured payload rather than scraping the textual ``fd`` output.
        The nearest flag by absolute distance is returned.

        Args:
            address: Address to resolve.

        Returns:
            str | None: Flag name or None if no flag at address.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("resolve_flag_without_binary", address=hex(address))
            raise ToolError(_ERR_NO_BINARY)

        raw = await self._r2_cmd(f"fdj @ {address}")
        flag_name: str | None = None

        if raw.strip():
            try:
                parsed: Any = json.loads(raw)
            except json.JSONDecodeError:
                _logger.warning("flag_resolve_json_parse_failed", address=hex(address))
            else:
                candidates: list[dict[str, Any]] = []
                if isinstance(parsed, dict):
                    candidates.append(cast("dict[str, Any]", parsed))
                elif isinstance(parsed, list):
                    candidates.extend(cast("dict[str, Any]", entry) for entry in cast("list[Any]", parsed) if isinstance(entry, dict))

                if candidates:
                    nearest = min(
                        candidates,
                        key=lambda item: abs(_get_int(item, "offset", _get_int(item, "addr", address)) - address),
                    )
                    flag_name = _get_optional_str(nearest, "name") or None

        _logger.debug("flag_resolved", address=hex(address), flag=flag_name)
        return flag_name

    async def get_types(self) -> list[dict[str, Any]]:
        """Get all defined types from the binary analysis.

        Returns:
            list[dict[str, Any]]: List of type definition dictionaries.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_types_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        result = await self._cmd_json("tj")
        _logger.debug("types_queried", result_count=len(result))
        return result

    async def get_structs(self) -> list[dict[str, Any]]:
        """Get all struct definitions from the binary.

        Returns:
            list[dict[str, Any]]: List of struct definition dictionaries.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_structs_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        result = await self._cmd_json("tsj")
        _logger.debug("structs_queried", result_count=len(result))
        return result

    async def get_unions(self) -> list[dict[str, Any]]:
        """Get all union definitions from the binary.

        Returns:
            list[dict[str, Any]]: List of union definition dictionaries.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_unions_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        result = await self._cmd_json("tuj")
        _logger.debug("unions_queried", result_count=len(result))
        return result

    async def get_enums(self) -> list[dict[str, Any]]:
        """Get all enum definitions from the binary.

        Returns:
            list[dict[str, Any]]: List of enum definition dictionaries.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_enums_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        result = await self._cmd_json("tej")
        _logger.debug("enums_queried", result_count=len(result))
        return result

    async def get_typedefs(self) -> list[dict[str, Any]]:
        """Get all typedef definitions from the binary.

        Returns:
            list[dict[str, Any]]: List of typedef definition dictionaries.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_typedefs_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        result = await self._cmd_json("ttj")
        _logger.debug("typedefs_queried", result_count=len(result))
        return result

    async def get_function_types(self) -> list[dict[str, Any]]:
        """Get all function type signatures from the binary.

        Returns:
            list[dict[str, Any]]: List of function type dictionaries.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_function_types_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        result = await self._cmd_json("tfsj")
        _logger.debug("function_types_queried", result_count=len(result))
        return result

    async def import_c_header(self, header_text: str) -> bool:
        """Import C header type definitions into the analysis.

        Writes ``header_text`` to a temporary ``.h`` file, invokes rizin's
        ``to`` command pointing at that file, and removes the temporary
        file on both success and failure paths.

        Args:
            header_text: C header source text to parse.

        Returns:
            bool: True if import succeeded.

        Raises:
            ToolError: If no binary is loaded or import fails.
        """
        if self._r2 is None:
            _logger.warning("import_c_header_without_binary", header_text=header_text)
            raise ToolError(_ERR_NO_BINARY)

        def _write_temp() -> Path:
            fd, name = tempfile.mkstemp(suffix=".h", prefix="intellicrack_hdr_")
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(header_text)
            return Path(name)

        temp_path = await asyncio.to_thread(_write_temp)
        try:
            await self._r2_cmd(f'"to {temp_path}"')
            _logger.info("c_header_imported", length=len(header_text))
        finally:
            await asyncio.to_thread(temp_path.unlink, missing_ok=True)
        return True

    async def esil_eval(self, expression: str) -> str:
        """Evaluate an ESIL expression.

        Args:
            expression: ESIL expression to evaluate.

        Returns:
            str: Evaluation result.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("esil_eval_without_binary", expression=expression)
            raise ToolError(_ERR_NO_BINARY)

        result = await self._r2_cmd(f"ae {expression}")
        _logger.debug("esil_eval_executed", expression=expression)
        return result

    async def esil_step(self, count: int = 1) -> str:
        """Step the ESIL emulator forward.

        Args:
            count: Number of steps to take.

        Returns:
            str: Step output.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("esil_step_without_binary", count=count)
            raise ToolError(_ERR_NO_BINARY)

        result = ""
        for _ in range(count):
            result = await self._r2_cmd("aes")
        _logger.debug("esil_stepped", count=count)
        return result

    async def esil_emulate_function(self, address: int) -> str:
        """Emulate a function using ESIL.

        Args:
            address: Function address to emulate.

        Returns:
            str: Emulation output.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("esil_emulate_function_without_binary", address=hex(address))
            raise ToolError(_ERR_NO_BINARY)

        result = await self._r2_cmd(f"aef @ {address}")
        _logger.debug("esil_function_emulated", address=hex(address))
        return result

    async def esil_init_memory(self) -> bool:
        """Initialize ESIL emulation memory stack.

        Returns:
            bool: True if initialization succeeded.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("esil_init_memory_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        await self._r2_cmd("aeim")
        _logger.debug("esil_memory_initialized")
        return True

    async def esil_set_pc(self, address: int) -> bool:
        """Set the ESIL program counter.

        Args:
            address: Address to set the PC to.

        Returns:
            bool: True if PC was set.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("esil_set_pc_without_binary", address=hex(address))
            raise ToolError(_ERR_NO_BINARY)

        await self._r2_cmd(f"aepc {address}")
        _logger.debug("esil_pc_set", address=hex(address))
        return True

    async def get_zignatures(self) -> list[dict[str, Any]]:
        """Get all zignatures (function signatures).

        Returns:
            list[dict[str, Any]]: List of zignature dictionaries.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_zignatures_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        result = await self._cmd_json("zj")
        _logger.debug("zignatures_queried", result_count=len(result))
        return result

    async def generate_zignatures(self, address: int | None = None) -> bool:
        """Generate zignatures from analyzed functions.

        Args:
            address: Optional specific function address. If None, generates for all.

        Returns:
            bool: True if generation succeeded.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning(
                "generate_zignatures_without_binary",
                address=hex(address) if address is not None else None,
            )
            raise ToolError(_ERR_NO_BINARY)

        cmd = f"zg @ {address}" if address is not None else "zg"
        await self._r2_cmd(cmd)
        _logger.info("zignatures_generated", address=hex(address) if address else "all")
        return True

    async def add_zignature(self, name: str, zigdata: str) -> bool:
        """Add a zignature definition.

        Args:
            name: Zignature name.
            zigdata: Zignature data string.

        Returns:
            bool: True if zignature was added.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("add_zignature_without_binary", zignature_name=name, zigdata=zigdata)
            raise ToolError(_ERR_NO_BINARY)

        await self._r2_cmd(f"za {name} {zigdata}")
        _logger.info("zignature_added", zig_name=name)
        return True

    async def search_zignatures(self) -> list[dict[str, Any]]:
        """Search for matching zignatures in the binary.

        Returns:
            list[dict[str, Any]]: List of zignature match dictionaries.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("search_zignatures_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        result = await self._cmd_json("z/j")
        _logger.debug("zignatures_searched", result_count=len(result))
        return result

    async def save_project(self, name: str) -> bool:
        """Save the current analysis as a Rizin project.

        Args:
            name: Project name.

        Returns:
            bool: True if project was saved.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("save_project_without_binary", project_name=name)
            raise ToolError(_ERR_NO_BINARY)

        await self._r2_cmd(f"Ps {name}")
        _logger.info("project_saved", project_name=name)
        return True

    async def open_project(self, name: str) -> bool:
        """Open an existing Rizin project.

        Args:
            name: Project name.

        Returns:
            bool: True if project was opened.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("open_project_without_binary", project_name=name)
            raise ToolError(_ERR_NO_BINARY)

        await self._r2_cmd(f"Po {name}")
        _logger.info("project_opened", project_name=name)
        return True

    async def list_projects(self) -> list[str]:
        """List available Rizin projects.

        Returns:
            list[str]: List of project names.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("list_projects_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        result = await self._r2_cmd("Pl")
        projects = [line.strip() for line in result.splitlines() if line.strip()]
        _logger.debug("projects_listed", count=len(projects))
        return projects

    async def get_config(self, key: str) -> str:
        """Get a Rizin configuration value.

        Args:
            key: Configuration key name.

        Returns:
            str: Configuration value.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_config_without_binary", key=key)
            raise ToolError(_ERR_NO_BINARY)

        result = await self._r2_cmd(f"e {key}")
        _logger.debug("config_read", key=key)
        return result.strip()

    async def set_config(self, key: str, value: str) -> bool:
        """Set a Rizin configuration value.

        Args:
            key: Configuration key name.
            value: Value to set.

        Returns:
            bool: True if configuration was set.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("set_config_without_binary", key=key, value=value)
            raise ToolError(_ERR_NO_BINARY)

        await self._r2_cmd(f"e {key}={value}")
        _logger.debug("config_set", key=key, value=value)
        return True

    async def write_xor(self, address: int, length: int, key: int) -> bool:
        """XOR bytes at an address with a key.

        Uses rizin's ``@!{length}`` block-size suffix so the operation
        targets exactly ``length`` bytes regardless of the current block
        size configured in the session.

        Args:
            address: Start address.
            length: Number of bytes to XOR.
            key: XOR key value.

        Returns:
            bool: True if write succeeded.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("write_xor_without_binary", address=hex(address), length=length)
            raise ToolError(_ERR_NO_BINARY)

        await self._r2_cmd(f"wox {key} @ {address} @!{length}")
        _logger.info("xor_written", address=hex(address), length=length, key=key)
        return True

    async def write_add(self, address: int, length: int, value: int) -> bool:
        """Add a value to bytes at an address.

        Uses rizin's ``@!{length}`` block-size suffix so the operation
        targets exactly ``length`` bytes regardless of the current block
        size configured in the session.

        Args:
            address: Start address.
            length: Number of bytes.
            value: Value to add.

        Returns:
            bool: True if write succeeded.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("write_add_without_binary", address=hex(address), length=length)
            raise ToolError(_ERR_NO_BINARY)

        await self._r2_cmd(f"woa {value} @ {address} @!{length}")
        _logger.info("add_written", address=hex(address), length=length)
        return True

    async def write_sub(self, address: int, length: int, value: int) -> bool:
        """Subtract a value from bytes at an address.

        Uses rizin's ``@!{length}`` block-size suffix so the operation
        targets exactly ``length`` bytes regardless of the current block
        size configured in the session.

        Args:
            address: Start address.
            length: Number of bytes.
            value: Value to subtract.

        Returns:
            bool: True if write succeeded.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("write_sub_without_binary", address=hex(address), length=length)
            raise ToolError(_ERR_NO_BINARY)

        await self._r2_cmd(f"wos {value} @ {address} @!{length}")
        _logger.info("sub_written", address=hex(address), length=length)
        return True

    async def write_from_file(self, file_path: str, address: int) -> bool:
        """Write file contents to an address.

        Args:
            file_path: Path to file to read from.
            address: Destination address.

        Returns:
            bool: True if write succeeded.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("write_from_file_without_binary", file_path=file_path, address=hex(address))
            raise ToolError(_ERR_NO_BINARY)

        await self._r2_cmd(f"wf {file_path} @ {address}")
        _logger.info("file_written", file_path=file_path, address=hex(address))
        return True

    async def write_to_file(self, file_path: str, size: int, address: int) -> bool:
        """Write bytes from an address to a file.

        Args:
            file_path: Output file path.
            size: Number of bytes to write.
            address: Source address.

        Returns:
            bool: True if write succeeded.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("write_to_file_without_binary", file_path=file_path, address=hex(address))
            raise ToolError(_ERR_NO_BINARY)

        await self._r2_cmd(f"wtf {file_path} {size} @ {address}")
        _logger.info("written_to_file", file_path=file_path, size=size, address=hex(address))
        return True

    async def write_value(self, address: int, value: int, size: int = 4) -> bool:
        """Write a numeric value at an address.

        Args:
            address: Destination address.
            value: Value to write.
            size: Value size in bytes (1, 2, 4, or 8).

        Returns:
            bool: True if write succeeded.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("write_value_without_binary", address=hex(address), size=size)
            raise ToolError(_ERR_NO_BINARY)

        await self._r2_cmd(f"wv{size} {value} @ {address}")
        _logger.info("value_written", address=hex(address), value=value, size=size)
        return True

    async def write_string(self, address: int, text: str) -> bool:
        """Write a string at an address.

        Args:
            address: Destination address.
            text: String text to write.

        Returns:
            bool: True if write succeeded.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("write_string_without_binary", address=hex(address), length=len(text))
            raise ToolError(_ERR_NO_BINARY)

        escaped = text.replace('"', '\\"')
        await self._r2_cmd(f'w "{escaped}" @ {address}')
        _logger.info("string_written", address=hex(address), length=len(text))
        return True

    async def search_string_live(self, text: str) -> list[int]:
        """Search for a literal string in binary content.

        Encodes ``text`` to UTF-8 hex and dispatches a ``/xj`` byte
        search instead of forwarding the raw text through ``/j``. This
        eliminates rizin command-injection vectors (``;``, ``@``,
        ``|``, ``~``, backticks, etc.) that the previous implementation
        carried by interpolating user input directly into the command
        string.

        Args:
            text: String text to search for. Empty strings are
                rejected because rizin would otherwise return every
                address in the binary.

        Returns:
            list[int]: List of addresses where the string was found.

        Raises:
            ToolError: If no binary is loaded or ``text`` is empty.
        """
        if self._r2 is None:
            _logger.warning("search_string_live_without_binary", text=text)
            raise ToolError(_ERR_NO_BINARY)
        if not text:
            msg = "search_string_live: text must not be empty"
            raise ToolError(msg)

        hex_pattern = text.encode("utf-8").hex()
        results = await self._cmd_json(f"/xj {hex_pattern}")
        addrs = [_get_int(r, "offset") for r in results]
        _logger.debug("string_search_live", text_length=len(text), result_count=len(addrs))
        return addrs

    async def search_assembly_pattern(self, pattern: str) -> list[int]:
        """Search for an assembly instruction pattern.

        Validates ``pattern`` via :func:`validate_r2_argument` so that
        rizin command-control characters (``;``, ``@``, ``|``, ``~``,
        backticks, ``>``) cannot be used to inject additional rizin
        commands through the searched text.

        Args:
            pattern: Assembly pattern to search for (e.g. ``mov eax,
                ebx``). Empty patterns are rejected.

        Returns:
            list[int]: List of addresses matching the pattern.

        Raises:
            ToolError: If no binary is loaded, ``pattern`` is empty, or
                ``pattern`` contains rizin command-control characters.
        """
        if self._r2 is None:
            _logger.warning("search_assembly_pattern_without_binary", pattern=pattern)
            raise ToolError(_ERR_NO_BINARY)
        if not pattern:
            msg = "search_assembly_pattern: pattern must not be empty"
            raise ToolError(msg)

        validate_r2_argument(pattern, field="search_assembly_pattern pattern")
        results = await self._cmd_json(f"/aj {pattern}")
        addrs = [_get_int(r, "offset") for r in results]
        _logger.debug("assembly_pattern_searched", pattern_length=len(pattern), result_count=len(addrs))
        return addrs

    async def search_crypto_constants(self) -> list[dict[str, Any]]:
        """Search for known cryptographic constants in the binary.

        Returns:
            list[dict[str, Any]]: List of crypto constant match dictionaries.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("search_crypto_constants_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        result = await self._cmd_json("/cj")
        _logger.debug("crypto_constants_searched", result_count=len(result))
        return result

    async def search_magic(self) -> list[dict[str, Any]]:
        """Search for magic signatures in the binary.

        Returns:
            list[dict[str, Any]]: List of magic match dictionaries.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("search_magic_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        result = await self._cmd_json("/mj")
        _logger.debug("magic_searched", result_count=len(result))
        return result

    async def search_value(self, value: int, size: int = 4) -> list[int]:
        """Search for a numeric value in the binary.

        Args:
            value: Value to search for.
            size: Value size in bytes (1, 2, 4, or 8).

        Returns:
            list[int]: List of addresses where the value was found.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("search_value_without_binary", value=value, size=size)
            raise ToolError(_ERR_NO_BINARY)

        results = await self._cmd_json(f"/vj{size} {value}")
        addrs = [_get_int(r, "offset") for r in results]
        _logger.debug("value_searched", value=value, size=size, result_count=len(addrs))
        return addrs

    async def compare_bytes(self, hex_data: str, address: int) -> str:
        """Compare bytes at an address with given hex data.

        Args:
            hex_data: Hex string to compare against.
            address: Address to compare at.

        Returns:
            str: Comparison output text.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("compare_bytes_without_binary", hex_data=hex_data, address=hex(address))
            raise ToolError(_ERR_NO_BINARY)

        result = await self._r2_cmd(f"c {hex_data} @ {address}")
        _logger.debug("bytes_compared", address=hex(address))
        return result

    async def compare_disassembly(self, file_path: str, address: int) -> str:
        """Compare disassembly at an address with another file.

        Issues rizin's ``cD`` (compare disassembly) command for a human
        readable listing, then requests the structured ``cCj`` output so
        callers can consume either the textual diff or the JSON tail.

        Args:
            file_path: Path to file to compare against.
            address: Address to compare at.

        Returns:
            str: Textual ``cD`` diff followed by a ``cCj`` JSON block.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("compare_disassembly_without_binary", file_path=str(file_path), address=hex(address))
            raise ToolError(_ERR_NO_BINARY)

        disasm_diff = await self._r2_cmd(f"cD {file_path} @ {address}")
        json_diff = await self._r2_cmd(f"cCj {file_path} @ {address}")
        _logger.debug("disassembly_compared", file_path=file_path, address=hex(address))

        sections: list[str] = []
        if disasm_diff.strip():
            sections.append(disasm_diff.rstrip())
        if json_diff.strip():
            sections.append(json_diff.rstrip())
        return "\n".join(sections)

    async def get_segments(self) -> list[SegmentInfo]:
        """Get binary segment information.

        Returns:
            list[SegmentInfo]: List of segment information.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_segments_without_binary")
            raise ToolError(_ERR_NO_BINARY)

        segments = await self._cmd_json("iSSj")
        result: list[SegmentInfo] = [
            SegmentInfo(
                name=_get_str(s, "name"),
                address=_get_int(s, "vaddr"),
                size=_get_int(s, "vsize", _get_int(s, "size")),
                permissions=_get_str(s, "perm"),
                type=_get_str(s, "type"),
            )
            for s in segments
        ]
        _logger.debug("segments_queried", result_count=len(result))
        return result

    async def hexdump(self, address: int, length: int = 256) -> str:
        """Get hex dump of bytes at an address.

        Args:
            address: Start address.
            length: Number of bytes to dump.

        Returns:
            str: Formatted hex dump text.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("hexdump_without_binary", address=hex(address), length=length)
            raise ToolError(_ERR_NO_BINARY)

        result = await self._r2_cmd(f"px {length} @ {address}")
        _logger.debug("hexdump_queried", address=hex(address), length=length)
        return result

    async def hexdump_words(self, address: int, length: int = 256) -> str:
        """Get word-sized hex dump at an address.

        Args:
            address: Start address.
            length: Number of bytes to dump.

        Returns:
            str: Formatted word hex dump text.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("hexdump_words_without_binary", address=hex(address), length=length)
            raise ToolError(_ERR_NO_BINARY)

        result = await self._r2_cmd(f"pxw {length} @ {address}")
        _logger.debug("hexdump_words_queried", address=hex(address), length=length)
        return result

    async def disassemble_function(self, address: int) -> str:
        """Disassemble a complete function.

        Args:
            address: Function address.

        Returns:
            str: Full function disassembly text.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("disassemble_function_without_binary", address=hex(address))
            raise ToolError(_ERR_NO_BINARY)

        result = await self._r2_cmd(f"pdf @ {address}")
        _logger.debug("function_disassembled", address=hex(address))
        return result

    async def get_basic_blocks(self, address: int) -> list[BlockInfo]:
        """Get basic blocks for a function.

        Args:
            address: Function address.

        Returns:
            list[BlockInfo]: List of basic block information.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._r2 is None:
            _logger.warning("get_basic_blocks_without_binary", address=hex(address))
            raise ToolError(_ERR_NO_BINARY)

        blocks = await self._cmd_json(f"afbj @ {address}")
        result: list[BlockInfo] = [
            BlockInfo(
                address=_get_int(b, "addr"),
                size=_get_int(b, "size"),
                jump=_get_optional_int(b, "jump"),
                fail=_get_optional_int(b, "fail"),
                instructions=_get_list(b, "ops"),
            )
            for b in blocks
        ]
        _logger.debug("basic_blocks_queried", address=hex(address), result_count=len(result))
        return result
