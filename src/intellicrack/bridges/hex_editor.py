# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Hex editor bridge wrapping the Rust-powered intellicrack_hexcore.

Provides hex editing, search, hash, template, and diff operations via the native Rust HexDocument backed by a piece table with memory-mapped
I/O for large file support.
"""

from __future__ import annotations

import asyncio
import base64
import inspect as _inspect_mod
import json
import os
import struct
import tempfile
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from intellicrack.bridges.base import BridgeCapabilities, ToolBridgeBase
from intellicrack.core.logging import get_logger
from intellicrack.core.types import ToolDefinition, ToolFunction, ToolName, ToolParameter


if TYPE_CHECKING:
    from intellicrack.bridges.hex_state import HexDocumentState
    from intellicrack.core.disassembler import HexDisassembler
    from intellicrack.core.hexpat import HexPatInterpreter, PatternRegistry
    from intellicrack.core.hexpat_compiler import HexPatCompiler, HexPatError
    from intellicrack.core.tools import ToolRegistry
    from intellicrack.core.transform_pipeline import TransformPipeline
    from intellicrack.core.yara_scanner import YaraScanner


_logger = get_logger("bridges.hex_editor")

_hexcore_mod: Any = None
_hexcore_available: bool = False

try:
    import intellicrack_hexcore

    _hexcore_mod = intellicrack_hexcore
    _hexcore_available = True
except ImportError:
    _logger.debug("hexcore_import_unavailable")

_HexPatCompiler: type[HexPatCompiler] | None = None
_HexPatError: type[HexPatError] | None = None
_hexpat_available: bool = False
try:
    from intellicrack.core.hexpat_compiler import (
        HexPatCompiler as _HexPatCompiler,
        HexPatError as _HexPatError,
    )

    _hexpat_available = True
except (ImportError, OSError) as _exc:
    _logger.debug("hexpat_compiler_unavailable", error=str(_exc))

_HexPatInterpreter: Any = None
_PatternRegistry: Any = None
_DataReader: Any = None
_hexpat_interpreter_available: bool = False
try:
    from intellicrack.core.hexpat import (
        HexPatInterpreter as _HexPatInterpreter,
        PatternRegistry as _PatternRegistry,
    )
    from intellicrack.core.hexpat.data_reader import DataReader as _DataReader

    _hexpat_interpreter_available = True
except (ImportError, OSError) as _exc:
    _logger.debug("hexpat_interpreter_unavailable", error=str(_exc))

_HexDisassembler: type[HexDisassembler] | None = None
_disasm_available: bool = False
try:
    from intellicrack.core.disassembler import HexDisassembler as _HexDisassembler

    _disasm_available = True
except (ImportError, OSError) as _exc:
    _logger.debug("hex_disassembler_unavailable", error=str(_exc))

_YaraScanner: type[YaraScanner] | None = None
_yara_bridge_available: bool = False
try:
    from intellicrack.core.yara_scanner import YaraScanner as _YaraScanner

    _yara_bridge_available = True
except (ImportError, OSError) as _exc:
    _logger.debug("yara_scanner_unavailable", error=str(_exc))

_get_all_transform_nodes: Any = None
_TransformPipeline: type[TransformPipeline] | None = None
_pipeline_available: bool = False
try:
    from intellicrack.core.transform_pipeline import (
        TransformPipeline as _TransformPipeline,
        get_all_transform_nodes as _get_all_transform_nodes,
    )

    _pipeline_available = True
except (ImportError, OSError) as _exc:
    _logger.debug("transform_pipeline_unavailable", error=str(_exc))


_JAVA_SIGNED_BYTE_THRESHOLD = 0x7F
_PRINTABLE_MIN = 0x20
_PRINTABLE_MAX = 0x7E
_DEFAULT_POINTER_SIZE = 4


class HexEditorBridge(ToolBridgeBase):
    """Bridge for the built-in hex editor powered by Rust.

    Wraps the ``intellicrack_hexcore.HexDocument`` class to provide
    hex editing, searching, hashing, data inspection, template
    parsing, and binary diffing through the standard bridge interface.
    """

    def __init__(self) -> None:
        super().__init__()
        self.document: Any | None = None
        self._cursor_offset: int = 0
        self._selection: tuple[int, int] | None = None
        self._hexcore_available: bool = _hexcore_available
        self._hexpat_available: bool = _hexpat_available
        self._hexpat_interpreter_available: bool = _hexpat_interpreter_available
        self._pipeline_available: bool = _pipeline_available
        self._interpreter: Any | None = None
        self._pattern_registry: Any | None = None
        self.state_holder: HexDocumentState | None = None
        self.tool_registry: ToolRegistry | None = None
        self._highlight_rules: dict[str, dict[str, Any]] = {}
        self._display_mode: str = "hex8"
        self._transform_node_cache: dict[str, Any] | None = None
        self._capabilities = BridgeCapabilities(
            supports_static_analysis=True,
            supports_patching=True,
            supported_architectures=["x86", "x86_64", "arm", "arm64"],
            supported_formats=["pe", "elf", "macho", "raw"],
        )

    def set_state_holder(self, state_holder: HexDocumentState) -> None:
        """Attach a shared state holder for bridge-GUI synchronization.

        Args:
            state_holder: The shared HexDocumentState instance.
        """
        self.state_holder = state_holder

    def set_tool_registry(self, registry: ToolRegistry) -> None:
        """Set the tool registry for cross-bridge access.

        Args:
            registry: The ToolRegistry providing access to other bridges.
        """
        self.tool_registry = registry

    @property
    def name(self) -> ToolName:
        """Get the tool name.

        Returns:
            ToolName: ToolName.HEX_EDITOR enum value.
        """
        return ToolName.HEX_EDITOR

    @property
    def tool_definition(self) -> ToolDefinition:
        """Get tool definition for LLM function calling.

        Returns:
            ToolDefinition: ToolDefinition with all hex editor functions.
        """
        return ToolDefinition(
            tool_name=ToolName.HEX_EDITOR,
            description="Built-in hex editor with Rust-powered piece table, search, hash, templates, and diff.",
            functions=[
                ToolFunction(
                    name="hex_editor.open_file",
                    description="Open a binary file in the hex editor.",
                    parameters=[ToolParameter(name="path", type="string", description="File path to open.")],
                    returns="dict with file_path, size, and file_type",
                ),
                ToolFunction(
                    name="hex_editor.close_file",
                    description="Close the currently open file.",
                    parameters=[],
                    returns="True if closed successfully",
                ),
                ToolFunction(
                    name="hex_editor.read_bytes",
                    description="Read bytes from the document.",
                    parameters=[
                        ToolParameter(name="offset", type="integer", description="Byte offset to read from."),
                        ToolParameter(name="length", type="integer", description="Number of bytes to read."),
                    ],
                    returns="Hex string of read bytes",
                ),
                ToolFunction(
                    name="hex_editor.write_bytes",
                    description="Overwrite bytes at offset.",
                    parameters=[
                        ToolParameter(name="offset", type="integer", description="Byte offset to write at."),
                        ToolParameter(name="data_hex", type="string", description="Hex string of bytes to write."),
                    ],
                    returns="True if write succeeded",
                ),
                ToolFunction(
                    name="hex_editor.insert_bytes",
                    description="Insert bytes at offset, shifting subsequent data.",
                    parameters=[
                        ToolParameter(name="offset", type="integer", description="Byte offset for insertion."),
                        ToolParameter(name="data_hex", type="string", description="Hex string of bytes to insert."),
                    ],
                    returns="True if insert succeeded",
                ),
                ToolFunction(
                    name="hex_editor.delete_bytes",
                    description="Delete bytes at offset.",
                    parameters=[
                        ToolParameter(name="offset", type="integer", description="Start offset."),
                        ToolParameter(name="length", type="integer", description="Number of bytes to delete."),
                    ],
                    returns="True if delete succeeded",
                ),
                ToolFunction(
                    name="hex_editor.search_hex",
                    description="Search for a hex pattern with optional wildcards (??).",
                    parameters=[
                        ToolParameter(name="pattern", type="string", description="Hex pattern (e.g. '4D 5A ?? 00')."),
                        ToolParameter(name="max_results", type="integer", description="Maximum results.", required=False, default=100),
                    ],
                    returns="List of {offset, length} dicts",
                ),
                ToolFunction(
                    name="hex_editor.search_text",
                    description="Search for text with encoding support.",
                    parameters=[
                        ToolParameter(name="text", type="string", description="Text to search for."),
                        ToolParameter(
                            name="encoding",
                            type="string",
                            description="Encoding (utf-8, utf-16le, ascii).",
                            required=False,
                            default="utf-8",
                        ),
                        ToolParameter(
                            name="case_sensitive",
                            type="boolean",
                            description="Case-sensitive match.",
                            required=False,
                            default=True,
                        ),
                        ToolParameter(name="max_results", type="integer", description="Maximum results.", required=False, default=100),
                    ],
                    returns="List of {offset, length} dicts",
                ),
                ToolFunction(
                    name="hex_editor.search_regex",
                    description="Search using a regular expression.",
                    parameters=[
                        ToolParameter(name="pattern", type="string", description="Regex pattern."),
                        ToolParameter(name="max_results", type="integer", description="Maximum results.", required=False, default=100),
                    ],
                    returns="List of {offset, length} dicts",
                ),
                ToolFunction(
                    name="hex_editor.undo",
                    description="Undo the last edit operation.",
                    parameters=[],
                    returns="True if undo was performed",
                ),
                ToolFunction(
                    name="hex_editor.redo",
                    description="Redo the last undone operation.",
                    parameters=[],
                    returns="True if redo was performed",
                ),
                ToolFunction(
                    name="hex_editor.inspect_data_at",
                    description="Inspect data at offset as multiple type interpretations.",
                    parameters=[ToolParameter(name="offset", type="integer", description="Byte offset to inspect.")],
                    returns="Dict of type interpretations (int8, uint16_le, float32_le, etc.)",
                ),
                ToolFunction(
                    name="hex_editor.calculate_hash",
                    description="Calculate hash of the entire document.",
                    parameters=[
                        ToolParameter(name="algorithm", type="string", description="Hash algorithm.", required=False, default="sha256"),
                    ],
                    returns="Hex digest string",
                ),
                ToolFunction(
                    name="hex_editor.apply_template",
                    description="Apply a struct template at offset.",
                    parameters=[
                        ToolParameter(name="template_name", type="string", description="Template name (e.g. IMAGE_DOS_HEADER)."),
                        ToolParameter(name="offset", type="integer", description="Byte offset.", required=False, default=0),
                    ],
                    returns="List of parsed field dicts",
                ),
                ToolFunction(
                    name="hex_editor.list_templates",
                    description="List available struct templates.",
                    parameters=[],
                    returns="List of {name, description} dicts",
                ),
                ToolFunction(
                    name="hex_editor.register_template",
                    description="Register a JSON template definition at runtime.",
                    parameters=[
                        ToolParameter(
                            name="json_str",
                            type="string",
                            description="JSON template definition string.",
                        ),
                    ],
                    returns="Registered template name",
                ),
                ToolFunction(
                    name="hex_editor.remove_template",
                    description="Remove a registered template by name.",
                    parameters=[
                        ToolParameter(
                            name="template_name",
                            type="string",
                            description="Name of the template to remove.",
                        ),
                    ],
                    returns="True if removed",
                ),
                ToolFunction(
                    name="hex_editor.compile_pattern",
                    description="Compile HexPat DSL source code into a JSON template definition.",
                    parameters=[
                        ToolParameter(
                            name="source",
                            type="string",
                            description="HexPat DSL source code.",
                        ),
                    ],
                    returns="Compiled JSON template string",
                ),
                ToolFunction(
                    name="hex_editor.execute_pattern",
                    description="Execute .hexpat pattern source against the open document.",
                    parameters=[
                        ToolParameter(name="source", type="string", description="HexPat source code."),
                        ToolParameter(name="offset", type="integer", description="Base offset.", required=False, default=0),
                    ],
                    returns="List of parsed field dicts with name, offset, size, display_value, children",
                ),
                ToolFunction(
                    name="hex_editor.execute_pattern_file",
                    description="Execute a .hexpat pattern file against the open document.",
                    parameters=[
                        ToolParameter(name="pattern_path", type="string", description="Path to the .hexpat file."),
                        ToolParameter(name="offset", type="integer", description="Base offset.", required=False, default=0),
                    ],
                    returns="List of parsed field dicts",
                ),
                ToolFunction(
                    name="hex_editor.list_hexpat_patterns",
                    description="List available .hexpat community patterns.",
                    parameters=[],
                    returns="List of {name, description, category} dicts",
                ),
                ToolFunction(
                    name="hex_editor.auto_detect_pattern",
                    description="Auto-detect .hexpat patterns matching the open file by magic bytes.",
                    parameters=[],
                    returns="List of {name, description, category} dicts sorted by specificity",
                ),
                ToolFunction(
                    name="hex_editor.export_template",
                    description="Export a registered template as JSON.",
                    parameters=[
                        ToolParameter(
                            name="template_name",
                            type="string",
                            description="Name of the template to export.",
                        ),
                    ],
                    returns="JSON template string",
                ),
                ToolFunction(
                    name="hex_editor.list_templates_detailed",
                    description="List all templates with detailed metadata.",
                    parameters=[],
                    returns="List of {name, description, category, field_count} dicts",
                ),
                ToolFunction(
                    name="hex_editor.compare_files",
                    description="Compare two files byte-by-byte.",
                    parameters=[
                        ToolParameter(name="path_a", type="string", description="First file path."),
                        ToolParameter(name="path_b", type="string", description="Second file path."),
                    ],
                    returns="Diff result with regions and statistics",
                ),
                ToolFunction(
                    name="hex_editor.add_bookmark",
                    description="Add a bookmark at an offset.",
                    parameters=[
                        ToolParameter(name="offset", type="integer", description="Byte offset."),
                        ToolParameter(name="length", type="integer", description="Length in bytes.", required=False, default=1),
                        ToolParameter(name="label", type="string", description="Bookmark label.", required=False, default="Bookmark"),
                        ToolParameter(name="color", type="string", description="Color hex string.", required=False, default="#FFFF00"),
                    ],
                    returns="Bookmark index",
                ),
                ToolFunction(
                    name="hex_editor.remove_bookmark",
                    description="Remove a bookmark by index.",
                    parameters=[ToolParameter(name="index", type="integer", description="Bookmark index.")],
                    returns="True if removed",
                ),
                ToolFunction(
                    name="hex_editor.list_bookmarks",
                    description="List all bookmarks.",
                    parameters=[],
                    returns="List of {offset, length, label, color} dicts",
                ),
                ToolFunction(
                    name="hex_editor.get_byte_statistics",
                    description="Get byte frequency statistics.",
                    parameters=[],
                    returns="List of {byte, count} dicts",
                ),
                ToolFunction(
                    name="hex_editor.copy_as",
                    description="Format bytes at cursor/selection in a specific format.",
                    parameters=[
                        ToolParameter(
                            name="fmt",
                            type="string",
                            description="Output format.",
                            enum=[
                                "hex",
                                "c_array",
                                "python",
                                "base64",
                                "rust_array",
                                "csharp_array",
                                "java_array",
                                "javascript_array",
                                "go_slice",
                                "hex_string_no_spaces",
                                "nasm_db",
                                "markdown_table",
                            ],
                        ),
                    ],
                    returns="Formatted string",
                ),
                ToolFunction(
                    name="hex_editor.save",
                    description="Save the document.",
                    parameters=[
                        ToolParameter(name="path", type="string", description="Save path (uses original if omitted).", required=False),
                    ],
                    returns="True if saved",
                ),
                ToolFunction(
                    name="hex_editor.get_cursor_position",
                    description="Get the current logical cursor position in the document.",
                    parameters=[],
                    returns="Current byte offset of the cursor as an integer",
                ),
                ToolFunction(
                    name="hex_editor.select_range",
                    description="Set the selection range to a span of bytes.",
                    parameters=[
                        ToolParameter(name="start", type="integer", description="Selection start offset."),
                        ToolParameter(name="end", type="integer", description="Selection end offset (inclusive)."),
                    ],
                    returns="True always",
                ),
                ToolFunction(
                    name="hex_editor.get_selection",
                    description="Get the current selection range.",
                    parameters=[],
                    returns="Tuple of (start, end) offsets, or null if no selection is active",
                ),
                ToolFunction(
                    name="hex_editor.save_as",
                    description="Save the document to a new file path.",
                    parameters=[
                        ToolParameter(name="path", type="string", description="New file path to save to."),
                    ],
                    returns="True if saved successfully",
                ),
                ToolFunction(
                    name="hex_editor.goto_offset",
                    description="Navigate the cursor to a specific byte offset.",
                    parameters=[
                        ToolParameter(name="offset", type="integer", description="Target byte offset."),
                    ],
                    returns="True always",
                ),
                ToolFunction(
                    name="hex_editor.replace_bytes",
                    description="Find and replace all occurrences of a byte pattern.",
                    parameters=[
                        ToolParameter(name="pattern_hex", type="string", description="Hex string pattern to find."),
                        ToolParameter(name="replacement_hex", type="string", description="Hex string replacement."),
                    ],
                    returns="Number of replacements made",
                ),
                ToolFunction(
                    name="hex_editor.calculate_hash_range",
                    description="Calculate hash of a byte range within the document.",
                    parameters=[
                        ToolParameter(name="start", type="integer", description="Start byte offset."),
                        ToolParameter(name="end", type="integer", description="End byte offset (exclusive)."),
                        ToolParameter(name="algorithm", type="string", description="Hash algorithm.", required=False, default="sha256"),
                    ],
                    returns="Hex digest string",
                ),
                ToolFunction(
                    name="hex_editor.get_document_info",
                    description="Get information about the currently open document.",
                    parameters=[],
                    returns="Dict with file_path, size, modified, cursor, selection",
                ),
                ToolFunction(
                    name="hex_editor.get_context_for_ai",
                    description="Get hex editor context for AI analysis.",
                    parameters=[
                        ToolParameter(
                            name="include_bytes",
                            type="integer",
                            description="Number of bytes around cursor to include.",
                            required=False,
                            default=256,
                        ),
                    ],
                    returns="Dict with document info, bytes at cursor, inspections, bookmarks",
                ),
                ToolFunction(
                    name="hex_editor.save_to_sandbox",
                    description="Save the current document to a sandbox environment.",
                    parameters=[
                        ToolParameter(name="dest_path", type="string", description="Destination path inside the sandbox."),
                        ToolParameter(
                            name="sandbox_type",
                            type="string",
                            description="Sandbox type (docker, qemu, windows_sandbox).",
                            required=False,
                            default="docker",
                        ),
                    ],
                    returns="Dict with sandbox_path and status",
                ),
                ToolFunction(
                    name="hex_editor.test_in_sandbox",
                    description="Save the document to a sandbox, execute it, and return the execution report.",
                    parameters=[
                        ToolParameter(
                            name="args",
                            type="string",
                            description="Command-line arguments for the binary.",
                            required=False,
                            default="",
                        ),
                        ToolParameter(
                            name="sandbox_type",
                            type="string",
                            description="Sandbox type.",
                            required=False,
                            default="docker",
                        ),
                        ToolParameter(
                            name="timeout",
                            type="integer",
                            description="Execution timeout in seconds.",
                            required=False,
                            default=30,
                        ),
                    ],
                    returns="Dict with execution report including exit code, stdout, stderr",
                ),
                ToolFunction(
                    name="hex_editor.get_entropy",
                    description="Get Shannon entropy of the entire document (0.0-8.0).",
                    parameters=[],
                    returns="Float entropy value",
                ),
                ToolFunction(
                    name="hex_editor.get_entropy_map",
                    description="Get per-block entropy values across the document.",
                    parameters=[
                        ToolParameter(name="block_size", type="integer", description="Block size in bytes.", required=False, default=4096),
                    ],
                    returns="List of float entropy values per block",
                ),
                ToolFunction(
                    name="hex_editor.get_byte_distribution",
                    description="Get 256-element byte frequency distribution.",
                    parameters=[],
                    returns="List of 256 integer counts",
                ),
                ToolFunction(
                    name="hex_editor.get_byte_type_distribution",
                    description="Get byte type counts: null, printable, control, high.",
                    parameters=[],
                    returns="Dict with null_count, printable_count, control_count, high_count",
                ),
                ToolFunction(
                    name="hex_editor.get_digram_matrix",
                    description="Get 256x256 byte-pair frequency matrix.",
                    parameters=[],
                    returns="List of 65536 integer frequencies (row-major)",
                ),
                ToolFunction(
                    name="hex_editor.get_content_classification",
                    description="Classify document blocks by content type.",
                    parameters=[
                        ToolParameter(name="block_size", type="integer", description="Block size in bytes.", required=False, default=4096),
                    ],
                    returns="List of ints: 0=null, 1=plaintext, 2=structured, 3=encrypted, 4=code",
                ),
                ToolFunction(
                    name="hex_editor.disassemble",
                    description="Disassemble instructions at offset.",
                    parameters=[
                        ToolParameter(name="offset", type="integer", description="Byte offset to disassemble from."),
                        ToolParameter(name="count", type="integer", description="Number of instructions.", required=False, default=50),
                        ToolParameter(
                            name="arch",
                            type="string",
                            description="Architecture (x86, arm, arm64, mips, etc.).",
                            required=False,
                            default="auto",
                        ),
                        ToolParameter(
                            name="mode",
                            type="string",
                            description="Mode (16, 32, 64, arm, thumb).",
                            required=False,
                            default="64",
                        ),
                    ],
                    returns="List of {address, bytes, mnemonic, operands, size} dicts",
                ),
                ToolFunction(
                    name="hex_editor.yara_scan",
                    description="Scan document with YARA rule source.",
                    parameters=[
                        ToolParameter(name="rule_source", type="string", description="YARA rule source code."),
                    ],
                    returns="List of {rule, tags, meta, strings} match dicts",
                ),
                ToolFunction(
                    name="hex_editor.yara_scan_files",
                    description="Scan document with YARA rule files.",
                    parameters=[
                        ToolParameter(name="rule_paths", type="string", description="Comma-separated paths to .yar files."),
                    ],
                    returns="List of match dicts",
                ),
                ToolFunction(
                    name="hex_editor.apply_transform",
                    description="Apply a data transform to a byte range.",
                    parameters=[
                        ToolParameter(name="name", type="string", description="Transform name (e.g. xor_single, base64_encode)."),
                        ToolParameter(name="offset", type="integer", description="Start offset."),
                        ToolParameter(name="length", type="integer", description="Number of bytes."),
                        ToolParameter(
                            name="params_json",
                            type="string",
                            description="JSON dict of params. Byte values as hex strings.",
                            required=False,
                            default="{}",
                        ),
                    ],
                    returns="Hex string of transformed bytes",
                ),
                ToolFunction(
                    name="hex_editor.apply_pipeline",
                    description="Apply a transform pipeline to a byte range.",
                    parameters=[
                        ToolParameter(name="pipeline_json", type="string", description="JSON array of {name, params} steps."),
                        ToolParameter(name="offset", type="integer", description="Start offset."),
                        ToolParameter(name="length", type="integer", description="Number of bytes."),
                    ],
                    returns="Hex string of transformed bytes",
                ),
                ToolFunction(
                    name="hex_editor.list_transforms",
                    description="List all available data transforms.",
                    parameters=[],
                    returns="List of {name, category, description} dicts",
                ),
                ToolFunction(
                    name="hex_editor.decode_text",
                    description="Decode bytes at offset as text in specified encoding.",
                    parameters=[
                        ToolParameter(name="offset", type="integer", description="Start offset."),
                        ToolParameter(name="length", type="integer", description="Byte length to decode."),
                        ToolParameter(name="encoding", type="string", description="Encoding name.", required=False, default="utf-8"),
                    ],
                    returns="Decoded text string",
                ),
                ToolFunction(
                    name="hex_editor.list_encodings",
                    description="List all supported text encodings.",
                    parameters=[],
                    returns="List of {name, label} dicts",
                ),
                ToolFunction(
                    name="hex_editor.encode_text",
                    description="Encode text into bytes using the specified encoding.",
                    parameters=[
                        ToolParameter(name="text", type="string", description="Text to encode."),
                        ToolParameter(
                            name="encoding",
                            type="string",
                            description="Encoding (e.g. utf-8, utf-16le, shift-jis).",
                            required=False,
                            default="utf-8",
                        ),
                    ],
                    returns="Hex string of encoded bytes",
                ),
                ToolFunction(
                    name="hex_editor.search_bytes",
                    description="Search for a raw byte pattern in the document.",
                    parameters=[
                        ToolParameter(name="pattern_hex", type="string", description="Hex string of bytes to find (e.g. '4D5A9000')."),
                        ToolParameter(name="max_results", type="integer", description="Maximum results.", required=False, default=100),
                    ],
                    returns="List of {offset, length} dicts",
                ),
                ToolFunction(
                    name="hex_editor.search_numeric_range",
                    description="Search for numeric values within a min/max range.",
                    parameters=[
                        ToolParameter(name="min_val", type="integer", description="Minimum value (inclusive)."),
                        ToolParameter(name="max_val", type="integer", description="Maximum value (inclusive)."),
                        ToolParameter(name="size", type="integer", description="Byte size: 1, 2, 4, or 8.", required=False, default=4),
                        ToolParameter(name="value_type", type="string", description="Type: uint, int.", required=False, default="uint"),
                        ToolParameter(
                            name="endianness",
                            type="string",
                            description="Byte order: little, big.",
                            required=False,
                            default="little",
                        ),
                        ToolParameter(name="alignment", type="integer", description="Search alignment.", required=False, default=1),
                        ToolParameter(name="max_results", type="integer", description="Max results.", required=False, default=100),
                    ],
                    returns="List of {offset, length} dicts",
                ),
                ToolFunction(
                    name="hex_editor.list_process_regions",
                    description="List memory regions of a process by PID (Windows only).",
                    parameters=[ToolParameter(name="pid", type="integer", description="Process ID.")],
                    returns="List of {base_address, size, protection, state} dicts",
                ),
                ToolFunction(
                    name="hex_editor.open_process_memory",
                    description="Open a process memory region as a hex document (Windows only).",
                    parameters=[
                        ToolParameter(name="pid", type="integer", description="Process ID."),
                        ToolParameter(name="address", type="integer", description="Base address."),
                        ToolParameter(name="size", type="integer", description="Bytes to read."),
                    ],
                    returns="Dict with pid, address, size, document_length",
                ),
                ToolFunction(
                    name="hex_editor.calculate_hash_custom_crc",
                    description="Calculate CRC with custom parameters.",
                    parameters=[
                        ToolParameter(name="start", type="integer", description="Start offset."),
                        ToolParameter(name="end", type="integer", description="End offset."),
                        ToolParameter(name="poly", type="integer", description="CRC polynomial."),
                        ToolParameter(name="init", type="integer", description="Initial value."),
                        ToolParameter(name="width", type="integer", description="CRC width: 8, 16, 32, or 64."),
                        ToolParameter(name="refin", type="boolean", description="Reflect input.", required=False, default=False),
                        ToolParameter(name="refout", type="boolean", description="Reflect output.", required=False, default=False),
                        ToolParameter(name="xorout", type="integer", description="Final XOR value.", required=False, default=0),
                    ],
                    returns="CRC hex digest string",
                ),
                ToolFunction(
                    name="hex_editor.export_patches",
                    description="Export document patches as IPS or IPS32.",
                    parameters=[
                        ToolParameter(name="patch_format", type="string", description="Patch format.", enum=["ips", "ips32"]),
                    ],
                    returns="Base64-encoded patch data",
                ),
                ToolFunction(
                    name="hex_editor.import_patches",
                    description="Import and apply IPS/IPS32 patches.",
                    parameters=[
                        ToolParameter(name="data_b64", type="string", description="Base64-encoded IPS/IPS32 data."),
                    ],
                    returns="Number of patches applied",
                ),
                ToolFunction(
                    name="hex_editor.search_numeric",
                    description="Search for a numeric value in the document.",
                    parameters=[
                        ToolParameter(name="value", type="integer", description="Value to search for."),
                        ToolParameter(name="size", type="integer", description="Byte size: 1, 2, 4, or 8."),
                        ToolParameter(
                            name="value_type",
                            type="string",
                            description="Value type.",
                            enum=["uint", "int", "float"],
                            required=False,
                            default="uint",
                        ),
                        ToolParameter(
                            name="endianness",
                            type="string",
                            description="Byte order.",
                            enum=["little", "big"],
                            required=False,
                            default="little",
                        ),
                        ToolParameter(name="alignment", type="integer", description="Search alignment.", required=False, default=1),
                        ToolParameter(name="max_results", type="integer", description="Max results.", required=False, default=100),
                    ],
                    returns="List of {offset, length} dicts",
                ),
                ToolFunction(
                    name="hex_editor.add_highlight_rule",
                    description="Add a byte highlighting rule.",
                    parameters=[
                        ToolParameter(
                            name="condition_type",
                            type="string",
                            description="Condition type.",
                            enum=["byte_value", "byte_range", "pattern"],
                        ),
                        ToolParameter(name="condition_params", type="string", description="JSON condition parameters."),
                        ToolParameter(name="color", type="string", description="Highlight color hex.", required=False, default="#FFFF00"),
                    ],
                    returns="Rule ID string",
                ),
                ToolFunction(
                    name="hex_editor.remove_highlight_rule",
                    description="Remove a highlighting rule.",
                    parameters=[
                        ToolParameter(name="rule_id", type="string", description="Rule ID to remove."),
                    ],
                    returns="True if removed",
                ),
                ToolFunction(
                    name="hex_editor.list_highlight_rules",
                    description="List all active highlighting rules.",
                    parameters=[],
                    returns="List of rule dicts",
                ),
                ToolFunction(
                    name="hex_editor.set_display_mode",
                    description="Set the hex display mode.",
                    parameters=[
                        ToolParameter(
                            name="mode",
                            type="string",
                            description="Display mode.",
                            enum=[
                                "hex8",
                                "hex16_le",
                                "hex16_be",
                                "hex32_le",
                                "hex32_be",
                                "hex64_le",
                                "hex64_be",
                                "dec_u8",
                                "dec_u16",
                                "dec_u32",
                                "dec_s8",
                                "dec_s16",
                                "dec_s32",
                                "float32",
                                "float64",
                                "rgba8",
                                "hexii",
                                "binary",
                            ],
                        ),
                    ],
                    returns="True",
                ),
                ToolFunction(
                    name="hex_editor.get_display_mode",
                    description="Get the current display mode.",
                    parameters=[],
                    returns="Display mode string",
                ),
            ],
        )

    async def initialize(self, tool_path: Path | None = None) -> None:
        """Initialize the hex editor bridge.

        Args:
            tool_path: Unused for this bridge.
        """
        _ = tool_path
        if self._hexcore_available:
            if _hexcore_mod is None or not hasattr(_hexcore_mod, "HexDocument"):
                self._state.connected = False
                self._state.tool_running = False
                _logger.warning("hex_editor_probe_failed", backend="intellicrack_hexcore")
                return
            self._state.connected = True
            self._state.tool_running = True
            if self.state_holder is not None:
                self._highlight_rules = self.state_holder.get_highlight_rules()
                self._display_mode = self.state_holder.get_display_mode()
            _logger.info("hex_editor_initialized", backend="rust_hexcore")
        else:
            self._state.connected = False
            self._state.tool_running = False
            _logger.warning("hex_editor_backend_unavailable", backend="intellicrack_hexcore")

    async def is_available(self) -> bool:
        """Check if the Rust hex core is available.

        Returns:
            bool: True if intellicrack_hexcore is importable.
        """
        return self._hexcore_available

    async def shutdown(self) -> None:
        """Shutdown the hex editor bridge."""
        if self.document is not None:
            self.document = None
        self._cursor_offset = 0
        self._selection = None
        _logger.debug("hex_editor_shutdown")
        await super().shutdown()

    async def open_file(self, path: str) -> dict[str, Any]:
        """Open a binary file in the hex editor.

        Args:
            path: Filesystem path to the file.

        Returns:
            dict[str, Any]: Dict with file_path, size, and modified status.

        Raises:
            RuntimeError: If the Rust core is not available.
        """
        if not self._hexcore_available or _hexcore_mod is None:
            msg = "intellicrack_hexcore not installed"
            raise RuntimeError(msg)

        self.document = _hexcore_mod.HexDocument.open(path)
        if self.document is None:
            msg = f"failed to open {path}"
            raise RuntimeError(msg)
        self._cursor_offset = 0
        self._selection = None
        self._state.binary_loaded = True
        self._state.target_path = Path(path)

        doc_len: int = self.document.length()
        _logger.info("file_opened", path=path, size=doc_len)

        if self.state_holder is not None:
            self.state_holder.set_document(self.document, Path(path), source="bridge")

        return {
            "file_path": path,
            "size": doc_len,
            "modified": False,
        }

    async def close_file(self) -> bool:
        """Close the currently open file.

        Returns:
            bool: True if a file was closed.
        """
        if self.document is None:
            return False

        self.document = None
        self._cursor_offset = 0
        self._selection = None
        self._state.binary_loaded = False
        self._state.target_path = None
        if self.state_holder is not None:
            self.state_holder.set_document(None, None, source="bridge")
        _logger.info("file_closed")
        return True

    async def read_bytes(self, offset: int, length: int) -> str:
        """Read bytes from the document as a hex string.

        Args:
            offset: Byte offset to read from.
            length: Number of bytes to read.

        Returns:
            str: Hex string of the read bytes.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        _logger.debug("bytes_read", offset=hex(offset), length=length)
        raw = self.document.read(offset, length)
        return " ".join(f"{b:02X}" for b in raw)

    async def write_bytes(self, offset: int, data_hex: str) -> bool:
        """Overwrite bytes at offset.

        Args:
            offset: Byte offset to write at.
            data_hex: Hex string of bytes (e.g. "4D 5A 90").

        Returns:
            bool: True if the write succeeded.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        data = bytes.fromhex(data_hex.replace(" ", ""))
        self.document.write_bytes(offset, data)
        _logger.debug("bytes_written", offset=hex(offset), length=len(data))
        if self.state_holder is not None:
            self.state_holder.notify_data_modified(offset, len(data), source="bridge")
        return True

    async def insert_bytes(self, offset: int, data_hex: str) -> bool:
        """Insert bytes at offset.

        Args:
            offset: Byte offset for insertion.
            data_hex: Hex string of bytes to insert.

        Returns:
            bool: True if the insert succeeded.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        data = bytes.fromhex(data_hex.replace(" ", ""))
        self.document.insert_bytes(offset, data)
        _logger.debug("bytes_inserted", offset=hex(offset), length=len(data))
        if self.state_holder is not None:
            self.state_holder.notify_data_modified(offset, len(data), source="bridge")
        return True

    async def delete_bytes(self, offset: int, length: int) -> bool:
        """Delete bytes at offset.

        Args:
            offset: Start offset.
            length: Number of bytes to delete.

        Returns:
            bool: True if the delete succeeded.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        self.document.delete_bytes(offset, length)
        _logger.debug("bytes_deleted", offset=hex(offset), length=length)
        if self.state_holder is not None:
            self.state_holder.notify_data_modified(offset, length, source="bridge")
        return True

    async def goto_offset(self, offset: int) -> bool:
        """Set the logical cursor position.

        Args:
            offset: Target byte offset.

        Returns:
            bool: True always.
        """
        self._cursor_offset = offset
        _logger.debug("cursor_moved", offset=hex(offset))
        if self.state_holder is not None:
            self.state_holder.set_cursor(offset, source="bridge")
        return True

    async def get_cursor_position(self) -> int:
        """Get the current cursor position.

        Returns:
            int: Current byte offset of the cursor.
        """
        return self._cursor_offset

    async def select_range(self, start: int, end: int) -> bool:
        """Set the selection range.

        Args:
            start: Selection start offset.
            end: Selection end offset.

        Returns:
            bool: True always.
        """
        self._selection = (start, end)
        _logger.debug("range_selected", start=hex(start), end=hex(end))
        if self.state_holder is not None:
            self.state_holder.set_selection(start, end, source="bridge")
        return True

    async def get_selection(self) -> tuple[int, int] | None:
        """Get the current selection range.

        Returns:
            tuple[int, int] | None: Tuple of (start, end) offsets, or None if no selection.
        """
        return self._selection

    async def search_hex(self, pattern: str, max_results: int = 100) -> list[dict[str, int]]:
        """Search for a hex pattern with optional wildcards.

        Args:
            pattern: Hex pattern string (e.g. "4D 5A ?? 00").
            max_results: Maximum number of results to return.

        Returns:
            list[dict[str, int]]: List of dicts with offset and length keys.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        results = self.document.search_hex(pattern, max_results)
        _logger.debug("search_hex_completed", pattern=pattern, matches=len(results))
        return [{"offset": r[0], "length": r[1]} for r in results]

    async def search_bytes(self, pattern_hex: str, max_results: int = 100) -> list[dict[str, int]]:
        """Search for a raw byte pattern in the document.

        Args:
            pattern_hex: Hex string of bytes to find (e.g. '4D5A9000').
            max_results: Maximum number of results to return.

        Returns:
            list[dict[str, int]]: List of dicts with offset and length keys.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        pattern = bytes.fromhex(pattern_hex.replace(" ", ""))
        results = self.document.search_bytes(pattern, max_results)
        _logger.debug("search_bytes_completed", pattern_len=len(pattern), matches=len(results))
        return [{"offset": r[0], "length": r[1]} for r in results]

    async def search_text(
        self,
        text: str,
        encoding: str = "utf-8",
        max_results: int = 100,
        *,
        case_sensitive: bool = True,
    ) -> list[dict[str, int]]:
        """Search for text with encoding support.

        Args:
            text: Text string to search for.
            encoding: Text encoding (utf-8, utf-16le, shift-jis, euc-kr, etc.).
            max_results: Maximum number of results.
            case_sensitive: Whether the search is case-sensitive.

        Returns:
            list[dict[str, int]]: List of dicts with offset and length keys.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        if hasattr(self.document, "search_text_encoded"):
            results = self.document.search_text_encoded(text, encoding, case_sensitive, max_results)
        else:
            results = self.document.search_text(text, encoding, case_sensitive, max_results)
        _logger.debug("search_text_completed", encoding=encoding, matches=len(results))
        return [{"offset": r[0], "length": r[1]} for r in results]

    async def search_regex(self, pattern: str, max_results: int = 100) -> list[dict[str, int]]:
        """Search using a regular expression.

        Args:
            pattern: Regex pattern string.
            max_results: Maximum number of results.

        Returns:
            list[dict[str, int]]: List of dicts with offset and length keys.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        results = self.document.search_regex(pattern, max_results)
        _logger.debug("search_regex_completed", pattern=pattern, matches=len(results))
        return [{"offset": r[0], "length": r[1]} for r in results]

    async def replace_bytes(self, pattern_hex: str, replacement_hex: str) -> int:
        """Find and replace all occurrences of a byte pattern.

        Args:
            pattern_hex: Hex string pattern to find (e.g. "4D 5A").
            replacement_hex: Hex string replacement (e.g. "90 90").

        Returns:
            int: Number of replacements made.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        pattern = list(bytes.fromhex(pattern_hex.replace(" ", "")))
        replacement = list(bytes.fromhex(replacement_hex.replace(" ", "")))
        count: int = self.document.replace_bytes(pattern, replacement)
        _logger.debug("bytes_replaced", pattern_length=len(pattern), replacements=count)
        if count > 0 and self.state_holder is not None:
            doc_len: int = self.document.length()
            self.state_holder.notify_data_modified(0, doc_len, source="bridge")
        return count

    async def undo(self) -> bool:
        """Undo the last edit operation.

        Returns:
            bool: True if an operation was undone.
        """
        if self.document is None:
            return False
        result: bool = self.document.undo()
        _logger.debug("undo_performed", success=result)
        if result and self.state_holder is not None:
            doc_len: int = self.document.length()
            self.state_holder.notify_data_modified(0, doc_len, source="bridge")
        return result

    async def redo(self) -> bool:
        """Redo the last undone operation.

        Returns:
            bool: True if an operation was redone.
        """
        if self.document is None:
            return False
        result: bool = self.document.redo()
        _logger.debug("redo_performed", success=result)
        if result and self.state_holder is not None:
            doc_len: int = self.document.length()
            self.state_holder.notify_data_modified(0, doc_len, source="bridge")
        return result

    async def inspect_data_at(self, offset: int) -> dict[str, str]:
        """Inspect data at offset as multiple type interpretations.

        Args:
            offset: Byte offset to inspect.

        Returns:
            dict[str, str]: Dict mapping type names to formatted value strings.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        _logger.debug("data_inspected", offset=hex(offset))
        result = self.document.inspect_at(offset)
        if not isinstance(result, dict):
            return {}
        typed = cast("dict[str, object]", result)
        return {k: str(v) for k, v in typed.items()}

    async def calculate_hash(self, algorithm: str = "sha256") -> str:
        """Calculate a hash of the entire document.

        Args:
            algorithm: Hash algorithm (md5, sha1, sha256, sha512, crc32).

        Returns:
            str: Hex digest string.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        digest: str = self.document.compute_hash(algorithm)
        _logger.debug("hash_calculated", algorithm=algorithm)
        return digest

    async def get_byte_statistics(self) -> list[dict[str, int]]:
        """Get byte frequency statistics for the document.

        Returns:
            list[dict[str, int]]: List of dicts with byte value and count.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        stats = self.document.byte_statistics()
        _logger.debug("byte_statistics_computed", unique_bytes=len(stats))
        return [{"byte": s[0], "count": s[1]} for s in stats]

    async def apply_template(self, template_name: str, offset: int = 0) -> list[dict[str, Any]]:
        """Apply a struct template at a byte offset.

        Args:
            template_name: Name of the template (e.g. IMAGE_DOS_HEADER).
            offset: Byte offset to apply at.

        Returns:
            list[dict[str, Any]]: List of parsed field dicts with name, offset, size, value.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        _logger.debug("template_applied", template=template_name, offset=hex(offset))
        result = self.document.apply_template(template_name, offset)
        if not isinstance(result, list):
            return []
        typed_list = cast("list[object]", result)
        return [cast("dict[str, Any]", entry) for entry in typed_list if isinstance(entry, dict)]

    async def list_templates(self) -> list[dict[str, str]]:
        """List all available struct templates.

        Returns:
            list[dict[str, str]]: List of dicts with name and description.
        """
        if self.document is None:
            if not self._hexcore_available or _hexcore_mod is None:
                return []
            try:
                doc = _hexcore_mod.HexDocument()
            except (RuntimeError, OSError, TypeError):
                _logger.warning("hexdocument_default_init_failed", exc_info=True)
                return []
            templates = doc.list_templates()
        else:
            templates = self.document.list_templates()

        _logger.debug("templates_listed", count=len(templates))
        return [{"name": t[0], "description": t[1]} for t in templates]

    async def register_template(self, json_str: str) -> str:
        """Register a JSON template definition at runtime.

        Args:
            json_str: JSON template definition string.

        Returns:
            str: Name of the registered template.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        name: str = self.document.register_json_template(json_str)
        _logger.info("template_registered", template_name=name)
        if self.state_holder is not None:
            self.state_holder.notify_template_registered(name, source="bridge")
        return name

    async def remove_template(self, template_name: str) -> bool:
        """Remove a registered template by name.

        Args:
            template_name: Name of the template to remove.

        Returns:
            bool: True if the template was removed.
        """
        if self.document is None:
            return False

        removed: bool = self.document.remove_template(template_name)
        if removed:
            _logger.info("template_removed", template_name=template_name)
            if self.state_holder is not None:
                self.state_holder.notify_template_removed(template_name, source="bridge")
        return removed

    async def compile_pattern(self, source: str) -> str:
        """Compile HexPat DSL source code into a JSON template.

        Args:
            source: HexPat DSL source code.

        Returns:
            str: Compiled JSON template string.

        Raises:
            ValueError: If the DSL source has syntax errors.
            RuntimeError: If the HexPat compiler is not available.
        """
        if not self._hexpat_available or _HexPatCompiler is None or _HexPatError is None:
            msg = "hexpat_compiler not available"
            raise RuntimeError(msg)
        compiler = _HexPatCompiler()
        try:
            return compiler.compile(source)
        except _HexPatError as exc:
            msg = f"compilation error at line {exc.line}, column {exc.column}: {exc.message}"
            raise ValueError(msg) from exc

    def _get_interpreter(self) -> HexPatInterpreter:
        """Get or create the HexPat interpreter instance.

        Returns:
            HexPatInterpreter: A HexPatInterpreter instance.

        Raises:
            RuntimeError: If the interpreter module is not available.
        """
        if self._interpreter is not None:
            return cast("HexPatInterpreter", self._interpreter)
        if not self._hexpat_interpreter_available or _HexPatInterpreter is None:
            msg = "hexpat interpreter not available"
            raise RuntimeError(msg)
        self._interpreter = _HexPatInterpreter()
        return cast("HexPatInterpreter", self._interpreter)

    def _get_pattern_registry(self) -> PatternRegistry:
        """Get or create the pattern registry instance.

        Returns:
            PatternRegistry: A PatternRegistry instance.

        Raises:
            RuntimeError: If the pattern registry module is not available.
        """
        if self._pattern_registry is not None:
            return cast("PatternRegistry", self._pattern_registry)
        if not self._hexpat_interpreter_available or _PatternRegistry is None:
            msg = "pattern registry not available"
            raise RuntimeError(msg)
        project_root = Path(__file__).resolve().parents[2]
        patterns_dir = project_root / "vendor" / "community-patterns" / "patterns"
        pattern_dirs: list[Path] = []
        if patterns_dir.exists():
            pattern_dirs.append(patterns_dir)
        self._pattern_registry = _PatternRegistry(pattern_dirs)
        return cast("PatternRegistry", self._pattern_registry)

    async def execute_pattern(
        self,
        source: str,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Execute .hexpat pattern source against the open document.

        Args:
            source: HexPat source code string.
            offset: Base offset in the binary data.

        Returns:
            list[dict[str, Any]]: List of parsed field dicts with name,
                offset, size, display_value, and children.

        Raises:
            RuntimeError: If no document is open or interpreter unavailable.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        interpreter = self._get_interpreter()
        fields: list[dict[str, Any]] = interpreter.execute(source, self.document, offset)
        _logger.info("pattern_executed", field_count=len(fields), offset=offset)
        if self.state_holder is not None:
            self.state_holder.notify_pattern_executed("<inline>", len(fields), source="bridge")
        return fields

    async def execute_pattern_file(
        self,
        pattern_path: str,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Execute a .hexpat pattern file against the open document.

        Args:
            pattern_path: Filesystem path to the .hexpat file.
            offset: Base offset in the binary data.

        Returns:
            list[dict[str, Any]]: List of parsed field dicts.

        Raises:
            RuntimeError: If no document is open or interpreter unavailable.
            FileNotFoundError: If the pattern file does not exist.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        path = Path(pattern_path)
        if not await asyncio.to_thread(path.exists):
            msg = f"pattern file not found: {pattern_path}"
            raise FileNotFoundError(msg)

        interpreter = self._get_interpreter()
        fields: list[dict[str, Any]] = interpreter.execute_file(path, self.document, offset)
        _logger.info(
            "pattern_file_executed",
            pattern_path=pattern_path,
            field_count=len(fields),
            offset=offset,
        )
        if self.state_holder is not None:
            self.state_holder.notify_pattern_executed(path.stem, len(fields), source="bridge")
        return fields

    async def list_hexpat_patterns(self) -> list[dict[str, str]]:
        """List all available .hexpat community patterns.

        Returns:
            list[dict[str, str]]: List of dicts with name, description, and category.
        """
        try:
            registry = self._get_pattern_registry()
        except RuntimeError:
            return []

        patterns = registry.list_patterns()
        _logger.debug("hexpat_patterns_listed", count=len(patterns))
        return [
            {
                "name": p.name,
                "description": p.description or "",
                "category": p.category,
            }
            for p in patterns
        ]

    async def auto_detect_pattern(self) -> list[dict[str, str]]:
        """Auto-detect .hexpat patterns matching the open file by magic bytes.

        Returns:
            list[dict[str, str]]: List of matching pattern dicts sorted by specificity.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        if not self._hexpat_interpreter_available or _DataReader is None:
            return []

        try:
            registry = self._get_pattern_registry()
        except RuntimeError:
            return []

        data_reader = _DataReader.from_document(self.document)
        matches = registry.match_file(data_reader)
        _logger.debug("pattern_auto_detect", match_count=len(matches))
        return [
            {
                "name": m.name,
                "description": m.description or "",
                "category": m.category,
            }
            for m in matches
        ]

    async def export_template(self, template_name: str) -> str:
        """Export a registered template as JSON.

        Args:
            template_name: Name of the template to export.

        Returns:
            str: JSON template string.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        result: str = self.document.export_template_json(template_name)
        _logger.debug("template_exported", template_name=template_name)
        return result

    async def list_templates_detailed(self) -> list[dict[str, Any]]:
        """List all templates with detailed metadata.

        Returns:
            list[dict[str, Any]]: List of dicts with name, description, category, field_count.
        """
        if self.document is None:
            if not self._hexcore_available or _hexcore_mod is None:
                return []
            try:
                doc = _hexcore_mod.HexDocument()
            except (RuntimeError, OSError, TypeError):
                _logger.warning("hexdocument_default_init_failed", exc_info=True)
                return []
            templates = doc.list_templates_detailed()
        else:
            templates = self.document.list_templates_detailed()

        _logger.debug("templates_listed_detailed", count=len(templates))
        return [
            {
                "name": t[0],
                "description": t[1],
                "category": t[2],
                "field_count": t[3],
            }
            for t in templates
        ]

    async def compare_files(self, path_a: str, path_b: str) -> dict[str, Any]:
        """Compare two files byte-by-byte.

        Args:
            path_a: Path to the first file.
            path_b: Path to the second file.

        Returns:
            dict[str, Any]: Dict with regions, total_differences, and files_identical.

        Raises:
            RuntimeError: If the Rust core is not available.
        """
        if not self._hexcore_available or _hexcore_mod is None:
            msg = "intellicrack_hexcore not installed"
            raise RuntimeError(msg)

        _logger.debug("file_comparison_starting", path_a=path_a, path_b=path_b)
        result = _hexcore_mod.diff_files(path_a, path_b)
        if isinstance(result, dict):
            return cast("dict[str, Any]", result)
        return {"regions": [], "total_differences": 0, "files_identical": True}

    async def copy_as(self, fmt: str = "hex") -> str:
        """Format bytes at the cursor position or selection.

        Args:
            fmt: Output format - "hex", "c_array", "python", "base64",
                "rust_array", "csharp_array", "java_array",
                "javascript_array", "go_slice", "hex_string_no_spaces",
                "nasm_db", "markdown_table".

        Returns:
            str: Formatted string representation.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        if self._selection is not None:
            start, end = self._selection
            length = end - start + 1
        else:
            _logger.warning("copy_as_no_selection", cursor_offset=self._cursor_offset)
            start = self._cursor_offset
            length = 1

        raw = self.document.read(start, length)
        if isinstance(raw, bytes):
            data = raw
        elif isinstance(raw, bytearray):
            data = bytes(raw)
        elif isinstance(raw, list):
            data = bytes(cast("list[int]", raw))
        else:
            data: bytes = bytes(raw)

        _logger.debug("data_formatted", fmt=fmt, length=len(data))
        if fmt == "hex":
            return " ".join(f"{b:02X}" for b in data)
        if fmt == "c_array":
            inner = ", ".join(f"0x{b:02X}" for b in data)
            return f"{{{inner}}}"
        if fmt == "python":
            inner = "".join(f"\\x{b:02x}" for b in data)
            return f'b"{inner}"'
        if fmt == "base64":
            return base64.b64encode(data).decode("ascii")
        if fmt == "rust_array":
            inner = ", ".join(f"0x{b:02X}" for b in data)
            return f"[{inner}]"
        if fmt == "csharp_array":
            inner = ", ".join(f"0x{b:02X}" for b in data)
            return f"new byte[] {{{inner}}}"
        if fmt == "java_array":
            parts: list[str] = []
            for b in data:
                if b > _JAVA_SIGNED_BYTE_THRESHOLD:
                    parts.append(f"(byte)0x{b:02X}")
                else:
                    parts.append(f"0x{b:02X}")
            return "new byte[] {" + ", ".join(parts) + "}"
        if fmt == "javascript_array":
            inner = ", ".join(f"0x{b:02X}" for b in data)
            return f"new Uint8Array([{inner}])"
        if fmt == "go_slice":
            inner = ", ".join(f"0x{b:02X}" for b in data)
            return f"[]byte{{{inner}}}"
        if fmt == "hex_string_no_spaces":
            return "".join(f"{b:02X}" for b in data)
        if fmt == "nasm_db":
            inner = ", ".join(f"0x{b:02X}" for b in data)
            return f"db {inner}"
        if fmt == "markdown_table":
            rows: list[str] = ["| Offset | Hex | ASCII |", "| --- | --- | --- |"]
            for i, b in enumerate(data):
                hex_val = f"{b:02X}"
                ascii_val = chr(b) if _PRINTABLE_MIN <= b <= _PRINTABLE_MAX else "."
                rows.append(f"| {start + i:#010x} | {hex_val} | {ascii_val} |")
            return "\n".join(rows)
        return ""

    async def add_bookmark(
        self,
        offset: int,
        length: int = 1,
        label: str = "Bookmark",
        color: str = "#FFFF00",
    ) -> int:
        """Add a bookmark at an offset.

        Args:
            offset: Byte offset.
            length: Length in bytes.
            label: Human-readable label.
            color: Color as hex string.

        Returns:
            int: Index of the new bookmark.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        idx: int = self.document.add_bookmark(offset, length, label, color)
        _logger.debug("bookmark_added", offset=hex(offset), label=label, index=idx)
        return idx

    async def remove_bookmark(self, index: int) -> bool:
        """Remove a bookmark by index.

        Args:
            index: Bookmark index.

        Returns:
            bool: True if the bookmark was removed.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        removed: bool = self.document.remove_bookmark(index)
        _logger.debug("bookmark_removed", index=index, success=removed)
        return removed

    async def list_bookmarks(self) -> list[dict[str, Any]]:
        """List all bookmarks.

        Returns:
            list[dict[str, Any]]: List of dicts with offset, length, label, color.
        """
        if self.document is None:
            return []

        bookmarks = self.document.list_bookmarks()
        _logger.debug("bookmarks_listed", count=len(bookmarks))
        return [{"offset": b[0], "length": b[1], "label": b[2], "color": b[3]} for b in bookmarks]

    async def save(self, path: str | None = None) -> bool:
        """Save the document.

        Args:
            path: Save path. Uses original path if None.

        Returns:
            bool: True if saved successfully.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        if path is not None:
            saved_path = path
            self.document.save(saved_path)
        else:
            file_path = self.document.file_path()
            if file_path is not None:
                saved_path = file_path
                self.document.save(saved_path)
            else:
                msg = "no file path; use save_as"
                raise RuntimeError(msg)

        _logger.info("file_saved", path=saved_path)
        if self.state_holder is not None:
            self.state_holder.notify_document_saved(str(saved_path), source="bridge")
        return True

    async def save_as(self, path: str) -> bool:
        """Save the document to a new path.

        Args:
            path: New file path.

        Returns:
            bool: True if saved successfully.
        """
        return await self.save(path)

    async def calculate_hash_range(
        self,
        start: int,
        end: int,
        algorithm: str = "sha256",
    ) -> str:
        """Calculate a hash of a byte range within the document.

        Args:
            start: Start byte offset.
            end: End byte offset (exclusive).
            algorithm: Hash algorithm (md5, sha1, sha256, sha512, crc32).

        Returns:
            str: Hex digest string.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        digest: str = self.document.compute_hash_range(start, end, algorithm)
        _logger.debug("hash_range_calculated", algorithm=algorithm, start=start, end=end)
        return digest

    async def get_document_info(self) -> dict[str, Any]:
        """Get information about the currently open document.

        Returns:
            dict[str, Any]: Dict with file_path, size, modified, cursor, and selection.
        """
        if self.document is None:
            return {
                "file_path": None,
                "size": 0,
                "modified": False,
                "cursor": 0,
                "selection": None,
            }

        file_path_val = self.document.file_path()
        return {
            "file_path": file_path_val,
            "size": self.document.length(),
            "modified": self.document.is_modified(),
            "cursor": self._cursor_offset,
            "selection": list(self._selection) if self._selection else None,
        }

    async def get_context_for_ai(self, include_bytes: int = 256) -> dict[str, Any]:
        """Get hex editor context suitable for AI analysis.

        Collects document metadata, bytes around the cursor, data
        inspection at the cursor, selected bytes, and bookmarks into
        a single dict for injection into an AI conversation.

        Args:
            include_bytes: Number of bytes around the cursor to include.

        Returns:
            dict[str, Any]: Dict with document info, bytes_at_cursor, inspection,
            selected_bytes, and bookmarks.
        """
        context: dict[str, Any] = await self.get_document_info()

        if self.document is not None:
            cursor = self._cursor_offset
            half = include_bytes // 2
            doc_len: int = self.document.length()
            read_start = max(0, cursor - half)
            read_len = min(include_bytes, doc_len - read_start)
            if read_len > 0:
                raw = self.document.read(read_start, read_len)
                context["bytes_at_cursor"] = " ".join(f"{b:02X}" for b in raw)
                context["bytes_offset"] = read_start
            else:
                context["bytes_at_cursor"] = ""
                context["bytes_offset"] = 0

            try:
                inspection = self.document.inspect_at(cursor)
                if isinstance(inspection, dict):
                    context["inspection"] = {k: str(v) for k, v in cast("dict[str, object]", inspection).items()}
            except (RuntimeError, OSError, ValueError) as exc:
                _logger.warning("inspect_at_failed", offset=cursor, exc_info=True)
                context["inspection"] = {"error": str(exc)}

            if self._selection is not None:
                sel_start, sel_end = self._selection
                sel_start, sel_end = min(sel_start, sel_end), max(sel_start, sel_end)
                sel_len = sel_end - sel_start + 1
                capped = min(sel_len, include_bytes)
                sel_raw = self.document.read(sel_start, capped)
                context["selected_bytes"] = " ".join(f"{b:02X}" for b in sel_raw)
                context["selection_range"] = [sel_start, sel_end]

            bookmarks = self.document.list_bookmarks()
            context["bookmarks"] = [{"offset": b[0], "length": b[1], "label": b[2]} for b in bookmarks]

        return context

    async def save_to_sandbox(
        self,
        dest_path: str,
        sandbox_type: str = "docker",
    ) -> dict[str, Any]:
        """Save the current document into a sandbox environment.

        Writes the document to a temporary file, then uses the sandbox
        bridge to copy it into the sandbox at the given destination path.

        Args:
            dest_path: Destination path inside the sandbox.
            sandbox_type: Sandbox type (docker, qemu, windows_sandbox).

        Returns:
            dict[str, Any]: Dict with sandbox_path and status.

        Raises:
            RuntimeError: If no document is open or sandbox unavailable.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        if self.tool_registry is None:
            msg = "tool registry not set; cannot access sandbox bridge"
            raise RuntimeError(msg)

        sandbox_bridge = self.tool_registry.get(ToolName.SANDBOX)
        if sandbox_bridge is None:
            msg = "sandbox bridge not available"
            raise RuntimeError(msg)

        file_path_str = self.document.file_path()
        tmp_path: str | None = None
        if file_path_str is None:
            tmp_fd, tmp_path = tempfile.mkstemp(suffix=".bin")
            os.close(tmp_fd)
            self.document.save(tmp_path)
            file_path_str = tmp_path

        try:
            copy_fn = getattr(sandbox_bridge, "copy_to_sandbox", None)
            if callable(copy_fn):
                if _inspect_mod.iscoroutinefunction(copy_fn):
                    await copy_fn(file_path_str, dest_path, sandbox_type)
                else:
                    await asyncio.to_thread(copy_fn, file_path_str, dest_path, sandbox_type)
        finally:
            if tmp_path is not None:
                try:
                    await asyncio.to_thread(Path(tmp_path).unlink)
                except OSError:
                    _logger.debug("tmp_file_cleanup_failed", path=tmp_path)

        _logger.info("saved_to_sandbox", dest=dest_path, sandbox_type=sandbox_type)
        return {"sandbox_path": dest_path, "status": "copied"}

    async def test_in_sandbox(
        self,
        args: str = "",
        sandbox_type: str = "docker",
        max_wait: int = 30,
    ) -> dict[str, Any]:
        """Save to sandbox, execute the binary, and return the report.

        Args:
            args: Command-line arguments for the binary.
            sandbox_type: Sandbox type.
            max_wait: Execution timeout in seconds.

        Returns:
            dict[str, Any]: Dict with execution report including exit_code, stdout, stderr.

        Raises:
            RuntimeError: If no document is open or sandbox unavailable.
            TypeError: If sandbox bridge does not support run_binary.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        file_name = "target.bin"
        file_path_str = self.document.file_path()
        if file_path_str is not None:
            file_name = Path(file_path_str).name

        dest_path = f"/sandbox_workdir/{file_name}"
        await self.save_to_sandbox(dest_path, sandbox_type)

        if self.tool_registry is None:
            msg = "tool registry not set"
            raise RuntimeError(msg)

        sandbox_bridge = self.tool_registry.get(ToolName.SANDBOX)
        if sandbox_bridge is None:
            msg = "sandbox bridge not available"
            raise RuntimeError(msg)

        run_fn = getattr(sandbox_bridge, "run_binary", None)
        if not callable(run_fn):
            msg = "sandbox bridge does not support run_binary"
            raise TypeError(msg)

        if _inspect_mod.iscoroutinefunction(run_fn):
            result = await run_fn(dest_path, args, max_wait)
        else:
            result = await asyncio.to_thread(run_fn, dest_path, args, max_wait)

        _logger.info(
            "sandbox_test_completed",
            dest=dest_path,
            sandbox_type=sandbox_type,
        )
        if isinstance(result, dict):
            return cast("dict[str, Any]", result)
        return {"exit_code": -1, "stdout": "", "stderr": str(result)}

    async def get_entropy(self) -> float:
        """Get Shannon entropy of the entire document.

        Returns:
            float: Entropy value between 0.0 and 8.0.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        result: float = self.document.entropy()
        _logger.debug("entropy_computed", value=result)
        return result

    async def get_entropy_map(self, block_size: int = 4096) -> list[float]:
        """Get per-block entropy values across the document.

        Args:
            block_size: Block size in bytes for entropy calculation.

        Returns:
            list[float]: List of entropy values per block.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        result = self.document.entropy_map(block_size)
        _logger.debug("entropy_map_computed", blocks=len(result), block_size=block_size)
        return [float(v) for v in result]

    async def get_byte_distribution(self) -> list[int]:
        """Get the 256-element byte frequency distribution.

        Returns:
            list[int]: List of 256 integer counts, one per byte value.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        result = self.document.byte_distribution_full()
        _logger.debug("byte_distribution_computed")
        return [int(v) for v in result]

    async def get_byte_type_distribution(self) -> dict[str, int]:
        """Get byte type counts across the document.

        Returns:
            dict[str, int]: Dict with null_count, printable_count, control_count, high_count.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        result: Any = self.document.byte_type_distribution()
        _logger.debug("byte_type_distribution_computed")
        if isinstance(result, dict):
            return cast("dict[str, int]", result)
        items: list[Any] = list(result)
        return {
            "null_count": int(items[0]),
            "printable_count": int(items[1]),
            "control_count": int(items[2]),
            "high_count": int(items[3]),
        }

    async def get_digram_matrix(self) -> list[int]:
        """Get the 256x256 byte-pair frequency matrix.

        Returns:
            list[int]: List of 65536 integer frequencies in row-major order.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        result = self.document.digram_matrix()
        _logger.debug("digram_matrix_computed")
        return [int(v) for v in result]

    async def get_content_classification(self, block_size: int = 4096) -> list[int]:
        """Classify document blocks by content type.

        Args:
            block_size: Block size in bytes for classification.

        Returns:
            list[int]: List of classification ints per block:
                0=null, 1=plaintext, 2=structured, 3=encrypted, 4=code.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        result = self.document.content_classification(block_size)
        _logger.debug("content_classification_computed", blocks=len(result), block_size=block_size)
        return [int(v) for v in result]

    async def disassemble(
        self,
        offset: int,
        count: int = 50,
        arch: str = "auto",
        mode: str = "64",
    ) -> list[dict[str, Any]]:
        """Disassemble instructions at a byte offset.

        Args:
            offset: Byte offset in the document to disassemble from.
            count: Number of instructions to disassemble.
            arch: Target architecture (x86, arm, arm64, mips, etc.) or "auto".
            mode: Architecture mode (16, 32, 64, arm, thumb).

        Returns:
            list[dict[str, Any]]: List of dicts with address, bytes, mnemonic, operands, size.

        Raises:
            RuntimeError: If no document is open or disassembler module is unavailable.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        if not _disasm_available or _HexDisassembler is None:
            msg = "disassembler module not available"
            raise RuntimeError(msg)

        max_bytes = count * 15
        doc_len: int = self.document.length()
        read_len = min(max_bytes, doc_len - offset)
        if read_len <= 0:
            _logger.info("disassemble_out_of_bounds", offset=offset, doc_len=doc_len)
            return []

        raw = self.document.read(offset, read_len)
        if isinstance(raw, bytes):
            data = raw
        elif isinstance(raw, bytearray) or not isinstance(raw, list):
            data = bytes(raw)
        else:
            data = bytes(cast("list[int]", raw))
        disassembler = _HexDisassembler()
        if arch == "auto":
            arch, mode = disassembler.auto_detect_arch(data)

        raw_instructions = disassembler.disassemble(data, offset, arch, mode, count)
        _logger.debug("disassembly_completed", offset=hex(offset), count=len(raw_instructions), arch=arch)
        return [
            {
                "address": insn.address,
                "bytes": insn.raw_bytes.hex(),
                "mnemonic": insn.mnemonic,
                "operands": insn.op_str,
                "size": insn.size,
            }
            for insn in raw_instructions
        ]

    async def yara_scan(self, rule_source: str) -> list[dict[str, Any]]:
        """Scan the document with a YARA rule given as source code.

        Args:
            rule_source: YARA rule source code string.

        Returns:
            list[dict[str, Any]]: List of match dicts with rule, tags, meta, strings.

        Raises:
            RuntimeError: If no document is open or YARA scanner module is unavailable.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        if not _yara_bridge_available or _YaraScanner is None:
            msg = "yara_scanner module not available"
            raise RuntimeError(msg)

        doc_len: int = self.document.length()
        raw = self.document.read(0, doc_len)
        if isinstance(raw, bytes):
            data = raw
        elif isinstance(raw, bytearray) or not isinstance(raw, list):
            data = bytes(raw)
        else:
            data = bytes(cast("list[int]", raw))
        scanner = _YaraScanner()
        compiled = scanner.compile_source(rule_source)
        raw_matches = scanner.scan_data(data, compiled)
        _logger.debug("yara_scan_completed", matches=len(raw_matches))
        return [
            {
                "rule": m.rule_name,
                "tags": m.tags,
                "meta": m.meta,
                "namespace": m.namespace,
                "strings": [{"identifier": s.identifier, "offset": s.offset, "data": s.data.hex()} for s in m.strings],
            }
            for m in raw_matches
        ]

    async def yara_scan_files(self, rule_paths: str) -> list[dict[str, Any]]:
        """Scan the document with YARA rules loaded from files.

        Args:
            rule_paths: Comma-separated paths to .yar rule files.

        Returns:
            list[dict[str, Any]]: List of match dicts with rule, tags, meta, strings.

        Raises:
            RuntimeError: If no document is open or YARA scanner module is unavailable.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        if not _yara_bridge_available or _YaraScanner is None:
            msg = "yara_scanner module not available"
            raise RuntimeError(msg)

        doc_len: int = self.document.length()
        raw = self.document.read(0, doc_len)
        if isinstance(raw, bytes):
            data = raw
        elif isinstance(raw, bytearray) or not isinstance(raw, list):
            data = bytes(raw)
        else:
            data = bytes(cast("list[int]", raw))
        paths: list[str | Path] = [Path(p.strip()) for p in rule_paths.split(",") if p.strip()]
        scanner = _YaraScanner()
        compiled = scanner.compile_rules(paths)
        raw_matches = scanner.scan_data(data, compiled)
        _logger.debug("yara_scan_files_completed", rule_paths=paths, matches=len(raw_matches))
        return [
            {
                "rule": m.rule_name,
                "tags": m.tags,
                "meta": m.meta,
                "namespace": m.namespace,
                "strings": [{"identifier": s.identifier, "offset": s.offset, "data": s.data.hex()} for s in m.strings],
            }
            for m in raw_matches
        ]

    async def apply_transform(
        self,
        name: str,
        offset: int,
        length: int,
        params_json: str = "{}",
    ) -> str:
        """Apply a data transform to a byte range.

        Args:
            name: Transform name (e.g. xor_single, base64_encode).
            offset: Start offset in the document.
            length: Number of bytes to transform.
            params_json: JSON dict of transform parameters. Byte values as hex strings.

        Returns:
            str: Hex string of the transformed bytes.

        Raises:
            RuntimeError: If the operation fails.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        raw_params = cast("dict[str, Any]", json.loads(params_json))
        params: dict[str, Any] = {}
        for k, v in raw_params.items():
            if isinstance(v, str):
                try:
                    params[k] = bytes.fromhex(v)
                except ValueError:
                    params[k] = v
            else:
                params[k] = v

        if not hasattr(self.document, "transform_data"):
            msg = "backend does not support transform_data"
            raise RuntimeError(msg)
        result = self.document.transform_data(name, offset, length, params)
        if isinstance(result, bytes):
            data = result
        elif isinstance(result, bytearray) or not isinstance(result, list):
            data = bytes(result)
        else:
            data = bytes(cast("list[int]", result))
        _logger.debug("transform_applied", name=name, offset=hex(offset), length=length)
        return data.hex()

    async def apply_pipeline(
        self,
        pipeline_json: str,
        offset: int,
        length: int,
    ) -> str:
        """Apply a transform pipeline to a byte range.

        Args:
            pipeline_json: JSON array of {name, params} step dicts.
            offset: Start offset in the document.
            length: Number of bytes to transform.

        Returns:
            str: Hex string of the transformed bytes.

        Raises:
            RuntimeError: If the operation fails.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        if _TransformPipeline is None:
            msg = "transform_pipeline module not available"
            raise RuntimeError(msg)

        steps = cast("list[dict[str, Any]]", json.loads(pipeline_json))
        raw = self.document.read(offset, length)
        if isinstance(raw, bytes):
            data = raw
        elif isinstance(raw, bytearray) or not isinstance(raw, list):
            data = bytes(raw)
        else:
            data = bytes(cast("list[int]", raw))

        if self._transform_node_cache is None:
            self._transform_node_cache = {n.name: n for n in _get_all_transform_nodes()}
        node_map = self._transform_node_cache
        pipeline = _TransformPipeline()
        for step in steps:
            step_name = str(step.get("name", ""))
            step_params = cast("dict[str, Any]", step.get("params", {}))
            if step_name in node_map:
                pipeline.add_step(node_map[step_name], step_params)
        result = pipeline.execute(data)
        _logger.debug("pipeline_applied", steps=len(steps), offset=hex(offset), length=length)
        return result.hex()

    async def list_transforms(self) -> list[dict[str, str]]:
        """List all available data transforms.

        Returns:
            list[dict[str, str]]: List of dicts with name, category, description.
        """
        if not self._pipeline_available or _get_all_transform_nodes is None:
            return []

        nodes = _get_all_transform_nodes()
        _logger.debug("transforms_listed", count=len(nodes))
        return [{"name": n.name, "category": n.category, "description": n.description} for n in nodes]

    async def decode_text(self, offset: int, length: int, encoding: str = "utf-8") -> str:
        """Decode bytes at an offset as text in the specified encoding.

        Args:
            offset: Start offset in the document.
            length: Number of bytes to decode.
            encoding: Python codec name (e.g. utf-8, utf-16le, latin-1).

        Returns:
            str: Decoded text string.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        if hasattr(self.document, "decode_text"):
            result: str = self.document.decode_text(offset, length, encoding)
            _logger.debug("text_decoded", offset=hex(offset), length=length, encoding=encoding, backend="rust")
            return result

        _logger.info("decode_text_fallback_used", offset=hex(offset), length=length, encoding=encoding)
        raw = self.document.read(offset, length)
        if isinstance(raw, bytes):
            data = raw
        elif isinstance(raw, bytearray) or not isinstance(raw, list):
            data = bytes(raw)
        else:
            data = bytes(cast("list[int]", raw))
        decoded = data.decode(encoding, errors="replace")
        _logger.debug("text_decoded", offset=hex(offset), length=length, encoding=encoding, backend="python")
        return decoded

    async def encode_text(self, text: str, encoding: str = "utf-8") -> str:
        """Encode text into bytes using the specified encoding.

        Args:
            text: Text string to encode.
            encoding: Python codec name (e.g. utf-8, utf-16le, shift-jis).

        Returns:
            str: Hex string of the encoded bytes.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        if hasattr(self.document, "encode_text_to_bytes"):
            raw_bytes: list[int] = self.document.encode_text_to_bytes(text, encoding)
            result = bytes(raw_bytes).hex()
            _logger.debug("text_encoded", encoding=encoding, length=len(raw_bytes), backend="rust")
            return result

        encoded = text.encode(encoding)
        _logger.debug("text_encoded", encoding=encoding, length=len(encoded), backend="python")
        return encoded.hex()

    async def list_encodings(self) -> list[dict[str, str]]:
        """List all supported text encodings.

        Returns:
            list[dict[str, str]]: List of dicts with name and label.
        """
        if self.document is not None and hasattr(self.document, "list_encodings"):
            raw = self.document.list_encodings()
            _logger.debug("encodings_listed", count=len(raw))
            return [{"name": str(e[0]), "label": str(e[1])} for e in raw]

        encodings: list[dict[str, str]] = [
            {"name": "utf-8", "label": "UTF-8"},
            {"name": "utf-16le", "label": "UTF-16 LE"},
            {"name": "utf-16be", "label": "UTF-16 BE"},
            {"name": "utf-32le", "label": "UTF-32 LE"},
            {"name": "utf-32be", "label": "UTF-32 BE"},
            {"name": "ascii", "label": "ASCII"},
            {"name": "latin-1", "label": "Latin-1 (ISO 8859-1)"},
            {"name": "cp1252", "label": "Windows-1252"},
            {"name": "cp1251", "label": "Windows-1251 (Cyrillic)"},
            {"name": "shift-jis", "label": "Shift-JIS"},
            {"name": "euc-jp", "label": "EUC-JP"},
            {"name": "gb2312", "label": "GB2312 (Simplified Chinese)"},
            {"name": "big5", "label": "Big5 (Traditional Chinese)"},
            {"name": "euc-kr", "label": "EUC-KR"},
        ]
        _logger.debug("encodings_listed", count=len(encodings))
        return encodings

    async def calculate_hash_custom_crc(
        self,
        start: int,
        end: int,
        poly: int,
        init: int,
        width: int,
        *,
        refin: bool = False,
        refout: bool = False,
        xorout: int = 0,
    ) -> str:
        """Calculate a CRC with fully custom parameters over a byte range.

        Args:
            start: Start byte offset (inclusive).
            end: End byte offset (exclusive).
            poly: CRC generator polynomial.
            init: Initial CRC register value.
            width: CRC width in bits: 8, 16, 32, or 64.
            refin: Reflect each input byte before processing.
            refout: Reflect the final CRC register before XOR.
            xorout: Value to XOR with the final CRC register.

        Returns:
            str: CRC value as a zero-padded hex string.

        Raises:
            RuntimeError: If no document is open.
            ValueError: If width is not 8, 16, 32, or 64.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        if hasattr(self.document, "compute_hash_custom_crc"):
            result: str = self.document.compute_hash_custom_crc(start, end, poly, init, width, refin, refout, xorout)
            _logger.debug("custom_crc_computed", width=width)
            return result

        valid_widths = {8, 16, 32, 64}
        if width not in valid_widths:
            msg = f"unsupported CRC width {width}; must be one of {valid_widths}"
            raise ValueError(msg)

        length = end - start
        raw = self.document.read(start, length)
        if isinstance(raw, bytes):
            data = raw
        elif isinstance(raw, bytearray):
            data = bytes(raw)
        elif isinstance(raw, list):
            data = bytes(cast("list[int]", raw))
        else:
            data = bytes(raw)

        mask = (1 << width) - 1

        def reflect(val: int, bits: int) -> int:
            reflected = 0
            for _ in range(bits):
                reflected = (reflected << 1) | (val & 1)
                val >>= 1
            return reflected

        crc = init & mask
        for byte in data:
            b = reflect(byte, 8) if refin else byte
            crc ^= b << (width - 8)
            for _ in range(8):
                crc = ((crc << 1) ^ poly) & mask if crc & (1 << (width - 1)) else (crc << 1) & mask
        if refout:
            crc = reflect(crc, width)
        crc ^= xorout
        crc &= mask

        hex_width = width // 4
        _logger.debug("custom_crc_computed", width=width, result=f"{crc:#0{hex_width + 2}x}")
        return f"{crc:0{hex_width}X}"

    async def export_patches(self, patch_format: str = "ips") -> str:
        """Export document patches as IPS or IPS32 format.

        Args:
            patch_format: Patch format, either "ips" or "ips32".

        Returns:
            str: Base64-encoded patch data.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        raw: bytes
        if patch_format == "ips32" and hasattr(self.document, "export_patches_ips32"):
            raw = self.document.export_patches_ips32()
        elif hasattr(self.document, "export_patches_ips"):
            raw = self.document.export_patches_ips()
        elif hasattr(self.document, "get_patches"):
            patches: list[tuple[int, bytes]] = self.document.get_patches()
            raw = self._build_ips_from_patches(patches, ips32=(patch_format == "ips32"))
        else:
            msg = f"patch export format '{patch_format}' not supported by backend"
            raise RuntimeError(msg)

        _logger.debug("patches_exported", patch_format=patch_format, size=len(raw))
        return base64.b64encode(raw).decode("ascii")

    async def import_patches(self, data_b64: str) -> int:
        """Import and apply IPS/IPS32 patches from base64-encoded data.

        Args:
            data_b64: Base64-encoded IPS or IPS32 patch data.

        Returns:
            int: Number of patches applied.

        Raises:
            RuntimeError: If no document is open or import is unsupported.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        raw = base64.b64decode(data_b64)
        if hasattr(self.document, "import_patches_ips"):
            count: int = self.document.import_patches_ips(raw)
        else:
            count = self._apply_ips_patches(raw)

        _logger.debug("patches_imported", count=count)
        if count > 0 and self.state_holder is not None:
            doc_len: int = self.document.length()
            self.state_holder.notify_data_modified(0, doc_len, source="bridge")
        return count

    @staticmethod
    def _build_ips_from_patches(
        patches: list[tuple[int, bytes]],
        *,
        ips32: bool = False,
    ) -> bytes:
        """Build IPS or IPS32 binary data from a list of patch tuples.

        Args:
            patches: List of (offset, data) tuples.
            ips32: If True, produce IPS32 format; otherwise standard IPS.

        Returns:
            bytes: Complete IPS/IPS32 binary blob.
        """
        parts: list[bytes] = []
        if ips32:
            parts.append(b"IPS32")
        else:
            parts.append(b"PATCH")
        for offset, data in patches:
            size = len(data)
            if ips32:
                parts.append(struct.pack(">I", offset))
            else:
                parts.append(struct.pack(">I", offset)[1:])
            parts.extend((struct.pack(">H", size), data))
        if ips32:
            parts.append(b"EEOF")
        else:
            parts.append(b"EOF")
        return b"".join(parts)

    def _apply_ips_patches(self, raw: bytes) -> int:
        """Parse and apply IPS/IPS32 patches to the current document.

        Args:
            raw: Raw IPS or IPS32 binary data.

        Returns:
            int: Number of patches applied.

        Raises:
            RuntimeError: If the header is invalid.
        """
        pos = 0
        if raw[:5] == b"IPS32":
            ips32 = True
            pos = 5
            eof_marker = b"EEOF"
        elif raw[:5] == b"PATCH":
            ips32 = False
            pos = 5
            eof_marker = b"EOF"
        else:
            msg = "invalid IPS header"
            raise RuntimeError(msg)

        count = 0
        while pos < len(raw) and raw[pos : pos + len(eof_marker)] != eof_marker:
            if ips32:
                if pos + 6 > len(raw):
                    break
                offset = struct.unpack(">I", raw[pos : pos + 4])[0]
                size = struct.unpack(">H", raw[pos + 4 : pos + 6])[0]
                pos += 6
            else:
                if pos + 5 > len(raw):
                    break
                offset = struct.unpack(">I", b"\x00" + raw[pos : pos + 3])[0]
                size = struct.unpack(">H", raw[pos + 3 : pos + 5])[0]
                pos += 5
            if pos + size > len(raw):
                break
            patch_data = raw[pos : pos + size]
            pos += size
            if self.document is not None:
                self.document.write_bytes(offset, list(patch_data))
            count += 1
        return count

    async def search_numeric(
        self,
        value: int,
        size: int = 4,
        value_type: str = "uint",
        endianness: str = "little",
        alignment: int = 1,
        max_results: int = 100,
    ) -> list[dict[str, int]]:
        """Search for a numeric value in the document.

        Args:
            value: Integer value to search for.
            size: Byte size of the value: 1, 2, 4, or 8.
            value_type: Value type interpretation: "uint", "int", or "float".
            endianness: Byte order: "little" or "big".
            alignment: Search step alignment in bytes.
            max_results: Maximum number of results to return.

        Returns:
            list[dict[str, int]]: List of dicts with offset and length.

        Raises:
            RuntimeError: If the operation fails.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        big_endian = endianness == "big"
        if value_type == "float":
            if hasattr(self.document, "search_numeric_float"):
                results = self.document.search_numeric_float(value, size, big_endian, alignment, max_results)
                _logger.debug("search_numeric_float_completed", matches=len(results))
                return [{"offset": r[0], "length": r[1]} for r in results]
        elif hasattr(self.document, "search_numeric"):
            results = self.document.search_numeric(value, size, value_type == "int", big_endian, alignment, max_results)
            _logger.debug("search_numeric_completed", matches=len(results))
            return [{"offset": r[0], "length": r[1]} for r in results]

        needle = self._pack_numeric_needle(value, size, value_type, big_endian=big_endian)
        doc_len: int = self.document.length()
        matches: list[dict[str, int]] = []
        pos = 0
        while pos <= doc_len - size and len(matches) < max_results:
            chunk_len = min(65536, doc_len - pos)
            raw = self.document.read(pos, chunk_len)
            if isinstance(raw, bytes):
                chunk = raw
            elif isinstance(raw, bytearray) or not isinstance(raw, list):
                chunk = bytes(raw)
            else:
                chunk = bytes(cast("list[int]", raw))
            idx = 0
            while idx <= len(chunk) - size and len(matches) < max_results:
                if chunk[idx : idx + size] == needle:
                    abs_offset = pos + idx
                    if (abs_offset % alignment) == 0:
                        matches.append({"offset": abs_offset, "length": size})
                idx += alignment
            pos += chunk_len - size + 1

        _logger.debug("search_numeric_completed", matches=len(matches))
        return matches

    async def search_numeric_range(
        self,
        min_val: int,
        max_val: int,
        size: int = 4,
        value_type: str = "uint",
        endianness: str = "little",
        alignment: int = 1,
        max_results: int = 100,
    ) -> list[dict[str, int]]:
        """Search for numeric values within a min/max range.

        Args:
            min_val: Minimum value (inclusive).
            max_val: Maximum value (inclusive).
            size: Byte size of the value: 1, 2, 4, or 8.
            value_type: Value type interpretation: "uint" or "int".
            endianness: Byte order: "little" or "big".
            alignment: Search step alignment in bytes.
            max_results: Maximum number of results to return.

        Returns:
            list[dict[str, int]]: List of dicts with offset and length.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        if hasattr(self.document, "search_numeric_range"):
            results = self.document.search_numeric_range(
                min_val,
                max_val,
                size,
                value_type == "int",
                endianness == "big",
                alignment,
                max_results,
            )
            _logger.debug("search_numeric_range_completed", matches=len(results))
            return [{"offset": r[0], "length": r[1]} for r in results]

        fmt = self._build_numeric_format(size, value_type, big_endian=endianness == "big")
        doc_len: int = self.document.length()
        matches: list[dict[str, int]] = []
        pos = 0
        while pos <= doc_len - size and len(matches) < max_results:
            read_len = min(65536, doc_len - pos)
            raw = self.document.read(pos, read_len)
            chunk = raw if isinstance(raw, bytes) else bytes(raw)
            idx = 0
            while idx <= len(chunk) - size and len(matches) < max_results:
                try:
                    (val,) = struct.unpack_from(fmt, chunk, idx)
                except struct.error:
                    idx += alignment
                    continue
                if ((pos + idx) % alignment) == 0 and min_val <= val <= max_val:
                    matches.append({"offset": pos + idx, "length": size})
                idx += alignment
            pos += read_len - size + 1

        _logger.debug("search_numeric_range_completed", matches=len(matches))
        return matches

    @staticmethod
    def _build_numeric_format(size: int, value_type: str, *, big_endian: bool) -> str:
        """Build a struct format string for numeric search.

        Args:
            size: Byte width: 1, 2, 4, or 8.
            value_type: ``"int"`` or ``"uint"``.
            big_endian: True for big-endian byte order.

        Returns:
            str: struct format string (e.g. ``"<I"``).

        Raises:
            ValueError: If size is not 1, 2, 4, or 8.
        """
        size_chars: dict[int, str] = {1: "b", 2: "h", 4: "i", 8: "q"}
        if size not in size_chars:
            msg = f"numeric size must be 1, 2, 4, or 8, got {size}"
            raise ValueError(msg)
        endian_char = ">" if big_endian else "<"
        fmt_char = size_chars[size] if value_type == "int" else size_chars[size].upper()
        return endian_char + fmt_char

    @staticmethod
    def _pack_numeric_needle(value: int, size: int, value_type: str, *, big_endian: bool) -> bytes:
        """Pack a numeric value into bytes for use as a search needle.

        Args:
            value: Numeric value to pack.
            size: Byte width: 1, 2, 4, or 8 for integers; 4 or 8 for floats.
            value_type: ``"float"``, ``"int"``, or ``"uint"``.
            big_endian: True for big-endian byte order.

        Returns:
            bytes: Packed bytes representation of the value.

        Raises:
            ValueError: If size is invalid for the given value_type.
        """
        endian_char = ">" if big_endian else "<"
        if value_type == "float":
            if size not in {4, 8}:
                msg = f"float size must be 4 or 8, got {size}"
                raise ValueError(msg)
            fmt_char = "f" if size == _DEFAULT_POINTER_SIZE else "d"
            return struct.pack(endian_char + fmt_char, float(value))
        if size not in {1, 2, 4, 8}:
            msg = f"numeric size must be 1, 2, 4, or 8, got {size}"
            raise ValueError(msg)
        signed = value_type == "int"
        size_chars = {1: "b", 2: "h", 4: "i", 8: "q"}
        fmt_char = size_chars[size] if signed else size_chars[size].upper()
        return struct.pack(endian_char + fmt_char, value)

    async def add_highlight_rule(
        self,
        condition_type: str,
        condition_params: str,
        color: str = "#FFFF00",
    ) -> str:
        """Add a byte highlighting rule.

        Args:
            condition_type: Condition type: "byte_value", "byte_range", or "pattern".
            condition_params: JSON string of condition parameters.
            color: Highlight color as a hex color string (e.g. "#FFFF00").

        Returns:
            str: Rule ID string (UUID).
        """
        parsed_params = cast("dict[str, Any]", json.loads(condition_params))
        rule_id = str(uuid.uuid4())
        rule: dict[str, Any] = {
            "id": rule_id,
            "condition_type": condition_type,
            "condition_params": parsed_params,
            "color": color,
        }
        self._highlight_rules[rule_id] = rule
        _logger.debug("highlight_rule_added", rule_id=rule_id, condition_type=condition_type)
        if self.state_holder is not None:
            self.state_holder.set_highlight_rule(rule_id, rule)
            self.state_holder.notify_highlight_rule_added(rule, source="bridge")
        return rule_id

    async def remove_highlight_rule(self, rule_id: str) -> bool:
        """Remove a highlighting rule by ID.

        Args:
            rule_id: The rule ID returned from add_highlight_rule.

        Returns:
            bool: True if the rule was found and removed.
        """
        if rule_id not in self._highlight_rules:
            return False
        del self._highlight_rules[rule_id]
        _logger.debug("highlight_rule_removed", rule_id=rule_id)
        if self.state_holder is not None:
            self.state_holder.remove_highlight_rule_state(rule_id)
            self.state_holder.notify_highlight_rule_removed(rule_id, source="bridge")
        return True

    async def list_highlight_rules(self) -> list[dict[str, Any]]:
        """List all active highlighting rules.

        Returns:
            list[dict[str, Any]]: List of rule dicts with id, condition_type,
                condition_params, and color.
        """
        rules = list(self._highlight_rules.values())
        _logger.debug("highlight_rules_listed", count=len(rules))
        return rules

    async def set_display_mode(self, mode: str) -> bool:
        """Set the hex display mode.

        Args:
            mode: Display mode string (e.g. "hex8", "hex16_le", "float32").

        Returns:
            bool: True always.
        """
        self._display_mode = mode
        _logger.debug("display_mode_set", mode=mode)
        if self.state_holder is not None:
            self.state_holder.set_display_mode_state(mode)
            self.state_holder.notify_display_mode_changed(mode, source="bridge")
        return True

    async def get_display_mode(self) -> str:
        """Get the current hex display mode.

        Returns:
            str: Current display mode string.
        """
        return self._display_mode

    async def list_process_regions(self, pid: int) -> list[dict[str, int]]:
        """List memory regions of a process by PID (Windows only).

        Args:
            pid: Process ID to inspect.

        Returns:
            list[dict[str, int]]: List of dicts with base_address, size, protection, state.

        Raises:
            RuntimeError: If hexcore native module is not available.
        """
        if not _hexcore_available or _hexcore_mod is None:
            msg = "hexcore native module not available"
            raise RuntimeError(msg)

        regions: list[tuple[int, int, int, int]] = _hexcore_mod.HexDocument.list_process_memory_regions(pid)
        _logger.debug("process_regions_listed", pid=pid, count=len(regions), bridge=self.name)
        return [{"base_address": r[0], "size": r[1], "protection": r[2], "state": r[3]} for r in regions]

    async def open_process_memory(self, pid: int, address: int, size: int) -> dict[str, Any]:
        """Open a process memory region as a hex document (Windows only).

        Args:
            pid: Process ID to read from.
            address: Base address of the memory region.
            size: Number of bytes to read.

        Returns:
            dict[str, Any]: Dict with pid, address, size, and document_length.

        Raises:
            RuntimeError: If hexcore native module is not available.
        """
        if not _hexcore_available or _hexcore_mod is None:
            msg = "hexcore native module not available"
            raise RuntimeError(msg)

        self.document = _hexcore_mod.HexDocument.from_process_memory(pid, address, size)
        self._cursor_position = 0
        self._selection = None
        self._state.binary_loaded = True
        _logger.info("process_memory_opened", pid=pid, address=hex(address), size=size)

        if self.state_holder is not None:
            self.state_holder.set_document(self.document, None, source="bridge")

        doc = self.document
        doc_length: int = doc.length() if doc is not None else size
        return {"pid": pid, "address": address, "size": size, "document_length": doc_length}
