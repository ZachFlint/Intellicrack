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
import builtins as _builtins_mod
import hashlib
import inspect as _inspect_mod
import io
import json
import math
import operator
import os
import struct
import tempfile
import threading
import uuid
import zlib
from itertools import cycle, islice
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol, cast, get_args

from intellicrack.bridges._pe_format import (
    is_pe64_optional_header,
    iterate_section_headers,
    read_dos_e_lfanew,
    unpack_coff_header,
    unpack_optional_header_image_base,
    unpack_section_header,
)
from intellicrack.bridges.base import BridgeCapabilities, ToolBridgeBase
from intellicrack.core.logging import get_logger
from intellicrack.core.types import ToolDefinition, ToolError, ToolFunction, ToolName, ToolParameter


if TYPE_CHECKING:
    from intellicrack.bridges.hex_state import HexDocumentState
    from intellicrack.core.disassembler import HexDisassembler
    from intellicrack.core.hexpat import HexPatInterpreter, PatternRegistry
    from intellicrack.core.hexpat_compiler import HexPatCompiler, HexPatError
    from intellicrack.core.tools import ToolRegistry
    from intellicrack.core.transform_pipeline import TransformPipeline
    from intellicrack.core.yara_scanner import YaraScanner


class _FPDFProtocol(Protocol):
    """Structural interface for the fpdf2 ``FPDF`` class.

    Declares only the methods used by the hex editor PDF export. This
    avoids a direct ``fpdf`` import so the bridge does not require the
    optional fpdf2 dependency at type-check time.
    """

    def __init__(self, **kwargs: str) -> None:
        """Construct a new FPDF document.

        Args:
            **kwargs: Constructor keyword arguments (``orientation``,
                ``unit``, ``format``) forwarded to the underlying
                ``fpdf.FPDF`` constructor.
        """
        _ = (self, kwargs)

    def set_auto_page_break(self, *, auto: bool, margin: float = 0) -> None:
        """Enable or disable automatic page breaks.

        Args:
            auto: Whether to automatically page-break.
            margin: Bottom margin at which to break in user units.
        """
        _ = (self, auto, margin)

    def add_page(self) -> None:
        """Add a new page to the document."""
        _ = self

    def set_font(self, family: str, style: str = "", size: float = 0) -> None:
        """Set the current font family, style, and size.

        Args:
            family: Font family name.
            style: Font style (e.g. ``""``, ``"B"``).
            size: Font size in points.
        """
        _ = (self, family, style, size)

    def cell(
        self,
        w: float,
        h: float = 0,
        txt: str = "",
        border: int | str = 0,
        ln: int = 0,
        align: str = "",
        *,
        fill: bool = False,
        link: str = "",
        new_x: str = "RIGHT",
        new_y: str = "TOP",
    ) -> None:
        """Write a rectangular cell with optional text and border.

        Args:
            w: Cell width in user units.
            h: Cell height in user units.
            txt: Cell text content.
            border: Border specification.
            ln: Line break flag.
            align: Horizontal alignment.
            fill: Whether to fill the cell background.
            link: Optional link target.
            new_x: Cursor X advance directive.
            new_y: Cursor Y advance directive.
        """
        _ = (self, w, h, txt, border, ln, align, fill, link, new_x, new_y)

    def ln(self, h: float = 0) -> None:
        """Advance to the next line.

        Args:
            h: Line height in user units.
        """
        _ = (self, h)

    def set_fill_color(self, r: int, g: int = 0, b: int = 0) -> None:
        """Set the fill color used for cells with ``fill=True``.

        Args:
            r: Red component (0-255).
            g: Green component (0-255).
            b: Blue component (0-255).
        """
        _ = (self, r, g, b)

    def output(self, name: str = "", dest: str = "") -> bytes | bytearray | str | None:
        """Write the document to the given destination.

        Args:
            name: Output filename or path.
            dest: Destination mode.

        Returns:
            bytes | bytearray | str | None: Output bytes or path,
                depending on the destination mode.
        """
        _ = (self, name, dest)
        return None


_logger = get_logger(__name__)

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

_pefile_mod: Any = None
_pefile_available: bool = False
try:
    import pefile as _pefile_import

    _pefile_mod = _pefile_import
    _pefile_available = True
except ImportError as _exc:
    _logger.debug("pefile_unavailable", error=str(_exc))


_JAVA_SIGNED_BYTE_THRESHOLD = 0x7F
_PRINTABLE_MIN = 0x20
_PRINTABLE_MAX = 0x7E
_MIN_HEADER_SIZE = 4
_BYTE_MASK = 0xFF
_U16_MASK = 0xFFFF
_U32_MASK = 0xFFFFFFFF
_U64_MASK = 0xFFFFFFFFFFFFFFFF
_BITS_PER_BYTE = 8
_BIT_INDEX_MAX = 7
_ELF_CLASS_64 = 2
_ELF_DATA_LE = 1
_PE_LFANEW_OFFSET = 0x3C
_PE_CHECKSUM_RELATIVE = 64
_PE_COFF_HEADER_SIZE = 20
_DOS_HEADER_SIZE = 64
_PE_SECTION_ENTRY_SIZE = 40
_MAX_PE_SECTIONS = 96
_MAX_BOOKMARK_ENTRIES = 20
_MAX_EP_BYTES = 256
_MAX_BPS_DIFF_LEN = 256
_MIN_BPS_AHEAD_MATCH = 4
_CRC32_MASK = 0xFFFFFFFF
_BPS_CMD_SOURCE_READ = 0
_BPS_CMD_TARGET_READ = 1
_BPS_CMD_SOURCE_COPY = 2
_BPS_CMD_TARGET_COPY = 3
_BPS_MIN_PATCH_SIZE = 12
_UPS_MIN_PATCH_SIZE = 16
_WHITESPACE_BYTES = frozenset({0x09, 0x0A, 0x0D})
_PT_LOAD = 1
_MAX_ELF_SEGMENTS = 64
_NDB_MIN_FIELDS = 4
_HDB_MIN_FIELDS = 3

_ERR_NO_DOCUMENT: Final[str] = "no document open"
_ERR_NO_SELECTION: Final[str] = "no selection active"
_ERR_UNKNOWN_FORMAT: Final[str] = "unsupported output format"
_ERR_UNKNOWN_PATCH_FORMAT: Final[str] = "unsupported patch format"
_ERR_UNKNOWN_PATCH_MAGIC: Final[str] = "unrecognized patch magic"
_ERR_UNKNOWN_TRANSFORM: Final[str] = "unknown arithmetic transform"
_ERR_PATCH_EXPORT_UNSUPPORTED: Final[str] = "patch export not supported by backend"
_ERR_INVALID_IPS: Final[str] = "invalid IPS patch header"

_COPY_AS_FORMATS: Final[frozenset[str]] = frozenset(
    {
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
    },
)

ExportPatchFormat = Literal["ips", "ips32", "bps", "ups"]
_EXPORT_PATCH_FORMATS: Final[frozenset[str]] = frozenset(get_args(ExportPatchFormat))
_BPS_UPS_FORMATS: Final[frozenset[str]] = frozenset({"bps", "ups"})

_IPS_MAGIC: Final[bytes] = b"PATCH"
_IPS32_MAGIC: Final[bytes] = b"IPS32"
_BPS_MAGIC: Final[bytes] = b"BPS1"
_UPS_MAGIC: Final[bytes] = b"UPS1"
_IPS_MAGIC_LEN: Final[int] = 5


class HexEditorBridge(ToolBridgeBase):
    """Bridge for the built-in hex editor powered by Rust.

    Wraps the ``intellicrack_hexcore.HexDocument`` class to provide hex
    editing, searching, hashing, data inspection, template parsing, and
    binary diffing through the standard bridge interface. Instances own
    the active document slot, cursor and selection state, the
    runtime-availability flags for the hexcore, hexpat, interpreter, and
    pipeline extensions, the hexpat interpreter and pattern-registry
    caches, the optional shared state holder and tool-registry
    references, highlighting and display configuration, the transform
    node cache, and the advertised ``BridgeCapabilities``.
    """

    def __init__(self) -> None:
        """Initialize the HexEditorBridge instance."""
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
        self._color_mode: str = "none"
        self._alignment_grid_size: int = 0
        self._transform_node_cache: dict[str, Any] | None = None
        self._state_lock: threading.Lock = threading.Lock()
        self._capabilities = BridgeCapabilities(
            supports_static_analysis=True,
            supports_patching=True,
            supports_scripting=True,
            supported_architectures=["x86", "x86_64", "arm", "arm64"],
            supported_formats=["pe", "elf", "macho", "raw"],
        )
        _logger.info(
            "hex_editor_bridge_initialized",
            hexcore_available=self._hexcore_available,
            hexpat_available=self._hexpat_available,
            hexpat_interpreter_available=self._hexpat_interpreter_available,
            pipeline_available=self._pipeline_available,
        )

    def set_state_holder(self, state_holder: HexDocumentState) -> None:
        """Attach a shared state holder for bridge-GUI synchronization.

        Args:
            state_holder: The shared HexDocumentState instance.
        """
        _logger.info("set_state_holder_started")
        self.state_holder = state_holder

    def set_tool_registry(self, registry: ToolRegistry) -> None:
        """Set the tool registry for cross-bridge access.

        Args:
            registry: The ToolRegistry providing access to other bridges.
        """
        _logger.info("set_tool_registry_started")
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
                            description="Sandbox type ('windows' or 'qemu').",
                            required=False,
                            enum=["windows", "qemu"],
                            default="windows",
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
                            description="Sandbox type ('windows' or 'qemu').",
                            required=False,
                            enum=["windows", "qemu"],
                            default="windows",
                        ),
                        ToolParameter(
                            name="time_limit",
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
                    name="hex_editor.get_pe_sections",
                    description="Parse PE section headers from the open document and return them as dicts.",
                    parameters=[],
                    returns=(
                        "List of {name, virtual_address, virtual_size, raw_size, raw_offset, "
                        "characteristics} dicts, one per PE section. Empty list when the open "
                        "document is not a PE."
                    ),
                ),
                ToolFunction(
                    name="hex_editor.get_pe_imports",
                    description="Parse the PE import directory and return imports grouped by DLL.",
                    parameters=[],
                    returns=(
                        "List of {dll, function, address, ordinal} dicts, one entry per imported "
                        "symbol. Empty list when the open document is not a PE or has no imports."
                    ),
                ),
                ToolFunction(
                    name="hex_editor.get_pe_exports",
                    description="Parse the PE export directory and return exported symbols.",
                    parameters=[],
                    returns=(
                        "List of {name, address, ordinal} dicts, one entry per exported symbol. "
                        "Empty list when the open document is not a PE or has no exports."
                    ),
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
                    description="Export document patches as IPS, IPS32, BPS, or UPS.",
                    parameters=[
                        ToolParameter(
                            name="patch_format",
                            type="string",
                            description="Patch format.",
                            enum=["ips", "ips32", "bps", "ups"],
                        ),
                        ToolParameter(
                            name="original_path",
                            type="string",
                            description="Path to the original file (required for BPS/UPS).",
                            required=False,
                        ),
                    ],
                    returns="Base64-encoded patch data",
                ),
                ToolFunction(
                    name="hex_editor.import_patches",
                    description="Import and apply IPS/IPS32/BPS/UPS patches.",
                    parameters=[
                        ToolParameter(name="data_b64", type="string", description="Base64-encoded patch data."),
                        ToolParameter(
                            name="original_path",
                            type="string",
                            description="Path to the original file (required for BPS/UPS).",
                            required=False,
                        ),
                    ],
                    returns="Number of patches applied or dict with target_size",
                ),
                ToolFunction(
                    name="hex_editor.search_numeric",
                    description="Search for a numeric value in the document.",
                    parameters=[
                        ToolParameter(name="value", type="number", description="Value to search for."),
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
                        ToolParameter(
                            name="tolerance",
                            type="number",
                            description="Acceptable difference for float comparisons.",
                            required=False,
                            default=1e-6,
                        ),
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
                ToolFunction(
                    name="hex_editor.fill_block",
                    description="Fill a block with a repeating byte pattern.",
                    parameters=[
                        ToolParameter(name="offset", type="integer", description="Start offset."),
                        ToolParameter(name="length", type="integer", description="Number of bytes to fill."),
                        ToolParameter(name="pattern_hex", type="string", description="Hex pattern to repeat (e.g. '90' or 'DEADBEEF')."),
                    ],
                    returns="True if fill succeeded",
                ),
                ToolFunction(
                    name="hex_editor.copy_block",
                    description="Copy a block of bytes from one offset to another.",
                    parameters=[
                        ToolParameter(name="src_offset", type="integer", description="Source offset."),
                        ToolParameter(name="length", type="integer", description="Number of bytes."),
                        ToolParameter(name="dst_offset", type="integer", description="Destination offset."),
                    ],
                    returns="True if copy succeeded",
                ),
                ToolFunction(
                    name="hex_editor.move_block",
                    description="Move a block of bytes from one offset to another.",
                    parameters=[
                        ToolParameter(name="src_offset", type="integer", description="Source offset."),
                        ToolParameter(name="length", type="integer", description="Number of bytes."),
                        ToolParameter(name="dst_offset", type="integer", description="Destination offset."),
                    ],
                    returns="True if move succeeded",
                ),
                ToolFunction(
                    name="hex_editor.swap_blocks",
                    description="Swap two non-overlapping blocks of bytes.",
                    parameters=[
                        ToolParameter(name="offset_a", type="integer", description="Start of block A."),
                        ToolParameter(name="len_a", type="integer", description="Length of block A."),
                        ToolParameter(name="offset_b", type="integer", description="Start of block B."),
                        ToolParameter(name="len_b", type="integer", description="Length of block B."),
                    ],
                    returns="True if swap succeeded",
                ),
                ToolFunction(
                    name="hex_editor.apply_arithmetic_to_selection",
                    description="Apply a bitwise arithmetic operation to the current selection.",
                    parameters=[
                        ToolParameter(
                            name="operation",
                            type="string",
                            description="Operation name.",
                            enum=["xor", "and", "or", "not", "shl", "shr", "rol", "ror"],
                        ),
                        ToolParameter(
                            name="key_hex",
                            type="string",
                            description="Key/mask hex (ignored for NOT).",
                            required=False,
                            default="",
                        ),
                        ToolParameter(name="count", type="integer", description="Shift/rotate bit count.", required=False, default=1),
                    ],
                    returns="Dict with offset, length, operation",
                ),
                ToolFunction(
                    name="hex_editor.get_bit",
                    description="Get the value of a specific bit at an offset.",
                    parameters=[
                        ToolParameter(name="offset", type="integer", description="Byte offset."),
                        ToolParameter(name="bit_index", type="integer", description="Bit index (0=LSB, 7=MSB)."),
                    ],
                    returns="Boolean bit value",
                ),
                ToolFunction(
                    name="hex_editor.set_bit",
                    description="Set or clear a specific bit at an offset.",
                    parameters=[
                        ToolParameter(name="offset", type="integer", description="Byte offset."),
                        ToolParameter(name="bit_index", type="integer", description="Bit index (0=LSB, 7=MSB)."),
                        ToolParameter(name="value", type="boolean", description="True to set, False to clear."),
                    ],
                    returns="True if bit was set",
                ),
                ToolFunction(
                    name="hex_editor.toggle_bit",
                    description="Toggle a specific bit at an offset.",
                    parameters=[
                        ToolParameter(name="offset", type="integer", description="Byte offset."),
                        ToolParameter(name="bit_index", type="integer", description="Bit index (0=LSB, 7=MSB)."),
                    ],
                    returns="New boolean bit value after toggle",
                ),
                ToolFunction(
                    name="hex_editor.set_va_base",
                    description="Add a virtual address mapping for a file region.",
                    parameters=[
                        ToolParameter(name="file_offset", type="integer", description="File offset start."),
                        ToolParameter(name="virtual_address", type="integer", description="Virtual address corresponding to file_offset."),
                        ToolParameter(name="length", type="integer", description="Length of the mapped region."),
                    ],
                    returns="True if mapping was added",
                ),
                ToolFunction(
                    name="hex_editor.remove_va_mapping",
                    description="Remove a virtual address mapping by index.",
                    parameters=[
                        ToolParameter(name="index", type="integer", description="Mapping index."),
                    ],
                    returns="True if removed",
                ),
                ToolFunction(
                    name="hex_editor.list_va_mappings",
                    description="List all virtual address mappings.",
                    parameters=[],
                    returns="List of {file_offset, virtual_address, length} dicts",
                ),
                ToolFunction(
                    name="hex_editor.auto_detect_va_mappings",
                    description="Auto-detect VA mappings from PE/ELF headers.",
                    parameters=[],
                    returns="List of {file_offset, virtual_address, length} dicts",
                ),
                ToolFunction(
                    name="hex_editor.file_offset_to_va",
                    description="Convert a file offset to a virtual address.",
                    parameters=[
                        ToolParameter(name="offset", type="integer", description="File offset."),
                    ],
                    returns="Virtual address integer or null if not mapped",
                ),
                ToolFunction(
                    name="hex_editor.va_to_file_offset",
                    description="Convert a virtual address to a file offset.",
                    parameters=[
                        ToolParameter(name="va", type="integer", description="Virtual address."),
                    ],
                    returns="File offset integer or null if not mapped",
                ),
                ToolFunction(
                    name="hex_editor.get_strings",
                    description="Extract strings from the document.",
                    parameters=[
                        ToolParameter(name="min_length", type="integer", description="Minimum string length.", required=False, default=4),
                        ToolParameter(
                            name="encoding",
                            type="string",
                            description="Encoding filter.",
                            enum=["ascii+utf16", "ascii", "utf16"],
                            required=False,
                            default="ascii+utf16",
                        ),
                        ToolParameter(name="max_results", type="integer", description="Maximum results.", required=False, default=5000),
                    ],
                    returns="List of {offset, length, encoding, content} dicts",
                ),
                ToolFunction(
                    name="hex_editor.generate_structure_bookmarks",
                    description="Auto-detect PE/ELF structure and create colored bookmarks for headers and sections.",
                    parameters=[],
                    returns="List of bookmark dicts created",
                ),
                ToolFunction(
                    name="hex_editor.export_annotated_html",
                    description="Export hex view as annotated HTML with bookmarks and highlights.",
                    parameters=[
                        ToolParameter(name="start", type="integer", description="Start offset.", required=False, default=0),
                        ToolParameter(
                            name="end",
                            type="integer",
                            description="End offset (0 = entire document).",
                            required=False,
                            default=0,
                        ),
                        ToolParameter(name="bytes_per_row", type="integer", description="Bytes per row.", required=False, default=16),
                    ],
                    returns="HTML string",
                ),
                ToolFunction(
                    name="hex_editor.export_annotated_pdf",
                    description="Export hex view as annotated PDF with bookmarks and structure highlights.",
                    parameters=[
                        ToolParameter(
                            name="output_path",
                            type="string",
                            description="Filesystem path for the output PDF file.",
                            required=True,
                        ),
                        ToolParameter(name="start", type="integer", description="Start offset.", required=False, default=0),
                        ToolParameter(
                            name="end",
                            type="integer",
                            description="End offset (0 = entire document).",
                            required=False,
                            default=0,
                        ),
                        ToolParameter(name="bytes_per_row", type="integer", description="Bytes per row.", required=False, default=16),
                    ],
                    returns="Output file path",
                ),
                ToolFunction(
                    name="hex_editor.snap_to_alignment",
                    description="Snap the cursor to the nearest alignment boundary.",
                    parameters=[
                        ToolParameter(
                            name="alignment_size",
                            type="integer",
                            description="Alignment in bytes.",
                            required=False,
                            default=512,
                        ),
                    ],
                    returns="New cursor offset after snapping",
                ),
                ToolFunction(
                    name="hex_editor.set_alignment_grid",
                    description="Set the alignment grid size for visual display.",
                    parameters=[
                        ToolParameter(name="size", type="integer", description="Grid size in bytes (0 to disable)."),
                    ],
                    returns="True",
                ),
                ToolFunction(
                    name="hex_editor.verify_pe_checksum",
                    description="Verify the PE optional header checksum.",
                    parameters=[],
                    returns="Dict with stored, calculated, offset, valid",
                ),
                ToolFunction(
                    name="hex_editor.repair_pe_checksum",
                    description="Recalculate and write the correct PE checksum.",
                    parameters=[],
                    returns="Dict with old_checksum, new_checksum, offset",
                ),
                ToolFunction(
                    name="hex_editor.base_convert",
                    description="Convert a numeric value between bases and show all representations.",
                    parameters=[
                        ToolParameter(name="value", type="string", description="Value string (decimal, 0xHex, 0bBinary, 0oOctal)."),
                        ToolParameter(name="from_base", type="string", description="Source base hint.", required=False, default="auto"),
                    ],
                    returns="Dict with decimal, hex, octal, binary, int/uint widths, float representations",
                ),
                ToolFunction(
                    name="hex_editor.run_python_script",
                    description="Execute a Python script with access to the hex document API.",
                    parameters=[
                        ToolParameter(name="source", type="string", description="Python source code."),
                    ],
                    returns="Dict with output, error, variables",
                ),
                ToolFunction(
                    name="hex_editor.set_chunk_size",
                    description="Set the chunk size hint for large file I/O.",
                    parameters=[
                        ToolParameter(name="size_bytes", type="integer", description="Chunk size in bytes."),
                    ],
                    returns="True",
                ),
                ToolFunction(
                    name="hex_editor.get_memory_usage",
                    description="Get current document memory usage estimate.",
                    parameters=[],
                    returns="Dict with usage_bytes, chunk_size, memory_budget",
                ),
                ToolFunction(
                    name="hex_editor.set_memory_budget",
                    description="Set the memory budget hint for large file operations.",
                    parameters=[
                        ToolParameter(name="budget_bytes", type="integer", description="Memory budget in bytes."),
                    ],
                    returns="True",
                ),
                ToolFunction(
                    name="hex_editor.set_color_mode",
                    description="Set the byte color-mapping mode.",
                    parameters=[
                        ToolParameter(
                            name="mode",
                            type="string",
                            description="Color mode.",
                            enum=["none", "entropy", "byte_value", "template", "content_type"],
                        ),
                    ],
                    returns="True",
                ),
                ToolFunction(
                    name="hex_editor.get_color_mode",
                    description="Get the current byte color-mapping mode.",
                    parameters=[],
                    returns="Color mode string",
                ),
                ToolFunction(
                    name="hex_editor.scan_die_signatures",
                    description="Scan document against a DIE-style JSON signature database.",
                    parameters=[
                        ToolParameter(name="db_path", type="string", description="Path to the DIE JSON database file."),
                    ],
                    returns="List of {name, type, version, offset, details} dicts",
                ),
                ToolFunction(
                    name="hex_editor.scan_clamav_signatures",
                    description="Scan document against ClamAV .ndb or .hdb signature files.",
                    parameters=[
                        ToolParameter(name="db_path", type="string", description="Path to the .ndb or .hdb file."),
                    ],
                    returns="List of {name, type, version, offset, details} dicts",
                ),
                ToolFunction(
                    name="hex_editor.scan_custom_signatures",
                    description="Scan document against a custom JSON signature database.",
                    parameters=[
                        ToolParameter(name="sig_file", type="string", description="Path to the custom JSON signature file."),
                    ],
                    returns="List of {name, type, version, offset, details} dicts",
                ),
                ToolFunction(
                    name="hex_editor.export_patches_bps",
                    description="Export a BPS patch comparing the current document against original.",
                    parameters=[
                        ToolParameter(name="original_path", type="string", description="Path to the original unmodified file."),
                    ],
                    returns="Base64-encoded BPS patch data",
                ),
                ToolFunction(
                    name="hex_editor.import_patches_bps",
                    description="Import and apply a BPS patch.",
                    parameters=[
                        ToolParameter(name="patch_b64", type="string", description="Base64-encoded BPS patch data."),
                        ToolParameter(name="original_path", type="string", description="Path to the original source file."),
                    ],
                    returns="Dict with target_size",
                ),
                ToolFunction(
                    name="hex_editor.export_patches_ups",
                    description="Export a UPS patch comparing the current document against original.",
                    parameters=[
                        ToolParameter(name="original_path", type="string", description="Path to the original unmodified file."),
                    ],
                    returns="Base64-encoded UPS patch data",
                ),
                ToolFunction(
                    name="hex_editor.import_patches_ups",
                    description="Import and apply a UPS patch.",
                    parameters=[
                        ToolParameter(name="patch_b64", type="string", description="Base64-encoded UPS patch data."),
                        ToolParameter(name="original_path", type="string", description="Path to the original source file."),
                    ],
                    returns="Dict with target_size",
                ),
            ],
        )

    async def initialize(self, tool_path: Path | None = None) -> None:
        """Initialize the hex editor bridge.

        Args:
            tool_path: Unused for this bridge.
        """
        _logger.info("initialize_started", tool_path=str(tool_path) if tool_path else None)
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
        _logger.debug("is_available_checked", hexcore_available=self._hexcore_available)
        return self._hexcore_available

    async def shutdown(self) -> None:
        """Shutdown the hex editor bridge.

        Mirrors :meth:`close_file`: notify the shared
        ``HexDocumentState`` that the document is going away
        (``set_document(None, None)``) before dropping the local
        reference so downstream observers see a consistent transition,
        then resets cursor and selection and clears cached highlight
        rules.
        """
        if self.state_holder is not None:
            self.state_holder.set_document(None, None, source="bridge")
        with self._state_lock:
            self.document = None
            self._cursor_offset = 0
            self._selection = None
            self._highlight_rules.clear()
        _logger.info("hex_editor_shutdown")
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
            _logger.error("read_bytes_failed_no_document", offset=hex(offset), length=length)
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
            _logger.error("write_bytes_failed_no_document", offset=hex(offset))
            msg = "no document open"
            raise RuntimeError(msg)

        data = bytes.fromhex(data_hex.replace(" ", ""))
        _logger.info("bytes_write_started", offset=hex(offset), length=len(data))
        self.document.write_bytes(offset, data)
        _logger.info("bytes_written", offset=hex(offset), length=len(data))
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
            _logger.error("insert_bytes_failed_no_document", offset=hex(offset))
            msg = "no document open"
            raise RuntimeError(msg)

        data = bytes.fromhex(data_hex.replace(" ", ""))
        _logger.info("bytes_insert_started", offset=hex(offset), length=len(data))
        self.document.insert_bytes(offset, data)
        _logger.info("bytes_inserted", offset=hex(offset), length=len(data))
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
            _logger.error("delete_bytes_failed_no_document", offset=hex(offset), length=length)
            msg = "no document open"
            raise RuntimeError(msg)

        _logger.info("bytes_delete_started", offset=hex(offset), length=length)
        self.document.delete_bytes(offset, length)
        _logger.info("bytes_deleted", offset=hex(offset), length=length)
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
        _logger.debug("cursor_moved", offset=hex(offset))
        self._cursor_offset = offset
        if self.state_holder is not None:
            self.state_holder.set_cursor(offset, source="bridge")
        return True

    async def get_cursor_position(self) -> int:
        """Get the current cursor position.

        Returns:
            int: Current byte offset of the cursor.
        """
        _logger.debug("get_cursor_position_started", cursor_offset=hex(self._cursor_offset))
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
        _logger.debug("get_selection_started", has_selection=self._selection is not None)
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
            _logger.error("operation_failed_no_document_open")
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
            _logger.error("operation_failed_no_document_open")
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
            _logger.error("operation_failed_no_document_open")
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
            _logger.error("operation_failed_no_document_open")
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
            _logger.error("operation_failed_no_document_open")
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
            _logger.error("operation_failed_no_document_open")
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
            _logger.error("operation_failed_no_document_open")
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
            _logger.error("operation_failed_no_document_open")
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
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        _logger.info("template_applied", template=template_name, offset=hex(offset))
        result = self.document.apply_template(template_name, offset)
        if not isinstance(result, list):
            return []
        typed_list = cast("list[object]", result)
        return [cast("dict[str, Any]", entry) for entry in typed_list if isinstance(entry, dict)]

    async def list_templates(self) -> list[dict[str, str]]:
        """List all available struct templates.

        When no document is open the bridge constructs a throwaway
        ``HexDocument`` just to query the template registry. If that
        construction fails the method returns the sentinel empty list
        so callers can distinguish "backend unavailable" from "backend
        raised while listing", which is propagated to the caller.

        Returns:
            list[dict[str, str]]: List of dicts with name and
                description, or an empty list when the hexcore backend
                cannot be instantiated.
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
            _logger.error("operation_failed_no_document_open")
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
        _logger.info("compile_pattern_started", source_len=len(source))
        if not self._hexpat_available or _HexPatCompiler is None or _HexPatError is None:
            _logger.error("compile_pattern_failed_compiler_unavailable")
            msg = "hexpat_compiler not available"
            raise RuntimeError(msg)
        compiler = _HexPatCompiler()
        try:
            return compiler.compile(source)
        except _HexPatError as exc:
            _logger.exception("compile_pattern_syntax_error", source_line=exc.line, source_column=exc.column, error_message=exc.message)
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
            _logger.error("get_interpreter_failed_unavailable")
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
            _logger.error("get_pattern_registry_failed_unavailable")
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
            _logger.error("operation_failed_no_document_open")
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
            _logger.error("operation_failed_no_document_open")
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
            _logger.exception("hexpat_pattern_registry_unavailable")
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
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        if not self._hexpat_interpreter_available or _DataReader is None:
            return []

        try:
            registry = self._get_pattern_registry()
        except RuntimeError:
            _logger.exception("hexpat_pattern_registry_unavailable")
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
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        result: str = self.document.export_template_json(template_name)
        _logger.debug("template_exported", template_name=template_name)
        return result

    async def list_templates_detailed(self) -> list[dict[str, Any]]:
        """List all templates with detailed metadata.

        Mirrors the error contract of :meth:`list_templates`: the
        sentinel empty list is returned when the backend cannot be
        instantiated, while exceptions raised by the template handler
        itself (e.g. from ``doc.list_templates_detailed()``) propagate
        to the caller so failures surface explicitly.

        Returns:
            list[dict[str, Any]]: List of dicts with name, description,
                category, and field_count, or an empty list when the
                hexcore backend cannot be instantiated.
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
            _logger.error("compare_files_failed_hexcore_unavailable", path_a=path_a, path_b=path_b)
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
            ToolError: If ``fmt`` is not a recognized output format.
        """
        if self.document is None:
            _logger.error("copy_as_failed_no_document_open", fmt=fmt)
            msg = _ERR_NO_DOCUMENT
            raise RuntimeError(msg)

        if fmt not in _COPY_AS_FORMATS:
            _logger.error("copy_as_failed_unknown_format", fmt=fmt)
            msg = f"{_ERR_UNKNOWN_FORMAT}: {fmt!r} (supported: {sorted(_COPY_AS_FORMATS)})"
            raise ToolError(msg)

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
        rows: list[str] = ["| Offset | Hex | ASCII |", "| --- | --- | --- |"]
        for i, b in enumerate(data):
            hex_val = f"{b:02X}"
            ascii_val = chr(b) if _PRINTABLE_MIN <= b <= _PRINTABLE_MAX else "."
            rows.append(f"| {start + i:#010x} | {hex_val} | {ascii_val} |")
        return "\n".join(rows)

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
            _logger.error("operation_failed_no_document_open")
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
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        removed: bool = self.document.remove_bookmark(index)
        _logger.info("bookmark_removed", index=index, success=removed)
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
            _logger.error("operation_failed_no_document_open")
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
        _logger.info("save_as_started", path=path)
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
            _logger.error("operation_failed_no_document_open")
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
        _logger.debug("get_document_info_started", has_document=self.document is not None)
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
        sandbox_type: str = "windows",
    ) -> dict[str, Any]:
        """Save the current document into a sandbox environment.

        Creates a sandbox instance and copies the document into it at the
        given destination path.

        Args:
            dest_path: Destination path inside the sandbox.
            sandbox_type: Sandbox type ('windows' or 'qemu').

        Returns:
            dict[str, Any]: Dict with sandbox_path, status, and instance_id.

        Raises:
            RuntimeError: If no document is open or sandbox unavailable.
            TypeError: If sandbox bridge does not support create.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
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
            create_fn = getattr(sandbox_bridge, "create", None)
            if not callable(create_fn):
                msg = "sandbox bridge does not support create"
                raise TypeError(msg)

            raw_create: object
            if _inspect_mod.iscoroutinefunction(create_fn):
                raw_create = await create_fn(sandbox_type=sandbox_type)
            else:
                raw_create = await asyncio.to_thread(create_fn, sandbox_type=sandbox_type)
            create_result = cast("dict[str, Any]", raw_create)

            instance_id: str = str(create_result.get("instance_id", ""))

            copy_fn = getattr(sandbox_bridge, "copy_to", None)
            if callable(copy_fn):
                if _inspect_mod.iscoroutinefunction(copy_fn):
                    await copy_fn(instance_id=instance_id, source=file_path_str, dest=dest_path)
                else:
                    await asyncio.to_thread(
                        copy_fn,
                        instance_id=instance_id,
                        source=file_path_str,
                        dest=dest_path,
                    )
        finally:
            if tmp_path is not None:
                try:
                    await asyncio.to_thread(Path(tmp_path).unlink)
                except OSError:
                    _logger.warning("tmp_file_cleanup_failed", path=tmp_path, exc_info=True)

        _logger.info("saved_to_sandbox", dest=dest_path, sandbox_type=sandbox_type)
        return {"sandbox_path": dest_path, "status": "copied", "instance_id": instance_id}

    async def test_in_sandbox(
        self,
        args: str = "",
        sandbox_type: str = "windows",
        time_limit: int = 30,
    ) -> dict[str, Any]:
        """Execute the current document binary in a sandbox and return the report.

        Uses the sandbox bridge's ``run_binary`` method which handles
        instance creation, file copy, and execution end-to-end.

        Args:
            args: Command-line arguments for the binary.
            sandbox_type: Sandbox type ('windows' or 'qemu').
            time_limit: Execution timeout in seconds.

        Returns:
            dict[str, Any]: Dict with execution report including exit_code, stdout, stderr.

        Raises:
            RuntimeError: If no document is open or sandbox unavailable.
            TypeError: If sandbox bridge does not support run_binary.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        file_path_str = self.document.file_path()
        if file_path_str is None:
            msg = "document has no file path; save the document first"
            raise RuntimeError(msg)

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

        args_list = args.split() if args else None

        if _inspect_mod.iscoroutinefunction(run_fn):
            result = await run_fn(
                binary_path=file_path_str,
                args=args_list,
                sandbox_type=sandbox_type,
                time_limit=time_limit,
            )
        else:
            result = await asyncio.to_thread(
                run_fn,
                binary_path=file_path_str,
                args=args_list,
                sandbox_type=sandbox_type,
                time_limit=time_limit,
            )

        _logger.info(
            "sandbox_test_completed",
            binary_path=file_path_str,
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
            _logger.error("operation_failed_no_document_open")
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
            _logger.error("operation_failed_no_document_open")
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
            _logger.error("operation_failed_no_document_open")
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
            _logger.error("operation_failed_no_document_open")
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
            _logger.error("operation_failed_no_document_open")
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
            _logger.error("operation_failed_no_document_open")
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
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        if not _disasm_available or _HexDisassembler is None:
            _logger.error("disassemble_failed_disassembler_module_unavailable")
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

        binary_path = str(self._state.target_path) if self._state.target_path is not None else ""
        _logger.info("disassemble_started", binary_path=binary_path, offset=hex(offset), arch=arch, mode=mode, count=count)
        raw_instructions = disassembler.disassemble(data, offset, arch, mode, count)
        _logger.info(
            "disassembly_completed",
            binary_path=binary_path,
            offset=hex(offset),
            arch=arch,
            count=len(raw_instructions),
        )
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
            _logger.error("operation_failed_no_document_open")
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
            _logger.error("operation_failed_no_document_open")
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

    async def get_pe_sections(self) -> list[dict[str, Any]]:
        """Parse PE section headers for the currently open document.

        Reads the document bytes through the same path used by
        :meth:`_detect_pe_va_mappings` and walks the section table via the
        shared :mod:`intellicrack.bridges._pe_format` helpers. The result
        is shape-stable for both PE32 and PE32+ images and never hits
        :mod:`pefile` for the section walk so it does not require an
        on-disk file path.

        Returns:
            list[dict[str, Any]]: One dict per section with keys
                ``name``, ``virtual_address``, ``virtual_size``,
                ``raw_size``, ``raw_offset``, and ``characteristics``.
                Returns an empty list when the open document is not a
                PE, has a malformed header, or no document is open.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = _ERR_NO_DOCUMENT
            raise RuntimeError(msg)

        doc_len: int = self.document.length()
        if doc_len < _DOS_HEADER_SIZE:
            return []

        try:
            dos_header = self._read_doc_bytes(0, _DOS_HEADER_SIZE)
            if dos_header[:2] != b"MZ":
                return []

            e_lfanew = read_dos_e_lfanew(dos_header)
            if self._read_doc_bytes(e_lfanew, 4) != b"PE\x00\x00":
                return []

            coff_header = self._read_doc_bytes(e_lfanew + 4, _PE_COFF_HEADER_SIZE)
            _machine, num_sections, opt_header_size, _characteristics = unpack_coff_header(coff_header, 0)
            section_table_offset = e_lfanew + 4 + _PE_COFF_HEADER_SIZE + opt_header_size
            count = min(num_sections, _MAX_PE_SECTIONS)
            if count <= 0:
                return []

            section_bytes = self._read_doc_bytes(section_table_offset, count * _PE_SECTION_ENTRY_SIZE)
            sections: list[dict[str, Any]] = [
                {
                    "name": section["name"],
                    "virtual_address": section["virtual_address"],
                    "virtual_size": section["virtual_size"],
                    "raw_size": section["raw_size"],
                    "raw_offset": section["raw_offset"],
                    "characteristics": section["characteristics"],
                }
                for section in iterate_section_headers(section_bytes, 0, count)
            ]
        except (struct.error, RuntimeError, OSError) as exc:
            _logger.warning("get_pe_sections_failed", error=str(exc))
            return []
        else:
            _logger.debug("get_pe_sections_completed", count=len(sections))
            return sections

    async def get_pe_imports(self) -> list[dict[str, Any]]:
        """Parse the PE import directory and return imports grouped by DLL.

        Loads the document bytes into memory, parses them with
        :mod:`pefile`, and walks ``DIRECTORY_ENTRY_IMPORT``. The bridge
        reads from the open ``HexDocument`` rather than the on-disk
        path so it works for documents that were opened from a process
        memory region or modified in place.

        Returns:
            list[dict[str, Any]]: One dict per imported symbol with
                keys ``dll`` (DLL name as a string), ``function``
                (resolved name or ``Ordinal N``), ``address`` (IAT slot
                address as an integer or 0 when unresolved), and
                ``ordinal`` (integer ordinal or 0 when name-imported).
                Returns an empty list when the open document is not a
                PE, has no import directory, or pefile is not
                installed.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = _ERR_NO_DOCUMENT
            raise RuntimeError(msg)

        if not _pefile_available or _pefile_mod is None:
            _logger.warning("get_pe_imports_failed_pefile_unavailable")
            return []

        data = self._read_all_doc_bytes()
        if len(data) < _MIN_HEADER_SIZE or data[:2] != b"MZ":
            return []

        try:
            pe = _pefile_mod.PE(data=data, fast_load=True)
        except (AttributeError, ValueError, OSError) as exc:
            _logger.warning("get_pe_imports_failed_parse", error=str(exc))
            return []

        results: list[dict[str, Any]] = []
        try:
            dir_entry: dict[str, int] = getattr(_pefile_mod, "DIRECTORY_ENTRY", {})
            pe.parse_data_directories(directories=[dir_entry.get("IMAGE_DIRECTORY_ENTRY_IMPORT", 1)])
            import_dir: Any = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None)
            if import_dir is not None:
                for entry in import_dir:
                    dll_bytes: Any = getattr(entry, "dll", None)
                    dll_name = dll_bytes.decode("utf-8", errors="replace") if dll_bytes else "unknown"
                    raw_imports: Any = getattr(entry, "imports", None)
                    imports_list: list[Any] = list(raw_imports) if raw_imports is not None else []
                    for imp in imports_list:
                        name_bytes: Any = getattr(imp, "name", None)
                        ordinal_val: int = int(getattr(imp, "ordinal", 0) or 0)
                        function_name = name_bytes.decode("utf-8", errors="replace") if name_bytes else f"Ordinal {ordinal_val}"
                        address_val: int = int(getattr(imp, "address", 0) or 0)
                        results.append(
                            {
                                "dll": dll_name,
                                "function": function_name,
                                "address": address_val,
                                "ordinal": ordinal_val,
                            },
                        )
        except (AttributeError, ValueError) as exc:
            _logger.warning("get_pe_imports_failed_walk", error=str(exc))
            results = []
        finally:
            pe.close()

        _logger.debug("get_pe_imports_completed", count=len(results))
        return results

    async def get_pe_exports(self) -> list[dict[str, Any]]:
        """Parse the PE export directory and return exported symbols.

        Loads the document bytes into memory, parses them with
        :mod:`pefile`, and walks ``DIRECTORY_ENTRY_EXPORT``. The bridge
        reads from the open ``HexDocument`` rather than the on-disk
        path so it works for documents that were opened from a process
        memory region or modified in place.

        Returns:
            list[dict[str, Any]]: One dict per exported symbol with
                keys ``name`` (resolved symbol name or ``Ordinal N``),
                ``address`` (RVA as an integer or 0 when unresolved),
                and ``ordinal`` (integer ordinal). Returns an empty
                list when the open document is not a PE, has no export
                directory, or pefile is not installed.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = _ERR_NO_DOCUMENT
            raise RuntimeError(msg)

        if not _pefile_available or _pefile_mod is None:
            _logger.warning("get_pe_exports_failed_pefile_unavailable")
            return []

        data = self._read_all_doc_bytes()
        if len(data) < _MIN_HEADER_SIZE or data[:2] != b"MZ":
            return []

        try:
            pe = _pefile_mod.PE(data=data, fast_load=True)
        except (AttributeError, ValueError, OSError) as exc:
            _logger.warning("get_pe_exports_failed_parse", error=str(exc))
            return []

        results: list[dict[str, Any]] = []
        try:
            dir_entry: dict[str, int] = getattr(_pefile_mod, "DIRECTORY_ENTRY", {})
            pe.parse_data_directories(directories=[dir_entry.get("IMAGE_DIRECTORY_ENTRY_EXPORT", 0)])
            export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
            if export_dir is not None:
                raw_symbols: Any = getattr(export_dir, "symbols", None)
                symbols: list[Any] = list(raw_symbols) if raw_symbols is not None else []
                for exp in symbols:
                    name_bytes: Any = getattr(exp, "name", None)
                    ordinal_val: int = int(getattr(exp, "ordinal", 0) or 0)
                    name_str = name_bytes.decode("utf-8", errors="replace") if name_bytes else f"Ordinal {ordinal_val}"
                    address_val: int = int(getattr(exp, "address", 0) or 0)
                    results.append(
                        {
                            "name": name_str,
                            "address": address_val,
                            "ordinal": ordinal_val,
                        },
                    )
        except (AttributeError, ValueError) as exc:
            _logger.warning("get_pe_exports_failed_walk", error=str(exc))
            results = []
        finally:
            pe.close()

        _logger.debug("get_pe_exports_completed", count=len(results))
        return results

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
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        raw_params = cast("dict[str, Any]", json.loads(params_json))
        params: dict[str, Any] = {}
        for k, v in raw_params.items():
            if isinstance(v, str):
                try:
                    params[k] = bytes.fromhex(v)
                except ValueError:
                    _logger.debug("transform_param_not_hex", param_key=k, exc_info=True)
                    params[k] = v
            else:
                params[k] = v

        if not hasattr(self.document, "transform_data"):
            _logger.error("transform_failed_backend_unsupported")
            msg = "backend does not support transform_data"
            raise RuntimeError(msg)
        result = self.document.transform_data(name, offset, length, params)
        if isinstance(result, bytes):
            data = result
        elif isinstance(result, bytearray) or not isinstance(result, list):
            data = bytes(result)
        else:
            data = bytes(cast("list[int]", result))
        _logger.info("transform_applied", transform_name=name, offset=hex(offset), length=length)
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
            _logger.error("operation_failed_no_document_open")
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
        _logger.info("pipeline_applied", steps=len(steps), offset=hex(offset), length=length)
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
            _logger.error("operation_failed_no_document_open")
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
            _logger.error("operation_failed_no_document_open")
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
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        if hasattr(self.document, "compute_hash_custom_crc"):
            result: str = self.document.compute_hash_custom_crc((start, end), poly, init, width, (refin, refout), xorout)
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
            """Reflect the low ``bits`` of ``val`` around its centre bit.

            Implements the bitwise reflection used by CRC algorithms that
            specify ``refin`` or ``refout`` to invert the bit order of
            each byte or the final remainder.

            Args:
                val: Input value to be reflected.
                bits: Number of low bits to consider during reflection.

            Returns:
                int: Value with its low ``bits`` bits reversed.
            """
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
        _logger.debug("custom_crc_computed", width=width, result=hex(crc), hex_width=hex_width)
        return f"{crc:0{hex_width}X}"

    async def export_patches(self, patch_format: str = "ips", original_path: str | None = None) -> str:
        """Export document patches in the requested patch format.

        Dispatches on ``patch_format``:

        * ``"ips"`` / ``"ips32"`` use the document's native IPS export
          when available, falling back to a Python builder.
        * ``"bps"`` / ``"ups"`` are routed to :meth:`export_patches_bps`
          / :meth:`export_patches_ups`, which require ``original_path``
          to point at the unmodified source file used for the diff.

        Args:
            patch_format: Patch format name (``"ips"``, ``"ips32"``,
                ``"bps"``, or ``"ups"``).
            original_path: Path to the original unmodified file. Required
                when ``patch_format`` is ``"bps"`` or ``"ups"``; ignored
                for IPS/IPS32.

        Returns:
            str: Base64-encoded patch data.

        Raises:
            RuntimeError: If no document is open.
            ToolError: If ``patch_format`` is not a recognized format,
                the current backend cannot export the requested format,
                or BPS/UPS were requested without an ``original_path``.
        """
        _logger.info("export_patches_started", patch_format=patch_format, has_original_path=original_path is not None)
        if self.document is None:
            _logger.error("export_patches_failed_no_document_open", patch_format=patch_format)
            msg = _ERR_NO_DOCUMENT
            raise RuntimeError(msg)

        normalized = patch_format.lower()
        if normalized not in _EXPORT_PATCH_FORMATS:
            _logger.error("export_patches_failed_unknown_format", patch_format=patch_format)
            msg = f"{_ERR_UNKNOWN_PATCH_FORMAT}: {patch_format!r} (supported: {sorted(_EXPORT_PATCH_FORMATS)})"
            raise ToolError(msg)
        if normalized in _BPS_UPS_FORMATS:
            if original_path is None:
                _logger.error("export_patches_failed_missing_original_path", patch_format=normalized)
                msg = f"patch format {normalized!r} requires original_path"
                raise ToolError(msg)
            if normalized == "bps":
                return await self.export_patches_bps(original_path)
            return await self.export_patches_ups(original_path)

        raw: bytes
        if normalized == "ips32" and hasattr(self.document, "export_patches_ips32"):
            raw = self.document.export_patches_ips32()
        elif normalized == "ips" and hasattr(self.document, "export_patches_ips"):
            raw = self.document.export_patches_ips()
        elif hasattr(self.document, "get_patches"):
            patches: list[tuple[int, bytes]] = self.document.get_patches()
            raw = self._build_ips_from_patches(patches, ips32=(normalized == "ips32"))
        else:
            _logger.error("export_patches_failed_unsupported_format", patch_format=normalized)
            msg = f"{_ERR_PATCH_EXPORT_UNSUPPORTED}: {normalized!r}"
            raise ToolError(msg)

        _logger.info("patches_exported", patch_format=normalized, size=len(raw))
        return base64.b64encode(raw).decode("ascii")

    async def import_patches(self, data_b64: str, original_path: str | None = None) -> int:
        """Import and apply a patch blob, dispatching by magic bytes.

        The first bytes of the decoded payload are inspected to select
        the patch format:

        * ``PATCH`` -> IPS / IPS with RLE runs
        * ``IPS32`` -> IPS32 (32-bit offsets)
        * ``BPS1``  -> BPS
        * ``UPS1``  -> UPS

        BPS and UPS reconstruct the target from a separate source file.
        When ``original_path`` is provided that file's bytes are used as
        the source; otherwise the current document contents are used,
        which only works when the document already matches the source
        referenced by the patch.

        Args:
            data_b64: Base64-encoded patch data.
            original_path: Optional path to the unmodified source file
                used as the input for BPS/UPS reconstruction. Ignored
                for IPS/IPS32 formats.

        Returns:
            int: Number of patch records applied. For BPS/UPS this is
                ``1`` when the patch is successfully applied.

        Raises:
            RuntimeError: If no document is open.
            ToolError: If the magic bytes are not recognized or the
                patch is malformed.
        """
        _logger.info("import_patches_started", payload_size=len(data_b64), has_original_path=original_path is not None)
        if self.document is None:
            _logger.error("import_patches_failed_no_document_open")
            msg = _ERR_NO_DOCUMENT
            raise RuntimeError(msg)

        raw = base64.b64decode(data_b64)
        if len(raw) < _MIN_HEADER_SIZE:
            _logger.error("import_patches_failed_payload_too_short", payload_size=len(raw))
            msg = f"{_ERR_UNKNOWN_PATCH_MAGIC}: payload shorter than {_MIN_HEADER_SIZE} bytes"
            raise ToolError(msg)

        magic4 = raw[:_MIN_HEADER_SIZE]
        magic5 = raw[:_IPS_MAGIC_LEN] if len(raw) >= _IPS_MAGIC_LEN else b""

        count: int
        if magic5 in {_IPS_MAGIC, _IPS32_MAGIC}:
            if hasattr(self.document, "import_patches_ips"):
                try:
                    count = self.document.import_patches_ips(raw)
                except (RuntimeError, ValueError, OSError) as exc:
                    _logger.exception("import_patches_ips_native_failed")
                    msg = f"{_ERR_INVALID_IPS}: {exc}"
                    raise ToolError(msg) from exc
            else:
                try:
                    count = self._apply_ips_patches(raw)
                except (struct.error, ValueError, RuntimeError) as exc:
                    _logger.exception("import_patches_ips_python_failed")
                    msg = f"{_ERR_INVALID_IPS}: {exc}"
                    raise ToolError(msg) from exc
        elif magic4 == _BPS_MAGIC:
            source = await self._resolve_patch_source(original_path)
            try:
                target = self._apply_bps_patch(raw, source)
            except (struct.error, ValueError, IndexError) as exc:
                _logger.exception("import_patches_bps_failed")
                msg = f"invalid BPS patch: {exc}"
                raise ToolError(msg) from exc
            _logger.info("bps_patch_write_started", target_size=len(target))
            self.document.write_bytes(0, target)
            _logger.info("file_written", path="document", size=len(target), patch_format="bps")
            count = 1
        elif magic4 == _UPS_MAGIC:
            source = await self._resolve_patch_source(original_path)
            try:
                target = self._apply_ups_patch(raw, source)
            except (struct.error, ValueError, IndexError) as exc:
                _logger.exception("import_patches_ups_failed")
                msg = f"invalid UPS patch: {exc}"
                raise ToolError(msg) from exc
            _logger.info("ups_patch_write_started", target_size=len(target))
            self.document.write_bytes(0, target)
            _logger.info("file_written", path="document", size=len(target), patch_format="ups")
            count = 1
        else:
            head_hex = raw[: min(len(raw), _IPS_MAGIC_LEN)].hex()
            _logger.error("import_patches_failed_unknown_magic", head_hex=head_hex)
            msg = f"{_ERR_UNKNOWN_PATCH_MAGIC}: 0x{head_hex}"
            raise ToolError(msg)

        _logger.info("patches_imported", count=count)
        if count > 0 and self.state_holder is not None:
            doc_len: int = self.document.length()
            self.state_holder.notify_data_modified(0, doc_len, source="bridge")
        return count

    async def _resolve_patch_source(self, original_path: str | None) -> bytes:
        """Resolve the source bytes used as the BPS/UPS reconstruction input.

        Args:
            original_path: Optional path to the unmodified source file.
                When provided the file bytes are returned; when ``None``
                the current document bytes are returned.

        Returns:
            bytes: Source bytes the BPS/UPS engine should treat as the
            patch input.
        """
        if original_path is None:
            return self._read_all_doc_bytes()
        return await asyncio.to_thread(Path(original_path).read_bytes)

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

        Supports the IPS run-length encoding (RLE) extension: a record
        whose ``size`` field is 0 is followed by a 2-byte run length
        and a single fill byte, which expands to ``run_length`` copies
        of the fill byte at ``offset``.

        Args:
            raw: Raw IPS or IPS32 binary data.

        Returns:
            int: Number of patch records applied.

        Raises:
            RuntimeError: If the header is invalid.
        """
        pos = 0
        if raw[:_IPS_MAGIC_LEN] == _IPS32_MAGIC:
            ips32 = True
            pos = _IPS_MAGIC_LEN
            eof_marker = b"EEOF"
        elif raw[:_IPS_MAGIC_LEN] == _IPS_MAGIC:
            ips32 = False
            pos = _IPS_MAGIC_LEN
            eof_marker = b"EOF"
        else:
            _logger.error("apply_ips_patches_failed_invalid_header", magic_hex=raw[:_IPS_MAGIC_LEN].hex())
            msg = _ERR_INVALID_IPS
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
            if size == 0:
                if pos + 3 > len(raw):
                    break
                run_length = struct.unpack(">H", raw[pos : pos + 2])[0]
                fill_value = raw[pos + 2]
                pos += 3
                patch_data = bytes([fill_value]) * run_length
            else:
                if pos + size > len(raw):
                    break
                patch_data = raw[pos : pos + size]
                pos += size
            if self.document is not None:
                _logger.info("ips_patch_record_write", offset=hex(offset), length=len(patch_data))
                self.document.write_bytes(offset, patch_data)
            count += 1
        return count

    async def search_numeric(
        self,
        value: float,
        size: int = 4,
        value_type: str = "uint",
        endianness: str = "little",
        alignment: int = 1,
        max_results: int = 100,
        tolerance: float = 1e-6,
    ) -> list[dict[str, int]]:
        """Search for a numeric value in the document.

        Always dispatches to the native ``intellicrack_hexcore`` Rust
        implementation (``search_numeric_float`` for floats, otherwise
        ``search_numeric``). The Rust extension is built into the
        project and ``open_file`` rejects up-front when it cannot be
        loaded, so any document held by this bridge is guaranteed to
        expose the native search APIs and no Python fallback is needed.

        Args:
            value: Numeric value to search for.
            size: Byte size of the value: 1, 2, 4, or 8.
            value_type: Value type interpretation: "uint", "int", or "float".
            endianness: Byte order: "little" or "big".
            alignment: Search step alignment in bytes.
            max_results: Maximum number of results to return.
            tolerance: Acceptable difference for float comparisons.

        Returns:
            list[dict[str, int]]: List of dicts with offset and length.

        Raises:
            RuntimeError: If no document is open or the document does
                not expose the native search APIs.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        big_endian = endianness == "big"
        if value_type == "float":
            if not hasattr(self.document, "search_numeric_float"):
                msg = "document backend does not expose search_numeric_float"
                raise RuntimeError(msg)
            results = self.document.search_numeric_float(value, size, big_endian, tolerance, alignment, max_results)
            _logger.debug("search_numeric_float_completed", matches=len(results))
            return [{"offset": r[0], "length": r[1]} for r in results]

        if not hasattr(self.document, "search_numeric"):
            msg = "document backend does not expose search_numeric"
            raise RuntimeError(msg)
        results = self.document.search_numeric(value, size, value_type == "int", big_endian, alignment, max_results)
        _logger.debug("search_numeric_completed", matches=len(results))
        return [{"offset": r[0], "length": r[1]} for r in results]

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
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        if hasattr(self.document, "search_numeric_range"):
            results = self.document.search_numeric_range(
                (min_val, max_val),
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
        step = max(alignment, 1)
        pos = 0
        while pos <= doc_len - size and len(matches) < max_results:
            read_len = min(65536, doc_len - pos)
            raw = self.document.read(pos, read_len)
            chunk = raw if isinstance(raw, bytes) else bytes(raw)
            start_rem = pos % step
            idx = 0 if start_rem == 0 else step - start_rem
            while idx <= len(chunk) - size and len(matches) < max_results:
                try:
                    (val,) = struct.unpack_from(fmt, chunk, idx)
                except struct.error:
                    _logger.debug("search_numeric_range_unpack_failed", offset=pos + idx, fmt=fmt, exc_info=True)
                    idx += step
                    continue
                if min_val <= val <= max_val:
                    matches.append({"offset": pos + idx, "length": size})
                idx += step
            advance = read_len - (size - 1)
            if advance <= 0:
                break
            pos += advance

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
            _logger.error("build_numeric_format_invalid_size", size=size)
            msg = f"numeric size must be 1, 2, 4, or 8, got {size}"
            raise ValueError(msg)
        endian_char = ">" if big_endian else "<"
        fmt_char = size_chars[size] if value_type == "int" else size_chars[size].upper()
        return endian_char + fmt_char

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
        _logger.info("highlight_rule_removed", rule_id=rule_id)
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
        _logger.debug("get_display_mode_started", mode=self._display_mode)
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
            _logger.error("list_process_regions_failed_hexcore_unavailable", pid=pid)
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
            _logger.error("open_process_memory_failed_hexcore_unavailable", pid=pid, address=hex(address), size=size)
            msg = "hexcore native module not available"
            raise RuntimeError(msg)

        self.document = _hexcore_mod.HexDocument.from_process_memory(pid, address, size)
        self._cursor_offset = 0
        self._selection = None
        self._state.binary_loaded = True
        _logger.info("process_memory_opened", pid=pid, address=hex(address), size=size)

        if self.state_holder is not None:
            self.state_holder.set_document(self.document, None, source="bridge")

        doc = self.document
        doc_length: int = doc.length() if doc is not None else size
        return {"pid": pid, "address": address, "size": size, "document_length": doc_length}

    def _read_doc_bytes(self, offset: int, length: int) -> bytes:
        """Read bytes from the document, handling all return types.

        Args:
            offset: Byte offset to read from.
            length: Number of bytes to read.

        Returns:
            bytes: The read data.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)
        raw: object = self.document.read(offset, length)
        if isinstance(raw, bytes):
            return raw
        if isinstance(raw, bytearray):
            return bytes(raw)
        if isinstance(raw, list):
            return bytes(cast("list[int]", raw))
        return bytes(cast("bytearray", raw))

    def _read_all_doc_bytes(self) -> bytes:
        """Read the entire document contents.

        Returns:
            bytes: Full document data.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)
        doc_len: int = self.document.length()
        return self._read_doc_bytes(0, doc_len)

    async def fill_block(self, offset: int, length: int, pattern_hex: str) -> bool:
        """Fill a block with a repeating byte pattern.

        Args:
            offset: Start offset.
            length: Number of bytes to fill.
            pattern_hex: Hex pattern to repeat (e.g. '90' or 'DEADBEEF').

        Returns:
            bool: True if fill succeeded.

        Raises:
            RuntimeError: If no document is open.
            ValueError: If pattern_hex is empty.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)
        pattern = bytes.fromhex(pattern_hex.replace(" ", ""))
        if not pattern:
            msg = "pattern must not be empty"
            raise ValueError(msg)

        if hasattr(self.document, "fill_block"):
            self.document.fill_block(offset, length, list(pattern))
        else:
            fill_data = bytes(islice(cycle(pattern), length))
            _logger.info("file_written", path="document", offset=hex(offset), size=len(fill_data), op="fill_block")
            self.document.write_bytes(offset, fill_data)

        _logger.info("fill_block_completed", offset=hex(offset), length=length, pattern_len=len(pattern))
        if self.state_holder is not None:
            self.state_holder.notify_data_modified(offset, length, source="bridge")
        return True

    async def copy_block(self, src_offset: int, length: int, dst_offset: int) -> bool:
        """Copy a block of bytes from one offset to another.

        Args:
            src_offset: Source offset.
            length: Number of bytes to copy.
            dst_offset: Destination offset.

        Returns:
            bool: True if copy succeeded.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        if hasattr(self.document, "copy_block"):
            self.document.copy_block(src_offset, length, dst_offset)
        else:
            data = self._read_doc_bytes(src_offset, length)
            _logger.info("file_written", path="document", offset=hex(dst_offset), size=len(data), op="copy_block")
            self.document.write_bytes(dst_offset, data)

        _logger.info("copy_block_completed", src=hex(src_offset), dst=hex(dst_offset), length=length)
        if self.state_holder is not None:
            self.state_holder.notify_data_modified(dst_offset, length, source="bridge")
        return True

    async def move_block(self, src_offset: int, length: int, dst_offset: int) -> bool:
        """Move a block of bytes from one offset to another.

        Args:
            src_offset: Source offset.
            length: Number of bytes to move.
            dst_offset: Destination offset.

        Returns:
            bool: True if move succeeded.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        if hasattr(self.document, "move_block"):
            self.document.move_block(src_offset, length, dst_offset)
        else:
            data = self._read_doc_bytes(src_offset, length)
            _logger.info("file_written", path="document", offset=hex(src_offset), size=length, op="move_block_clear_src")
            self.document.write_bytes(src_offset, bytes(length))
            _logger.info("file_written", path="document", offset=hex(dst_offset), size=len(data), op="move_block_write_dst")
            self.document.write_bytes(dst_offset, data)

        _logger.info("move_block_completed", src=hex(src_offset), dst=hex(dst_offset), length=length)
        if self.state_holder is not None:
            doc_len: int = self.document.length()
            self.state_holder.notify_data_modified(0, doc_len, source="bridge")
        return True

    async def swap_blocks(
        self,
        offset_a: int,
        len_a: int,
        offset_b: int,
        len_b: int,
    ) -> bool:
        """Swap two non-overlapping blocks of bytes.

        Audit-1 F-0002: ``len_a`` must equal ``len_b``. Mismatched lengths
        cannot be swapped without zero-padding or truncating one side, which
        silently corrupts data; the bridge rejects the call with
        ``ValueError`` instead of producing nonsense output.

        Args:
            offset_a: Start of block A.
            len_a: Length of block A.
            offset_b: Start of block B.
            len_b: Length of block B.

        Returns:
            bool: True if swap succeeded.

        Raises:
            RuntimeError: If no document is open.
            ValueError: If blocks overlap or have unequal lengths.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        if len_a != len_b:
            _logger.error(
                "swap_blocks_failed_unequal_lengths",
                offset_a=hex(offset_a),
                offset_b=hex(offset_b),
                len_a=len_a,
                len_b=len_b,
            )
            msg = f"swap_blocks requires equal-length blocks; got len_a={len_a}, len_b={len_b}"
            raise ValueError(msg)

        end_a = offset_a + len_a
        end_b = offset_b + len_b
        if offset_a < end_b and offset_b < end_a:
            _logger.error("swap_blocks_failed_overlap", offset_a=hex(offset_a), offset_b=hex(offset_b), len_a=len_a, len_b=len_b)
            msg = "blocks overlap"
            raise ValueError(msg)

        if hasattr(self.document, "swap_blocks"):
            self.document.swap_blocks(offset_a, len_a, offset_b, len_b)
        else:
            data_a = self._read_doc_bytes(offset_a, len_a)
            data_b = self._read_doc_bytes(offset_b, len_b)
            _logger.info("file_written", path="document", offset=hex(offset_a), size=len(data_b), op="swap_blocks_a")
            self.document.write_bytes(offset_a, data_b)
            _logger.info("file_written", path="document", offset=hex(offset_b), size=len(data_a), op="swap_blocks_b")
            self.document.write_bytes(offset_b, data_a)

        _logger.info("swap_blocks_completed", a=hex(offset_a), b=hex(offset_b))
        if self.state_holder is not None:
            doc_len: int = self.document.length()
            self.state_holder.notify_data_modified(0, doc_len, source="bridge")
        return True

    async def apply_arithmetic_to_selection(
        self,
        operation: str,
        key_hex: str = "",
        count: int = 1,
    ) -> dict[str, Any]:
        """Apply a bitwise arithmetic operation to the current selection.

        The supported operations and their native Rust backend
        transform names are defined in the local ``transform_map``.
        Unknown ``operation`` values are rejected up front with a
        :class:`ToolError` rather than silently producing identity
        output.

        Args:
            operation: One of xor, and, or, not, shl, shr, rol, ror.
            key_hex: Key/mask as hex string (ignored for NOT).
            count: Bit count for shift/rotate operations.

        Returns:
            dict[str, Any]: Dict with offset, length, and operation.

        Raises:
            RuntimeError: If no document is open or no selection.
            ToolError: If ``operation`` is not a supported transform
                name.
        """
        if self.document is None:
            _logger.error("apply_arithmetic_failed_no_document_open", operation=operation)
            msg = _ERR_NO_DOCUMENT
            raise RuntimeError(msg)
        if self._selection is None:
            _logger.error("apply_arithmetic_failed_no_selection", operation=operation)
            msg = _ERR_NO_SELECTION
            raise RuntimeError(msg)

        transform_map: dict[str, str] = {
            "xor": "xor_repeating",
            "and": "mask_and",
            "or": "mask_or",
            "not": "bit_invert",
            "shl": "bit_shift_left",
            "shr": "bit_shift_right",
            "rol": "bit_rotate_left",
            "ror": "bit_rotate_right",
        }
        if operation not in transform_map:
            _logger.error("apply_arithmetic_failed_unknown_operation", operation=operation)
            msg = f"{_ERR_UNKNOWN_TRANSFORM}: {operation!r} (supported: {sorted(transform_map)})"
            raise ToolError(msg)

        start, end = self._selection
        length = end - start + 1
        data = bytearray(self._read_doc_bytes(start, length))
        key = bytes.fromhex(key_hex.replace(" ", "")) if key_hex else b""

        used_native = False
        if hasattr(self.document, "transform_data"):
            params: dict[str, Any] = {}
            if operation in {"xor", "and", "or"} and key:
                params["key"] = key
            if operation in {"shl", "shr", "rol", "ror"}:
                params["count"] = bytes([count & 0xFF])
            try:
                result_raw = self.document.transform_data(transform_map[operation], start, length, params)
                if isinstance(result_raw, bytes):
                    result_data = result_raw
                elif isinstance(result_raw, list):
                    result_data = bytes(cast("list[int]", result_raw))
                else:
                    result_data = bytes(result_raw)
                _logger.info("file_written", path="document", offset=hex(start), size=len(result_data), op=operation)
                self.document.write_bytes(start, result_data)
                used_native = True
            except (TypeError, ValueError, RuntimeError) as exc:
                _logger.warning(
                    "native_transform_failed",
                    operation=operation,
                    error=str(exc),
                    exc_info=True,
                )

        if not used_native:
            result_data = bytes(self._apply_arithmetic_fallback(data, operation, key, count))
            _logger.info("file_written", path="document", offset=hex(start), size=len(result_data), op=operation)
            self.document.write_bytes(start, result_data)

        _logger.info("arithmetic_applied", operation=operation, offset=hex(start), length=length)
        if self.state_holder is not None:
            self.state_holder.notify_data_modified(start, length, source="bridge")
        return {"offset": start, "length": length, "operation": operation}

    @staticmethod
    def _apply_arithmetic_fallback(
        data: bytearray,
        operation: str,
        key: bytes,
        count: int,
    ) -> bytearray:
        """Apply arithmetic operation in pure Python.

        Args:
            data: Input byte data.
            operation: Operation name. Must be one of ``xor``, ``and``,
                ``or``, ``not``, ``shl``, ``shr``, ``rol``, ``ror``.
            key: Key/mask bytes.
            count: Bit count for shift/rotate.

        Returns:
            bytearray: Transformed data.

        Raises:
            ToolError: If ``operation`` is not recognized.
        """
        result = bytearray(len(data))
        byte_mask = 0xFF
        bits_per_byte = 8
        for i, b in enumerate(data):
            if operation == "xor" and key:
                result[i] = b ^ key[i % len(key)]
            elif operation == "and" and key:
                result[i] = b & key[i % len(key)]
            elif operation == "or" and key:
                result[i] = b | key[i % len(key)]
            elif operation == "not":
                result[i] = (~b) & byte_mask
            elif operation == "shl":
                result[i] = (b << count) & byte_mask
            elif operation == "shr":
                result[i] = (b >> count) & byte_mask
            elif operation == "rol":
                shift = count % bits_per_byte
                result[i] = ((b << shift) | (b >> (bits_per_byte - shift))) & byte_mask
            elif operation == "ror":
                shift = count % bits_per_byte
                result[i] = ((b >> shift) | (b << (bits_per_byte - shift))) & byte_mask
            elif operation in {"xor", "and", "or"}:
                result[i] = b
            else:
                _logger.error("apply_arithmetic_fallback_unknown_operation", operation=operation)
                msg = f"{_ERR_UNKNOWN_TRANSFORM}: {operation!r} has no pure-Python fallback implementation"
                raise ToolError(msg)
        return result

    async def get_bit(self, offset: int, bit_index: int) -> bool:
        """Get the value of a specific bit at an offset.

        Args:
            offset: Byte offset.
            bit_index: Bit index (0=LSB, 7=MSB).

        Returns:
            bool: True if the bit is set.

        Raises:
            RuntimeError: If no document is open.
            ValueError: If bit_index is not 0-7.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)
        if not 0 <= bit_index <= _BIT_INDEX_MAX:
            _logger.error("get_bit_failed_invalid_index", bit_index=bit_index)
            msg = f"bit_index must be 0-7, got {bit_index}"
            raise ValueError(msg)

        if hasattr(self.document, "get_bit"):
            result: bool = self.document.get_bit(offset, bit_index)
            return result

        byte_val = self._read_doc_bytes(offset, 1)[0]
        return bool(byte_val & (1 << bit_index))

    async def set_bit(self, offset: int, bit_index: int, *, value: bool) -> bool:
        """Set or clear a specific bit at an offset.

        Args:
            offset: Byte offset.
            bit_index: Bit index (0=LSB, 7=MSB).
            value: True to set, False to clear.

        Returns:
            bool: True if the operation succeeded.

        Raises:
            RuntimeError: If no document is open.
            ValueError: If bit_index is not 0-7.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)
        if not 0 <= bit_index <= _BIT_INDEX_MAX:
            _logger.error("set_bit_failed_invalid_index", bit_index=bit_index)
            msg = f"bit_index must be 0-7, got {bit_index}"
            raise ValueError(msg)

        if hasattr(self.document, "set_bit"):
            self.document.set_bit(offset, bit_index, value)
        else:
            byte_val = self._read_doc_bytes(offset, 1)[0]
            if value:
                byte_val |= 1 << bit_index
            else:
                byte_val &= ~(1 << bit_index) & 0xFF
            _logger.info("file_written", path="document", offset=hex(offset), size=1, op="set_bit")
            self.document.write_bytes(offset, bytes([byte_val]))

        _logger.info("bit_set", offset=hex(offset), bit=bit_index, value=value)
        if self.state_holder is not None:
            self.state_holder.notify_data_modified(offset, 1, source="bridge")
        return True

    async def toggle_bit(self, offset: int, bit_index: int) -> bool:
        """Toggle a specific bit at an offset.

        Args:
            offset: Byte offset.
            bit_index: Bit index (0=LSB, 7=MSB).

        Returns:
            bool: New bit value after toggle.

        Raises:
            RuntimeError: If no document is open.
            ValueError: If bit_index is not 0-7.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)
        if not 0 <= bit_index <= _BIT_INDEX_MAX:
            _logger.error("toggle_bit_failed_invalid_index", bit_index=bit_index)
            msg = f"bit_index must be 0-7, got {bit_index}"
            raise ValueError(msg)

        if hasattr(self.document, "toggle_bit"):
            result: bool = self.document.toggle_bit(offset, bit_index)
            if self.state_holder is not None:
                self.state_holder.notify_data_modified(offset, 1, source="bridge")
            return result

        byte_val = self._read_doc_bytes(offset, 1)[0]
        byte_val ^= 1 << bit_index
        _logger.info("file_written", path="document", offset=hex(offset), size=1, op="toggle_bit")
        self.document.write_bytes(offset, bytes([byte_val]))
        _logger.info("bit_toggled", offset=hex(offset), bit=bit_index)
        if self.state_holder is not None:
            self.state_holder.notify_data_modified(offset, 1, source="bridge")
        return bool(byte_val & (1 << bit_index))

    async def set_va_base(
        self,
        file_offset: int,
        virtual_address: int,
        length: int,
    ) -> bool:
        """Add a virtual address mapping for a file region.

        Args:
            file_offset: File offset start.
            virtual_address: Virtual address corresponding to file_offset.
            length: Length of the mapped region.

        Returns:
            bool: True if the mapping was added.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        if hasattr(self.document, "add_va_mapping"):
            self.document.add_va_mapping(file_offset, virtual_address, length)
        _logger.debug(
            "va_mapping_added",
            file_offset=hex(file_offset),
            va=hex(virtual_address),
            length=length,
        )
        if self.state_holder is not None:
            mapping_count = (
                len(self.document.list_va_mappings()) if self.document is not None and hasattr(self.document, "list_va_mappings") else 0
            )
            self.state_holder.notify_va_mapping_changed(mapping_count, source="bridge")
        return True

    async def remove_va_mapping(self, index: int) -> bool:
        """Remove a virtual address mapping by index.

        Args:
            index: Mapping index.

        Returns:
            bool: True if removed.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        if hasattr(self.document, "remove_va_mapping"):
            result: bool = self.document.remove_va_mapping(index)
            if result and self.state_holder is not None:
                va_count = len(self.document.list_va_mappings()) if hasattr(self.document, "list_va_mappings") else 0
                self.state_holder.notify_va_mapping_changed(va_count, source="bridge")
            return result
        return False

    async def list_va_mappings(self) -> list[dict[str, int]]:
        """List all virtual address mappings.

        Returns:
            list[dict[str, int]]: List of dicts with file_offset, virtual_address, length.
        """
        _logger.debug("list_va_mappings_started", has_document=self.document is not None)
        if self.document is None:
            return []

        if hasattr(self.document, "list_va_mappings"):
            mappings: list[tuple[int, int, int]] = self.document.list_va_mappings()
            return [{"file_offset": m[0], "virtual_address": m[1], "length": m[2]} for m in mappings]
        return []

    async def auto_detect_va_mappings(self) -> list[dict[str, int]]:
        """Auto-detect VA mappings from PE or ELF headers.

        Returns:
            list[dict[str, int]]: List of detected mappings.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        doc_len: int = self.document.length()
        if doc_len < _MIN_HEADER_SIZE:
            return []

        magic = self._read_doc_bytes(0, _MIN_HEADER_SIZE)

        if magic[:2] == b"MZ":
            return await self._detect_pe_va_mappings()
        if magic[:_MIN_HEADER_SIZE] == b"\x7fELF":
            return await self._detect_elf_va_mappings()
        return []

    async def _detect_pe_va_mappings(self) -> list[dict[str, int]]:
        """Detect VA mappings from PE headers.

        Returns:
            list[dict[str, int]]: List of detected PE section mappings.
        """
        if self.document is None:
            return []

        try:
            dos_header = self._read_doc_bytes(0, _DOS_HEADER_SIZE)
            e_lfanew = read_dos_e_lfanew(dos_header)
            if self._read_doc_bytes(e_lfanew, 4) != b"PE\x00\x00":
                return []

            coff_header = self._read_doc_bytes(e_lfanew + 4, _PE_COFF_HEADER_SIZE)
            _machine, num_sections, opt_header_size, _characteristics = unpack_coff_header(coff_header, 0)
            opt_offset = e_lfanew + 4 + _PE_COFF_HEADER_SIZE
            opt_header = self._read_doc_bytes(opt_offset, min(opt_header_size, _DOS_HEADER_SIZE))
            is_pe64 = is_pe64_optional_header(opt_header, 0)
            image_base = unpack_optional_header_image_base(opt_header, 0, is_pe64=is_pe64)

            mappings: list[dict[str, int]] = [
                {"file_offset": 0, "virtual_address": image_base, "length": e_lfanew},
            ]
            if hasattr(self.document, "add_va_mapping"):
                self.document.add_va_mapping(0, image_base, e_lfanew)

            self._parse_pe_sections_va(
                opt_offset + opt_header_size,
                min(num_sections, _MAX_PE_SECTIONS),
                image_base,
                mappings,
            )

            _logger.info("pe_va_mappings_detected", count=len(mappings))
            if self.state_holder is not None:
                self.state_holder.notify_va_mapping_changed(len(mappings), source="bridge")
        except (struct.error, RuntimeError, OSError) as exc:
            _logger.warning("pe_va_detection_failed", error=str(exc))
            return []
        else:
            return mappings

    def _parse_pe_sections_va(
        self,
        section_offset: int,
        count: int,
        image_base: int,
        mappings: list[dict[str, int]],
    ) -> None:
        """Parse PE section headers and add VA mappings.

        Args:
            section_offset: File offset of the first section header.
            count: Number of sections to parse.
            image_base: PE image base address.
            mappings: List to append mapping dicts to.
        """
        for i in range(count):
            sec_data = self._read_doc_bytes(section_offset + i * _PE_SECTION_ENTRY_SIZE, _PE_SECTION_ENTRY_SIZE)
            section = unpack_section_header(sec_data, 0)
            virtual_addr = cast("int", section["virtual_address"])
            raw_size = cast("int", section["raw_size"])
            raw_offset = cast("int", section["raw_offset"])
            virtual_size = cast("int", section["virtual_size"])
            sec_length = max(virtual_size, raw_size)
            sec_va = image_base + virtual_addr
            if self.document is not None and hasattr(self.document, "add_va_mapping"):
                self.document.add_va_mapping(raw_offset, sec_va, sec_length)
            mappings.append({"file_offset": raw_offset, "virtual_address": sec_va, "length": sec_length})

    async def _detect_elf_va_mappings(self) -> list[dict[str, int]]:
        """Detect VA mappings from ELF program headers.

        Returns:
            list[dict[str, int]]: List of detected ELF segment mappings.
        """
        if self.document is None:
            return []

        try:
            ident = self._read_doc_bytes(0, 16)
            is_64 = ident[4] == _ELF_CLASS_64
            endian = "<" if ident[5] == _ELF_DATA_LE else ">"
            phoff, phentsize, phnum = self._parse_elf_phdr_info(endian, is_64=is_64)

            mappings: list[dict[str, int]] = []
            for i in range(min(phnum, _MAX_ELF_SEGMENTS)):
                phdr_data = self._read_doc_bytes(phoff + i * phentsize, phentsize)
                if struct.unpack_from(f"{endian}I", phdr_data, 0)[0] != _PT_LOAD:
                    continue
                p_offset, p_vaddr, p_filesz = self._parse_elf_load_segment(phdr_data, endian, is_64=is_64)
                if hasattr(self.document, "add_va_mapping"):
                    self.document.add_va_mapping(p_offset, p_vaddr, p_filesz)
                mappings.append({"file_offset": p_offset, "virtual_address": p_vaddr, "length": p_filesz})

            _logger.info("elf_va_mappings_detected", count=len(mappings))
            if self.state_holder is not None:
                self.state_holder.notify_va_mapping_changed(len(mappings), source="bridge")
        except (struct.error, RuntimeError, OSError) as exc:
            _logger.warning("elf_va_detection_failed", error=str(exc))
            return []
        else:
            return mappings

    def _parse_elf_phdr_info(self, endian: str, *, is_64: bool) -> tuple[int, int, int]:
        """Parse ELF header to extract program header table location.

        Args:
            endian: Endianness string ("<" or ">").
            is_64: True for 64-bit ELF.

        Returns:
            tuple[int, int, int]: phoff, phentsize, phnum.
        """
        if is_64:
            hdr = self._read_doc_bytes(0, _DOS_HEADER_SIZE)
            return (
                struct.unpack_from(f"{endian}Q", hdr, 32)[0],
                struct.unpack_from(f"{endian}H", hdr, 54)[0],
                struct.unpack_from(f"{endian}H", hdr, 56)[0],
            )
        hdr = self._read_doc_bytes(0, 52)
        return (
            struct.unpack_from(f"{endian}I", hdr, 28)[0],
            struct.unpack_from(f"{endian}H", hdr, 42)[0],
            struct.unpack_from(f"{endian}H", hdr, 44)[0],
        )

    @staticmethod
    def _parse_elf_load_segment(phdr_data: bytes, endian: str, *, is_64: bool) -> tuple[int, int, int]:
        """Parse a PT_LOAD program header entry.

        Args:
            phdr_data: Raw program header bytes.
            endian: Endianness string.
            is_64: True for 64-bit ELF.

        Returns:
            tuple[int, int, int]: p_offset, p_vaddr, p_filesz.
        """
        if is_64:
            return (
                struct.unpack_from(f"{endian}Q", phdr_data, 8)[0],
                struct.unpack_from(f"{endian}Q", phdr_data, 16)[0],
                struct.unpack_from(f"{endian}Q", phdr_data, 32)[0],
            )
        return (
            struct.unpack_from(f"{endian}I", phdr_data, 4)[0],
            struct.unpack_from(f"{endian}I", phdr_data, 8)[0],
            struct.unpack_from(f"{endian}I", phdr_data, 16)[0],
        )

    async def file_offset_to_va(self, offset: int) -> int | None:
        """Convert a file offset to a virtual address.

        Args:
            offset: File offset.

        Returns:
            int | None: Virtual address, or None if not mapped.
        """
        _logger.debug("file_offset_to_va_started", offset=hex(offset))
        if self.document is None:
            return None

        if hasattr(self.document, "file_offset_to_va"):
            result: int | None = self.document.file_offset_to_va(offset)
            return result
        return None

    async def va_to_file_offset(self, va: int) -> int | None:
        """Convert a virtual address to a file offset.

        Args:
            va: Virtual address.

        Returns:
            int | None: File offset, or None if not mapped.
        """
        _logger.debug("va_to_file_offset_started", va=hex(va))
        if self.document is None:
            return None

        if hasattr(self.document, "va_to_file_offset"):
            result: int | None = self.document.va_to_file_offset(va)
            return result
        return None

    async def get_strings(
        self,
        min_length: int = 4,
        encoding: str = "ascii+utf16",
        max_results: int = 5000,
    ) -> list[dict[str, Any]]:
        """Extract strings from the document.

        Args:
            min_length: Minimum string length to include.
            encoding: Encoding filter: "ascii+utf16", "ascii", or "utf16".
            max_results: Maximum number of strings to return.

        Returns:
            list[dict[str, Any]]: List of dicts with offset, length, encoding, content.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        include_ascii = encoding in {"ascii+utf16", "ascii"}
        include_utf16 = encoding in {"ascii+utf16", "utf16"}

        if hasattr(self.document, "extract_strings"):
            raw_strings: list[Any] = self.document.extract_strings(
                min_length,
                include_ascii,
                include_utf16,
                max_results,
            )
            _logger.debug("strings_extracted", count=len(raw_strings), backend="rust")
            if raw_strings:
                first_item: Any = raw_strings[0]
                if isinstance(first_item, dict):
                    return cast("list[dict[str, Any]]", raw_strings)
                converted: list[dict[str, Any]] = []
                for s_item in raw_strings:
                    if isinstance(s_item, tuple):
                        tpl = cast("tuple[int, int, str, str]", s_item)
                        converted.append({
                            "offset": tpl[0],
                            "length": tpl[1],
                            "encoding": tpl[2],
                            "content": tpl[3],
                        })
                    else:
                        obj: Any = s_item
                        converted.append({
                            "offset": int(obj.offset) if hasattr(obj, "offset") else 0,
                            "length": int(obj.length) if hasattr(obj, "length") else 0,
                            "encoding": str(obj.encoding) if hasattr(obj, "encoding") else "ascii",
                            "content": str(obj.content) if hasattr(obj, "content") else "",
                        })
                return converted
            return []

        data = self._read_all_doc_bytes()
        return self._extract_strings_fallback(
            data,
            min_length,
            max_results,
            include_ascii=include_ascii,
            include_utf16=include_utf16,
        )

    @staticmethod
    def _extract_strings_fallback(
        data: bytes,
        min_length: int,
        max_results: int,
        *,
        include_ascii: bool,
        include_utf16: bool,
    ) -> list[dict[str, Any]]:
        """Extract strings using pure Python scanning.

        Args:
            data: Binary data to scan.
            min_length: Minimum string length.
            max_results: Maximum results.
            include_ascii: Include ASCII strings.
            include_utf16: Include UTF-16LE strings.

        Returns:
            list[dict[str, Any]]: List of string match dicts.
        """
        results: list[dict[str, Any]] = []
        printable_min = 0x20
        printable_max = 0x7E

        if include_ascii:
            run_start = -1
            for i, b in enumerate(data):
                if printable_min <= b <= printable_max or b in _WHITESPACE_BYTES:
                    if run_start < 0:
                        run_start = i
                elif run_start >= 0:
                    run_len = i - run_start
                    if run_len >= min_length:
                        content = data[run_start:i].decode("ascii", errors="replace")
                        results.append({
                            "offset": run_start,
                            "length": run_len,
                            "encoding": "ascii",
                            "content": content,
                        })
                        if len(results) >= max_results:
                            return results
                    run_start = -1
            if run_start >= 0:
                run_len = len(data) - run_start
                if run_len >= min_length:
                    content = data[run_start:].decode("ascii", errors="replace")
                    results.append({
                        "offset": run_start,
                        "length": run_len,
                        "encoding": "ascii",
                        "content": content,
                    })

        if include_utf16 and len(results) < max_results:
            run_start_u16 = -1
            i = 0
            while i + 1 < len(data):
                code_unit = data[i] | (data[i + 1] << 8)
                if printable_min <= code_unit <= printable_max or code_unit in _WHITESPACE_BYTES:
                    if run_start_u16 < 0:
                        run_start_u16 = i
                elif run_start_u16 >= 0:
                    char_count = (i - run_start_u16) // 2
                    if char_count >= min_length:
                        content = data[run_start_u16:i].decode("utf-16le", errors="replace")
                        results.append({
                            "offset": run_start_u16,
                            "length": i - run_start_u16,
                            "encoding": "utf-16le",
                            "content": content,
                        })
                        if len(results) >= max_results:
                            return results
                    run_start_u16 = -1
                i += 2

        results.sort(key=operator.itemgetter("offset"))
        return results[:max_results]

    async def generate_structure_bookmarks(self) -> list[dict[str, Any]]:
        """Auto-detect PE/ELF structure and create colored bookmarks.

        Returns:
            list[dict[str, Any]]: List of bookmark dicts that were created.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        doc_len: int = self.document.length()
        if doc_len < _MIN_HEADER_SIZE:
            return []

        magic = self._read_doc_bytes(0, _MIN_HEADER_SIZE)
        if magic[:2] == b"MZ":
            return self._bookmark_pe_structure()
        if magic[:4] == b"\x7fELF":
            return self._bookmark_elf_structure()
        return []

    def _bookmark_pe_structure(self) -> list[dict[str, Any]]:
        """Create colored bookmarks for PE structure headers.

        Returns:
            list[dict[str, Any]]: Created bookmark dicts.
        """
        if self.document is None:
            return []

        bookmarks: list[dict[str, Any]] = []
        colors = ("#FF6B6B", "#4ECDC4", "#45B7D1", "#96CEB4")

        try:
            e_lfanew = struct.unpack_from("<I", self._read_doc_bytes(_PE_LFANEW_OFFSET, 4), 0)[0]
            self._add_bm(bookmarks, 0, _DOS_HEADER_SIZE, "DOS Header", colors[0])
            self._add_bm(bookmarks, e_lfanew, 4, "PE Signature", colors[1])

            coff_offset = e_lfanew + 4
            self._add_bm(bookmarks, coff_offset, _PE_COFF_HEADER_SIZE, "COFF Header", colors[1])

            coff_header = self._read_doc_bytes(coff_offset, _PE_COFF_HEADER_SIZE)
            num_sections = struct.unpack_from("<H", coff_header, 2)[0]
            opt_size = struct.unpack_from("<H", coff_header, 16)[0]
            opt_offset = coff_offset + _PE_COFF_HEADER_SIZE
            if opt_size > 0:
                self._add_bm(bookmarks, opt_offset, opt_size, "Optional Header", colors[2])

            self._bookmark_pe_sections(opt_offset + opt_size, num_sections, bookmarks, colors[3])

            _logger.info("pe_structure_bookmarked", bookmark_count=len(bookmarks))
        except (struct.error, RuntimeError, OSError) as exc:
            _logger.warning("pe_structure_bookmark_failed", error=str(exc))
        return bookmarks

    def _add_bm(self, bookmarks: list[dict[str, Any]], offset: int, length: int, label: str, color: str) -> None:
        """Add a bookmark to the document and tracking list.

        Args:
            bookmarks: List to append the bookmark dict to.
            offset: Byte offset.
            length: Length in bytes.
            label: Bookmark label.
            color: Color hex string.
        """
        if self.document is not None:
            self.document.add_bookmark(offset, length, label, color)
        bookmarks.append({"offset": offset, "length": length, "label": label, "color": color})

    def _bookmark_pe_sections(
        self,
        section_table_offset: int,
        num_sections: int,
        bookmarks: list[dict[str, Any]],
        color: str,
    ) -> None:
        """Bookmark PE section headers.

        Args:
            section_table_offset: File offset of the first section header.
            num_sections: Number of section headers.
            bookmarks: List to append bookmarks to.
            color: Color hex string.
        """
        for i in range(min(num_sections, _MAX_BOOKMARK_ENTRIES)):
            sec_off = section_table_offset + i * _PE_SECTION_ENTRY_SIZE
            sec_name = self._read_doc_bytes(sec_off, 8).rstrip(b"\x00").decode("ascii", errors="replace")
            self._add_bm(bookmarks, sec_off, _PE_SECTION_ENTRY_SIZE, f"Section: {sec_name}", color)

    def _bookmark_elf_structure(self) -> list[dict[str, Any]]:
        """Create colored bookmarks for ELF structure headers.

        Returns:
            list[dict[str, Any]]: Created bookmark dicts.
        """
        if self.document is None:
            return []

        bookmarks: list[dict[str, Any]] = []
        colors = ("#FF6B6B", "#4ECDC4", "#45B7D1")

        try:
            ident = self._read_doc_bytes(0, 16)
            is_64 = ident[4] == _ELF_CLASS_64
            endian = "<" if ident[5] == _ELF_DATA_LE else ">"
            ehdr_size, ph_info, sh_info = self._parse_elf_bookmark_info(endian, is_64=is_64)

            self._add_bm(bookmarks, 0, ehdr_size, "ELF Header", colors[0])
            for i in range(min(ph_info[2], _MAX_BOOKMARK_ENTRIES)):
                self._add_bm(bookmarks, ph_info[0] + i * ph_info[1], ph_info[1], f"Program Header {i}", colors[1])
            for i in range(min(sh_info[2], _MAX_BOOKMARK_ENTRIES)):
                self._add_bm(bookmarks, sh_info[0] + i * sh_info[1], sh_info[1], f"Section Header {i}", colors[2])

            _logger.info("elf_structure_bookmarked", bookmark_count=len(bookmarks))
        except (struct.error, RuntimeError, OSError) as exc:
            _logger.warning("elf_structure_bookmark_failed", error=str(exc))
        return bookmarks

    def _parse_elf_bookmark_info(
        self,
        endian: str,
        *,
        is_64: bool,
    ) -> tuple[int, tuple[int, int, int], tuple[int, int, int]]:
        """Parse ELF header for bookmark generation.

        Args:
            endian: Endianness string.
            is_64: True for 64-bit ELF.

        Returns:
            tuple[int, tuple[int, int, int], tuple[int, int, int]]:
                ehdr_size, (phoff, phentsize, phnum), (shoff, shentsize, shnum).
        """
        if is_64:
            hdr = self._read_doc_bytes(0, _DOS_HEADER_SIZE)
            return (
                _DOS_HEADER_SIZE,
                (
                    struct.unpack_from(f"{endian}Q", hdr, 32)[0],
                    struct.unpack_from(f"{endian}H", hdr, 54)[0],
                    struct.unpack_from(f"{endian}H", hdr, 56)[0],
                ),
                (
                    struct.unpack_from(f"{endian}Q", hdr, 40)[0],
                    struct.unpack_from(f"{endian}H", hdr, 58)[0],
                    struct.unpack_from(f"{endian}H", hdr, 60)[0],
                ),
            )
        hdr = self._read_doc_bytes(0, 52)
        return (
            52,
            (
                struct.unpack_from(f"{endian}I", hdr, 28)[0],
                struct.unpack_from(f"{endian}H", hdr, 42)[0],
                struct.unpack_from(f"{endian}H", hdr, 44)[0],
            ),
            (
                struct.unpack_from(f"{endian}I", hdr, 32)[0],
                struct.unpack_from(f"{endian}H", hdr, 46)[0],
                struct.unpack_from(f"{endian}H", hdr, 48)[0],
            ),
        )

    async def export_annotated_html(
        self,
        start: int = 0,
        end: int = 0,
        bytes_per_row: int = 16,
    ) -> str:
        """Export hex view as annotated HTML with bookmarks and highlights.

        Args:
            start: Start offset.
            end: End offset (0 = entire document).
            bytes_per_row: Number of bytes per row.

        Returns:
            str: Complete HTML string.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        doc_len: int = self.document.length()
        end = min(end if end > 0 else doc_len, doc_len)
        start = max(0, start)

        data = self._read_doc_bytes(start, end - start)
        bookmarks = [{"offset": b[0], "length": b[1], "label": b[2], "color": b[3]} for b in self.document.list_bookmarks()]
        bookmark_map = self._build_bookmark_map(bookmarks, start, end)

        lines = self._html_header()
        self._render_hex_rows(lines, data, start, bytes_per_row, bookmark_map)
        lines.append("</table>")

        if bookmarks:
            lines.append("<div class='legend'><strong>Bookmarks:</strong><br>")
            seen_labels: set[str] = set()
            for bm in bookmarks:
                label = bm["label"]
                if label not in seen_labels:
                    seen_labels.add(label)
                    lines.append(
                        f"<span class='legend-item' style='background:{bm['color']}40;color:{bm['color']}'>"
                        f"{label} (0x{bm['offset']:X})</span>",
                    )
            lines.append("</div>")

        lines.append("</body></html>")
        _logger.debug("annotated_html_exported", start=start, end=end)
        return "\n".join(lines)

    async def export_annotated_pdf(
        self,
        output_path: str,
        start: int = 0,
        end: int = 0,
        bytes_per_row: int = 16,
    ) -> str:
        """Export hex view as an annotated PDF with bookmarks and highlights.

        Args:
            output_path: Filesystem path for the output PDF file.
            start: Start offset.
            end: End offset (0 = entire document).
            bytes_per_row: Number of bytes per row.

        Returns:
            str: Path of the written PDF file.

        Raises:
            ToolError: If no document is open or fpdf2 is unavailable.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise ToolError(msg)

        doc_len: int = self.document.length()
        actual_end = min(end if end > 0 else doc_len, doc_len)
        actual_start = max(0, start)

        data = self._read_doc_bytes(actual_start, actual_end - actual_start)
        bookmarks_raw: list[tuple[int, int, str, str]] = self.document.list_bookmarks()
        bookmarks: list[dict[str, object]] = [{"offset": b[0], "length": b[1], "label": b[2], "color": b[3]} for b in bookmarks_raw]
        bookmark_map = self._build_bookmark_map(bookmarks, actual_start, actual_end)

        result: str = await asyncio.to_thread(
            _generate_pdf,
            output_path,
            data,
            actual_start,
            bytes_per_row,
            bookmark_map,
            bookmarks,
            doc_len,
        )
        _logger.debug("annotated_pdf_exported", path=result, start=actual_start, end=actual_end)
        return result

    @staticmethod
    def _build_bookmark_map(
        bookmarks: list[dict[str, Any]],
        start: int,
        end: int,
    ) -> dict[int, dict[str, Any]]:
        """Build an offset-to-bookmark lookup map.

        Args:
            bookmarks: List of bookmark dicts.
            start: Start offset.
            end: End offset.

        Returns:
            dict[int, dict[str, Any]]: Map from offset to bookmark dict.
        """
        bm_map: dict[int, dict[str, Any]] = {}
        for bm in bookmarks:
            bm_start = bm["offset"]
            bm_end = bm_start + bm["length"]
            for off in range(max(bm_start, start), min(bm_end, end)):
                bm_map[off] = bm
        return bm_map

    @staticmethod
    def _html_header() -> list[str]:
        """Generate the HTML header with CSS styles.

        Returns:
            list[str]: List of HTML header lines.
        """
        return [
            "<!DOCTYPE html>",
            "<html><head><meta charset='utf-8'>",
            "<style>",
            "body { font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; background: #1e1e2e; color: #cdd6f4; }",
            "table { border-collapse: collapse; }",
            "td { padding: 1px 4px; white-space: pre; }",
            ".offset { color: #89b4fa; }",
            ".ascii { color: #a6e3a1; }",
            ".hex { color: #cdd6f4; }",
            ".bm { border-radius: 2px; padding: 0 2px; }",
            ".legend { margin-top: 16px; }",
            ".legend-item { display: inline-block; margin-right: 12px; padding: 2px 6px; border-radius: 3px; }",
            "</style></head><body>",
            "<h3>Hex Dump</h3>",
            "<table>",
        ]

    @staticmethod
    def _render_hex_rows(
        lines: list[str],
        data: bytes,
        start: int,
        bytes_per_row: int,
        bookmark_map: dict[int, dict[str, Any]],
    ) -> None:
        """Render hex dump rows into the HTML lines list.

        Args:
            lines: List to append rendered HTML rows to.
            data: Binary data to render.
            start: Absolute start offset of the data.
            bytes_per_row: Number of bytes per row.
            bookmark_map: Map from absolute offset to bookmark dict.
        """
        for row_start in range(0, len(data), bytes_per_row):
            abs_offset = start + row_start
            row_data = data[row_start : row_start + bytes_per_row]
            hex_cells: list[str] = []
            ascii_cells: list[str] = []
            for j, b in enumerate(row_data):
                bm = bookmark_map.get(abs_offset + j)
                hex_str = f"{b:02X}"
                if bm is not None:
                    hex_cells.append(f"<span class='bm' style='background:{bm['color']}40;color:{bm['color']}'>{hex_str}</span>")
                else:
                    hex_cells.append(f"<span class='hex'>{hex_str}</span>")
                ch = chr(b) if _PRINTABLE_MIN <= b <= _PRINTABLE_MAX else "."
                if ch in {"&", "<", ">"}:
                    ch = f"&#{ord(ch)};"
                ascii_cells.append(ch)
            lines.append(
                f"<tr><td class='offset'>{abs_offset:08X}</td>"
                f"<td>{' '.join(hex_cells)}</td>"
                f"<td class='ascii'>{''.join(ascii_cells)}</td></tr>",
            )

    async def snap_to_alignment(self, alignment_size: int = 512) -> int:
        """Snap the cursor to the nearest alignment boundary.

        Args:
            alignment_size: Alignment boundary in bytes.

        Returns:
            int: New cursor offset after snapping.
        """
        if alignment_size <= 0:
            alignment_size = 512
        new_offset = (self._cursor_offset // alignment_size) * alignment_size
        self._cursor_offset = new_offset
        _logger.debug("cursor_snapped", offset=hex(new_offset), alignment=alignment_size)
        if self.state_holder is not None:
            self.state_holder.set_cursor(new_offset, source="bridge")
        return new_offset

    async def set_alignment_grid(self, size: int = 512) -> bool:
        """Set the alignment grid size for visual display.

        Args:
            size: Grid size in bytes (0 to disable).

        Returns:
            bool: True always.
        """
        self._alignment_grid_size = size
        _logger.debug("alignment_grid_set", size=size)
        if self.state_holder is not None:
            self.state_holder.notify_alignment_grid_changed(size, source="bridge")
        return True

    async def verify_pe_checksum(self) -> dict[str, Any]:
        """Verify the PE optional header checksum.

        Returns:
            dict[str, Any]: Dict with stored, calculated, offset, valid.

        Raises:
            RuntimeError: If no document is open or file is not PE.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        if hasattr(self.document, "verify_pe_checksum"):
            result = self.document.verify_pe_checksum()
            if isinstance(result, dict):
                return cast("dict[str, Any]", result)

        data = self._read_all_doc_bytes()
        if data[:2] != b"MZ":
            _logger.error("verify_pe_checksum_failed_not_pe", magic_hex=data[:2].hex())
            msg = "not a PE file"
            raise RuntimeError(msg)

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            _logger.error("verify_pe_checksum_failed_invalid_pe_sig", e_lfanew=hex(e_lfanew))
            msg = "invalid PE signature"
            raise RuntimeError(msg)

        checksum_offset = e_lfanew + 4 + 20 + 64
        if checksum_offset + 4 > len(data):
            _logger.error("verify_pe_checksum_failed_header_too_short", checksum_offset=hex(checksum_offset))
            msg = "PE header too short for checksum field"
            raise RuntimeError(msg)

        stored = struct.unpack_from("<I", data, checksum_offset)[0]
        calculated = self._compute_pe_checksum_static(data, checksum_offset)

        _logger.debug(
            "pe_checksum_verified",
            stored=hex(stored),
            calculated=hex(calculated),
        )
        return {
            "stored": stored,
            "calculated": calculated,
            "offset": checksum_offset,
            "valid": stored == calculated,
        }

    async def repair_pe_checksum(self) -> dict[str, Any]:
        """Recalculate and write the correct PE checksum.

        Returns:
            dict[str, Any]: Dict with old_checksum, new_checksum, offset.

        Raises:
            RuntimeError: If no document is open or file is not PE.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        if hasattr(self.document, "repair_pe_checksum"):
            self.document.repair_pe_checksum()
            verify_result = await self.verify_pe_checksum()
            return {
                "old_checksum": 0,
                "new_checksum": verify_result.get("calculated", 0),
                "offset": verify_result.get("offset", 0),
            }

        verify_result = await self.verify_pe_checksum()
        old_checksum = verify_result["stored"]
        new_checksum = verify_result["calculated"]
        checksum_offset = verify_result["offset"]

        _logger.info(
            "file_written",
            path="document",
            offset=hex(checksum_offset),
            size=4,
            op="pe_checksum_repair",
        )
        self.document.write_bytes(checksum_offset, struct.pack("<I", new_checksum))
        _logger.info("pe_checksum_repaired", old=hex(old_checksum), new=hex(new_checksum))
        if self.state_holder is not None:
            self.state_holder.notify_data_modified(checksum_offset, 4, source="bridge")
        return {
            "old_checksum": old_checksum,
            "new_checksum": new_checksum,
            "offset": checksum_offset,
        }

    @staticmethod
    def _compute_pe_checksum_static(data: bytes, checksum_offset: int) -> int:
        """Compute the PE checksum using the Windows algorithm.

        Args:
            data: Full file data.
            checksum_offset: Byte offset of the CheckSum field.

        Returns:
            int: Computed checksum value.
        """
        checksum = 0
        top = 1 << 32

        for i in range(0, len(data) & ~1, 2):
            if i == checksum_offset or i == checksum_offset + 2:
                continue
            word = data[i] | (data[i + 1] << 8)
            checksum += word
            if checksum >= top:
                checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)

        if len(data) & 1:
            checksum += data[-1]
            if checksum >= top:
                checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)

        checksum = (checksum & 0xFFFF) + (checksum >> 16)
        checksum += checksum >> 16
        return (checksum & 0xFFFF) + len(data)

    @staticmethod
    async def base_convert(value: str, from_base: str = "auto") -> dict[str, str]:
        """Convert a numeric value between bases and show all representations.

        Args:
            value: Value string (decimal, 0xHex, 0bBinary, 0oOctal).
            from_base: Source base hint (auto, decimal, hex, binary, octal).

        Returns:
            dict[str, str]: Dict with decimal, hex, octal, binary, and
                integer width representations.
        """
        value = value.strip()
        parsed: int

        if from_base == "auto":
            if value.startswith(("0x", "0X")):
                parsed = int(value, 16)
            elif value.startswith(("0b", "0B")):
                parsed = int(value, 2)
            elif value.startswith(("0o", "0O")):
                parsed = int(value, 8)
            else:
                parsed = int(value)
        elif from_base == "hex":
            parsed = int(value.removeprefix("0x").removeprefix("0X"), 16)
        elif from_base == "binary":
            parsed = int(value.removeprefix("0b").removeprefix("0B"), 2)
        elif from_base == "octal":
            parsed = int(value.removeprefix("0o").removeprefix("0O"), 8)
        else:
            parsed = int(value)

        result: dict[str, str] = {
            "decimal": str(parsed),
            "hex": hex(parsed),
            "octal": oct(parsed),
            "binary": bin(parsed),
        }

        byte_mask = 0xFF
        u16_mask = 0xFFFF
        u32_mask = 0xFFFFFFFF
        u64_mask = 0xFFFFFFFFFFFFFFFF

        if 0 <= parsed <= byte_mask:
            result["uint8"] = str(parsed)
            result["int8"] = str(struct.unpack("b", struct.pack("B", parsed))[0])
        if 0 <= parsed <= u16_mask:
            result["uint16_le"] = str(parsed)
            result["int16_le"] = str(struct.unpack("<h", struct.pack("<H", parsed))[0])
        if 0 <= parsed <= u32_mask:
            result["uint32_le"] = str(parsed)
            result["int32_le"] = str(struct.unpack("<i", struct.pack("<I", parsed))[0])
        if 0 <= parsed <= u64_mask:
            result["uint64_le"] = str(parsed)
            result["int64_le"] = str(struct.unpack("<q", struct.pack("<Q", parsed))[0])

        try:
            if 0 <= parsed <= u32_mask:
                float_val: float = struct.unpack("<f", struct.pack("<I", parsed))[0]
                if math.isfinite(float_val):
                    result["float32_le"] = str(float_val)
            if 0 <= parsed <= u64_mask:
                double_val: float = struct.unpack("<d", struct.pack("<Q", parsed))[0]
                if math.isfinite(double_val):
                    result["float64_le"] = str(double_val)
        except (struct.error, OverflowError):
            _logger.debug("base_convert_float_unpack_failed", value=value, exc_info=True)

        _logger.debug("base_convert", input_value=value)
        return result

    async def run_python_script(self, source: str) -> dict[str, Any]:
        """Execute a Python script with access to the hex document API.

        Args:
            source: Python source code.

        Returns:
            dict[str, Any]: Dict with output, error, and variables keys.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        stdout_capture = io.StringIO()
        doc = self.document

        class _DocAPI:
            """Restricted document API for user scripts."""

            @staticmethod
            def read(offset: int, length: int) -> list[int]:
                """Read bytes from the document as a list of integers.

                Args:
                    offset: Absolute offset to start reading from.
                    length: Number of bytes to read.

                Returns:
                    list[int]: Byte values read from the document.
                """
                raw: object = doc.read(offset, length)
                if isinstance(raw, (bytes, bytearray)):
                    return list(raw)
                if isinstance(raw, list):
                    return cast("list[int]", raw)
                return list(cast("bytearray", raw))

            @staticmethod
            def write(offset: int, data: bytes | list[int]) -> None:
                """Overwrite bytes at ``offset`` with ``data``.

                Args:
                    offset: Absolute offset where the write starts.
                    data: Replacement bytes, either as ``bytes`` or a list
                        of byte-valued integers.
                """
                if isinstance(data, list):
                    data = bytes(data)
                _logger.info("file_written", path="document", offset=hex(offset), size=len(data), op="script_doc_write")
                doc.write_bytes(offset, data)

            @staticmethod
            def insert(offset: int, data: bytes | list[int]) -> None:
                """Insert ``data`` at ``offset`` without overwriting.

                Args:
                    offset: Absolute offset where the insertion occurs.
                    data: Bytes to insert, either as ``bytes`` or a list
                        of byte-valued integers.
                """
                if isinstance(data, list):
                    data = bytes(data)
                doc.insert_bytes(offset, data)

            @staticmethod
            def delete(offset: int, length: int) -> None:
                """Delete ``length`` bytes starting at ``offset``.

                Args:
                    offset: Absolute offset where deletion starts.
                    length: Number of bytes to remove.
                """
                doc.delete_bytes(offset, length)

            @staticmethod
            def length() -> int:
                """Return the current byte length of the document.

                Returns:
                    int: Number of bytes in the document.
                """
                result: int = doc.length()
                return result

            @staticmethod
            def search_hex(pattern: str) -> list[tuple[int, int]]:
                """Search the document for a hex pattern.

                Args:
                    pattern: Hex pattern expressed as a string (whitespace
                        and wildcard tokens are passed straight through to
                        the underlying hexcore search).

                Returns:
                    list[tuple[int, int]]: ``(offset, length)`` matches,
                    capped at 1000.
                """
                results: list[tuple[int, int]] = doc.search_hex(pattern, 1000)
                return results

            @staticmethod
            def search_text(text: str) -> list[tuple[int, int]]:
                """Search the document for a UTF-8 text literal.

                Args:
                    text: Text to search for; matching is case-sensitive.

                Returns:
                    list[tuple[int, int]]: ``(offset, length)`` matches,
                    capped at 1000.
                """
                case_sensitive = True
                results: list[tuple[int, int]] = doc.search_text(text, "utf-8", case_sensitive, 1000)
                return results

            @staticmethod
            def add_bookmark(offset: int, length: int = 1, label: str = "Bookmark", color: str = "#FFFF00") -> int:
                """Add a bookmark spanning ``length`` bytes at ``offset``.

                Args:
                    offset: Absolute offset of the bookmark.
                    length: Length in bytes that the bookmark covers.
                    label: Human-readable bookmark label.
                    color: Bookmark highlight colour as ``#RRGGBB``.

                Returns:
                    int: Identifier of the newly created bookmark.
                """
                idx: int = doc.add_bookmark(offset, length, label, color)
                return idx

        forbidden_builtins = {"__import__", "eval", "exec", "open", "compile", "breakpoint"}
        safe_builtins: dict[str, Any] = {k: v for k, v in vars(_builtins_mod).items() if k not in forbidden_builtins}

        def safe_print(*args: object, **kwargs: object) -> None:
            """Capture script ``print`` output into the sandboxed buffer.

            Replaces the built-in ``print`` inside the restricted script
            environment so that anything the user script prints ends up in
            ``stdout_capture`` rather than the host process stdout.

            Args:
                *args: Positional values that would normally be printed.
                **kwargs: Recognised keyword arguments ``sep`` and ``end``
                    mirroring the built-in ``print`` semantics.
            """
            sep = str(kwargs.get("sep", " "))
            end_val = str(kwargs.get("end", "\n"))
            stdout_capture.write(sep.join(str(a) for a in args) + end_val)

        namespace: dict[str, Any] = {
            "__builtins__": safe_builtins,
            "doc": _DocAPI(),
            "print": safe_print,
        }

        error_str: str = ""
        try:
            compiled = compile(source, "<script>", "exec")
            exec(compiled, namespace)  # noqa: S102
        except SyntaxError as exc:
            _logger.warning("python_script_syntax_error", error_lineno=exc.lineno, error_message=exc.msg)
            error_str = f"SyntaxError at line {exc.lineno}: {exc.msg}"
        except (
            NameError,
            TypeError,
            ValueError,
            AttributeError,
            KeyError,
            IndexError,
            RuntimeError,
            OSError,
            ArithmeticError,
            ImportError,
            StopIteration,
            AssertionError,
            MemoryError,
            RecursionError,
            UnicodeError,
            EOFError,
            BufferError,
            LookupError,
        ) as exc:
            _logger.warning("python_script_runtime_error", error_type=type(exc).__name__, error=str(exc))
            error_str = f"{type(exc).__name__}: {exc}"

        output = stdout_capture.getvalue()
        user_vars: dict[str, str] = {}
        skip_keys = {"__builtins__", "doc", "print"}
        for k, v in namespace.items():
            if k not in skip_keys and not k.startswith("_"):
                try:
                    user_vars[k] = repr(v)
                except (RuntimeError, TypeError, ValueError):
                    _logger.debug("python_script_var_unrepresentable", var_name=k, exc_info=True)
                    user_vars[k] = "<unrepresentable>"

        _logger.info("python_script_executed", output_len=len(output), has_error=bool(error_str))
        if self.state_holder is not None:
            doc_len_val: int = self.document.length() if self.document is not None else 0
            self.state_holder.notify_data_modified(0, doc_len_val, source="bridge")
        return {"output": output, "error": error_str, "variables": user_vars}

    async def set_chunk_size(self, size_bytes: int) -> bool:
        """Set the chunk size hint for large file I/O.

        Args:
            size_bytes: Chunk size in bytes.

        Returns:
            bool: True always.
        """
        if self.document is not None and hasattr(self.document, "set_chunk_size_hint"):
            self.document.set_chunk_size_hint(size_bytes)
        _logger.debug("chunk_size_set", size=size_bytes)
        return True

    async def get_memory_usage(self) -> dict[str, int]:
        """Get current document memory usage estimate.

        Returns:
            dict[str, int]: Dict with usage_bytes, chunk_size, memory_budget.
        """
        _logger.debug("get_memory_usage_started", has_document=self.document is not None)
        usage = 0
        chunk = 0
        budget = 0
        if self.document is not None:
            if hasattr(self.document, "get_document_memory_usage"):
                usage = int(self.document.get_document_memory_usage())
            if hasattr(self.document, "get_chunk_size_hint"):
                chunk = int(self.document.get_chunk_size_hint())
            if hasattr(self.document, "get_memory_budget_hint"):
                budget = int(self.document.get_memory_budget_hint())
        return {"usage_bytes": usage, "chunk_size": chunk, "memory_budget": budget}

    async def set_memory_budget(self, budget_bytes: int) -> bool:
        """Set the memory budget hint for large file operations.

        Args:
            budget_bytes: Memory budget in bytes.

        Returns:
            bool: True always.
        """
        if self.document is not None and hasattr(self.document, "set_memory_budget_hint"):
            self.document.set_memory_budget_hint(budget_bytes)
        _logger.debug("memory_budget_set", budget=budget_bytes)
        return True

    async def set_color_mode(self, mode: str) -> bool:
        """Set the byte color-mapping mode.

        Args:
            mode: One of "none", "entropy", "byte_value", "template", "content_type".

        Returns:
            bool: True always.
        """
        self._color_mode = mode
        _logger.debug("color_mode_set", mode=mode)
        if self.state_holder is not None:
            self.state_holder.notify_color_mode_changed(mode, source="bridge")
        return True

    async def get_color_mode(self) -> str:
        """Get the current byte color-mapping mode.

        Returns:
            str: Current color mode string.
        """
        _logger.debug("get_color_mode_started", mode=self._color_mode)
        return self._color_mode

    async def scan_die_signatures(self, db_path: str) -> list[dict[str, Any]]:
        """Scan document against a DIE-style JSON signature database.

        Args:
            db_path: Path to the DIE JSON database file.

        Returns:
            list[dict[str, Any]]: List of match dicts with name, type, version, offset, details.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        db_text = await asyncio.to_thread(Path(db_path).read_text, encoding="utf-8")
        db_entries: list[dict[str, Any]] = json.loads(db_text)
        ep_bytes = self._read_doc_bytes(0, min(_MAX_EP_BYTES, self.document.length()))
        results: list[dict[str, Any]] = []

        for entry in db_entries:
            sig_info = (str(entry.get("name", "unknown")), str(entry.get("type", "unknown")), str(entry.get("version", "")))
            for pattern_info in list(entry.get("patterns", [])):
                self._match_die_pattern(pattern_info, sig_info, ep_bytes, results)

        _logger.info("die_scan_completed", matches=len(results))
        return results

    def _match_die_pattern(
        self,
        pattern_info: str | dict[str, str] | object,
        sig_info: tuple[str, str, str],
        ep_bytes: bytes,
        results: list[dict[str, Any]],
    ) -> None:
        """Match a single DIE pattern against the document.

        Args:
            pattern_info: Pattern entry (string or dict).
            sig_info: Tuple of (name, type, version).
            ep_bytes: Entry point bytes for EP matching.
            results: List to append matches to.
        """
        if isinstance(pattern_info, str):
            hex_pattern, scan_offset = pattern_info, "ep"
        elif isinstance(pattern_info, dict):
            typed_info = cast("dict[str, Any]", pattern_info)
            hex_pattern = str(typed_info.get("pattern", ""))
            scan_offset = str(typed_info.get("offset", "ep"))
        else:
            return

        try:
            pattern_bytes = bytes.fromhex(hex_pattern.replace(" ", ""))
        except ValueError:
            _logger.debug("die_pattern_invalid_hex", hex_pattern=hex_pattern, exc_info=True)
            return

        sig_name, sig_type, sig_version = sig_info

        if scan_offset == "ep":
            idx = ep_bytes.find(pattern_bytes)
            if idx >= 0:
                results.append({
                    "name": sig_name,
                    "type": sig_type,
                    "version": sig_version,
                    "offset": idx,
                    "details": f"Entry point match at +{idx}",
                })
        elif scan_offset == "any":
            idx = self._read_all_doc_bytes().find(pattern_bytes)
            if idx >= 0:
                results.append({
                    "name": sig_name,
                    "type": sig_type,
                    "version": sig_version,
                    "offset": idx,
                    "details": f"Full scan match at 0x{idx:X}",
                })
        else:
            try:
                fixed_offset = int(scan_offset, 0)
            except ValueError:
                _logger.debug("die_pattern_invalid_offset", scan_offset=scan_offset, exc_info=True)
                return
            if self.document is not None and fixed_offset + len(pattern_bytes) <= self.document.length():
                region = self._read_doc_bytes(fixed_offset, len(pattern_bytes))
                if region == pattern_bytes:
                    results.append({
                        "name": sig_name,
                        "type": sig_type,
                        "version": sig_version,
                        "offset": fixed_offset,
                        "details": f"Fixed offset match at 0x{fixed_offset:X}",
                    })

    async def scan_clamav_signatures(self, db_path: str) -> list[dict[str, Any]]:
        """Scan document against ClamAV .ndb or .hdb signature files.

        Args:
            db_path: Path to the .ndb or .hdb file.

        Returns:
            list[dict[str, Any]]: List of match dicts.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        path = Path(db_path)
        suffix = path.suffix.lower()
        lines_text = await asyncio.to_thread(path.read_text, encoding="utf-8", errors="replace")
        lines = lines_text.splitlines()

        if suffix == ".hdb":
            return self._scan_clamav_hdb(lines)
        return self._scan_clamav_ndb(lines)

    def _scan_clamav_hdb(self, lines: list[str]) -> list[dict[str, Any]]:
        """Scan ClamAV hash-based (.hdb) signatures.

        Args:
            lines: Lines from the .hdb file.

        Returns:
            list[dict[str, Any]]: Match results.
        """
        data = self._read_all_doc_bytes()
        file_md5 = hashlib.md5(data).hexdigest()  # noqa: S324
        file_size = len(data)
        results: list[dict[str, Any]] = []
        hdb_fields = 3

        for line in lines:
            parts = line.strip().split(":")
            if len(parts) < hdb_fields:
                continue
            sig_md5 = parts[0].lower()
            sig_name = parts[2]
            try:
                sig_size = int(parts[1])
            except ValueError:
                _logger.debug("clamav_hdb_invalid_size", line=line, exc_info=True)
                continue
            if sig_md5 == file_md5 and sig_size == file_size:
                results.append({
                    "name": sig_name,
                    "type": "hash",
                    "version": "",
                    "offset": 0,
                    "details": f"MD5 hash match (size={file_size})",
                })

        _logger.info("clamav_hdb_scan_completed", matches=len(results))
        return results

    def _scan_clamav_ndb(self, lines: list[str]) -> list[dict[str, Any]]:
        """Scan ClamAV pattern-based (.ndb) signatures.

        Args:
            lines: Lines from the .ndb file.

        Returns:
            list[dict[str, Any]]: Match results.
        """
        data = self._read_all_doc_bytes()
        results: list[dict[str, Any]] = []
        ndb_fields = 4

        for line in lines:
            parts = line.strip().split(":")
            if len(parts) < ndb_fields:
                continue
            sig_name = parts[0]
            sig_offset_spec = parts[2]
            sig_hex = parts[3]
            try:
                clean_hex = sig_hex.replace("*", "").replace("?", "")
                if not clean_hex:
                    continue
                pattern_bytes = bytes.fromhex(clean_hex)
            except ValueError:
                _logger.debug("clamav_ndb_invalid_hex", sig_hex=sig_hex, exc_info=True)
                continue

            if sig_offset_spec == "*":
                idx = data.find(pattern_bytes)
                if idx >= 0:
                    results.append({
                        "name": sig_name,
                        "type": "ndb",
                        "version": "",
                        "offset": idx,
                        "details": f"Pattern match at 0x{idx:X}",
                    })
            elif sig_offset_spec.startswith("EP") and data[: len(pattern_bytes)] == pattern_bytes:
                results.append({
                    "name": sig_name,
                    "type": "ndb",
                    "version": "",
                    "offset": 0,
                    "details": "Entry point match",
                })
            else:
                try:
                    offset_val = int(sig_offset_spec, 0)
                except ValueError:
                    _logger.debug("clamav_ndb_invalid_offset", sig_offset_spec=sig_offset_spec, exc_info=True)
                    continue
                end_pos = offset_val + len(pattern_bytes)
                if end_pos <= len(data) and data[offset_val:end_pos] == pattern_bytes:
                    results.append({
                        "name": sig_name,
                        "type": "ndb",
                        "version": "",
                        "offset": offset_val,
                        "details": f"Fixed offset match at 0x{offset_val:X}",
                    })

        _logger.info("clamav_ndb_scan_completed", matches=len(results))
        return results

    async def scan_custom_signatures(self, sig_file: str) -> list[dict[str, Any]]:
        """Scan document against a custom JSON signature database.

        Args:
            sig_file: Path to the custom JSON signature file.

        Returns:
            list[dict[str, Any]]: List of match dicts.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        text = await asyncio.to_thread(Path(sig_file).read_text, encoding="utf-8")
        entries: list[dict[str, str]] = json.loads(text)
        data = self._read_all_doc_bytes()
        results: list[dict[str, Any]] = []
        max_ep_bytes = 256

        for entry in entries:
            sig_name = entry.get("name", "unknown")
            hex_pattern = entry.get("pattern", "")
            offset_spec = entry.get("offset", "any")
            sig_type = entry.get("type", "unknown")

            try:
                pattern_bytes = bytes.fromhex(hex_pattern.replace(" ", ""))
            except ValueError:
                _logger.debug("custom_signature_invalid_hex", sig_name=sig_name, hex_pattern=hex_pattern, exc_info=True)
                continue

            if offset_spec == "ep":
                idx = data[:max_ep_bytes].find(pattern_bytes)
                if idx >= 0:
                    results.append({
                        "name": sig_name,
                        "type": sig_type,
                        "version": "",
                        "offset": idx,
                        "details": f"Entry point match at +{idx}",
                    })
            elif offset_spec == "any":
                idx = data.find(pattern_bytes)
                if idx >= 0:
                    results.append({
                        "name": sig_name,
                        "type": sig_type,
                        "version": "",
                        "offset": idx,
                        "details": f"Full scan match at 0x{idx:X}",
                    })
            else:
                try:
                    fixed_offset = int(offset_spec, 0)
                except ValueError:
                    _logger.debug("custom_signature_invalid_offset", sig_name=sig_name, offset_spec=offset_spec, exc_info=True)
                    continue
                end_pos = fixed_offset + len(pattern_bytes)
                if end_pos <= len(data) and data[fixed_offset:end_pos] == pattern_bytes:
                    results.append({
                        "name": sig_name,
                        "type": sig_type,
                        "version": "",
                        "offset": fixed_offset,
                        "details": f"Fixed offset match at 0x{fixed_offset:X}",
                    })

        _logger.info("custom_sig_scan_completed", matches=len(results))
        return results

    async def export_patches_bps(self, original_path: str) -> str:
        """Export a BPS patch comparing the current document against the original.

        Args:
            original_path: Path to the original unmodified file.

        Returns:
            str: Base64-encoded BPS patch data.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        source_data = await asyncio.to_thread(Path(original_path).read_bytes)
        target_data = self._read_all_doc_bytes()

        if hasattr(self.document, "export_patches_bps"):
            raw: bytes = self.document.export_patches_bps(source_data)
        else:
            raw = self._build_bps_patch(source_data, target_data)

        _logger.info("bps_patch_exported", size=len(raw))
        return base64.b64encode(raw).decode("ascii")

    async def import_patches_bps(self, patch_b64: str, original_path: str) -> dict[str, int]:
        """Import and apply a BPS patch.

        Args:
            patch_b64: Base64-encoded BPS patch data.
            original_path: Path to the original source file.

        Returns:
            dict[str, int]: Dict with target_size.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        patch_data = base64.b64decode(patch_b64)
        source_data = await asyncio.to_thread(Path(original_path).read_bytes)

        if hasattr(self.document, "import_patches_bps"):
            self.document.import_patches_bps(patch_data, source_data)
        else:
            target = self._apply_bps_patch(patch_data, source_data)
            _logger.info("file_written", path="document", offset=hex(0), size=len(target), op="bps_patch_apply")
            self.document.write_bytes(0, target)

        doc_len: int = self.document.length()
        _logger.info("bps_patch_imported", target_size=doc_len)
        if self.state_holder is not None:
            self.state_holder.notify_data_modified(0, doc_len, source="bridge")
        return {"target_size": doc_len}

    async def export_patches_ups(self, original_path: str) -> str:
        """Export a UPS patch comparing the current document against the original.

        Args:
            original_path: Path to the original unmodified file.

        Returns:
            str: Base64-encoded UPS patch data.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        source_data = await asyncio.to_thread(Path(original_path).read_bytes)
        target_data = self._read_all_doc_bytes()

        if hasattr(self.document, "export_patches_ups"):
            raw: bytes = self.document.export_patches_ups(source_data)
        else:
            raw = self._build_ups_patch(source_data, target_data)

        _logger.info("ups_patch_exported", size=len(raw))
        return base64.b64encode(raw).decode("ascii")

    async def import_patches_ups(self, patch_b64: str, original_path: str) -> dict[str, int]:
        """Import and apply a UPS patch.

        Args:
            patch_b64: Base64-encoded UPS patch data.
            original_path: Path to the original source file.

        Returns:
            dict[str, int]: Dict with target_size.

        Raises:
            RuntimeError: If no document is open.
        """
        if self.document is None:
            _logger.error("operation_failed_no_document_open")
            msg = "no document open"
            raise RuntimeError(msg)

        patch_data = base64.b64decode(patch_b64)
        source_data = await asyncio.to_thread(Path(original_path).read_bytes)

        if hasattr(self.document, "import_patches_ups"):
            self.document.import_patches_ups(patch_data, source_data)
        else:
            target = self._apply_ups_patch(patch_data, source_data)
            _logger.info("file_written", path="document", offset=hex(0), size=len(target), op="ups_patch_apply")
            self.document.write_bytes(0, target)

        doc_len: int = self.document.length()
        _logger.info("ups_patch_imported", target_size=doc_len)
        if self.state_holder is not None:
            self.state_holder.notify_data_modified(0, doc_len, source="bridge")
        return {"target_size": doc_len}

    @staticmethod
    def _encode_bps_var_int(val: int) -> bytes:
        """Encode a variable-length integer in BPS format.

        Args:
            val: Non-negative integer value.

        Returns:
            bytes: Encoded bytes.
        """
        result = bytearray()
        while True:
            byte = val & 0x7F
            val >>= 7
            if val == 0:
                result.append(byte | 0x80)
                break
            result.append(byte)
            val -= 1
        return bytes(result)

    @staticmethod
    def _decode_bps_var_int(data: bytes, pos: int) -> tuple[int, int]:
        """Decode a variable-length integer in BPS format.

        Args:
            data: Source byte array.
            pos: Current read position.

        Returns:
            tuple[int, int]: Decoded value and new position.
        """
        result = 0
        shift = 0
        while pos < len(data):
            byte = data[pos]
            pos += 1
            result += (byte & 0x7F) << shift
            if byte & 0x80:
                return result, pos
            shift += 7
            result += 1 << shift
        return result, pos

    @staticmethod
    def _crc32_compute(data: bytes) -> int:
        """Compute CRC32 of data using zlib.

        Args:
            data: Input bytes.

        Returns:
            int: CRC32 value as unsigned 32-bit integer.
        """
        return zlib.crc32(data) & _CRC32_MASK

    def _build_bps_patch(self, source: bytes, target: bytes) -> bytes:
        """Build a BPS patch from source and target data.

        Args:
            source: Original file data.
            target: Modified file data.

        Returns:
            bytes: Complete BPS patch binary.
        """
        patch = bytearray(b"BPS1")
        patch.extend(self._encode_bps_var_int(len(source)))
        patch.extend(self._encode_bps_var_int(len(target)))
        patch.extend(self._encode_bps_var_int(0))

        src_pos = 0
        tgt_pos = 0

        while tgt_pos < len(target):
            match_len = 0
            while (
                src_pos + match_len < len(source)
                and tgt_pos + match_len < len(target)
                and source[src_pos + match_len] == target[tgt_pos + match_len]
            ):
                match_len += 1

            if match_len > 0:
                patch.extend(self._encode_bps_var_int((match_len - 1) << 2))
                src_pos += match_len
                tgt_pos += match_len

            if tgt_pos >= len(target):
                break

            diff_len = 0
            max_diff = 256
            while tgt_pos + diff_len < len(target) and diff_len < max_diff:
                if src_pos + diff_len < len(source) and source[src_pos + diff_len] == target[tgt_pos + diff_len]:
                    ahead = 0
                    while (
                        src_pos + diff_len + ahead < len(source)
                        and tgt_pos + diff_len + ahead < len(target)
                        and source[src_pos + diff_len + ahead] == target[tgt_pos + diff_len + ahead]
                    ):
                        ahead += 1
                    min_ahead_match = 4
                    if ahead >= min_ahead_match:
                        break
                diff_len += 1

            if diff_len > 0:
                patch.extend(self._encode_bps_var_int(((diff_len - 1) << 2) | 1))
                patch.extend(target[tgt_pos : tgt_pos + diff_len])
                src_pos += diff_len
                tgt_pos += diff_len

        source_crc = self._crc32_compute(source)
        target_crc = self._crc32_compute(target)
        patch.extend(struct.pack("<I", source_crc))
        patch.extend(struct.pack("<I", target_crc))

        patch_crc = self._crc32_compute(bytes(patch))
        patch.extend(struct.pack("<I", patch_crc))
        return bytes(patch)

    def _apply_bps_patch(self, patch: bytes, source: bytes) -> bytes:
        """Apply a BPS patch to produce the target data.

        Args:
            patch: BPS patch binary data.
            source: Original source data.

        Returns:
            bytes: Patched target data.

        Raises:
            ValueError: If the patch is invalid or CRC verification fails.
        """
        self._validate_bps_header(patch, source)
        footer_start = len(patch) - _BPS_MIN_PATCH_SIZE
        stored_target_crc = struct.unpack_from("<I", patch, footer_start + 4)[0]

        pos = 4
        _, pos = self._decode_bps_var_int(patch, pos)
        target_size, pos = self._decode_bps_var_int(patch, pos)
        metadata_size, pos = self._decode_bps_var_int(patch, pos)
        pos += metadata_size

        target = bytearray(target_size)
        state = [0, 0, 0]

        while pos < footer_start:
            action, pos = self._decode_bps_var_int(patch, pos)
            pos = self._exec_bps_command(action, patch, source, target, pos, footer_start, state)

        if self._crc32_compute(bytes(target)) != stored_target_crc:
            _logger.error("apply_bps_patch_failed_target_crc_mismatch", target_size=len(target))
            msg = "target CRC mismatch"
            raise ValueError(msg)
        return bytes(target)

    def _validate_bps_header(self, patch: bytes, source: bytes) -> None:
        """Validate BPS patch header and CRC checksums.

        Args:
            patch: BPS patch data.
            source: Original source data.

        Raises:
            ValueError: If validation fails.
        """
        if len(patch) < _BPS_MIN_PATCH_SIZE or patch[:4] != b"BPS1":
            _logger.error(
                "validate_bps_header_failed_invalid_patch",
                patch_size=len(patch),
                magic_hex=patch[:_MIN_HEADER_SIZE].hex() if len(patch) >= _MIN_HEADER_SIZE else "",
            )
            msg = "invalid BPS patch"
            raise ValueError(msg)
        if self._crc32_compute(patch[:-4]) != struct.unpack_from("<I", patch, len(patch) - 4)[0]:
            _logger.error("validate_bps_header_failed_patch_crc_mismatch")
            msg = "BPS patch CRC mismatch"
            raise ValueError(msg)
        footer_start = len(patch) - _BPS_MIN_PATCH_SIZE
        if self._crc32_compute(source) != struct.unpack_from("<I", patch, footer_start)[0]:
            _logger.error("validate_bps_header_failed_source_crc_mismatch", source_size=len(source))
            msg = "source CRC mismatch"
            raise ValueError(msg)

    def _exec_bps_command(
        self,
        action: int,
        patch: bytes,
        source: bytes,
        target: bytearray,
        pos: int,
        footer_start: int,
        state: list[int],
    ) -> int:
        """Execute a single BPS patch command.

        Args:
            action: Encoded action value.
            patch: Full patch data.
            source: Original source data.
            target: Target buffer being built.
            pos: Current read position in the patch.
            footer_start: End-of-data marker position.
            state: Mutable list [output_offset, source_rel_offset, target_rel_offset].

        Returns:
            int: Updated read position.
        """
        command = action & 3
        length = (action >> 2) + 1

        if command == _BPS_CMD_SOURCE_READ:
            for _ in range(length):
                if state[0] < len(target) and state[0] < len(source):
                    target[state[0]] = source[state[0]]
                state[0] += 1
        elif command == _BPS_CMD_TARGET_READ:
            for _ in range(length):
                if pos < footer_start and state[0] < len(target):
                    target[state[0]] = patch[pos]
                    pos += 1
                    state[0] += 1
        elif command == _BPS_CMD_SOURCE_COPY:
            offset_data, pos = self._decode_bps_var_int(patch, pos)
            delta = -(offset_data >> 1) if offset_data & 1 else offset_data >> 1
            state[1] += delta
            for _ in range(length):
                if 0 <= state[1] < len(source) and state[0] < len(target):
                    target[state[0]] = source[state[1]]
                state[1] += 1
                state[0] += 1
        elif command == _BPS_CMD_TARGET_COPY:
            offset_data, pos = self._decode_bps_var_int(patch, pos)
            delta = -(offset_data >> 1) if offset_data & 1 else offset_data >> 1
            state[2] += delta
            for _ in range(length):
                if 0 <= state[2] < len(target) and state[0] < len(target):
                    target[state[0]] = target[state[2]]
                state[2] += 1
                state[0] += 1
        return pos

    def _build_ups_patch(self, source: bytes, target: bytes) -> bytes:
        """Build a UPS patch from source and target data.

        Args:
            source: Original file data.
            target: Modified file data.

        Returns:
            bytes: Complete UPS patch binary.
        """
        patch = bytearray(b"UPS1")
        patch.extend(self._encode_bps_var_int(len(source)))
        patch.extend(self._encode_bps_var_int(len(target)))

        max_len = max(len(source), len(target))
        write_pos = 0
        offset = 0

        while offset < max_len:
            src_byte = source[offset] if offset < len(source) else 0
            tgt_byte = target[offset] if offset < len(target) else 0
            xor_val = src_byte ^ tgt_byte

            if xor_val != 0:
                rel_offset = offset - write_pos
                patch.extend(self._encode_bps_var_int(rel_offset))

                while offset < max_len:
                    s = source[offset] if offset < len(source) else 0
                    t = target[offset] if offset < len(target) else 0
                    x = s ^ t
                    patch.append(x)
                    offset += 1
                    if x == 0:
                        break
                write_pos = offset
            else:
                offset += 1

        source_crc = self._crc32_compute(source)
        target_crc = self._crc32_compute(target)
        patch.extend(struct.pack("<I", source_crc))
        patch.extend(struct.pack("<I", target_crc))

        patch_crc = self._crc32_compute(bytes(patch))
        patch.extend(struct.pack("<I", patch_crc))
        return bytes(patch)

    def _apply_ups_patch(self, patch: bytes, source: bytes) -> bytes:
        """Apply a UPS patch to produce the target data.

        Args:
            patch: UPS patch binary data.
            source: Original source data.

        Returns:
            bytes: Patched target data.

        Raises:
            ValueError: If the patch is invalid or CRC verification fails.
        """
        min_patch_size = 16
        if len(patch) < min_patch_size or patch[:4] != b"UPS1":
            msg = "invalid UPS patch"
            raise ValueError(msg)

        patch_body_crc = self._crc32_compute(patch[:-4])
        stored_patch_crc = struct.unpack_from("<I", patch, len(patch) - 4)[0]
        if patch_body_crc != stored_patch_crc:
            msg = "UPS patch CRC mismatch"
            raise ValueError(msg)

        footer_start = len(patch) - 12
        stored_source_crc = struct.unpack_from("<I", patch, footer_start)[0]
        stored_target_crc = struct.unpack_from("<I", patch, footer_start + 4)[0]

        if self._crc32_compute(source) != stored_source_crc:
            msg = "source CRC mismatch"
            raise ValueError(msg)

        pos = 4
        _source_size, pos = self._decode_bps_var_int(patch, pos)
        target_size, pos = self._decode_bps_var_int(patch, pos)

        target = bytearray(source)
        target_len = target_size
        if len(target) < target_len:
            target.extend(bytes(target_len - len(target)))
        elif len(target) > target_len:
            target = target[:target_len]

        data_offset = 0
        while pos < footer_start:
            rel_offset, pos = self._decode_bps_var_int(patch, pos)
            data_offset += rel_offset

            while pos < footer_start:
                xor_byte = patch[pos]
                pos += 1
                if xor_byte == 0:
                    data_offset += 1
                    break
                if data_offset < len(target):
                    target[data_offset] ^= xor_byte
                data_offset += 1

        if self._crc32_compute(bytes(target)) != stored_target_crc:
            msg = "target CRC mismatch"
            raise ValueError(msg)

        return bytes(target)


_PRINTABLE_PDF_LO = 32
_PRINTABLE_PDF_HI = 126


def _generate_pdf(
    output_path: str,
    data: bytes,
    start_offset: int,
    bytes_per_row: int,
    bookmark_map: dict[int, dict[str, object]],
    bookmarks: list[dict[str, object]],
    doc_size: int,
) -> str:
    """Generate an annotated hex dump PDF.

    Args:
        output_path: Destination file path for the PDF.
        data: Binary data to render.
        start_offset: Absolute file offset of the first byte in data.
        bytes_per_row: Number of bytes per hex row.
        bookmark_map: Map from absolute offset to bookmark dict.
        bookmarks: List of bookmark metadata dicts.
        doc_size: Total document size in bytes.

    Returns:
        str: The written file path.
    """
    import importlib  # noqa: PLC0415

    fpdf_mod = importlib.import_module("fpdf")
    fpdf_cls = cast("type[_FPDFProtocol]", fpdf_mod.FPDF)
    pdf: _FPDFProtocol = fpdf_cls(orientation="L", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=10)

    pdf.add_page()
    pdf.set_font("Courier", "B", 14)
    pdf.cell(0, 10, "Hex Dump Report", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("Courier", "", 9)
    pdf.cell(0, 6, f"Document size: {doc_size} bytes (0x{doc_size:X})", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(
        0,
        6,
        f"Range: 0x{start_offset:08X} - 0x{start_offset + len(data):08X} ({len(data)} bytes)",
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.ln(4)

    _pdf_render_bookmarks(pdf, bookmarks)

    col_widths = (22.0, 2.7 * bytes_per_row + 4, 1.8 * bytes_per_row + 2)
    pdf.set_font("Courier", "B", 7)
    pdf.cell(col_widths[0], 4, "Offset")
    pdf.cell(col_widths[1], 4, "Hex")
    pdf.cell(col_widths[2], 4, "ASCII")
    pdf.ln(4)
    pdf.set_font("Courier", "", 6)

    _pdf_render_hex_rows(pdf, data, start_offset, bytes_per_row, bookmark_map, col_widths)
    pdf.output(output_path)
    return output_path


def _pdf_render_bookmarks(
    pdf: _FPDFProtocol,
    bookmarks: list[dict[str, object]],
) -> None:
    """Render bookmark legend section into a PDF.

    Args:
        pdf: FPDF instance.
        bookmarks: List of bookmark metadata dicts.
    """
    if not bookmarks:
        return

    pdf.set_font("Courier", "B", 10)
    pdf.cell(0, 6, "Bookmarks:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Courier", "", 8)
    seen: set[str] = set()
    for bm in bookmarks:
        label = str(bm.get("label", ""))
        if label and label not in seen:
            seen.add(label)
            pdf.cell(
                0,
                5,
                f"  {label}: 0x{bm.get('offset', 0):X} ({bm.get('length', 0)} bytes)",
                new_x="LMARGIN",
                new_y="NEXT",
            )
    pdf.ln(4)


def _pdf_render_hex_rows(
    pdf: _FPDFProtocol,
    data: bytes,
    start_offset: int,
    bytes_per_row: int,
    bookmark_map: dict[int, dict[str, object]],
    col_widths: tuple[float, float, float],
) -> None:
    """Render hex dump rows into a PDF.

    Args:
        pdf: FPDF instance.
        data: Binary data to render.
        start_offset: Absolute file offset of the first byte.
        bytes_per_row: Bytes per row.
        bookmark_map: Offset-to-bookmark lookup.
        col_widths: Column widths as (offset, hex, ascii).
    """
    for row_start in range(0, len(data), bytes_per_row):
        abs_off = start_offset + row_start
        row_data = data[row_start : row_start + bytes_per_row]

        hex_parts: list[str] = []
        ascii_parts: list[str] = []
        has_bookmark = False

        for j, b in enumerate(row_data):
            hex_parts.append(f"{b:02X}")
            ascii_parts.append(chr(b) if _PRINTABLE_PDF_LO <= b <= _PRINTABLE_PDF_HI else ".")
            if abs_off + j in bookmark_map:
                has_bookmark = True

        if has_bookmark:
            pdf.set_fill_color(230, 240, 255)
            pdf.cell(col_widths[0], 3.5, f"{abs_off:08X}", fill=True)
            pdf.cell(col_widths[1], 3.5, " ".join(hex_parts), fill=True)
            pdf.cell(col_widths[2], 3.5, "".join(ascii_parts), fill=True)
        else:
            pdf.cell(col_widths[0], 3.5, f"{abs_off:08X}")
            pdf.cell(col_widths[1], 3.5, " ".join(hex_parts))
            pdf.cell(col_widths[2], 3.5, "".join(ascii_parts))

        pdf.ln(3.5)
