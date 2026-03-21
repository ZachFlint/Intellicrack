# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Hex editor bridge wrapping the Rust-powered intellicrack_hexcore.

Provides hex editing, search, hash, template, and diff operations
via the native Rust HexDocument backed by a piece table with
memory-mapped I/O for large file support.
"""

from __future__ import annotations

import asyncio
import base64
import inspect as _inspect_mod
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from ..core.logging import get_logger
from ..core.types import ToolDefinition, ToolFunction, ToolName, ToolParameter
from .base import BridgeCapabilities, ToolBridgeBase


if TYPE_CHECKING:
    from ..core.tools import ToolRegistry
    from .hex_state import HexDocumentState


_hexcore_mod: Any = None
_hexcore_available: bool = False

try:
    import intellicrack_hexcore

    _hexcore_mod = intellicrack_hexcore
    _hexcore_available = True
except ImportError:
    pass

_logger = get_logger("bridges.hex_editor")
if not _hexcore_available:
    _logger.debug("hexcore_import_unavailable")


class HexEditorBridge(ToolBridgeBase):
    """Bridge for the built-in hex editor powered by Rust.

    Wraps the ``intellicrack_hexcore.HexDocument`` class to provide
    hex editing, searching, hashing, data inspection, template
    parsing, and binary diffing through the standard bridge interface.

    Attributes:
        _document: Active HexDocument instance or None.
        _cursor_offset: Current logical cursor position.
        _selection: Current selection range or None.
        _hexcore_available: Whether the Rust extension is importable.
    """

    def __init__(self) -> None:
        """Initialize the hex editor bridge."""
        super().__init__()
        self._document: Any | None = None
        self._cursor_offset: int = 0
        self._selection: tuple[int, int] | None = None
        self._hexcore_available: bool = _hexcore_available
        self._state_holder: HexDocumentState | None = None
        self._tool_registry: ToolRegistry | None = None
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
        self._state_holder = state_holder

    def set_tool_registry(self, registry: ToolRegistry) -> None:
        """Set the tool registry for cross-bridge access.

        Args:
            registry: The ToolRegistry providing access to other bridges.
        """
        self._tool_registry = registry

    @property
    def name(self) -> ToolName:
        """Get the tool name.

        Returns:
            ToolName.HEX_EDITOR enum value.
        """
        return ToolName.HEX_EDITOR

    @property
    def tool_definition(self) -> ToolDefinition:
        """Get tool definition for LLM function calling.

        Returns:
            ToolDefinition with all hex editor functions.
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
                            name="case_sensitive", type="boolean", description="Case-sensitive match.", required=False, default=True
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
                        ToolParameter(name="algorithm", type="string", description="Hash algorithm.", required=False, default="sha256")
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
                        ToolParameter(name="fmt", type="string", description="Output format.", enum=["hex", "c_array", "python", "base64"]),
                    ],
                    returns="Formatted string",
                ),
                ToolFunction(
                    name="hex_editor.save",
                    description="Save the document.",
                    parameters=[
                        ToolParameter(name="path", type="string", description="Save path (uses original if omitted).", required=False)
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
            ],
        )

    async def initialize(self, tool_path: Path | None = None) -> None:
        """Initialize the hex editor bridge.

        Args:
            tool_path: Unused for this bridge.
        """
        _ = tool_path
        if self._hexcore_available:
            self._state.connected = True
            self._state.tool_running = True
            _logger.info("hex_editor_initialized", backend="rust_hexcore")
        else:
            self._state.connected = False
            self._state.tool_running = False
            _logger.warning("hex_editor_backend_unavailable", backend="intellicrack_hexcore")

    async def is_available(self) -> bool:
        """Check if the Rust hex core is available.

        Returns:
            True if intellicrack_hexcore is importable.
        """
        return self._hexcore_available

    async def shutdown(self) -> None:
        """Shutdown the hex editor bridge."""
        if self._document is not None:
            self._document = None
        self._cursor_offset = 0
        self._selection = None
        _logger.debug("hex_editor_shutdown")
        await super().shutdown()

    async def open_file(self, path: str) -> dict[str, Any]:
        """Open a binary file in the hex editor.

        Args:
            path: Filesystem path to the file.

        Returns:
            Dict with file_path, size, and modified status.

        Raises:
            RuntimeError: If the Rust core is not available.
        """
        if not self._hexcore_available or _hexcore_mod is None:
            msg = "intellicrack_hexcore not installed"
            raise RuntimeError(msg)

        self._document = _hexcore_mod.HexDocument.open(path)
        if self._document is None:
            msg = f"failed to open {path}"
            raise RuntimeError(msg)
        self._cursor_offset = 0
        self._selection = None
        self._state.binary_loaded = True
        self._state.target_path = Path(path)

        doc_len: int = self._document.length()
        _logger.info("file_opened", path=path, size=doc_len)

        if self._state_holder is not None:
            self._state_holder.set_document(self._document, Path(path), source="bridge")

        return {
            "file_path": path,
            "size": doc_len,
            "modified": False,
        }

    async def close_file(self) -> bool:
        """Close the currently open file.

        Returns:
            True if a file was closed.
        """
        if self._document is None:
            return False

        self._document = None
        self._cursor_offset = 0
        self._selection = None
        self._state.binary_loaded = False
        self._state.target_path = None
        if self._state_holder is not None:
            self._state_holder.set_document(None, None, source="bridge")
        _logger.info("file_closed")
        return True

    async def read_bytes(self, offset: int, length: int) -> str:
        """Read bytes from the document as a hex string.

        Args:
            offset: Byte offset to read from.
            length: Number of bytes to read.

        Returns:
            Hex string of the read bytes.

        Raises:
            RuntimeError: If no document is open.
        """
        if self._document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        _logger.debug("bytes_read", offset=hex(offset), length=length)
        raw = self._document.read(offset, length)
        return " ".join(f"{b:02X}" for b in raw)

    async def write_bytes(self, offset: int, data_hex: str) -> bool:
        """Overwrite bytes at offset.

        Args:
            offset: Byte offset to write at.
            data_hex: Hex string of bytes (e.g. "4D 5A 90").

        Returns:
            True if the write succeeded.

        Raises:
            RuntimeError: If no document is open.
        """
        if self._document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        data = bytes.fromhex(data_hex.replace(" ", ""))
        self._document.write_bytes(offset, data)
        _logger.debug("bytes_written", offset=hex(offset), length=len(data))
        if self._state_holder is not None:
            self._state_holder.notify_data_modified(offset, len(data), source="bridge")
        return True

    async def insert_bytes(self, offset: int, data_hex: str) -> bool:
        """Insert bytes at offset.

        Args:
            offset: Byte offset for insertion.
            data_hex: Hex string of bytes to insert.

        Returns:
            True if the insert succeeded.

        Raises:
            RuntimeError: If no document is open.
        """
        if self._document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        data = bytes.fromhex(data_hex.replace(" ", ""))
        self._document.insert_bytes(offset, data)
        _logger.debug("bytes_inserted", offset=hex(offset), length=len(data))
        if self._state_holder is not None:
            self._state_holder.notify_data_modified(offset, len(data), source="bridge")
        return True

    async def delete_bytes(self, offset: int, length: int) -> bool:
        """Delete bytes at offset.

        Args:
            offset: Start offset.
            length: Number of bytes to delete.

        Returns:
            True if the delete succeeded.

        Raises:
            RuntimeError: If no document is open.
        """
        if self._document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        self._document.delete_bytes(offset, length)
        _logger.debug("bytes_deleted", offset=hex(offset), length=length)
        if self._state_holder is not None:
            self._state_holder.notify_data_modified(offset, length, source="bridge")
        return True

    async def goto_offset(self, offset: int) -> bool:
        """Set the logical cursor position.

        Args:
            offset: Target byte offset.

        Returns:
            True always.
        """
        self._cursor_offset = offset
        _logger.debug("cursor_moved", offset=hex(offset))
        if self._state_holder is not None:
            self._state_holder.set_cursor(offset, source="bridge")
        return True

    async def get_cursor_position(self) -> int:
        """Get the current cursor position.

        Returns:
            Current byte offset of the cursor.
        """
        return self._cursor_offset

    async def select_range(self, start: int, end: int) -> bool:
        """Set the selection range.

        Args:
            start: Selection start offset.
            end: Selection end offset.

        Returns:
            True always.
        """
        self._selection = (start, end)
        _logger.debug("range_selected", start=hex(start), end=hex(end))
        if self._state_holder is not None:
            self._state_holder.set_selection(start, end, source="bridge")
        return True

    async def get_selection(self) -> tuple[int, int] | None:
        """Get the current selection range.

        Returns:
            Tuple of (start, end) offsets, or None if no selection.
        """
        return self._selection

    async def search_hex(self, pattern: str, max_results: int = 100) -> list[dict[str, int]]:
        """Search for a hex pattern with optional wildcards.

        Args:
            pattern: Hex pattern string (e.g. "4D 5A ?? 00").
            max_results: Maximum number of results to return.

        Returns:
            List of dicts with offset and length keys.

        Raises:
            RuntimeError: If no document is open.
        """
        if self._document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        results = self._document.search_hex(pattern, max_results)
        _logger.debug("search_hex_completed", pattern=pattern, matches=len(results))
        return [{"offset": r[0], "length": r[1]} for r in results]

    async def search_text(
        self,
        text: str,
        encoding: str = "utf-8",
        case_sensitive: bool = True,
        max_results: int = 100,
    ) -> list[dict[str, int]]:
        """Search for text with encoding support.

        Args:
            text: Text string to search for.
            encoding: Text encoding (utf-8, utf-16le, ascii).
            case_sensitive: Whether the search is case-sensitive.
            max_results: Maximum number of results.

        Returns:
            List of dicts with offset and length keys.

        Raises:
            RuntimeError: If no document is open.
        """
        if self._document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        results = self._document.search_text(text, encoding, case_sensitive, max_results)
        _logger.debug("search_text_completed", encoding=encoding, matches=len(results))
        return [{"offset": r[0], "length": r[1]} for r in results]

    async def search_regex(self, pattern: str, max_results: int = 100) -> list[dict[str, int]]:
        """Search using a regular expression.

        Args:
            pattern: Regex pattern string.
            max_results: Maximum number of results.

        Returns:
            List of dicts with offset and length keys.

        Raises:
            RuntimeError: If no document is open.
        """
        if self._document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        results = self._document.search_regex(pattern, max_results)
        _logger.debug("search_regex_completed", pattern=pattern, matches=len(results))
        return [{"offset": r[0], "length": r[1]} for r in results]

    async def replace_bytes(self, pattern_hex: str, replacement_hex: str) -> int:
        """Find and replace all occurrences of a byte pattern.

        Args:
            pattern_hex: Hex string pattern to find (e.g. "4D 5A").
            replacement_hex: Hex string replacement (e.g. "90 90").

        Returns:
            Number of replacements made.

        Raises:
            RuntimeError: If no document is open.
        """
        if self._document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        pattern = list(bytes.fromhex(pattern_hex.replace(" ", "")))
        replacement = list(bytes.fromhex(replacement_hex.replace(" ", "")))
        count: int = self._document.replace_bytes(pattern, replacement)
        _logger.debug("bytes_replaced", pattern_length=len(pattern), replacements=count)
        if count > 0 and self._state_holder is not None:
            self._state_holder.notify_data_modified(0, 0, source="bridge")
        return count

    async def undo(self) -> bool:
        """Undo the last edit operation.

        Returns:
            True if an operation was undone.
        """
        if self._document is None:
            return False
        result: bool = self._document.undo()
        _logger.debug("undo_performed", success=result)
        if result and self._state_holder is not None:
            self._state_holder.notify_data_modified(0, 0, source="bridge")
        return result

    async def redo(self) -> bool:
        """Redo the last undone operation.

        Returns:
            True if an operation was redone.
        """
        if self._document is None:
            return False
        result: bool = self._document.redo()
        _logger.debug("redo_performed", success=result)
        if result and self._state_holder is not None:
            self._state_holder.notify_data_modified(0, 0, source="bridge")
        return result

    async def inspect_data_at(self, offset: int) -> dict[str, str]:
        """Inspect data at offset as multiple type interpretations.

        Args:
            offset: Byte offset to inspect.

        Returns:
            Dict mapping type names to formatted value strings.

        Raises:
            RuntimeError: If no document is open.
        """
        if self._document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        _logger.debug("data_inspected", offset=hex(offset))
        result = self._document.inspect_at(offset)
        if not isinstance(result, dict):
            return {}
        typed = cast("dict[str, object]", result)
        return {k: str(v) for k, v in typed.items()}

    async def calculate_hash(self, algorithm: str = "sha256") -> str:
        """Calculate a hash of the entire document.

        Args:
            algorithm: Hash algorithm (md5, sha1, sha256, sha512, crc32).

        Returns:
            Hex digest string.

        Raises:
            RuntimeError: If no document is open.
        """
        if self._document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        digest: str = self._document.compute_hash(algorithm)
        _logger.debug("hash_calculated", algorithm=algorithm)
        return digest

    async def get_byte_statistics(self) -> list[dict[str, int]]:
        """Get byte frequency statistics for the document.

        Returns:
            List of dicts with byte value and count.

        Raises:
            RuntimeError: If no document is open.
        """
        if self._document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        stats = self._document.byte_statistics()
        _logger.debug("byte_statistics_computed", unique_bytes=len(stats))
        return [{"byte": s[0], "count": s[1]} for s in stats]

    async def apply_template(self, template_name: str, offset: int = 0) -> list[dict[str, Any]]:
        """Apply a struct template at a byte offset.

        Args:
            template_name: Name of the template (e.g. IMAGE_DOS_HEADER).
            offset: Byte offset to apply at.

        Returns:
            List of parsed field dicts with name, offset, size, value.

        Raises:
            RuntimeError: If no document is open.
        """
        if self._document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        _logger.debug("template_applied", template=template_name, offset=hex(offset))
        result = self._document.apply_template(template_name, offset)
        if not isinstance(result, list):
            return []
        typed_list = cast("list[object]", result)
        return [cast("dict[str, Any]", entry) for entry in typed_list if isinstance(entry, dict)]

    async def list_templates(self) -> list[dict[str, str]]:
        """List all available struct templates.

        Returns:
            List of dicts with name and description.
        """
        if self._document is None:
            if not self._hexcore_available or _hexcore_mod is None:
                return []
            doc = _hexcore_mod.HexDocument()
            templates = doc.list_templates()
        else:
            templates = self._document.list_templates()

        _logger.debug("templates_listed", count=len(templates))
        return [{"name": t[0], "description": t[1]} for t in templates]

    async def compare_files(self, path_a: str, path_b: str) -> dict[str, Any]:
        """Compare two files byte-by-byte.

        Args:
            path_a: Path to the first file.
            path_b: Path to the second file.

        Returns:
            Dict with regions, total_differences, and files_identical.

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
            fmt: Output format - "hex", "c_array", "python", "base64".

        Returns:
            Formatted string representation.

        Raises:
            RuntimeError: If no document is open.
        """
        if self._document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        if self._selection is not None:
            start, end = self._selection
            length = end - start + 1
        else:
            start = self._cursor_offset
            length = 1

        raw = self._document.read(start, length)
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
            Index of the new bookmark.

        Raises:
            RuntimeError: If no document is open.
        """
        if self._document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        idx: int = self._document.add_bookmark(offset, length, label, color)
        _logger.debug("bookmark_added", offset=hex(offset), label=label, index=idx)
        return idx

    async def remove_bookmark(self, index: int) -> bool:
        """Remove a bookmark by index.

        Args:
            index: Bookmark index.

        Returns:
            True if the bookmark was removed.

        Raises:
            RuntimeError: If no document is open.
        """
        if self._document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        removed: bool = self._document.remove_bookmark(index)
        _logger.debug("bookmark_removed", index=index, success=removed)
        return removed

    async def list_bookmarks(self) -> list[dict[str, Any]]:
        """List all bookmarks.

        Returns:
            List of dicts with offset, length, label, color.
        """
        if self._document is None:
            return []

        bookmarks = self._document.list_bookmarks()
        _logger.debug("bookmarks_listed", count=len(bookmarks))
        return [{"offset": b[0], "length": b[1], "label": b[2], "color": b[3]} for b in bookmarks]

    async def save(self, path: str | None = None) -> bool:
        """Save the document.

        Args:
            path: Save path. Uses original path if None.

        Returns:
            True if saved successfully.

        Raises:
            RuntimeError: If no document is open.
        """
        if self._document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        if path is not None:
            self._document.save(path)
        else:
            file_path = self._document.file_path()
            if file_path is not None:
                self._document.save(file_path)
            else:
                msg = "no file path; use save_as"
                raise RuntimeError(msg)

        saved_path = path or self._document.file_path() or ""
        _logger.info("file_saved", path=saved_path)
        if self._state_holder is not None:
            self._state_holder.notify_document_saved(str(saved_path), source="bridge")
        return True

    async def save_as(self, path: str) -> bool:
        """Save the document to a new path.

        Args:
            path: New file path.

        Returns:
            True if saved successfully.

        Raises:
            RuntimeError: If no document is open.
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
            Hex digest string.

        Raises:
            RuntimeError: If no document is open.
        """
        if self._document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        digest: str = self._document.compute_hash_range(start, end, algorithm)
        _logger.debug("hash_range_calculated", algorithm=algorithm, start=start, end=end)
        return digest

    async def get_document_info(self) -> dict[str, Any]:
        """Get information about the currently open document.

        Returns:
            Dict with file_path, size, modified, cursor, and selection.
        """
        if self._document is None:
            return {
                "file_path": None,
                "size": 0,
                "modified": False,
                "cursor": 0,
                "selection": None,
            }

        file_path_val = self._document.file_path()
        return {
            "file_path": file_path_val,
            "size": self._document.length(),
            "modified": self._document.is_modified(),
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
            Dict with document info, bytes_at_cursor, inspection,
            selected_bytes, and bookmarks.
        """
        context: dict[str, Any] = await self.get_document_info()

        if self._document is not None:
            cursor = self._cursor_offset
            half = include_bytes // 2
            doc_len: int = self._document.length()
            read_start = max(0, cursor - half)
            read_len = min(include_bytes, doc_len - read_start)
            if read_len > 0:
                raw = self._document.read(read_start, read_len)
                context["bytes_at_cursor"] = " ".join(f"{b:02X}" for b in raw)
                context["bytes_offset"] = read_start
            else:
                context["bytes_at_cursor"] = ""
                context["bytes_offset"] = 0

            try:
                inspection = self._document.inspect_at(cursor)
                if isinstance(inspection, dict):
                    context["inspection"] = {k: str(v) for k, v in cast("dict[str, object]", inspection).items()}
            except Exception:
                context["inspection"] = {}

            if self._selection is not None:
                sel_start, sel_end = self._selection
                sel_len = sel_end - sel_start + 1
                capped = min(sel_len, include_bytes)
                sel_raw = self._document.read(sel_start, capped)
                context["selected_bytes"] = " ".join(f"{b:02X}" for b in sel_raw)
                context["selection_range"] = [sel_start, sel_end]

            bookmarks = self._document.list_bookmarks()
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
            Dict with sandbox_path and status.

        Raises:
            RuntimeError: If no document is open or sandbox unavailable.
        """
        if self._document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        if self._tool_registry is None:
            msg = "tool registry not set; cannot access sandbox bridge"
            raise RuntimeError(msg)

        sandbox_bridge = self._tool_registry.get(ToolName.SANDBOX)
        if sandbox_bridge is None:
            msg = "sandbox bridge not available"
            raise RuntimeError(msg)

        file_path_str = self._document.file_path()
        if file_path_str is None:
            import os  # noqa: PLC0415

            tmp_fd, tmp_path = tempfile.mkstemp(suffix=".bin")
            os.close(tmp_fd)
            self._document.save(tmp_path)
            file_path_str = tmp_path

        copy_fn = getattr(sandbox_bridge, "copy_to_sandbox", None)
        if callable(copy_fn):
            if _inspect_mod.iscoroutinefunction(copy_fn):
                await copy_fn(file_path_str, dest_path, sandbox_type)
            else:
                await asyncio.to_thread(copy_fn, file_path_str, dest_path, sandbox_type)

        _logger.info("saved_to_sandbox", dest=dest_path, sandbox_type=sandbox_type)
        return {"sandbox_path": dest_path, "status": "copied"}

    async def test_in_sandbox(
        self,
        args: str = "",
        sandbox_type: str = "docker",
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Save to sandbox, execute the binary, and return the report.

        Args:
            args: Command-line arguments for the binary.
            sandbox_type: Sandbox type.
            timeout: Execution timeout in seconds.

        Returns:
            Dict with execution report including exit_code, stdout, stderr.

        Raises:
            RuntimeError: If no document is open or sandbox unavailable.
        """
        if self._document is None:
            msg = "no document open"
            raise RuntimeError(msg)

        file_name = "target.bin"
        file_path_str = self._document.file_path()
        if file_path_str is not None:
            file_name = Path(file_path_str).name

        dest_path = f"/sandbox_workdir/{file_name}"
        await self.save_to_sandbox(dest_path, sandbox_type)

        if self._tool_registry is None:
            msg = "tool registry not set"
            raise RuntimeError(msg)

        sandbox_bridge = self._tool_registry.get(ToolName.SANDBOX)
        if sandbox_bridge is None:
            msg = "sandbox bridge not available"
            raise RuntimeError(msg)

        run_fn = getattr(sandbox_bridge, "run_binary", None)
        if not callable(run_fn):
            msg = "sandbox bridge does not support run_binary"
            raise TypeError(msg)

        if _inspect_mod.iscoroutinefunction(run_fn):
            result = await run_fn(dest_path, args, timeout)
        else:
            result = await asyncio.to_thread(run_fn, dest_path, args, timeout)

        _logger.info(
            "sandbox_test_completed",
            dest=dest_path,
            sandbox_type=sandbox_type,
        )
        if isinstance(result, dict):
            return cast("dict[str, Any]", result)
        return {"exit_code": -1, "stdout": "", "stderr": str(result)}
