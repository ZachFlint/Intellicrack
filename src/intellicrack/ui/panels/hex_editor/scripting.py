# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Python scripting mixin for the hex editor panel."""

from __future__ import annotations

import ast
import builtins
import codecs
import hashlib
import io
import re
import sys
import tempfile
import traceback
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, Final, Protocol, cast, override

from PyQt6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat, QTextDocument
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import GenericCallableWorker
from intellicrack.ui.resources.theme_manager import ThemeManager


_logger = get_logger(__name__)


_FONT_FAMILY: Final[str] = "Consolas"
_FONT_SIZE: Final[int] = 10
_OUTPUT_FONT_SIZE: Final[int] = 9
_OUTPUT_MAX_HEIGHT: Final[int] = 200

_FORBIDDEN_ATTRIBUTES: Final[frozenset[str]] = frozenset(
    {
        "__class__",
        "__mro__",
        "__subclasses__",
        "__bases__",
        "__base__",
        "__globals__",
        "__builtins__",
        "__dict__",
        "__code__",
        "__closure__",
        "__func__",
        "__self__",
        "__module__",
        "__qualname__",
        "__getattribute__",
        "__delattr__",
        "__setattr__",
        "__reduce__",
        "__reduce_ex__",
        "__subclasshook__",
        "__init_subclass__",
        "__new__",
        "__import__",
        "func_globals",
        "func_code",
        "func_closure",
        "func_defaults",
        "gi_frame",
        "gi_code",
        "cr_frame",
        "cr_code",
        "f_globals",
        "f_locals",
        "f_builtins",
        "f_back",
        "tb_frame",
        "tb_next",
    },
)

_FORBIDDEN_NAMES: Final[frozenset[str]] = frozenset(
    {
        "__import__",
        "__builtins__",
        "__loader__",
        "__spec__",
        "__name__",
        "__file__",
        "__package__",
        "eval",
        "exec",
        "compile",
        "open",
        "exit",
        "quit",
        "help",
        "input",
        "breakpoint",
        "globals",
        "locals",
        "memoryview",
    },
)

_FORBIDDEN_AST_NODES: Final[tuple[type[ast.AST], ...]] = (
    ast.Import,
    ast.ImportFrom,
    ast.Global,
    ast.Nonlocal,
    ast.AsyncFunctionDef,
    ast.AsyncFor,
    ast.AsyncWith,
    ast.Await,
    ast.Yield,
    ast.YieldFrom,
)

_DOC_WRITE_METHODS: Final[frozenset[str]] = frozenset({"write", "insert", "delete"})

_EXEC_FN: Final[list[Any]] = [builtins.exec]


class _SandboxViolationError(PermissionError):
    """Raised when a script attempts an operation forbidden by the sandbox.

    Using a dedicated subclass keeps exception raise sites clean and still presents as ``PermissionError`` to surrounding callers.
    """

    def __init__(self, message: str) -> None:
        """Initialize the sandbox violation with a descriptive message.

        Args:
            message: Human-readable description of the violation.
        """
        super().__init__(message)


_PYTHON_KEYWORDS: Final[list[str]] = [
    "False",
    "None",
    "True",
    "and",
    "as",
    "assert",
    "async",
    "await",
    "break",
    "class",
    "continue",
    "def",
    "del",
    "elif",
    "else",
    "except",
    "finally",
    "for",
    "from",
    "global",
    "if",
    "import",
    "in",
    "is",
    "lambda",
    "nonlocal",
    "not",
    "or",
    "pass",
    "raise",
    "return",
    "try",
    "while",
    "with",
    "yield",
]

_BUILTIN_NAMES: Final[list[str]] = [
    "abs",
    "all",
    "any",
    "bin",
    "bool",
    "bytes",
    "chr",
    "dict",
    "enumerate",
    "filter",
    "float",
    "format",
    "frozenset",
    "getattr",
    "hasattr",
    "hash",
    "hex",
    "int",
    "isinstance",
    "issubclass",
    "iter",
    "len",
    "list",
    "map",
    "max",
    "min",
    "next",
    "oct",
    "ord",
    "pow",
    "print",
    "range",
    "repr",
    "reversed",
    "round",
    "set",
    "setattr",
    "slice",
    "sorted",
    "str",
    "sum",
    "super",
    "tuple",
    "type",
    "vars",
    "zip",
]


if TYPE_CHECKING:
    from collections.abc import Callable

    class _HexDocumentProtocol(Protocol):
        """Protocol describing the minimal hex document interface used by scripting."""

        def length(self) -> int:
            """Return total document length in bytes.

            Returns:
                int: Document size in bytes.
            """
            _ = self
            return 0

        def read(self, offset: int, length: int) -> bytes | bytearray:
            """Read bytes from the document.

            Args:
                offset: Start byte offset.
                length: Number of bytes to read.

            Returns:
                bytes | bytearray: The bytes read.
            """
            _ = (self, offset, length)
            return b""

        def write_bytes(self, offset: int, data: bytes) -> None:
            """Write bytes at the given offset.

            Args:
                offset: Start byte offset.
                data: Bytes to write.
            """
            _ = (self, offset, data)

        def insert_bytes(self, offset: int, data: bytes) -> None:
            """Insert bytes at the given offset.

            Args:
                offset: Insertion byte offset.
                data: Bytes to insert.
            """
            _ = (self, offset, data)

        def delete_bytes(self, offset: int, length: int) -> None:
            """Delete bytes at the given offset.

            Args:
                offset: Start byte offset.
                length: Number of bytes to delete.
            """
            _ = (self, offset, length)

        def search_hex(self, pattern: str, max_results: int) -> list[tuple[int, int]]:
            """Search for a hex pattern in the document.

            Args:
                pattern: Hex string pattern with optional wildcards.
                max_results: Maximum number of matches to return.

            Returns:
                list[tuple[int, int]]: List of (offset, length) match tuples.
            """
            _ = (self, pattern, max_results)
            return []

        def search_text(
            self,
            text: str,
            encoding: str,
            *,
            case_sensitive: bool,
            max_results: int,
        ) -> list[tuple[int, int]]:
            """Search for text in the document.

            Args:
                text: Text string to search for.
                encoding: Character encoding to use.
                case_sensitive: Whether the search is case-sensitive.
                max_results: Maximum number of matches to return.

            Returns:
                list[tuple[int, int]]: List of (offset, length) match tuples.
            """
            _ = (self, text, encoding, case_sensitive, max_results)
            return []

        def add_bookmark(
            self,
            offset: int,
            length: int,
            label: str,
            color: str,
        ) -> int:
            """Add a bookmark to the document.

            Args:
                offset: Bookmark start offset.
                length: Bookmark length in bytes.
                label: Bookmark label text.
                color: Bookmark color as hex string.

            Returns:
                int: Index of the newly added bookmark.
            """
            _ = (self, offset, length, label, color)
            return 0


class _PythonSyntaxHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for Python source code in the scripting editor.

    Highlights keywords, built-in names, strings, comments, numbers, and decorators using distinct color formats resolved from the active
    theme's analysis color palette via :class:`ThemeManager`, so tokens stay readable in both the light and dark themes. The highlighter
    subscribes to :attr:`ThemeManager.theme_changed` and rebuilds its formats and re-highlights the document whenever the theme switches.
    """

    def __init__(self, parent: QTextDocument) -> None:
        """Initialize the _PythonSyntaxHighlighter with highlighting rules.

        Args:
            parent: The QTextDocument to highlight.
        """
        super().__init__(parent)
        self._rules: list[tuple[str, QTextCharFormat]] = []
        self._theme_manager: ThemeManager = ThemeManager.get_instance()
        self._build_rules()
        self._theme_manager.theme_changed.connect(self._on_theme_changed)

    def _build_rules(self) -> None:
        """Construct regex-based highlighting rules from the active theme palette."""
        colors = self._theme_manager.get_analysis_colors()
        rules: list[tuple[str, QTextCharFormat]] = []

        kw_fmt = QTextCharFormat()
        kw_fmt.setForeground(QColor(colors["mnemonic_jump"]))
        kw_fmt.setFontWeight(QFont.Weight.Bold)
        rules.extend((rf"\b{kw}\b", kw_fmt) for kw in _PYTHON_KEYWORDS)

        builtin_fmt = QTextCharFormat()
        builtin_fmt.setForeground(QColor(colors["operand_register"]))
        rules.extend((rf"\b{bn}\b", builtin_fmt) for bn in _BUILTIN_NAMES)

        number_fmt = QTextCharFormat()
        number_fmt.setForeground(QColor(colors["operand_immediate"]))
        rules.extend(
            [
                (r"\b0[xX][0-9a-fA-F]+\b", number_fmt),
                (r"\b0[bB][01]+\b", number_fmt),
                (r"\b0[oO][0-7]+\b", number_fmt),
                (r"\b\d+\.?\d*(?:[eE][+-]?\d+)?\b", number_fmt),
            ],
        )

        decorator_fmt = QTextCharFormat()
        decorator_fmt.setForeground(QColor(colors["warning"]))
        rules.append((r"@\w+", decorator_fmt))

        string_fmt = QTextCharFormat()
        string_fmt.setForeground(QColor(colors["mnemonic_ret"]))
        rules.extend(
            [
                (r'""".*?"""', string_fmt),
                (r"'''.*?'''", string_fmt),
                (r'"[^"\\]*(\\.[^"\\]*)*"', string_fmt),
                (r"'[^'\\]*(\\.[^'\\]*)*'", string_fmt),
            ],
        )

        comment_fmt = QTextCharFormat()
        comment_fmt.setForeground(QColor(colors["muted"]))
        rules.append((r"#[^\n]*", comment_fmt))

        self._rules = rules

    def _on_theme_changed(self, _theme_name: str) -> None:
        """Rebuild highlighting formats from the new theme palette and re-highlight.

        Args:
            _theme_name: Resolved theme name emitted by :class:`ThemeManager`
                (unused; colors are re-queried from the manager directly).
        """
        self._build_rules()
        self.rehighlight()

    @override
    def highlightBlock(self, text: str | None) -> None:
        """Apply highlighting rules to a single text block.

        Args:
            text: The text content of the block to highlight.
        """
        if text is None:
            return

        for pattern, fmt in self._rules:
            for match in re.finditer(pattern, text):
                start = match.start()
                length = match.end() - start
                self.setFormat(start, length, fmt)


class _DocAPI:
    """Restricted document API exposed to user scripts.

    Provides safe read/write/search operations on the hex document without exposing the full document interface.
    """

    _doc: _HexDocumentProtocol
    _widget: object

    def __init__(
        self,
        document: _HexDocumentProtocol,
        hex_widget: object,
        file_path: str | None,
        encoding_provider: Callable[[], str | None] | None = None,
    ) -> None:
        """Initialize the _DocAPI with document and widget references.

        Args:
            document: The backing hex document object.
            hex_widget: The hex editor widget for cursor/selection access.
            file_path: Path of the currently loaded file.
            encoding_provider: Optional zero-argument callable returning the
                panel's currently selected text encoding (for example
                ``"utf-8"`` or ``"utf-16-le"``). Used by ``search_text`` when
                the script does not pass an explicit ``encoding=`` keyword.
                A ``None`` return value falls back to UTF-8.
        """
        self._doc = document
        self._widget = hex_widget
        self._file_path = file_path
        self._encoding_provider = encoding_provider
        _logger.debug("doc_api_initialized", file_path=file_path)

    @property
    def file_path(self) -> str | None:
        """The path of the currently loaded file.

        Returns:
            str | None: File path string or None.
        """
        return self._file_path

    @property
    def cursor(self) -> int:
        """The current cursor offset.

        Returns:
            int: Cursor byte offset.
        """
        if self._widget is not None:
            return int(getattr(self._widget, "_cursor_offset", 0))
        return 0

    @cursor.setter
    def cursor(self, offset: int) -> None:
        """Set the cursor offset.

        Args:
            offset: New cursor byte offset.
        """
        if self._widget is not None:
            goto_fn = getattr(self._widget, "goto_offset", None)
            if callable(goto_fn):
                goto_fn(offset)

    @property
    def selection(self) -> tuple[int, int] | None:
        """The current selection range.

        Returns:
            tuple[int, int] | None: (start, end) tuple or None.
        """
        if self._widget is not None:
            start = getattr(self._widget, "_selection_start", -1)
            end = getattr(self._widget, "_selection_end", -1)
            if isinstance(start, int) and isinstance(end, int) and start >= 0 and end >= 0:
                return (start, end)
        return None

    @selection.setter
    def selection(self, value: tuple[int, int]) -> None:
        """Set the selection range.

        Args:
            value: (start, end) byte offset tuple.
        """
        if self._widget is not None:
            set_sel = getattr(self._widget, "set_selection_range", None)
            if callable(set_sel):
                set_sel(value[0], value[1])

    def length(self) -> int:
        """Get the document length in bytes.

        Returns:
            int: Document size.
        """
        return int(self._doc.length())

    def read(self, offset: int, length: int) -> bytes:
        """Read bytes from the document.

        Args:
            offset: Start offset.
            length: Number of bytes to read.

        Returns:
            bytes: Read data.
        """
        raw = self._doc.read(offset, length)
        return raw if isinstance(raw, bytes) else bytes(raw)

    def write(self, offset: int, data: bytes) -> None:
        """Write bytes to the document.

        Args:
            offset: Start offset.
            data: Bytes to write.
        """
        _logger.info(
            "file_written",
            path="<scripted_doc>",
            offset=offset,
            size=len(data),
            data_size=len(data),
            data_sha256=hashlib.sha256(data).hexdigest()[:12],
        )
        self._doc.write_bytes(offset, data)

    def insert(self, offset: int, data: bytes) -> None:
        """Insert bytes at the given offset.

        Args:
            offset: Insertion point.
            data: Bytes to insert.
        """
        self._doc.insert_bytes(offset, data)

    def delete(self, offset: int, length: int) -> None:
        """Delete bytes from the document.

        Args:
            offset: Start offset.
            length: Number of bytes to delete.
        """
        self._doc.delete_bytes(offset, length)

    def search_hex(self, pattern: str, max_results: int = 100) -> list[tuple[int, int]]:
        """Search for a hex pattern in the document.

        Args:
            pattern: Hex string pattern with optional wildcards.
            max_results: Maximum number of results to return.

        Returns:
            list[tuple[int, int]]: List of (offset, length) matches.
        """
        raw = self._doc.search_hex(pattern, max_results)
        return [(int(r[0]), int(r[1])) for r in raw]

    def search_text(
        self,
        text: str,
        max_results: int = 100,
        *,
        encoding: str | None = None,
    ) -> list[tuple[int, int]]:
        """Search for text in the document using a configurable encoding.

        Resolution order for the encoding used to convert ``text`` to bytes:

        1. The explicit ``encoding`` keyword argument when provided.
        2. The panel's current encoding-combo selection (passed in via the
           ``encoding_provider`` callback at construction time).
        3. ``"utf-8"`` as a final fallback.

        The resolved encoding is validated through :func:`codecs.lookup` so a
        misspelled codec surfaces as :class:`LookupError` rather than silently
        falling back to UTF-8.

        Args:
            text: Text string to search for.
            max_results: Maximum number of results to return.
            encoding: Optional explicit encoding override. When supplied this
                wins over both the panel selection and the UTF-8 fallback.

        Returns:
            list[tuple[int, int]]: List of (offset, length) matches.

        Raises:
            LookupError: If the resolved encoding is not a known Python codec.
        """
        resolved = self._resolve_search_encoding(encoding)
        try:
            codecs.lookup(resolved)
        except LookupError as exc:
            _logger.warning("scripting_search_text_unknown_encoding", encoding=resolved, error=str(exc))
            msg = f"unknown encoding {resolved!r} for doc.search_text"
            raise LookupError(msg) from exc
        raw = self._doc.search_text(text, resolved, case_sensitive=True, max_results=max_results)
        return [(int(r[0]), int(r[1])) for r in raw]

    def _resolve_search_encoding(self, explicit: str | None) -> str:
        """Resolve the codec name used by :meth:`search_text`.

        Selection order:

        1. ``explicit`` when not ``None``.
        2. The panel's current encoding-combo selection via
           ``encoding_provider`` when set.
        3. ``"utf-8"`` as a final fallback.

        Args:
            explicit: Encoding name passed via the script's ``encoding=``
                keyword argument, or ``None`` when no override was supplied.

        Returns:
            str: The codec name to pass through to the document search call.
        """
        if explicit is not None:
            return explicit

        if self._encoding_provider is not None and (panel_encoding := self._encoding_provider()):
            return panel_encoding

        return "utf-8"

    def add_bookmark(
        self,
        offset: int,
        length: int = 1,
        label: str = "Bookmark",
        color: str = "#FFFF00",
    ) -> int:
        """Add a bookmark to the document.

        Args:
            offset: Bookmark start offset.
            length: Bookmark length in bytes.
            label: Bookmark label.
            color: Bookmark color as hex string.

        Returns:
            int: Index of the added bookmark.
        """
        return int(self._doc.add_bookmark(offset, length, label, color))


class _ReadOnlyDocAPI:
    """Read-only proxy around ``_DocAPI`` that disables mutating methods.

    Forwards read/search/navigation operations to the underlying API while raising :class:`PermissionError` for any write, insert, or delete
    request so scripts cannot mutate the document.
    """

    def __init__(self, inner: _DocAPI) -> None:
        """Initialize the read-only proxy with the underlying API.

        Args:
            inner: The underlying ``_DocAPI`` instance to proxy.
        """
        self._inner = inner

    @property
    def file_path(self) -> str | None:
        """The path of the currently loaded file.

        Returns:
            str | None: File path string or None.
        """
        return self._inner.file_path

    @property
    def cursor(self) -> int:
        """The current cursor offset.

        Returns:
            int: Cursor byte offset.
        """
        return self._inner.cursor

    @cursor.setter
    def cursor(self, offset: int) -> None:
        """Set the cursor offset.

        Args:
            offset: New cursor byte offset.
        """
        self._inner.cursor = offset

    @property
    def selection(self) -> tuple[int, int] | None:
        """The current selection range.

        Returns:
            tuple[int, int] | None: (start, end) tuple or None.
        """
        return self._inner.selection

    @selection.setter
    def selection(self, value: tuple[int, int]) -> None:
        """Set the selection range.

        Args:
            value: (start, end) byte offset tuple.
        """
        self._inner.selection = value

    def length(self) -> int:
        """Get the document length in bytes.

        Returns:
            int: Document size.
        """
        return self._inner.length()

    def read(self, offset: int, length: int) -> bytes:
        """Read bytes from the document.

        Args:
            offset: Start offset.
            length: Number of bytes to read.

        Returns:
            bytes: Read data.
        """
        return self._inner.read(offset, length)

    @staticmethod
    def write(offset: int, data: bytes) -> None:
        """Reject writes in read-only mode.

        Args:
            offset: Unused start offset.
            data: Unused payload bytes.

        Raises:
            _SandboxViolationError: Always raised because writes are disabled.
        """
        _ = (offset, data)
        msg = "doc.write is disabled in read-only script mode"
        _logger.warning("script_sandbox_write_denied", offset=offset, size=len(data))
        raise _SandboxViolationError(msg)

    @staticmethod
    def insert(offset: int, data: bytes) -> None:
        """Reject inserts in read-only mode.

        Args:
            offset: Unused insertion offset.
            data: Unused payload bytes.

        Raises:
            _SandboxViolationError: Always raised because inserts are disabled.
        """
        _ = (offset, data)
        msg = "doc.insert is disabled in read-only script mode"
        _logger.warning("script_sandbox_insert_denied", offset=offset, size=len(data))
        raise _SandboxViolationError(msg)

    @staticmethod
    def delete(offset: int, length: int) -> None:
        """Reject deletes in read-only mode.

        Args:
            offset: Unused start offset.
            length: Unused byte count.

        Raises:
            _SandboxViolationError: Always raised because deletes are disabled.
        """
        _ = (offset, length)
        msg = "doc.delete is disabled in read-only script mode"
        _logger.warning("script_sandbox_delete_denied", offset=offset, length=length)
        raise _SandboxViolationError(msg)

    def search_hex(self, pattern: str, max_results: int = 100) -> list[tuple[int, int]]:
        """Search for a hex pattern in the document.

        Args:
            pattern: Hex string pattern with optional wildcards.
            max_results: Maximum number of results to return.

        Returns:
            list[tuple[int, int]]: List of (offset, length) matches.
        """
        return self._inner.search_hex(pattern, max_results)

    def search_text(
        self,
        text: str,
        max_results: int = 100,
        *,
        encoding: str | None = None,
    ) -> list[tuple[int, int]]:
        """Search for text in the document using a configurable encoding.

        Forwards to :meth:`_DocAPI.search_text` after re-raising any
        :class:`LookupError` produced when validating the explicit override
        so the read-only proxy preserves the same surface contract as the
        full API.

        Args:
            text: Text string to search for.
            max_results: Maximum number of results to return.
            encoding: Optional explicit encoding override.

        Returns:
            list[tuple[int, int]]: List of (offset, length) matches.

        Raises:
            LookupError: If the resolved encoding is not a known Python codec.
        """
        try:
            return self._inner.search_text(text, max_results, encoding=encoding)
        except LookupError as exc:
            _logger.warning("scripting_search_text_proxy_lookup_failed", encoding=encoding, error=str(exc))
            raise LookupError(str(exc)) from exc

    def add_bookmark(
        self,
        offset: int,
        length: int = 1,
        label: str = "Bookmark",
        color: str = "#FFFF00",
    ) -> int:
        """Add a bookmark to the document.

        Args:
            offset: Bookmark start offset.
            length: Bookmark length in bytes.
            label: Bookmark label.
            color: Bookmark color as hex string.

        Returns:
            int: Index of the added bookmark.
        """
        return self._inner.add_bookmark(offset, length, label, color)


def _script_uses_writes(source: str) -> bool:
    """Detect whether the script invokes any document mutation method.

    Performs a syntactic scan for ``doc.write``, ``doc.insert``, or
    ``doc.delete`` references so the main thread can prompt for
    write confirmation before handing the script to a worker.

    Args:
        source: Python script source code.

    Returns:
        bool: True if the script references any mutating doc method.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        _logger.exception("script_uses_writes_parse_failed")
        return False

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in _DOC_WRITE_METHODS:
            value = node.value
            if isinstance(value, ast.Name) and value.id == "doc":
                return True
    return False


def _validate_script_ast(source: str) -> None:
    """Validate script source against the sandbox whitelist.

    Walks the AST and rejects dangerous attribute chains, disallowed
    builtin names, imports, async constructs, and ``getattr`` calls
    that target dunder attributes.

    Args:
        source: Python script source code to validate.

    Raises:
        _SandboxViolationError: If the AST references disallowed constructs.
    """
    tree = ast.parse(source, filename="<script>", mode="exec")

    for node in ast.walk(tree):
        if isinstance(node, _FORBIDDEN_AST_NODES):
            msg = f"{type(node).__name__} is not permitted in sandboxed scripts"
            raise _SandboxViolationError(msg)

        if isinstance(node, ast.Attribute) and node.attr in _FORBIDDEN_ATTRIBUTES:
            msg = f"access to attribute '{node.attr}' is forbidden"
            raise _SandboxViolationError(msg)

        if isinstance(node, ast.Name) and node.id in _FORBIDDEN_NAMES:
            msg = f"name '{node.id}' is not permitted in sandboxed scripts"
            raise _SandboxViolationError(msg)

        if isinstance(node, ast.Call):
            func = node.func
            target_name: str | None = None
            if isinstance(func, ast.Name):
                target_name = func.id
            elif isinstance(func, ast.Attribute):
                target_name = func.attr
            if target_name in {"getattr", "setattr", "delattr", "hasattr"} and len(node.args) > 1:
                attr_arg = node.args[1]
                if (
                    isinstance(attr_arg, ast.Constant)
                    and isinstance(attr_arg.value, str)
                    and (attr_arg.value.startswith("_") or attr_arg.value in _FORBIDDEN_ATTRIBUTES)
                ):
                    msg = f"{target_name}(..., '{attr_arg.value}') is forbidden"
                    raise _SandboxViolationError(msg)


def _build_safe_builtins() -> dict[str, Any]:
    """Construct the curated builtins mapping exposed to sandboxed scripts.

    Starts from the standard builtins module and removes every name
    listed in ``_FORBIDDEN_NAMES`` plus all dunder attributes so
    ``__import__``, ``eval``, ``exec``, ``compile``, ``open`` and
    similar escape hatches are absent from the script namespace.

    Returns:
        dict[str, Any]: Mapping of safe builtin names to their values.
    """
    safe: dict[str, Any] = {}
    for name, value in vars(builtins).items():
        if name.startswith("_"):
            continue
        if name in _FORBIDDEN_NAMES:
            continue
        safe[name] = value
    return safe


def _safe_getattr(target: object, name: object, *default: object) -> object:
    """Sandbox-safe replacement for the ``getattr`` builtin.

    Rejects attempts to access dunder attributes or any name in
    ``_FORBIDDEN_ATTRIBUTES``. The ``name`` parameter is typed as
    ``object`` because user scripts can pass arbitrary values at
    runtime; non-string names are rejected before dispatch.

    Args:
        target: Object whose attribute should be fetched.
        name: Attribute name (validated as a string at runtime).
        *default: Optional default value returned when missing.

    Returns:
        object: The attribute value, or the default when supplied.

    Raises:
        _SandboxViolationError: If the attribute name is forbidden.
    """
    if not isinstance(name, str) or name.startswith("_") or name in _FORBIDDEN_ATTRIBUTES:
        msg = f"getattr(..., {name!r}) is forbidden"
        _logger.warning("script_sandbox_getattr_denied", attr_name=str(name))
        raise _SandboxViolationError(msg)
    return getattr(target, name, default[0]) if default else getattr(target, name)


def _safe_setattr(target: object, name: object, value: object) -> None:
    """Sandbox-safe replacement for the ``setattr`` builtin.

    Rejects attempts to mutate dunder attributes. The ``name``
    parameter is typed as ``object`` because user scripts can pass
    arbitrary values at runtime.

    Args:
        target: Object whose attribute should be set.
        name: Attribute name (validated as a string at runtime).
        value: New attribute value.

    Raises:
        _SandboxViolationError: If the attribute name is forbidden.
    """
    if not isinstance(name, str) or name.startswith("_") or name in _FORBIDDEN_ATTRIBUTES:
        msg = f"setattr(..., {name!r}, ...) is forbidden"
        _logger.warning("script_sandbox_setattr_denied", attr_name=str(name))
        raise _SandboxViolationError(msg)
    setattr(target, name, value)


def _safe_hasattr(target: object, name: object) -> bool:
    """Sandbox-safe replacement for the ``hasattr`` builtin.

    Returns ``False`` for dunder or forbidden names so scripts cannot
    probe for dangerous attributes. The ``name`` parameter is typed as
    ``object`` because user scripts can pass arbitrary values.

    Args:
        target: Object whose attribute is tested.
        name: Attribute name (validated as a string at runtime).

    Returns:
        bool: True if the attribute exists and is allowed.
    """
    if not isinstance(name, str) or name.startswith("_") or name in _FORBIDDEN_ATTRIBUTES:
        return False
    return hasattr(target, name)


_SCRIPT_TEMPDIR_PREFIX: Final[str] = "intellicrack_hex_script_"


def _resolve_user_print_path(
    name: str,
    sandbox_dir: Path,
    opened: dict[str, IO[str]],
) -> Path:
    """Resolve a user-supplied filename into a sandboxed path under ``sandbox_dir``.

    Rejects absolute paths, drive-qualified paths, and ``..`` traversal so
    sandboxed scripts can only create files inside the per-execution
    tempdir. Reuses an already-opened handle for repeat ``print(..., file=name)``
    calls within the same script run.

    Args:
        name: User-supplied filename (relative path, no traversal segments).
        sandbox_dir: Per-script tempdir that constrains output file creation.
        opened: Mutable mapping of filename to open text handle, used to
            reuse handles across multiple ``print`` calls.

    Returns:
        Path: Absolute path inside ``sandbox_dir`` corresponding to ``name``.

    Raises:
        _SandboxViolationError: If ``name`` is absolute, contains ``..``, or
            otherwise escapes ``sandbox_dir``.
    """
    candidate = Path(name)
    if candidate.is_absolute() or candidate.drive:
        msg = f"print(..., file={name!r}) must be a relative filename inside the script tempdir"
        raise _SandboxViolationError(msg)
    if any(part in {"..", ""} for part in candidate.parts):
        msg = f"print(..., file={name!r}) may not contain '..' segments"
        raise _SandboxViolationError(msg)

    resolved = (sandbox_dir / candidate).resolve()
    sandbox_root = sandbox_dir.resolve()
    try:
        resolved.relative_to(sandbox_root)
    except ValueError as exc:
        msg = f"print(..., file={name!r}) escapes the script tempdir"
        raise _SandboxViolationError(msg) from exc

    if name not in opened:
        resolved.parent.mkdir(parents=True, exist_ok=True)
        _logger.debug("scripting_user_print_file_open", file_name=name, path=str(resolved))
        opened[name] = resolved.open("w", encoding="utf-8")
    return resolved


def execute_script(source: str, doc_api: _DocAPI | _ReadOnlyDocAPI) -> dict[str, Any]:
    """Run a user-supplied Python script in a sandboxed namespace.

    Validates the script via :func:`_validate_script_ast`, builds a safe
    builtin set, captures ``stdout`` and ``stderr`` into separate sinks,
    executes the source, and returns the captured output plus the names of
    any non-callable user variables.

    The replacement ``print`` builtin honours the standard ``file=`` keyword:

    * ``file=None`` (the default) writes to the captured stdout sink.
    * ``file=sys.stderr`` writes to a separate stderr sink.
    * Any object with a ``.write`` method is written to directly, allowing
      scripts to redirect into their own ``io.StringIO`` instances.
    * A bare string is treated as a filename relative to a per-script
      tempdir; the file is opened inside the tempdir and its absolute path
      is reported back through the result for the panel to surface.

    Script-level exceptions are caught, formatted with
    :func:`traceback.format_exception`, and returned via the ``traceback``
    key so the panel can render them inline rather than swallowing them.

    Args:
        source: Python script source code to execute.
        doc_api: Document API providing safe hex document access.

    Returns:
        dict[str, Any]: Dict with the following keys:

            * ``output``: Captured stdout text.
            * ``stderr``: Captured stderr text.
            * ``error``: Short ``"Type: message"`` string when the script
              raised, else ``None``.
            * ``traceback``: Full formatted traceback when the script
              raised, else ``None``.
            * ``variables``: Mapping of user-defined non-callable variable
              names to their ``repr`` strings.
            * ``output_files``: List of absolute paths created via
              ``print(..., file="name")``.
    """
    _validate_script_ast(source)

    safe_builtins = _build_safe_builtins()

    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    sandbox_dir = Path(tempfile.mkdtemp(prefix=_SCRIPT_TEMPDIR_PREFIX))
    _logger.debug("scripting_sandbox_tempdir_created", path=str(sandbox_dir))
    user_opened_files: dict[str, IO[str]] = {}

    def _write_to_target(target: IO[str], text: str, *, flush: bool) -> None:
        """Write ``text`` to ``target`` and flush when requested.

        Args:
            target: Open text sink with ``write`` and (optionally) ``flush``.
            text: Already-joined output string.
            flush: Whether to call ``target.flush()`` after writing.
        """
        target.write(text)
        if flush:
            flush_fn = getattr(target, "flush", None)
            if callable(flush_fn):
                flush_fn()

    def _safe_print(
        *values: object,
        sep: str | None = " ",
        end: str | None = "\n",
        file: object = None,
        flush: bool = False,
    ) -> None:
        """Replacement for ``print`` honouring ``file=`` redirection.

        Args:
            *values: Values to print.
            sep: Separator string between values.
            end: String appended after the last value.
            file: Optional output sink. ``None`` and :data:`sys.stdout` map
                to the captured stdout buffer; :data:`sys.stderr` maps to the
                captured stderr buffer; a string is treated as a filename
                inside the per-script tempdir; any other object must expose a
                ``write`` method and is written to directly.
            flush: Whether to flush ``file`` after writing.

        Raises:
            _SandboxViolationError: If ``file`` is a string filename that
                escapes the per-script tempdir.
            TypeError: If ``file`` is not ``None``, a recognised stdio handle,
                a string filename, or a writable file-like object.
        """
        text = (sep or " ").join(str(v) for v in values) + (end or "\n")

        if file is None or file is sys.stdout:
            _write_to_target(stdout_capture, text, flush=flush)
            return
        if file is sys.stderr:
            _write_to_target(stderr_capture, text, flush=flush)
            return
        if isinstance(file, str):
            try:
                resolved = _resolve_user_print_path(file, sandbox_dir, user_opened_files)
            except _SandboxViolationError as exc:
                raise _SandboxViolationError(str(exc)) from exc
            _write_to_target(user_opened_files[file], text, flush=flush)
            del resolved
            return
        write_fn = getattr(file, "write", None)
        if not callable(write_fn):
            msg = f"print(..., file={file!r}) requires a writable file-like object"
            raise TypeError(msg)
        write_fn(text)
        if flush:
            flush_fn = getattr(file, "flush", None)
            if callable(flush_fn):
                flush_fn()

    safe_builtins["print"] = _safe_print
    safe_builtins["getattr"] = _safe_getattr
    safe_builtins["setattr"] = _safe_setattr
    safe_builtins["hasattr"] = _safe_hasattr

    namespace: dict[str, Any] = {
        "__builtins__": safe_builtins,
        "doc": doc_api,
    }

    _logger.info("scripting_execute_script_started", source_length=len(source), sandbox_dir=str(sandbox_dir))
    error_message: str | None = None
    traceback_text: str | None = None
    try:
        compiled = compile(source, "<script>", "exec")
        _EXEC_FN[0](compiled, namespace)
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit, MemoryError)):
            _logger.warning("scripting_execute_script_critical", exception_type=type(exc).__name__)
            for handle in user_opened_files.values():
                handle.close()
            raise
        _logger.exception("scripting_execute_script_failed", exception_type=type(exc).__name__)
        error_message = f"{type(exc).__name__}: {exc}"
        traceback_text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    finally:
        for handle in user_opened_files.values():
            handle.close()
    _logger.info("scripting_execute_script_completed", had_error=error_message is not None, output_file_count=len(user_opened_files))

    user_vars: dict[str, str] = {}
    for key, val in namespace.items():
        if not key.startswith("_") and key != "doc" and not callable(val):
            user_vars[key] = repr(val)

    output_files: list[str] = []
    for name in user_opened_files:
        resolved = (sandbox_dir / name).resolve()
        output_files.append(str(resolved))

    return {
        "output": stdout_capture.getvalue(),
        "stderr": stderr_capture.getvalue(),
        "error": error_message,
        "traceback": traceback_text,
        "variables": user_vars,
        "output_files": output_files,
    }


class ScriptingMixin:
    """Mixin providing Python scripting for the hex editor panel."""

    document: _HexDocumentProtocol | None
    _hex_widget: object | None
    file_path: Path | None
    _side_tabs: QTabWidget | None
    _script_editor: QPlainTextEdit | None
    _script_output: QPlainTextEdit | None
    _script_worker: GenericCallableWorker | None
    _script_status: QLabel | None
    _encoding_combo: QComboBox | None

    def _create_scripting_tab(self) -> QWidget:
        """Create the Python scripting side panel tab.

        Returns:
            QWidget: Container with code editor, buttons, and output console.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(4)

        self._script_editor = QPlainTextEdit()
        editor_font = QFont(_FONT_FAMILY, _FONT_SIZE)
        self._script_editor.setFont(editor_font)
        self._script_editor.setTabStopDistance(
            self._script_editor.fontMetrics().horizontalAdvance(" ") * 4,
        )
        editor_doc = self._script_editor.document()
        if editor_doc is not None:
            _PythonSyntaxHighlighter(editor_doc)
        layout.addWidget(self._script_editor)

        btn_row = QHBoxLayout()
        run_btn = QPushButton("Run")
        run_btn.setToolTip("Ctrl+Shift+R")
        run_btn.clicked.connect(self._on_run_script)
        btn_row.addWidget(run_btn)
        load_btn = QPushButton("Load...")
        load_btn.clicked.connect(self._on_load_script)
        btn_row.addWidget(load_btn)
        save_btn = QPushButton("Save...")
        save_btn.clicked.connect(self._on_save_script)
        btn_row.addWidget(save_btn)
        clear_btn = QPushButton("Clear Output")
        clear_btn.clicked.connect(self._on_clear_script_output)
        btn_row.addWidget(clear_btn)
        layout.addLayout(btn_row)

        self._script_status = QLabel("")
        layout.addWidget(self._script_status)

        self._script_output = QPlainTextEdit()
        self._script_output.setReadOnly(True)
        out_font = QFont(_FONT_FAMILY, _OUTPUT_FONT_SIZE)
        self._script_output.setFont(out_font)
        self._script_output.setMaximumHeight(_OUTPUT_MAX_HEIGHT)
        layout.addWidget(self._script_output)

        self._script_worker = None
        return container

    def _on_run_script(self) -> None:
        """Execute the script from the editor in a background thread.

        Scans the script for document-mutating calls and, if any are present, shows a modal confirmation dialog before granting write
        access. When the user declines the dialog, the script still runs but receives a read-only document proxy that rejects
        ``doc.write``/``doc.insert``/``doc.delete``.
        """
        if self._script_editor is None or self.document is None:
            return

        source = self._script_editor.toPlainText()
        if not source.strip():
            return

        if self._script_worker is not None and self._script_worker.isRunning():
            return

        fp = str(self.file_path) if self.file_path else None
        encoding_provider = self._build_panel_encoding_provider()
        base_api = _DocAPI(self.document, self._hex_widget, fp, encoding_provider)
        doc_api: _DocAPI | _ReadOnlyDocAPI = _ReadOnlyDocAPI(base_api)

        if _script_uses_writes(source):
            parent = self if isinstance(self, QWidget) else None
            prompt = (
                "This script calls doc.write, doc.insert, or doc.delete.\n\n"
                "Allow it to modify the loaded document?\n\n"
                "Choose 'No' to run the script in read-only mode."
            )
            answer = QMessageBox.question(
                parent,
                "Allow script to modify document?",
                prompt,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer == QMessageBox.StandardButton.Yes:
                doc_api = base_api
                _logger.info("script_write_access_granted")
            else:
                _logger.warning("script_write_access_denied")

        if self._script_status is not None:
            self._script_status.setText("Running...")

        worker = GenericCallableWorker(execute_script, source, doc_api)
        _: object = worker.call_finished.connect(self._on_script_finished_obj)
        _ = worker.call_error.connect(self._on_script_error_obj)
        self._script_worker = worker
        _logger.info("script_worker_starting", source_length=len(source))
        worker.start()

    def _build_panel_encoding_provider(self) -> Callable[[], str | None]:
        """Construct an encoding-resolver callback bound to the panel's combo.

        The returned callable reads the current encoding-combo selection on
        each call so scripts always observe the user's latest pick rather
        than a value snapshotted at construction time. Falls back to the
        combo's display text when no item user-data is set, and to ``None``
        when the combo has not been wired up.

        Returns:
            Callable[[], str | None]: Callback returning the codec name to
                use for ``doc.search_text`` when the script does not pass an
                explicit ``encoding=`` keyword argument.
        """

        def _provider() -> str | None:
            """Return the panel's currently selected codec name, if any.

            Returns:
                str | None: Selected codec name, or ``None`` if unavailable.
            """
            combo = self._encoding_combo
            if combo is None:
                return None
            current_data = getattr(combo, "currentData", None)
            if callable(current_data):
                data = current_data()
                if isinstance(data, str) and data:
                    return data
            current_text = getattr(combo, "currentText", None)
            if callable(current_text):
                text = current_text()
                if isinstance(text, str) and text:
                    return text
            return None

        return _provider

    def _on_script_finished_obj(self, result: object) -> None:
        """Forward worker results to the typed script handler.

        Args:
            result: Raw object emitted by ``GenericCallableWorker.call_finished``.
        """
        if isinstance(result, dict):
            self._on_script_finished(cast("dict[str, Any]", result))

    def _on_script_error_obj(self, exc: object) -> None:
        """Forward worker exceptions to the typed script error handler.

        Args:
            exc: Exception object emitted by ``GenericCallableWorker.call_error``.
        """
        self._on_script_error(f"{type(exc).__name__}: {exc}")

    def _on_load_script(self) -> None:
        """Load a Python script file into the editor."""
        parent = self if isinstance(self, QWidget) else None
        result = QFileDialog.getOpenFileName(
            parent,
            "Load Script",
            "",
            "Python Files (*.py);;All Files (*)",
        )
        script_path = result[0] if result else ""
        if script_path and self._script_editor is not None:
            _logger.info("script_load_started", path=script_path)
            try:
                content = Path(script_path).read_text(encoding="utf-8")
                self._script_editor.setPlainText(content)
                _logger.info("script_load_completed", path=script_path, size=len(content))
            except OSError:
                _logger.exception("script_load_failed", path=script_path)

    def _on_save_script(self) -> None:
        """Save the editor content to a Python file."""
        parent = self if isinstance(self, QWidget) else None
        result = QFileDialog.getSaveFileName(
            parent,
            "Save Script",
            "",
            "Python Files (*.py);;All Files (*)",
        )
        save_path = result[0] if result else ""
        if save_path and self._script_editor is not None:
            script_text = self._script_editor.toPlainText()
            _logger.info(
                "file_written",
                path=save_path,
                size=len(script_text),
                kind="script",
            )
            try:
                Path(save_path).write_text(
                    script_text,
                    encoding="utf-8",
                )
            except OSError:
                _logger.exception("script_save_failed", path=save_path)

    def _on_clear_script_output(self) -> None:
        """Clear the script output console."""
        if self._script_output is not None:
            self._script_output.clear()
        if self._script_status is not None:
            self._script_status.setText("")

    def _on_script_finished(self, result: dict[str, Any]) -> None:
        """Display script execution results in the output console.

        Surfaces (in order) the captured stdout, captured stderr, any files
        the script wrote via ``print(..., file="name")``, the user-defined
        variables snapshot, and finally the formatted traceback when the
        script raised. Updates the status label to ``"Error"`` whenever a
        traceback is present so failed runs are visually distinguished.

        Args:
            result: Result dict produced by :func:`execute_script` containing
                ``output``, ``stderr``, ``error``, ``traceback``, ``variables``,
                and ``output_files`` keys.
        """
        traceback_text = result.get("traceback")
        has_error = bool(traceback_text)

        if self._script_status is not None:
            self._script_status.setText("Error" if has_error else "Done")

        if self._script_output is None:
            return

        lines: list[str] = []
        if output := result.get("output", ""):
            lines.append(output)

        if stderr_text := result.get("stderr", ""):
            lines.extend(("--- stderr ---", stderr_text))

        if output_files := result.get("output_files", []):
            lines.append("--- Files ---")
            lines.extend(f"  {path}" for path in output_files)

        if user_vars := result.get("variables", {}):
            lines.append("--- Variables ---")
            lines.extend(f"  {name} = {val}" for name, val in user_vars.items())

        if traceback_text:
            lines.extend(("--- Traceback ---", traceback_text))

        self._script_output.setPlainText("\n".join(lines))

        if has_error:
            error_message = result.get("error", "")
            _logger.warning("script_execution_error", error=str(error_message))

        if self._hex_widget is not None:
            update_fn = getattr(self._hex_widget, "_update_viewport", None)
            if callable(update_fn):
                update_fn()

    def _on_script_error(self, error: str) -> None:
        """Display a script execution error in the output console.

        Args:
            error: Error message string.
        """
        if self._script_status is not None:
            self._script_status.setText("Error")
        if self._script_output is not None:
            self._script_output.setPlainText(f"Error:\n{error}")
        _logger.warning("script_execution_error", error=error)
