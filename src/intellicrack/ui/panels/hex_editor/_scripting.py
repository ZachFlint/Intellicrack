# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Python scripting mixin for the hex editor panel."""

from __future__ import annotations

import ast
import builtins
import io
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Protocol, override

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat, QTextDocument
from PyQt6.QtWidgets import (
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

from intellicrack.ui.panels.hex_editor._base import logger


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


class _SandboxViolationError(PermissionError):
    """Raised when a script attempts an operation forbidden by the sandbox.

    Using a dedicated subclass keeps exception raise sites clean and
    still presents as ``PermissionError`` to surrounding callers.
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

    Highlights keywords, built-in names, strings, comments, numbers, and decorators using distinct color formats.
    """

    def __init__(self, parent: QTextDocument) -> None:
        """Initialize the _PythonSyntaxHighlighter with highlighting rules.

        Args:
            parent: The QTextDocument to highlight.
        """
        super().__init__(parent)
        self._rules: list[tuple[str, QTextCharFormat]] = []
        self._build_rules()

    def _build_rules(self) -> None:
        """Construct regex-based highlighting rules."""
        kw_fmt = QTextCharFormat()
        kw_fmt.setForeground(QColor("#569CD6"))
        kw_fmt.setFontWeight(QFont.Weight.Bold)
        for kw in _PYTHON_KEYWORDS:
            self._rules.append((rf"\b{kw}\b", kw_fmt))

        builtin_fmt = QTextCharFormat()
        builtin_fmt.setForeground(QColor("#4EC9B0"))
        for bn in _BUILTIN_NAMES:
            self._rules.append((rf"\b{bn}\b", builtin_fmt))

        number_fmt = QTextCharFormat()
        number_fmt.setForeground(QColor("#B5CEA8"))
        self._rules.append((r"\b0[xX][0-9a-fA-F]+\b", number_fmt))
        self._rules.append((r"\b0[bB][01]+\b", number_fmt))
        self._rules.append((r"\b0[oO][0-7]+\b", number_fmt))
        self._rules.append((r"\b\d+\.?\d*(?:[eE][+-]?\d+)?\b", number_fmt))

        decorator_fmt = QTextCharFormat()
        decorator_fmt.setForeground(QColor("#C586C0"))
        self._rules.append((r"@\w+", decorator_fmt))

        string_fmt = QTextCharFormat()
        string_fmt.setForeground(QColor("#CE9178"))
        self._rules.append((r'""".*?"""', string_fmt))
        self._rules.append((r"'''.*?'''", string_fmt))
        self._rules.append((r'"[^"\\]*(\\.[^"\\]*)*"', string_fmt))
        self._rules.append((r"'[^'\\]*(\\.[^'\\]*)*'", string_fmt))

        comment_fmt = QTextCharFormat()
        comment_fmt.setForeground(QColor("#6A9955"))
        self._rules.append((r"#[^\n]*", comment_fmt))

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
    ) -> None:
        """Initialize the _DocAPI with document and widget references.

        Args:
            document: The backing hex document object.
            hex_widget: The hex editor widget for cursor/selection access.
            file_path: Path of the currently loaded file.
        """
        self._doc = document
        self._widget = hex_widget
        self._file_path = file_path

    @property
    def file_path(self) -> str | None:
        """Get the path of the currently loaded file.

        Returns:
            str | None: File path string or None.
        """
        return self._file_path

    @property
    def cursor(self) -> int:
        """Get the current cursor offset.

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
        """Get the current selection range.

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
        if isinstance(raw, bytes):
            return raw
        return bytes(raw)

    def write(self, offset: int, data: bytes) -> None:
        """Write bytes to the document.

        Args:
            offset: Start offset.
            data: Bytes to write.
        """
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

    def search_text(self, text: str, max_results: int = 100) -> list[tuple[int, int]]:
        """Search for text in the document.

        Args:
            text: Text string to search for.
            max_results: Maximum number of results to return.

        Returns:
            list[tuple[int, int]]: List of (offset, length) matches.
        """
        raw = self._doc.search_text(text, "utf-8", case_sensitive=True, max_results=max_results)
        return [(int(r[0]), int(r[1])) for r in raw]

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

    Forwards read/search/navigation operations to the underlying API
    while raising :class:`PermissionError` for any write, insert, or
    delete request so scripts cannot mutate the document.
    """

    def __init__(self, inner: _DocAPI) -> None:
        """Initialize the read-only proxy with the underlying API.

        Args:
            inner: The underlying ``_DocAPI`` instance to proxy.
        """
        self._inner = inner

    @property
    def file_path(self) -> str | None:
        """Get the path of the currently loaded file.

        Returns:
            str | None: File path string or None.
        """
        return self._inner.file_path

    @property
    def cursor(self) -> int:
        """Get the current cursor offset.

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
        """Get the current selection range.

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

    def search_text(self, text: str, max_results: int = 100) -> list[tuple[int, int]]:
        """Search for text in the document.

        Args:
            text: Text string to search for.
            max_results: Maximum number of results to return.

        Returns:
            list[tuple[int, int]]: List of (offset, length) matches.
        """
        return self._inner.search_text(text, max_results)

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
        raise _SandboxViolationError(msg)
    if default:
        return getattr(target, name, default[0])
    return getattr(target, name)


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


class ScriptWorker(QThread):
    """Background worker for executing Python scripts.

    Runs user-supplied Python source code in a sandboxed namespace
    validated by an AST whitelist. Captures stdout to avoid blocking
    the GUI thread and reports results via Qt signals.

    Attributes:
        script_finished: Emitted with result dict on success.
        script_error: Emitted with error message on failure.
    """

    script_finished: pyqtSignal = pyqtSignal(dict)
    script_error: pyqtSignal = pyqtSignal(str)

    def __init__(
        self,
        source: str,
        doc_api: _DocAPI | _ReadOnlyDocAPI,
        parent: QThread | None = None,
    ) -> None:
        """Initialize the ScriptWorker with script source and document API.

        Args:
            source: Python script source code to execute.
            doc_api: Document API providing safe hex document access.
            parent: Parent QObject.
        """
        super().__init__(parent)
        self._source = source
        self._doc_api = doc_api

    @override
    def run(self) -> None:
        """Execute the script in a restricted namespace."""
        try:
            result = self._execute()
            self.script_finished.emit(result)
        except PermissionError as exc:
            self.script_error.emit(f"PermissionError: {exc}")
        except SyntaxError as exc:
            self.script_error.emit(f"SyntaxError: {exc}")
        except (
            RuntimeError,
            ValueError,
            TypeError,
            KeyError,
            IndexError,
            AttributeError,
            ArithmeticError,
            LookupError,
            OSError,
        ) as exc:
            self.script_error.emit(f"{type(exc).__name__}: {exc}")

    def _execute(self) -> dict[str, Any]:
        """Run the source in a sandboxed namespace and capture output.

        Returns:
            dict[str, Any]: Dict with output, error (if any), and
                user-defined variable names.
        """
        _validate_script_ast(self._source)

        safe_builtins = _build_safe_builtins()

        stdout_capture = io.StringIO()

        def _safe_print(
            *values: object,
            sep: str | None = " ",
            end: str | None = "\n",
            **kwargs: object,
        ) -> None:
            text = (sep or " ").join(str(v) for v in values) + (end or "\n")
            stdout_capture.write(text)
            if kwargs.get("flush"):
                stdout_capture.flush()

        safe_builtins["print"] = _safe_print
        safe_builtins["getattr"] = _safe_getattr
        safe_builtins["setattr"] = _safe_setattr
        safe_builtins["hasattr"] = _safe_hasattr

        namespace: dict[str, Any] = {
            "__builtins__": safe_builtins,
            "doc": self._doc_api,
        }

        compiled = compile(self._source, "<script>", "exec")
        exec(compiled, namespace)  # noqa: S102

        user_vars: dict[str, str] = {}
        for key, val in namespace.items():
            if not key.startswith("_") and key != "doc" and not callable(val):
                user_vars[key] = repr(val)

        return {
            "output": stdout_capture.getvalue(),
            "error": None,
            "variables": user_vars,
        }


class ScriptingMixin:
    """Mixin providing Python scripting for the hex editor panel."""

    document: _HexDocumentProtocol | None
    _hex_widget: object | None
    file_path: Path | None
    _side_tabs: QTabWidget | None
    _script_editor: QPlainTextEdit | None
    _script_output: QPlainTextEdit | None
    _script_worker: ScriptWorker | None
    _script_status: QLabel | None

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

        Scans the script for document-mutating calls and, if any are
        present, shows a modal confirmation dialog before granting
        write access. When the user declines the dialog, the script
        still runs but receives a read-only document proxy that
        rejects ``doc.write``/``doc.insert``/``doc.delete``.
        """
        if self._script_editor is None or self.document is None:
            return

        source = self._script_editor.toPlainText()
        if not source.strip():
            return

        if self._script_worker is not None and self._script_worker.isRunning():
            return

        fp = str(self.file_path) if self.file_path else None
        base_api = _DocAPI(self.document, self._hex_widget, fp)
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
                logger.info("script_write_access_granted")
            else:
                logger.info("script_write_access_denied")

        if self._script_status is not None:
            self._script_status.setText("Running...")

        worker = ScriptWorker(source, doc_api)
        worker.script_finished.connect(self._on_script_finished)
        worker.script_error.connect(self._on_script_error)
        self._script_worker = worker
        worker.start()

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
            try:
                content = Path(script_path).read_text(encoding="utf-8")
                self._script_editor.setPlainText(content)
            except OSError as exc:
                logger.warning("script_load_failed", error=str(exc))

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
            try:
                Path(save_path).write_text(
                    self._script_editor.toPlainText(),
                    encoding="utf-8",
                )
            except OSError as exc:
                logger.warning("script_save_failed", error=str(exc))

    def _on_clear_script_output(self) -> None:
        """Clear the script output console."""
        if self._script_output is not None:
            self._script_output.clear()
        if self._script_status is not None:
            self._script_status.setText("")

    def _on_script_finished(self, result: dict[str, Any]) -> None:
        """Display script execution results in the output console.

        Args:
            result: Dict with output, error, and variables keys.
        """
        if self._script_status is not None:
            self._script_status.setText("Done")

        if self._script_output is None:
            return

        lines: list[str] = []
        output = result.get("output", "")
        if output:
            lines.append(output)

        user_vars = result.get("variables", {})
        if user_vars:
            lines.append("--- Variables ---")
            lines.extend(f"  {name} = {val}" for name, val in user_vars.items())

        self._script_output.setPlainText("\n".join(lines))

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
        logger.debug("script_execution_error", error=error)
