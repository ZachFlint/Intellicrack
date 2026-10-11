# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the sandbox, document API and panel mixin of the hex editor scripting tab.

Every test drives the production code with real objects: a genuine ``intellicrack_hexcore.HexDocument`` holding known bytes, a real
``HexEditorWidget``, real Qt controls built by ``ScriptingMixin._create_scripting_tab``, and the real asynchronous worker used by the Run
button. Expected values are derived from byte arithmetic, the Python standard library, or the documented contract of each function rather
than read back from the code under test.
"""

from __future__ import annotations

import io
import re
import sys
import tempfile
import threading
import types
from pathlib import Path
from typing import TYPE_CHECKING, Any, override

import intellicrack_hexcore
import pytest
from PyQt6.QtGui import QSyntaxHighlighter
from PyQt6.QtWidgets import QComboBox, QFileDialog, QLabel, QMessageBox, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget

from intellicrack.core.color_defaults import DEFAULT_BOOKMARK_COLOR
from intellicrack.ui.panels.async_bridge import (
    GenericCallableWorker,
    drain_bridge_workers,
    drain_bridge_workers_for,
    run_callable_async,
)
from intellicrack.ui.panels.hex_editor import scripting as scripting_module
from intellicrack.ui.panels.hex_editor.scripting import ScriptingMixin, execute_script
from intellicrack.ui.panels.hex_editor_widget import HexEditorWidget


if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")


_DocAPI: Any = getattr(scripting_module, "_DocAPI")
_ReadOnlyDocAPI: Any = getattr(scripting_module, "_ReadOnlyDocAPI")
_SandboxViolationError: Any = getattr(scripting_module, "_SandboxViolationError")
_script_uses_writes: Any = getattr(scripting_module, "_script_uses_writes")
_validate_script_ast: Any = getattr(scripting_module, "_validate_script_ast")
_safe_getattr: Any = getattr(scripting_module, "_safe_getattr")
_safe_setattr: Any = getattr(scripting_module, "_safe_setattr")
_safe_hasattr: Any = getattr(scripting_module, "_safe_hasattr")
_resolve_user_print_path: Any = getattr(scripting_module, "_resolve_user_print_path")

_SAMPLE: bytes = b"\x00\xde\xad\x11\xef\x00\xde\xad\x22\xef\x10\x11\x12\x13\x14\x15"
_TEXT_SAMPLE: bytes = b"AB\x00\x00" + "AB".encode("utf-16-le") + b"\xff"
_WAIT_MS: int = 20_000
_SANDBOX_GLOB: str = "intellicrack_hex_script_*"


class _CountingHexWidget(HexEditorWidget):
    """Real hex editor widget that counts how often its viewport repaint hook runs.

    Attributes:
        viewport_updates: Number of times ``_update_viewport`` was invoked.
    """

    viewport_updates: int = 0

    @override
    def _update_viewport(self) -> None:
        """Count the repaint request and forward it to the real implementation."""
        self.viewport_updates += 1
        super()._update_viewport()


class _ScriptingHost(ScriptingMixin, QWidget):
    """Concrete widget host that exposes the scripting mixin's slots to the tests."""

    def __init__(
        self,
        document: intellicrack_hexcore.HexDocument | None,
        hex_widget: object | None = None,
        file_path: Path | None = None,
    ) -> None:
        """Create a host with no scripting tab built yet.

        Args:
            document: Real hexcore document the scripts operate on, or ``None``.
            hex_widget: Widget the document API reads cursor and selection from.
            file_path: Path reported to scripts as ``doc.file_path``.
        """
        super().__init__()
        self.document = document
        self._hex_widget = hex_widget
        self.file_path = file_path
        self._side_tabs = None
        self._script_editor = None
        self._script_output = None
        self._script_worker = None
        self._script_status = None
        self._encoding_combo = None

    def build_tab(self) -> QWidget:
        """Build the real scripting tab and place it inside the host.

        Returns:
            QWidget: The tab container created by the mixin.
        """
        container = self._create_scripting_tab()
        QVBoxLayout(self).addWidget(container)
        return container

    def button(self, text: str) -> QPushButton:
        """Find a tab button by its caption.

        Args:
            text: Caption of the wanted button.

        Returns:
            QPushButton: The matching button.

        Raises:
            LookupError: If no button has that caption.
        """
        for candidate in self.findChildren(QPushButton):
            if candidate.text() == text:
                return candidate
        msg = f"no button captioned {text!r}"
        raise LookupError(msg)

    @property
    def editor(self) -> QPlainTextEdit:
        """The script editor created by the tab.

        Returns:
            QPlainTextEdit: The editor widget.
        """
        editor = self._script_editor
        assert editor is not None
        return editor

    @property
    def output(self) -> QPlainTextEdit:
        """The script output console created by the tab.

        Returns:
            QPlainTextEdit: The console widget.
        """
        output = self._script_output
        assert output is not None
        return output

    @property
    def status(self) -> QLabel:
        """The status label created by the tab.

        Returns:
            QLabel: The status label.
        """
        status = self._script_status
        assert status is not None
        return status

    @property
    def worker(self) -> GenericCallableWorker | None:
        """The worker the Run slot started most recently.

        Returns:
            GenericCallableWorker | None: The worker, or ``None`` when nothing has run.
        """
        return self._script_worker

    def adopt_worker(self, worker: GenericCallableWorker) -> None:
        """Record a worker as the host's current script worker.

        Args:
            worker: The worker to record.
        """
        self._script_worker = worker

    def drop_editor(self) -> None:
        """Forget the editor so the slots see it as not yet created."""
        self._script_editor = None

    def drop_output(self) -> None:
        """Forget the output console so the slots see it as not yet created."""
        self._script_output = None

    def drop_status(self) -> None:
        """Forget the status label so the slots see it as not yet created."""
        self._script_status = None

    def use_combo(self, combo: object | None) -> None:
        """Install the object the encoding provider reads from.

        Args:
            combo: The encoding selector, or any other object, or ``None``.
        """
        setattr(self, "_encoding_combo", combo)

    def run(self) -> None:
        """Invoke the slot the Run button triggers."""
        self._on_run_script()

    def load(self) -> None:
        """Invoke the slot the Load button triggers."""
        self._on_load_script()

    def save(self) -> None:
        """Invoke the slot the Save button triggers."""
        self._on_save_script()

    def clear(self) -> None:
        """Invoke the slot the Clear Output button triggers."""
        self._on_clear_script_output()

    def finished(self, result: dict[str, Any]) -> None:
        """Deliver a typed result to the finished handler.

        Args:
            result: Result dictionary shaped like ``execute_script`` output.
        """
        self._on_script_finished(result)

    def finished_obj(self, result: object) -> None:
        """Deliver an untyped worker result to the finished forwarder.

        Args:
            result: Raw object a worker emitted.
        """
        self._on_script_finished_obj(result)

    def error(self, message: str) -> None:
        """Deliver an error string to the error handler.

        Args:
            message: Error text to display.
        """
        self._on_script_error(message)

    def error_obj(self, exc: object) -> None:
        """Deliver a raw exception object to the error forwarder.

        Args:
            exc: Exception object a worker emitted.
        """
        self._on_script_error_obj(exc)

    def provider(self) -> Callable[[], str | None]:
        """Build the panel encoding provider.

        Returns:
            Callable[[], str | None]: The provider the mixin produces.
        """
        return self._build_panel_encoding_provider()


def _run(source: str, document: intellicrack_hexcore.HexDocument) -> dict[str, Any]:
    """Run a script through ``execute_script`` with a read-only document proxy.

    Args:
        source: Script source.
        document: Real hexcore document.

    Returns:
        dict[str, Any]: The result dictionary of ``execute_script``.
    """
    return execute_script(source, _ReadOnlyDocAPI(_DocAPI(document, None, None)))


def _answer_yes(*_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
    """Answer a confirmation prompt affirmatively.

    Args:
        *_args: Ignored dialog arguments.
        **_kwargs: Ignored dialog keyword arguments.

    Returns:
        QMessageBox.StandardButton: The Yes button.
    """
    return QMessageBox.StandardButton.Yes


def _answer_no(*_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
    """Answer a confirmation prompt negatively.

    Args:
        *_args: Ignored dialog arguments.
        **_kwargs: Ignored dialog keyword arguments.

    Returns:
        QMessageBox.StandardButton: The No button.
    """
    return QMessageBox.StandardButton.No


def _file_picker(path: str) -> Callable[..., tuple[str, str]]:
    """Build a file-dialog replacement that picks a fixed path.

    Args:
        path: Path the picker reports as chosen.

    Returns:
        Callable[..., tuple[str, str]]: Function with the static dialog's result shape.
    """

    def _pick(*_args: object, **_kwargs: object) -> tuple[str, str]:
        """Report the fixed path as the user's choice.

        Args:
            *_args: Ignored dialog arguments.
            **_kwargs: Ignored dialog keyword arguments.

        Returns:
            tuple[str, str]: The path and an empty filter.
        """
        return (path, "")

    return _pick


def _wait_for_run(qtbot: QtBot, host: _ScriptingHost) -> None:
    """Wait until the status label reports that the script finished or failed.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        host: Host whose script was started.
    """
    qtbot.waitUntil(lambda: host.status.text() in {"Done", "Error"}, timeout=_WAIT_MS)


@pytest.fixture(autouse=True)
def _sandbox_tempdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect the per-script sandbox directories into the test's temporary directory.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: pytest monkeypatch fixture.

    Returns:
        Path: The directory under which sandbox directories are created.
    """
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    return tmp_path


@pytest.fixture
def document() -> intellicrack_hexcore.HexDocument:
    """Open a real document over the sample bytes.

    Returns:
        intellicrack_hexcore.HexDocument: Document holding ``_SAMPLE``.
    """
    return intellicrack_hexcore.HexDocument.open_bytes(_SAMPLE)


@pytest.fixture
def hex_widget(qtbot: QtBot, document: intellicrack_hexcore.HexDocument) -> HexEditorWidget:
    """Create a real hex editor widget showing the sample document.

    Args:
        qtbot: pytest-qt fixture that owns the widget.
        document: Document to display.

    Returns:
        HexEditorWidget: Widget with the document attached.
    """
    widget = HexEditorWidget()
    qtbot.addWidget(widget)
    widget.set_document(document)
    return widget


@pytest.fixture
def host(
    qtbot: QtBot,
    document: intellicrack_hexcore.HexDocument,
    hex_widget: HexEditorWidget,
) -> Generator[_ScriptingHost]:
    """Create a host whose scripting tab is built and whose workers are joined on teardown.

    Args:
        qtbot: pytest-qt fixture that owns the host.
        document: Document the scripts operate on.
        hex_widget: Widget the document API reads cursor and selection from.

    Yields:
        _ScriptingHost: Host with the tab built.
    """
    instance = _ScriptingHost(document, hex_widget)
    qtbot.addWidget(instance)
    instance.build_tab()
    try:
        yield instance
    finally:
        drain_bridge_workers_for(instance)
        drain_bridge_workers()


def test_sandbox_violation_error_is_permission_error_carrying_message() -> None:
    """The violation error is a ``PermissionError`` whose only argument is the message."""
    error = _SandboxViolationError("denied here")
    assert isinstance(error, PermissionError)
    assert error.args == ("denied here",)
    assert str(error) == "denied here"


@pytest.mark.parametrize("method", ["write", "insert", "delete"])
def test_script_uses_writes_detects_each_mutating_doc_call(method: str) -> None:
    """A script that references ``doc.write``, ``doc.insert`` or ``doc.delete`` is flagged.

    Args:
        method: Mutating method name.
    """
    assert _script_uses_writes(f"doc.{method}(0, b'')") is True


@pytest.mark.parametrize(
    "source",
    [
        "doc.read(0, 1)",
        "doc.length()",
        "other.write(0, b'')",
        "self.doc.write(0, b'')",
        "write = 1",
    ],
)
def test_script_uses_writes_ignores_reads_and_foreign_receivers(source: str) -> None:
    """Read-only calls and mutators on objects other than the bare name ``doc`` are not flagged.

    Args:
        source: Script source without a document mutation.
    """
    assert _script_uses_writes(source) is False


def test_script_uses_writes_is_false_for_unparseable_source() -> None:
    """A script that does not parse is reported as not using writes instead of raising."""
    assert _script_uses_writes("def (") is False


@pytest.mark.parametrize(
    ("source", "node_name"),
    [
        ("import os", "Import"),
        ("from os import path", "ImportFrom"),
        ("global counter", "Global"),
        ("def outer():\n    nonlocal counter", "Nonlocal"),
        ("async def run():\n    pass", "AsyncFunctionDef"),
        ("def gen():\n    yield 1", "Yield"),
        ("def gen():\n    yield from range(3)", "YieldFrom"),
    ],
)
def test_validate_script_ast_rejects_forbidden_statements(source: str, node_name: str) -> None:
    """Imports, scope escapes, async constructs and generators are refused with the node's name.

    Args:
        source: Script containing the forbidden construct.
        node_name: Python AST class name expected in the message.
    """
    with pytest.raises(_SandboxViolationError) as excinfo:
        _validate_script_ast(source)
    assert str(excinfo.value) == f"{node_name} is not permitted in sandboxed scripts"


@pytest.mark.parametrize("attribute", ["__class__", "__subclasses__", "__globals__", "f_back"])
def test_validate_script_ast_rejects_forbidden_attribute_access(attribute: str) -> None:
    """Attribute chains that reach interpreter internals are refused by name.

    Args:
        attribute: Forbidden attribute name.
    """
    with pytest.raises(_SandboxViolationError) as excinfo:
        _validate_script_ast(f"value = doc.{attribute}")
    assert str(excinfo.value) == f"access to attribute '{attribute}' is forbidden"


@pytest.mark.parametrize("name", ["eval", "exec", "compile", "open", "__import__", "globals", "memoryview"])
def test_validate_script_ast_rejects_forbidden_names(name: str) -> None:
    """Escape-hatch builtins are refused wherever they appear as a bare name.

    Args:
        name: Forbidden builtin name.
    """
    with pytest.raises(_SandboxViolationError) as excinfo:
        _validate_script_ast(f"{name}('x')")
    assert str(excinfo.value) == f"name '{name}' is not permitted in sandboxed scripts"


@pytest.mark.parametrize(
    ("source", "target", "attribute"),
    [
        ("getattr(doc, '_inner')", "getattr", "_inner"),
        ("setattr(doc, '__dict__', 1)", "setattr", "__dict__"),
        ("hasattr(doc, '_doc')", "hasattr", "_doc"),
        ("delattr(doc, '_widget')", "delattr", "_widget"),
        ("doc.getattr(doc, '_inner')", "getattr", "_inner"),
    ],
)
def test_validate_script_ast_rejects_reflective_calls_with_private_constant(source: str, target: str, attribute: str) -> None:
    """Reflection helpers called with a constant private or forbidden attribute name are refused.

    Args:
        source: Script calling a reflective helper.
        target: Helper name expected in the message.
        attribute: Constant attribute name expected in the message.
    """
    with pytest.raises(_SandboxViolationError) as excinfo:
        _validate_script_ast(source)
    assert str(excinfo.value) == f"{target}(..., '{attribute}') is forbidden"


@pytest.mark.parametrize(
    "source",
    [
        "getattr(doc, 'length')",
        "getattr(doc, name)",
        "getattr(doc, 5)",
        "hasattr(doc)",
        "fns[0](1)",
        "(lambda: 1)()",
        "values = [1, 2, 3]\ntotal = sum(values)",
    ],
)
def test_validate_script_ast_accepts_public_reflection_and_unusual_callees(source: str) -> None:
    """Public attribute names, non-constant names and non-name callees pass validation.

    Args:
        source: Harmless script.
    """
    assert _validate_script_ast(source) is None


def test_safe_getattr_returns_public_attributes_and_defaults() -> None:
    """The replacement ``getattr`` resolves public names and honours a default for missing ones."""
    holder = io.StringIO("abc")
    assert _safe_getattr(holder, "getvalue")() == "abc"
    assert _safe_getattr(holder, "missing", "fallback") == "fallback"
    with pytest.raises(AttributeError):
        _safe_getattr(holder, "missing")


@pytest.mark.parametrize("name", ["_private", "__class__", 7])
def test_safe_getattr_refuses_private_forbidden_and_non_string_names(name: object) -> None:
    """Underscore names, forbidden names and non-string names are refused.

    Args:
        name: Attribute name to request.
    """
    with pytest.raises(_SandboxViolationError) as excinfo:
        _safe_getattr(io.StringIO(), name)
    assert str(excinfo.value) == f"getattr(..., {name!r}) is forbidden"


def test_safe_setattr_sets_public_attributes_only() -> None:
    """The replacement ``setattr`` assigns public names and refuses underscore and non-string names."""
    target = types.SimpleNamespace()
    _safe_setattr(target, "flag", 5)
    assert getattr(target, "flag") == 5
    for name in ("_hidden", "__dict__", 3):
        with pytest.raises(_SandboxViolationError) as excinfo:
            _safe_setattr(target, name, 1)
        assert str(excinfo.value) == f"setattr(..., {name!r}, ...) is forbidden"
    assert not hasattr(target, "_hidden")


def test_safe_hasattr_hides_private_and_forbidden_names() -> None:
    """The replacement ``hasattr`` answers truthfully for public names and ``False`` for hidden ones."""
    holder = io.StringIO()
    assert _safe_hasattr(holder, "getvalue") is True
    assert _safe_hasattr(holder, "missing") is False
    assert _safe_hasattr(holder, "_checkClosed") is False
    assert _safe_hasattr(holder, "__class__") is False
    assert _safe_hasattr(holder, 9) is False


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("C:/evil.txt", "must be a relative filename inside the script tempdir"),
        ("C:evil.txt", "must be a relative filename inside the script tempdir"),
        ("../evil.txt", "may not contain '..' segments"),
        ("a/../../evil.txt", "may not contain '..' segments"),
        ("/evil.txt", "escapes the script tempdir"),
    ],
)
def test_resolve_user_print_path_refuses_paths_outside_the_sandbox(tmp_path: Path, name: str, reason: str) -> None:
    """Absolute, drive-qualified, traversing and root-relative names never open a file.

    Args:
        tmp_path: Per-test temporary directory used as the sandbox.
        name: Requested file name.
        reason: Message tail documenting why the name is refused.
    """
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    opened: dict[str, Any] = {}
    with pytest.raises(_SandboxViolationError) as excinfo:
        _resolve_user_print_path(name, sandbox, opened)
    assert str(excinfo.value) == f"print(..., file={name!r}) {reason}"
    assert opened == {}
    assert list(sandbox.iterdir()) == []


def test_resolve_user_print_path_opens_once_and_creates_parents(tmp_path: Path) -> None:
    """A valid relative name opens one handle inside the sandbox and reuses it on the next call.

    Args:
        tmp_path: Per-test temporary directory used as the sandbox.
    """
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    opened: dict[str, Any] = {}
    try:
        first = _resolve_user_print_path("deep/dir/out.txt", sandbox, opened)
        handle = opened["deep/dir/out.txt"]
        second = _resolve_user_print_path("deep/dir/out.txt", sandbox, opened)
        assert first == second == (sandbox / "deep" / "dir" / "out.txt").resolve()
        assert opened["deep/dir/out.txt"] is handle
        assert len(opened) == 1
        assert first.parent.is_dir()
    finally:
        for handle in opened.values():
            handle.close()


def test_execute_script_captures_output_and_user_variables(document: intellicrack_hexcore.HexDocument) -> None:
    """Stdout is captured with ``sep``/``end`` honoured, and non-callable names are reported as ``repr`` strings.

    Args:
        document: Real document handed to the script.
    """
    result = _run(
        "x = 3\ny = [1, 2]\ndef helper():\n    pass\nprint('a', 'b', sep='-', end='!')\nprint('c', sep=None, end=None)",
        document,
    )
    assert result["output"] == "a-b!c\n"
    assert not result["stderr"]
    assert result["error"] is None
    assert result["traceback"] is None
    assert result["variables"] == {"x": "3", "y": "[1, 2]"}
    assert result["output_files"] == []


def test_execute_script_reports_runtime_errors_with_traceback(document: intellicrack_hexcore.HexDocument) -> None:
    """A script that raises yields its error text and traceback while keeping earlier output.

    Args:
        document: Real document handed to the script.
    """
    result = _run("print('before')\nvalue = 1 / 0", document)
    assert result["output"] == "before\n"
    assert result["error"] == "ZeroDivisionError: division by zero"
    assert result["traceback"].startswith("Traceback (most recent call last):")
    assert 'File "<script>", line 2' in result["traceback"]
    assert result["traceback"].rstrip().endswith("ZeroDivisionError: division by zero")


@pytest.mark.parametrize(
    ("statement", "exception_type"),
    [
        ("raise SystemExit(2)", SystemExit),
        ("raise KeyboardInterrupt()", KeyboardInterrupt),
        ("raise MemoryError('out of memory')", MemoryError),
    ],
)
def test_execute_script_propagates_critical_exceptions_after_closing_files(
    tmp_path: Path,
    document: intellicrack_hexcore.HexDocument,
    statement: str,
    exception_type: type[BaseException],
) -> None:
    """Interpreter-level exceptions escape the sandbox, and files the script opened are flushed and closed first.

    Args:
        tmp_path: Per-test temporary directory holding the sandbox.
        document: Real document handed to the script.
        statement: Statement raising the critical exception.
        exception_type: Exception class expected to propagate.
    """
    with pytest.raises(exception_type):
        _run(f"print('partial', file='p.txt')\n{statement}", document)
    written = next(tmp_path.glob(f"{_SANDBOX_GLOB}/p.txt"))
    assert written.read_text(encoding="utf-8") == "partial\n"


def test_execute_script_writes_named_files_inside_its_own_tempdir(tmp_path: Path, document: intellicrack_hexcore.HexDocument) -> None:
    """``print(..., file="name")`` creates files in a per-run directory and reports their absolute paths.

    Args:
        tmp_path: Per-test temporary directory holding the sandbox.
        document: Real document handed to the script.
    """
    result = _run(
        "print('alpha', file='out.txt')\nprint('beta', file='out.txt', flush=True)\nprint('gamma', file='sub/inner.txt')\nprint('shown')",
        document,
    )
    sandbox = next(tmp_path.glob(_SANDBOX_GLOB))
    assert result["output"] == "shown\n"
    assert result["error"] is None
    assert [Path(p).resolve() for p in result["output_files"]] == [
        (sandbox / "out.txt").resolve(),
        (sandbox / "sub" / "inner.txt").resolve(),
    ]
    assert (sandbox / "out.txt").read_text(encoding="utf-8") == "alpha\nbeta\n"
    assert (sandbox / "sub" / "inner.txt").read_text(encoding="utf-8") == "gamma\n"


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("C:/evil.txt", "must be a relative filename inside the script tempdir"),
        ("../evil.txt", "may not contain '..' segments"),
        ("/evil.txt", "escapes the script tempdir"),
    ],
)
def test_execute_script_reports_refused_print_targets(document: intellicrack_hexcore.HexDocument, name: str, reason: str) -> None:
    """A script printing to a path outside its tempdir fails with the sandbox violation and creates no file.

    Args:
        document: Real document handed to the script.
        name: Requested file name.
        reason: Message tail documenting why the name is refused.
    """
    result = _run(f"print('x', file={name!r})", document)
    assert result["error"] == f"_SandboxViolationError: print(..., file={name!r}) {reason}"
    assert result["output_files"] == []


def test_execute_script_routes_print_to_stderr_stdout_and_file_like_sinks() -> None:
    """``file=`` accepts the stdio handles and any object exposing ``write``."""
    sink = io.StringIO()
    handles: Any = types.SimpleNamespace(out=sys.stdout, err=sys.stderr, sink=sink)
    result = execute_script(
        "print('to-err', file=doc.err, flush=True)\n"
        "print('to-out', file=doc.out)\n"
        "print('a', 'b', file=doc.sink, flush=True)\n"
        "print('quiet', file=doc.sink)",
        handles,
    )
    assert result["error"] is None
    assert result["stderr"] == "to-err\n"
    assert result["output"] == "to-out\n"
    assert sink.getvalue() == "a b\nquiet\n"


def test_execute_script_rejects_print_target_without_write_method(document: intellicrack_hexcore.HexDocument) -> None:
    """A ``file=`` argument that is not a string or writable object raises ``TypeError`` inside the script.

    Args:
        document: Real document handed to the script.
    """
    result = _run("print('x', file=42)", document)
    assert result["error"] == "TypeError: print(..., file=42) requires a writable file-like object"


def test_execute_script_applies_safe_reflection_at_runtime(document: intellicrack_hexcore.HexDocument) -> None:
    """Dynamically built private names are refused by the replacement builtins while public ones work.

    Args:
        document: Real document handed to the script.
    """
    result = _run(
        "n = getattr(doc, 'length')()\n"
        "has_public = hasattr(doc, 'length')\n"
        "has_private = hasattr(doc, '_' + 'inner')\n"
        "getattr(doc, '_' + 'inner')",
        document,
    )
    assert result["variables"]["n"] == "16"
    assert result["variables"]["has_public"] == "True"
    assert result["variables"]["has_private"] == "False"
    assert result["error"] == "_SandboxViolationError: getattr(..., '_inner') is forbidden"
    refused_set = _run("setattr(doc, 'x' + 'y', 1)\nsetattr(doc, '_' + 'q', 1)", document)
    assert refused_set["error"] == "_SandboxViolationError: setattr(..., '_q', ...) is forbidden"


def test_execute_script_refuses_forbidden_constructs_before_running(tmp_path: Path, document: intellicrack_hexcore.HexDocument) -> None:
    """Validation failures raise before any code runs, so no sandbox directory is created for them.

    Args:
        tmp_path: Per-test temporary directory that would hold a sandbox.
        document: Real document handed to the script.
    """
    with pytest.raises(PermissionError, match="Import is not permitted in sandboxed scripts"):
        _run("import os", document)
    assert list(tmp_path.glob(_SANDBOX_GLOB)) == []


def test_read_only_script_cannot_mutate_document_via_private_attributes(document: intellicrack_hexcore.HexDocument) -> None:
    """Read-only mode must keep the document unchanged even when the script reaches for underscore attributes.

    Args:
        document: Real document handed to the script in read-only mode.
    """
    before = document.read(0, document.length())
    result = _run("doc._inner._doc.write_bytes(0, bytes([255]))", document)
    assert document.read(0, document.length()) == before
    assert result["error"] is not None


def test_doc_api_reports_path_length_and_reads_bytes(document: intellicrack_hexcore.HexDocument) -> None:
    """Path, length and read forward to the real document and return plain ``bytes``.

    Args:
        document: Real document under test.
    """
    api = _DocAPI(document, None, "C:/samples/x.bin")
    chunk = api.read(1, 3)
    assert api.file_path == "C:/samples/x.bin"
    assert api.length() == len(_SAMPLE)
    assert chunk == _SAMPLE[1:4]
    assert type(chunk) is bytes


def test_doc_api_write_insert_delete_edit_the_document(document: intellicrack_hexcore.HexDocument) -> None:
    """Write, insert and delete produce the same bytes as the equivalent ``bytearray`` edits.

    Args:
        document: Real document under test.
    """
    api = _DocAPI(document, None, None)
    model = bytearray(_SAMPLE)
    api.write(0, b"\xaa\xbb")
    model[0:2] = b"\xaa\xbb"
    api.insert(2, b"\x77\x78")
    model[2:2] = b"\x77\x78"
    api.delete(10, 3)
    del model[10:13]
    assert document.read(0, document.length()) == bytes(model)
    assert api.length() == len(model)


def test_doc_api_search_hex_returns_integer_pairs(document: intellicrack_hexcore.HexDocument) -> None:
    """Hex search with a wildcard finds every match, in order, and honours ``max_results``.

    Args:
        document: Real document under test.
    """
    api = _DocAPI(document, None, None)
    expected = [(m.start(), m.end() - m.start()) for m in re.finditer(rb"\xde\xad.\xef", _SAMPLE, re.DOTALL)]
    assert expected == [(1, 4), (6, 4)]
    assert api.search_hex("DE AD ?? EF") == expected
    assert api.search_hex("DE AD ?? EF", 1) == expected[:1]


def test_doc_api_search_text_resolves_encoding_in_priority_order() -> None:
    """Explicit encoding wins over the panel provider, which wins over the UTF-8 fallback.

    ``_TEXT_SAMPLE`` holds ``AB`` as ASCII at offset 0 and as UTF-16LE at offset 4.
    """
    document = intellicrack_hexcore.HexDocument.open_bytes(_TEXT_SAMPLE)
    utf16_offset = _TEXT_SAMPLE.find("AB".encode("utf-16-le"))
    assert utf16_offset == 4

    def _provider() -> str | None:
        """Report the panel's selected encoding.

        Returns:
            str | None: UTF-16 little endian.
        """
        return "utf-16le"

    def _silent_provider() -> str | None:
        """Report that the panel has no selected encoding.

        Returns:
            str | None: Always ``None``.
        """
        return None

    plain = _DocAPI(document, None, None)
    panel = _DocAPI(document, None, None, _provider)
    silent = _DocAPI(document, None, None, _silent_provider)
    assert plain.search_text("AB") == [(0, 2)]
    assert silent.search_text("AB") == [(0, 2)]
    assert panel.search_text("AB") == [(utf16_offset, 4)]
    assert panel.search_text("AB", encoding="utf-8") == [(0, 2)]
    assert plain.search_text("AB", encoding="utf-16le") == [(utf16_offset, 4)]


def test_doc_api_search_text_rejects_unknown_encoding_names() -> None:
    """A misspelled codec raises ``LookupError`` through both the full API and the read-only proxy."""
    document = intellicrack_hexcore.HexDocument.open_bytes(_TEXT_SAMPLE)
    api = _DocAPI(document, None, None)
    proxy = _ReadOnlyDocAPI(api)
    message = "unknown encoding 'no-such-codec' for doc.search_text"
    with pytest.raises(LookupError) as direct:
        api.search_text("AB", encoding="no-such-codec")
    with pytest.raises(LookupError) as proxied:
        proxy.search_text("AB", encoding="no-such-codec")
    assert str(direct.value) == message
    assert str(proxied.value) == message


def test_doc_api_add_bookmark_stores_bookmarks_with_defaults(document: intellicrack_hexcore.HexDocument) -> None:
    """Bookmarks added through the API appear in the document with the given and default attributes.

    Args:
        document: Real document under test.
    """
    api = _DocAPI(document, None, None)
    first = api.add_bookmark(4, 2, "header", "#00FF00")
    second = api.add_bookmark(9)
    third = _ReadOnlyDocAPI(api).add_bookmark(12, 3, "tail")
    assert (first, second, third) == (0, 1, 2)
    assert document.list_bookmarks() == [
        (4, 2, "header", "#00FF00"),
        (9, 1, "Bookmark", DEFAULT_BOOKMARK_COLOR),
        (12, 3, "tail", DEFAULT_BOOKMARK_COLOR),
    ]


def test_doc_api_cursor_and_selection_follow_the_real_widget(
    hex_widget: HexEditorWidget,
    document: intellicrack_hexcore.HexDocument,
) -> None:
    """Cursor and selection reads and writes go through the real widget, clamped to the document.

    Args:
        hex_widget: Real widget attached to the document.
        document: Real document under test.
    """
    api = _DocAPI(document, hex_widget, None)
    assert api.cursor == 0
    assert api.selection is None
    api.cursor = 7
    assert api.cursor == 7
    assert getattr(hex_widget, "_cursor_offset") == 7
    api.cursor = 1000
    assert api.cursor == len(_SAMPLE) - 1
    api.selection = (4, 9)
    assert api.selection == (4, 9)
    assert getattr(hex_widget, "_selection_start") == 4
    assert getattr(hex_widget, "_selection_end") == 9
    api.cursor = 3
    assert api.selection is None


def test_doc_api_cursor_and_selection_are_inert_without_a_capable_widget(document: intellicrack_hexcore.HexDocument) -> None:
    """Without a widget, or with one lacking the hooks, the cursor stays at zero and no selection exists.

    Args:
        document: Real document under test.
    """
    for widget in (None, object()):
        api = _DocAPI(document, widget, None)
        api.cursor = 9
        api.selection = (1, 2)
        assert api.cursor == 0
        assert api.selection is None


def test_doc_api_selection_requires_both_ends_to_be_set(hex_widget: HexEditorWidget, document: intellicrack_hexcore.HexDocument) -> None:
    """A selection whose end is unset is reported as no selection.

    Args:
        hex_widget: Real widget attached to the document.
        document: Real document under test.
    """
    api = _DocAPI(document, hex_widget, None)
    setattr(hex_widget, "_selection_start", 3)
    setattr(hex_widget, "_selection_end", -1)
    assert api.selection is None


def test_read_only_proxy_forwards_reads_and_navigation(hex_widget: HexEditorWidget, document: intellicrack_hexcore.HexDocument) -> None:
    """The proxy exposes the same read, search, cursor and selection results as the wrapped API.

    Args:
        hex_widget: Real widget attached to the document.
        document: Real document under test.
    """
    proxy = _ReadOnlyDocAPI(_DocAPI(document, hex_widget, "C:/samples/y.bin"))
    assert proxy.file_path == "C:/samples/y.bin"
    assert proxy.length() == len(_SAMPLE)
    assert proxy.read(5, 4) == _SAMPLE[5:9]
    assert proxy.search_hex("DE AD ?? EF", 5) == [(1, 4), (6, 4)]
    proxy.cursor = 6
    assert proxy.cursor == 6
    proxy.selection = (2, 5)
    assert proxy.selection == (2, 5)
    assert getattr(hex_widget, "_selection_end") == 5


@pytest.mark.parametrize(
    ("method", "arguments", "message"),
    [
        ("write", (0, b"\x01"), "doc.write is disabled in read-only script mode"),
        ("insert", (0, b"\x01"), "doc.insert is disabled in read-only script mode"),
        ("delete", (0, 1), "doc.delete is disabled in read-only script mode"),
    ],
)
def test_read_only_proxy_refuses_every_mutation(
    document: intellicrack_hexcore.HexDocument,
    method: str,
    arguments: tuple[Any, ...],
    message: str,
) -> None:
    """Write, insert and delete raise the sandbox violation and leave the document untouched.

    Args:
        document: Real document under test.
        method: Name of the mutator invoked on the proxy.
        arguments: Positional arguments passed to the mutator.
        message: Expected violation message.
    """
    proxy = _ReadOnlyDocAPI(_DocAPI(document, None, None))
    with pytest.raises(_SandboxViolationError) as excinfo:
        getattr(proxy, method)(*arguments)
    assert isinstance(excinfo.value, PermissionError)
    assert str(excinfo.value) == message
    assert document.read(0, document.length()) == _SAMPLE


def test_highlighter_skips_a_block_without_text(host: _ScriptingHost) -> None:
    """A ``None`` block is skipped without error and leaves the document text alone.

    Args:
        host: Host whose scripting tab and highlighter are built.
    """
    host.editor.setPlainText("def f(): return 1")
    text_document = host.editor.document()
    assert text_document is not None
    highlighters = text_document.findChildren(QSyntaxHighlighter)
    assert len(highlighters) == 1
    assert highlighters[0].highlightBlock(None) is None
    assert text_document.toPlainText() == "def f(): return 1"


def test_create_scripting_tab_builds_editor_buttons_and_console(host: _ScriptingHost) -> None:
    """The tab exposes the four buttons, an empty status, a read-only console and no worker.

    Args:
        host: Host whose scripting tab is built.
    """
    captions = [b.text() for b in host.findChildren(QPushButton)]
    assert captions == ["Run", "Load...", "Save...", "Clear Output"]
    assert host.button("Run").toolTip() == "Ctrl+Shift+R"
    assert not host.status.text()
    assert host.output.isReadOnly()
    assert not host.editor.isReadOnly()
    assert host.worker is None


def test_run_script_does_nothing_without_editor_document_or_source(qtbot: QtBot, document: intellicrack_hexcore.HexDocument) -> None:
    """The Run slot returns quietly when the tab is missing, the document is missing, or the source is blank.

    Args:
        qtbot: pytest-qt fixture that owns the hosts.
        document: Real document the hosts hold.
    """
    bare = _ScriptingHost(document)
    qtbot.addWidget(bare)
    bare.run()
    assert bare.worker is None

    without_document = _ScriptingHost(None)
    qtbot.addWidget(without_document)
    without_document.build_tab()
    without_document.editor.setPlainText("x = 1")
    without_document.run()
    assert without_document.worker is None
    assert not without_document.status.text()

    blank = _ScriptingHost(document)
    qtbot.addWidget(blank)
    blank.build_tab()
    blank.editor.setPlainText("  \n\t  ")
    blank.run()
    assert blank.worker is None
    assert not blank.status.text()


def test_run_script_does_not_start_a_second_worker_while_one_is_running(host: _ScriptingHost) -> None:
    """While a script worker is still running, pressing Run again changes nothing.

    Args:
        host: Host whose scripting tab is built.
    """
    release = threading.Event()
    blocker = run_callable_async(release.wait, 30.0)
    try:
        host.adopt_worker(blocker)
        host.editor.setPlainText("x = 1")
        host.run()
        assert host.worker is blocker
        assert not host.status.text()
    finally:
        release.set()
        drain_bridge_workers()


def test_run_script_executes_read_only_script_and_shows_results(qtbot: QtBot, host: _ScriptingHost) -> None:
    """A script without writes runs in the worker and its output and variables reach the console.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker.
        host: Host whose scripting tab is built.
    """
    host.editor.setPlainText("print(doc.length())\nx = 5\n")
    host.button("Run").click()
    assert host.status.text() == "Running..."
    _wait_for_run(qtbot, host)
    assert host.status.text() == "Done"
    assert host.output.toPlainText() == "16\n\n--- Variables ---\n  x = 5"


def test_run_script_exposes_path_cursor_and_selection_to_scripts(
    qtbot: QtBot,
    hex_widget: HexEditorWidget,
    host: _ScriptingHost,
    tmp_path: Path,
) -> None:
    """Scripts see the panel's file path, cursor and selection.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker.
        hex_widget: Real widget the host reads cursor and selection from.
        host: Host whose scripting tab is built.
        tmp_path: Per-test temporary directory supplying the file path.
    """
    sample_path = tmp_path / "sample.bin"
    host.file_path = sample_path
    hex_widget.goto_offset(5)
    hex_widget.set_selection_range(2, 6)
    host.editor.setPlainText("p = doc.file_path\nc = doc.cursor\ns = doc.selection")
    host.run()
    _wait_for_run(qtbot, host)
    assert host.output.toPlainText() == f"--- Variables ---\n  p = {str(sample_path)!r}\n  c = 5\n  s = (2, 6)"


def test_run_script_reports_no_path_when_the_panel_has_no_file(qtbot: QtBot, host: _ScriptingHost) -> None:
    """With no file loaded the script sees ``doc.file_path`` as ``None``.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker.
        host: Host whose scripting tab is built.
    """
    host.editor.setPlainText("p = doc.file_path")
    host.run()
    _wait_for_run(qtbot, host)
    assert host.output.toPlainText() == "--- Variables ---\n  p = None"


def test_run_script_without_status_label_still_shows_output(qtbot: QtBot, host: _ScriptingHost) -> None:
    """The Run slot and the result handler tolerate a missing status label.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker.
        host: Host whose scripting tab is built.
    """
    host.drop_status()
    host.editor.setPlainText("print('hello')")
    host.run()
    qtbot.waitUntil(lambda: host.output.toPlainText() == "hello\n", timeout=_WAIT_MS)


def test_run_script_with_writes_applies_them_when_the_user_agrees(
    monkeypatch: pytest.MonkeyPatch,
    qtbot: QtBot,
    host: _ScriptingHost,
    document: intellicrack_hexcore.HexDocument,
) -> None:
    """Answering Yes to the confirmation gives the script a writable document.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the confirmation dialog.
        qtbot: pytest-qt fixture used to wait for the worker.
        host: Host whose scripting tab is built.
        document: Real document the script modifies.
    """
    monkeypatch.setattr(QMessageBox, "question", _answer_yes)
    host.editor.setPlainText("doc.write(0, bytes([0xAA, 0xBB]))")
    host.run()
    _wait_for_run(qtbot, host)
    assert host.status.text() == "Done"
    assert document.read(0, 2) == b"\xaa\xbb"
    assert document.read(2, len(_SAMPLE) - 2) == _SAMPLE[2:]


def test_run_script_with_writes_stays_read_only_when_the_user_declines(
    monkeypatch: pytest.MonkeyPatch,
    qtbot: QtBot,
    host: _ScriptingHost,
    document: intellicrack_hexcore.HexDocument,
) -> None:
    """Answering No runs the script read-only, so the write fails and the document is unchanged.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the confirmation dialog.
        qtbot: pytest-qt fixture used to wait for the worker.
        host: Host whose scripting tab is built.
        document: Real document the script tries to modify.
    """
    monkeypatch.setattr(QMessageBox, "question", _answer_no)
    host.editor.setPlainText("doc.write(0, bytes([0xAA, 0xBB]))")
    host.run()
    _wait_for_run(qtbot, host)
    assert host.status.text() == "Error"
    assert "--- Traceback ---" in host.output.toPlainText()
    assert "_SandboxViolationError: doc.write is disabled in read-only script mode" in host.output.toPlainText()
    assert document.read(0, document.length()) == _SAMPLE


def test_run_script_shows_sandbox_rejection_as_an_error(qtbot: QtBot, host: _ScriptingHost) -> None:
    """A script that fails validation reaches the error handler instead of the result handler.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker.
        host: Host whose scripting tab is built.
    """
    host.editor.setPlainText("import os")
    host.run()
    _wait_for_run(qtbot, host)
    assert host.status.text() == "Error"
    assert host.output.toPlainText() == "Error:\n_SandboxViolationError: Import is not permitted in sandboxed scripts"


def test_run_script_searches_text_with_the_panels_selected_encoding(qtbot: QtBot, hex_widget: HexEditorWidget) -> None:
    """``doc.search_text`` uses the encoding currently selected in the panel's combo box.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker.
        hex_widget: Real widget attached to a document, replaced here by the text sample.
    """
    document = intellicrack_hexcore.HexDocument.open_bytes(_TEXT_SAMPLE)
    hex_widget.set_document(document)
    instance = _ScriptingHost(document, hex_widget)
    qtbot.addWidget(instance)
    instance.build_tab()
    combo = QComboBox()
    qtbot.addWidget(combo)
    combo.addItem("UTF-8", "utf-8")
    combo.addItem("UTF-16 LE", "utf-16le")
    instance.use_combo(combo)
    try:
        instance.editor.setPlainText("hits = doc.search_text('AB')")
        combo.setCurrentIndex(1)
        instance.run()
        _wait_for_run(qtbot, instance)
        assert instance.output.toPlainText() == "--- Variables ---\n  hits = [(4, 4)]"
        drain_bridge_workers_for(instance)
        combo.setCurrentIndex(0)
        instance.run()
        qtbot.waitUntil(lambda: instance.output.toPlainText().endswith("hits = [(0, 2)]"), timeout=_WAIT_MS)
    finally:
        drain_bridge_workers_for(instance)
        drain_bridge_workers()


def test_encoding_provider_reads_current_combo_data_then_text(qtbot: QtBot, document: intellicrack_hexcore.HexDocument) -> None:
    """The provider prefers the item's data, falls back to its text, and follows the live selection.

    Args:
        qtbot: pytest-qt fixture that owns the widgets.
        document: Real document the host holds.
    """
    instance = _ScriptingHost(document)
    qtbot.addWidget(instance)
    provider = instance.provider()
    assert provider() is None

    combo = QComboBox()
    qtbot.addWidget(combo)
    instance.use_combo(combo)
    assert provider() is None
    combo.addItem("UTF-16 LE", "utf-16le")
    combo.addItem("Plain text")
    combo.addItem("Latin-1", 5)
    combo.setCurrentIndex(0)
    assert provider() == "utf-16le"
    combo.setCurrentIndex(1)
    assert provider() == "Plain text"
    combo.setCurrentIndex(2)
    assert provider() == "Latin-1"


def test_encoding_provider_is_none_when_the_selector_lacks_combo_methods(qtbot: QtBot, document: intellicrack_hexcore.HexDocument) -> None:
    """An object that is not a combo box yields no encoding.

    Args:
        qtbot: pytest-qt fixture that owns the host.
        document: Real document the host holds.
    """
    instance = _ScriptingHost(document)
    qtbot.addWidget(instance)
    instance.use_combo(object())
    assert instance.provider()() is None


def test_script_finished_obj_forwards_dictionaries_only(host: _ScriptingHost) -> None:
    """Dictionary results are displayed; any other object is ignored.

    Args:
        host: Host whose scripting tab is built.
    """
    host.finished_obj(["not", "a", "dict"])
    assert not host.status.text()
    assert not host.output.toPlainText()
    host.finished_obj({"output": "forwarded\n"})
    assert host.status.text() == "Done"
    assert host.output.toPlainText() == "forwarded\n"


def test_script_finished_renders_every_section_in_order(host: _ScriptingHost) -> None:
    """A failed run shows stdout, stderr, files, variables and traceback in that order and marks the status as an error.

    Args:
        host: Host whose scripting tab is built.
    """
    host.finished(
        {
            "output": "hello\n",
            "stderr": "warn\n",
            "error": "ValueError: bad",
            "traceback": "Traceback (most recent call last):\nValueError: bad\n",
            "variables": {"x": "1", "y": "'a'"},
            "output_files": ["C:/o/a.txt", "C:/o/b.txt"],
        },
    )
    assert host.status.text() == "Error"
    assert host.output.toPlainText() == (
        "hello\n\n--- stderr ---\nwarn\n\n--- Files ---\n  C:/o/a.txt\n  C:/o/b.txt\n--- Variables ---\n  x = 1\n  y = 'a'\n"
        "--- Traceback ---\nTraceback (most recent call last):\nValueError: bad\n"
    )


def test_script_finished_with_empty_result_reports_done_and_blank_console(host: _ScriptingHost) -> None:
    """A result with no sections is a success with an empty console.

    Args:
        host: Host whose scripting tab is built.
    """
    host.output.setPlainText("stale")
    host.finished({"traceback": None})
    assert host.status.text() == "Done"
    assert not host.output.toPlainText()


def test_script_finished_tolerates_missing_status_and_console(host: _ScriptingHost) -> None:
    """The result handler skips whichever of the status label or console does not exist.

    Args:
        host: Host whose scripting tab is built.
    """
    console = host.output
    host.drop_status()
    host.finished({"output": "kept\n"})
    assert console.toPlainText() == "kept\n"
    host.drop_output()
    host.finished({"output": "ignored\n"})
    assert console.toPlainText() == "kept\n"


def test_script_finished_requests_a_viewport_repaint_from_widgets_that_support_it(
    qtbot: QtBot,
    document: intellicrack_hexcore.HexDocument,
) -> None:
    """After a run the hex widget is asked to repaint once, and widgets without the hook are left alone.

    Args:
        qtbot: pytest-qt fixture that owns the widgets.
        document: Real document the widget shows.
    """
    widget = _CountingHexWidget()
    qtbot.addWidget(widget)
    widget.set_document(document)
    instance = _ScriptingHost(document, widget)
    qtbot.addWidget(instance)
    instance.build_tab()
    before = widget.viewport_updates
    instance.finished({"output": "x\n"})
    assert widget.viewport_updates == before + 1

    for other in (object(), None):
        plain = _ScriptingHost(document, other)
        qtbot.addWidget(plain)
        plain.build_tab()
        plain.finished({"output": "y\n"})
        assert plain.output.toPlainText() == "y\n"


def test_script_error_shows_message_in_status_and_console(host: _ScriptingHost) -> None:
    """The error handler marks the status and writes the message under an ``Error:`` heading.

    Args:
        host: Host whose scripting tab is built.
    """
    host.error("RuntimeError: broke")
    assert host.status.text() == "Error"
    assert host.output.toPlainText() == "Error:\nRuntimeError: broke"


def test_script_error_obj_formats_exception_type_and_message(host: _ScriptingHost) -> None:
    """The exception forwarder renders ``Type: message`` before displaying it.

    Args:
        host: Host whose scripting tab is built.
    """
    host.error_obj(ValueError("boom"))
    assert host.status.text() == "Error"
    assert host.output.toPlainText() == "Error:\nValueError: boom"


def test_script_error_tolerates_missing_status_and_console(host: _ScriptingHost) -> None:
    """The error handler skips whichever of the status label or console does not exist.

    Args:
        host: Host whose scripting tab is built.
    """
    console = host.output
    host.drop_status()
    host.error("first")
    assert console.toPlainText() == "Error:\nfirst"
    host.drop_output()
    host.error("second")
    assert console.toPlainText() == "Error:\nfirst"


def test_clear_output_empties_console_and_status(host: _ScriptingHost) -> None:
    """The Clear Output button empties both the console and the status label.

    Args:
        host: Host whose scripting tab is built.
    """
    host.output.setPlainText("old output")
    host.status.setText("Done")
    host.button("Clear Output").click()
    assert not host.output.toPlainText()
    assert not host.status.text()


def test_clear_output_tolerates_missing_console_and_status(host: _ScriptingHost) -> None:
    """Clearing with the console or status label absent does not raise and clears what exists.

    Args:
        host: Host whose scripting tab is built.
    """
    host.status.setText("Done")
    host.drop_output()
    host.clear()
    assert not host.status.text()
    host.drop_status()
    host.clear()


def test_load_script_reads_the_chosen_file_into_the_editor(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, host: _ScriptingHost) -> None:
    """The Load button replaces the editor text with the chosen file's UTF-8 content.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory holding the script file.
        host: Host whose scripting tab is built.
    """
    script = tmp_path / "loaded.py"
    script.write_bytes("name = 'h\u00e9llo'".encode())
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(str(script)))
    host.editor.setPlainText("old")
    host.button("Load...").click()
    assert host.editor.toPlainText() == "name = 'h\u00e9llo'"


def test_load_script_keeps_editor_when_the_file_cannot_be_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    host: _ScriptingHost,
) -> None:
    """A path that cannot be read leaves the editor text unchanged.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory; the chosen file does not exist in it.
        host: Host whose scripting tab is built.
    """
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(str(tmp_path / "missing.py")))
    host.editor.setPlainText("keep me")
    host.load()
    assert host.editor.toPlainText() == "keep me"


def test_load_script_does_nothing_when_the_dialog_is_cancelled_or_editor_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    host: _ScriptingHost,
) -> None:
    """A cancelled dialog, or a missing editor, leaves everything untouched.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory holding a readable script.
        host: Host whose scripting tab is built.
    """
    script = tmp_path / "readable.py"
    script.write_text("x = 1", encoding="utf-8")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(""))
    host.editor.setPlainText("keep me")
    host.load()
    assert host.editor.toPlainText() == "keep me"

    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(str(script)))
    editor = host.editor
    host.drop_editor()
    host.load()
    assert editor.toPlainText() == "keep me"


def test_save_script_writes_editor_text_as_utf8(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, host: _ScriptingHost) -> None:
    """The Save button writes the editor's text to the chosen file encoded as UTF-8.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory receiving the saved script.
        host: Host whose scripting tab is built.
    """
    target = tmp_path / "saved.py"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _file_picker(str(target)))
    host.editor.setPlainText("print('caf\u00e9')")
    host.button("Save...").click()
    assert target.read_bytes() == "print('caf\u00e9')".encode()


def test_save_script_survives_an_unwritable_target(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, host: _ScriptingHost) -> None:
    """A target in a directory that does not exist is reported through the log and creates nothing.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory; the chosen parent directory is absent.
        host: Host whose scripting tab is built.
    """
    target = tmp_path / "absent-dir" / "saved.py"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _file_picker(str(target)))
    host.editor.setPlainText("x = 1")
    host.save()
    assert not target.exists()
    assert not target.parent.exists()


def test_save_script_does_nothing_when_cancelled_or_editor_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    host: _ScriptingHost,
) -> None:
    """A cancelled dialog, or a missing editor, writes no file.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory that must stay empty of saved scripts.
        host: Host whose scripting tab is built.
    """
    target = tmp_path / "never.py"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _file_picker(""))
    host.save()
    assert not target.exists()

    monkeypatch.setattr(QFileDialog, "getSaveFileName", _file_picker(str(target)))
    host.drop_editor()
    host.save()
    assert not target.exists()
