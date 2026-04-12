# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge Python script execution with restricted namespace."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path


pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        T: The result of the coroutine.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


class TestScriptOutput:
    """Tests for Python script output capture."""

    def test_script_print_captured(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that print() output is captured in the result.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "script.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        result = _run(bridge.run_python_script('print("hello")'))
        assert result["output"] == "hello\n"

    def test_script_variables_returned(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that user-defined variables appear in the result variables dict.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "script_vars.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        result = _run(bridge.run_python_script("x = 42"))
        assert "x" in result["variables"]
        assert "42" in result["variables"]["x"]


class TestScriptDocumentAccess:
    """Tests for script access to the hex document API."""

    def test_script_doc_read(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify scripts can read document bytes via doc.read().

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "script_read.bin"
        f.write_bytes(b"\xAA\xBB\xCC\xDD" + b"\x00" * 60)
        _run(bridge.open_file(str(f)))
        result = _run(bridge.run_python_script("data = doc.read(0, 4)\nprint(len(data))"))
        assert "4" in result["output"]

    def test_script_doc_write(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify scripts can write bytes via doc.write().

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "script_write.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        _run(bridge.run_python_script("doc.write(0, [0x90, 0x90])"))
        result = _run(bridge.read_bytes(0, 2))
        assert result.replace(" ", "").lower() == "9090"

    def test_script_doc_length(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify scripts can query document length via doc.length().

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "script_len.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        result = _run(bridge.run_python_script("print(doc.length())"))
        assert "64" in result["output"]


class TestScriptErrors:
    """Tests for script error handling and reporting."""

    def test_script_syntax_error(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify syntax errors are reported in the error field.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "script_syn.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        result = _run(bridge.run_python_script("def foo("))
        assert "SyntaxError" in result["error"]

    def test_script_runtime_error(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify runtime errors are reported in the error field.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "script_rt.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        result = _run(bridge.run_python_script("1/0"))
        assert "ZeroDivisionError" in result["error"]


class TestScriptSandbox:
    """Tests for script sandbox restrictions blocking dangerous operations."""

    def test_script_import_blocked(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify __import__ is removed from the namespace.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "script_import.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        result = _run(bridge.run_python_script("import os"))
        assert result["error"]

    def test_script_eval_blocked(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify eval() is removed from the namespace.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "script_eval.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        result = _run(bridge.run_python_script('eval("1+1")'))
        assert result["error"]

    def test_script_open_blocked(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify open() is removed from the namespace.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "script_open.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        result = _run(bridge.run_python_script('open("test.txt")'))
        assert result["error"]

    def test_no_document_raises(self, bridge: HexEditorBridge) -> None:
        """Verify run_python_script raises RuntimeError without a document.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.run_python_script('print("test")'))
