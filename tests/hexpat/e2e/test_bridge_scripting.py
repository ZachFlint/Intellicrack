# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests asserting that HexEditorBridge Python script execution is disabled.

The in-process ``run_python_script`` feature was permanently removed because the
hand-rolled builtin denylist could be escaped (for example via
``().__class__.__base__.__subclasses__()``) to reach
:class:`subprocess.Popen` / :func:`os.system`. As the method is registered as an
LLM-callable tool, that was a remote-code-execution path on the host. The method
binding is preserved so tool dispatch still resolves, but every invocation now
raises a typed :class:`~intellicrack.core.types.ToolError`. These tests pin that
disabled contract.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)


_DISABLED_MESSAGE = "hex_editor.run_python_script is disabled"


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


class TestRunPythonScriptDisabled:
    """Tests asserting that run_python_script is permanently disabled."""

    def test_disabled_with_document_open(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify run_python_script raises ToolError even when a document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "script.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        with pytest.raises(ToolError, match=_DISABLED_MESSAGE):
            _run(bridge.run_python_script('print("hello")'))

    def test_disabled_without_document(self, bridge: HexEditorBridge) -> None:
        """Verify run_python_script raises ToolError when no document is open.

        The disabled guard short-circuits before any document state is
        consulted, so the failure mode is identical with or without an open
        document.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(ToolError, match=_DISABLED_MESSAGE):
            _run(bridge.run_python_script('print("test")'))

    def test_disabled_for_empty_source(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify run_python_script rejects empty source rather than executing it.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "script_empty.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        with pytest.raises(ToolError, match=_DISABLED_MESSAGE):
            _run(bridge.run_python_script(""))

    def test_disabled_message_explains_sandbox_removal(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify the ToolError message states the in-process sandbox was removed.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "script_msg.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        with pytest.raises(ToolError) as exc_info:
            _run(bridge.run_python_script("x = 42"))
        message = str(exc_info.value)
        assert _DISABLED_MESSAGE in message
        assert "cannot be safely sandboxed" in message

    def test_disabled_does_not_execute_dangerous_source(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify dangerous source is rejected outright and never executed.

        Source that the old sandbox attempted to block (imports, ``eval``,
        ``open``) must now raise the disabled ToolError instead of running.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "script_danger.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        for source in ("import os", 'eval("1+1")', 'open("test.txt")'):
            with pytest.raises(ToolError, match=_DISABLED_MESSAGE):
                _run(bridge.run_python_script(source))
