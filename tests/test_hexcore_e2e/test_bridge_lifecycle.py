# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge initialization, file operations, and shutdown."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from pathlib import Path


def _run(coro: Any) -> Any:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        Any: The result of the coroutine.
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


class TestBridgeInit:
    """Tests covering bridge availability reporting and initialization state."""

    def test_is_available_returns_true_when_hexcore_installed(self, bridge: Any) -> None:
        """Verify that is_available returns True when hexcore is built.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        result: bool = _run(bridge.is_available())
        assert result is True

    def test_initialize_sets_connected_state(self, bridge: Any) -> None:
        """Verify that initialize marks the bridge as connected.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        assert bridge._state.connected is True

    def test_initialize_sets_tool_running(self, bridge: Any) -> None:
        """Verify that initialize marks the bridge tool as running.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        assert bridge._state.tool_running is True

    def test_bridge_has_no_document_after_init(self, bridge: Any) -> None:
        """Verify that no document is loaded immediately after initialization.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        assert bridge._document is None


class TestBridgeFileOps:
    """Tests covering open_file, close_file, and reopen semantics."""

    def test_open_file_returns_dict_with_file_path(
        self, bridge: Any, pe_binary: Path
    ) -> None:
        """Verify that open_file returns a dict containing file_path.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        result: dict[str, Any] = _run(bridge.open_file(str(pe_binary)))
        assert "file_path" in result
        assert result["file_path"] == str(pe_binary)

    def test_open_file_returns_dict_with_positive_size(
        self, bridge: Any, pe_binary: Path
    ) -> None:
        """Verify that open_file returns a dict with a positive size field.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        result: dict[str, Any] = _run(bridge.open_file(str(pe_binary)))
        assert "size" in result
        assert result["size"] > 0

    def test_open_file_returns_dict_with_modified_false(
        self, bridge: Any, pe_binary: Path
    ) -> None:
        """Verify that open_file returns modified=False for a freshly opened file.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        result: dict[str, Any] = _run(bridge.open_file(str(pe_binary)))
        assert result["modified"] is False

    def test_close_file_returns_true_when_open(
        self, bridge: Any, pe_binary: Path
    ) -> None:
        """Verify that close_file returns True when a file is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        closed: bool = _run(bridge.close_file())
        assert closed is True

    def test_close_file_returns_false_when_already_closed(
        self, bridge: Any
    ) -> None:
        """Verify that close_file returns False when no file is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        closed: bool = _run(bridge.close_file())
        assert closed is False

    def test_open_then_close_then_reopen_succeeds(
        self, bridge: Any, pe_binary: Path
    ) -> None:
        """Verify that a file can be closed and reopened with consistent size.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        first: dict[str, Any] = _run(bridge.open_file(str(pe_binary)))
        _run(bridge.close_file())
        second: dict[str, Any] = _run(bridge.open_file(str(pe_binary)))
        assert first["size"] == second["size"]

    def test_open_file_sets_binary_loaded_state(
        self, bridge: Any, pe_binary: Path
    ) -> None:
        """Verify that open_file marks binary_loaded on the bridge state.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        assert bridge._state.binary_loaded is True

    def test_close_file_clears_binary_loaded_state(
        self, bridge: Any, pe_binary: Path
    ) -> None:
        """Verify that close_file clears binary_loaded on the bridge state.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        _run(bridge.close_file())
        assert bridge._state.binary_loaded is False


class TestBridgeShutdown:
    """Tests covering shutdown behavior and post-shutdown operation safety."""

    def test_shutdown_clears_document(
        self, bridge: Any, pe_binary: Path
    ) -> None:
        """Verify that shutdown discards the open document reference.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        _run(bridge.shutdown())
        assert bridge._document is None

    def test_shutdown_resets_cursor_offset(
        self, bridge: Any, pe_binary: Path
    ) -> None:
        """Verify that shutdown resets the cursor offset to zero.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        _run(bridge.goto_offset(128))
        _run(bridge.shutdown())
        assert bridge._cursor_offset == 0

    def test_operations_after_shutdown_raise_or_return_gracefully(
        self, bridge: Any, pe_binary: Path
    ) -> None:
        """Verify that read_bytes after shutdown raises RuntimeError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        _run(bridge.shutdown())
        with pytest.raises(RuntimeError):
            _run(bridge.read_bytes(0, 4))
