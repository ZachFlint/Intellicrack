# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge sandbox integration error paths."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest


pytest.importorskip("intellicrack_hexcore")


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


class _MinimalRegistry:
    """Minimal stub registry that returns None for all bridge lookups."""

    def get(self, _name: Any) -> None:
        """Return None for any bridge name.

        Args:
            _name: Bridge name to look up.

        Returns:
            None: Always None, simulating missing sandbox bridge.
        """
        return


class TestSaveToSandboxErrorPaths:
    """Tests covering save_to_sandbox validation error paths."""

    def test_save_to_sandbox_no_document_raises_runtime_error(
        self, bridge: Any
    ) -> None:
        """Verify save_to_sandbox raises RuntimeError when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.save_to_sandbox("/sandbox/target.bin"))

    def test_save_to_sandbox_no_tool_registry_raises_runtime_error(
        self, loaded_bridge: Any
    ) -> None:
        """Verify save_to_sandbox raises RuntimeError when tool registry is not set.

        Args:
            loaded_bridge: HexEditorBridge with a PE file already opened.
        """
        loaded_bridge._tool_registry = None
        with pytest.raises(RuntimeError, match="tool registry"):
            _run(loaded_bridge.save_to_sandbox("/sandbox/target.bin"))

    def test_save_to_sandbox_no_sandbox_bridge_raises_runtime_error(
        self, loaded_bridge: Any
    ) -> None:
        """Verify save_to_sandbox raises RuntimeError when sandbox bridge is absent.

        Args:
            loaded_bridge: HexEditorBridge with a PE file already opened.
        """
        loaded_bridge.set_tool_registry(_MinimalRegistry())
        with pytest.raises(RuntimeError, match="sandbox bridge not available"):
            _run(loaded_bridge.save_to_sandbox("/sandbox/target.bin"))

    def test_save_to_sandbox_document_required_before_registry(
        self, bridge: Any
    ) -> None:
        """Verify save_to_sandbox checks for open document before registry access.

        The no-document check must fire before any registry lookup.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        bridge.set_tool_registry(_MinimalRegistry())
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.save_to_sandbox("/sandbox/target.bin"))

    def test_save_to_sandbox_sandbox_type_forwarded(
        self, loaded_bridge: Any
    ) -> None:
        """Verify save_to_sandbox fails on missing bridge even with custom sandbox_type.

        Args:
            loaded_bridge: HexEditorBridge with a PE file already opened.
        """
        loaded_bridge.set_tool_registry(_MinimalRegistry())
        with pytest.raises(RuntimeError):
            _run(loaded_bridge.save_to_sandbox("/sandbox/target.bin", sandbox_type="qemu"))


class TestTestInSandboxErrorPaths:
    """Tests covering test_in_sandbox validation error paths."""

    def test_test_in_sandbox_no_document_raises_runtime_error(
        self, bridge: Any
    ) -> None:
        """Verify test_in_sandbox raises RuntimeError when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.test_in_sandbox())

    def test_test_in_sandbox_no_tool_registry_raises_runtime_error(
        self, loaded_bridge: Any
    ) -> None:
        """Verify test_in_sandbox raises RuntimeError when tool registry is not set.

        The method reaches the save_to_sandbox step first, which checks the registry.

        Args:
            loaded_bridge: HexEditorBridge with a PE file already opened.
        """
        loaded_bridge._tool_registry = None
        with pytest.raises(RuntimeError, match="tool registry"):
            _run(loaded_bridge.test_in_sandbox())

    def test_test_in_sandbox_no_sandbox_bridge_raises_runtime_error(
        self, loaded_bridge: Any
    ) -> None:
        """Verify test_in_sandbox raises RuntimeError when sandbox bridge is absent.

        Args:
            loaded_bridge: HexEditorBridge with a PE file already opened.
        """
        loaded_bridge.set_tool_registry(_MinimalRegistry())
        with pytest.raises(RuntimeError, match="sandbox bridge not available"):
            _run(loaded_bridge.test_in_sandbox())

    def test_test_in_sandbox_with_args_still_requires_document(
        self, bridge: Any
    ) -> None:
        """Verify test_in_sandbox raises RuntimeError for no-document even with args set.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.test_in_sandbox(args="--flag", sandbox_type="docker", timeout=10))


class TestSetToolRegistry:
    """Tests covering the set_tool_registry method."""

    def test_set_tool_registry_method_exists(self, bridge: Any) -> None:
        """Verify the bridge exposes set_tool_registry as a callable.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        assert callable(getattr(bridge, "set_tool_registry", None))

    def test_set_tool_registry_stores_registry(self, bridge: Any) -> None:
        """Verify that set_tool_registry persists the provided registry.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        registry = _MinimalRegistry()
        bridge.set_tool_registry(registry)
        assert bridge._tool_registry is registry
