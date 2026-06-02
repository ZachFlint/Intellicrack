# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""End-to-end tests for HexEditorBridge sandbox integration.

These tests drive the real :class:`HexEditorBridge` against a real
:class:`ToolRegistry` holding a real :class:`SandboxBridge`. No bridge or
tool response is mocked: the document/registry/sandbox-bridge precondition
checks, the cross-bridge ``ToolName.SANDBOX`` lookup, and the forwarding of
the ``sandbox_type`` argument into the sandbox bridge's own validation are
all exercised through to the genuine error each layer produces.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ToolError, ToolName


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from intellicrack.bridges.hex_editor import HexEditorBridge


pytest.importorskip("intellicrack_hexcore")


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously and return its result.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        T: The result produced by awaiting ``coro``.
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


@pytest.fixture
def empty_registry() -> ToolRegistry:
    """Create a real ToolRegistry that holds no bridges.

    Returns:
        ToolRegistry: A registry whose ``get(ToolName.SANDBOX)`` returns None.
    """
    return ToolRegistry(Path(tempfile.gettempdir()))


@pytest.fixture
def sandbox_registry() -> ToolRegistry:
    """Create a real ToolRegistry with a real SandboxBridge registered.

    Returns:
        ToolRegistry: A registry whose ``get(ToolName.SANDBOX)`` returns a
        live :class:`SandboxBridge` instance.
    """
    registry = ToolRegistry(Path(tempfile.gettempdir()))
    registry.register_bridge(ToolName.SANDBOX, SandboxBridge())
    return registry


class TestSaveToSandboxPreconditionOrdering:
    """Validate the precondition checks of save_to_sandbox in order."""

    def test_no_document_raises_exact_runtime_error(self, bridge: HexEditorBridge, sandbox_registry: ToolRegistry) -> None:
        """save_to_sandbox rejects a missing document before any registry use.

        A registry that *does* contain a working sandbox bridge is supplied so
        the test proves the no-document guard fires first; if the guard were
        removed the call would instead reach the sandbox bridge and fail with a
        different error, which this exact-message assertion would catch.

        Args:
            bridge: An initialized HexEditorBridge with no document open.
            sandbox_registry: A registry holding a real SandboxBridge.
        """
        bridge.set_tool_registry(sandbox_registry)
        assert bridge.document is None

        with pytest.raises(RuntimeError) as exc_info:
            _run(bridge.save_to_sandbox("/sandbox/target.bin"))

        assert str(exc_info.value) == "no document open"

    def test_no_tool_registry_raises_exact_runtime_error(self, loaded_bridge: HexEditorBridge) -> None:
        """save_to_sandbox surfaces the registry-missing guard after document check.

        Args:
            loaded_bridge: HexEditorBridge with a real PE document opened.
        """
        loaded_bridge.tool_registry = None
        assert loaded_bridge.document is not None

        with pytest.raises(RuntimeError) as exc_info:
            _run(loaded_bridge.save_to_sandbox("/sandbox/target.bin"))

        assert str(exc_info.value) == "tool registry not set; cannot access sandbox bridge"

    def test_empty_registry_raises_sandbox_unavailable(self, loaded_bridge: HexEditorBridge, empty_registry: ToolRegistry) -> None:
        """save_to_sandbox reports the real empty-registry ToolName.SANDBOX miss.

        The lookup is exercised against a real, empty ToolRegistry. The exact
        ``sandbox bridge not available`` message can only be produced after
        ``registry.get(ToolName.SANDBOX)`` returns None, proving the genuine
        lookup path is taken rather than an unrelated guard.

        Args:
            loaded_bridge: HexEditorBridge with a real PE document opened.
            empty_registry: A real registry containing no sandbox bridge.
        """
        assert empty_registry.get(ToolName.SANDBOX) is None
        loaded_bridge.set_tool_registry(empty_registry)

        with pytest.raises(RuntimeError) as exc_info:
            _run(loaded_bridge.save_to_sandbox("/sandbox/target.bin"))

        assert str(exc_info.value) == "sandbox bridge not available"

    def test_populated_registry_passes_unavailable_guard(self, loaded_bridge: HexEditorBridge, sandbox_registry: ToolRegistry) -> None:
        """A registered sandbox bridge moves past the availability guard into create.

        With a real SandboxBridge present, the ``sandbox bridge not available``
        guard must NOT fire; instead the bridge forwards an invalid
        ``sandbox_type`` to the real ``SandboxBridge.create``, which raises a
        :class:`ToolError` whose exact message proves the argument was passed
        through unchanged. This is the boundary the audit demanded: the same
        operation that fails on an empty registry succeeds past the guard here.

        Args:
            loaded_bridge: HexEditorBridge with a real PE document opened.
            sandbox_registry: A registry holding a real SandboxBridge.
        """
        assert isinstance(sandbox_registry.get(ToolName.SANDBOX), SandboxBridge)
        loaded_bridge.set_tool_registry(sandbox_registry)

        with pytest.raises(ToolError) as exc_info:
            _run(loaded_bridge.save_to_sandbox("/sandbox/target.bin", sandbox_type="not-a-real-type"))

        assert str(exc_info.value) == "Invalid sandbox_type: 'not-a-real-type'"

    def test_sandbox_type_forwarded_verbatim_to_real_bridge(self, loaded_bridge: HexEditorBridge, sandbox_registry: ToolRegistry) -> None:
        """save_to_sandbox forwards the exact sandbox_type string into create.

        The sandbox bridge echoes the offending value back inside its
        ``ToolError`` message, so the test asserts the precise string round
        trips, proving no silent rewrite or default substitution occurs.

        Args:
            loaded_bridge: HexEditorBridge with a real PE document opened.
            sandbox_registry: A registry holding a real SandboxBridge.
        """
        loaded_bridge.set_tool_registry(sandbox_registry)

        with pytest.raises(ToolError) as exc_info:
            _run(loaded_bridge.save_to_sandbox("/sandbox/target.bin", sandbox_type="Windows"))

        assert str(exc_info.value) == "Invalid sandbox_type: 'Windows'"


class TestTestInSandboxPreconditionOrdering:
    """Validate the precondition checks of test_in_sandbox in order."""

    def test_no_document_raises_exact_runtime_error(self, bridge: HexEditorBridge, sandbox_registry: ToolRegistry) -> None:
        """test_in_sandbox rejects a missing document before any registry use.

        Args:
            bridge: An initialized HexEditorBridge with no document open.
            sandbox_registry: A registry holding a real SandboxBridge.
        """
        bridge.set_tool_registry(sandbox_registry)
        assert bridge.document is None

        with pytest.raises(RuntimeError) as exc_info:
            _run(bridge.test_in_sandbox())

        assert str(exc_info.value) == "no document open"

    def test_no_tool_registry_raises_exact_runtime_error(self, loaded_bridge: HexEditorBridge) -> None:
        """test_in_sandbox surfaces its own registry-missing message.

        ``test_in_sandbox`` uses a distinct message from ``save_to_sandbox``;
        the exact-string assertion proves which code path produced the error.

        Args:
            loaded_bridge: HexEditorBridge with a real PE document opened.
        """
        loaded_bridge.tool_registry = None
        assert loaded_bridge.document is not None

        with pytest.raises(RuntimeError) as exc_info:
            _run(loaded_bridge.test_in_sandbox())

        assert str(exc_info.value) == "tool registry not set"

    def test_empty_registry_raises_sandbox_unavailable(self, loaded_bridge: HexEditorBridge, empty_registry: ToolRegistry) -> None:
        """test_in_sandbox reports the real empty-registry ToolName.SANDBOX miss.

        Args:
            loaded_bridge: HexEditorBridge with a real PE document opened.
            empty_registry: A real registry containing no sandbox bridge.
        """
        assert empty_registry.get(ToolName.SANDBOX) is None
        loaded_bridge.set_tool_registry(empty_registry)

        with pytest.raises(RuntimeError) as exc_info:
            _run(loaded_bridge.test_in_sandbox())

        assert str(exc_info.value) == "sandbox bridge not available"

    def test_populated_registry_forwards_args_to_real_run_binary(
        self,
        loaded_bridge: HexEditorBridge,
        sandbox_registry: ToolRegistry,
    ) -> None:
        """test_in_sandbox forwards sandbox_type into the real run_binary path.

        With a real SandboxBridge registered, an invalid ``sandbox_type``
        reaches ``SandboxBridge.run_binary`` and triggers its up-front
        validation, proving the document path, registry lookup, and argument
        forwarding all completed before the failure.

        Args:
            loaded_bridge: HexEditorBridge with a real PE document opened.
            sandbox_registry: A registry holding a real SandboxBridge.
        """
        assert isinstance(sandbox_registry.get(ToolName.SANDBOX), SandboxBridge)
        loaded_bridge.set_tool_registry(sandbox_registry)

        with pytest.raises(ToolError) as exc_info:
            _run(loaded_bridge.test_in_sandbox(args="--flag", sandbox_type="docker", time_limit=10))

        assert str(exc_info.value) == "Invalid sandbox_type: 'docker'"


class TestSetToolRegistry:
    """Validate set_tool_registry wiring against the live save path."""

    def test_set_tool_registry_stores_exact_instance(self, bridge: HexEditorBridge, sandbox_registry: ToolRegistry) -> None:
        """set_tool_registry persists the exact registry object it is given.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            sandbox_registry: A registry holding a real SandboxBridge.
        """
        assert bridge.tool_registry is None
        bridge.set_tool_registry(sandbox_registry)
        assert bridge.tool_registry is sandbox_registry

    def test_stored_registry_is_consulted_by_save_to_sandbox(self, loaded_bridge: HexEditorBridge, sandbox_registry: ToolRegistry) -> None:
        """The stored registry is the one save_to_sandbox actually queries.

        Registering a real sandbox bridge then driving save_to_sandbox to the
        sandbox bridge's own validation error proves set_tool_registry wired
        the live registry into the cross-bridge lookup, not merely stored a
        field. Without the stored registry the call would instead raise the
        ``tool registry not set`` RuntimeError.

        Args:
            loaded_bridge: HexEditorBridge with a real PE document opened.
            sandbox_registry: A registry holding a real SandboxBridge.
        """
        loaded_bridge.set_tool_registry(sandbox_registry)

        with pytest.raises(ToolError) as exc_info:
            _run(loaded_bridge.save_to_sandbox("/sandbox/target.bin", sandbox_type="qemu-bad"))

        assert str(exc_info.value) == "Invalid sandbox_type: 'qemu-bad'"
