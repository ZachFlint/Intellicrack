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

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ToolError, ToolName


if TYPE_CHECKING:
    from collections.abc import Coroutine


pytest.importorskip("intellicrack_hexcore")


def _build_loaded_bridge(pe_path: Path) -> HexEditorBridge:
    """Build an independent, initialized bridge with a real PE document open.

    A fresh :class:`HexEditorBridge` is constructed and the given PE file is
    opened into it. Because every call creates a new instance, a test can hold
    a document-present bridge and a document-absent bridge simultaneously
    without the two sharing state.

    Args:
        pe_path: Filesystem path to a real PE binary to open.

    Returns:
        HexEditorBridge: A bridge whose ``document`` is the opened PE file.
    """
    instance = HexEditorBridge()
    _run(instance.initialize())
    _run(instance.open_file(str(pe_path)))
    return instance


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously on a fresh event loop.

    A brand-new loop is created, used, and closed for every call so the
    result is deterministic and independent of test ordering or of any
    loop a previous test may have left open or closed. The project floor
    is Python 3.13 (``requires-python >= 3.13`` in ``pyproject.toml``),
    so the PEP 695 generic ``[T]`` syntax is fully supported.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        T: The result produced by awaiting ``coro``.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        asyncio.set_event_loop(None)
        loop.close()


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

    def test_no_document_raises_exact_runtime_error(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
        sandbox_registry: ToolRegistry,
    ) -> None:
        """save_to_sandbox rejects a missing document before any registry use.

        A registry that *does* contain a working sandbox bridge is supplied so
        the test proves the no-document guard fires first; if the guard were
        removed the call would instead reach the sandbox bridge and fail with a
        different error, which this exact-message assertion would catch.

        The boundary is asserted explicitly: an independently built bridge with
        a real PE document open, driven through the identical registry, moves
        *past* the ``no document open`` guard and instead raises the sandbox
        bridge's own ``Invalid sandbox_type`` ``ToolError``. That proves the
        guard is keyed on the document being absent, not on some unrelated
        condition that would also reject the document-present case.

        Args:
            bridge: An initialized HexEditorBridge with no document open.
            pe_binary: Path to a real PE binary fixture on disk.
            sandbox_registry: A registry holding a real SandboxBridge.
        """
        bridge.set_tool_registry(sandbox_registry)
        assert bridge.document is None

        with pytest.raises(RuntimeError) as exc_info:
            _run(bridge.save_to_sandbox("/sandbox/target.bin"))

        assert type(exc_info.value) is RuntimeError
        assert str(exc_info.value) == "no document open"

        loaded = _build_loaded_bridge(pe_binary)
        loaded.set_tool_registry(sandbox_registry)
        assert loaded.document is not None
        with pytest.raises(ToolError) as past_guard:
            _run(loaded.save_to_sandbox("/sandbox/target.bin", sandbox_type="no-such-type"))
        assert str(past_guard.value) == "Invalid sandbox_type: 'no-such-type'"

    def test_no_tool_registry_raises_exact_runtime_error(
        self,
        loaded_bridge: HexEditorBridge,
        sandbox_registry: ToolRegistry,
    ) -> None:
        """save_to_sandbox surfaces the registry-missing guard after document check.

        With ``tool_registry`` cleared the call must raise the exact
        ``tool registry not set; cannot access sandbox bridge`` message and
        nothing else. The boundary is asserted in the same test: once a real
        registry is wired in, that guard no longer fires and the call instead
        reaches the sandbox bridge, which rejects the bad ``sandbox_type`` with
        a ``ToolError``. That proves the guard is keyed on ``tool_registry``
        being ``None`` rather than on an unrelated precondition.

        Args:
            loaded_bridge: HexEditorBridge with a real PE document opened.
            sandbox_registry: A registry holding a real SandboxBridge.
        """
        loaded_bridge.tool_registry = None
        assert loaded_bridge.document is not None

        with pytest.raises(RuntimeError) as exc_info:
            _run(loaded_bridge.save_to_sandbox("/sandbox/target.bin"))

        assert type(exc_info.value) is RuntimeError
        assert str(exc_info.value) == "tool registry not set; cannot access sandbox bridge"

        loaded_bridge.set_tool_registry(sandbox_registry)
        assert loaded_bridge.tool_registry is sandbox_registry
        with pytest.raises(ToolError) as past_guard:
            _run(loaded_bridge.save_to_sandbox("/sandbox/target.bin", sandbox_type="no-such-type"))
        assert str(past_guard.value) == "Invalid sandbox_type: 'no-such-type'"

    def test_empty_registry_raises_sandbox_unavailable(
        self,
        loaded_bridge: HexEditorBridge,
        empty_registry: ToolRegistry,
        sandbox_registry: ToolRegistry,
    ) -> None:
        """save_to_sandbox reports the real empty-registry ToolName.SANDBOX miss.

        The lookup is exercised against a real, empty ToolRegistry. The exact
        ``sandbox bridge not available`` message can only be produced after
        ``registry.get(ToolName.SANDBOX)`` returns None, so the test asserts
        that lookup returns ``None`` first to prove the genuine cross-bridge
        lookup path is taken rather than an unrelated guard.

        The happy-path boundary is asserted in the same test: a registry that
        *does* hold a real ``SandboxBridge`` returns a live bridge from the
        same ``get(ToolName.SANDBOX)`` lookup, the availability guard does NOT
        fire, and the call proceeds into ``SandboxBridge.create`` where the bad
        ``sandbox_type`` is rejected with a ``ToolError``. If the production
        guard wrongly fired on a populated registry this boundary assertion
        would go red.

        Args:
            loaded_bridge: HexEditorBridge with a real PE document opened.
            empty_registry: A real registry containing no sandbox bridge.
            sandbox_registry: A registry holding a real SandboxBridge.
        """
        assert empty_registry.get(ToolName.SANDBOX) is None
        loaded_bridge.set_tool_registry(empty_registry)

        with pytest.raises(RuntimeError) as exc_info:
            _run(loaded_bridge.save_to_sandbox("/sandbox/target.bin"))

        assert type(exc_info.value) is RuntimeError
        assert str(exc_info.value) == "sandbox bridge not available"

        assert isinstance(sandbox_registry.get(ToolName.SANDBOX), SandboxBridge)
        loaded_bridge.set_tool_registry(sandbox_registry)
        with pytest.raises(ToolError) as past_guard:
            _run(loaded_bridge.save_to_sandbox("/sandbox/target.bin", sandbox_type="no-such-type"))
        assert str(past_guard.value) == "Invalid sandbox_type: 'no-such-type'"

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
