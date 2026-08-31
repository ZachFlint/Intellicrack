# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for the ``ToolRegistry.set_session`` plumbing.

The registry must propagate the active session to every bridge it
manages so each bridge can publish lifecycle transitions to
``Session.tool_states``. These tests assert that wiring works for
bridges registered before *and* after the session is attached.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from intellicrack.bridges.base import BridgeState, ToolBridgeBase
from intellicrack.core.session import Session
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ProviderName, ToolDefinition, ToolName


if TYPE_CHECKING:
    from pathlib import Path


class _CountingBridge(ToolBridgeBase):
    """Bridge that records how many times its session is reassigned.

    Exposes ``orchestrator_session``, ``force_state``, and
    ``publish_state`` as public methods so test code can inspect and
    drive protected base-class internals without triggering
    ``reportPrivateUsage`` errors.
    """

    def __init__(self, tool: ToolName) -> None:
        """Initialize the counting bridge.

        Args:
            tool: Tool identity used by the session-state registry.
        """
        super().__init__()
        self._tool_name: ToolName = tool
        self.set_session_calls: int = 0

    @property
    def name(self) -> ToolName:
        """The bridge's tool identity.

        Returns:
            ToolName: Tool identity for this bridge.
        """
        return self._tool_name

    @property
    def tool_definition(self) -> ToolDefinition:
        """A minimal tool definition.

        Returns:
            ToolDefinition: Definition with no functions.
        """
        return ToolDefinition(tool_name=self._tool_name, description="counting bridge", functions=[])

    async def initialize(self, tool_path: Path | None = None) -> None:
        """Mark the bridge connected.

        Args:
            tool_path: Unused.
        """
        del tool_path
        self.state = BridgeState(
            connected=True,
            tool_running=True,
            binary_loaded=False,
            process_attached=False,
            target_path=None,
            target_pid=None,
            last_error=None,
        )

    async def shutdown(self) -> None:
        """Reset state via the shared finalize hook."""
        await self._finalize_shutdown()

    async def is_available(self) -> bool:
        """Return availability.

        Returns:
            bool: Always ``True``.
        """
        return True

    def set_session(self, session: Session | None) -> None:
        """Track the call and delegate to the base implementation.

        Args:
            session: Active session or ``None`` to detach.
        """
        self.set_session_calls += 1
        super().set_session(session)

    def orchestrator_session(self) -> Session | None:
        """Expose the protected ``_orchestrator_session`` for test assertions.

        Returns:
            Session | None: The currently attached session, or ``None``.
        """
        return self._orchestrator_session

    def force_state(self, new_state: BridgeState) -> None:
        """Directly assign a new ``BridgeState`` without triggering a publish.

        This writes to ``_state`` bypassing the property setter (which
        would immediately call ``_publish_tool_state``). Tests that need
        to verify that a subsequent explicit ``publish_state()`` is a
        no-op after detach must set the state this way to avoid an
        accidental pre-publish.

        Args:
            new_state: The bridge state to apply.
        """
        self._state = new_state

    def publish_state(self) -> None:
        """Delegate to the protected ``_publish_tool_state`` method.

        Allows test code to trigger a state publish from outside the class
        without accessing the protected method directly.
        """
        self._publish_tool_state()


def _build_session() -> Session:
    """Build a throw-away in-memory session.

    Returns:
        Session: A fresh ``Session`` instance.
    """
    return Session.create(provider=ProviderName.OPENAI, model="gpt-4")


def test_set_session_propagates_to_registered_bridges(tmp_path: Path) -> None:
    """Bridges registered before ``set_session`` must receive the session.

    Args:
        tmp_path: Pytest-managed temporary directory for the registry's
            tools directory.
    """
    registry = ToolRegistry(tools_dir=tmp_path)
    bridge_a = _CountingBridge(ToolName.GHIDRA)
    bridge_b = _CountingBridge(ToolName.FRIDA)
    registry.register_bridge(ToolName.GHIDRA, bridge_a)
    registry.register_bridge(ToolName.FRIDA, bridge_b)

    session = _build_session()
    registry.set_session(session)

    assert bridge_a.set_session_calls >= 1
    assert bridge_b.set_session_calls >= 1

    asyncio.run(bridge_a.initialize())
    asyncio.run(bridge_b.initialize())

    assert ToolName.GHIDRA in session.tool_states
    assert ToolName.FRIDA in session.tool_states


def test_set_session_attaches_newly_registered_bridges(tmp_path: Path) -> None:
    """Bridges registered after ``set_session`` must inherit the session.

    Args:
        tmp_path: Pytest-managed temporary directory for the registry's
            tools directory.
    """
    registry = ToolRegistry(tools_dir=tmp_path)
    session = _build_session()
    registry.set_session(session)

    bridge = _CountingBridge(ToolName.SANDBOX)
    registry.register_bridge(ToolName.SANDBOX, bridge)

    asyncio.run(bridge.initialize())

    assert ToolName.SANDBOX in session.tool_states
    assert session.tool_states[ToolName.SANDBOX].connected is True


def test_set_session_none_detaches_all_bridges(tmp_path: Path) -> None:
    """Passing ``None`` to ``set_session`` must sever the bridge-to-session wiring.

    After detach, calling ``publish_state()`` must be a no-op:
    the session's previously-recorded ``ToolState`` must remain identical
    to the state published during ``initialize()``, even after the bridge
    mutates its internal ``BridgeState``.

    Falsifiability proof: if ``set_session(None)`` were deleted (so
    ``_orchestrator_session`` remained pointing at the session), the
    subsequent ``publish_state()`` call would push ``connected=False`` and
    ``last_error="changed_after_detach"`` into ``session.tool_states``.
    The assertions on ``connected is True`` and ``last_error is None``
    would then fail, catching the regression.

    Args:
        tmp_path: Pytest-managed temporary directory for the registry's
            tools directory.
    """
    registry = ToolRegistry(tools_dir=tmp_path)
    bridge = _CountingBridge(ToolName.X64DBG)
    registry.register_bridge(ToolName.X64DBG, bridge)

    session = _build_session()
    registry.set_session(session)
    asyncio.run(bridge.initialize())

    assert ToolName.X64DBG in session.tool_states
    state_before_detach = session.tool_states[ToolName.X64DBG]
    assert state_before_detach.connected is True
    assert state_before_detach.last_error is None

    registry.set_session(None)

    assert bridge.orchestrator_session() is None, "set_session(None) must clear the attached session on the bridge"

    bridge.force_state(
        BridgeState(
            connected=False,
            tool_running=False,
            binary_loaded=False,
            process_attached=False,
            target_path=None,
            target_pid=None,
            last_error="changed_after_detach",
        ),
    )
    bridge.publish_state()

    state_after_publish = session.tool_states[ToolName.X64DBG]
    assert state_after_publish.connected is True, "session must retain the pre-detach connected=True, not the post-detach False"
    assert state_after_publish.last_error is None, "session must retain the pre-detach last_error=None, not 'changed_after_detach'"
