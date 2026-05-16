# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for F-0007 bridge tool_state lifecycle.

Exercises a full connect/attach/error/detach cycle against the real
``ToolBridgeBase`` machinery and asserts every transition reaches the
attached ``Session.tool_states`` registry. These tests fail on ``main``
because bridges never publish lifecycle changes to the session.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from intellicrack.bridges.base import BridgeState, ToolBridgeBase
from intellicrack.core.session import Session
from intellicrack.core.types import ProviderName, ToolDefinition, ToolName


if TYPE_CHECKING:
    from pathlib import Path


class _FakeBridge(ToolBridgeBase):
    """Minimal concrete bridge used to exercise the lifecycle hooks.

    Only the abstract surface required by :class:`ToolBridgeBase` is
    implemented; the bridge does not talk to any external tool.
    """

    def __init__(self, tool: ToolName) -> None:
        """Initialize the fake bridge.

        Args:
            tool: Tool identity used by the session-state registry.
        """
        super().__init__()
        self._tool_name: ToolName = tool

    @property
    def name(self) -> ToolName:
        """Return the bridge's tool identity.

        Returns:
            ToolName: The tool this fake bridge represents.
        """
        return self._tool_name

    @property
    def tool_definition(self) -> ToolDefinition:
        """Return a minimal tool definition.

        Returns:
            ToolDefinition: Definition with no functions.
        """
        return ToolDefinition(tool_name=self._tool_name, description="fake bridge", functions=[])

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
        """Return availability for the fake bridge.

        Returns:
            bool: Always ``True`` for the fake bridge.
        """
        return True

    async def fake_attach(self, pid: int, target_path: Path) -> None:
        """Simulate attaching to a process and publish the new state.

        Args:
            pid: Process ID.
            target_path: Target path to record.
        """
        self._state.process_attached = True
        self._state.target_pid = pid
        self._state.target_path = target_path
        self._publish_tool_state()

    async def fake_error(self, message: str) -> None:
        """Record an error on the bridge state and publish it.

        Args:
            message: Error message.
        """
        self._state.last_error = message
        self._publish_tool_state()


def _build_session() -> Session:
    """Build a throw-away in-memory session.

    Returns:
        Session: A fresh ``Session`` instance.
    """
    return Session.create(provider=ProviderName.OPENAI, model="gpt-4")


def test_bridge_publishes_connect_state_to_session() -> None:
    """Initialize must publish a connected ``ToolState`` to the session."""
    session = _build_session()
    bridge = _FakeBridge(ToolName.GHIDRA)
    bridge.set_session(session)

    asyncio.run(bridge.initialize())

    assert ToolName.GHIDRA in session.tool_states
    state = session.tool_states[ToolName.GHIDRA]
    assert state.connected is True
    assert state.process_attached is False
    assert state.last_error is None


def test_bridge_publishes_attach_state_to_session(tmp_path: Path) -> None:
    """Attach must record the process attachment and target path on the session.

    Args:
        tmp_path: Pytest-managed temporary directory used as a fake
            target binary path.
    """
    session = _build_session()
    bridge = _FakeBridge(ToolName.FRIDA)
    bridge.set_session(session)

    asyncio.run(bridge.initialize())
    target = tmp_path / "target.exe"
    target.write_bytes(b"fake")
    asyncio.run(bridge.fake_attach(4242, target))

    state = session.tool_states[ToolName.FRIDA]
    assert state.connected is True
    assert state.process_attached is True
    assert state.target_path == target


def test_bridge_publishes_error_state_to_session() -> None:
    """Error transitions must surface ``last_error`` in the session state."""
    session = _build_session()
    bridge = _FakeBridge(ToolName.X64DBG)
    bridge.set_session(session)

    asyncio.run(bridge.initialize())
    asyncio.run(bridge.fake_error("attach denied"))

    state = session.tool_states[ToolName.X64DBG]
    assert state.last_error == "attach denied"


def test_bridge_detach_clears_state_in_session() -> None:
    """Shutdown must clear the bridge's entry from ``Session.tool_states``."""
    session = _build_session()
    bridge = _FakeBridge(ToolName.CUTTER)
    bridge.set_session(session)

    asyncio.run(bridge.initialize())
    assert ToolName.CUTTER in session.tool_states

    asyncio.run(bridge.shutdown())

    assert ToolName.CUTTER not in session.tool_states


def test_full_lifecycle_cycle(tmp_path: Path) -> None:
    """Connect, attach, error, detach must all reach the session.

    Args:
        tmp_path: Pytest-managed temporary directory used as a fake
            target binary path.
    """
    session = _build_session()
    bridge = _FakeBridge(ToolName.HEX_EDITOR)
    bridge.set_session(session)

    asyncio.run(bridge.initialize())
    connect_state = session.tool_states[ToolName.HEX_EDITOR]
    assert connect_state.connected is True
    assert connect_state.process_attached is False

    target = tmp_path / "lifecycle.bin"
    target.write_bytes(b"data")
    asyncio.run(bridge.fake_attach(1234, target))
    attach_state = session.tool_states[ToolName.HEX_EDITOR]
    assert attach_state.process_attached is True
    assert attach_state.target_path == target

    asyncio.run(bridge.fake_error("io error"))
    err_state = session.tool_states[ToolName.HEX_EDITOR]
    assert err_state.last_error == "io error"

    asyncio.run(bridge.shutdown())
    assert ToolName.HEX_EDITOR not in session.tool_states


def test_set_session_publishes_current_state_immediately() -> None:
    """Attaching the session after init must publish the existing state."""
    session = _build_session()
    bridge = _FakeBridge(ToolName.SANDBOX)

    asyncio.run(bridge.initialize())
    assert ToolName.SANDBOX not in session.tool_states

    bridge.set_session(session)
    assert ToolName.SANDBOX in session.tool_states
    assert session.tool_states[ToolName.SANDBOX].connected is True


def test_set_session_none_does_not_publish() -> None:
    """Setting ``None`` detaches without writing to any session."""
    session = _build_session()
    bridge = _FakeBridge(ToolName.PROCESS)
    bridge.set_session(session)

    asyncio.run(bridge.initialize())
    assert ToolName.PROCESS in session.tool_states

    bridge.set_session(None)

    asyncio.run(bridge.fake_error("after detach"))
    assert session.tool_states[ToolName.PROCESS].last_error is None
