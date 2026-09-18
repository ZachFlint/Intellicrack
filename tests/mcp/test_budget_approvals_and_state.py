# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for the context budget, approval lifetime, and session state.

These drive the real orchestrator helpers, the real approval and trust stores
against real files on disk, and the real session store against a real SQLite
database. Nothing is stubbed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import McpServerState, Session, SessionStore
from intellicrack.core.types import (
    Message,
    TextResultPart,
    ToolCall,
    ToolError,
    ToolName,
    ToolResult,
    ToolState,
)
from intellicrack.mcp.consent import ApprovalScope, ApprovalStore, TrustState, TrustStore


if TYPE_CHECKING:
    from pathlib import Path


_WINDOW = 10_000
_NAMESPACE = "mcp-files"
_FUNCTION = "mcp-files.read_file"
_GENERATION_A = "aaaaaaaaaaaaaaaa"
_GENERATION_B = "bbbbbbbbbbbbbbbb"


def _tool_message(payload: str) -> Message:
    """Build a tool message whose weight lives entirely in its results.

    Args:
        payload: Text carried by the tool result.

    Returns:
        Message: A tool message with empty ``content``.
    """
    return Message(
        role="tool",
        content="",
        tool_results=[
            ToolResult(
                call_id="call-1",
                success=True,
                result=None,
                error=None,
                duration_ms=1.0,
                content=[TextResultPart(text=payload)],
            ),
        ],
    )


class TestContextBudgetCountsToolTraffic:
    """A tool message's real weight is its results, not its empty ``content``."""

    def test_history_of_tool_calls_alone_is_trimmed(self) -> None:
        """A history whose weight is entirely in tool-call arguments is trimmed."""
        messages: list[Message] = [Message(role="system", content="system prompt")]
        messages.extend(
            Message(
                role="assistant",
                content="",
                tool_calls=[ToolCall(id=f"c{index}", tool_name=_NAMESPACE, function_name=_FUNCTION, arguments={"path": "y" * 8000})],
            )
            for index in range(12)
        )
        original = len(messages)

        trimmed = Orchestrator.trim_messages_to_context_window(list(messages), _WINDOW)
        assert len(trimmed) < original, "a history of oversized tool-call arguments was not trimmed"

    def test_history_of_tool_results_alone_is_trimmed(self) -> None:
        """A history whose weight is entirely in results gets trimmed.

        This is the regression the budget change exists for: such a history
        previously measured as free and was never trimmed at all.
        """
        messages = [Message(role="system", content="system prompt")]
        messages.extend(_tool_message("z" * 8000) for _ in range(12))
        original = len(messages)

        trimmed = Orchestrator.trim_messages_to_context_window(list(messages), _WINDOW)
        assert len(trimmed) < original, "a history of oversized tool results was not trimmed"

    def test_advertised_tools_reduce_the_message_budget(self) -> None:
        """Tool schemas consume budget that messages can then no longer use."""
        history = [Message(role="user", content="q" * 1200) for _ in range(6)]
        overhead = _WINDOW // 2

        without = Orchestrator.trim_messages_to_context_window(list(history), _WINDOW)
        with_tools = Orchestrator.trim_messages_to_context_window(list(history), _WINDOW, tool_overhead_tokens=overhead)

        assert len(without) == len(history), "the history should fit when no tools are advertised"
        assert len(with_tools) < len(without), "advertising tools freed no budget from the history"

    def test_impossible_budget_raises_rather_than_sending(self) -> None:
        """Tool overhead past the whole window is refused, not silently sent."""
        with pytest.raises(ToolError):
            Orchestrator.trim_messages_to_context_window(
                [Message(role="user", content="hello")],
                _WINDOW,
                tool_overhead_tokens=_WINDOW * 2,
            )

    def test_unknown_window_still_raises(self) -> None:
        """An unknown context window remains a hard error."""
        with pytest.raises(ToolError):
            Orchestrator.trim_messages_to_context_window([Message(role="user", content="hello")], None)


class TestApprovalLifetime:
    """Approvals are scoped, and a changed tool listing forgets them."""

    def test_always_is_remembered(self, tmp_path: Path) -> None:
        """An ``always`` answer is recalled for the same generation.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        store = ApprovalStore(tmp_path / "approvals.json")
        store.remember(_NAMESPACE, _FUNCTION, _GENERATION_A, approved=True, scope=ApprovalScope.ALWAYS)
        assert store.decision(_NAMESPACE, _FUNCTION, _GENERATION_A) is True

    def test_always_survives_a_restart(self, tmp_path: Path) -> None:
        """An ``always`` answer is still there for a fresh store.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        path = tmp_path / "approvals.json"
        ApprovalStore(path).remember(_NAMESPACE, _FUNCTION, _GENERATION_A, approved=True, scope=ApprovalScope.ALWAYS)
        assert ApprovalStore(path).decision(_NAMESPACE, _FUNCTION, _GENERATION_A) is True

    def test_session_does_not_survive_a_restart(self, tmp_path: Path) -> None:
        """A ``session`` answer is not persisted to disk.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        path = tmp_path / "approvals.json"
        ApprovalStore(path).remember(_NAMESPACE, _FUNCTION, _GENERATION_A, approved=True, scope=ApprovalScope.SESSION)
        assert ApprovalStore(path).decision(_NAMESPACE, _FUNCTION, _GENERATION_A) is None

    def test_once_is_never_remembered(self, tmp_path: Path) -> None:
        """A ``once`` answer is not recalled even in the same store.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        store = ApprovalStore(tmp_path / "approvals.json")
        store.remember(_NAMESPACE, _FUNCTION, _GENERATION_A, approved=True, scope=ApprovalScope.ONCE)
        assert store.decision(_NAMESPACE, _FUNCTION, _GENERATION_A) is None

    def test_a_changed_tool_listing_forgets_the_answer(self, tmp_path: Path) -> None:
        """An approval does not carry over to a different generation.

        A server that changes what a tool does must not inherit the operator's
        approval of the old one.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        store = ApprovalStore(tmp_path / "approvals.json")
        store.remember(_NAMESPACE, _FUNCTION, _GENERATION_A, approved=True, scope=ApprovalScope.ALWAYS)

        assert store.decision(_NAMESPACE, _FUNCTION, _GENERATION_A) is True
        assert store.decision(_NAMESPACE, _FUNCTION, _GENERATION_B) is None

    def test_denial_is_remembered_as_denial(self, tmp_path: Path) -> None:
        """A remembered refusal reads back as refusal, not as absence.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        store = ApprovalStore(tmp_path / "approvals.json")
        store.remember(_NAMESPACE, _FUNCTION, _GENERATION_A, approved=False, scope=ApprovalScope.ALWAYS)
        assert store.decision(_NAMESPACE, _FUNCTION, _GENERATION_A) is False

    def test_trust_resets_to_untrusted(self, tmp_path: Path) -> None:
        """Resetting a server's trust puts it back to untrusted.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        path = tmp_path / "trust.json"
        store = TrustStore(path)
        store.set_state("files", TrustState.TRUSTED)
        assert TrustStore(path).state("files") is TrustState.TRUSTED

        store.reset("files")
        assert TrustStore(path).state("files") is TrustState.UNTRUSTED


class TestSessionState:
    """MCP state persists without breaking the bridge-keyed state beside it."""

    def test_mcp_state_round_trips(self, tmp_path: Path) -> None:
        """A server's state survives a save and load.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        store = SessionStore(tmp_path / "sessions.db")
        session = Session.create(provider="openai", model="gpt-5", name="mcp")
        session.mcp_servers["files"] = McpServerState(
            server_id="files",
            health="ready",
            tool_count=7,
            generation=_GENERATION_A,
            last_error=None,
        )
        store.save(session)

        loaded = store.load(session.id)
        assert loaded is not None
        assert loaded.mcp_servers["files"].tool_count == 7
        assert loaded.mcp_servers["files"].generation == _GENERATION_A

    def test_mcp_state_does_not_land_in_tool_states(self, tmp_path: Path) -> None:
        """MCP ids never reach the enum-keyed bridge state.

        ``tool_states`` is deserialized with ``ToolName(key)``, so an MCP id
        written there would make the session fail to load at all.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        store = SessionStore(tmp_path / "sessions.db")
        session = Session.create(provider="openai", model="gpt-5", name="mcp")
        session.mcp_servers["files"] = McpServerState(server_id="files", health="ready", tool_count=1, generation=None, last_error=None)
        session.tool_states[ToolName.GHIDRA] = ToolState(
            tool=ToolName.GHIDRA,
            connected=False,
            process_attached=False,
            target_path=None,
            last_error=None,
        )
        store.save(session)

        loaded = store.load(session.id)
        assert loaded is not None
        assert set(loaded.tool_states) == {ToolName.GHIDRA}
        assert set(loaded.mcp_servers) == {"files"}

    def test_a_session_without_mcp_state_still_loads(self, tmp_path: Path) -> None:
        """A session predating MCP support loads with an empty mapping.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        store = SessionStore(tmp_path / "sessions.db")
        session = Session.create(provider="openai", model="gpt-5", name="legacy")
        session.tool_states[ToolName.FRIDA] = ToolState(
            tool=ToolName.FRIDA,
            connected=False,
            process_attached=False,
            target_path=None,
            last_error=None,
        )
        store.save(session)

        loaded = store.load(session.id)
        assert loaded is not None
        assert loaded.mcp_servers == {}
        assert set(loaded.tool_states) == {ToolName.FRIDA}

    def test_loaded_tools_carry_canonical_mcp_names(self, tmp_path: Path) -> None:
        """Discovered MCP tools persist through the existing loaded-tools list.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        store = SessionStore(tmp_path / "sessions.db")
        session = Session.create(provider="openai", model="gpt-5", name="mcp")
        assert session.add_loaded_tool(_FUNCTION) is True
        assert session.add_loaded_tool(_FUNCTION) is False
        store.save(session)

        loaded = store.load(session.id)
        assert loaded is not None
        assert _FUNCTION in loaded.loaded_tools
