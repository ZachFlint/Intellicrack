# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 19: a cancelled turn leaves no call without its result, and an unpaired history is never sent.

The gates run the real orchestrator against a real MCP server over stdio and a real OpenAI SDK client talking to a loopback endpoint.
A turn cancelled between two tool calls, and one cancelled while its tool is still running, both leave the session as it was, and the
next request carries no trace of them. A session whose history starts with results for a call that is gone, or holds a call nothing
answered, is sent with those dropped.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.core.types import Message, ToolCall, ToolResult
from intellicrack.providers.capabilities import ApiDialect
from intellicrack.providers.tool_names import to_wire_name
from tests._helpers.mcp_agent_harness import DIALECT_SCRIPTS, MODEL, TURN_TIMEOUT_S, agent_stack, stdio_server
from tests._helpers.mcp_interactive_server import GREETING_TOOL_NAME, NAP_TOOL_NAME


if TYPE_CHECKING:
    from tests._helpers.mcp_agent_harness import AgentStack


_SERVER_SCRIPT: Final[Path] = Path(__file__).resolve().parents[1] / "_helpers" / "mcp_interactive_server.py"
_NAMESPACE: Final[str] = "mcp-play"
_CHAT: Final = DIALECT_SCRIPTS[ApiDialect.CHAT_COMPLETIONS]
_NAP_S: Final[float] = 60.0
_CANCEL_AFTER_S: Final[float] = 0.5
_CALL_WAIT_S: Final[float] = 30.0


def _calls_response(*calls: tuple[str, str, dict[str, Any]]) -> dict[str, Any]:
    """Build a Chat Completions response asking for several tool calls.

    Args:
        *calls: ``(call id, canonical function name, arguments)`` for each call.

    Returns:
        dict[str, Any]: The response body.
    """
    tool_calls = [
        {"id": call_id, "type": "function", "function": {"name": to_wire_name(name), "arguments": json.dumps(arguments)}}
        for call_id, name, arguments in calls
    ]
    return {
        "id": "calls",
        "object": "chat.completion",
        "model": MODEL,
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": None, "tool_calls": tool_calls}, "finish_reason": "tool_calls"},
        ],
    }


def _sent_calls_and_results(body: dict[str, Any]) -> tuple[set[str], set[str]]:
    """Collect the tool call ids and tool result ids a request carries.

    Args:
        body: A Chat Completions request body.

    Returns:
        tuple[set[str], set[str]]: Ids of the calls sent, and ids the tool messages answer.
    """
    calls: set[str] = set()
    results: set[str] = set()
    for message in body["messages"]:
        calls.update(call["id"] for call in message.get("tool_calls") or ())
        if message["role"] == "tool":
            results.add(message["tool_call_id"])
    return calls, results


async def _run_cancelled_turn(stack: AgentStack, *, cancel_task: bool) -> None:
    """Start a turn and cancel it once its first tool call has started.

    Args:
        stack: The running stack.
        cancel_task: Cancel the turn's task outright while the tool runs,
            rather than asking the orchestrator to cancel.
    """
    orchestrator = stack.orchestrator
    started = asyncio.Event()
    orchestrator.set_tool_call_callback(lambda _call: started.set())
    turn = asyncio.create_task(orchestrator.process_user_input("call the tools"))
    await asyncio.wait_for(started.wait(), timeout=_CALL_WAIT_S)
    if cancel_task:
        await asyncio.sleep(_CANCEL_AFTER_S)
        _ = turn.cancel()
    else:
        await orchestrator.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(turn, timeout=TURN_TIMEOUT_S)


@pytest.mark.parametrize(
    ("cancel_task", "calls"),
    [
        (
            False,
            (
                ("first", f"{_NAMESPACE}.{GREETING_TOOL_NAME}", {"name": "one"}),
                ("second", f"{_NAMESPACE}.{GREETING_TOOL_NAME}", {"name": "two"}),
            ),
        ),
        (True, (("first", f"{_NAMESPACE}.{NAP_TOOL_NAME}", {"seconds": _NAP_S}),)),
    ],
    ids=["between-calls", "while-the-tool-runs"],
)
def test_cancelled_turn_leaves_no_unanswered_call(
    tmp_path: Path,
    *,
    cancel_task: bool,
    calls: tuple[tuple[str, str, dict[str, Any]], ...],
) -> None:
    """A turn cancelled after the model asked for tools leaves the session as it was, and the next request has no unanswered call.

    Args:
        tmp_path: Per-test directory.
        cancel_task: Whether the turn's task is cancelled outright.
        calls: The tool calls the model asks for.
    """
    server = stdio_server("play", _SERVER_SCRIPT, "--with-nap")

    async def body() -> list[dict[str, Any]]:
        """Cancel one turn, then run another.

        Returns:
            list[dict[str, Any]]: Every model request body.
        """
        async with agent_stack(tmp_path, ApiDialect.CHAT_COMPLETIONS, (server,), [_calls_response(*calls), _CHAT.final()]) as stack:
            session = stack.orchestrator.current_session
            assert session is not None
            before = list(session.messages)
            await _run_cancelled_turn(stack, cancel_task=cancel_task)
            assert session.messages == before
            await asyncio.wait_for(stack.orchestrator.process_user_input("again"), timeout=TURN_TIMEOUT_S)
            return stack.model_requests()

    requests = asyncio.run(body())
    assert len(requests) == len(("cancelled", "next"))
    sent_calls, sent_results = _sent_calls_and_results(requests[-1])
    assert sent_calls == set()
    assert sent_results == set()
    assert [message["content"] for message in requests[-1]["messages"] if message["role"] == "user"] == ["again"]


def test_unpaired_history_is_not_sent(tmp_path: Path) -> None:
    """Results whose call is gone and a call nothing answered are dropped from the request, and the session keeps them.

    Args:
        tmp_path: Per-test directory.
    """
    server = stdio_server("play", _SERVER_SCRIPT)
    orphan_result = ToolResult(call_id="gone", success=True, result="stale", error=None, duration_ms=1.0)
    unanswered = ToolCall(id="lost", tool_name=_NAMESPACE, function_name=f"{_NAMESPACE}.{GREETING_TOOL_NAME}", arguments={"name": "x"})
    answered = ToolCall(id="kept", tool_name=_NAMESPACE, function_name=f"{_NAMESPACE}.{GREETING_TOOL_NAME}", arguments={"name": "y"})
    kept_result = ToolResult(call_id="kept", success=True, result="hello y", error=None, duration_ms=1.0)
    stray_result = ToolResult(call_id="stray", success=True, result="nobody asked", error=None, duration_ms=1.0)
    history = [
        Message(role="tool", content="", tool_results=[orphan_result]),
        Message(role="user", content="earlier question"),
        Message(role="assistant", content="", tool_calls=[unanswered]),
        Message(role="user", content="follow-up"),
        Message(role="assistant", content="checking", tool_calls=[answered, unanswered]),
        Message(role="tool", content="", tool_results=[kept_result, stray_result]),
        Message(role="assistant", content="earlier answer"),
    ]

    async def body() -> tuple[list[dict[str, Any]], list[Message]]:
        """Seed the history, then run one turn.

        Returns:
            tuple[list[dict[str, Any]], list[Message]]: The model request bodies and the session's history afterwards.
        """
        async with agent_stack(tmp_path, ApiDialect.CHAT_COMPLETIONS, (server,), [_CHAT.final()]) as stack:
            session = stack.orchestrator.current_session
            assert session is not None
            session.messages.extend(history)
            await asyncio.wait_for(stack.orchestrator.process_user_input("now"), timeout=TURN_TIMEOUT_S)
            return stack.model_requests(), list(session.messages)

    requests, after = asyncio.run(body())
    sent = requests[-1]["messages"]
    sent_calls, sent_results = _sent_calls_and_results(requests[-1])
    assert sent_calls == {"kept"}
    assert sent_results == {"kept"}
    assert [message["role"] for message in sent] == ["system", "user", "user", "assistant", "tool", "assistant", "user"]
    assert sent[3]["content"] == "checking"
    assert after[: len(history)] == history
