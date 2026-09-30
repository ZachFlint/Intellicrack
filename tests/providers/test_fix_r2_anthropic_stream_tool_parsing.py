# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 30: the built-in Anthropic stream builds its tool calls through the shared ``parse_tool_call``.

Round 1 replaced the stream finaliser's hand-built ``ToolCall`` with the shared parser the other paths use, so a change to how wire
names or arguments are read reaches the stream too. The refactor kept behaviour identical, which is why no behavioural gate could tell it
apart from the hand-built code. This gate streams a real turn through the real ``anthropic`` SDK from a loopback endpoint into a provider
whose shared parser notes each call before delegating to it, and checks both that the stream's calls went through that parser and that
they come out right, a hash-fallback wire name included.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any, ClassVar, Final, override

from intellicrack.core.types import Message, ProviderCredentials, ToolCall, ToolDefinition, ToolFunction, ToolParameter
from intellicrack.providers.anthropic import AnthropicProvider
from intellicrack.providers.tool_names import to_wire_name
from tests._helpers.scripted_sdk_server import ScriptedHTTPServer, json_response, sse_response


if TYPE_CHECKING:
    from collections.abc import Mapping


_API_KEY: Final[str] = "sk-ant-loopbackStreamParse0123456789"
_MODEL: Final[str] = "claude-sonnet-4-5"
_SHORT_NAME: Final[str] = "frida.spawn"
_LONG_NAME: Final[str] = "mcp-analysis_server_with_a_long_name.enumerate_every_exported_symbol_in_the_loaded_image"


class _NotingProvider(AnthropicProvider):
    """The real Anthropic provider, noting each tool call its shared parser builds.

    Attributes:
        parsed: The calls the shared parser returned, in order.
    """

    parsed: ClassVar[list[ToolCall]] = []

    @staticmethod
    @override
    def _parse_tool_call_common(
        *,
        call_id: str,
        function_name: str,
        raw_arguments: str | dict[str, object],
    ) -> ToolCall:
        """Parse through the shared parser and note the result.

        Args:
            call_id: The call id.
            function_name: The wire function name.
            raw_arguments: The arguments.

        Returns:
            ToolCall: The shared parser's result.
        """
        call = AnthropicProvider._parse_tool_call_common(call_id=call_id, function_name=function_name, raw_arguments=raw_arguments)
        _NotingProvider.parsed.append(call)
        return call


def _tool(name: str) -> ToolDefinition:
    """Describe one tool with one function.

    Args:
        name: The canonical function name.

    Returns:
        ToolDefinition: The tool.
    """
    namespace = name.split(".", 1)[0]
    parameter = ToolParameter(name="target", type="string", description="What to act on")
    function = ToolFunction(name=name, description="Act on a target.", parameters=[parameter], returns="result")
    return ToolDefinition(tool_name=namespace, description="A tool.", functions=[function])


def _tool_use_events(index: int, call_id: str, wire_name: str, arguments: Mapping[str, object]) -> list[dict[str, Any]]:
    """Build the events of one streamed ``tool_use`` block.

    Args:
        index: The block index.
        call_id: The call id.
        wire_name: The tool's wire name.
        arguments: The call's arguments.

    Returns:
        list[dict[str, Any]]: Start, the input as one delta, stop.
    """
    opened: dict[str, Any] = {"type": "tool_use", "id": call_id, "name": wire_name, "input": {}}
    return [
        {"type": "content_block_start", "index": index, "content_block": opened},
        {"type": "content_block_delta", "index": index, "delta": {"type": "input_json_delta", "partial_json": json.dumps(arguments)}},
        {"type": "content_block_stop", "index": index},
    ]


def test_streamed_tool_calls_go_through_the_shared_parser() -> None:
    """Both streamed calls are built by the shared parser, with canonical names, namespaces and arguments restored."""
    long_wire = to_wire_name(_LONG_NAME)
    assert long_wire != _LONG_NAME.replace(".", "__"), "the long name must take the hash fallback"
    start: dict[str, Any] = {
        "type": "message_start",
        "message": {
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": _MODEL,
            "content": [],
            "stop_reason": None,
            "stop_sequence": None,
            "usage": {"input_tokens": 10, "output_tokens": 1},
        },
    }
    events: list[dict[str, Any]] = [
        start,
        *_tool_use_events(0, "toolu_01", to_wire_name(_SHORT_NAME), {"target": "notepad.exe"}),
        *_tool_use_events(1, "toolu_02", long_wire, {"target": "kernel32.dll"}),
        {"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": None}, "usage": {"output_tokens": 9}},
        {"type": "message_stop"},
    ]
    server = ScriptedHTTPServer({
        ("GET", "/v1/models"): json_response({"data": [], "has_more": False, "first_id": None, "last_id": None}),
        ("POST", "/v1/messages"): sse_response(events),
    })
    _NotingProvider.parsed.clear()

    async def run() -> list[ToolCall]:
        """Stream the turn.

        Returns:
            list[ToolCall]: The calls the provider reports.
        """
        provider = _NotingProvider()
        await provider.connect(ProviderCredentials(api_key=_API_KEY, api_base=server.origin))
        _ = [
            chunk
            async for chunk in provider.chat_stream(
                [Message(role="user", content="inspect it")],
                _MODEL,
                tools=[_tool(_SHORT_NAME), _tool(_LONG_NAME)],
            )
        ]
        return provider.get_pending_tool_calls()

    try:
        calls = asyncio.run(run())
    finally:
        server.close()
    summary = [(call.id, call.tool_name, call.function_name, call.arguments) for call in calls]
    assert summary == [
        ("toolu_01", "frida", _SHORT_NAME, {"target": "notepad.exe"}),
        ("toolu_02", "mcp-analysis_server_with_a_long_name", _LONG_NAME, {"target": "kernel32.dll"}),
    ]
    assert _NotingProvider.parsed == calls
