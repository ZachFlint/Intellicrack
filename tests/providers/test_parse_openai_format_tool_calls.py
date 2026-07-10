# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for the shared OpenAI-format tool-call parser on LLMProviderBase."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from openai.types.chat.chat_completion_message import ChatCompletionMessage
from openai.types.chat.chat_completion_message_custom_tool_call import (
    ChatCompletionMessageCustomToolCall,
    Custom,
)
from openai.types.chat.chat_completion_message_function_tool_call import (
    ChatCompletionMessageFunctionToolCall,
    Function,
)

from intellicrack.providers.grok import GrokProvider
from intellicrack.providers.openai import OpenAIProvider


if TYPE_CHECKING:
    from collections.abc import Callable

    from intellicrack.core.types import ToolCall
    from intellicrack.providers.base import LLMProviderBase


_EXPECTED_MULTIPLE_CALLS = 2
_ATTR_PARSE_OPENAI_FORMAT_TOOL_CALLS = "_parse_openai_format_tool_calls"
_NOT_CALLABLE_ERR = "_parse_openai_format_tool_calls is not callable"


def _invoke_parser(provider: LLMProviderBase, message: object) -> list[ToolCall]:
    """Invoke ``_parse_openai_format_tool_calls`` via ``getattr``.

    Resolves the helper through ``getattr`` so the test does not trigger
    ``reportPrivateUsage`` for accessing a name-mangled private method.

    Args:
        provider: The provider instance whose helper should be invoked.
        message: The chat-completion message (or duck-typed equivalent)
            to pass to the helper.

    Returns:
        list[ToolCall]: The list of :class:`ToolCall` objects returned
        by the helper.

    Raises:
        TypeError: If the resolved attribute is not callable.
    """
    fn: object = getattr(provider, _ATTR_PARSE_OPENAI_FORMAT_TOOL_CALLS)
    if not callable(fn):
        raise TypeError(_NOT_CALLABLE_ERR)
    typed_fn = cast("Callable[[object], list[ToolCall]]", fn)
    return typed_fn(message)


def _make_function_tool_call(call_id: str, name: str, arguments: str) -> ChatCompletionMessageFunctionToolCall:
    """Build a typed OpenAI function tool-call payload.

    Args:
        call_id: Unique identifier assigned to the tool call.
        name: Function name reported by the model.
        arguments: Raw JSON string of arguments emitted by the model.

    Returns:
        ChatCompletionMessageFunctionToolCall: A populated function tool-call instance.
    """
    return ChatCompletionMessageFunctionToolCall(
        id=call_id,
        type="function",
        function=Function(name=name, arguments=arguments),
    )


def _make_custom_tool_call(call_id: str, name: str, body: str) -> ChatCompletionMessageCustomToolCall:
    """Build a typed OpenAI custom tool-call payload.

    Args:
        call_id: Unique identifier assigned to the tool call.
        name: Custom tool name reported by the model.
        body: Free-form input string produced by the model.

    Returns:
        ChatCompletionMessageCustomToolCall: A populated custom tool-call instance.
    """
    return ChatCompletionMessageCustomToolCall(
        id=call_id,
        type="custom",
        custom=Custom(name=name, input=body),
    )


def _make_message(
    *tool_calls: ChatCompletionMessageFunctionToolCall | ChatCompletionMessageCustomToolCall,
) -> ChatCompletionMessage:
    """Build a ``ChatCompletionMessage`` with the supplied tool calls.

    Args:
        *tool_calls: Tool-call payloads to attach. Pass none to produce
            a plain assistant message.

    Returns:
        ChatCompletionMessage: An assistant message carrying the tool
        calls.
    """
    return ChatCompletionMessage(
        role="assistant",
        content=None,
        tool_calls=list(tool_calls) if tool_calls else None,
    )


def test_returns_empty_when_no_tool_calls() -> None:
    """A message with no tool_calls produces an empty list."""
    provider = OpenAIProvider()
    message = _make_message()

    result = _invoke_parser(provider, message)

    assert result == []


def test_parses_single_function_tool_call() -> None:
    """A typed OpenAI function tool call is parsed into a ToolCall."""
    provider = OpenAIProvider()
    message = _make_message(
        _make_function_tool_call("call_abc", "get_weather", '{"city": "NYC"}'),
    )

    result = _invoke_parser(provider, message)

    assert len(result) == 1
    tc = result[0]
    assert tc.id == "call_abc"
    assert tc.function_name == "get_weather"
    assert tc.tool_name == "get_weather"
    assert tc.arguments == {"city": "NYC"}


def test_parses_multiple_function_tool_calls_in_order() -> None:
    """Multiple tool calls are returned in their original order."""
    provider = OpenAIProvider()
    message = _make_message(
        _make_function_tool_call("id_a", "fn_a", '{"x": 1}'),
        _make_function_tool_call("id_b", "fn_b", '{"y": 2}'),
    )

    result = _invoke_parser(provider, message)

    assert len(result) == _EXPECTED_MULTIPLE_CALLS
    assert [tc.id for tc in result] == ["id_a", "id_b"]
    assert [tc.function_name for tc in result] == ["fn_a", "fn_b"]
    assert result[0].arguments == {"x": 1}
    assert result[1].arguments == {"y": 2}


def test_skips_custom_tool_calls() -> None:
    """Custom (non-function) tool calls are silently skipped."""
    provider = OpenAIProvider()
    message = _make_message(
        _make_custom_tool_call("custom_1", "weird_tool", "freeform body"),
        _make_function_tool_call("call_1", "fn_real", "{}"),
    )

    result = _invoke_parser(provider, message)

    assert len(result) == 1
    assert result[0].id == "call_1"
    assert result[0].function_name == "fn_real"


def test_dotted_function_name_split_into_tool_name() -> None:
    """Dotted function names are split so tool_name is the namespace."""
    provider = OpenAIProvider()
    message = _make_message(
        _make_function_tool_call("call_dot", "ghidra.decompile", '{"address": "0x401000"}'),
    )

    result = _invoke_parser(provider, message)

    assert len(result) == 1
    assert result[0].tool_name == "ghidra"
    assert result[0].function_name == "ghidra.decompile"
    assert result[0].arguments == {"address": "0x401000"}


def test_invalid_json_arguments_yield_empty_dict() -> None:
    """Malformed JSON arguments are tolerated and yield an empty dict."""
    provider = OpenAIProvider()
    message = _make_message(
        _make_function_tool_call("call_bad", "fn", "not-json-at-all"),
    )

    result = _invoke_parser(provider, message)

    assert len(result) == 1
    assert result[0].arguments == {}


def test_grok_provider_uses_same_helper() -> None:
    """GrokProvider parses OpenAI-shaped tool calls via the shared helper."""
    provider = GrokProvider()
    message = _make_message(
        _make_function_tool_call("grok_1", "search", '{"q": "hello"}'),
        _make_custom_tool_call("custom_skip", "ignored", "x"),
        _make_function_tool_call("grok_2", "fetch", '{"url": "https://example.com"}'),
    )

    result = _invoke_parser(provider, message)

    assert len(result) == _EXPECTED_MULTIPLE_CALLS
    assert [tc.id for tc in result] == ["grok_1", "grok_2"]
    assert result[0].arguments == {"q": "hello"}
    assert result[1].arguments == {"url": "https://example.com"}


class _LooseFunction:
    """Duck-typed function payload mimicking a non-OpenAI-SDK response."""

    def __init__(self, name: str, arguments: str) -> None:
        """Store the raw function name and arguments.

        Args:
            name: Function name as reported by the looser backend.
            arguments: Raw arguments string emitted by the model.
        """
        self.name: str = name
        self.arguments: str = arguments


class _LooseToolCall:
    """Duck-typed tool-call payload mimicking a non-OpenAI-SDK response."""

    def __init__(self, call_id: str, function: _LooseFunction | None) -> None:
        """Store the call identifier and optional function payload.

        Args:
            call_id: Unique identifier assigned to the tool call.
            function: Inner function payload, or ``None`` to simulate
                a non-function tool call.
        """
        self.id: str = call_id
        self.function: _LooseFunction | None = function


class _LooseMessage:
    """Duck-typed chat completion message for compatibility testing."""

    def __init__(self, tool_calls: list[_LooseToolCall] | None) -> None:
        """Store the optional list of tool calls.

        Args:
            tool_calls: Tool calls to expose, or ``None`` for a plain
                assistant reply.
        """
        self.tool_calls: list[_LooseToolCall] | None = tool_calls


def test_loose_response_shape_compatible() -> None:
    """The helper accepts duck-typed responses lacking SDK class identity."""
    provider = OpenAIProvider()
    loose_message = _LooseMessage(
        tool_calls=[
            _LooseToolCall("loose_1", _LooseFunction("ping", '{"host": "1.1.1.1"}')),
            _LooseToolCall("loose_skip", None),
            _LooseToolCall("loose_2", _LooseFunction("noop", "{}")),
        ],
    )

    result = _invoke_parser(provider, loose_message)

    assert len(result) == _EXPECTED_MULTIPLE_CALLS
    assert [tc.id for tc in result] == ["loose_1", "loose_2"]
    assert result[0].arguments == {"host": "1.1.1.1"}
    assert result[1].arguments == {}
