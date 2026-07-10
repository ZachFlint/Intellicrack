# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for shared message conversion helpers on LLMProviderBase.

Uses ``getattr`` to access protected static methods from the base class,
avoiding ``reportPrivateUsage`` while preserving full type safety in
assertions via explicit casts.
"""

from __future__ import annotations

import json
from typing import Any, cast

from intellicrack.core.types import Message, ToolCall, ToolResult
from intellicrack.providers.base import LLMProviderBase


_TOOL_CALL_ID = "call_abc123"
_FUNCTION_NAME = "analyze_binary"
_EXPECTED_MULTI_RESULT_COUNT = 2
_EXPECTED_MIXED_MESSAGE_COUNT = 5
_EXPECTED_OLLAMA_COMBINED_COUNT = 3

_SERIALIZE_ATTR = "_serialize_tool_result"
_CONVERT_ATTR = "_convert_messages_to_openai_format"
_serialize_tool_result: Any = getattr(LLMProviderBase, _SERIALIZE_ATTR)
_convert_messages: Any = getattr(LLMProviderBase, _CONVERT_ATTR)


def _make_tool_call(
    *,
    call_id: str = _TOOL_CALL_ID,
    function_name: str = _FUNCTION_NAME,
    arguments: dict[str, object] | None = None,
) -> ToolCall:
    """Build a ToolCall with sensible defaults.

    Args:
        call_id: Unique identifier for the tool call.
        function_name: Name of the function being called.
        arguments: Function arguments dict.

    Returns:
        ToolCall: A populated ToolCall instance.
    """
    args: dict[str, object] = arguments if arguments is not None else {"path": "/bin/target"}
    tool_name = function_name.split(".", maxsplit=1)[0] if "." in function_name else function_name
    return ToolCall(
        id=call_id,
        tool_name=tool_name,
        function_name=function_name,
        arguments=args,
    )


def _make_tool_result(
    *,
    call_id: str = _TOOL_CALL_ID,
    result: object = "ok",
    success: bool = True,
) -> ToolResult:
    """Build a ToolResult with sensible defaults.

    Args:
        call_id: ID of the corresponding ToolCall.
        result: The result value.
        success: Whether the operation succeeded.

    Returns:
        ToolResult: A populated ToolResult instance.
    """
    return ToolResult(
        call_id=call_id,
        success=success,
        result=result,
        error=None,
        duration_ms=0.0,
    )


def _convert(
    messages: list[Message],
    *,
    serialize_tool_arguments: bool = True,
    include_tool_call_type: bool = True,
) -> list[dict[str, Any]]:
    """Call _convert_messages_to_openai_format with typed return.

    Args:
        messages: List of Message objects to convert.
        serialize_tool_arguments: Whether to JSON-serialize arguments.
        include_tool_call_type: Whether to include 'type' key.

    Returns:
        list[dict[str, Any]]: List of converted message dicts.
    """
    return cast(
        "list[dict[str, Any]]",
        _convert_messages(
            messages,
            serialize_tool_arguments=serialize_tool_arguments,
            include_tool_call_type=include_tool_call_type,
        ),
    )


def test_serialize_string_passthrough() -> None:
    """String values are returned as-is without re-encoding."""
    assert _serialize_tool_result("hello") == "hello"


def test_serialize_empty_string() -> None:
    """Empty string is returned unchanged."""
    result: str = _serialize_tool_result("")
    assert isinstance(result, str)
    assert not result


def test_serialize_dict() -> None:
    """Dict values are JSON-serialized."""
    data = {"key": "value", "count": 42}
    result: str = _serialize_tool_result(data)
    assert json.loads(result) == data


def test_serialize_list() -> None:
    """List values are JSON-serialized."""
    data = [1, 2, 3]
    result: str = _serialize_tool_result(data)
    assert json.loads(result) == data


def test_serialize_integer() -> None:
    """Integer values are JSON-serialized."""
    assert _serialize_tool_result(42) == "42"


def test_serialize_none() -> None:
    """None is serialized as JSON null."""
    assert _serialize_tool_result(None) == "null"


def test_serialize_bool() -> None:
    """Boolean values are JSON-serialized."""
    bool_val = True
    assert _serialize_tool_result(bool_val) == "true"


def test_serialize_nested_dict() -> None:
    """Nested structures are properly serialized."""
    data = {"outer": {"inner": [1, 2]}, "flag": True}
    result: str = _serialize_tool_result(data)
    assert json.loads(result) == data


def test_convert_system_message() -> None:
    """System messages produce correct role and content."""
    msgs = [Message(role="system", content="You are a helper.")]
    result = _convert(msgs)
    assert len(result) == 1
    assert result[0] == {"role": "system", "content": "You are a helper."}


def test_convert_user_message() -> None:
    """User messages produce correct role and content."""
    msgs = [Message(role="user", content="Hello")]
    result = _convert(msgs)
    assert len(result) == 1
    assert result[0] == {"role": "user", "content": "Hello"}


def test_convert_assistant_no_tools() -> None:
    """Assistant messages without tool calls have no tool_calls key."""
    msgs = [Message(role="assistant", content="Sure thing.")]
    result = _convert(msgs)
    assert len(result) == 1
    assert result[0] == {"role": "assistant", "content": "Sure thing."}
    assert "tool_calls" not in result[0]


def test_convert_assistant_with_tool_calls() -> None:
    """Assistant messages with tool calls include serialized tool_calls."""
    tc = _make_tool_call(arguments={"file": "test.exe"})
    msgs = [Message(role="assistant", content="", tool_calls=[tc])]
    result = _convert(msgs)
    assert len(result) == 1
    msg = result[0]
    assert msg["role"] == "assistant"
    tool_calls: list[dict[str, Any]] = msg["tool_calls"]
    assert len(tool_calls) == 1
    tc_dict = tool_calls[0]
    assert tc_dict["id"] == _TOOL_CALL_ID
    assert tc_dict["type"] == "function"
    func: dict[str, Any] = tc_dict["function"]
    assert func["name"] == _FUNCTION_NAME
    assert json.loads(func["arguments"]) == {"file": "test.exe"}


def test_convert_tool_result_string() -> None:
    """Tool results with string values are passed through."""
    tr = _make_tool_result(result="analysis complete")
    msgs = [Message(role="tool", content="", tool_results=[tr])]
    result = _convert(msgs)
    assert len(result) == 1
    assert result[0]["role"] == "tool"
    assert result[0]["tool_call_id"] == _TOOL_CALL_ID
    assert result[0]["content"] == "analysis complete"


def test_convert_tool_result_dict() -> None:
    """Tool results with dict values are JSON-serialized."""
    data = {"findings": ["nop_sled", "license_check"]}
    tr = _make_tool_result(result=data)
    msgs = [Message(role="tool", content="", tool_results=[tr])]
    result = _convert(msgs)
    assert len(result) == 1
    assert json.loads(str(result[0]["content"])) == data


def test_convert_multiple_tool_results_expand() -> None:
    """Multiple tool results in one message expand to separate dicts."""
    tr1 = _make_tool_result(call_id="call_1", result="res1")
    tr2 = _make_tool_result(call_id="call_2", result="res2")
    msgs = [Message(role="tool", content="", tool_results=[tr1, tr2])]
    result = _convert(msgs)
    assert len(result) == _EXPECTED_MULTI_RESULT_COUNT
    assert result[0]["tool_call_id"] == "call_1"
    assert result[1]["tool_call_id"] == "call_2"


def test_convert_tool_message_without_results_skipped() -> None:
    """Tool messages with no tool_results produce no output."""
    msgs = [Message(role="tool", content="")]
    result = _convert(msgs)
    assert result == []


def test_convert_mixed_conversation() -> None:
    """A full conversation with all roles converts correctly."""
    tc = _make_tool_call()
    tr = _make_tool_result(result="done")
    msgs = [
        Message(role="system", content="sys"),
        Message(role="user", content="usr"),
        Message(role="assistant", content="", tool_calls=[tc]),
        Message(role="tool", content="", tool_results=[tr]),
        Message(role="assistant", content="final"),
    ]
    result = _convert(msgs)
    assert len(result) == _EXPECTED_MIXED_MESSAGE_COUNT
    assert result[0]["role"] == "system"
    assert result[1]["role"] == "user"
    assert result[2]["role"] == "assistant"
    assert "tool_calls" in result[2]
    assert result[3]["role"] == "tool"
    assert result[4]["role"] == "assistant"
    assert result[4]["content"] == "final"


def test_convert_empty_list() -> None:
    """Empty input produces empty output."""
    assert _convert([]) == []


def test_ollama_arguments_not_serialized() -> None:
    """With serialize_tool_arguments=False, arguments stay as dict."""
    tc = _make_tool_call(arguments={"target": "app.exe"})
    msgs = [Message(role="assistant", content="", tool_calls=[tc])]
    result = _convert(msgs, serialize_tool_arguments=False)
    tool_calls: list[dict[str, Any]] = result[0]["tool_calls"]
    func: dict[str, Any] = tool_calls[0]["function"]
    assert func["arguments"] == {"target": "app.exe"}


def test_ollama_type_key_omitted() -> None:
    """With include_tool_call_type=False, 'type' key is absent."""
    tc = _make_tool_call()
    msgs = [Message(role="assistant", content="", tool_calls=[tc])]
    result = _convert(msgs, include_tool_call_type=False)
    tool_calls: list[dict[str, Any]] = result[0]["tool_calls"]
    assert "type" not in tool_calls[0]


def test_type_key_present_by_default() -> None:
    """By default, 'type': 'function' is present in tool call dicts."""
    tc = _make_tool_call()
    msgs = [Message(role="assistant", content="", tool_calls=[tc])]
    result = _convert(msgs)
    tool_calls: list[dict[str, Any]] = result[0]["tool_calls"]
    assert tool_calls[0]["type"] == "function"


def test_ollama_combined_flags() -> None:
    """Both Ollama flags together produce the expected format."""
    tc = _make_tool_call(arguments={"x": 1})
    tr = _make_tool_result(result={"status": "patched"})
    msgs = [
        Message(role="user", content="patch it"),
        Message(role="assistant", content="", tool_calls=[tc]),
        Message(role="tool", content="", tool_results=[tr]),
    ]
    result = _convert(
        msgs,
        serialize_tool_arguments=False,
        include_tool_call_type=False,
    )
    assert len(result) == _EXPECTED_OLLAMA_COMBINED_COUNT
    tool_calls: list[dict[str, Any]] = result[1]["tool_calls"]
    tc_dict = tool_calls[0]
    assert "type" not in tc_dict
    func: dict[str, Any] = tc_dict["function"]
    assert func["arguments"] == {"x": 1}
    assert result[2]["role"] == "tool"
    assert json.loads(str(result[2]["content"])) == {"status": "patched"}
