# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for AnthropicProvider bridge layer.

Unit tests cover the bridge's internal transformation logic (message
conversion, tool schema building, API kwargs construction, cache
breakpoints, usage extraction, response block parsing) without any live
network calls or mocked responses.

Integration tests issue real API calls and require a valid
ANTHROPIC_API_KEY in the .env file; they are skipped when credentials
are absent.
"""

from __future__ import annotations

import asyncio
import copy
from typing import TYPE_CHECKING, Any, cast

import pytest
from anthropic.types import (
    Message as AnthropicMessage,
    MessageParam,
    TextBlock,
    ThinkingBlock,
    ToolUseBlock,
    Usage,
)

from intellicrack.core.types import (
    AuthenticationError,
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    ProviderName,
    ThinkingConfig,
    ToolCall,
    ToolChoice,
    ToolChoiceMode,
    ToolDefinition,
    ToolFunction,
    ToolName,
    ToolParameter,
    ToolResult,
)
from intellicrack.providers.anthropic import AnthropicProvider


if TYPE_CHECKING:
    from intellicrack.credentials.env_loader import CredentialLoader
    from intellicrack.providers.base import UsageInfo


_KNOWN_CLAUDE_PREFIX: str = "claude-"
_CONTEXT_WINDOW_200K: int = 200_000

_build_model_info: Any = getattr(AnthropicProvider, "_build_model_info")
_build_api_kwargs: Any = getattr(AnthropicProvider, "_build_api_kwargs")
_apply_cache_breakpoints: Any = getattr(AnthropicProvider, "_apply_cache_breakpoints")
_cache_last_message_block: Any = getattr(AnthropicProvider, "_cache_last_message_block")
_build_usage_from_message: Any = getattr(AnthropicProvider, "_build_usage_from_message")


class TestBuildModelInfo:
    """Unit tests for AnthropicProvider._build_model_info.

    Validates that the static helper constructs ModelInfo objects with
    the correct, independently-known field values for every combination
    of display-name presence and absence.
    """

    def test_known_model_id_and_display_name_fields_are_exact(self) -> None:
        """All fields are exact for a model with a full display name.

        Expected values are independently known constants, not derived from the implementation.
        """
        model: ModelInfo = _build_model_info(
            "claude-3-5-sonnet-20241022",
            "Claude 3.5 Sonnet",
        )

        assert model.id == "claude-3-5-sonnet-20241022"
        assert model.name == "Claude 3.5 Sonnet"
        assert model.provider == ProviderName.ANTHROPIC
        assert model.context_window == _CONTEXT_WINDOW_200K
        assert model.supports_tools is True
        assert model.supports_vision is True
        assert model.supports_streaming is True
        assert model.input_cost_per_1m_tokens is None
        assert model.output_cost_per_1m_tokens is None

    def test_empty_display_name_falls_back_to_model_id(self) -> None:
        """When display_name_raw is empty the name field equals the model ID."""
        model: ModelInfo = _build_model_info("claude-3-opus-20240229", "")

        assert model.id == "claude-3-opus-20240229"
        assert model.name == "claude-3-opus-20240229", (
            f"Bridge must use model_id as name when display_name_raw is empty, got {model.name!r}"
        )

    def test_none_display_name_falls_back_to_model_id(self) -> None:
        """When display_name_raw is None the name field equals the model ID."""
        model: ModelInfo = _build_model_info("claude-3-haiku-20240307", None)

        assert model.id == "claude-3-haiku-20240307"
        assert model.name == "claude-3-haiku-20240307", (
            f"Bridge must use model_id as name when display_name_raw is None, got {model.name!r}"
        )

    def test_context_window_is_always_200k(self) -> None:
        """All Anthropic models expose the 200k context window constant."""
        for model_id in [
            "claude-3-5-sonnet-20241022",
            "claude-3-opus-20240229",
            "claude-3-haiku-20240307",
            "claude-3-5-haiku-20241022",
        ]:
            model: ModelInfo = _build_model_info(model_id, model_id)
            assert model.context_window == _CONTEXT_WINDOW_200K, (
                f"context_window must be {_CONTEXT_WINDOW_200K} for {model_id}, got {model.context_window}"
            )

    def test_provider_is_always_anthropic(self) -> None:
        """Provider field is always ProviderName.ANTHROPIC regardless of model ID."""
        model: ModelInfo = _build_model_info("claude-3-5-haiku-20241022", "Claude 3.5 Haiku")

        assert model.provider is ProviderName.ANTHROPIC
        assert model.provider.value == "anthropic"


class TestBuildApiKwargs:
    """Unit tests for AnthropicProvider._build_api_kwargs.

    Validates that API request kwargs are assembled exactly as required
    by the Anthropic messages API, with correct handling of optional
    fields, tool-choice modes, and extended thinking configuration.
    """

    def test_basic_kwargs_structure_without_optional_fields(self) -> None:
        """Required fields appear and optional ones are absent when not specified."""
        msgs: list[MessageParam] = [MessageParam(role="user", content="hello")]

        result: dict[str, Any] = _build_api_kwargs(
            model="claude-3-5-sonnet-20241022",
            max_tokens=4096,
            temperature=0.7,
            messages=msgs,
            system_prompt=None,
            tools=None,
        )

        assert result["model"] == "claude-3-5-sonnet-20241022"
        assert result["max_tokens"] == 4096
        assert abs(float(result["temperature"]) - 0.7) < 1e-9
        assert result["messages"] is msgs
        assert "system" not in result, "system must be absent when system_prompt is None"
        assert "tools" not in result, "tools must be absent when tools arg is None"
        assert "tool_choice" not in result
        assert "thinking" not in result

    def test_system_prompt_is_set_when_provided(self) -> None:
        """System key is present and matches the provided string."""
        result: dict[str, Any] = _build_api_kwargs(
            model="claude-3-5-sonnet-20241022",
            max_tokens=4096,
            temperature=0.7,
            messages=cast("list[MessageParam]", []),
            system_prompt="You are a binary analysis expert",
            tools=None,
        )

        assert result["system"] == "You are a binary analysis expert"

    def test_tool_choice_auto_mode_produces_correct_dict(self) -> None:
        """ToolChoiceMode.AUTO translates to the wire form ``{'type': 'auto'}``."""
        dummy_tool: dict[str, object] = {
            "name": "my_tool",
            "description": "A tool",
            "input_schema": {"type": "object", "properties": {}, "required": []},
        }

        result: dict[str, Any] = _build_api_kwargs(
            model="claude-3-5-sonnet-20241022",
            max_tokens=4096,
            temperature=0.7,
            messages=cast("list[MessageParam]", []),
            system_prompt=None,
            tools=[dummy_tool],
            tool_choice=ToolChoice(mode=ToolChoiceMode.AUTO),
        )

        assert result["tool_choice"] == {"type": "auto"}

    def test_tool_choice_required_mode_produces_any_dict(self) -> None:
        """ToolChoiceMode.REQUIRED translates to the wire form ``{'type': 'any'}``."""
        dummy_tool: dict[str, object] = {
            "name": "my_tool",
            "description": "A tool",
            "input_schema": {"type": "object", "properties": {}, "required": []},
        }

        result: dict[str, Any] = _build_api_kwargs(
            model="claude-3-5-sonnet-20241022",
            max_tokens=4096,
            temperature=0.7,
            messages=cast("list[MessageParam]", []),
            system_prompt=None,
            tools=[dummy_tool],
            tool_choice=ToolChoice(mode=ToolChoiceMode.REQUIRED),
        )

        assert result["tool_choice"] == {"type": "any"}

    def test_tool_choice_specific_mode_names_exact_function(self) -> None:
        """ToolChoiceMode.SPECIFIC maps to ``{'type': 'tool', 'name': <fn>}``."""
        dummy_tool: dict[str, object] = {
            "name": "ghidra.decompile",
            "description": "Decompile function",
            "input_schema": {"type": "object", "properties": {}, "required": []},
        }

        result: dict[str, Any] = _build_api_kwargs(
            model="claude-3-5-sonnet-20241022",
            max_tokens=4096,
            temperature=0.7,
            messages=cast("list[MessageParam]", []),
            system_prompt=None,
            tools=[dummy_tool],
            tool_choice=ToolChoice(mode=ToolChoiceMode.SPECIFIC, function_name="ghidra.decompile"),
        )

        assert result["tool_choice"] == {"type": "tool", "name": "ghidra.decompile"}

    def test_tool_choice_none_mode_removes_tools_from_kwargs(self) -> None:
        """ToolChoiceMode.NONE removes the tools key so no tools are offered."""
        dummy_tool: dict[str, object] = {
            "name": "my_tool",
            "description": "A tool",
            "input_schema": {"type": "object", "properties": {}, "required": []},
        }

        result: dict[str, Any] = _build_api_kwargs(
            model="claude-3-5-sonnet-20241022",
            max_tokens=4096,
            temperature=0.7,
            messages=cast("list[MessageParam]", []),
            system_prompt=None,
            tools=[dummy_tool],
            tool_choice=ToolChoice(mode=ToolChoiceMode.NONE),
        )

        assert "tools" not in result, "NONE tool_choice mode must strip tools from kwargs"
        assert "tool_choice" not in result

    def test_thinking_enabled_forces_temperature_to_one_and_inflates_max_tokens(self) -> None:
        """Extended thinking sets temperature=1.0 and max_tokens=max(req, budget+1024)."""
        result: dict[str, Any] = _build_api_kwargs(
            model="claude-3-7-sonnet-20250219",
            max_tokens=100,
            temperature=0.5,
            messages=cast("list[MessageParam]", []),
            system_prompt=None,
            tools=None,
            thinking=ThinkingConfig(enabled=True, budget_tokens=5000),
        )

        assert abs(float(result["temperature"]) - 1.0) < 1e-9, f"thinking mode must force temperature to 1.0, got {result['temperature']}"
        expected_max_tokens: int = max(100, 5000 + 1024)
        assert result["max_tokens"] == expected_max_tokens, (
            f"thinking mode must set max_tokens={expected_max_tokens}, got {result['max_tokens']}"
        )
        assert result["thinking"] == {"type": "enabled", "budget_tokens": 5000}

    def test_thinking_disabled_leaves_temperature_and_max_tokens_unchanged(self) -> None:
        """When ThinkingConfig.enabled is False the kwargs are not modified."""
        result: dict[str, Any] = _build_api_kwargs(
            model="claude-3-5-sonnet-20241022",
            max_tokens=4096,
            temperature=0.7,
            messages=cast("list[MessageParam]", []),
            system_prompt=None,
            tools=None,
            thinking=ThinkingConfig(enabled=False, budget_tokens=10000),
        )

        assert abs(float(result["temperature"]) - 0.7) < 1e-9
        assert result["max_tokens"] == 4096
        assert "thinking" not in result

    def test_thinking_max_tokens_when_requested_exceeds_budget_plus_overhead(self) -> None:
        """max_tokens stays at the requested value when it already exceeds budget+1024."""
        result: dict[str, Any] = _build_api_kwargs(
            model="claude-3-7-sonnet-20250219",
            max_tokens=50000,
            temperature=0.5,
            messages=cast("list[MessageParam]", []),
            system_prompt=None,
            tools=None,
            thinking=ThinkingConfig(enabled=True, budget_tokens=5000),
        )

        assert result["max_tokens"] == 50000, (
            "max_tokens must not shrink below the caller's requested value when it already satisfies the budget"
        )


class TestApplyCacheBreakpoints:
    """Unit tests for AnthropicProvider._apply_cache_breakpoints.

    Validates that the helper places ``cache_control`` breakpoints on
    exactly the correct positions: the system block, the last tool
    entry, and the last content block of the last message.
    """

    def test_system_prompt_rewrites_to_structured_block_with_cache_control(self) -> None:
        """System prompt becomes a list with a single text block carrying cache_control."""
        kwargs: dict[str, Any] = {
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 4096,
            "temperature": 0.7,
            "messages": [],
        }
        _apply_cache_breakpoints(kwargs, system_prompt="You are a binary analysis expert")

        system_val: list[dict[str, Any]] = cast("list[dict[str, Any]]", kwargs["system"])
        assert isinstance(system_val, list), f"system must become a list, got {type(system_val)}"
        assert len(system_val) == 1
        block: dict[str, Any] = system_val[0]
        assert block["type"] == "text"
        assert block["text"] == "You are a binary analysis expert"
        assert block["cache_control"] == {"type": "ephemeral"}

    def test_last_tool_receives_cache_control_others_unchanged(self) -> None:
        """Only the last tool in the list gets a cache_control breakpoint."""
        tools: list[dict[str, Any]] = [
            {"name": "tool_a", "description": "First tool", "input_schema": {}},
            {"name": "tool_b", "description": "Second tool", "input_schema": {}},
            {"name": "tool_c", "description": "Last tool", "input_schema": {}},
        ]
        kwargs: dict[str, Any] = {
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 4096,
            "temperature": 0.7,
            "messages": [],
            "tools": copy.deepcopy(tools),
        }
        _apply_cache_breakpoints(kwargs, system_prompt=None)

        result_tools: list[dict[str, Any]] = cast("list[dict[str, Any]]", kwargs["tools"])
        assert len(result_tools) == 3
        assert "cache_control" not in result_tools[0], "tool_a must not receive cache_control"
        assert "cache_control" not in result_tools[1], "tool_b must not receive cache_control"
        assert result_tools[2]["cache_control"] == {"type": "ephemeral"}, "The last tool must receive cache_control breakpoint"
        assert result_tools[2]["name"] == "tool_c"
        assert result_tools[2]["description"] == "Last tool"

    def test_last_message_string_content_rewrites_to_block_with_cache_control(self) -> None:
        """String message content is rewritten to a structured block with cache_control."""
        kwargs: dict[str, Any] = {
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 4096,
            "temperature": 0.7,
            "messages": [{"role": "user", "content": "Analyze this binary"}],
        }
        _apply_cache_breakpoints(kwargs, system_prompt=None)

        msgs: list[dict[str, Any]] = cast("list[dict[str, Any]]", kwargs["messages"])
        assert len(msgs) == 1
        content: list[dict[str, Any]] = cast("list[dict[str, Any]]", msgs[0]["content"])
        assert isinstance(content, list), f"String content must be rewritten to list, got {type(content)}"
        assert len(content) == 1
        assert content[0]["type"] == "text"
        assert content[0]["text"] == "Analyze this binary"
        assert content[0]["cache_control"] == {"type": "ephemeral"}

    def test_last_message_list_content_last_block_gets_cache_control(self) -> None:
        """When message content is already a list, only the last block is tagged."""
        kwargs: dict[str, Any] = {
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 4096,
            "temperature": 0.7,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "First block"},
                        {"type": "text", "text": "Second block"},
                        {"type": "text", "text": "Last block"},
                    ],
                },
            ],
        }
        _apply_cache_breakpoints(kwargs, system_prompt=None)

        msgs: list[dict[str, Any]] = cast("list[dict[str, Any]]", kwargs["messages"])
        content: list[dict[str, Any]] = cast("list[dict[str, Any]]", msgs[0]["content"])
        assert len(content) == 3
        assert "cache_control" not in content[0], "First block must not receive cache_control"
        assert "cache_control" not in content[1], "Second block must not receive cache_control"
        assert content[2]["cache_control"] == {"type": "ephemeral"}, "Last block must receive cache_control"
        assert content[2]["text"] == "Last block"

    def test_original_tool_dict_is_not_mutated(self) -> None:
        """The helper must copy tool dicts; the caller's original must be unchanged."""
        original_tool: dict[str, Any] = {"name": "my_tool", "description": "A tool", "input_schema": {}}
        kwargs: dict[str, Any] = {
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 4096,
            "temperature": 0.7,
            "messages": [],
            "tools": [original_tool],
        }
        _apply_cache_breakpoints(kwargs, system_prompt=None)

        assert "cache_control" not in original_tool, "The original tool dict must not be mutated; helper must copy"


class TestCacheLastMessageBlock:
    """Unit tests for AnthropicProvider._cache_last_message_block."""

    def test_string_content_becomes_text_block_with_cache_control(self) -> None:
        """String content is replaced by a one-element list with the cached text block."""
        messages: list[dict[str, Any]] = [{"role": "user", "content": "Hello world"}]
        _cache_last_message_block(messages)

        content: list[dict[str, Any]] = cast("list[dict[str, Any]]", messages[0]["content"])
        assert isinstance(content, list)
        assert len(content) == 1
        assert content[0] == {"type": "text", "text": "Hello world", "cache_control": {"type": "ephemeral"}}

    def test_list_content_only_last_block_receives_cache_control(self) -> None:
        """Only the final block in a list-valued content gets the ephemeral tag."""
        messages: list[dict[str, Any]] = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "A"},
                    {"type": "text", "text": "B"},
                ],
            },
        ]
        _cache_last_message_block(messages)

        content: list[dict[str, Any]] = cast("list[dict[str, Any]]", messages[0]["content"])
        assert len(content) == 2
        assert "cache_control" not in content[0]
        assert content[1]["cache_control"] == {"type": "ephemeral"}
        assert content[1]["text"] == "B"

    def test_operates_on_last_message_in_list(self) -> None:
        """Only the last message is mutated; earlier messages are left alone."""
        messages: list[dict[str, Any]] = [
            {"role": "user", "content": "First message"},
            {"role": "assistant", "content": "Second message"},
        ]
        _cache_last_message_block(messages)

        assert messages[0]["content"] == "First message", "First message must not be mutated"
        second_content: list[dict[str, Any]] = cast("list[dict[str, Any]]", messages[1]["content"])
        assert isinstance(second_content, list)
        assert second_content[0]["cache_control"] == {"type": "ephemeral"}


class TestBuildUsageFromMessage:
    """Unit tests for AnthropicProvider._build_usage_from_message.

    Validates that token counts are extracted exactly from the Anthropic
    message usage attribute and that the helper returns None when usage
    is absent.
    """

    def test_usage_fields_are_extracted_exactly(self) -> None:
        """prompt_tokens, completion_tokens, and total_tokens have the exact API values."""
        msg: AnthropicMessage = AnthropicMessage(
            id="msg_01",
            type="message",
            role="assistant",
            content=[TextBlock(type="text", text="test")],
            model="claude-3-5-sonnet-20241022",
            stop_reason="end_turn",
            stop_sequence=None,
            usage=Usage(input_tokens=150, output_tokens=75),
        )

        usage: UsageInfo | None = _build_usage_from_message(msg)

        assert usage is not None
        assert usage.prompt_tokens == 150
        assert usage.completion_tokens == 75
        assert usage.total_tokens == 225

    def test_zero_usage_fields_produce_zero_total(self) -> None:
        """Zero token counts produce a UsageInfo with all-zero fields."""
        msg: AnthropicMessage = AnthropicMessage(
            id="msg_02",
            type="message",
            role="assistant",
            content=[],
            model="claude-3-5-sonnet-20241022",
            stop_reason="end_turn",
            stop_sequence=None,
            usage=Usage(input_tokens=0, output_tokens=0),
        )

        usage: UsageInfo | None = _build_usage_from_message(msg)

        assert usage is not None
        assert usage.prompt_tokens == 0
        assert usage.completion_tokens == 0
        assert usage.total_tokens == 0


class TestParseResponseBlocks:
    """Unit tests for AnthropicProvider._parse_response_blocks.

    Validates that text, thinking, and tool-call blocks are correctly
    separated, that tool_name is extracted from dotted function names,
    and that arguments are passed through faithfully.
    """

    def test_text_only_response_extracted_exactly(self) -> None:
        """Plain text response content is returned verbatim; no tool calls or thinking."""
        provider = AnthropicProvider()
        msg: AnthropicMessage = AnthropicMessage(
            id="msg_01",
            type="message",
            role="assistant",
            content=[TextBlock(type="text", text="The entry point is 0x1400.")],
            model="claude-3-5-sonnet-20241022",
            stop_reason="end_turn",
            stop_sequence=None,
            usage=Usage(input_tokens=10, output_tokens=5),
        )

        parse_blocks: Any = getattr(provider, "_parse_response_blocks")
        text, tool_calls, thinking = parse_blocks(msg)

        assert text == "The entry point is 0x1400."
        assert tool_calls == []
        assert not thinking

    def test_thinking_block_is_captured_separately_from_text(self) -> None:
        """ThinkingBlock content appears only in thinking; TextBlock only in text."""
        provider = AnthropicProvider()
        msg: AnthropicMessage = AnthropicMessage(
            id="msg_02",
            type="message",
            role="assistant",
            content=[
                ThinkingBlock(type="thinking", thinking="Let me reason step by step...", signature="sig123"),
                TextBlock(type="text", text="The function is a decryption routine."),
            ],
            model="claude-3-7-sonnet-20250219",
            stop_reason="end_turn",
            stop_sequence=None,
            usage=Usage(input_tokens=20, output_tokens=10),
        )

        parse_blocks: Any = getattr(provider, "_parse_response_blocks")
        text, tool_calls, thinking = parse_blocks(msg)

        assert text == "The function is a decryption routine."
        assert thinking == "Let me reason step by step..."
        assert tool_calls == []

    def test_tool_use_block_tool_name_extracted_from_dotted_function_name(self) -> None:
        """Dotted function name is split: tool_name='ghidra', function_name='ghidra.decompile'."""
        provider = AnthropicProvider()
        msg: AnthropicMessage = AnthropicMessage(
            id="msg_03",
            type="message",
            role="assistant",
            content=[
                ToolUseBlock(
                    type="tool_use",
                    id="toolu_01",
                    name="ghidra.decompile",
                    input={"address": "0x1400", "max_lines": 50},
                ),
            ],
            model="claude-3-5-sonnet-20241022",
            stop_reason="tool_use",
            stop_sequence=None,
            usage=Usage(input_tokens=30, output_tokens=15),
        )

        parse_blocks: Any = getattr(provider, "_parse_response_blocks")
        text, tool_calls, thinking = parse_blocks(msg)

        assert not text
        assert not thinking
        assert len(tool_calls) == 1
        tc: ToolCall = tool_calls[0]
        assert tc.id == "toolu_01"
        assert tc.tool_name == "ghidra"
        assert tc.function_name == "ghidra.decompile"
        assert tc.arguments == {"address": "0x1400", "max_lines": 50}

    def test_mixed_thinking_text_and_tool_use_blocks(self) -> None:
        """All three block types coexist; each is routed to the correct output slot."""
        provider = AnthropicProvider()
        msg: AnthropicMessage = AnthropicMessage(
            id="msg_04",
            type="message",
            role="assistant",
            content=[
                ThinkingBlock(type="thinking", thinking="Reasoning block.", signature="sig456"),
                TextBlock(type="text", text="I will call the tool."),
                ToolUseBlock(
                    type="tool_use",
                    id="toolu_02",
                    name="x64dbg.get_registers",
                    input={"thread_id": 1},
                ),
            ],
            model="claude-3-5-sonnet-20241022",
            stop_reason="tool_use",
            stop_sequence=None,
            usage=Usage(input_tokens=40, output_tokens=20),
        )

        parse_blocks: Any = getattr(provider, "_parse_response_blocks")
        text, tool_calls, thinking = parse_blocks(msg)

        assert text == "I will call the tool."
        assert thinking == "Reasoning block."
        assert len(tool_calls) == 1
        assert tool_calls[0].tool_name == "x64dbg"
        assert tool_calls[0].function_name == "x64dbg.get_registers"
        assert tool_calls[0].arguments == {"thread_id": 1}

    def test_multiple_text_blocks_are_concatenated(self) -> None:
        """Multiple TextBlock instances are concatenated in order."""
        provider = AnthropicProvider()
        msg: AnthropicMessage = AnthropicMessage(
            id="msg_05",
            type="message",
            role="assistant",
            content=[
                TextBlock(type="text", text="Part one. "),
                TextBlock(type="text", text="Part two."),
            ],
            model="claude-3-5-sonnet-20241022",
            stop_reason="end_turn",
            stop_sequence=None,
            usage=Usage(input_tokens=10, output_tokens=5),
        )

        parse_blocks: Any = getattr(provider, "_parse_response_blocks")
        text, tool_calls, thinking = parse_blocks(msg)

        assert text == "Part one. Part two."
        assert tool_calls == []
        assert not thinking


class TestConvertMessagesToProviderFormat:
    """Unit tests for AnthropicProvider._convert_messages_to_provider_format.

    Validates that each role is correctly mapped to the Anthropic wire
    format, that system messages are dropped, and that tool calls and
    tool results produce the expected structured content.
    """

    def test_system_messages_are_dropped(self) -> None:
        """System-role messages must be excluded from the converted list."""
        provider = AnthropicProvider()
        messages: list[Message] = [
            Message(role="system", content="You are a binary analysis assistant"),
            Message(role="user", content="Analyze this binary"),
        ]

        result: list[dict[str, object]] = provider.convert_messages_to_provider_format(messages)

        assert len(result) == 1, f"System message must be dropped; got {len(result)} messages"
        assert result[0]["role"] == "user"
        assert result[0]["content"] == "Analyze this binary"

    def test_user_message_converts_to_exact_wire_format(self) -> None:
        """User message maps to role='user', content=<string>."""
        provider = AnthropicProvider()
        messages: list[Message] = [Message(role="user", content="What is the entry point?")]

        result: list[dict[str, object]] = provider.convert_messages_to_provider_format(messages)

        assert len(result) == 1
        assert result[0] == {"role": "user", "content": "What is the entry point?"}

    def test_assistant_message_with_text_only_uses_list_content(self) -> None:
        """Assistant text-only message produces a list containing one text block."""
        provider = AnthropicProvider()
        messages: list[Message] = [Message(role="assistant", content="The entry point is 0x1400.")]

        result: list[dict[str, object]] = provider.convert_messages_to_provider_format(messages)

        assert len(result) == 1
        assert result[0]["role"] == "assistant"
        content: list[dict[str, object]] = cast("list[dict[str, object]]", result[0]["content"])
        assert isinstance(content, list)
        assert len(content) == 1
        assert content[0] == {"type": "text", "text": "The entry point is 0x1400."}

    def test_assistant_message_with_tool_calls_produces_tool_use_blocks(self) -> None:
        """Tool calls in an assistant message appear as tool_use blocks in content."""
        provider = AnthropicProvider()
        tc = ToolCall(
            id="toolu_01",
            tool_name="ghidra",
            function_name="ghidra.decompile",
            arguments={"address": "0x1400"},
        )
        messages: list[Message] = [
            Message(role="assistant", content="I will decompile this function.", tool_calls=[tc]),
        ]

        result: list[dict[str, object]] = provider.convert_messages_to_provider_format(messages)

        assert len(result) == 1
        content: list[dict[str, object]] = cast("list[dict[str, object]]", result[0]["content"])
        assert isinstance(content, list)
        assert len(content) == 2

        text_block: dict[str, object] = content[0]
        assert text_block["type"] == "text"
        assert text_block["text"] == "I will decompile this function."

        tool_block: dict[str, object] = content[1]
        assert tool_block["type"] == "tool_use"
        assert tool_block["id"] == "toolu_01"
        assert tool_block["name"] == "ghidra.decompile"
        assert tool_block["input"] == {"address": "0x1400"}

    def test_tool_result_message_produces_tool_result_blocks_in_user_role(self) -> None:
        """Tool result messages appear as role='user' with tool_result content blocks."""
        provider = AnthropicProvider()
        tr = ToolResult(
            call_id="toolu_01",
            success=True,
            result="void FUN_00001400(void) { ... }",
            error=None,
            duration_ms=120.0,
        )
        messages: list[Message] = [Message(role="tool", content="", tool_results=[tr])]

        result: list[dict[str, object]] = provider.convert_messages_to_provider_format(messages)

        assert len(result) == 1
        assert result[0]["role"] == "user"
        content: list[dict[str, object]] = cast("list[dict[str, object]]", result[0]["content"])
        assert isinstance(content, list)
        assert len(content) == 1
        block: dict[str, object] = content[0]
        assert block["type"] == "tool_result"
        assert block["tool_use_id"] == "toolu_01"
        assert block["content"] == "void FUN_00001400(void) { ... }"
        assert block["is_error"] is False

    def test_failed_tool_result_sets_is_error_true(self) -> None:
        """A tool result with success=False produces is_error=True in the wire format."""
        provider = AnthropicProvider()
        tr = ToolResult(
            call_id="toolu_02",
            success=False,
            result=None,
            error="Function not found at 0x9999",
            duration_ms=5.0,
        )
        messages: list[Message] = [Message(role="tool", content="", tool_results=[tr])]

        result: list[dict[str, object]] = provider.convert_messages_to_provider_format(messages)

        content: list[dict[str, object]] = cast("list[dict[str, object]]", result[0]["content"])
        block: dict[str, object] = content[0]
        assert block["is_error"] is True

    def test_empty_tool_results_message_is_dropped(self) -> None:
        """A tool-role message with no tool_results produces no output entry."""
        provider = AnthropicProvider()
        messages: list[Message] = [Message(role="tool", content="", tool_results=None)]

        result: list[dict[str, object]] = provider.convert_messages_to_provider_format(messages)

        assert result == [], f"Tool message with no results must be dropped, got {result}"


class TestConvertToolsToProviderFormat:
    """Unit tests for AnthropicProvider._convert_tools_to_provider_format.

    Validates that ToolDefinition objects are translated faithfully into
    Anthropic's ``input_schema``-based tool format.
    """

    def test_single_tool_produces_correct_anthropic_schema_structure(self) -> None:
        """One ToolFunction produces one AnthropicToolSchema with exact field values."""
        provider = AnthropicProvider()
        tool_def = ToolDefinition(
            tool_name=ToolName.GHIDRA,
            description="Ghidra binary analysis tool",
            functions=[
                ToolFunction(
                    name="ghidra.decompile",
                    description="Decompile a function at the given address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="string",
                            description="Hex address of the function",
                            required=True,
                        ),
                        ToolParameter(
                            name="max_lines",
                            type="integer",
                            description="Maximum output lines",
                            required=False,
                        ),
                    ],
                    returns="Decompiled C pseudocode",
                ),
            ],
        )

        result: list[dict[str, object]] = provider.convert_tools_to_provider_format([tool_def])

        assert len(result) == 1
        schema: dict[str, object] = result[0]
        assert schema["name"] == "ghidra.decompile"
        assert schema["description"] == "Decompile a function at the given address"
        input_schema: dict[str, object] = cast("dict[str, object]", schema["input_schema"])
        assert input_schema["type"] == "object"
        props: dict[str, dict[str, object]] = cast("dict[str, dict[str, object]]", input_schema["properties"])
        assert "address" in props
        assert props["address"]["type"] == "string"
        assert props["address"]["description"] == "Hex address of the function"
        assert "max_lines" in props
        required: list[str] = cast("list[str]", input_schema["required"])
        assert "address" in required
        assert "max_lines" not in required

    def test_required_params_appear_in_required_list_only(self) -> None:
        """Only required=True params appear in the required array."""
        provider = AnthropicProvider()
        tool_def = ToolDefinition(
            tool_name=ToolName.FRIDA,
            description="Frida instrumentation tool",
            functions=[
                ToolFunction(
                    name="frida.hook_function",
                    description="Hook a function",
                    parameters=[
                        ToolParameter(name="target", type="string", description="Target address", required=True),
                        ToolParameter(name="script", type="string", description="Hook script", required=True),
                        ToolParameter(name="timeout_ms", type="integer", description="Timeout", required=False),
                    ],
                    returns="Hook ID",
                ),
            ],
        )

        result: list[dict[str, object]] = provider.convert_tools_to_provider_format([tool_def])

        input_schema: dict[str, object] = cast("dict[str, object]", result[0]["input_schema"])
        required: list[str] = cast("list[str]", input_schema["required"])
        assert set(required) == {"target", "script"}, f"Only required params must appear in required list, got {required}"


class TestProviderNameAndConnectedState:
    """Unit tests for AnthropicProvider name property and is_connected state."""

    def test_name_property_returns_anthropic_enum_value(self) -> None:
        """The name property returns exactly ProviderName.ANTHROPIC."""
        provider = AnthropicProvider()

        assert provider.name is ProviderName.ANTHROPIC
        assert provider.name.value == "anthropic"

    def test_is_connected_false_before_connect(self) -> None:
        """is_connected is False immediately after construction."""
        provider = AnthropicProvider()

        assert provider.is_connected is False

    def test_list_models_raises_provider_error_when_not_connected(self) -> None:
        """list_models raises ProviderError with 'Not connected' message."""
        provider = AnthropicProvider()

        async def _call() -> None:
            await provider.list_models()

        with pytest.raises(ProviderError) as exc_info:
            asyncio.run(_call())

        assert "not connected" in str(exc_info.value).lower(), f"ProviderError must mention 'not connected', got: {exc_info.value}"

    def test_chat_raises_provider_error_when_not_connected(self) -> None:
        """chat() raises ProviderError when the provider is not connected."""
        provider = AnthropicProvider()

        async def _call() -> None:
            await provider.chat(
                messages=[Message(role="user", content="Hello")],
                model="claude-3-5-sonnet-20241022",
            )

        with pytest.raises(ProviderError) as exc_info:
            asyncio.run(_call())

        assert "not connected" in str(exc_info.value).lower()


class TestConnectionErrorHandling:
    """Tests for error handling during provider connection."""

    def test_connect_with_empty_key_raises_authentication_error(self) -> None:
        """connect() with an empty api_key raises AuthenticationError immediately."""
        provider = AnthropicProvider()

        async def _call() -> None:
            await provider.connect(ProviderCredentials(api_key=""))

        with pytest.raises(AuthenticationError) as exc_info:
            asyncio.run(_call())

        assert "api key" in str(exc_info.value).lower(), f"AuthenticationError must mention API key, got: {exc_info.value}"

    def test_connect_with_none_key_raises_authentication_error(self) -> None:
        """connect() with api_key=None raises AuthenticationError."""
        provider = AnthropicProvider()

        async def _call() -> None:
            await provider.connect(ProviderCredentials(api_key=None))

        with pytest.raises(AuthenticationError):
            asyncio.run(_call())


@pytest.mark.integration
class TestAnthropicModelListing:
    """Integration tests for Anthropic model listing functionality.

    These tests validate that AnthropicProvider can dynamically fetch
    models from the Anthropic API. Tests are skipped when no API key
    is configured.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_returns_claude_prefixed_ids(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Every model ID returned by the API starts with 'claude-'.

        This is an independently-known invariant of the Anthropic models
        endpoint: the provider exclusively hosts Claude models. Any model
        ID that does not start with 'claude-' would represent either an
        API change or a bridge transformation defect.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        models: list[ModelInfo] = await anthropic_provider.list_models()

        assert len(models) > 0, "Anthropic API must return at least one model"
        non_claude: list[str] = [m.id for m in models if not m.id.startswith(_KNOWN_CLAUDE_PREFIX)]
        assert non_claude == [], f"All model IDs must start with '{_KNOWN_CLAUDE_PREFIX}', but these do not: {non_claude}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_includes_a_known_production_model(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """At least one independently-known production model appears in the listing.

        The set of known IDs below represents models that have been
        publicly documented by Anthropic and were confirmed available
        via a live API call on 2026-06-07. The test fails only if none
        of these IDs appear in the live response, which would indicate
        the bridge is silently truncating or filtering the model list.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        known_claude_models: frozenset[str] = frozenset({
            "claude-sonnet-4-20250514",
            "claude-opus-4-20250514",
            "claude-opus-4-1-20250805",
            "claude-sonnet-4-5-20250929",
            "claude-haiku-4-5-20251001",
            "claude-opus-4-5-20251101",
            "claude-opus-4-6",
            "claude-sonnet-4-6",
            "claude-opus-4-7",
            "claude-opus-4-8",
        })

        models: list[ModelInfo] = await anthropic_provider.list_models()
        returned_ids: set[str] = {m.id for m in models}

        matching: set[str] = returned_ids & known_claude_models
        assert len(matching) > 0, (
            f"At least one known production model must appear in the API response. Known: {known_claude_models}. Got: {returned_ids}"
        )

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_all_have_200k_context_window(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Every returned model reports the 200k context window.

        The bridge hardcodes 200k for all Anthropic models (see
        ``_build_model_info``). If any model is returned with a different
        value it indicates the hardcoded constant was changed silently.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        models: list[ModelInfo] = await anthropic_provider.list_models()

        assert len(models) > 0
        wrong_window: list[tuple[str, int]] = [(m.id, m.context_window) for m in models if m.context_window != _CONTEXT_WINDOW_200K]
        assert wrong_window == [], f"All models must report {_CONTEXT_WINDOW_200K} context_window, but these do not: {wrong_window}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_all_have_true_capability_flags(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Every returned model has supports_tools, supports_vision, and supports_streaming set True.

        The bridge asserts all three as True for every Anthropic model.
        A False value would indicate the bridge is applying incorrect
        per-model capability logic.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        models: list[ModelInfo] = await anthropic_provider.list_models()

        assert len(models) > 0
        for model in models:
            assert model.supports_tools is True, f"Model {model.id!r} must have supports_tools=True"
            assert model.supports_vision is True, f"Model {model.id!r} must have supports_vision=True"
            assert model.supports_streaming is True, f"Model {model.id!r} must have supports_streaming=True"

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_all_have_anthropic_provider_tag(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Every returned model carries ProviderName.ANTHROPIC.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        models: list[ModelInfo] = await anthropic_provider.list_models()

        assert len(models) > 0
        for model in models:
            assert model.provider is ProviderName.ANTHROPIC, f"Model {model.id!r} must have provider=ANTHROPIC, got {model.provider}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_all_have_nonempty_name(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Every returned model has a non-empty name string.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        models: list[ModelInfo] = await anthropic_provider.list_models()

        assert len(models) > 0
        empty_name: list[str] = [m.id for m in models if not m.name]
        assert empty_name == [], f"These models have empty names: {empty_name}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_multiple_calls_return_same_model_ids(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Two consecutive list_models calls return the same set of IDs.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        models1: list[ModelInfo] = await anthropic_provider.list_models()
        models2: list[ModelInfo] = await anthropic_provider.list_models()

        ids1: set[str] = {m.id for m in models1}
        ids2: set[str] = {m.id for m in models2}

        assert ids1 == ids2, f"Inconsistent model IDs across consecutive calls: {ids1 ^ ids2}"


@pytest.mark.integration
class TestAnthropicConnection:
    """Integration tests for Anthropic provider connection lifecycle."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_is_connected_true_after_successful_connect(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Provider reports is_connected=True after the fixture connects.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        assert anthropic_provider.is_connected is True

    @pytest.mark.asyncio
    @staticmethod
    async def test_provider_name_is_anthropic_enum_value(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Connected provider's name property is ProviderName.ANTHROPIC.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        assert anthropic_provider.name is ProviderName.ANTHROPIC
        assert anthropic_provider.name.value == "anthropic"

    @pytest.mark.asyncio
    @staticmethod
    async def test_disconnect_sets_is_connected_false(
        credential_loader: CredentialLoader,
        *,
        has_anthropic_key: bool,
    ) -> None:
        """disconnect() sets is_connected to False.

        Args:
            credential_loader: Credential loader fixture.
            has_anthropic_key: Whether an Anthropic API key is configured.
        """
        if not has_anthropic_key:
            pytest.skip("ANTHROPIC_API_KEY not configured")

        provider = AnthropicProvider()
        credentials = credential_loader.get_credentials(ProviderName.ANTHROPIC)
        assert credentials is not None

        await provider.connect(credentials)
        assert provider.is_connected is True

        await provider.disconnect()
        assert provider.is_connected is False, "Provider must report is_connected=False after disconnect()"

    @pytest.mark.asyncio
    @staticmethod
    async def test_connect_with_structurally_invalid_key_raises_authentication_error() -> None:
        """connect() with a syntactically-formatted-but-rejected key raises AuthenticationError.

        The key ``sk-ant-api03-invalid-key-for-testing-only`` matches the ``sk-ant-``
        prefix pattern but is rejected by the live Anthropic API with a 401 response.
        This validates that the bridge layer correctly maps the Anthropic SDK's
        ``AuthenticationError`` to Intellicrack's ``AuthenticationError`` type.
        """
        provider = AnthropicProvider()

        with pytest.raises(AuthenticationError) as exc_info:
            await provider.connect(ProviderCredentials(api_key="sk-ant-api03-invalid-key-for-testing-only"))

        assert exc_info.type is AuthenticationError, f"Must raise AuthenticationError, got {exc_info.type}"
        assert provider.is_connected is False, "Provider must remain disconnected after auth failure"

    @pytest.mark.asyncio
    @staticmethod
    async def test_provider_remains_disconnected_after_failed_connect() -> None:
        """is_connected must be False after a connect() call with an invalid key.

        Issues a real API call with a structurally-valid-but-rejected key and
        confirms the bridge does not flip is_connected to True when the API
        returns a 401 authentication error.
        """
        provider = AnthropicProvider()

        raised: bool = False
        try:
            await provider.connect(ProviderCredentials(api_key="sk-ant-api03-invalid"))
        except AuthenticationError:
            raised = True

        assert raised, "connect() with an invalid key must raise AuthenticationError"
        assert provider.is_connected is False, "Provider must report is_connected=False after failed connect()"
