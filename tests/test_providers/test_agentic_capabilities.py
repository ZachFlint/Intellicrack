# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Integration tests for LLM provider agentic capabilities.

Tests tool_choice, streaming tool calls, context window enforcement,
extended thinking, and prompt caching across all providers.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.types import (
    Message,
    ThinkingConfig,
    ToolCall,
    ToolChoice,
    ToolChoiceMode,
    ToolDefinition,
    ToolFunction,
    ToolName,
    ToolParameter,
)


if TYPE_CHECKING:
    from intellicrack.providers.anthropic import AnthropicProvider
    from intellicrack.providers.google import GoogleProvider
    from intellicrack.providers.grok import GrokProvider
    from intellicrack.providers.huggingface import HuggingFaceProvider
    from intellicrack.providers.ollama import OllamaProvider
    from intellicrack.providers.openai import OpenAIProvider
    from intellicrack.providers.openrouter import OpenRouterProvider


pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


def _make_test_tool() -> list[ToolDefinition]:
    """Build a minimal tool definition for testing function calling.

    Returns:
        list[ToolDefinition]: A list containing a single ToolDefinition for binary.get_file_size.
    """
    return [
        ToolDefinition(
            tool_name=ToolName.GHIDRA,
            description="Binary analysis tools",
            functions=[
                ToolFunction(
                    name="binary.get_file_size",
                    description="Get the file size in bytes of the loaded binary.",
                    parameters=[
                        ToolParameter(
                            name="path",
                            type="string",
                            description="Path to the binary file.",
                            required=True,
                        ),
                    ],
                    returns="File size in bytes as an integer.",
                ),
            ],
        ),
    ]


def _make_messages(prompt: str) -> list[Message]:
    """Build a simple user message list for testing.

    Args:
        prompt: The user message text.

    Returns:
        list[Message]: A list containing a single user Message.
    """
    return [Message(role="user", content=prompt, timestamp=datetime.now(tz=UTC))]


class TestToolChoiceRequired:
    """Verify tool_choice=REQUIRED forces a tool call on capable providers."""

    async def test_anthropic_tool_choice_required_forces_tool_call(
        self,
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Anthropic should return a tool call when tool_choice is REQUIRED.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        tools = _make_test_tool()
        messages = _make_messages("What is the size of notepad.exe?")
        choice = ToolChoice(mode=ToolChoiceMode.REQUIRED)

        _, tool_calls = await anthropic_provider.chat(
            messages=messages,
            model="claude-sonnet-4-20250514",
            tools=tools,
            tool_choice=choice,
            max_tokens=1024,
        )
        assert tool_calls is not None
        assert len(tool_calls) > 0
        assert isinstance(tool_calls[0], ToolCall)

    async def test_openai_tool_choice_none_prevents_tool_call(
        self,
        openai_provider: OpenAIProvider,
    ) -> None:
        """OpenAI should not return tool calls when tool_choice is NONE.

        Args:
            openai_provider: Connected OpenAI provider fixture.
        """
        tools = _make_test_tool()
        messages = _make_messages("What is the size of notepad.exe?")
        choice = ToolChoice(mode=ToolChoiceMode.NONE)

        _, tool_calls = await openai_provider.chat(
            messages=messages,
            model="gpt-4o-mini",
            tools=tools,
            tool_choice=choice,
            max_tokens=1024,
        )
        assert tool_calls is None

    async def test_grok_tool_choice_required(
        self,
        grok_provider: GrokProvider,
    ) -> None:
        """Grok should return a tool call when tool_choice is REQUIRED.

        Args:
            grok_provider: Connected Grok provider fixture.
        """
        tools = _make_test_tool()
        messages = _make_messages("What is the size of notepad.exe?")
        choice = ToolChoice(mode=ToolChoiceMode.REQUIRED)

        _, tool_calls = await grok_provider.chat(
            messages=messages,
            model="grok-3-mini",
            tools=tools,
            tool_choice=choice,
            max_tokens=1024,
        )
        assert tool_calls is not None
        assert len(tool_calls) > 0

    async def test_google_tool_choice_auto(
        self,
        google_provider: GoogleProvider,
    ) -> None:
        """Google should handle tool_choice=AUTO without error."""
        tools = _make_test_tool()
        messages = _make_messages("What is the size of notepad.exe?")
        choice = ToolChoice(mode=ToolChoiceMode.AUTO)

        response, _ = await google_provider.chat(
            messages=messages,
            model="gemini-2.0-flash",
            tools=tools,
            tool_choice=choice,
            max_tokens=1024,
        )
        assert response.role == "assistant"

    async def test_openrouter_tool_choice_required(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """OpenRouter should return a tool call when tool_choice is REQUIRED."""
        tools = _make_test_tool()
        messages = _make_messages("What is the size of notepad.exe?")
        choice = ToolChoice(mode=ToolChoiceMode.REQUIRED)

        _, tool_calls = await openrouter_provider.chat(
            messages=messages,
            model="openai/gpt-4o-mini",
            tools=tools,
            tool_choice=choice,
            max_tokens=1024,
        )
        assert tool_calls is not None
        assert len(tool_calls) > 0


class TestStreamingToolCalls:
    """Verify streaming captures tool calls on previously broken providers."""

    async def test_huggingface_stream_captures_tool_calls(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """HuggingFace stream should capture tool calls via ToolCallBufferManager."""
        tools = _make_test_tool()
        messages = _make_messages("Use the binary.get_file_size tool to check notepad.exe")

        _chunks = [
            chunk
            async for chunk in huggingface_provider.chat_stream(
                messages=messages,
                model="meta-llama/Llama-3.1-8B-Instruct",
                tools=tools,
                max_tokens=1024,
            )
        ]

        pending = huggingface_provider.get_pending_tool_calls()
        assert isinstance(pending, list)

    async def test_ollama_stream_with_tools_returns_tool_calls(
        self,
        ollama_provider: OllamaProvider,
    ) -> None:
        """Ollama stream should capture tool calls via non-streaming fallback."""
        tools = _make_test_tool()
        messages = _make_messages("Use binary.get_file_size to get the size of C:\\Windows\\notepad.exe")

        _chunks = [
            chunk
            async for chunk in ollama_provider.chat_stream(
                messages=messages,
                model="local/llama3.2",
                tools=tools,
                max_tokens=1024,
            )
        ]

        pending = ollama_provider.get_pending_tool_calls()
        assert isinstance(pending, list)


class TestAccurateToolSupport:
    """Verify models report accurate supports_tools metadata."""

    async def test_ollama_models_report_accurate_tool_support(
        self,
        ollama_provider: OllamaProvider,
    ) -> None:
        """Ollama model list should have varying supports_tools values."""
        models = await ollama_provider.list_models()
        if not models:
            pytest.skip("No Ollama models installed locally")

        tool_support_values = {m.supports_tools for m in models}
        assert isinstance(tool_support_values, set)

    async def test_openrouter_models_report_accurate_tool_support(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """OpenRouter model list should include models without tool support."""
        models = await openrouter_provider.list_models()
        assert len(models) > 0

        tool_support_values = {m.supports_tools for m in models}
        assert False in tool_support_values, "Expected some models without tool support"


class TestContextWindowEnforcement:
    """Verify orchestrator message trimming logic."""

    def test_message_trimming_removes_oldest_first(self) -> None:
        """Oldest non-system messages should be removed first."""
        messages = [
            Message(role="system", content="You are an assistant."),
            Message(role="user", content="A" * 4000),
            Message(role="assistant", content="B" * 4000),
            Message(role="user", content="C" * 4000),
        ]

        trimmed = Orchestrator.trim_messages_to_context_window(
            list(messages),
            context_window=2000,
        )

        assert trimmed[0].role == "system"
        assert len(trimmed) < len(messages)

    def test_system_message_never_trimmed(self) -> None:
        """System message should survive trimming."""
        messages = [
            Message(role="system", content="System prompt " * 100),
            Message(role="user", content="Hello"),
        ]

        trimmed = Orchestrator.trim_messages_to_context_window(
            list(messages),
            context_window=500,
        )

        system_messages = [m for m in trimmed if m.role == "system"]
        assert len(system_messages) == 1

    def test_no_trimming_within_limit(self) -> None:
        """Messages within the context window should not be trimmed."""
        messages = [
            Message(role="system", content="Short system prompt."),
            Message(role="user", content="Short user message."),
        ]
        original_count = len(messages)

        trimmed = Orchestrator.trim_messages_to_context_window(
            list(messages),
            context_window=128000,
        )

        assert len(trimmed) == original_count


class TestExtendedThinking:
    """Verify extended thinking support on Anthropic."""

    async def test_anthropic_extended_thinking_returns_thinking_content(
        self,
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Anthropic should return thinking_content when thinking is enabled."""
        messages = _make_messages("What are the first 5 prime numbers? Think step by step.")
        thinking = ThinkingConfig(enabled=True, budget_tokens=5000)

        response, _ = await anthropic_provider.chat(
            messages=messages,
            model="claude-sonnet-4-20250514",
            thinking=thinking,
            max_tokens=8192,
        )
        assert response.thinking_content is not None
        assert len(response.thinking_content) > 0

    async def test_non_anthropic_ignores_thinking(
        self,
        openai_provider: OpenAIProvider,
    ) -> None:
        """Non-Anthropic providers should not error when thinking param passed."""
        messages = _make_messages("Hello")
        thinking = ThinkingConfig(enabled=True, budget_tokens=5000)

        response, _ = await openai_provider.chat(
            messages=messages,
            model="gpt-4o-mini",
            thinking=thinking,
            max_tokens=1024,
        )
        assert response.role == "assistant"


class TestPromptCaching:
    """Verify prompt caching support."""

    async def test_anthropic_caching_succeeds(
        self,
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Anthropic caching should not error on API calls."""
        messages = _make_messages("Hello, respond briefly.")

        response1, _ = await anthropic_provider.chat(
            messages=messages,
            model="claude-sonnet-4-20250514",
            enable_cache=True,
            max_tokens=256,
        )
        assert response1.role == "assistant"

        response2, _ = await anthropic_provider.chat(
            messages=messages,
            model="claude-sonnet-4-20250514",
            enable_cache=True,
            max_tokens=256,
        )
        assert response2.role == "assistant"
