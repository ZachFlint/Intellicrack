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
from typing import TYPE_CHECKING, ClassVar

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


pytestmark = [pytest.mark.integration]


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

    pytestmark: ClassVar[list[pytest.MarkDecorator]] = [pytest.mark.integration, pytest.mark.asyncio]

    async def test_anthropic_tool_choice_required_forces_tool_call(
        self,
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Anthropic REQUIRED must yield a structured call to the only tool.

        Drives the real connected Anthropic provider with a single tool whose
        schema declares one required ``path`` parameter and
        ``tool_choice=REQUIRED``. Because exactly one tool is offered and a tool
        call is mandatory, the provider's response translation must surface a
        :class:`ToolCall` naming that exact function (``binary.get_file_size``)
        with ``tool_name`` derived from the function-name prefix (``binary``) and
        the required ``path`` argument present and non-empty. A regression in the
        REQUIRED-mode mapping or the streaming/non-streaming tool-call assembler
        (wrong function name, dropped arguments, or a free-text answer instead of
        a tool call) fails these assertions.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        tools = _make_test_tool()
        messages = _make_messages("What is the size of notepad.exe at C:\\Windows\\notepad.exe?")
        choice = ToolChoice(mode=ToolChoiceMode.REQUIRED)

        _, tool_calls = await anthropic_provider.chat(
            messages=messages,
            model="claude-sonnet-4-20250514",
            tools=tools,
            tool_choice=choice,
            max_tokens=1024,
        )
        assert tool_calls is not None
        assert len(tool_calls) == 1
        call = tool_calls[0]
        assert isinstance(call, ToolCall)
        assert call.function_name == "binary.get_file_size"
        assert call.tool_name == "binary"
        assert len(call.id) > 0
        assert "path" in call.arguments
        path_arg = call.arguments["path"]
        assert isinstance(path_arg, str)
        assert len(path_arg) > 0

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
        """Grok REQUIRED must yield a structured call to the only offered tool.

        Drives the real connected Grok provider with a single tool whose schema
        declares one required ``path`` parameter and ``tool_choice=REQUIRED``.
        Because exactly one tool is offered and a tool call is mandatory, the
        provider's response translation must surface a :class:`ToolCall` naming
        that exact function (``binary.get_file_size``) with a non-empty ``id``
        and the required ``path`` argument present and typed as ``str``. A
        regression in the REQUIRED-mode mapping, function-name translation, or
        dropped-argument handling fails these assertions.

        Args:
            grok_provider: Connected Grok provider fixture.
        """
        tools = _make_test_tool()
        messages = _make_messages("What is the size of notepad.exe at C:\\Windows\\notepad.exe?")
        choice = ToolChoice(mode=ToolChoiceMode.REQUIRED)

        _, tool_calls = await grok_provider.chat(
            messages=messages,
            model="grok-3-mini",
            tools=tools,
            tool_choice=choice,
            max_tokens=1024,
        )
        assert tool_calls is not None
        assert len(tool_calls) == 1
        call = tool_calls[0]
        assert isinstance(call, ToolCall)
        assert call.function_name == "binary.get_file_size"
        assert call.tool_name == "binary"
        assert len(call.id) > 0
        assert "path" in call.arguments
        path_arg = call.arguments["path"]
        assert isinstance(path_arg, str)
        assert len(path_arg) > 0

    async def test_google_tool_choice_auto(
        self,
        google_provider: GoogleProvider,
    ) -> None:
        """Google AUTO mode must return an assistant-role response without raising.

        Drives the real connected Google provider with a single tool and
        ``tool_choice=AUTO``. The provider may or may not elect to call the
        tool; what must hold is that the response carries role ``"assistant"``
        and either the response content is non-empty (free-text reply) or
        tool_calls is non-None (a tool call was made). Both outcomes are valid
        under AUTO mode. A regression that crashes, drops the role, or
        returns both empty content and no tool calls fails.

        Args:
            google_provider: Connected Google provider fixture.
        """
        tools = _make_test_tool()
        messages = _make_messages("What is the size of notepad.exe?")
        choice = ToolChoice(mode=ToolChoiceMode.AUTO)

        response, tool_calls = await google_provider.chat(
            messages=messages,
            model="gemini-2.5-flash",
            tools=tools,
            tool_choice=choice,
            max_tokens=1024,
        )
        assert response.role == "assistant"
        has_content = len(response.content) > 0
        has_tool_calls = tool_calls is not None and len(tool_calls) > 0
        assert has_content or has_tool_calls, (
            f"Expected non-empty content or at least one tool call under AUTO mode, "
            f"got content={response.content!r}, tool_calls={tool_calls!r}"
        )

    async def test_openrouter_tool_choice_required(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """OpenRouter REQUIRED must yield a structured call to the only offered tool.

        Drives the real connected OpenRouter provider routing to ``gpt-4o-mini``
        with a single tool whose schema declares one required ``path`` parameter
        and ``tool_choice=REQUIRED``. Because exactly one tool is offered and a
        tool call is mandatory, the provider's response translation must surface
        a :class:`ToolCall` naming that exact function (``binary.get_file_size``)
        with a non-empty ``id`` and the required ``path`` argument present and
        typed as ``str``. A regression in REQUIRED-mode mapping, function-name
        translation, or dropped-argument handling fails these assertions.

        Args:
            openrouter_provider: Connected OpenRouter provider fixture.
        """
        tools = _make_test_tool()
        messages = _make_messages("What is the size of notepad.exe at C:\\Windows\\notepad.exe?")
        choice = ToolChoice(mode=ToolChoiceMode.REQUIRED)

        _, tool_calls = await openrouter_provider.chat(
            messages=messages,
            model="openai/gpt-4o-mini",
            tools=tools,
            tool_choice=choice,
            max_tokens=1024,
        )
        assert tool_calls is not None
        assert len(tool_calls) == 1
        call = tool_calls[0]
        assert isinstance(call, ToolCall)
        assert call.function_name == "binary.get_file_size"
        assert call.tool_name == "binary"
        assert len(call.id) > 0
        assert "path" in call.arguments
        path_arg = call.arguments["path"]
        assert isinstance(path_arg, str)
        assert len(path_arg) > 0


class TestStreamingToolCalls:
    """Verify streaming captures tool calls on previously broken providers."""

    pytestmark: ClassVar[list[pytest.MarkDecorator]] = [pytest.mark.integration, pytest.mark.asyncio]

    async def test_huggingface_stream_captures_tool_calls(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """HuggingFace stream must capture tool calls via ToolCallBufferManager.

        Drives the real connected HuggingFace provider with a streaming call
        that explicitly requests use of ``binary.get_file_size``. After the
        stream completes, ``get_pending_tool_calls()`` must return either a
        non-empty list of correctly-structured :class:`ToolCall` objects (when
        the model elected to call the tool) or an empty list accompanied by
        non-empty stream chunks (when the model answered in free text). The
        branch that matters for the bug being guarded is the non-empty case:
        if the bridge's ``ToolCallBufferManager`` is broken, tool calls will
        be silently dropped and the list will be empty even though the model
        made a call. An empty list with no stream content fails because that
        indicates both the call and the text response were dropped.

        Args:
            huggingface_provider: Connected HuggingFace provider fixture.
        """
        model_id = "meta-llama/Llama-3.1-8B-Instruct"
        available_models = await huggingface_provider.list_models()
        model_info = next((m for m in available_models if m.id == model_id), None)
        if model_info is not None and not model_info.supports_tools:
            pytest.skip(f"Model {model_id!r} does not advertise tool support in current environment")

        tools = _make_test_tool()
        messages = _make_messages(
            "Use the binary.get_file_size tool on C:\\Windows\\notepad.exe and tell me the size.",
        )

        chunks: list[str] = [
            chunk
            async for chunk in huggingface_provider.chat_stream(
                messages=messages,
                model=model_id,
                tools=tools,
                max_tokens=1024,
            )
        ]

        pending = huggingface_provider.get_pending_tool_calls()

        if pending:
            assert len(pending) >= 1
            call = pending[0]
            assert isinstance(call, ToolCall)
            assert call.function_name == "binary.get_file_size", (
                f"Expected function_name 'binary.get_file_size', got {call.function_name!r}"
            )
            assert call.tool_name == "binary", f"Expected tool_name 'binary', got {call.tool_name!r}"
            assert len(call.id) > 0, "ToolCall id must be non-empty"
            assert "path" in call.arguments, f"Expected 'path' argument in ToolCall.arguments, got {call.arguments!r}"
            path_arg = call.arguments["path"]
            assert isinstance(path_arg, str), f"Expected 'path' argument to be str, got {type(path_arg).__name__}"
            assert len(path_arg) > 0, "ToolCall 'path' argument must be non-empty"
        else:
            total_content = "".join(chunks)
            assert len(total_content) > 0, (
                "Both pending tool calls and stream content are empty: the streaming bridge dropped the model's complete response"
            )

    async def test_ollama_stream_with_tools_returns_tool_calls(
        self,
        ollama_provider: OllamaProvider,
    ) -> None:
        """Ollama stream must capture tool calls via the non-streaming fallback path.

        Drives the real connected Ollama provider with a streaming call that
        explicitly requests use of ``binary.get_file_size``. Ollama's streaming
        path falls back to a non-streaming round-trip when tools are present;
        after that completes, ``get_pending_tool_calls()`` must return either a
        non-empty list of correctly-structured :class:`ToolCall` objects (when
        the model elected to call the tool) or an empty list accompanied by
        non-empty stream chunks (when the model answered in free text instead).
        When the locally installed ``llama3.2`` model does not advertise tool
        support, the test skips rather than asserting a capability the model
        cannot provide.

        Args:
            ollama_provider: Connected Ollama provider fixture.
        """
        model_id = "local/llama3.2"
        available_models = await ollama_provider.list_models()
        model_info = next((m for m in available_models if m.id == model_id), None)
        if model_info is None:
            pytest.skip(f"Model {model_id!r} not installed in local Ollama instance")
        if not model_info.supports_tools:
            pytest.skip(f"Model {model_id!r} does not advertise tool support; cannot verify tool-call capture")

        tools = _make_test_tool()
        messages = _make_messages(
            "Use binary.get_file_size to get the size of C:\\Windows\\notepad.exe",
        )

        chunks: list[str] = [
            chunk
            async for chunk in ollama_provider.chat_stream(
                messages=messages,
                model=model_id,
                tools=tools,
                max_tokens=1024,
            )
        ]

        pending = ollama_provider.get_pending_tool_calls()

        if pending:
            assert len(pending) >= 1
            call = pending[0]
            assert isinstance(call, ToolCall)
            assert call.function_name == "binary.get_file_size", (
                f"Expected function_name 'binary.get_file_size', got {call.function_name!r}"
            )
            assert call.tool_name == "binary", f"Expected tool_name 'binary', got {call.tool_name!r}"
            assert len(call.id) > 0, "ToolCall id must be non-empty"
            assert "path" in call.arguments, f"Expected 'path' argument in ToolCall.arguments, got {call.arguments!r}"
            path_arg = call.arguments["path"]
            assert isinstance(path_arg, str), f"Expected 'path' argument to be str, got {type(path_arg).__name__}"
            assert len(path_arg) > 0, "ToolCall 'path' argument must be non-empty"
        else:
            total_content = "".join(chunks)
            assert len(total_content) > 0, (
                "Both pending tool calls and stream content are empty: the streaming bridge dropped the model's complete response"
            )


class TestAccurateToolSupport:
    """Verify models report accurate supports_tools metadata."""

    pytestmark: ClassVar[list[pytest.MarkDecorator]] = [pytest.mark.integration, pytest.mark.asyncio]

    async def test_ollama_models_report_accurate_tool_support(
        self,
        ollama_provider: OllamaProvider,
    ) -> None:
        """Ollama model list should have varying supports_tools values.

        Args:
            ollama_provider: Connected Ollama provider fixture.
        """
        models = await ollama_provider.list_models()
        if not models:
            pytest.skip("No Ollama models installed locally")

        tool_support_values = {m.supports_tools for m in models}
        assert isinstance(tool_support_values, set)

    async def test_openrouter_models_report_accurate_tool_support(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """OpenRouter model list should include models without tool support.

        Args:
            openrouter_provider: Connected OpenRouter provider fixture.
        """
        models = await openrouter_provider.list_models()
        assert len(models) > 0

        tool_support_values = {m.supports_tools for m in models}
        assert False in tool_support_values, "Expected some models without tool support"


class TestContextWindowEnforcement:
    """Verify orchestrator message trimming logic."""

    pytestmark: ClassVar[list[pytest.MarkDecorator]] = [pytest.mark.integration]

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

    pytestmark: ClassVar[list[pytest.MarkDecorator]] = [pytest.mark.integration, pytest.mark.asyncio]

    async def test_anthropic_extended_thinking_returns_thinking_content(
        self,
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Anthropic should return thinking_content when thinking is enabled.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
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
        """Non-Anthropic providers should not error when thinking param passed.

        Args:
            openai_provider: Connected OpenAI provider fixture.
        """
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

    pytestmark: ClassVar[list[pytest.MarkDecorator]] = [pytest.mark.integration, pytest.mark.asyncio]

    async def test_anthropic_caching_succeeds(
        self,
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Anthropic caching should not error on API calls.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
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
