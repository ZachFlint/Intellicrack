# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Integration tests for LLM provider agentic capabilities.

Tests tool_choice, streaming tool calls, context window enforcement,
extended thinking, and prompt caching across all providers.
"""

from __future__ import annotations

import json
import re
import socket
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, ClassVar

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
from intellicrack.providers.base import ToolCallBufferManager
from intellicrack.providers.ollama import OllamaProvider


if TYPE_CHECKING:
    from collections.abc import Callable

    from intellicrack.providers.anthropic import AnthropicProvider
    from intellicrack.providers.google import GoogleProvider
    from intellicrack.providers.grok import GrokProvider
    from intellicrack.providers.openai import OpenAIProvider
    from intellicrack.providers.openrouter import OpenRouterProvider

    AccumulateDeltas = Callable[[dict[str, Any], dict[str, dict[str, Any]], list[str]], None]
    FinalizeNativeToolCalls = Callable[[dict[str, dict[str, Any]], list[str]], list[ToolCall]]


pytestmark = [pytest.mark.integration]

_GOOGLE_API_HOST = "generativelanguage.googleapis.com"
_GOOGLE_API_PORT = 443
_NETWORK_PROBE_TIMEOUT = 3.0


def _is_google_api_reachable() -> bool:
    """Probe TCP connectivity to the Google Generative Language API endpoint.

    Attempts a non-blocking TCP connection to ``generativelanguage.googleapis.com:443``
    with a short timeout. Returns ``False`` when the sandbox network is absent
    (``network='none'``) or when DNS resolution fails (getaddrinfo error), so
    tests that require a live Google API connection can be skipped rather than
    erroring during fixture setup.

    Returns:
        bool: ``True`` if the endpoint is reachable, ``False`` otherwise.
    """
    try:
        with socket.create_connection((_GOOGLE_API_HOST, _GOOGLE_API_PORT), timeout=_NETWORK_PROBE_TIMEOUT):
            return True
    except OSError:
        return False


_google_api_reachable: bool = _is_google_api_reachable()

_skip_google_offline = pytest.mark.skipif(
    not _google_api_reachable,
    reason="Google API endpoint unreachable (network='none' or offline); live Google provider test skipped",
)


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

    @_skip_google_offline
    async def test_google_tool_choice_required_forces_tool_call(
        self,
        google_provider: GoogleProvider,
    ) -> None:
        """Google REQUIRED must yield a structured call to the only offered tool.

        Drives the real connected Google provider with a single tool whose
        schema declares one required ``path`` parameter and
        ``tool_choice=REQUIRED``. The bridge maps REQUIRED to Gemini's
        ``FunctionCallingConfigMode.ANY``, which compels a function call;
        because exactly one tool is offered, the response translation must
        surface a :class:`ToolCall` naming that exact function
        (``binary.get_file_size``), with ``tool_name`` derived from the
        function-name prefix (``binary``), a non-empty ``id``, and the required
        ``path`` argument present and typed as ``str``. A regression that
        dropped the REQUIRED-to-ANY mapping (letting the model answer in free
        text), mistranslated the function name, or dropped arguments fails
        these assertions.

        Args:
            google_provider: Connected Google provider fixture.
        """
        tools = _make_test_tool()
        messages = _make_messages("What is the size of notepad.exe at C:\\Windows\\notepad.exe?")
        choice = ToolChoice(mode=ToolChoiceMode.REQUIRED)

        _, tool_calls = await google_provider.chat(
            messages=messages,
            model="gemini-2.5-flash",
            tools=tools,
            tool_choice=choice,
            max_tokens=1024,
        )
        assert tool_calls is not None
        assert len(tool_calls) >= 1
        call = tool_calls[0]
        assert isinstance(call, ToolCall)
        assert call.function_name == "binary.get_file_size"
        assert call.tool_name == "binary"
        assert len(call.id) > 0
        assert "path" in call.arguments
        path_arg = call.arguments["path"]
        assert isinstance(path_arg, str)
        assert len(path_arg) > 0

    @_skip_google_offline
    async def test_google_tool_choice_none_prevents_tool_call(
        self,
        google_provider: GoogleProvider,
    ) -> None:
        """Google NONE must answer in free text and emit no tool calls.

        Drives the real connected Google provider with a single tool and
        ``tool_choice=NONE``, which the bridge maps to Gemini's
        ``FunctionCallingConfigMode.NONE``. With function calling disabled the
        model must answer the deterministic arithmetic prompt in plain text:
        the assistant message must carry role ``"assistant"`` with non-empty
        content, and ``tool_calls`` must be ``None``. A regression that dropped
        the NONE-mode mapping (allowing a spurious tool call) or returned an
        empty response fails these assertions.

        Args:
            google_provider: Connected Google provider fixture.
        """
        tools = _make_test_tool()
        messages = _make_messages("What is 2 plus 2? Answer with the number only.")
        choice = ToolChoice(mode=ToolChoiceMode.NONE)

        response, tool_calls = await google_provider.chat(
            messages=messages,
            model="gemini-2.5-flash",
            tools=tools,
            tool_choice=choice,
            max_tokens=1024,
        )
        assert response.role == "assistant"
        assert len(response.content) > 0
        assert tool_calls is None

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
    """Verify the streaming tool-call assemblers reconstruct fragmented deltas.

    These gates exercise the exact production units a provider's
    ``chat_stream`` uses to reassemble tool calls that arrive split across
    many stream chunks. They feed recorded, fragmented delta sequences (the
    shape real backends emit, where the function name and JSON argument text
    are split across frames) through the real assembler and assert the
    finalised :class:`ToolCall` exactly matches a hand-decoded oracle. This
    is the regression these tests were named to guard: a buffer manager that
    fails to concatenate argument fragments or drops the tool call silently
    yields the wrong, or no, ToolCall.
    """

    pytestmark: ClassVar[list[pytest.MarkDecorator]] = [pytest.mark.integration]

    def test_huggingface_buffer_manager_assembles_fragmented_tool_call(self) -> None:
        """ToolCallBufferManager must reassemble a split OpenAI-style tool call.

        Replays the per-chunk deltas that
        :meth:`HuggingFaceProvider._consume_stream_chunks` forwards into
        :class:`ToolCallBufferManager` for a real HuggingFace SSE tool-call
        stream: the ``id`` and function ``name`` arrive on the first frame,
        and the JSON ``arguments`` string is split across four subsequent
        frames. The independent oracle is the hand-assembled argument JSON
        decoded by ``json.loads`` from the concatenated fragments; after
        ``finalize()`` the single :class:`ToolCall` must carry that exact ``id``,
        ``function_name`` (``binary.get_file_size``), prefix-derived
        ``tool_name`` (``binary``), and the parsed ``path`` argument. A
        regression in delta concatenation (dropping or reordering argument
        fragments) or in id/name capture diverges from the oracle and fails.
        """
        buffer = ToolCallBufferManager()
        arg_fragments = ['{"path": "C:', "\\\\Windows", "\\\\notepad", '.exe"}']
        buffer.accumulate(index=0, call_id="call_hf_001", name="binary.get_file_size", arguments=None)
        for fragment in arg_fragments:
            buffer.accumulate(index=0, call_id=None, name=None, arguments=fragment)

        finalized = buffer.finalize()

        expected_arguments: dict[str, str] = json.loads("".join(arg_fragments))
        assert len(finalized) == 1
        call = finalized[0]
        assert isinstance(call, ToolCall)
        assert call.id == "call_hf_001"
        assert call.function_name == "binary.get_file_size"
        assert call.tool_name == "binary"
        assert call.arguments == expected_arguments
        assert call.arguments["path"] == "C:\\Windows\\notepad.exe"
        assert not buffer.finalize()

    def test_ollama_native_stream_assembler_reconstructs_tool_call(self) -> None:
        """Ollama native stream assembler must merge fragmented tool-call deltas.

        Replays the ``message`` dicts that the local NDJSON ``/api/chat``
        stream emits, feeding each through
        :meth:`OllamaProvider._accumulate_native_tool_call_deltas` exactly as
        :meth:`OllamaProvider._iter_native_stream_chunks` does, then finalises
        with :meth:`OllamaProvider._finalize_native_tool_calls`. The function
        name lands on the first delta and the JSON ``arguments`` string is
        split across later deltas. The independent oracle is the JSON decoded
        by ``json.loads`` from the concatenated fragments; the single
        reconstructed :class:`ToolCall` must carry that exact
        ``function_name`` (``binary.get_file_size``), prefix-derived
        ``tool_name`` (``binary``), and parsed ``path`` argument. A regression
        that stops concatenating argument fragments or loses the call diverges
        from the oracle and fails.
        """
        provider = OllamaProvider()
        accumulate: AccumulateDeltas = getattr(provider, "_accumulate_native_tool_call_deltas")
        finalize: FinalizeNativeToolCalls = getattr(provider, "_finalize_native_tool_calls")

        accumulated: dict[str, dict[str, Any]] = {}
        order: list[str] = []
        arg_fragments = ['{"path": "C:', "\\\\Windows\\\\", "notepad.exe", '"}']
        deltas: list[dict[str, Any]] = [
            {"tool_calls": [{"id": "call_ollama_0", "function": {"name": "binary.get_file_size", "arguments": ""}}]},
            *[{"tool_calls": [{"id": "call_ollama_0", "function": {"arguments": fragment}}]} for fragment in arg_fragments],
        ]
        for message_obj in deltas:
            accumulate(message_obj, accumulated, order)

        finalized = finalize(accumulated, order)

        expected_arguments: dict[str, str] = json.loads("".join(arg_fragments))
        assert len(finalized) == 1
        call = finalized[0]
        assert isinstance(call, ToolCall)
        assert call.id == "call_ollama_0"
        assert call.function_name == "binary.get_file_size"
        assert call.tool_name == "binary"
        assert call.arguments == expected_arguments
        assert call.arguments["path"] == "C:\\Windows\\notepad.exe"


class TestAccurateToolSupport:
    """Verify models report accurate supports_tools metadata."""

    pytestmark: ClassVar[list[pytest.MarkDecorator]] = [pytest.mark.integration, pytest.mark.asyncio]

    async def test_ollama_models_report_accurate_tool_support(
        self,
        ollama_provider: OllamaProvider,
    ) -> None:
        """Ollama ``supports_tools`` must match the model's own template directive.

        The Ollama bridge derives ``supports_tools`` for each local model by
        querying ``/api/show`` and searching the model's chat template for the
        ``{{ .Tools }}`` directive (a model only honours tool definitions when
        its template renders them). This test independently re-derives the
        expected flag for every installed model: it fetches the same
        ``/api/show`` payload via :meth:`OllamaProvider.show_model` and applies
        the template-directive contract itself, then asserts the bridge's
        ``supports_tools`` equals that independent value. A bridge that
        hardcoded ``supports_tools`` (all-True, all-False, or a constant) or
        broke the template detection would diverge from the recomputed oracle
        and fail.

        Args:
            ollama_provider: Connected Ollama provider fixture.
        """
        models = await ollama_provider.list_models()
        if not models:
            pytest.skip("No Ollama models installed locally")

        tools_directive = re.compile(r"\{\{-?\s*\.Tools\s*-?\}\}")
        checked_local = False
        for model in models:
            if not model.id.startswith("local/"):
                continue
            checked_local = True
            show = await ollama_provider.show_model(model.id)
            template = show.get("template", "")
            expected_supports_tools = tools_directive.search(template) is not None
            assert model.supports_tools == expected_supports_tools, (
                f"Model {model.id!r} reported supports_tools={model.supports_tools} "
                f"but its /api/show template {'contains' if expected_supports_tools else 'lacks'} "
                f"the .Tools directive (expected supports_tools={expected_supports_tools})"
            )

        if not checked_local:
            pytest.skip("No local Ollama models installed to verify tool-support derivation")

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
