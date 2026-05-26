# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""End-to-end chat tests for all 7 cloud/API providers and cross-provider consistency.

Validates that every provider can send messages, receive real responses,
stream output, handle tool calling, maintain multi-turn context, respect
max_tokens, and list models with valid fields. Also tests cross-provider
consistency and error handling.
"""

from __future__ import annotations

import shutil
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import httpx
import pytest
import pytest_asyncio

from intellicrack.core.subprocess_compat import DEVNULL, Popen
from intellicrack.core.types import (
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    ProviderName,
    ToolCall,
    ToolDefinition,
    ToolFunction,
    ToolName,
    ToolParameter,
)
from intellicrack.providers.anthropic import AnthropicProvider
from intellicrack.providers.google import GoogleProvider
from intellicrack.providers.grok import GrokProvider
from intellicrack.providers.huggingface import HuggingFaceProvider
from intellicrack.providers.ollama import OllamaProvider
from intellicrack.providers.openai import OpenAIProvider
from intellicrack.providers.openrouter import OpenRouterProvider


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Generator

    from intellicrack.credentials.env_loader import CredentialLoader
    from intellicrack.providers.base import LLMProviderBase

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

ANTHROPIC_MODEL = "claude-haiku-4-20250414"
OPENAI_MODEL = "gpt-4o-mini"
GOOGLE_MODEL = "gemini-2.0-flash-lite"
GROK_MODEL = "grok-3-mini"
OPENROUTER_MODEL = "openai/gpt-4o-mini"
HUGGINGFACE_MODEL = "katanemo/Arch-Router-1.5B"

_OLLAMA_URL = "http://localhost:11434"
_OLLAMA_TAGS_URL = f"{_OLLAMA_URL}/api/tags"
_OLLAMA_STARTUP_TIMEOUT = 30
_OLLAMA_POLL_INTERVAL = 1.0
_HTTP_OK = 200
_MAX_TOKENS_SHORT = 32


def _make_messages(prompt: str) -> list[Message]:
    """Build a single user message list for testing.

    Args:
        prompt: The user message text.

    Returns:
        list[Message]: A list containing a single user Message.
    """
    return [Message(role="user", content=prompt, timestamp=datetime.now(tz=UTC))]


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


def _make_multi_turn_messages() -> list[Message]:
    """Build a multi-turn conversation for context retention testing.

    Returns:
        list[Message]: Messages with system, user, fake assistant, and followup.
    """
    return [
        Message(
            role="system",
            content="You are a helpful binary analysis assistant.",
            timestamp=datetime.now(tz=UTC),
        ),
        Message(
            role="user",
            content="My name is Archimedes and I work on binary analysis.",
            timestamp=datetime.now(tz=UTC),
        ),
        Message(
            role="assistant",
            content="Hello Archimedes! Nice to meet you. I'm ready to help with binary analysis.",
            timestamp=datetime.now(tz=UTC),
        ),
        Message(
            role="user",
            content="What is my name and what do I work on?",
            timestamp=datetime.now(tz=UTC),
        ),
    ]


@pytest.fixture(scope="session")
def ollama_server() -> Generator[Popen[bytes] | None]:
    """Start an Ollama server subprocess for testing.

    Starts ``ollama serve`` and polls the health endpoint until the
    server responds. Skips if the ``ollama`` binary is not on PATH.
    Kills the server on teardown.

    Yields:
        Generator[Popen[bytes] | None]: The Ollama server process, or None if already running.
    """
    try:
        response = httpx.get(_OLLAMA_TAGS_URL, timeout=2.0)
        if response.status_code == _HTTP_OK:
            yield None
            return
    except (OSError, httpx.HTTPError):
        pass

    ollama_path = shutil.which("ollama")
    if ollama_path is None:
        pytest.skip("ollama binary not found on PATH")

    proc = Popen(
        [ollama_path, "serve"],
        stdout=DEVNULL,
        stderr=DEVNULL,
    )

    deadline = time.monotonic() + _OLLAMA_STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(_OLLAMA_TAGS_URL, timeout=2.0)
            if resp.status_code == _HTTP_OK:
                break
        except (OSError, httpx.HTTPError):
            pass
        time.sleep(_OLLAMA_POLL_INTERVAL)
    else:
        proc.kill()
        pytest.skip("Ollama server failed to start within timeout")

    yield proc
    proc.kill()
    proc.wait()


@pytest_asyncio.fixture
async def ollama_e2e_provider(
    credential_loader: CredentialLoader,
    ollama_server: Popen[bytes] | None,
) -> AsyncGenerator[OllamaProvider]:
    """Create a connected Ollama provider backed by the test server.

    Args:
        credential_loader: The credential loader instance.
        ollama_server: The Ollama server process fixture.

    Yields:
        AsyncGenerator[OllamaProvider]: A connected OllamaProvider instance.
    """
    _ = ollama_server
    provider = OllamaProvider()
    credentials = credential_loader.get_credentials(ProviderName.OLLAMA)
    if credentials is None:
        credentials = ProviderCredentials(
            api_key=None,
            api_base=_OLLAMA_URL,
        )
    await provider.connect(credentials)
    yield provider
    await provider.disconnect()


@pytest_asyncio.fixture
async def ollama_model(
    ollama_e2e_provider: OllamaProvider,
) -> str:
    """Get the first available Ollama model for testing.

    Skips if no models are installed.

    Args:
        ollama_e2e_provider: A connected OllamaProvider instance.

    Returns:
        str: The model ID of the first available model.
    """
    models = await ollama_e2e_provider.list_models()
    if not models:
        pytest.skip("No Ollama models installed locally")
    return models[0].id


@pytest_asyncio.fixture
async def ollama_tool_model(
    ollama_e2e_provider: OllamaProvider,
) -> str:
    """Get the first Ollama model that supports tool calling.

    Skips if no models with tool support are installed.

    Args:
        ollama_e2e_provider: A connected OllamaProvider instance.

    Returns:
        str: The model ID of the first tool-capable model.
    """
    models = await ollama_e2e_provider.list_models()
    for model in models:
        if model.supports_tools:
            return model.id
    pytest.skip("No Ollama models with tool support installed")


class TestAnthropicE2EChat:
    """End-to-end chat tests for the Anthropic provider."""

    async def test_chat_returns_valid_assistant_message(
        self,
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Chat should return a valid assistant message with non-empty content.

        Args:
            anthropic_provider: A connected AnthropicProvider instance.
        """
        messages = _make_messages("Respond with one word: hello")
        response, _ = await anthropic_provider.chat(
            messages=messages,
            model=ANTHROPIC_MODEL,
            max_tokens=64,
        )
        assert response.role == "assistant"
        assert len(response.content) > 0

    async def test_chat_stream_yields_chunks_and_completes(
        self,
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Streaming should yield at least one chunk that assembles into text.

        Args:
            anthropic_provider: A connected AnthropicProvider instance.
        """
        messages = _make_messages("Say hello briefly.")
        chunks: list[str] = [
            chunk
            async for chunk in anthropic_provider.chat_stream(
                messages=messages,
                model=ANTHROPIC_MODEL,
                max_tokens=64,
            )
        ]

        assert len(chunks) >= 1
        full_text = "".join(chunks).strip()
        assert len(full_text) > 0

    async def test_tool_calling_returns_valid_tool_call(
        self,
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Tool calling should return a ToolCall with correct structure.

        Args:
            anthropic_provider: A connected AnthropicProvider instance.
        """
        tools = _make_test_tool()
        messages = _make_messages(
            "Use the binary.get_file_size tool to check the size of C:\\Windows\\notepad.exe",
        )
        _, tool_calls = await anthropic_provider.chat(
            messages=messages,
            model=ANTHROPIC_MODEL,
            tools=tools,
            max_tokens=256,
        )
        assert tool_calls is not None
        assert len(tool_calls) > 0
        assert isinstance(tool_calls[0], ToolCall)
        assert tool_calls[0].function_name == "binary.get_file_size"
        assert "path" in tool_calls[0].arguments

    async def test_multi_turn_conversation_retains_context(
        self,
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Multi-turn conversation should reference information from prior messages.

        Args:
            anthropic_provider: A connected AnthropicProvider instance.
        """
        messages = _make_multi_turn_messages()
        response, _ = await anthropic_provider.chat(
            messages=messages,
            model=ANTHROPIC_MODEL,
            max_tokens=128,
        )
        content_lower = response.content.lower()
        assert "archimedes" in content_lower or "binary" in content_lower

    async def test_max_tokens_respected(
        self,
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Response with max_tokens=32 should be short.

        Args:
            anthropic_provider: A connected AnthropicProvider instance.
        """
        messages = _make_messages("Write a very long essay about the history of computing.")
        response, _ = await anthropic_provider.chat(
            messages=messages,
            model=ANTHROPIC_MODEL,
            max_tokens=_MAX_TOKENS_SHORT,
        )
        words = response.content.split()
        assert len(words) < 100

    async def test_model_listing_fields_valid(
        self,
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Model listing should return ModelInfo objects with correct types.

        Args:
            anthropic_provider: A connected AnthropicProvider instance.
        """
        models = await anthropic_provider.list_models()
        assert len(models) > 0
        for model in models:
            assert isinstance(model, ModelInfo)
            assert isinstance(model.id, str)
            assert len(model.id) > 0
            assert isinstance(model.name, str)
            assert model.provider == ProviderName.ANTHROPIC
            assert isinstance(model.context_window, int)
            assert model.context_window > 0
            assert isinstance(model.supports_tools, bool)
            assert isinstance(model.supports_streaming, bool)


class TestOpenAIE2EChat:
    """End-to-end chat tests for the OpenAI provider."""

    async def test_chat_returns_valid_assistant_message(
        self,
        openai_provider: OpenAIProvider,
    ) -> None:
        """Chat should return a valid assistant message with non-empty content.

        Args:
            openai_provider: A connected OpenAIProvider instance.
        """
        messages = _make_messages("Respond with one word: hello")
        response, _ = await openai_provider.chat(
            messages=messages,
            model=OPENAI_MODEL,
            max_tokens=64,
        )
        assert response.role == "assistant"
        assert len(response.content) > 0

    async def test_chat_stream_yields_chunks_and_completes(
        self,
        openai_provider: OpenAIProvider,
    ) -> None:
        """Streaming should yield at least one chunk that assembles into text.

        Args:
            openai_provider: A connected OpenAIProvider instance.
        """
        messages = _make_messages("Say hello briefly.")
        chunks: list[str] = [
            chunk
            async for chunk in openai_provider.chat_stream(
                messages=messages,
                model=OPENAI_MODEL,
                max_tokens=64,
            )
        ]

        assert len(chunks) >= 1
        full_text = "".join(chunks).strip()
        assert len(full_text) > 0

    async def test_tool_calling_returns_valid_tool_call(
        self,
        openai_provider: OpenAIProvider,
    ) -> None:
        """Tool calling should return a ToolCall with correct structure.

        Args:
            openai_provider: A connected OpenAIProvider instance.
        """
        tools = _make_test_tool()
        messages = _make_messages(
            "Use the binary.get_file_size tool to check the size of C:\\Windows\\notepad.exe",
        )
        _, tool_calls = await openai_provider.chat(
            messages=messages,
            model=OPENAI_MODEL,
            tools=tools,
            max_tokens=256,
        )
        assert tool_calls is not None
        assert len(tool_calls) > 0
        assert isinstance(tool_calls[0], ToolCall)
        assert tool_calls[0].function_name == "binary.get_file_size"
        assert "path" in tool_calls[0].arguments

    async def test_multi_turn_conversation_retains_context(
        self,
        openai_provider: OpenAIProvider,
    ) -> None:
        """Multi-turn conversation should reference information from prior messages.

        Args:
            openai_provider: A connected OpenAIProvider instance.
        """
        messages = _make_multi_turn_messages()
        response, _ = await openai_provider.chat(
            messages=messages,
            model=OPENAI_MODEL,
            max_tokens=128,
        )
        content_lower = response.content.lower()
        assert "archimedes" in content_lower or "binary" in content_lower

    async def test_max_tokens_respected(
        self,
        openai_provider: OpenAIProvider,
    ) -> None:
        """Response with max_tokens=32 should be short.

        Args:
            openai_provider: A connected OpenAIProvider instance.
        """
        messages = _make_messages("Write a very long essay about the history of computing.")
        response, _ = await openai_provider.chat(
            messages=messages,
            model=OPENAI_MODEL,
            max_tokens=_MAX_TOKENS_SHORT,
        )
        words = response.content.split()
        assert len(words) < 100

    async def test_model_listing_fields_valid(
        self,
        openai_provider: OpenAIProvider,
    ) -> None:
        """Model listing should return ModelInfo objects with correct types.

        Args:
            openai_provider: A connected OpenAIProvider instance.
        """
        models = await openai_provider.list_models()
        assert len(models) > 0
        for model in models:
            assert isinstance(model, ModelInfo)
            assert isinstance(model.id, str)
            assert len(model.id) > 0
            assert model.provider == ProviderName.OPENAI


class TestGoogleE2EChat:
    """End-to-end chat tests for the Google provider."""

    async def test_chat_returns_valid_assistant_message(
        self,
        google_provider: GoogleProvider,
    ) -> None:
        """Chat should return a valid assistant message with non-empty content.

        Args:
            google_provider: A connected GoogleProvider instance.
        """
        messages = _make_messages("Respond with one word: hello")
        response, _ = await google_provider.chat(
            messages=messages,
            model=GOOGLE_MODEL,
            max_tokens=64,
        )
        assert response.role == "assistant"
        assert len(response.content) > 0

    async def test_chat_stream_yields_chunks_and_completes(
        self,
        google_provider: GoogleProvider,
    ) -> None:
        """Streaming should yield at least one chunk that assembles into text.

        Args:
            google_provider: A connected GoogleProvider instance.
        """
        messages = _make_messages("Say hello briefly.")
        chunks: list[str] = [
            chunk
            async for chunk in google_provider.chat_stream(
                messages=messages,
                model=GOOGLE_MODEL,
                max_tokens=64,
            )
        ]

        assert len(chunks) >= 1
        full_text = "".join(chunks).strip()
        assert len(full_text) > 0

    async def test_tool_calling_returns_valid_tool_call(
        self,
        google_provider: GoogleProvider,
    ) -> None:
        """Tool calling should return a ToolCall with correct structure.

        Args:
            google_provider: A connected GoogleProvider instance.
        """
        tools = _make_test_tool()
        messages = _make_messages(
            "Use the binary.get_file_size tool to check the size of C:\\Windows\\notepad.exe",
        )
        _, tool_calls = await google_provider.chat(
            messages=messages,
            model=GOOGLE_MODEL,
            tools=tools,
            max_tokens=256,
        )
        assert tool_calls is not None
        assert len(tool_calls) > 0
        assert isinstance(tool_calls[0], ToolCall)
        assert tool_calls[0].function_name == "binary.get_file_size"
        assert "path" in tool_calls[0].arguments

    async def test_multi_turn_conversation_retains_context(
        self,
        google_provider: GoogleProvider,
    ) -> None:
        """Multi-turn conversation should reference information from prior messages.

        Args:
            google_provider: A connected GoogleProvider instance.
        """
        messages = _make_multi_turn_messages()
        response, _ = await google_provider.chat(
            messages=messages,
            model=GOOGLE_MODEL,
            max_tokens=128,
        )
        content_lower = response.content.lower()
        assert "archimedes" in content_lower or "binary" in content_lower

    async def test_max_tokens_respected(
        self,
        google_provider: GoogleProvider,
    ) -> None:
        """Response with max_tokens=32 should be short.

        Args:
            google_provider: A connected GoogleProvider instance.
        """
        messages = _make_messages("Write a very long essay about the history of computing.")
        response, _ = await google_provider.chat(
            messages=messages,
            model=GOOGLE_MODEL,
            max_tokens=_MAX_TOKENS_SHORT,
        )
        words = response.content.split()
        assert len(words) < 100

    async def test_model_listing_fields_valid(
        self,
        google_provider: GoogleProvider,
    ) -> None:
        """Model listing should return ModelInfo objects with correct types.

        Args:
            google_provider: A connected GoogleProvider instance.
        """
        models = await google_provider.list_models()
        assert len(models) > 0
        for model in models:
            assert isinstance(model, ModelInfo)
            assert isinstance(model.id, str)
            assert len(model.id) > 0
            assert model.provider == ProviderName.GOOGLE


class TestGrokE2EChat:
    """End-to-end chat tests for the Grok provider."""

    async def test_chat_returns_valid_assistant_message(
        self,
        grok_provider: GrokProvider,
    ) -> None:
        """Chat should return a valid assistant message with non-empty content.

        Args:
            grok_provider: A connected GrokProvider instance.
        """
        messages = _make_messages("Respond with one word: hello")
        response, _ = await grok_provider.chat(
            messages=messages,
            model=GROK_MODEL,
            max_tokens=64,
        )
        assert response.role == "assistant"
        assert len(response.content) > 0

    async def test_chat_stream_yields_chunks_and_completes(
        self,
        grok_provider: GrokProvider,
    ) -> None:
        """Streaming should yield at least one chunk that assembles into text.

        Args:
            grok_provider: A connected GrokProvider instance.
        """
        messages = _make_messages("Say hello briefly.")
        chunks: list[str] = [
            chunk
            async for chunk in grok_provider.chat_stream(
                messages=messages,
                model=GROK_MODEL,
                max_tokens=64,
            )
        ]

        assert len(chunks) >= 1
        full_text = "".join(chunks).strip()
        assert len(full_text) > 0

    async def test_tool_calling_returns_valid_tool_call(
        self,
        grok_provider: GrokProvider,
    ) -> None:
        """Tool calling should return a ToolCall with correct structure.

        Args:
            grok_provider: A connected GrokProvider instance.
        """
        tools = _make_test_tool()
        messages = _make_messages(
            "Use the binary.get_file_size tool to check the size of C:\\Windows\\notepad.exe",
        )
        _, tool_calls = await grok_provider.chat(
            messages=messages,
            model=GROK_MODEL,
            tools=tools,
            max_tokens=256,
        )
        assert tool_calls is not None
        assert len(tool_calls) > 0
        assert isinstance(tool_calls[0], ToolCall)
        assert tool_calls[0].function_name == "binary.get_file_size"
        assert "path" in tool_calls[0].arguments

    async def test_multi_turn_conversation_retains_context(
        self,
        grok_provider: GrokProvider,
    ) -> None:
        """Multi-turn conversation should reference information from prior messages.

        Args:
            grok_provider: A connected GrokProvider instance.
        """
        messages = _make_multi_turn_messages()
        response, _ = await grok_provider.chat(
            messages=messages,
            model=GROK_MODEL,
            max_tokens=128,
        )
        content_lower = response.content.lower()
        assert "archimedes" in content_lower or "binary" in content_lower

    async def test_max_tokens_respected(
        self,
        grok_provider: GrokProvider,
    ) -> None:
        """Response with max_tokens=32 should be short.

        Args:
            grok_provider: A connected GrokProvider instance.
        """
        messages = _make_messages("Write a very long essay about the history of computing.")
        response, _ = await grok_provider.chat(
            messages=messages,
            model=GROK_MODEL,
            max_tokens=_MAX_TOKENS_SHORT,
        )
        words = response.content.split()
        assert len(words) < 100

    async def test_model_listing_fields_valid(
        self,
        grok_provider: GrokProvider,
    ) -> None:
        """Model listing should return ModelInfo objects with correct types.

        Args:
            grok_provider: A connected GrokProvider instance.
        """
        models = await grok_provider.list_models()
        assert len(models) > 0
        for model in models:
            assert isinstance(model, ModelInfo)
            assert isinstance(model.id, str)
            assert len(model.id) > 0
            assert model.provider == ProviderName.GROK


class TestOpenRouterE2EChat:
    """End-to-end chat tests for the OpenRouter provider."""

    async def test_chat_returns_valid_assistant_message(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Chat should return a valid assistant message with non-empty content.

        Args:
            openrouter_provider: A connected OpenRouterProvider instance.
        """
        messages = _make_messages("Respond with one word: hello")
        response, _ = await openrouter_provider.chat(
            messages=messages,
            model=OPENROUTER_MODEL,
            max_tokens=64,
        )
        assert response.role == "assistant"
        assert len(response.content) > 0

    async def test_chat_stream_yields_chunks_and_completes(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Streaming should yield at least one chunk that assembles into text.

        Args:
            openrouter_provider: A connected OpenRouterProvider instance.
        """
        messages = _make_messages("Say hello briefly.")
        chunks: list[str] = [
            chunk
            async for chunk in openrouter_provider.chat_stream(
                messages=messages,
                model=OPENROUTER_MODEL,
                max_tokens=64,
            )
        ]

        assert len(chunks) >= 1
        full_text = "".join(chunks).strip()
        assert len(full_text) > 0

    async def test_tool_calling_returns_valid_tool_call(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Tool calling should return a ToolCall with correct structure.

        Args:
            openrouter_provider: A connected OpenRouterProvider instance.
        """
        tools = _make_test_tool()
        messages = _make_messages(
            "Use the binary.get_file_size tool to check the size of C:\\Windows\\notepad.exe",
        )
        _, tool_calls = await openrouter_provider.chat(
            messages=messages,
            model=OPENROUTER_MODEL,
            tools=tools,
            max_tokens=256,
        )
        assert tool_calls is not None
        assert len(tool_calls) > 0
        assert isinstance(tool_calls[0], ToolCall)
        assert tool_calls[0].function_name == "binary.get_file_size"
        assert "path" in tool_calls[0].arguments

    async def test_multi_turn_conversation_retains_context(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Multi-turn conversation should reference information from prior messages.

        Args:
            openrouter_provider: A connected OpenRouterProvider instance.
        """
        messages = _make_multi_turn_messages()
        response, _ = await openrouter_provider.chat(
            messages=messages,
            model=OPENROUTER_MODEL,
            max_tokens=128,
        )
        content_lower = response.content.lower()
        assert "archimedes" in content_lower or "binary" in content_lower

    async def test_max_tokens_respected(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Response with max_tokens=32 should be short.

        Args:
            openrouter_provider: A connected OpenRouterProvider instance.
        """
        messages = _make_messages("Write a very long essay about the history of computing.")
        response, _ = await openrouter_provider.chat(
            messages=messages,
            model=OPENROUTER_MODEL,
            max_tokens=_MAX_TOKENS_SHORT,
        )
        words = response.content.split()
        assert len(words) < 100

    async def test_model_listing_fields_valid(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Model listing should return ModelInfo objects with correct types.

        Args:
            openrouter_provider: A connected OpenRouterProvider instance.
        """
        models = await openrouter_provider.list_models()
        assert len(models) > 0
        for model in models:
            assert isinstance(model, ModelInfo)
            assert isinstance(model.id, str)
            assert len(model.id) > 0
            assert model.provider == ProviderName.OPENROUTER


class TestHuggingFaceE2EChat:
    """End-to-end chat tests for the HuggingFace provider."""

    async def test_chat_returns_valid_assistant_message(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Chat should return a valid assistant message with non-empty content.

        Args:
            huggingface_provider: A connected HuggingFaceProvider instance.
        """
        messages = _make_messages("Respond with one word: hello")
        response, _ = await huggingface_provider.chat(
            messages=messages,
            model=HUGGINGFACE_MODEL,
            max_tokens=64,
        )
        assert response.role == "assistant"
        assert len(response.content) > 0

    async def test_chat_stream_yields_chunks_and_completes(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Streaming should yield at least one chunk that assembles into text.

        Args:
            huggingface_provider: A connected HuggingFaceProvider instance.
        """
        messages = _make_messages("Say hello briefly.")
        chunks: list[str] = [
            chunk
            async for chunk in huggingface_provider.chat_stream(
                messages=messages,
                model=HUGGINGFACE_MODEL,
                max_tokens=64,
            )
        ]

        assert len(chunks) >= 1
        full_text = "".join(chunks).strip()
        assert len(full_text) > 0

    @pytest.mark.xfail(reason="Open-source model tool calling is unreliable")
    async def test_tool_calling_returns_valid_tool_call(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Tool calling should return a ToolCall with correct structure.

        Args:
            huggingface_provider: A connected HuggingFaceProvider instance.
        """
        tools = _make_test_tool()
        messages = _make_messages(
            "Use the binary.get_file_size tool to check the size of C:\\Windows\\notepad.exe",
        )
        _, tool_calls = await huggingface_provider.chat(
            messages=messages,
            model=HUGGINGFACE_MODEL,
            tools=tools,
            max_tokens=256,
        )
        assert tool_calls is not None
        assert len(tool_calls) > 0
        assert isinstance(tool_calls[0], ToolCall)
        assert tool_calls[0].function_name == "binary.get_file_size"

    async def test_multi_turn_conversation_retains_context(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Multi-turn conversation should reference information from prior messages.

        Args:
            huggingface_provider: A connected HuggingFaceProvider instance.
        """
        messages = _make_multi_turn_messages()
        response, _ = await huggingface_provider.chat(
            messages=messages,
            model=HUGGINGFACE_MODEL,
            max_tokens=128,
        )
        content_lower = response.content.lower()
        assert "archimedes" in content_lower or "binary" in content_lower

    async def test_max_tokens_respected(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Response with max_tokens=32 should be short.

        Args:
            huggingface_provider: A connected HuggingFaceProvider instance.
        """
        messages = _make_messages("Write a very long essay about the history of computing.")
        response, _ = await huggingface_provider.chat(
            messages=messages,
            model=HUGGINGFACE_MODEL,
            max_tokens=_MAX_TOKENS_SHORT,
        )
        words = response.content.split()
        assert len(words) < 100

    async def test_model_listing_fields_valid(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Model listing should return ModelInfo objects with correct types.

        Args:
            huggingface_provider: A connected HuggingFaceProvider instance.
        """
        models = await huggingface_provider.list_models()
        assert len(models) > 0
        for model in models:
            assert isinstance(model, ModelInfo)
            assert isinstance(model.id, str)
            assert len(model.id) > 0
            assert model.provider == ProviderName.HUGGINGFACE


class TestOllamaE2EChat:
    """End-to-end chat tests for the Ollama provider."""

    async def test_chat_returns_valid_assistant_message(
        self,
        ollama_e2e_provider: OllamaProvider,
        ollama_model: str,
    ) -> None:
        """Chat should return a valid assistant message with non-empty content.

        Args:
            ollama_e2e_provider: A connected OllamaProvider instance.
            ollama_model: The first available Ollama model ID.
        """
        messages = _make_messages("Respond with one word: hello")
        response, _ = await ollama_e2e_provider.chat(
            messages=messages,
            model=ollama_model,
            max_tokens=64,
        )
        assert response.role == "assistant"
        assert len(response.content) > 0

    async def test_chat_stream_yields_chunks_and_completes(
        self,
        ollama_e2e_provider: OllamaProvider,
        ollama_model: str,
    ) -> None:
        """Streaming should yield at least one chunk that assembles into text.

        Args:
            ollama_e2e_provider: A connected OllamaProvider instance.
            ollama_model: The first available Ollama model ID.
        """
        messages = _make_messages("Say hello briefly.")
        chunks: list[str] = [
            chunk
            async for chunk in ollama_e2e_provider.chat_stream(
                messages=messages,
                model=ollama_model,
                max_tokens=64,
            )
        ]

        assert len(chunks) >= 1
        full_text = "".join(chunks).strip()
        assert len(full_text) > 0

    async def test_tool_calling_returns_valid_tool_call(
        self,
        ollama_e2e_provider: OllamaProvider,
        ollama_tool_model: str,
    ) -> None:
        """Tool calling should return a ToolCall with correct structure.

        Args:
            ollama_e2e_provider: A connected OllamaProvider instance.
            ollama_tool_model: An Ollama model ID that supports tools.
        """
        tools = _make_test_tool()
        messages = _make_messages(
            "Use the binary.get_file_size tool to check the size of C:\\Windows\\notepad.exe",
        )
        _, tool_calls = await ollama_e2e_provider.chat(
            messages=messages,
            model=ollama_tool_model,
            tools=tools,
            max_tokens=256,
        )
        assert tool_calls is not None
        assert len(tool_calls) > 0
        assert isinstance(tool_calls[0], ToolCall)
        assert tool_calls[0].function_name == "binary.get_file_size"
        assert "path" in tool_calls[0].arguments

    async def test_multi_turn_conversation_retains_context(
        self,
        ollama_e2e_provider: OllamaProvider,
        ollama_model: str,
    ) -> None:
        """Multi-turn conversation should reference information from prior messages.

        Args:
            ollama_e2e_provider: A connected OllamaProvider instance.
            ollama_model: The first available Ollama model ID.
        """
        messages = _make_multi_turn_messages()
        response, _ = await ollama_e2e_provider.chat(
            messages=messages,
            model=ollama_model,
            max_tokens=128,
        )
        content_lower = response.content.lower()
        assert "archimedes" in content_lower or "binary" in content_lower

    async def test_max_tokens_respected(
        self,
        ollama_e2e_provider: OllamaProvider,
        ollama_model: str,
    ) -> None:
        """Response with max_tokens=32 should be short.

        Args:
            ollama_e2e_provider: A connected OllamaProvider instance.
            ollama_model: The first available Ollama model ID.
        """
        messages = _make_messages("Write a very long essay about the history of computing.")
        response, _ = await ollama_e2e_provider.chat(
            messages=messages,
            model=ollama_model,
            max_tokens=_MAX_TOKENS_SHORT,
        )
        words = response.content.split()
        assert len(words) < 100

    async def test_model_listing_fields_valid(
        self,
        ollama_e2e_provider: OllamaProvider,
        ollama_model: str,
    ) -> None:
        """Model listing should return ModelInfo objects with correct types.

        Args:
            ollama_e2e_provider: A connected OllamaProvider instance.
            ollama_model: The first available Ollama model ID.
        """
        _ = ollama_model
        models = await ollama_e2e_provider.list_models()
        assert len(models) > 0
        for model in models:
            assert isinstance(model, ModelInfo)
            assert isinstance(model.id, str)
            assert len(model.id) > 0
            assert model.provider == ProviderName.OLLAMA


class TestCrossProviderConsistency:
    """Validate consistent behavior across all available providers."""

    @pytest_asyncio.fixture
    async def available_providers(
        self,
        credential_loader: CredentialLoader,
        ollama_server: Popen[bytes] | None,
        *,
        has_anthropic_key: bool,
        has_openai_key: bool,
        has_google_key: bool,
        has_grok_key: bool,
        has_openrouter_key: bool,
        has_huggingface_key: bool,
    ) -> AsyncGenerator[list[tuple[str, str, LLMProviderBase]]]:
        """Create connected providers for all configured credentials.

        Each element is a tuple of (provider_name, model_id, provider_instance).

        Args:
            credential_loader: The credential loader instance.
            has_anthropic_key: Whether Anthropic key is configured.
            has_openai_key: Whether OpenAI key is configured.
            has_google_key: Whether Google key is configured.
            has_grok_key: Whether Grok key is configured.
            has_openrouter_key: Whether OpenRouter key is configured.
            has_huggingface_key: Whether HuggingFace key is configured.
            ollama_server: The Ollama server process fixture.

        Yields:
            AsyncGenerator[list[tuple[str, str, LLMProviderBase]]]: List of available provider tuples.
        """
        _ = ollama_server
        providers: list[tuple[str, str, LLMProviderBase]] = []

        provider_configs: list[tuple[bool, type[LLMProviderBase], ProviderName, str]] = [
            (has_anthropic_key, AnthropicProvider, ProviderName.ANTHROPIC, ANTHROPIC_MODEL),
            (has_openai_key, OpenAIProvider, ProviderName.OPENAI, OPENAI_MODEL),
            (has_google_key, GoogleProvider, ProviderName.GOOGLE, GOOGLE_MODEL),
            (has_grok_key, GrokProvider, ProviderName.GROK, GROK_MODEL),
            (has_openrouter_key, OpenRouterProvider, ProviderName.OPENROUTER, OPENROUTER_MODEL),
            (has_huggingface_key, HuggingFaceProvider, ProviderName.HUGGINGFACE, HUGGINGFACE_MODEL),
        ]

        for has_key, provider_cls, provider_name, model_id in provider_configs:
            if not has_key:
                continue
            provider = provider_cls()
            creds = credential_loader.get_credentials(provider_name)
            if creds is None:
                continue
            await provider.connect(creds)
            providers.append((provider_name.value, model_id, provider))

        ollama_available = False
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(_OLLAMA_TAGS_URL)
                ollama_available = resp.status_code == _HTTP_OK
        except (OSError, httpx.HTTPError):
            pass

        if ollama_available:
            ollama_prov = OllamaProvider()
            ollama_creds = credential_loader.get_credentials(ProviderName.OLLAMA)
            if ollama_creds is None:
                ollama_creds = ProviderCredentials(api_key=None, api_base=_OLLAMA_URL)
            await ollama_prov.connect(ollama_creds)
            models = await ollama_prov.list_models()
            if models:
                providers.append(("ollama", models[0].id, ollama_prov))
            else:
                await ollama_prov.disconnect()

        if not providers:
            pytest.skip("No providers with credentials configured")

        yield providers

        for _, _, prov in providers:
            await prov.disconnect()

    async def test_same_prompt_all_providers_return_valid_messages(
        self,
        available_providers: list[tuple[str, str, LLMProviderBase]],
    ) -> None:
        """All available providers should return valid assistant messages for the same prompt.

        Args:
            available_providers: List of available provider tuples.
        """
        messages = _make_messages("What is 2 + 2? Answer in one word.")
        for provider_name, model_id, provider in available_providers:
            response, _ = await provider.chat(
                messages=messages,
                model=model_id,
                max_tokens=32,
            )
            assert response.role == "assistant", f"{provider_name} did not return assistant role"
            assert len(response.content) > 0, f"{provider_name} returned empty content"

    async def test_all_providers_handle_empty_tool_list(
        self,
        available_providers: list[tuple[str, str, LLMProviderBase]],
    ) -> None:
        """Passing tools=[] should not crash any provider.

        Args:
            available_providers: List of available provider tuples.
        """
        messages = _make_messages("Hello")
        for provider_name, model_id, provider in available_providers:
            response, _ = await provider.chat(
                messages=messages,
                model=model_id,
                tools=[],
                max_tokens=32,
            )
            assert response.role == "assistant", f"{provider_name} failed with empty tools"

    async def test_streaming_all_providers_yield_at_least_one_chunk(
        self,
        available_providers: list[tuple[str, str, LLMProviderBase]],
    ) -> None:
        """Streaming should yield at least one chunk from every provider.

        Args:
            available_providers: List of available provider tuples.
        """
        messages = _make_messages("Say hello.")
        for provider_name, model_id, provider in available_providers:
            chunks: list[str] = [
                chunk
                async for chunk in provider.chat_stream(
                    messages=messages,
                    model=model_id,
                    max_tokens=32,
                )
            ]
            assert len(chunks) >= 1, f"{provider_name} yielded no chunks"


class TestRateLimitAndErrorHandling:
    """Validate error handling for invalid models and timeouts."""

    async def test_anthropic_invalid_model_raises_provider_error(
        self,
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Requesting a nonexistent Anthropic model should raise ProviderError.

        Args:
            anthropic_provider: A connected AnthropicProvider instance.
        """
        messages = _make_messages("Hello")
        with pytest.raises(ProviderError):
            await anthropic_provider.chat(
                messages=messages,
                model="claude-nonexistent-999",
                max_tokens=32,
            )

    async def test_openai_invalid_model_raises_provider_error(
        self,
        openai_provider: OpenAIProvider,
    ) -> None:
        """Requesting a nonexistent OpenAI model should raise ProviderError.

        Args:
            openai_provider: A connected OpenAIProvider instance.
        """
        messages = _make_messages("Hello")
        with pytest.raises(ProviderError):
            await openai_provider.chat(
                messages=messages,
                model="gpt-nonexistent-999",
                max_tokens=32,
            )

    async def test_timeout_with_very_short_timeout(
        self,
        credential_loader: CredentialLoader,
        *,
        has_openai_key: bool,
    ) -> None:
        """An extremely short timeout should trigger an error.

        Args:
            credential_loader: The credential loader instance.
            has_openai_key: Whether OpenAI key is configured.
        """
        if not has_openai_key:
            pytest.skip("OPENAI_API_KEY not configured in .env")

        provider = OpenAIProvider()
        credentials = credential_loader.get_credentials(ProviderName.OPENAI)
        assert credentials is not None
        short_timeout_creds = ProviderCredentials(
            api_key=credentials.api_key,
            api_base=credentials.api_base,
            timeout=0.001,
        )
        await provider.connect(short_timeout_creds)

        messages = _make_messages("Hello")
        with pytest.raises((ProviderError, TimeoutError, OSError)):
            await provider.chat(
                messages=messages,
                model=OPENAI_MODEL,
                max_tokens=32,
            )

        await provider.disconnect()
