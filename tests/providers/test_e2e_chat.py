# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""End-to-end chat tests for all 7 cloud/API providers and cross-provider consistency.

Validates that every provider faithfully relays real model output through the
bridge layer: chat responses are relevant to the prompt, streaming reassembles
into coherent text, tool calling round-trips exact argument values, multi-turn
context is retained, ``max_tokens`` is honoured, and model listings expose
correct identifiers and capabilities. Also validates cross-provider consistency
and that API rejections and transport timeouts are surfaced as typed errors
rather than swallowed.

The assertions here use oracles that are independent of the implementation: the
known-correct answer to ``2 + 2``, the exact Windows path echoed back by a tool
call, the documented model-identifier naming convention of each vendor, and the
configured model constant that must appear in each provider's listing. None of
these are derived from Intellicrack's own output, so a corrupted bridge that
dropped content, mangled tool arguments, ignored ``max_tokens``, or fabricated
model records would fail the relevant gate.
"""

from __future__ import annotations

import re
import shutil
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

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
    ToolChoice,
    ToolChoiceMode,
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
GOOGLE_MODEL = "gemini-2.5-flash-lite"
GROK_MODEL = "grok-3-mini"
OPENROUTER_MODEL = "openai/gpt-4o-mini"
HUGGINGFACE_MODEL = "katanemo/Arch-Router-1.5B"

_OLLAMA_URL = "http://localhost:11434"
_OLLAMA_TAGS_URL = f"{_OLLAMA_URL}/api/tags"
_OLLAMA_STARTUP_TIMEOUT = 30
_OLLAMA_POLL_INTERVAL = 1.0
_HTTP_OK = 200

# max_tokens=32 truncates an English completion to roughly 24 words on average
# (a token averages about 0.75 words). A cap of 45 words leaves headroom for
# provider tokenizer differences while still failing any response that ignored
# the limit and ran on to dozens or hundreds of words.
_MAX_TOKENS_SHORT = 32
_MAX_TOKENS_WORD_CAP = 45

# A genuine notepad.exe path on Windows. Tool-calling tests assert the model
# echoes this exact target back through the bridge's argument parser.
_NOTEPAD_PATH = "C:\\Windows\\notepad.exe"

# Greeting tokens any reasonable model emits in response to a "say hello"
# prompt. Used to gate that chat/stream output is relevant, not random noise.
_GREETING_TOKENS = ("hello", "hi", "hey", "greetings", "howdy", "hallo")

# Acceptable spellings of the correct answer to "2 + 2".
_FOUR_TOKENS = ("4", "four")

# HTTP status codes that indicate the API rejected the request itself
# (bad model, bad request, quota) rather than a transport failure.
_CLIENT_REJECTION_STATUS = frozenset({400, 401, 402, 403, 404, 422, 429})

# Minimum context window any modern chat-capable model exposes. A listing that
# reported 0 or 1 would be nonsensical and must fail the gate.
_MIN_CONTEXT_WINDOW = 4000

# Word-character ratio threshold proving streamed text is human-readable prose
# rather than binary garbage or control noise.
_MIN_READABLE_RATIO = 0.6


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
                        ToolParameter(
                            name="section_names",
                            type="array",
                            description="Optional section names to restrict the size calculation to.",
                            required=False,
                            items_type="string",
                        ),
                        ToolParameter(
                            name="regions",
                            type="array",
                            description="Optional explicit byte regions to measure.",
                            required=False,
                            items_type="object",
                            item_properties=[
                                ToolParameter(
                                    name="start",
                                    type="integer",
                                    description="Region start offset in bytes.",
                                    required=True,
                                ),
                                ToolParameter(
                                    name="end",
                                    type="integer",
                                    description="Region end offset in bytes.",
                                    required=True,
                                ),
                            ],
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


def _readable_ratio(text: str) -> float:
    """Compute the fraction of characters that are alphanumeric or common punctuation.

    Args:
        text: The text to measure.

    Returns:
        float: Ratio in ``[0.0, 1.0]`` of readable characters; ``0.0`` for empty text.
    """
    if not text:
        return 0.0
    readable = sum(bool(ch.isalnum() or ch.isspace() or ch in ".,!?'\"-:;()") for ch in text)
    return readable / len(text)


def _assert_greeting_response(content: str, provider_name: str) -> None:
    """Assert that chat content is a relevant greeting and not random noise.

    Args:
        content: The assistant response text.
        provider_name: Provider label used in assertion messages.
    """
    assert content.strip(), f"{provider_name} returned empty content for a greeting prompt"
    lowered = content.lower()
    assert any(token in lowered for token in _GREETING_TOKENS), f"{provider_name} greeting response had no greeting token: {content!r}"
    assert _readable_ratio(content) >= _MIN_READABLE_RATIO, f"{provider_name} greeting response was not readable text: {content!r}"


def _assert_coherent_stream(chunks: list[str], provider_name: str) -> str:
    """Assert that streamed chunks reassemble into a coherent greeting.

    Args:
        chunks: The text chunks yielded by ``chat_stream``.
        provider_name: Provider label used in assertion messages.

    Returns:
        str: The reassembled stream text.
    """
    assert chunks, f"{provider_name} yielded no streaming chunks"
    assert all(isinstance(chunk, str) for chunk in chunks), f"{provider_name} yielded a non-string chunk"
    full_text = "".join(chunks)
    assert full_text.strip(), f"{provider_name} stream reassembled to empty text"
    lowered = full_text.lower()
    assert any(token in lowered for token in _GREETING_TOKENS), f"{provider_name} streamed text had no greeting token: {full_text!r}"
    assert _readable_ratio(full_text) >= _MIN_READABLE_RATIO, f"{provider_name} streamed text was not readable: {full_text!r}"
    return full_text


def _assert_notepad_tool_call(tool_calls: list[ToolCall] | None, provider_name: str) -> None:
    """Assert a tool call targets ``binary.get_file_size`` with the exact notepad path.

    Args:
        tool_calls: The tool calls returned by ``chat``.
        provider_name: Provider label used in assertion messages.
    """
    assert tool_calls is not None, f"{provider_name} returned no tool calls"
    assert len(tool_calls) >= 1, f"{provider_name} returned an empty tool-call list"
    call = tool_calls[0]
    assert isinstance(call, ToolCall), f"{provider_name} returned a non-ToolCall object"
    assert call.function_name == "binary.get_file_size", f"{provider_name} called the wrong function: {call.function_name!r}"
    assert call.tool_name == "binary", f"{provider_name} derived the wrong tool name: {call.tool_name!r}"
    assert "path" in call.arguments, f"{provider_name} tool call missing 'path' argument: {call.arguments!r}"
    raw_path = call.arguments["path"]
    assert isinstance(raw_path, str), f"{provider_name} 'path' argument was not a string: {raw_path!r}"
    normalized = raw_path.replace("/", "\\").lower()
    assert normalized.endswith("notepad.exe"), f"{provider_name} path did not target notepad.exe: {raw_path!r}"
    assert "windows" in normalized, f"{provider_name} path did not reference the Windows directory: {raw_path!r}"


def _assert_recalls_context(content: str, provider_name: str) -> None:
    """Assert a multi-turn response recalls both the user's name and field of work.

    Args:
        content: The assistant response text.
        provider_name: Provider label used in assertion messages.
    """
    lowered = content.lower()
    assert "archimedes" in lowered, f"{provider_name} did not recall the name 'Archimedes': {content!r}"
    assert "binary" in lowered or "analysis" in lowered, f"{provider_name} did not recall the field of work: {content!r}"


def _assert_short_response(content: str, provider_name: str) -> None:
    """Assert a response honoured a tight ``max_tokens`` cap.

    Args:
        content: The assistant response text.
        provider_name: Provider label used in assertion messages.
    """
    assert content.strip(), f"{provider_name} returned empty content under a token cap"
    words = content.split()
    assert len(words) <= _MAX_TOKENS_WORD_CAP, f"{provider_name} ignored max_tokens={_MAX_TOKENS_SHORT}: produced {len(words)} words"


def _assert_math_answer(content: str, provider_name: str) -> None:
    """Assert a response to ``2 + 2`` contains the correct answer.

    Args:
        content: The assistant response text.
        provider_name: Provider label used in assertion messages.
    """
    lowered = content.lower()
    assert any(re.search(rf"\b{re.escape(token)}\b", lowered) for token in _FOUR_TOKENS), (
        f"{provider_name} gave a wrong answer to '2 + 2': {content!r}"
    )


def _assert_model_listing(
    models: list[ModelInfo],
    *,
    provider: ProviderName,
    id_substring: str,
    required_model: str | None,
) -> None:
    """Assert a model listing exposes well-formed, vendor-consistent records.

    Args:
        models: The models returned by ``list_models``.
        provider: The provider that produced the listing.
        id_substring: Lowercase substring every model id must contain (the
            vendor's documented identifier convention, e.g. ``"claude"`` or
            ``"/"``).
        required_model: A model id that must appear in the listing (the
            configured chat-model constant), or ``None`` to skip the check.
    """
    assert models, f"{provider.value} returned an empty model listing"
    ids: list[str] = []
    for model in models:
        assert isinstance(model, ModelInfo), f"{provider.value} returned a non-ModelInfo entry"
        assert model.id, f"{provider.value} returned a model with an empty id"
        assert id_substring in model.id.lower(), f"{provider.value} model id lacks {id_substring!r}: {model.id!r}"
        assert isinstance(model.name, str), f"{provider.value} model {model.id!r} name was not a string"
        assert model.name, f"{provider.value} model {model.id!r} had an empty name"
        assert model.provider == provider, f"{provider.value} model {model.id!r} mislabelled provider as {model.provider!r}"
        assert model.context_window >= _MIN_CONTEXT_WINDOW, (
            f"{provider.value} model {model.id!r} had unrealistic context window {model.context_window}"
        )
        assert isinstance(model.supports_tools, bool), f"{provider.value} model {model.id!r} supports_tools was not bool"
        assert isinstance(model.supports_streaming, bool), f"{provider.value} model {model.id!r} supports_streaming was not bool"
        ids.append(model.id)
    if required_model is not None:
        assert required_model in ids, f"{provider.value} listing omitted the configured model {required_model!r}"


def _walk_exception_chain(exc: BaseException) -> list[BaseException]:
    """Collect an exception and every ``__cause__``/``__context__`` ancestor.

    Args:
        exc: The exception to walk from.

    Returns:
        list[BaseException]: The exception followed by its chained ancestors,
        de-duplicated and order-preserving.
    """
    chain: list[BaseException] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


def _assert_api_rejection(exc: ProviderError, provider_name: str) -> None:
    """Assert a ProviderError reflects a server-side request rejection, not a transport fault.

    A faithful bridge surfaces an invalid-model request as a typed
    :class:`ProviderError` whose chain carries a 4xx HTTP status. This
    distinguishes a genuine API rejection (bad model / bad request / quota)
    from a swallowed error or a bare network failure with no status.

    Args:
        exc: The raised :class:`ProviderError`.
        provider_name: Provider label used in assertion messages.
    """
    statuses: list[int] = []
    for link in _walk_exception_chain(exc):
        status = getattr(link, "status_code", None)
        if isinstance(status, int):
            statuses.append(status)
    assert any(status in _CLIENT_REJECTION_STATUS for status in statuses), (
        f"{provider_name} error was not a client-side API rejection; statuses seen: {statuses}"
    )


@pytest.fixture(scope="session")
def ollama_server() -> Generator[Popen[bytes] | None]:
    """Start an Ollama server subprocess for testing.

    Starts ``ollama serve`` and polls the health endpoint until the
    server responds. Skips if the ``ollama`` binary is not on PATH.
    Kills the server on teardown.

    Yields:
        Popen[bytes] | None: The Ollama server process, or None if already running.
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
        OllamaProvider: A connected OllamaProvider instance.
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

    async def test_chat_returns_relevant_greeting(
        self,
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Chat should answer a greeting prompt with relevant greeting text.

        Args:
            anthropic_provider: A connected AnthropicProvider instance.
        """
        messages = _make_messages("Respond with one word: hello")
        response, _ = await anthropic_provider.chat(messages=messages, model=ANTHROPIC_MODEL, max_tokens=64)
        assert response.role == "assistant"
        _assert_greeting_response(response.content, "anthropic")

    async def test_chat_stream_reassembles_coherent_greeting(
        self,
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Streaming should yield chunks that reassemble into a coherent greeting.

        Args:
            anthropic_provider: A connected AnthropicProvider instance.
        """
        messages = _make_messages("Say hello briefly.")
        chunks = [chunk async for chunk in anthropic_provider.chat_stream(messages=messages, model=ANTHROPIC_MODEL, max_tokens=64)]
        _assert_coherent_stream(chunks, "anthropic")

    async def test_tool_calling_echoes_exact_notepad_path(
        self,
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Tool calling should return the exact requested path in the arguments.

        Args:
            anthropic_provider: A connected AnthropicProvider instance.
        """
        tools = _make_test_tool()
        messages = _make_messages(f"Use the binary.get_file_size tool to check the size of {_NOTEPAD_PATH}")
        _, tool_calls = await anthropic_provider.chat(messages=messages, model=ANTHROPIC_MODEL, tools=tools, max_tokens=256)
        _assert_notepad_tool_call(tool_calls, "anthropic")

    async def test_multi_turn_conversation_recalls_name_and_field(
        self,
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Multi-turn conversation should recall both the user name and field.

        Args:
            anthropic_provider: A connected AnthropicProvider instance.
        """
        messages = _make_multi_turn_messages()
        response, _ = await anthropic_provider.chat(messages=messages, model=ANTHROPIC_MODEL, max_tokens=128)
        _assert_recalls_context(response.content, "anthropic")

    async def test_max_tokens_caps_response_length(
        self,
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """A tight max_tokens cap should produce a short response.

        Args:
            anthropic_provider: A connected AnthropicProvider instance.
        """
        messages = _make_messages("Write a very long essay about the history of computing.")
        response, _ = await anthropic_provider.chat(messages=messages, model=ANTHROPIC_MODEL, max_tokens=_MAX_TOKENS_SHORT)
        _assert_short_response(response.content, "anthropic")

    async def test_model_listing_exposes_valid_claude_models(
        self,
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Model listing should expose well-formed Claude models.

        Args:
            anthropic_provider: A connected AnthropicProvider instance.
        """
        models = await anthropic_provider.list_models()
        _assert_model_listing(models, provider=ProviderName.ANTHROPIC, id_substring="claude", required_model=None)


class TestOpenAIE2EChat:
    """End-to-end chat tests for the OpenAI provider."""

    async def test_chat_returns_relevant_greeting(
        self,
        openai_provider: OpenAIProvider,
    ) -> None:
        """Chat should answer a greeting prompt with relevant greeting text.

        Args:
            openai_provider: A connected OpenAIProvider instance.
        """
        messages = _make_messages("Respond with one word: hello")
        response, _ = await openai_provider.chat(messages=messages, model=OPENAI_MODEL, max_tokens=64)
        assert response.role == "assistant"
        _assert_greeting_response(response.content, "openai")

    async def test_chat_stream_reassembles_coherent_greeting(
        self,
        openai_provider: OpenAIProvider,
    ) -> None:
        """Streaming should yield chunks that reassemble into a coherent greeting.

        Args:
            openai_provider: A connected OpenAIProvider instance.
        """
        messages = _make_messages("Say hello briefly.")
        chunks = [chunk async for chunk in openai_provider.chat_stream(messages=messages, model=OPENAI_MODEL, max_tokens=64)]
        _assert_coherent_stream(chunks, "openai")

    async def test_tool_calling_echoes_exact_notepad_path(
        self,
        openai_provider: OpenAIProvider,
    ) -> None:
        """Tool calling should return the exact requested path in the arguments.

        Args:
            openai_provider: A connected OpenAIProvider instance.
        """
        tools = _make_test_tool()
        messages = _make_messages(f"Use the binary.get_file_size tool to check the size of {_NOTEPAD_PATH}")
        _, tool_calls = await openai_provider.chat(messages=messages, model=OPENAI_MODEL, tools=tools, max_tokens=256)
        _assert_notepad_tool_call(tool_calls, "openai")

    async def test_multi_turn_conversation_recalls_name_and_field(
        self,
        openai_provider: OpenAIProvider,
    ) -> None:
        """Multi-turn conversation should recall both the user name and field.

        Args:
            openai_provider: A connected OpenAIProvider instance.
        """
        messages = _make_multi_turn_messages()
        response, _ = await openai_provider.chat(messages=messages, model=OPENAI_MODEL, max_tokens=128)
        _assert_recalls_context(response.content, "openai")

    async def test_max_tokens_caps_response_length(
        self,
        openai_provider: OpenAIProvider,
    ) -> None:
        """A tight max_tokens cap should produce a short response.

        Args:
            openai_provider: A connected OpenAIProvider instance.
        """
        messages = _make_messages("Write a very long essay about the history of computing.")
        response, _ = await openai_provider.chat(messages=messages, model=OPENAI_MODEL, max_tokens=_MAX_TOKENS_SHORT)
        _assert_short_response(response.content, "openai")

    async def test_model_listing_contains_configured_model(
        self,
        openai_provider: OpenAIProvider,
    ) -> None:
        """Model listing should expose well-formed records including the configured model.

        Args:
            openai_provider: A connected OpenAIProvider instance.
        """
        models = await openai_provider.list_models()
        _assert_model_listing(models, provider=ProviderName.OPENAI, id_substring="", required_model=OPENAI_MODEL)


class TestGoogleE2EChat:
    """End-to-end chat tests for the Google provider."""

    async def test_chat_returns_relevant_greeting(
        self,
        google_provider: GoogleProvider,
    ) -> None:
        """Chat should answer a greeting prompt with relevant greeting text.

        Args:
            google_provider: A connected GoogleProvider instance.
        """
        messages = _make_messages("Respond with one word: hello")
        response, _ = await google_provider.chat(messages=messages, model=GOOGLE_MODEL, max_tokens=64)
        assert response.role == "assistant"
        _assert_greeting_response(response.content, "google")

    async def test_chat_stream_reassembles_coherent_greeting(
        self,
        google_provider: GoogleProvider,
    ) -> None:
        """Streaming should yield chunks that reassemble into a coherent greeting.

        Args:
            google_provider: A connected GoogleProvider instance.
        """
        messages = _make_messages("Say hello briefly.")
        chunks = [chunk async for chunk in google_provider.chat_stream(messages=messages, model=GOOGLE_MODEL, max_tokens=64)]
        _assert_coherent_stream(chunks, "google")

    async def test_tool_calling_echoes_exact_notepad_path(
        self,
        google_provider: GoogleProvider,
    ) -> None:
        """Tool calling should return the exact requested path in the arguments.

        Args:
            google_provider: A connected GoogleProvider instance.
        """
        tools = _make_test_tool()
        messages = _make_messages(f"Use the binary.get_file_size tool to check the size of {_NOTEPAD_PATH}")
        _, tool_calls = await google_provider.chat(messages=messages, model=GOOGLE_MODEL, tools=tools, max_tokens=256)
        _assert_notepad_tool_call(tool_calls, "google")

    async def test_multi_turn_conversation_recalls_name_and_field(
        self,
        google_provider: GoogleProvider,
    ) -> None:
        """Multi-turn conversation should recall both the user name and field.

        Args:
            google_provider: A connected GoogleProvider instance.
        """
        messages = _make_multi_turn_messages()
        response, _ = await google_provider.chat(messages=messages, model=GOOGLE_MODEL, max_tokens=128)
        _assert_recalls_context(response.content, "google")

    async def test_max_tokens_caps_response_length(
        self,
        google_provider: GoogleProvider,
    ) -> None:
        """A tight max_tokens cap should produce a short response.

        Args:
            google_provider: A connected GoogleProvider instance.
        """
        messages = _make_messages("Write a very long essay about the history of computing.")
        response, _ = await google_provider.chat(messages=messages, model=GOOGLE_MODEL, max_tokens=_MAX_TOKENS_SHORT)
        _assert_short_response(response.content, "google")

    async def test_model_listing_exposes_valid_gemini_models(
        self,
        google_provider: GoogleProvider,
    ) -> None:
        """Model listing should expose well-formed Gemini models.

        Args:
            google_provider: A connected GoogleProvider instance.
        """
        models = await google_provider.list_models()
        _assert_model_listing(models, provider=ProviderName.GOOGLE, id_substring="gemini", required_model=None)


class TestGrokE2EChat:
    """End-to-end chat tests for the Grok provider."""

    async def test_chat_returns_relevant_greeting(
        self,
        grok_provider: GrokProvider,
    ) -> None:
        """Chat should answer a greeting prompt with relevant greeting text.

        Args:
            grok_provider: A connected GrokProvider instance.
        """
        messages = _make_messages("Respond with one word: hello")
        response, _ = await grok_provider.chat(messages=messages, model=GROK_MODEL, max_tokens=64)
        assert response.role == "assistant"
        _assert_greeting_response(response.content, "grok")

    async def test_chat_stream_reassembles_coherent_greeting(
        self,
        grok_provider: GrokProvider,
    ) -> None:
        """Streaming should yield chunks that reassemble into a coherent greeting.

        Args:
            grok_provider: A connected GrokProvider instance.
        """
        messages = _make_messages("Say hello briefly.")
        chunks = [chunk async for chunk in grok_provider.chat_stream(messages=messages, model=GROK_MODEL, max_tokens=64)]
        _assert_coherent_stream(chunks, "grok")

    async def test_tool_calling_echoes_exact_notepad_path(
        self,
        grok_provider: GrokProvider,
    ) -> None:
        """Tool calling should return the exact requested path in the arguments.

        Args:
            grok_provider: A connected GrokProvider instance.
        """
        tools = _make_test_tool()
        messages = _make_messages(f"Use the binary.get_file_size tool to check the size of {_NOTEPAD_PATH}")
        _, tool_calls = await grok_provider.chat(messages=messages, model=GROK_MODEL, tools=tools, max_tokens=256)
        _assert_notepad_tool_call(tool_calls, "grok")

    async def test_multi_turn_conversation_recalls_name_and_field(
        self,
        grok_provider: GrokProvider,
    ) -> None:
        """Multi-turn conversation should recall both the user name and field.

        Args:
            grok_provider: A connected GrokProvider instance.
        """
        messages = _make_multi_turn_messages()
        response, _ = await grok_provider.chat(messages=messages, model=GROK_MODEL, max_tokens=128)
        _assert_recalls_context(response.content, "grok")

    async def test_max_tokens_caps_response_length(
        self,
        grok_provider: GrokProvider,
    ) -> None:
        """A tight max_tokens cap should produce a short response.

        Args:
            grok_provider: A connected GrokProvider instance.
        """
        messages = _make_messages("Write a very long essay about the history of computing.")
        response, _ = await grok_provider.chat(messages=messages, model=GROK_MODEL, max_tokens=_MAX_TOKENS_SHORT)
        _assert_short_response(response.content, "grok")

    async def test_model_listing_exposes_valid_grok_models(
        self,
        grok_provider: GrokProvider,
    ) -> None:
        """Model listing should expose well-formed Grok models.

        Args:
            grok_provider: A connected GrokProvider instance.
        """
        models = await grok_provider.list_models()
        _assert_model_listing(models, provider=ProviderName.GROK, id_substring="grok", required_model=None)


class TestOpenRouterE2EChat:
    """End-to-end chat tests for the OpenRouter provider."""

    async def test_chat_returns_relevant_greeting(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Chat should answer a greeting prompt with relevant greeting text.

        Args:
            openrouter_provider: A connected OpenRouterProvider instance.
        """
        messages = _make_messages("Respond with one word: hello")
        response, _ = await openrouter_provider.chat(messages=messages, model=OPENROUTER_MODEL, max_tokens=64)
        assert response.role == "assistant"
        _assert_greeting_response(response.content, "openrouter")

    async def test_chat_stream_reassembles_coherent_greeting(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Streaming should yield chunks that reassemble into a coherent greeting.

        Args:
            openrouter_provider: A connected OpenRouterProvider instance.
        """
        messages = _make_messages("Say hello briefly.")
        chunks = [chunk async for chunk in openrouter_provider.chat_stream(messages=messages, model=OPENROUTER_MODEL, max_tokens=64)]
        _assert_coherent_stream(chunks, "openrouter")

    async def test_tool_calling_echoes_exact_notepad_path(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Tool calling should return the exact requested path in the arguments.

        Args:
            openrouter_provider: A connected OpenRouterProvider instance.
        """
        tools = _make_test_tool()
        messages = _make_messages(f"Use the binary.get_file_size tool to check the size of {_NOTEPAD_PATH}")
        _, tool_calls = await openrouter_provider.chat(messages=messages, model=OPENROUTER_MODEL, tools=tools, max_tokens=256)
        _assert_notepad_tool_call(tool_calls, "openrouter")

    async def test_multi_turn_conversation_recalls_name_and_field(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Multi-turn conversation should recall both the user name and field.

        Args:
            openrouter_provider: A connected OpenRouterProvider instance.
        """
        messages = _make_multi_turn_messages()
        response, _ = await openrouter_provider.chat(messages=messages, model=OPENROUTER_MODEL, max_tokens=128)
        _assert_recalls_context(response.content, "openrouter")

    async def test_max_tokens_caps_response_length(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """A tight max_tokens cap should produce a short response.

        Args:
            openrouter_provider: A connected OpenRouterProvider instance.
        """
        messages = _make_messages("Write a very long essay about the history of computing.")
        response, _ = await openrouter_provider.chat(messages=messages, model=OPENROUTER_MODEL, max_tokens=_MAX_TOKENS_SHORT)
        _assert_short_response(response.content, "openrouter")

    async def test_model_listing_contains_configured_model(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Model listing should expose org-scoped records including the configured model.

        Args:
            openrouter_provider: A connected OpenRouterProvider instance.
        """
        models = await openrouter_provider.list_models()
        _assert_model_listing(models, provider=ProviderName.OPENROUTER, id_substring="/", required_model=OPENROUTER_MODEL)


class TestHuggingFaceE2EChat:
    """End-to-end chat tests for the HuggingFace provider."""

    async def test_chat_returns_relevant_greeting(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Chat should answer a greeting prompt with relevant greeting text.

        Args:
            huggingface_provider: A connected HuggingFaceProvider instance.
        """
        messages = _make_messages("Respond with one word: hello")
        response, _ = await huggingface_provider.chat(messages=messages, model=HUGGINGFACE_MODEL, max_tokens=64)
        assert response.role == "assistant"
        _assert_greeting_response(response.content, "huggingface")

    async def test_chat_stream_reassembles_coherent_greeting(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Streaming should yield chunks that reassemble into a coherent greeting.

        Args:
            huggingface_provider: A connected HuggingFaceProvider instance.
        """
        messages = _make_messages("Say hello briefly.")
        chunks = [chunk async for chunk in huggingface_provider.chat_stream(messages=messages, model=HUGGINGFACE_MODEL, max_tokens=64)]
        _assert_coherent_stream(chunks, "huggingface")

    async def test_tool_schema_conversion_and_typed_rejection(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """The bridge should convert tool schema faithfully and surface backend rejection as a typed error.

        Open-source inference endpoints frequently lack the server-side flags
        needed for tool calling and reject a tool-bearing request with HTTP 400.
        This gate exercises two real bridge responsibilities: (1) the internal
        :class:`ToolDefinition` is converted to the exact OpenAI-compatible
        function schema, and (2) when the backend rejects the tool-bearing
        request the bridge translates that HTTP 400 into an Intellicrack-typed
        :class:`ProviderError`, never leaking the raw ``httpx`` / SDK exception.

        Args:
            huggingface_provider: A connected HuggingFaceProvider instance.
        """
        tools = _make_test_tool()
        provider_tools = huggingface_provider.convert_tools_to_provider_format(tools)
        assert provider_tools, "tool definition did not convert to provider schema"
        first_tool = provider_tools[0]
        assert first_tool.get("type") == "function", f"converted tool missing function type: {first_tool!r}"
        function_schema: object = first_tool.get("function")
        assert isinstance(function_schema, dict), f"converted tool missing function schema: {first_tool!r}"
        schema_dict = cast("dict[str, object]", function_schema)
        assert schema_dict.get("name") == "binary.get_file_size", f"converted tool name wrong: {schema_dict!r}"
        assert schema_dict.get("description") == "Get the file size in bytes of the loaded binary.", (
            f"converted tool description wrong: {schema_dict!r}"
        )
        parameters = schema_dict.get("parameters")
        assert isinstance(parameters, dict), f"converted tool missing parameters object: {schema_dict!r}"
        params_dict = cast("dict[str, object]", parameters)
        assert params_dict.get("required") == ["path"], f"converted tool required list wrong: {params_dict!r}"

        messages = _make_messages(f"Use the binary.get_file_size tool to check the size of {_NOTEPAD_PATH}")
        with pytest.raises(ProviderError):
            await huggingface_provider.chat(messages=messages, model=HUGGINGFACE_MODEL, tools=tools, max_tokens=256)

    async def test_multi_turn_conversation_recalls_name_and_field(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Multi-turn conversation should recall both the user name and field.

        Args:
            huggingface_provider: A connected HuggingFaceProvider instance.
        """
        messages = _make_multi_turn_messages()
        response, _ = await huggingface_provider.chat(messages=messages, model=HUGGINGFACE_MODEL, max_tokens=128)
        _assert_recalls_context(response.content, "huggingface")

    async def test_max_tokens_caps_response_length(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """A tight max_tokens cap should produce a short response.

        Args:
            huggingface_provider: A connected HuggingFaceProvider instance.
        """
        messages = _make_messages("Write a very long essay about the history of computing.")
        response, _ = await huggingface_provider.chat(messages=messages, model=HUGGINGFACE_MODEL, max_tokens=_MAX_TOKENS_SHORT)
        _assert_short_response(response.content, "huggingface")

    async def test_model_listing_exposes_org_scoped_models(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Model listing should expose well-formed org-scoped models.

        Args:
            huggingface_provider: A connected HuggingFaceProvider instance.
        """
        models = await huggingface_provider.list_models()
        _assert_model_listing(models, provider=ProviderName.HUGGINGFACE, id_substring="/", required_model=None)


class TestOllamaE2EChat:
    """End-to-end chat tests for the Ollama provider."""

    async def test_chat_returns_relevant_greeting(
        self,
        ollama_e2e_provider: OllamaProvider,
        ollama_model: str,
    ) -> None:
        """Chat should answer a greeting prompt with relevant greeting text.

        Args:
            ollama_e2e_provider: A connected OllamaProvider instance.
            ollama_model: The first available Ollama model ID.
        """
        messages = _make_messages("Respond with one word: hello")
        response, _ = await ollama_e2e_provider.chat(messages=messages, model=ollama_model, max_tokens=64)
        assert response.role == "assistant"
        _assert_greeting_response(response.content, "ollama")

    async def test_chat_stream_reassembles_coherent_greeting(
        self,
        ollama_e2e_provider: OllamaProvider,
        ollama_model: str,
    ) -> None:
        """Streaming should yield chunks that reassemble into a coherent greeting.

        Args:
            ollama_e2e_provider: A connected OllamaProvider instance.
            ollama_model: The first available Ollama model ID.
        """
        messages = _make_messages("Say hello briefly.")
        chunks = [chunk async for chunk in ollama_e2e_provider.chat_stream(messages=messages, model=ollama_model, max_tokens=64)]
        _assert_coherent_stream(chunks, "ollama")

    async def test_tool_calling_echoes_exact_notepad_path(
        self,
        ollama_e2e_provider: OllamaProvider,
        ollama_tool_model: str,
    ) -> None:
        """Tool calling should return the exact requested path in the arguments.

        Args:
            ollama_e2e_provider: A connected OllamaProvider instance.
            ollama_tool_model: An Ollama model ID that supports tools.
        """
        tools = _make_test_tool()
        messages = _make_messages(f"Use the binary.get_file_size tool to check the size of {_NOTEPAD_PATH}")
        _, tool_calls = await ollama_e2e_provider.chat(messages=messages, model=ollama_tool_model, tools=tools, max_tokens=256)
        _assert_notepad_tool_call(tool_calls, "ollama")

    async def test_multi_turn_conversation_recalls_name_and_field(
        self,
        ollama_e2e_provider: OllamaProvider,
        ollama_model: str,
    ) -> None:
        """Multi-turn conversation should recall both the user name and field.

        Args:
            ollama_e2e_provider: A connected OllamaProvider instance.
            ollama_model: The first available Ollama model ID.
        """
        messages = _make_multi_turn_messages()
        response, _ = await ollama_e2e_provider.chat(messages=messages, model=ollama_model, max_tokens=128)
        _assert_recalls_context(response.content, "ollama")

    async def test_max_tokens_caps_response_length(
        self,
        ollama_e2e_provider: OllamaProvider,
        ollama_model: str,
    ) -> None:
        """A tight max_tokens cap should produce a short response.

        Args:
            ollama_e2e_provider: A connected OllamaProvider instance.
            ollama_model: The first available Ollama model ID.
        """
        messages = _make_messages("Write a very long essay about the history of computing.")
        response, _ = await ollama_e2e_provider.chat(messages=messages, model=ollama_model, max_tokens=_MAX_TOKENS_SHORT)
        _assert_short_response(response.content, "ollama")

    async def test_model_listing_includes_active_model(
        self,
        ollama_e2e_provider: OllamaProvider,
        ollama_model: str,
    ) -> None:
        """Model listing should expose well-formed records including the active model.

        Args:
            ollama_e2e_provider: A connected OllamaProvider instance.
            ollama_model: The first available Ollama model ID.
        """
        models = await ollama_e2e_provider.list_models()
        _assert_model_listing(models, provider=ProviderName.OLLAMA, id_substring="", required_model=ollama_model)


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
            ollama_server: The Ollama server process fixture.
            has_anthropic_key: Whether Anthropic key is configured.
            has_openai_key: Whether OpenAI key is configured.
            has_google_key: Whether Google key is configured.
            has_grok_key: Whether Grok key is configured.
            has_openrouter_key: Whether OpenRouter key is configured.
            has_huggingface_key: Whether HuggingFace key is configured.

        Yields:
            list[tuple[str, str, LLMProviderBase]]: List of available provider tuples.
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

    async def test_same_math_prompt_all_providers_answer_four(
        self,
        available_providers: list[tuple[str, str, LLMProviderBase]],
    ) -> None:
        """Every available provider should answer ``2 + 2`` with the correct value.

        Args:
            available_providers: List of available provider tuples.
        """
        messages = _make_messages("What is 2 + 2? Answer in one word.")
        for provider_name, model_id, provider in available_providers:
            response, _ = await provider.chat(messages=messages, model=model_id, max_tokens=32)
            assert response.role == "assistant", f"{provider_name} did not return assistant role"
            _assert_math_answer(response.content, provider_name)

    async def test_all_providers_reject_malformed_tool_choice(
        self,
        available_providers: list[tuple[str, str, LLMProviderBase]],
    ) -> None:
        """An empty tool list must be accepted; a malformed tool_choice must be a typed error.

        The happy path (``tools=[]``) must still produce a valid assistant turn.
        The error path drives a real tool definition together with a
        :class:`ToolChoice` in ``SPECIFIC`` mode whose ``function_name`` is empty
        - an unsatisfiable selection - through the public ``chat`` API, which
        must raise :class:`ProviderError` rather than silently sending a
        malformed request to the backend.

        Args:
            available_providers: List of available provider tuples.
        """
        messages = _make_messages("Hello")
        tools = _make_test_tool()
        malformed_choice = ToolChoice(mode=ToolChoiceMode.SPECIFIC, function_name="")
        for provider_name, model_id, provider in available_providers:
            response, _ = await provider.chat(messages=messages, model=model_id, tools=[], max_tokens=32)
            assert response.role == "assistant", f"{provider_name} failed with empty tools"

            with pytest.raises(ProviderError):
                await provider.chat(
                    messages=messages,
                    model=model_id,
                    tools=tools,
                    tool_choice=malformed_choice,
                    max_tokens=32,
                )

    async def test_streaming_all_providers_yield_readable_text(
        self,
        available_providers: list[tuple[str, str, LLMProviderBase]],
    ) -> None:
        """Streaming should reassemble into readable greeting text for every provider.

        Args:
            available_providers: List of available provider tuples.
        """
        messages = _make_messages("Say hello.")
        for provider_name, model_id, provider in available_providers:
            chunks = [chunk async for chunk in provider.chat_stream(messages=messages, model=model_id, max_tokens=32)]
            assert chunks, f"{provider_name} yielded no chunks"
            joined = "".join(chunks)
            assert joined.strip(), f"{provider_name} streamed empty text"
            assert _readable_ratio(joined) >= _MIN_READABLE_RATIO, f"{provider_name} streamed unreadable text: {joined!r}"


class TestRateLimitAndErrorHandling:
    """Validate error handling for invalid models and timeouts."""

    async def test_anthropic_invalid_model_raises_client_rejection(
        self,
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """A nonexistent Anthropic model should raise a typed client-rejection error.

        Args:
            anthropic_provider: A connected AnthropicProvider instance.
        """
        messages = _make_messages("Hello")
        with pytest.raises(ProviderError) as exc_info:
            await anthropic_provider.chat(messages=messages, model="claude-nonexistent-999", max_tokens=32)
        _assert_api_rejection(exc_info.value, "anthropic")

    async def test_openai_invalid_model_reports_missing_model(
        self,
        openai_provider: OpenAIProvider,
    ) -> None:
        """A nonexistent OpenAI model should raise a ProviderError naming the model problem.

        Args:
            openai_provider: A connected OpenAIProvider instance.
        """
        messages = _make_messages("Hello")
        with pytest.raises(ProviderError) as exc_info:
            await openai_provider.chat(messages=messages, model="gpt-nonexistent-999", max_tokens=32)
        _assert_api_rejection(exc_info.value, "openai")
        combined = " ".join(str(link).lower() for link in _walk_exception_chain(exc_info.value))
        assert "model" in combined, f"openai error did not reference the model: {combined[:200]!r}"
        assert "does not exist" in combined or "not found" in combined, f"openai error did not flag a missing model: {combined[:200]!r}"

    async def test_unreachable_endpoint_surfaces_timeout_as_provider_error(
        self,
        credential_loader: CredentialLoader,
        *,
        has_openai_key: bool,
    ) -> None:
        """A short timeout against an unreachable endpoint must surface a typed timeout error.

        Pointing the OpenAI-compatible client at a non-routable address with a
        short timeout produces a deterministic transport timeout that does not
        depend on live-account state. The bridge must translate that transport
        failure into a :class:`ProviderError` whose message names the timeout,
        rather than leaking a raw transport exception or hanging.

        Args:
            credential_loader: The credential loader instance.
            has_openai_key: Whether OpenAI key is configured.
        """
        if not has_openai_key:
            pytest.skip("OPENAI_API_KEY not configured in .env")

        base = credential_loader.get_credentials(ProviderName.OPENAI)
        assert base is not None
        unreachable_creds = ProviderCredentials(
            api_key=base.api_key,
            api_base="http://10.255.255.1:9/v1",
            timeout=2.0,
        )
        provider = OpenAIProvider()
        start = time.monotonic()
        with pytest.raises(ProviderError) as exc_info:
            await provider.connect(unreachable_creds)
        elapsed = time.monotonic() - start

        combined = " ".join(str(link).lower() for link in _walk_exception_chain(exc_info.value))
        if "the network location cannot be reached" in combined or "winerror 1231" in combined or "network is unreachable" in combined:
            await provider.disconnect()
            pytest.skip(
                "outbound network unavailable: the non-routable address fails fast with ENETUNREACH "
                "instead of hanging to a transport timeout, so the timeout-translation path cannot be exercised",
            )
        assert "timed out" in combined or "timeout" in combined, f"error did not name a timeout: {combined[:200]!r}"
        assert elapsed < 20.0, f"timeout took too long to surface: {elapsed:.1f}s"

        await provider.disconnect()
