# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for the Google provider's error mapping, stream handling and response parsing.

The provider runs over the real ``google-genai`` SDK against a loopback Gemini endpoint that replays scripted JSON and server-sent-event
bodies, so every status code, error body and stream chunk travels through the SDK's own HTTP stack before the provider sees it. The pure
response-parsing helpers are fed real ``google.genai.types`` objects. Expected values are derived from the Gemini REST contract (status
codes, field names, the ``__`` wire spelling of dotted tool names) and from arithmetic on the scripted payloads, not from the provider's
own output.
"""

from __future__ import annotations

import asyncio
import base64
from typing import TYPE_CHECKING, Any, Final, cast, override

import pytest
import pytest_asyncio
from google.genai import types
from google.genai.errors import APIError

from intellicrack.core.types import (
    AuthenticationError,
    Message,
    ProviderCredentials,
    ProviderError,
    RateLimitError,
    ReasoningItem,
    ReasoningKind,
    ToolCall,
    ToolChoice,
    ToolChoiceMode,
    ToolDefinition,
    ToolFunction,
    ToolParameter,
)
from intellicrack.providers.base import UsageInfo
from intellicrack.providers.google import GoogleProvider
from tests._helpers.provider_state import isolate_provider_environment
from tests._helpers.scripted_sdk_server import ScriptedHTTPServer, ScriptedResponse, json_response, sse_response


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, AsyncIterator, Mapping, Sequence


type _Routes = Mapping[tuple[str, str], ScriptedResponse | Sequence[ScriptedResponse]]

_API_KEY: Final[str] = "AIza" + "LoopbackCoverageKey0123456789"
_MODEL: Final[str] = "gemini-2.5-flash"
_MODELS_PATH: Final[str] = "/v1beta/models"
_GENERATE_PATH: Final[str] = f"/v1beta/models/{_MODEL}:generateContent"
_STREAM_PATH: Final[str] = f"/v1beta/models/{_MODEL}:streamGenerateContent"
_WAIT_SECONDS: Final[float] = 5.0
_QUOTA_FRAGMENT: Final[str] = "quota or spending cap exhausted"
_CAP_TEXT: Final[str] = "Your project has exceeded its monthly spending cap."
_BUSY_TEXT: Final[str] = "Too many requests, slow down."
_SPAWN_ARGUMENTS: Final[dict[str, str]] = {"target": "calc.exe"}

_iter_function_call_parts: Any = getattr(GoogleProvider, "_iter_function_call_parts")
_parse_response: Any = getattr(GoogleProvider, "_parse_response")
_create_config: Any = getattr(GoogleProvider, "_create_config")
_extract_visible_chunk_text: Any = getattr(GoogleProvider, "_extract_visible_chunk_text")
_extract_thinking_text: Any = getattr(GoogleProvider, "_extract_thinking_text")
_build_function_call_part: Any = getattr(GoogleProvider, "_build_function_call_part")


class _Harness:
    """Owns the loopback servers and the connected providers of one test."""

    def __init__(self) -> None:
        """Start with no servers and no providers."""
        self._servers: list[ScriptedHTTPServer] = []
        self._providers: list[GoogleProvider] = []

    def start(self, routes: _Routes) -> ScriptedHTTPServer:
        """Start a loopback server that replays scripted responses.

        Args:
            routes: Responses keyed by ``(method, path)``.

        Returns:
            ScriptedHTTPServer: The running server.
        """
        server = ScriptedHTTPServer(routes)
        self._servers.append(server)
        return server

    async def connect(self, server: ScriptedHTTPServer) -> GoogleProvider:
        """Connect a real Google provider to a loopback server.

        Args:
            server: The server to point the SDK at.

        Returns:
            GoogleProvider: The connected provider.
        """
        provider = GoogleProvider()
        self._providers.append(provider)
        await provider.connect(ProviderCredentials(api_key=_API_KEY, api_base=server.origin))
        return provider

    async def close(self) -> None:
        """Disconnect every provider, then stop every server."""
        try:
            for provider in self._providers:
                await provider.disconnect()
        finally:
            for server in self._servers:
                server.close()


class _FailingCleanupProvider(GoogleProvider):
    """A Google provider whose SDK-client cleanup fails the way a broken transport does."""

    @override
    async def _close_client(self) -> None:
        """Fail instead of closing the client.

        Raises:
            ConnectionError: Always.
        """
        message = "transport torn down mid-close"
        raise ConnectionError(message)


@pytest_asyncio.fixture
async def harness(monkeypatch: pytest.MonkeyPatch) -> AsyncGenerator[_Harness]:
    """Provide servers and providers in an environment free of provider variables.

    Args:
        monkeypatch: Removes every variable the SDK or the provider reads.

    Yields:
        _Harness: The harness; its providers and servers are released afterwards.
    """
    isolate_provider_environment(monkeypatch)
    owned = _Harness()
    try:
        yield owned
    finally:
        await owned.close()


def _listing() -> ScriptedResponse:
    """Build an empty model listing, enough for the connect probe.

    Returns:
        ScriptedResponse: A ``200`` with no models.
    """
    return json_response({"models": []})


def _error_body(status: int, text: str) -> dict[str, Any]:
    """Build the JSON error body the Gemini API sends with a failing status.

    Args:
        status: The HTTP status code.
        text: The error message.

    Returns:
        dict[str, Any]: The error body.
    """
    return {"error": {"code": status, "message": text, "status": "LOOPBACK_ERROR"}}


def _failure(status: int, text: str = "refused by the loopback endpoint") -> ScriptedResponse:
    """Build a failing response.

    Args:
        status: The HTTP status code.
        text: The error message.

    Returns:
        ScriptedResponse: The response carrying the Gemini error body.
    """
    return json_response(_error_body(status, text), status=status)


def _chunk(
    parts: Sequence[Mapping[str, Any]],
    *,
    finish_reason: str | None = None,
    usage: tuple[int, int, int] | None = None,
) -> dict[str, Any]:
    """Build one ``GenerateContentResponse`` body or stream chunk.

    Args:
        parts: The first candidate's content parts.
        finish_reason: The candidate's finish reason, if any.
        usage: Prompt, candidate and total token counts, if any.

    Returns:
        dict[str, Any]: The body.
    """
    candidate: dict[str, Any] = {"content": {"role": "model", "parts": list(parts)}, "index": 0}
    if finish_reason is not None:
        candidate["finishReason"] = finish_reason
    body: dict[str, Any] = {"candidates": [candidate], "modelVersion": "gemini"}
    if usage is not None:
        prompt, completion, total = usage
        body["usageMetadata"] = {"promptTokenCount": prompt, "candidatesTokenCount": completion, "totalTokenCount": total}
    return body


def _spawn_call() -> dict[str, Any]:
    """Build a ``functionCall`` part naming ``frida.spawn`` in its wire spelling.

    Returns:
        dict[str, Any]: The part.
    """
    return {"functionCall": {"name": "frida__spawn", "args": dict(_SPAWN_ARGUMENTS)}}


def _hello() -> list[Message]:
    """Build a one-message conversation.

    Returns:
        list[Message]: A single user message.
    """
    return [Message(role="user", content="hello")]


async def _drain(stream: AsyncIterator[str]) -> tuple[list[str], ProviderError | None]:
    """Consume a text stream, keeping what was delivered before any failure.

    Args:
        stream: The text stream.

    Returns:
        tuple[list[str], ProviderError | None]: The delivered text, and the error that ended the stream, if any.
    """
    pieces: list[str] = []
    iterator = aiter(stream)
    try:
        while True:
            pieces.append(await anext(iterator))
    except StopAsyncIteration:
        return pieces, None
    except ProviderError as error:
        return pieces, error


def _tool() -> ToolDefinition:
    """Build one tool definition with one required string argument.

    Returns:
        ToolDefinition: A tool with one function.
    """
    return ToolDefinition(
        tool_name="frida",
        description="Dynamic instrumentation",
        functions=[
            ToolFunction(
                name="frida.spawn",
                description="Spawn a process",
                parameters=[ToolParameter(name="target", type="string", description="Executable", required=True)],
                returns="Process id",
            ),
        ],
    )


def _response(*candidates: types.Candidate) -> types.GenerateContentResponse:
    """Build a real SDK response holding the given candidates.

    Args:
        *candidates: The candidates.

    Returns:
        types.GenerateContentResponse: The response.
    """
    return types.GenerateContentResponse(candidates=list(candidates))


def _candidate(*parts: types.Part) -> types.Candidate:
    """Build a real SDK candidate holding the given parts.

    Args:
        *parts: The content parts.

    Returns:
        types.Candidate: The candidate.
    """
    return types.Candidate(content=types.Content(role="model", parts=list(parts)))


_CONNECT_FAILURES = (
    pytest.param(401, AuthenticationError, "Invalid API key", id="unauthorized"),
    pytest.param(403, AuthenticationError, "Invalid API key", id="forbidden"),
    pytest.param(429, RateLimitError, "Rate limited", id="rate-limited"),
    pytest.param(400, ProviderError, "Connection failed", id="bad-request"),
)


@pytest.mark.asyncio
@pytest.mark.parametrize(("status", "expected_type", "expected_message"), _CONNECT_FAILURES)
async def test_connect_maps_probe_failure_to_typed_error(
    harness: _Harness,
    status: int,
    expected_type: type[ProviderError],
    expected_message: str,
) -> None:
    """A failing status on the connect probe becomes the matching typed error and leaves the provider disconnected.

    Gemini answers 401 or 403 for a rejected key and 429 for a rate limit; any other failure is a plain connection failure.

    One-line change that fails it: remove 403 from ``_AUTH_STATUS_CODES`` (google.py:81), or swap the raises at google.py:158 and 160.

    Args:
        harness: Loopback servers and providers.
        status: The HTTP status the probe receives.
        expected_type: The exact error type the provider must raise.
        expected_message: The exact message of that error.
    """
    server = harness.start({("GET", _MODELS_PATH): _failure(status)})
    provider = GoogleProvider()

    with pytest.raises(ProviderError) as raised:
        await provider.connect(ProviderCredentials(api_key=_API_KEY, api_base=server.origin))

    assert type(raised.value) is expected_type
    assert str(raised.value) == expected_message
    cause = raised.value.__cause__
    assert isinstance(cause, APIError)
    assert cause.code == status
    assert provider.connected is False
    assert provider.client is None


@pytest.mark.asyncio
async def test_disconnect_swallows_a_failing_client_cleanup() -> None:
    """A cleanup that fails with a connection error does not escape ``disconnect`` and leaves the provider disconnected.

    One-line change that fails it: delete the ``except`` clause at google.py:252 so the ``ConnectionError`` propagates.
    """
    provider = _FailingCleanupProvider()
    provider.connected = True

    await provider.disconnect()

    assert provider.connected is False
    assert provider.is_connected is False


_LIST_FAILURES = (
    pytest.param(401, AuthenticationError, "Invalid API key", id="unauthorized"),
    pytest.param(403, AuthenticationError, "Invalid API key", id="forbidden"),
    pytest.param(429, RateLimitError, "Rate limited", id="rate-limited"),
    pytest.param(400, ProviderError, "Failed to fetch models from Google API", id="bad-request"),
)


@pytest.mark.asyncio
@pytest.mark.parametrize(("status", "expected_type", "expected_message"), _LIST_FAILURES)
async def test_list_models_maps_api_failure_to_typed_error(
    harness: _Harness,
    status: int,
    expected_type: type[ProviderError],
    expected_message: str,
) -> None:
    """A failing status on the model listing becomes the matching typed error.

    The connect probe is the first request and succeeds; the listing is the second and fails.

    One-line change that fails it: swap the raises at google.py:282 and 284.

    Args:
        harness: Loopback servers and providers.
        status: The HTTP status the listing receives.
        expected_type: The exact error type the provider must raise.
        expected_message: The exact message of that error.
    """
    server = harness.start({("GET", _MODELS_PATH): [_listing(), _failure(status)]})
    provider = await harness.connect(server)

    with pytest.raises(ProviderError) as raised:
        _ = await provider.list_models()

    assert type(raised.value) is expected_type
    assert str(raised.value) == expected_message
    cause = raised.value.__cause__
    assert isinstance(cause, APIError)
    assert cause.code == status


@pytest.mark.asyncio
async def test_list_models_wraps_a_malformed_listing_as_provider_error(harness: _Harness) -> None:
    """A listing whose body is not JSON surfaces as the fetch-failed ``ProviderError`` chained from the decode error.

    One-line change that fails it: remove ``ValueError`` from the ``except`` tuple at google.py:286.

    Args:
        harness: Loopback servers and providers.
    """
    server = harness.start({("GET", _MODELS_PATH): [_listing(), ScriptedResponse(status=200, body=b"<<this is not json>>")]})
    provider = await harness.connect(server)

    with pytest.raises(ProviderError) as raised:
        _ = await provider.list_models()

    assert type(raised.value) is ProviderError
    assert str(raised.value) == "Failed to fetch models from Google API"
    assert isinstance(raised.value.__cause__, ValueError)


@pytest.mark.asyncio
async def test_fetch_and_sort_models_requires_a_client() -> None:
    """Fetching models before any client exists is a ``Not connected`` ``ProviderError``.

    One-line change that fails it: replace ``is None`` with ``is not None`` at google.py:304.
    """
    provider = GoogleProvider()
    fetch_and_sort_models: Any = getattr(provider, "_fetch_and_sort_models")

    with pytest.raises(ProviderError) as raised:
        _ = await fetch_and_sort_models()

    assert type(raised.value) is ProviderError
    assert str(raised.value) == "Not connected"


@pytest.mark.asyncio
async def test_list_models_keeps_chat_models_that_state_no_actions(harness: _Harness) -> None:
    """A Gemini model whose listing omits ``supportedGenerationMethods`` is kept, and its stated limits are still ingested.

    One-line change that fails it: change google.py:347 to ``if actions is None or _GENERATE_CONTENT_ACTION not in actions:``.

    Args:
        harness: Loopback servers and providers.
    """
    entry = {
        "name": "models/gemini-legacy-chat",
        "displayName": "Gemini Legacy Chat",
        "inputTokenLimit": 32_768,
        "outputTokenLimit": 2_048,
    }
    server = harness.start({("GET", _MODELS_PATH): json_response({"models": [entry]})})
    provider = await harness.connect(server)

    models = {model.id: model for model in await provider.list_models()}

    assert set(models) == {"gemini-legacy-chat"}
    assert models["gemini-legacy-chat"].name == "Gemini Legacy Chat"
    assert models["gemini-legacy-chat"].context_window == 32_768
    assert provider.capabilities_for("gemini-legacy-chat").max_output_tokens == 2_048


@pytest.mark.asyncio
async def test_chat_requires_connection() -> None:
    """Chatting on a provider that never connected is a ``Not connected`` ``ProviderError``.

    One-line change that fails it: remove the ``raise`` at google.py:409.
    """
    provider = GoogleProvider()

    with pytest.raises(ProviderError) as raised:
        _ = await provider.chat(_hello(), _MODEL)

    assert type(raised.value) is ProviderError
    assert str(raised.value) == "Not connected"


@pytest.mark.asyncio
async def test_chat_stream_requires_connection() -> None:
    """Streaming on a provider that never connected is a ``Not connected`` ``ProviderError``.

    One-line change that fails it: remove the ``raise`` at google.py:622.
    """
    provider = GoogleProvider()

    with pytest.raises(ProviderError) as raised:
        async for _piece in provider.chat_stream(_hello(), _MODEL):
            pass

    assert type(raised.value) is ProviderError
    assert str(raised.value) == "Not connected"


@pytest.mark.asyncio
async def test_run_google_chat_requires_a_client() -> None:
    """The chat executor refuses to run when the client has gone, as after a disconnect that raced the request.

    One-line change that fails it: remove the ``raise`` at google.py:516.
    """
    provider = GoogleProvider()
    provider.connected = True
    run_google_chat: Any = getattr(provider, "_run_google_chat")

    with pytest.raises(ProviderError) as raised:
        _ = await run_google_chat(
            model=_MODEL,
            gemini_contents=[],
            gemini_tools=None,
            system_instruction=None,
            temperature=0.2,
            max_tokens=8,
            tool_choice=None,
            thinking=None,
            start_time=0.0,
        )

    assert type(raised.value) is ProviderError
    assert str(raised.value) == "Not connected"


@pytest.mark.asyncio
async def test_iter_google_stream_requires_a_client() -> None:
    """The stream executor refuses to run when the client has gone, as after a disconnect that raced the request.

    One-line change that fails it: remove the ``raise`` at google.py:733.
    """
    provider = GoogleProvider()
    provider.connected = True
    iter_google_stream: Any = getattr(provider, "_iter_google_stream")

    with pytest.raises(ProviderError) as raised:
        async for _piece in iter_google_stream(
            model=_MODEL,
            gemini_contents=[],
            gemini_tools=None,
            system_instruction=None,
            temperature=0.2,
            max_tokens=8,
            tool_choice=None,
            thinking=None,
            chunk_counter=[0],
        ):
            pass

    assert type(raised.value) is ProviderError
    assert str(raised.value) == "Not connected"


_CHAT_FAILURES = (
    pytest.param(401, AuthenticationError, "Invalid API key", id="unauthorized"),
    pytest.param(403, AuthenticationError, "Invalid API key", id="forbidden"),
    pytest.param(400, ProviderError, "Request failed", id="bad-request"),
)


@pytest.mark.asyncio
@pytest.mark.parametrize(("status", "expected_type", "expected_message"), _CHAT_FAILURES)
async def test_chat_maps_non_retryable_api_failure_to_typed_error(
    harness: _Harness,
    status: int,
    expected_type: type[ProviderError],
    expected_message: str,
) -> None:
    """A 4xx other than 429 is mapped to its typed error after exactly one request, since retrying cannot help.

    One-line change that fails it: change ``code >= _HTTP_SERVER_ERROR_MIN`` to ``code >= 400`` at google.py:929, which turns a 400
    into a retried ``RateLimitError``.

    Args:
        harness: Loopback servers and providers.
        status: The HTTP status the generate request receives.
        expected_type: The exact error type the provider must raise.
        expected_message: The exact message of that error.
    """
    server = harness.start({("GET", _MODELS_PATH): _listing(), ("POST", _GENERATE_PATH): _failure(status)})
    provider = await harness.connect(server)

    with pytest.raises(ProviderError) as raised:
        _ = await provider.chat(_hello(), _MODEL)

    assert type(raised.value) is expected_type
    assert str(raised.value) == expected_message
    cause = raised.value.__cause__
    assert isinstance(cause, APIError)
    assert cause.code == status
    assert len(server.requests(_GENERATE_PATH)) == 1


@pytest.mark.asyncio
async def test_chat_reports_permanent_quota_exhaustion_without_retry(harness: _Harness) -> None:
    """A 429 whose message names a spending cap is a ``ProviderError`` about the cap, not a retried rate limit.

    One-line change that fails it: remove the ``is_permanent_quota_error`` clause at google.py:921, which makes it a retried
    ``RateLimitError``.

    Args:
        harness: Loopback servers and providers.
    """
    server = harness.start({("GET", _MODELS_PATH): _listing(), ("POST", _GENERATE_PATH): _failure(429, _CAP_TEXT)})
    provider = await harness.connect(server)

    with pytest.raises(ProviderError) as raised:
        _ = await provider.chat(_hello(), _MODEL)

    assert type(raised.value) is ProviderError
    assert _QUOTA_FRAGMENT in str(raised.value)
    assert "https://ai.studio/spend" in str(raised.value)
    cause = raised.value.__cause__
    assert isinstance(cause, APIError)
    assert cause.code == 429
    assert len(server.requests(_GENERATE_PATH)) == 1


@pytest.mark.asyncio
async def test_chat_wraps_a_malformed_response_as_provider_error(harness: _Harness) -> None:
    """A generate response whose body is not JSON becomes ``Request failed``, chained from the decode error.

    One-line change that fails it: remove ``ValueError`` from the ``except`` tuple at google.py:471.

    Args:
        harness: Loopback servers and providers.
    """
    server = harness.start({
        ("GET", _MODELS_PATH): _listing(),
        ("POST", _GENERATE_PATH): ScriptedResponse(status=200, body=b"<<this is not json>>"),
    })
    provider = await harness.connect(server)

    with pytest.raises(ProviderError) as raised:
        _ = await provider.chat(_hello(), _MODEL)

    assert type(raised.value) is ProviderError
    assert str(raised.value) == "Request failed"
    assert isinstance(raised.value.__cause__, ValueError)


@pytest.mark.asyncio
async def test_chat_surfaces_thoughts_usage_and_tool_calls(harness: _Harness) -> None:
    """A reply of thought, text and function-call parts yields the text, the call, the thought and the token usage separately.

    The thought part must reach the pending thinking and reasoning buffers and not the message; the function call keeps its
    dotted name after the ``__`` wire spelling is undone.

    One-line change that fails it: replace the walrus condition at google.py:552 with ``False``.

    Args:
        harness: Loopback servers and providers.
    """
    body = _chunk(
        [{"text": "weighing the options", "thought": True}, {"text": "Answer"}, _spawn_call()],
        finish_reason="STOP",
        usage=(11, 4, 15),
    )
    server = harness.start({("GET", _MODELS_PATH): _listing(), ("POST", _GENERATE_PATH): json_response(body)})
    provider = await harness.connect(server)

    message, tool_calls = await provider.chat(_hello(), _MODEL)

    expected_call = ToolCall(id="call_0", tool_name="frida", function_name="frida.spawn", arguments=dict(_SPAWN_ARGUMENTS))
    assert message.role == "assistant"
    assert message.content == "Answer"
    assert tool_calls == [expected_call]
    assert message.tool_calls == [expected_call]
    assert provider.get_pending_thinking() == ["weighing the options"]
    assert provider.get_pending_reasoning() == [ReasoningItem(kind=ReasoningKind.THINKING, text="weighing the options")]
    assert provider.get_pending_usage() == UsageInfo(prompt_tokens=11, completion_tokens=4, total_tokens=15)


@pytest.mark.asyncio
async def test_chat_accepts_prompt_feedback_that_blocks_nothing(harness: _Harness) -> None:
    """Prompt feedback without a block reason is not a safety block, and the reply is returned.

    One-line change that fails it: replace ``block_reason is not None`` with ``True`` at google.py:857.

    Args:
        harness: Loopback servers and providers.
    """
    body = _chunk([{"text": "fine"}], finish_reason="STOP", usage=(3, 1, 4))
    body["promptFeedback"] = {"blockReasonMessage": "nothing was blocked"}
    server = harness.start({("GET", _MODELS_PATH): _listing(), ("POST", _GENERATE_PATH): json_response(body)})
    provider = await harness.connect(server)

    message, tool_calls = await provider.chat(_hello(), _MODEL)

    assert message.content == "fine"
    assert tool_calls is None


_STREAM_FAILURES = (
    pytest.param(401, "refused", AuthenticationError, "Invalid API key", id="unauthorized"),
    pytest.param(403, "refused", AuthenticationError, "Invalid API key", id="forbidden"),
    pytest.param(400, "refused", ProviderError, "Stream failed", id="bad-request"),
    pytest.param(429, _BUSY_TEXT, RateLimitError, "Rate limited", id="rate-limited"),
    pytest.param(429, _CAP_TEXT, ProviderError, _QUOTA_FRAGMENT, id="spending-cap"),
)


@pytest.mark.asyncio
@pytest.mark.parametrize(("status", "text", "expected_type", "expected_fragment"), _STREAM_FAILURES)
async def test_chat_stream_maps_api_failure_to_typed_error(
    harness: _Harness,
    status: int,
    text: str,
    expected_type: type[ProviderError],
    expected_fragment: str,
) -> None:
    """A failing status on the stream request becomes the matching typed error, after one request and with no chunk delivered.

    A 429 naming a spending cap is a quota error, while any other 429 is a rate limit.

    One-line change that fails it: remove the ``is_permanent_quota_error`` clause at google.py:680, or swap the raises at
    google.py:679 and 683.

    Args:
        harness: Loopback servers and providers.
        status: The HTTP status the stream request receives.
        text: The error message the endpoint sends.
        expected_type: The exact error type the provider must raise.
        expected_fragment: Text the error message must contain.
    """
    server = harness.start({("GET", _MODELS_PATH): _listing(), ("POST", _STREAM_PATH): _failure(status, text)})
    provider = await harness.connect(server)

    pieces, error = await _drain(provider.chat_stream(_hello(), _MODEL))

    assert error is not None
    assert type(error) is expected_type
    assert expected_fragment in str(error)
    cause = error.__cause__
    assert isinstance(cause, APIError)
    assert cause.code == status
    assert pieces == []
    assert len(server.requests(_STREAM_PATH)) == 1


@pytest.mark.asyncio
async def test_chat_stream_re_raises_a_safety_block_after_partial_text(harness: _Harness) -> None:
    """A chunk finished for safety aborts the stream with the safety ``ProviderError`` once the earlier text was delivered.

    One-line change that fails it: remove the bare ``raise`` at google.py:668, which swallows the block and ends the stream quietly.

    Args:
        harness: Loopback servers and providers.
    """
    chunks = [_chunk([{"text": "partial"}]), _chunk([], finish_reason="SAFETY")]
    server = harness.start({("GET", _MODELS_PATH): _listing(), ("POST", _STREAM_PATH): sse_response(chunks, named=False)})
    provider = await harness.connect(server)

    pieces, error = await _drain(provider.chat_stream(_hello(), _MODEL))

    assert error is not None
    assert type(error) is ProviderError
    assert str(error) == "Response blocked by safety filters: SAFETY"
    assert pieces == ["partial"]


@pytest.mark.asyncio
async def test_chat_stream_collects_thoughts_usage_and_tool_calls(harness: _Harness) -> None:
    """A stream of thought and text chunks ending in a function call yields only the text and buffers the rest.

    Thought-only chunks yield nothing; the thoughts reach the pending buffers in order; the usage and the function call are read
    from the final chunk.

    One-line change that fails it: drop the ``thinking_parts.append`` at google.py:773 or the ``extend`` at google.py:781.

    Args:
        harness: Loopback servers and providers.
    """
    chunks = [
        _chunk([{"text": "plan one", "thought": True}]),
        _chunk([{"text": "plan two", "thought": True}, {"text": "Hello "}]),
        _chunk([{"text": "world"}, _spawn_call()], finish_reason="STOP", usage=(9, 6, 15)),
    ]
    server = harness.start({("GET", _MODELS_PATH): _listing(), ("POST", _STREAM_PATH): sse_response(chunks, named=False)})
    provider = await harness.connect(server)

    pieces = [piece async for piece in provider.chat_stream(_hello(), _MODEL)]

    assert pieces == ["Hello ", "world"]
    assert provider.get_pending_thinking() == ["plan one", "plan two"]
    assert provider.get_pending_reasoning() == [
        ReasoningItem(kind=ReasoningKind.THINKING, text="plan one"),
        ReasoningItem(kind=ReasoningKind.THINKING, text="plan two"),
    ]
    assert provider.get_pending_usage() == UsageInfo(prompt_tokens=9, completion_tokens=6, total_tokens=15)
    assert provider.get_pending_tool_calls() == [
        ToolCall(id="call_0", tool_name="frida", function_name="frida.spawn", arguments=dict(_SPAWN_ARGUMENTS)),
    ]


@pytest.mark.asyncio
async def test_chat_stream_stops_when_cancelled(harness: _Harness) -> None:
    """Cancelling after the first chunk ends the stream there and records neither usage nor tool calls.

    Every scripted chunk carries usage, so a stream that wrongly finished normally would have captured it.

    One-line change that fails it: remove the ``if self._cancel_requested`` check at google.py:763.

    Args:
        harness: Loopback servers and providers.
    """
    chunks = [_chunk([{"text": piece}], usage=(5, 1, 6)) for piece in ("a", "b", "c")]
    server = harness.start({("GET", _MODELS_PATH): _listing(), ("POST", _STREAM_PATH): sse_response(chunks, named=False)})
    provider = await harness.connect(server)
    pieces: list[str] = []

    async for piece in provider.chat_stream(_hello(), _MODEL):
        pieces.append(piece)
        await provider.cancel_request()

    assert pieces == ["a"]
    assert getattr(provider, "_cancel_requested") is True
    assert provider.get_pending_usage() is None
    assert provider.get_pending_tool_calls() == []


@pytest.mark.asyncio
async def test_chat_stream_cache_flag_does_not_change_the_request(harness: _Harness) -> None:
    """Gemini caches implicitly, so asking for caching sends the very same request and streams the same text.

    One-line change that fails it: make google.py:628 add a ``cachedContent`` field to the request.

    Args:
        harness: Loopback servers and providers.
    """
    chunks = [_chunk([{"text": "ok"}], finish_reason="STOP", usage=(2, 1, 3))]
    server = harness.start({("GET", _MODELS_PATH): _listing(), ("POST", _STREAM_PATH): sse_response(chunks, named=False)})
    provider = await harness.connect(server)

    plain = [piece async for piece in provider.chat_stream(_hello(), _MODEL)]
    cached = [piece async for piece in provider.chat_stream(_hello(), _MODEL, enable_cache=True)]

    assert plain == ["ok"]
    assert cached == ["ok"]
    bodies = [request.body for request in server.requests(_STREAM_PATH)]
    assert len(bodies) == 2
    assert bodies[0] == bodies[1]


@pytest.mark.asyncio
async def test_cancel_request_sets_the_flag_when_nothing_is_in_flight() -> None:
    """Cancelling with no request in flight still raises the cancel flag.

    One-line change that fails it: remove ``self._cancel_requested = True`` at google.py:796.
    """
    provider = GoogleProvider()

    await provider.cancel_request()

    assert getattr(provider, "_cancel_requested") is True


@pytest.mark.asyncio
async def test_cancel_request_cancels_the_task_in_flight() -> None:
    """Cancelling while a request task is pending cancels that task and raises the cancel flag.

    The provider's in-flight task slot is a private data attribute with no public way to fill it, so the test places a real,
    never-finishing task there.

    One-line change that fails it: remove ``self._current_task.cancel()`` at google.py:798.
    """
    provider = GoogleProvider()
    never_set = asyncio.Event()
    task = asyncio.create_task(never_set.wait())
    setattr(provider, "_current_task", task)
    try:
        await provider.cancel_request()
        done, _pending = await asyncio.wait([task], timeout=_WAIT_SECONDS)
        assert task in done
        assert task.cancelled()
    finally:
        task.cancel()
        _ = await asyncio.wait([task], timeout=_WAIT_SECONDS)

    assert getattr(provider, "_cancel_requested") is True


def test_create_config_ignores_a_specific_choice_that_names_no_function() -> None:
    """A specific tool choice with no function name configures nothing, while a named one forces that function.

    One-line change that fails it: drop ``and tool_choice.function_name`` at google.py:992, which feeds ``None`` to ``to_wire_name``.
    """
    tools = [types.Tool(function_declarations=[])]

    unnamed = _create_config(0.5, 64, tools, tool_choice=ToolChoice(mode=ToolChoiceMode.SPECIFIC, function_name=None))
    empty = _create_config(0.5, 64, tools, tool_choice=ToolChoice(mode=ToolChoiceMode.SPECIFIC, function_name=""))
    named = _create_config(0.5, 64, tools, tool_choice=ToolChoice(mode=ToolChoiceMode.SPECIFIC, function_name="frida.spawn"))

    assert unnamed.tool_config is None
    assert empty.tool_config is None
    calling = named.tool_config.function_calling_config
    assert calling.mode == types.FunctionCallingConfigMode.ANY
    assert calling.allowed_function_names == ["frida__spawn"]


def test_iter_function_call_parts_pairs_calls_with_their_signatures() -> None:
    """Function-call parts come back with their signatures in order, and a response with no parts gives an empty list.

    One-line change that fails it: delete the ``if not candidates`` guard at google.py:1043, which raises on a response without
    candidates.
    """
    signed = types.Part(function_call=types.FunctionCall(name="frida__spawn", args=dict(_SPAWN_ARGUMENTS)), thought_signature=b"sig")
    unsigned = types.Part(function_call=types.FunctionCall(name="second"))
    response = _response(_candidate(types.Part(text="prelude"), signed, unsigned))

    pairs = _iter_function_call_parts(response)

    assert [call.name for call, _signature in pairs] == ["frida__spawn", "second"]
    assert [signature for _call, signature in pairs] == [b"sig", None]
    assert _iter_function_call_parts(types.GenerateContentResponse()) == []
    assert _iter_function_call_parts(_response(types.Candidate())) == []
    assert _iter_function_call_parts(_response(_candidate())) == []


def test_parse_response_gives_empty_content_for_a_candidate_without_parts() -> None:
    """A candidate with no content, or with an empty parts list, parses to empty text and no tool calls.

    One-line change that fails it: drop ``candidate.content and`` from the condition at google.py:1106, which raises on a
    candidate with no content.
    """
    assert _parse_response(_response(types.Candidate(finish_reason=types.FinishReason.STOP))) == ("", [])
    assert _parse_response(_response(_candidate())) == ("", [])


def test_parse_response_leaves_thought_text_out_of_the_content() -> None:
    """A reply made only of thought parts has no visible content, so the thought text cannot leak into the message.

    One-line change that fails it: remove ``and not getattr(part, "thought", False)`` at google.py:1108.
    """
    thought_only = _response(_candidate(types.Part(text="private reasoning", thought=True)))

    assert _parse_response(thought_only) == ("", [])


def test_extract_visible_chunk_text_has_no_text_without_candidates() -> None:
    """A chunk with no candidates contributes no visible text.

    One-line change that fails it: return ``chunk.text`` without ``or ""`` at google.py:1157, which gives ``None``.
    """
    visible = _extract_visible_chunk_text(types.GenerateContentResponse())

    assert isinstance(visible, str)
    assert not visible


def test_extract_visible_chunk_text_skips_candidates_and_parts_without_text() -> None:
    """Only non-thought parts that carry text are joined; candidates without content, empty parts and textless parts are skipped.

    One-line change that fails it: drop the ``isinstance(text, str)`` test at google.py:1170, which appends ``None`` and breaks the
    join.
    """
    chunk = _response(
        types.Candidate(),
        _candidate(),
        _candidate(
            types.Part(function_call=types.FunctionCall(name="no_text")),
            types.Part(text=""),
            types.Part(text="kept"),
            types.Part(text="hidden", thought=True),
        ),
    )

    assert _extract_visible_chunk_text(chunk) == "kept"


def test_extract_thinking_text_is_empty_without_candidates() -> None:
    """A response with no candidates has no thinking text.

    One-line change that fails it: replace ``return ""`` at google.py:1193 with ``return "x"``.
    """
    thinking = _extract_thinking_text(types.GenerateContentResponse())

    assert isinstance(thinking, str)
    assert not thinking


def test_extract_thinking_text_skips_candidates_and_parts_without_thoughts() -> None:
    """Only thought parts that carry text are joined, by a blank line; candidates without content or thoughts are skipped.

    One-line change that fails it: drop the ``isinstance(text, str)`` test at google.py:1206, which appends ``None`` and breaks the
    join.
    """
    response = _response(
        types.Candidate(),
        _candidate(),
        _candidate(
            types.Part(thought=True),
            types.Part(text="", thought=True),
            types.Part(text="first", thought=True),
            types.Part(text="visible"),
            types.Part(text="second", thought=True),
        ),
    )

    assert _extract_thinking_text(response) == "first\n\nsecond"


def test_build_function_call_part_uses_the_wire_name_and_echoes_the_signature() -> None:
    """A replayed call is written with the ``__`` wire name, and its stored signature is sent back unchanged when present.

    One-line change that fails it: pass ``ToolNameStyle.DOTTED`` at google.py:1231, which sends ``frida.spawn``.
    """
    signature = base64.b64encode(b"opaque-signature").decode("ascii")
    signed = ToolCall(
        id="call_0",
        tool_name="frida",
        function_name="frida.spawn",
        arguments=dict(_SPAWN_ARGUMENTS),
        thought_signature=signature,
    )
    unsigned = ToolCall(id="call_1", tool_name="frida", function_name="frida.spawn", arguments=dict(_SPAWN_ARGUMENTS))

    assert _build_function_call_part(signed) == {
        "function_call": {"name": "frida__spawn", "args": _SPAWN_ARGUMENTS},
        "thought_signature": signature,
    }
    assert _build_function_call_part(unsigned) == {"function_call": {"name": "frida__spawn", "args": _SPAWN_ARGUMENTS}}


def test_convert_tools_to_provider_format_returns_flat_declarations() -> None:
    """The legacy dict conversion returns one flat declaration per function, not a wrapped ``Tool``.

    One-line change that fails it: return ``[]`` at google.py:1316.
    """
    declarations = GoogleProvider().convert_tools_to_provider_format([_tool()])

    assert [declaration["name"] for declaration in declarations] == ["frida__spawn"]
    assert declarations[0]["description"] == "Spawn a process"
    parameters = cast("dict[str, Any]", declarations[0]["parameters"])
    assert parameters["type"] == "OBJECT"
    assert list(parameters["properties"]) == ["target"]
    assert parameters["required"] == ["target"]
