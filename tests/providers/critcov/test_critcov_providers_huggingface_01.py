# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Drive the real HuggingFace provider against loopback servers.

The provider talks to two kinds of endpoint. The Hub client (``HfApi``) is synchronous and always targets
the Hub origin, so the tests point it at a loopback server through ``huggingface_hub``'s public
``set_client_factory`` hook, which rewrites the request URL before it is sent. The inference client
(``AsyncInferenceClient``) and the router catalog query follow the provider's own ``api_base``, so they
are pointed at a loopback server through the credentials. Every request is answered locally by
``ScriptedHTTPServer``; nothing leaves the machine and no real token is used.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, cast
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from huggingface_hub import AsyncInferenceClient, set_async_client_factory, set_client_factory
from huggingface_hub.errors import HfHubHTTPError

from intellicrack.core.types import (
    AuthenticationError,
    Message,
    ProviderCredentials,
    ProviderError,
    RateLimitError,
    ThinkingConfig,
    ToolChoice,
    ToolChoiceMode,
    ToolDefinition,
    ToolFunction,
    ToolParameter,
)
from intellicrack.providers.huggingface import HuggingFaceProvider
from tests._helpers.scripted_sdk_server import ScriptedHTTPServer, ScriptedResponse, json_response, sse_response


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable, Callable, Generator, Mapping


_TOKEN: Final[str] = "hf" + "_" + "loopback" + "Token" + "01" * 5
_MODEL: Final[str] = "org/served-model"
_VISION_MODEL: Final[str] = "org/other-served"
_UNSERVED_MODEL: Final[str] = "org/unserved-model"
_ROUTER_ONLY_MODEL: Final[str] = "org/router-only-model"
_WHOAMI_PATH: Final[str] = "/api/whoami-v2"
_HUB_MODELS_PATH: Final[str] = "/api/models"
_ROUTER_MODELS_PATH: Final[str] = "/v1/models"
_COMPLETIONS_PATH: Final[str] = "/v1/chat/completions"
_TIMEOUT: Final[float] = 30.0
_ERROR_BODY: Final[dict[str, Any]] = {"error": "Model is loading", "estimated_time": 20.0}
_LOADING_TEXT: Final[str] = "Model is loading (estimated_time=20.0s)"

_HUB_MODELS: Final[list[dict[str, Any]]] = [
    {"id": _MODEL, "pipeline_tag": "text-generation", "tags": ["text-generation", "tool-use"]},
    {"id": _UNSERVED_MODEL, "pipeline_tag": "text-generation", "tags": ["text-generation"]},
    {"id": _VISION_MODEL, "pipeline_tag": "image-text-to-text", "tags": ["multimodal"]},
]
_ROUTER_MODELS: Final[dict[str, Any]] = {
    "object": "list",
    "data": [{"id": _MODEL}, {"id": _VISION_MODEL}, {"id": _ROUTER_ONLY_MODEL}],
}

_OPERATIONS: Final[tuple[str, ...]] = ("connect", "hub_listing", "router_listing", "chat", "stream")
_COMMON_FAILURES: Final[tuple[tuple[int, type[ProviderError], str], ...]] = (
    (401, AuthenticationError, "Invalid HuggingFace API token"),
    (403, AuthenticationError, "Invalid HuggingFace API token"),
    (429, RateLimitError, "rate limit exceeded"),
    (503, ProviderError, _LOADING_TEXT),
)
_UNMAPPED_FAILURES: Final[tuple[tuple[str, str], ...]] = (
    ("connect", "Failed to connect to HuggingFace"),
    ("hub_listing", "Failed to list HuggingFace models"),
    ("router_listing", "Failed to fetch the HuggingFace Inference Providers served-model catalog"),
    ("chat", "HuggingFace API error"),
    ("stream", "HuggingFace API error"),
)


@dataclass
class _HubWiring:
    """Mutable controls for the loopback wiring of the Hub clients.

    Attributes:
        port: Loopback port that Hub requests are rewritten to.
        sync_faults: Exceptions raised, one per request, by the next synchronous Hub requests.
        async_faults: Exceptions raised, one per request, by the next inference requests.
    """

    port: int
    sync_faults: list[Exception] = field(default_factory=list[Exception])
    async_faults: list[Exception] = field(default_factory=list[Exception])


def _port_of(origin: str) -> int:
    """Return the port of a loopback origin.

    Args:
        origin: An ``http://127.0.0.1:<port>`` origin.

    Returns:
        int: The port number.
    """
    port = urlsplit(origin).port
    assert port is not None
    return port


@contextlib.contextmanager
def _hub_pointed_at(origin: str) -> Generator[_HubWiring]:
    """Route the Hub's synchronous client to a loopback origin and arm the inference client.

    Installs HTTP client factories through ``huggingface_hub``'s public setters and restores the factories
    that were installed before, closing the shared Hub session each time.

    Args:
        origin: The loopback origin that Hub requests are rewritten to.

    Yields:
        _HubWiring: Controls for the port and for queued transport faults.
    """
    http_module = importlib.import_module("huggingface_hub.utils._http")
    previous_sync = cast("Callable[[], httpx.Client]", getattr(http_module, "_GLOBAL_CLIENT_FACTORY"))
    previous_async = cast("Callable[[], httpx.AsyncClient]", getattr(http_module, "_GLOBAL_ASYNC_CLIENT_FACTORY"))
    response_hook = cast("Callable[[httpx.Response], Awaitable[None]]", getattr(http_module, "async_hf_response_event_hook"))
    wiring = _HubWiring(port=_port_of(origin))

    def _redirect_or_fail(request: httpx.Request) -> None:
        """Rewrite a Hub request to the loopback port, or raise a queued fault.

        Args:
            request: The outgoing Hub request.

        Raises:
            wiring.sync_faults.pop: The next queued synchronous fault, when one is waiting.
        """
        if wiring.sync_faults:
            raise wiring.sync_faults.pop(0)
        request.url = request.url.copy_with(scheme="http", host="127.0.0.1", port=wiring.port)

    async def _fail_if_queued(request: httpx.Request) -> None:
        """Raise a queued fault before an inference request is sent.

        Args:
            request: The outgoing inference request.

        Raises:
            wiring.async_faults.pop: The next queued inference fault, when one is waiting.
        """
        del request
        await asyncio.sleep(0)
        if wiring.async_faults:
            raise wiring.async_faults.pop(0)

    def _sync_client() -> httpx.Client:
        """Build the synchronous Hub client.

        Returns:
            httpx.Client: A client that rewrites requests to the loopback server.
        """
        return httpx.Client(event_hooks={"request": [_redirect_or_fail]}, follow_redirects=True, timeout=10.0)

    def _async_client() -> httpx.AsyncClient:
        """Build the asynchronous inference client.

        Returns:
            httpx.AsyncClient: A client that raises queued faults and reads error bodies like the stock one.
        """
        return httpx.AsyncClient(
            event_hooks={"request": [_fail_if_queued], "response": [response_hook]},
            follow_redirects=True,
            timeout=_TIMEOUT,
        )

    set_client_factory(_sync_client)
    set_async_client_factory(_async_client)
    try:
        yield wiring
    finally:
        set_client_factory(previous_sync)
        set_async_client_factory(previous_async)


@contextlib.contextmanager
def _loopback(routes: Mapping[tuple[str, str], ScriptedResponse]) -> Generator[tuple[ScriptedHTTPServer, _HubWiring]]:
    """Serve scripted routes on loopback and point the Hub clients at them.

    Args:
        routes: Scripted responses keyed by ``(method, path)``.

    Yields:
        tuple[ScriptedHTTPServer, _HubWiring]: The running server and the Hub wiring controls.
    """
    with ScriptedHTTPServer(routes) as server, _hub_pointed_at(server.origin) as wiring:
        yield server, wiring


def _dead_origin() -> str:
    """Return a loopback origin on which nothing listens.

    Returns:
        str: The origin of a server that has already been shut down.
    """
    with ScriptedHTTPServer({}) as dead:
        return dead.origin


def _credentials(origin: str, *, timeout: float | None = _TIMEOUT) -> ProviderCredentials:
    """Build credentials that target a loopback origin.

    Args:
        origin: The loopback origin used as ``api_base``.
        timeout: Request timeout in seconds, or ``None`` for the provider default.

    Returns:
        ProviderCredentials: Credentials carrying the loopback token.
    """
    return ProviderCredentials(api_key=_TOKEN, api_base=origin, timeout=timeout)


@contextlib.asynccontextmanager
async def _connected(origin: str, *, request_timeout: float | None = _TIMEOUT) -> AsyncGenerator[HuggingFaceProvider]:
    """Connect a provider to a loopback origin and always disconnect it afterwards.

    Args:
        origin: The loopback origin used as ``api_base``.
        request_timeout: Request timeout in seconds, or ``None`` for the provider default.

    Yields:
        HuggingFaceProvider: The connected provider.
    """
    provider = HuggingFaceProvider()
    try:
        await provider.connect(_credentials(origin, timeout=request_timeout))
        yield provider
    finally:
        await provider.disconnect()


def _user() -> list[Message]:
    """Build a one-message conversation.

    Returns:
        list[Message]: A conversation holding a single user message.
    """
    return [Message(role="user", content="hello")]


def _tool() -> ToolDefinition:
    """Build a tool definition with one function.

    Returns:
        ToolDefinition: A disassembler tool.
    """
    return ToolDefinition(
        tool_name="radare2",
        description="Disassembler",
        functions=[
            ToolFunction(
                name="radare2.disassemble",
                description="Disassemble at an address",
                parameters=[ToolParameter(name="address", type="string", description="Address", required=True)],
                returns="Listing",
            ),
        ],
    )


def _completion(*, content: str | None, tool_calls: list[dict[str, Any]] | None = None, empty: bool = False) -> dict[str, Any]:
    """Build a non-streaming chat completion body.

    Args:
        content: Assistant text, or ``None``.
        tool_calls: Tool calls to attach to the assistant message.
        empty: Whether to return no choices at all.

    Returns:
        dict[str, Any]: The completion body.
    """
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    choices = [] if empty else [{"index": 0, "finish_reason": "stop", "message": message}]
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 0,
        "model": _MODEL,
        "system_fingerprint": "fp",
        "choices": choices,
        "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10},
    }


def _chunk(
    *,
    content: str | None = None,
    tool_call: dict[str, Any] | None = None,
    usage: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Build one streaming chunk body.

    Args:
        content: Text delta, or ``None``.
        tool_call: One tool-call delta, or ``None``.
        usage: Usage block; when given the chunk carries no choices.

    Returns:
        dict[str, Any]: The chunk body.
    """
    delta: dict[str, Any] = {"role": "assistant"}
    if content is not None:
        delta["content"] = content
    if tool_call is not None:
        delta["tool_calls"] = [tool_call]
    chunk: dict[str, Any] = {
        "id": "chunk-1",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": _MODEL,
        "system_fingerprint": "fp",
        "choices": [{"index": 0, "delta": delta, "finish_reason": None}],
    }
    if usage is not None:
        chunk["choices"] = []
        chunk["usage"] = usage
    return chunk


def _stream_with_garbage(first_piece: str) -> ScriptedResponse:
    """Build a stream whose second frame is not valid JSON.

    Args:
        first_piece: Text carried by the valid first frame.

    Returns:
        ScriptedResponse: The streaming response.
    """
    frames = f"data: {json.dumps(_chunk(content=first_piece))}\n\ndata: {{not json\n\n"
    return ScriptedResponse(status=200, body=frames.encode(), content_type="text/event-stream")


def _routes(
    *,
    whoami: ScriptedResponse | None = None,
    hub_models: ScriptedResponse | None = None,
    router_models: ScriptedResponse | None = None,
    completions: ScriptedResponse | None = None,
) -> dict[tuple[str, str], ScriptedResponse]:
    """Build the full route table, answering success unless a route is overridden.

    Args:
        whoami: Replacement answer for the Hub identity probe.
        hub_models: Replacement answer for the Hub model listing.
        router_models: Replacement answer for the router model catalog.
        completions: Replacement answer for chat completions.

    Returns:
        dict[tuple[str, str], ScriptedResponse]: Responses keyed by ``(method, path)``.
    """
    return {
        ("GET", _WHOAMI_PATH): whoami or json_response({"type": "user", "name": "loopback-user"}),
        ("GET", _HUB_MODELS_PATH): hub_models or json_response(_HUB_MODELS),
        ("GET", _ROUTER_MODELS_PATH): router_models or json_response(_ROUTER_MODELS),
        ("POST", _COMPLETIONS_PATH): completions or json_response(_completion(content="ok")),
    }


def _routes_failing(operation: str, response: ScriptedResponse) -> dict[tuple[str, str], ScriptedResponse]:
    """Build a route table in which the route behind one operation fails.

    Args:
        operation: One of ``_OPERATIONS``.
        response: The failing response.

    Returns:
        dict[tuple[str, str], ScriptedResponse]: Responses keyed by ``(method, path)``.
    """
    failing_key = {
        "connect": ("GET", _WHOAMI_PATH),
        "hub_listing": ("GET", _HUB_MODELS_PATH),
        "router_listing": ("GET", _ROUTER_MODELS_PATH),
        "chat": ("POST", _COMPLETIONS_PATH),
        "stream": ("POST", _COMPLETIONS_PATH),
    }[operation]
    routes = _routes()
    routes[failing_key] = response
    return routes


async def _consume(provider: HuggingFaceProvider, model: str = _MODEL) -> list[str]:
    """Drain a chat stream.

    Args:
        provider: A connected provider.
        model: The model to stream from.

    Returns:
        list[str]: The text pieces in arrival order.
    """
    return [piece async for piece in provider.chat_stream(_user(), model)]


async def _drain_into(provider: HuggingFaceProvider, sink: Callable[[str], object]) -> None:
    """Hand each piece of a chat stream to a sink as soon as it arrives.

    Args:
        provider: A connected provider.
        sink: Receives every text piece.
    """
    async for piece in provider.chat_stream(_user(), _MODEL):
        sink(piece)


async def _drive(operation: str, origin: str) -> None:
    """Connect a provider and run one operation against a loopback origin.

    Args:
        operation: One of ``_OPERATIONS``.
        origin: The loopback origin used as ``api_base``.
    """
    async with _connected(origin) as provider:
        if operation in {"hub_listing", "router_listing"}:
            await provider.list_models()
        elif operation == "chat":
            await provider.chat(_user(), _MODEL)
        elif operation == "stream":
            await _consume(provider)


async def _outcome(awaitable: Awaitable[object]) -> BaseException | None:
    """Await a call and return the provider or transport error it raised, if any.

    Args:
        awaitable: The call to await.

    Returns:
        BaseException | None: The error that escaped the call, or ``None`` when it returned.
    """
    try:
        await awaitable
    except (ProviderError, httpx.HTTPError) as exc:
        return exc
    return None


@pytest.mark.asyncio
async def test_connect_configures_client_and_probes_identity() -> None:
    """Connect builds the inference client from the credentials and probes ``whoami`` with the token."""
    with _loopback(_routes()) as (server, _):
        async with _connected(server.origin, request_timeout=12.5) as provider:
            client = provider.client
            assert provider.is_connected is True
            assert isinstance(client, AsyncInferenceClient)
            assert client.model == server.origin
            assert client.timeout == pytest.approx(12.5)
            assert client.token == _TOKEN
        probes = server.requests(_WHOAMI_PATH)
    assert len(probes) == 1
    assert probes[0].method == "GET"
    assert probes[0].headers["authorization"] == f"Bearer {_TOKEN}"
    assert provider.client is None
    assert provider.is_connected is False


@pytest.mark.asyncio
async def test_connect_without_timeout_uses_two_minute_default() -> None:
    """Credentials without a timeout give the inference client a 120 second timeout."""
    with _loopback(_routes()) as (server, _):
        async with _connected(server.origin, request_timeout=None) as provider:
            assert provider.client is not None
            assert provider.client.timeout == pytest.approx(120.0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("operation", "status", "expected", "fragment"),
    [(operation, status, expected, fragment) for operation in _OPERATIONS for status, expected, fragment in _COMMON_FAILURES],
)
async def test_http_status_is_translated_to_typed_error(
    operation: str,
    status: int,
    expected: type[ProviderError],
    fragment: str,
) -> None:
    """Auth, rate-limit and loading statuses become their typed provider errors on every operation.

    Args:
        operation: The provider operation whose backing route fails.
        status: The HTTP status the failing route answers with.
        expected: The exact error type the provider must raise.
        fragment: Text the error message must contain.
    """
    routes = _routes_failing(operation, json_response(_ERROR_BODY, status=status))
    with _loopback(routes) as (server, _), pytest.raises(expected) as info:
        await _drive(operation, server.origin)
    assert type(info.value) is expected
    assert fragment in str(info.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(("operation", "fragment"), _UNMAPPED_FAILURES)
async def test_unmapped_status_becomes_plain_provider_error(operation: str, fragment: str) -> None:
    """A status with no typed mapping becomes a plain provider error carrying the operation's own message.

    Args:
        operation: The provider operation whose backing route fails.
        fragment: Text the error message must contain.
    """
    routes = _routes_failing(operation, json_response(_ERROR_BODY, status=500))
    with _loopback(routes) as (server, _), pytest.raises(ProviderError) as info:
        await _drive(operation, server.origin)
    assert type(info.value) is ProviderError
    assert fragment in str(info.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["chat", "stream"])
async def test_bad_request_becomes_bad_request_provider_error(operation: str) -> None:
    """A 400 from the inference endpoint is reported as a bad request, not as a generic API error.

    Args:
        operation: Either ``chat`` or ``stream``.
    """
    routes = _routes_failing(operation, json_response({"error": "bad payload"}, status=400))
    with _loopback(routes) as (server, _), pytest.raises(ProviderError) as info:
        await _drive(operation, server.origin)
    assert type(info.value) is ProviderError
    assert "HuggingFace bad request" in str(info.value)
    assert "bad payload" in str(info.value)


@pytest.mark.asyncio
async def test_failed_connect_leaves_provider_disconnected_without_client() -> None:
    """A rejected token leaves the provider disconnected and releases its inference client."""
    routes = _routes_failing("connect", json_response({"error": "nope"}, status=401))
    with _loopback(routes) as (server, _):
        provider = HuggingFaceProvider()
        with pytest.raises(AuthenticationError):
            await provider.connect(_credentials(server.origin))
    assert provider.is_connected is False
    assert provider.client is None


@pytest.mark.asyncio
async def test_connect_wraps_transport_oserror_as_connect_failure() -> None:
    """A transport-level connection error during the identity probe becomes a connect failure."""
    with _loopback(_routes()) as (server, wiring):
        wiring.sync_faults.append(ConnectionResetError("peer reset"))
        provider = HuggingFaceProvider()
        with pytest.raises(ProviderError) as info:
            await provider.connect(_credentials(server.origin))
    assert type(info.value) is ProviderError
    assert str(info.value) == "Failed to connect to HuggingFace: peer reset"
    assert provider.is_connected is False
    assert provider.client is None


def test_extract_503_message_ignores_non_object_body() -> None:
    """A 503 whose JSON body is not an object falls back to the generic loading message."""
    request = httpx.Request("GET", "http://127.0.0.1/")
    response = httpx.Response(503, json=["model", "loading"], request=request)
    error = HfHubHTTPError("service unavailable", response=response)
    extract = cast("Callable[[BaseException], str]", getattr(HuggingFaceProvider, "_extract_503_message"))

    assert extract(error) == "Model is loading and not yet ready"


@pytest.mark.asyncio
async def test_disconnect_survives_runtime_error_while_closing_client() -> None:
    """A RuntimeError raised while the inference client closes is swallowed and the client released."""

    async def _fail_to_close() -> None:
        """Fail the way a half-torn-down transport does.

        Raises:
            RuntimeError: Always.
        """
        await asyncio.sleep(0)
        message = "transport already torn down"
        raise RuntimeError(message)

    with _loopback(_routes()) as (server, _):
        provider = HuggingFaceProvider()
        await provider.connect(_credentials(server.origin))
        client = provider.client
        assert client is not None
        client.exit_stack.push_async_callback(_fail_to_close)
        await provider.disconnect()
    assert provider.client is None
    assert provider.is_connected is False


@pytest.mark.asyncio
async def test_list_models_returns_hub_catalog_intersected_with_router_served_set() -> None:
    """Only models that are both in the Hub catalog and served by the router are listed, in catalog order."""
    with _loopback(_routes()) as (server, _):
        async with _connected(server.origin) as provider:
            models = await provider.list_models()
            cached = cast("set[str] | None", getattr(provider, "_served_model_ids"))
        hub_requests = [request for request in server.requests() if request.path.startswith(_HUB_MODELS_PATH)]
        router_requests = server.requests(_ROUTER_MODELS_PATH)

    assert [model.id for model in models] == [_MODEL, _VISION_MODEL]
    by_id = {model.id: model for model in models}
    assert by_id[_MODEL].name == "served-model"
    assert by_id[_MODEL].supports_tools is True
    assert by_id[_MODEL].supports_vision is False
    assert by_id[_VISION_MODEL].supports_vision is True
    assert cached == {_MODEL, _VISION_MODEL, _ROUTER_ONLY_MODEL}
    assert len(hub_requests) == 1
    query = parse_qs(urlsplit(hub_requests[0].path).query)
    assert query["filter"] == ["text-generation"]
    assert query["inference_provider"] == ["all"]
    assert query["sort"] == ["downloads"]
    assert query["limit"] == ["100"]
    assert "cardData" not in query
    assert hub_requests[0].headers["authorization"] == f"Bearer {_TOKEN}"
    assert len(router_requests) == 1
    assert router_requests[0].headers["authorization"] == f"Bearer {_TOKEN}"


@pytest.mark.asyncio
async def test_list_models_wraps_undecodable_hub_response() -> None:
    """A Hub listing that is not JSON surfaces as a provider error, not a raw decode error."""
    html = ScriptedResponse(status=200, body=b"<html>not json</html>", content_type="text/html")
    with _loopback(_routes(hub_models=html)) as (server, _), pytest.raises(ProviderError) as info:
        await _drive("hub_listing", server.origin)
    assert type(info.value) is ProviderError
    assert str(info.value).startswith("Failed to list HuggingFace models:")


@pytest.mark.asyncio
async def test_list_models_wraps_unreachable_router_catalog() -> None:
    """A router that cannot be reached makes list_models fail with the served-catalog error."""
    dead = _dead_origin()
    with _loopback(_routes()):
        async with _connected(dead) as provider:
            with pytest.raises(ProviderError) as info:
                await provider.list_models()
    assert type(info.value) is ProviderError
    assert str(info.value).startswith("Failed to fetch the HuggingFace Inference Providers served-model catalog:")


@pytest.mark.asyncio
async def test_fetch_served_model_ids_requires_connection() -> None:
    """Asking a never-connected provider for the served catalog is rejected."""
    provider = HuggingFaceProvider()
    fetch = cast("Callable[[], Awaitable[set[str]]]", getattr(provider, "_fetch_served_model_ids"))

    with pytest.raises(ProviderError) as info:
        await fetch()

    assert str(info.value) == "Not connected to HuggingFace"


@pytest.mark.asyncio
async def test_chat_sends_expected_request_and_returns_content_and_usage() -> None:
    """Chat sends the model, messages and sampling settings, and returns text plus the reported usage."""
    answer = json_response(_completion(content="pong"))
    with _loopback(_routes(completions=answer)) as (server, _):
        async with _connected(server.origin) as provider:
            message, calls = await provider.chat(
                _user(),
                _MODEL,
                temperature=0.25,
                max_tokens=256,
                thinking=ThinkingConfig(enabled=True, budget_tokens=2000),
                enable_cache=True,
            )
            usage = provider.get_pending_usage()
        sent = server.requests(_COMPLETIONS_PATH)

    assert message.role == "assistant"
    assert message.content == "pong"
    assert calls is None
    assert usage is not None
    assert (usage.prompt_tokens, usage.completion_tokens, usage.total_tokens) == (7, 3, 10)
    assert len(sent) == 1
    assert sent[0].headers["authorization"] == f"Bearer {_TOKEN}"
    assert sent[0].body == {
        "model": _MODEL,
        "messages": [{"role": "user", "content": "hello"}],
        "max_tokens": 256,
        "temperature": 0.25,
        "stream": False,
    }


@pytest.mark.asyncio
async def test_chat_forwards_tool_choice_and_parses_tool_calls() -> None:
    """Tools and a required tool choice reach the wire, and a returned tool call is parsed to its canonical name."""
    call = {
        "id": "call_1",
        "type": "function",
        "function": {"name": "radare2__disassemble", "arguments": '{"address": "0x401000"}'},
    }
    answer = json_response(_completion(content=None, tool_calls=[call]))
    with _loopback(_routes(completions=answer)) as (server, _):
        async with _connected(server.origin) as provider:
            message, calls = await provider.chat(
                _user(),
                _MODEL,
                tools=[_tool()],
                tool_choice=ToolChoice(mode=ToolChoiceMode.REQUIRED),
            )
        body = server.requests(_COMPLETIONS_PATH)[0].body

    assert body["tool_choice"] == "required"
    assert [tool["function"]["name"] for tool in body["tools"]] == ["radare2__disassemble"]
    assert message.content is not None
    assert len(message.content) == 0
    assert calls is not None
    assert len(calls) == 1
    assert calls[0].id == "call_1"
    assert calls[0].tool_name == "radare2"
    assert calls[0].function_name == "radare2.disassemble"
    assert calls[0].arguments == {"address": "0x401000"}
    assert message.tool_calls == calls


@pytest.mark.asyncio
async def test_chat_omits_tool_choice_when_no_tools_are_offered() -> None:
    """A tool choice without any tools is not sent to the endpoint."""
    with _loopback(_routes()) as (server, _):
        async with _connected(server.origin) as provider:
            await provider.chat(_user(), _MODEL, tool_choice=ToolChoice(mode=ToolChoiceMode.REQUIRED))
        body = server.requests(_COMPLETIONS_PATH)[0].body

    assert "tool_choice" not in body
    assert "tools" not in body


@pytest.mark.asyncio
async def test_chat_without_choices_is_an_error() -> None:
    """A completion with an empty choices list is reported as an error."""
    answer = json_response(_completion(content=None, empty=True))
    with _loopback(_routes(completions=answer)) as (server, _), pytest.raises(ProviderError) as info:
        await _drive("chat", server.origin)
    assert type(info.value) is ProviderError
    assert str(info.value) == "No response choices returned"


@pytest.mark.asyncio
async def test_chat_and_stream_require_connection() -> None:
    """Chat and chat_stream on a provider that never connected are rejected."""
    provider = HuggingFaceProvider()

    with pytest.raises(ProviderError) as chat_info:
        await provider.chat(_user(), _MODEL)
    with pytest.raises(ProviderError) as stream_info:
        await _consume(provider)

    assert str(chat_info.value) == "Not connected to HuggingFace"
    assert str(stream_info.value) == "Not connected to HuggingFace"


@pytest.mark.asyncio
async def test_chat_rejects_model_missing_from_served_catalog_but_accepts_policy_suffix() -> None:
    """After a catalog refresh an unserved model is refused before any request, and a policy suffix is kept."""
    with _loopback(_routes()) as (server, _):
        async with _connected(server.origin) as provider:
            await provider.list_models()
            with pytest.raises(ProviderError) as info:
                await provider.chat(_user(), _UNSERVED_MODEL)
            refused_requests = server.requests(_COMPLETIONS_PATH)
            await provider.chat(_user(), f"{_MODEL}:cheapest")
        sent = server.requests(_COMPLETIONS_PATH)

    assert _UNSERVED_MODEL in str(info.value)
    assert "Inference Provider" in str(info.value)
    assert refused_requests == []
    assert len(sent) == 1
    assert sent[0].body["model"] == f"{_MODEL}:cheapest"


@pytest.mark.asyncio
async def test_stream_rejects_model_missing_from_served_catalog() -> None:
    """Streaming an unserved model is refused before any request is sent."""
    with _loopback(_routes()) as (server, _):
        async with _connected(server.origin) as provider:
            await provider.list_models()
            with pytest.raises(ProviderError) as info:
                await _consume(provider, _UNSERVED_MODEL)
        sent = server.requests(_COMPLETIONS_PATH)

    assert _UNSERVED_MODEL in str(info.value)
    assert sent == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("operation", "error_type", "fragment"),
    [
        ("chat", TimeoutError, "HuggingFace inference timeout: Inference call timed out"),
        ("stream", TimeoutError, "HuggingFace inference timeout: Inference call timed out"),
        ("chat", ConnectionResetError, "HuggingFace API error: peer reset"),
        ("stream", ConnectionResetError, "HuggingFace stream failed: peer reset"),
    ],
)
async def test_transport_faults_before_response_are_translated(
    operation: str,
    error_type: type[Exception],
    fragment: str,
) -> None:
    """A timeout or connection error raised while sending a chat request becomes a provider error.

    Args:
        operation: Either ``chat`` or ``stream``.
        error_type: The exception the transport raises.
        fragment: Text the provider error must contain.
    """
    with _loopback(_routes()) as (server, wiring):
        wiring.async_faults.append(error_type("peer reset"))
        with pytest.raises(ProviderError) as info:
            await _drive(operation, server.origin)
    assert type(info.value) is ProviderError
    assert fragment in str(info.value)
    assert server.requests(_COMPLETIONS_PATH) == []


@pytest.mark.asyncio
async def test_stream_yields_text_collects_tool_calls_and_usage() -> None:
    """A stream yields its text pieces and leaves the assembled tool call and usage for the caller."""
    events = [
        _chunk(content="Hel"),
        _chunk(content="lo"),
        _chunk(
            tool_call={
                "index": 0,
                "id": "call_1",
                "type": "function",
                "function": {"name": "radare2__disassemble", "arguments": '{"address": '},
            },
        ),
        _chunk(tool_call={"index": 0, "function": {"arguments": '"0x401000"}'}}),
        _chunk(usage={"prompt_tokens": 11, "completion_tokens": 4, "total_tokens": 15}),
    ]
    answer = sse_response(events, named=False, done_marker=True)
    with _loopback(_routes(completions=answer)) as (server, _):
        async with _connected(server.origin) as provider:
            await provider.cancel_request()
            pieces = [
                piece
                async for piece in provider.chat_stream(
                    _user(),
                    _MODEL,
                    temperature=0.25,
                    max_tokens=256,
                    thinking=ThinkingConfig(enabled=True, budget_tokens=2000),
                    enable_cache=True,
                )
            ]
            calls = provider.get_pending_tool_calls()
            usage = provider.get_pending_usage()
        sent = server.requests(_COMPLETIONS_PATH)

    assert pieces == ["Hel", "lo"]
    assert len(calls) == 1
    assert calls[0].id == "call_1"
    assert calls[0].function_name == "radare2.disassemble"
    assert calls[0].arguments == {"address": "0x401000"}
    assert usage is not None
    assert (usage.prompt_tokens, usage.completion_tokens, usage.total_tokens) == (11, 4, 15)
    assert len(sent) == 1
    assert sent[0].headers["authorization"] == f"Bearer {_TOKEN}"
    assert sent[0].body == {
        "model": _MODEL,
        "messages": [{"role": "user", "content": "hello"}],
        "max_tokens": 256,
        "temperature": 0.25,
        "stream": True,
    }


@pytest.mark.asyncio
async def test_stream_decode_failure_after_first_piece_is_a_stream_error() -> None:
    """A malformed frame mid-stream stops the stream with a stream error after the earlier text was delivered."""
    with _loopback(_routes(completions=_stream_with_garbage("Hel"))) as (server, _):
        async with _connected(server.origin) as provider:
            pieces: list[str] = []
            with pytest.raises(ProviderError) as info:
                await _drain_into(provider, pieces.append)

    assert pieces == ["Hel"]
    assert type(info.value) is ProviderError
    assert str(info.value).startswith("HuggingFace stream failed:")


@pytest.mark.asyncio
async def test_stream_decode_failure_after_cancel_ends_quietly() -> None:
    """A stream that breaks after the caller cancelled ends without an error."""
    with _loopback(_routes(completions=_stream_with_garbage("Hel"))) as (server, _):
        async with _connected(server.origin) as provider:
            pieces: list[str] = []
            async for piece in provider.chat_stream(_user(), _MODEL):
                pieces.append(piece)
                await provider.cancel_request()
            cancelled = cast("bool", getattr(provider, "_cancel_requested"))

    assert pieces == ["Hel"]
    assert cancelled is True


@pytest.mark.asyncio
async def test_connect_translates_unreachable_hub_into_provider_error() -> None:
    """A Hub that cannot be reached during connect fails with a provider error, not a raw transport error."""
    dead = _dead_origin()
    with _hub_pointed_at(dead):
        provider = HuggingFaceProvider()
        try:
            outcome = await _outcome(provider.connect(_credentials(dead)))
        finally:
            await provider.disconnect()

    assert isinstance(outcome, ProviderError), f"connect let {type(outcome).__name__} escape"


@pytest.mark.asyncio
async def test_list_models_translates_unreachable_hub_into_provider_error() -> None:
    """A Hub that goes away after connect fails list_models with a provider error, not a raw transport error."""
    dead = _dead_origin()
    with _loopback(_routes()) as (server, wiring):
        async with _connected(server.origin) as provider:
            wiring.port = _port_of(dead)
            outcome = await _outcome(provider.list_models())

    assert isinstance(outcome, ProviderError), f"list_models let {type(outcome).__name__} escape"


@pytest.mark.asyncio
async def test_chat_translates_unreachable_endpoint_into_provider_error() -> None:
    """An inference endpoint that cannot be reached fails chat with a provider error, not a raw transport error."""
    dead = _dead_origin()
    with _loopback(_routes()):
        async with _connected(dead) as provider:
            outcome = await _outcome(provider.chat(_user(), _MODEL))

    assert isinstance(outcome, ProviderError), f"chat let {type(outcome).__name__} escape"


@pytest.mark.asyncio
async def test_stream_translates_unreachable_endpoint_into_provider_error() -> None:
    """An inference endpoint that cannot be reached fails chat_stream with a provider error, not a raw transport error."""
    dead = _dead_origin()
    with _loopback(_routes()):
        async with _connected(dead) as provider:
            outcome = await _outcome(_consume(provider))

    assert isinstance(outcome, ProviderError), f"chat_stream let {type(outcome).__name__} escape"
