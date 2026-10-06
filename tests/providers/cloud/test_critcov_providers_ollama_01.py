# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Critical-coverage tests for ``intellicrack.providers.ollama``.

Every test drives the real :class:`~intellicrack.providers.ollama.OllamaProvider` against loopback HTTP servers that speak the Ollama
wire formats: ``/api/tags``, ``/api/show``, ``/api/ps``, ``/api/generate``, ``/api/pull`` and the NDJSON ``/api/chat`` stream for a local
daemon, and the OpenAI-compatible ``/v1/chat/completions`` JSON and server-sent-event routes for the Ollama cloud. The cloud endpoint is
a loopback server too: a subclass of the provider points ``CLOUD_API_URL`` at it, which is the only thing the provider consults to find
the cloud. The tests cover the transport and parsing edges of the provider: source selection, model discovery, tool-call assembly from
streamed deltas, usage accounting, cancellation, and the mapping of HTTP and transport failures to typed provider errors.

Expected request bodies and parsed results are written out from the Ollama and OpenAI wire shapes, not read back from the provider. A
server that must stall gates one chunk of its reply on a :class:`threading.Event` that the test sets in ``finally``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import threading
from typing import TYPE_CHECKING, Any, cast

import httpx
import pytest
from structlog.testing import capture_logs

from intellicrack.core.types import (
    AuthenticationError,
    Message,
    ProviderCredentials,
    ProviderError,
    RateLimitError,
    ThinkingConfig,
    ToolCall,
    ToolChoice,
    ToolChoiceMode,
    ToolDefinition,
    ToolFunction,
    ToolParameter,
)
from intellicrack.providers import ids as provider_ids
from intellicrack.providers.ollama import OllamaProvider
from tests._helpers.scripted_http_server import (
    RecordedRequest,
    ScriptedHttpServer,
    ScriptedResponse,
    json_response,
    sse_response,
)


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, AsyncIterator, Callable, Generator, Mapping


_KEY = "loopback-cloud-credential"
_STALL_TIMEOUT = 0.4
_TAGS = "/api/tags"
_SHOW = "/api/show"
_PS = "/api/ps"
_CHAT = "/api/chat"
_GENERATE = "/api/generate"
_PULL = "/api/pull"
_CLOUD_CHAT = "/v1/chat/completions"
_READ_OPERATIONS = ("tags", "running", "show")
_STREAM_ERRORS = [(401, AuthenticationError), (429, RateLimitError), (500, ProviderError)]
_DECOMPILE_TOOL = ToolDefinition(
    tool_name="ghidra",
    description="Ghidra analysis tools",
    functions=[
        ToolFunction(
            name="ghidra.decompile",
            description="Decompile the function at an address",
            parameters=[ToolParameter(name="address", type="string", description="Function address")],
            returns="Decompiled C source",
        ),
    ],
)


def _hello() -> list[Message]:
    """Build a one-message conversation.

    Returns:
        list[Message]: A single user message saying ``hi``.
    """
    return [Message(role="user", content="hi")]


def _tags(*names: str) -> ScriptedResponse:
    """Build an ``/api/tags`` reply listing the given model names.

    Args:
        *names: Model names to list.

    Returns:
        ScriptedResponse: The ``200`` reply.
    """
    return json_response(200, {"models": [{"name": name} for name in names]})


def _show_router(table: Mapping[str, tuple[str, str]]) -> Callable[[RecordedRequest], ScriptedResponse]:
    """Build an ``/api/show`` handler that answers per requested model.

    Args:
        table: Model name mapped to its ``(parameters, template)`` pair.

    Returns:
        Callable[[RecordedRequest], ScriptedResponse]: A handler answering the model named in the request body.
    """

    def _route(request: RecordedRequest) -> ScriptedResponse:
        """Answer one ``/api/show`` request.

        Args:
            request: The received request.

        Returns:
            ScriptedResponse: The show reply of the requested model.
        """
        parameters, template = table[request.json_object()["name"]]
        return json_response(200, {"parameters": parameters, "template": template})

    return _route


def _line(frame: Mapping[str, Any]) -> bytes:
    """Encode one NDJSON frame.

    Args:
        frame: The JSON object.

    Returns:
        bytes: The frame followed by a newline.
    """
    return json.dumps(frame).encode() + b"\n"


def _ndjson(*chunks: bytes, gates: dict[int, threading.Event] | None = None) -> ScriptedResponse:
    """Build an NDJSON reply, one HTTP chunk per element.

    Args:
        *chunks: The body chunks.
        gates: Chunk index mapped to the event the server waits on before writing that chunk.

    Returns:
        ScriptedResponse: The reply.
    """
    return ScriptedResponse(headers=(("content-type", "application/x-ndjson"),), chunks=chunks, gates=dict(gates or {}))


def _sse_frame(payload: Mapping[str, Any]) -> bytes:
    """Encode one server-sent-event ``data:`` frame.

    Args:
        payload: The JSON object.

    Returns:
        bytes: The frame, terminated by a blank line.
    """
    return b"data: " + json.dumps(payload).encode() + b"\n\n"


def _cloud_provider(cloud_url: str) -> OllamaProvider:
    """Build a provider whose Ollama cloud endpoint is ``cloud_url``.

    Args:
        cloud_url: Base URL of the loopback server standing in for the cloud.

    Returns:
        OllamaProvider: A provider that treats ``cloud_url`` as ``CLOUD_API_URL``.
    """

    class _LoopbackCloudOllama(OllamaProvider):
        """OllamaProvider whose cloud endpoint is a loopback server."""

        CLOUD_API_URL = cloud_url

    return _LoopbackCloudOllama()


@contextlib.asynccontextmanager
async def _session(
    provider: OllamaProvider,
    *,
    local: str | None,
    key: str | None = None,
    http_timeout: float | None = None,
) -> AsyncGenerator[OllamaProvider]:
    """Connect a provider and disconnect it afterwards.

    Args:
        provider: The provider to connect.
        local: Base URL of the local Ollama server, or ``None`` for the default.
        key: Cloud API key, or ``None`` for no cloud source.
        http_timeout: HTTP timeout override in seconds.

    Yields:
        OllamaProvider: The connected provider.
    """
    await provider.connect(ProviderCredentials(api_key=key, api_base=local, timeout=http_timeout))
    try:
        yield provider
    finally:
        await provider.disconnect()


@contextlib.contextmanager
def _event_loop() -> Generator[asyncio.AbstractEventLoop]:
    """Run a fresh event loop for the duration of a ``with`` block.

    Yields:
        asyncio.AbstractEventLoop: A new loop that is closed afterwards.
    """
    loop = asyncio.new_event_loop()
    try:
        yield loop
    finally:
        loop.close()


def _client(provider: OllamaProvider, attribute: str) -> httpx.AsyncClient | None:
    """Read one of the provider's HTTP clients.

    Args:
        provider: The provider.
        attribute: Name of the client attribute.

    Returns:
        httpx.AsyncClient | None: The client, or ``None`` when the source has none.
    """
    value: object = getattr(provider, attribute)
    if value is None:
        return None
    assert isinstance(value, httpx.AsyncClient)
    return value


async def _collect(stream: AsyncIterator[str]) -> list[str]:
    """Drain a text stream.

    Args:
        stream: The stream.

    Returns:
        list[str]: Every part, in arrival order.
    """
    return [part async for part in stream]


async def _drain_into(stream: AsyncIterator[str], received: list[str]) -> None:
    """Drain a text stream into a list that survives an error.

    Args:
        stream: The stream.
        received: List the parts are appended to as they arrive.
    """
    async for part in stream:
        received += [part]


async def _drain_cancelling(provider: OllamaProvider, stream: AsyncIterator[str]) -> list[str]:
    """Drain a text stream, asking the provider to cancel after every part.

    Args:
        provider: The provider that produced the stream.
        stream: The stream.

    Returns:
        list[str]: The parts received before the stream ended.
    """
    received: list[str] = []
    async for part in stream:
        received.append(part)
        await provider.cancel_request()
    return received


async def _call_read_operation(provider: OllamaProvider, operation: str) -> object:
    """Call one of the three read-only Ollama endpoints on the local source.

    Args:
        provider: A connected provider.
        operation: ``tags``, ``running`` or ``show``.

    Returns:
        object: The endpoint's parsed reply.
    """
    if operation == "tags":
        return await provider.list_tags()
    if operation == "running":
        return await provider.list_running_models()
    return await provider.show_model("local/llama3")


def _script_read_operation(server: ScriptedHttpServer, operation: str, reply: ScriptedResponse) -> None:
    """Script a local server so the connect probe succeeds and the operation gets ``reply``.

    Args:
        server: The local loopback server.
        operation: ``tags``, ``running`` or ``show``.
        reply: The reply the operation's own request receives.
    """
    if operation == "tags":
        server.script("GET", _TAGS, _tags("seed"), reply)
    elif operation == "running":
        server.script("GET", _TAGS, _tags("seed"))
        server.script("GET", _PS, reply)
    else:
        server.script("GET", _TAGS, _tags("seed"))
        server.script("POST", _SHOW, reply)


@pytest.mark.asyncio
async def test_connect_reports_both_sources_available_and_sends_the_key_only_to_cloud() -> None:
    """With both sources answering, both flags are set and only the cloud probe carries the bearer key."""
    with ScriptedHttpServer() as local, ScriptedHttpServer() as cloud:
        local.script("GET", _TAGS, _tags("seed"))
        cloud.script("GET", _TAGS, _tags("seed"))
        provider = _cloud_provider(cloud.origin)
        async with _session(provider, local=local.origin, key=_KEY):
            assert provider.connected is True
            assert provider.local_available is True
            assert provider.cloud_available is True
        assert cloud.requests(_TAGS)[0].headers["authorization"] == f"Bearer {_KEY}"
        assert "authorization" not in local.requests(_TAGS)[0].headers


@pytest.mark.asyncio
async def test_connect_without_a_key_leaves_cloud_unavailable() -> None:
    """A connect with no API key never configures the cloud source."""
    with ScriptedHttpServer() as local:
        local.script("GET", _TAGS, _tags("seed"))
        provider = OllamaProvider()
        async with _session(provider, local=local.origin):
            assert provider.local_available is True
            assert provider.cloud_available is False


@pytest.mark.asyncio
async def test_connect_applies_the_credentials_timeout_to_both_clients() -> None:
    """The timeout in the credentials, not the 300 second default, governs both HTTP clients."""
    with ScriptedHttpServer() as local, ScriptedHttpServer() as cloud:
        local.script("GET", _TAGS, _tags("seed"))
        cloud.script("GET", _TAGS, _tags("seed"))
        provider = _cloud_provider(cloud.origin)
        async with _session(provider, local=local.origin, key=_KEY, http_timeout=7.5):
            for attribute in ("_local_client", "_cloud_client"):
                client = _client(provider, attribute)
                assert client is not None
                assert client.timeout == httpx.Timeout(7.5)


@pytest.mark.asyncio
async def test_connect_warns_when_the_cloud_url_ends_with_api() -> None:
    """A cloud base URL ending in ``/api`` is logged as a misconfiguration and still used verbatim."""
    with ScriptedHttpServer() as local, ScriptedHttpServer() as cloud, capture_logs() as logs:
        cloud_url = f"{cloud.origin}/api"
        local.script("GET", _TAGS, _tags("seed"))
        cloud.script("GET", "/api/api/tags", _tags("seed"))
        provider = _cloud_provider(cloud_url)
        async with _session(provider, local=local.origin, key=_KEY):
            assert provider.cloud_available is True
    warnings = [entry for entry in logs if entry["event"] == "cloud_url_ends_with_api"]
    assert len(warnings) == 1
    assert warnings[0]["log_level"] == "warning"
    assert warnings[0]["cloud_url"] == cloud_url


@pytest.mark.asyncio
async def test_connect_local_401_drops_the_local_client_but_keeps_cloud() -> None:
    """A local daemon answering 401 is marked unavailable and its client discarded, while cloud still connects."""
    with ScriptedHttpServer() as local, ScriptedHttpServer() as cloud:
        local.script("GET", _TAGS, json_response(401, {"error": "unauthorized"}))
        cloud.script("GET", _TAGS, _tags("seed"))
        provider = _cloud_provider(cloud.origin)
        async with _session(provider, local=local.origin, key=_KEY):
            assert provider.connected is True
            assert provider.local_available is False
            assert provider.cloud_available is True
            assert _client(provider, "_local_client") is None
            assert _client(provider, "_cloud_client") is not None


@pytest.mark.asyncio
async def test_connect_cloud_401_drops_the_cloud_client_but_keeps_local() -> None:
    """A cloud endpoint rejecting the key is marked unavailable and its client discarded, while local still connects."""
    with ScriptedHttpServer() as local, ScriptedHttpServer() as cloud:
        local.script("GET", _TAGS, _tags("seed"))
        cloud.script("GET", _TAGS, json_response(401, {"error": "invalid key"}))
        provider = _cloud_provider(cloud.origin)
        async with _session(provider, local=local.origin, key=_KEY):
            assert provider.connected is True
            assert provider.local_available is True
            assert provider.cloud_available is False
            assert _client(provider, "_cloud_client") is None
            assert _client(provider, "_local_client") is not None


def test_disconnect_swallows_the_error_of_a_client_whose_event_loop_is_closed() -> None:
    """Closing a pooled connection that belongs to a closed loop fails; disconnect still leaves the provider disconnected."""
    with ScriptedHttpServer() as local:
        local.script("GET", _TAGS, _tags("seed"))
        provider = OllamaProvider()
        with _event_loop() as connect_loop:
            connect_loop.run_until_complete(provider.connect(ProviderCredentials(api_base=local.origin)))
        with _event_loop() as later_loop:
            later_loop.run_until_complete(provider.disconnect())
        assert provider.connected is False


def test_clients_are_rebuilt_when_the_running_loop_changes() -> None:
    """Listing models on a different loop than the one that connected rebuilds both clients for that loop."""
    with _event_loop() as first_loop, _event_loop() as second_loop, ScriptedHttpServer() as local, ScriptedHttpServer() as cloud:
        local.script("GET", _TAGS, _tags("seed"), _tags("alpha"))
        local.script("POST", _SHOW, _show_router({"alpha": ("num_ctx 2048", "{{ .Prompt }}")}))
        cloud.script("GET", _TAGS, _tags("seed"), _tags("zeta"))
        cloud.script("POST", _SHOW, _show_router({"zeta": ("num_ctx 4096", "{{ .Prompt }}")}))
        provider = _cloud_provider(cloud.origin)
        first_loop.run_until_complete(provider.connect(ProviderCredentials(api_key=_KEY, api_base=local.origin, timeout=5.0)))
        old_local = _client(provider, "_local_client")
        old_cloud = _client(provider, "_cloud_client")
        models = second_loop.run_until_complete(provider.list_models())
        new_local = _client(provider, "_local_client")
        new_cloud = _client(provider, "_cloud_client")
        bound_to = (getattr(provider, "_local_client_loop"), getattr(provider, "_cloud_client_loop"))
        second_loop.run_until_complete(provider.disconnect())
        assert old_local is not None
        assert old_cloud is not None
        first_loop.run_until_complete(old_local.aclose())
        first_loop.run_until_complete(old_cloud.aclose())
    assert [model.id for model in models] == ["cloud/zeta", "local/alpha"]
    assert new_local is not None
    assert new_local is not old_local
    assert new_cloud is not None
    assert new_cloud is not old_cloud
    assert bound_to == (second_loop, second_loop)


@pytest.mark.asyncio
@pytest.mark.parametrize(("status", "expected"), _STREAM_ERRORS)
async def test_native_stream_http_error_keeps_its_type_and_leaves_an_empty_body_preview(
    status: int,
    expected: type[ProviderError],
) -> None:
    """A failing ``/api/chat`` stream raises the status's own error type; its unread body gives an empty preview.

    Args:
        status: HTTP status the server answers with.
        expected: The exact exception type that status maps to.
    """
    with ScriptedHttpServer() as local:
        local.script("GET", _TAGS, _tags("seed"))
        local.script("POST", _CHAT, json_response(status, {"error": "refused"}))
        provider = OllamaProvider()
        async with _session(provider, local=local.origin):
            with pytest.raises(ProviderError) as excinfo:
                _ = await _collect(provider.chat_stream(_hello(), "llama3"))
    assert type(excinfo.value) is expected
    assert excinfo.value.status_code == status
    assert excinfo.value.response_body is not None
    assert not excinfo.value.response_body


@pytest.mark.asyncio
async def test_list_models_merges_both_sources_sorted_with_show_metadata() -> None:
    """Models from both sources are merged, sorted by display name, with context window, tools and vision read from ``/api/show``."""
    local_table = {
        "alpha": ('temperature 0.8\nnum_ctx                        8192\nmirostat\nstop "<|im_end|>"', "{{ .Prompt }}"),
        "llava:13b": ("", "{{ if .Tools }}{{ .Tools }}{{ end }}{{ .Prompt }}"),
    }
    with ScriptedHttpServer() as local, ScriptedHttpServer() as cloud:
        local.script("GET", _TAGS, _tags("seed"), _tags("alpha", "llava:13b"))
        local.script("POST", _SHOW, *([_show_router(local_table)] * 2))
        cloud.script("GET", _TAGS, _tags("seed"), _tags("zeta"))
        cloud.script("POST", _SHOW, _show_router({"zeta": ("num_ctx 32768", "{{- .Tools -}}")}))
        provider = _cloud_provider(cloud.origin)
        async with _session(provider, local=local.origin, key=_KEY):
            models = await provider.list_models()
    assert [(m.id, m.name, m.context_window, m.supports_tools, m.supports_vision) for m in models] == [
        ("cloud/zeta", "[Cloud] zeta", 32768, True, False),
        ("local/alpha", "[Local] alpha", 8192, False, False),
        ("local/llava:13b", "[Local] llava:13b", 4096, True, True),
    ]
    assert all(m.provider == provider_ids.OLLAMA and m.supports_streaming for m in models)


@pytest.mark.asyncio
async def test_list_models_with_only_cloud_available_lists_only_cloud_models() -> None:
    """When the local daemon is unreachable the listing contains just the cloud models."""
    with ScriptedHttpServer() as dead_local, ScriptedHttpServer() as cloud:
        cloud.script("GET", _TAGS, _tags("seed"), _tags("zeta"))
        cloud.script("POST", _SHOW, _show_router({"zeta": ("num_ctx 16384", "{{ .Prompt }}")}))
        provider = _cloud_provider(cloud.origin)
        async with _session(provider, local=dead_local.origin, key=_KEY):
            assert provider.local_available is False
            models = await provider.list_models()
    assert [(m.id, m.context_window) for m in models] == [("cloud/zeta", 16384)]


@pytest.mark.asyncio
async def test_list_models_omits_a_local_source_whose_listing_fails() -> None:
    """A local listing that fails with a server error drops the local models without failing the cloud ones."""
    with ScriptedHttpServer() as local, ScriptedHttpServer() as cloud:
        local.script("GET", _TAGS, _tags("seed"), json_response(500, {"error": "daemon busy"}))
        cloud.script("GET", _TAGS, _tags("seed"), _tags("zeta"))
        cloud.script("POST", _SHOW, _show_router({"zeta": ("", "{{ .Prompt }}")}))
        provider = _cloud_provider(cloud.origin)
        async with _session(provider, local=local.origin, key=_KEY):
            models = await provider.list_models()
    assert [m.id for m in models] == ["cloud/zeta"]


@pytest.mark.asyncio
async def test_list_models_omits_a_cloud_source_whose_listing_fails() -> None:
    """A cloud listing that fails with a server error drops the cloud models without failing the local ones."""
    with ScriptedHttpServer() as local, ScriptedHttpServer() as cloud:
        local.script("GET", _TAGS, _tags("seed"), _tags("alpha"))
        local.script("POST", _SHOW, _show_router({"alpha": ("", "{{ .Prompt }}")}))
        cloud.script("GET", _TAGS, _tags("seed"), json_response(500, {"error": "overloaded"}))
        provider = _cloud_provider(cloud.origin)
        async with _session(provider, local=local.origin, key=_KEY):
            models = await provider.list_models()
    assert [m.id for m in models] == ["local/alpha"]


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", _READ_OPERATIONS)
@pytest.mark.parametrize(("status", "expected"), [(401, AuthenticationError), (500, ProviderError)])
async def test_read_endpoint_http_error_keeps_its_type_and_body(
    operation: str,
    status: int,
    expected: type[ProviderError],
) -> None:
    """``list_tags``, ``list_running_models`` and ``show_model`` re-raise the typed error for a failing status, with the body attached.

    Args:
        operation: Which endpoint is called.
        status: HTTP status the server answers with.
        expected: The exact exception type that status maps to.
    """
    with ScriptedHttpServer() as local:
        _script_read_operation(local, operation, json_response(status, {"error": "refused"}))
        provider = OllamaProvider()
        async with _session(provider, local=local.origin):
            with pytest.raises(ProviderError) as excinfo:
                _ = await _call_read_operation(provider, operation)
    assert type(excinfo.value) is expected
    assert excinfo.value.status_code == status
    assert excinfo.value.response_body == json.dumps({"error": "refused"})


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", _READ_OPERATIONS)
async def test_read_endpoint_non_json_body_is_a_transport_error(operation: str) -> None:
    """A 200 reply that is not JSON surfaces as a transport ``ProviderError`` caused by the decode failure.

    Args:
        operation: Which endpoint is called.
    """
    with ScriptedHttpServer() as local:
        _script_read_operation(local, operation, ScriptedResponse(chunks=(b"<html>not json</html>",)))
        provider = OllamaProvider()
        async with _session(provider, local=local.origin):
            with pytest.raises(ProviderError) as excinfo:
                _ = await _call_read_operation(provider, operation)
    assert type(excinfo.value) is ProviderError
    assert str(excinfo.value).startswith("Ollama request transport error:")
    assert isinstance(excinfo.value.__cause__, ValueError)


@pytest.mark.asyncio
async def test_generate_sends_system_and_context_and_records_usage() -> None:
    """``generate`` puts ``system`` and ``context`` in the body next to the options, and records the eval counters as usage."""
    with ScriptedHttpServer() as local:
        local.script("GET", _TAGS, _tags("seed"))
        local.script(
            "POST",
            _GENERATE,
            json_response(200, {"model": "llama3", "response": "done", "done": True, "prompt_eval_count": 3, "eval_count": 4}),
        )
        provider = OllamaProvider()
        async with _session(provider, local=local.origin):
            result = await provider.generate("llama3", "why?", temperature=0.1, max_tokens=32, system="be terse", context=[7, 8, 9])
            usage = provider.get_pending_usage()
        body = local.requests(_GENERATE)[0].json_object()
    assert body == {
        "model": "llama3",
        "prompt": "why?",
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 32},
        "system": "be terse",
        "context": [7, 8, 9],
    }
    assert result.get("response") == "done"
    assert usage is not None
    assert (usage.prompt_tokens, usage.completion_tokens, usage.total_tokens) == (3, 4, 7)


@pytest.mark.asyncio
async def test_generate_refuses_a_cloud_prefixed_model_without_a_cloud_source() -> None:
    """A ``cloud/`` model with only the local source connected is refused before any request is sent."""
    with ScriptedHttpServer() as local:
        local.script("GET", _TAGS, _tags("seed"))
        provider = OllamaProvider()
        async with _session(provider, local=local.origin):
            with pytest.raises(ProviderError, match="Ollama cloud not available"):
                _ = await provider.generate("cloud/llama3", "p")
        assert local.requests(_GENERATE) == []


@pytest.mark.asyncio
async def test_generate_refuses_a_local_prefixed_model_without_a_local_source() -> None:
    """A ``local/`` model with only the cloud source connected is refused before any request is sent."""
    with ScriptedHttpServer() as dead_local, ScriptedHttpServer() as cloud:
        cloud.script("GET", _TAGS, _tags("seed"))
        provider = _cloud_provider(cloud.origin)
        async with _session(provider, local=dead_local.origin, key=_KEY):
            with pytest.raises(ProviderError, match="Local Ollama not available"):
                _ = await provider.generate("local/llama3", "p")
        assert cloud.requests(_GENERATE) == []


@pytest.mark.asyncio
async def test_generate_local_prefix_routes_to_the_local_server_without_the_prefix() -> None:
    """A ``local/`` model goes to the local server, named without the six-character prefix, and never to the cloud."""
    with ScriptedHttpServer() as local, ScriptedHttpServer() as cloud:
        local.script("GET", _TAGS, _tags("seed"))
        local.script("POST", _GENERATE, json_response(200, {"response": "from local", "done": True}))
        cloud.script("GET", _TAGS, _tags("seed"))
        provider = _cloud_provider(cloud.origin)
        async with _session(provider, local=local.origin, key=_KEY):
            result = await provider.generate("local/llama3", "p")
        assert local.requests(_GENERATE)[0].json_object()["model"] == "llama3"
        assert cloud.requests(_GENERATE) == []
    assert result.get("response") == "from local"


@pytest.mark.asyncio
async def test_generate_falls_back_to_cloud_when_local_is_down() -> None:
    """An unprefixed model with no local source is served by the cloud server, with the bearer key."""
    with ScriptedHttpServer() as dead_local, ScriptedHttpServer() as cloud:
        cloud.script("GET", _TAGS, _tags("seed"))
        cloud.script("POST", _GENERATE, json_response(200, {"response": "from cloud", "done": True}))
        provider = _cloud_provider(cloud.origin)
        async with _session(provider, local=dead_local.origin, key=_KEY):
            result = await provider.generate("llama3", "p")
        request = cloud.requests(_GENERATE)[0]
    assert request.json_object()["model"] == "llama3"
    assert request.headers["authorization"] == f"Bearer {_KEY}"
    assert result.get("response") == "from cloud"


@pytest.mark.asyncio
async def test_generate_without_any_source_is_refused() -> None:
    """A provider marked connected that has neither source refuses with the no-client error."""
    provider = OllamaProvider()
    provider.connected = True
    with pytest.raises(ProviderError, match="No Ollama client available"):
        _ = await provider.generate("llama3", "p")


def test_cloud_hosts_select_the_openai_compatible_chat_route() -> None:
    """Hosts of the Ollama cloud get ``/v1/chat/completions``; a loopback daemon without a key gets ``/api/chat``."""
    provider = OllamaProvider()
    is_cloud = cast("Callable[[str], bool]", getattr(provider, "_is_cloud_endpoint"))
    chat_endpoint = cast("Callable[[str], str]", getattr(provider, "_chat_endpoint"))
    assert is_cloud("https://ollama.com") is True
    assert is_cloud("https://API.Ollama.AI/v1") is True
    assert is_cloud("http://127.0.0.1:11434") is False
    assert chat_endpoint("https://ollama.com") == "/v1/chat/completions"
    assert chat_endpoint("http://127.0.0.1:11434") == "/api/chat"


@pytest.mark.asyncio
async def test_chat_refuses_when_not_connected() -> None:
    """``chat`` on a provider that never connected raises the not-connected error."""
    provider = OllamaProvider()
    with pytest.raises(ProviderError, match="Not connected"):
        _ = await provider.chat(_hello(), "llama3")


@pytest.mark.asyncio
async def test_chat_stream_refuses_when_not_connected() -> None:
    """``chat_stream`` on a provider that never connected raises the not-connected error on first iteration."""
    provider = OllamaProvider()
    with pytest.raises(ProviderError, match="Not connected"):
        _ = await _collect(provider.chat_stream(_hello(), "llama3"))


@pytest.mark.asyncio
async def test_chat_local_ignores_thinking_and_cache_and_sends_tools_with_choice() -> None:
    """Thinking and caching requests add nothing to the local body, while tools and a specific tool choice are sent."""
    with ScriptedHttpServer() as local:
        local.script("GET", _TAGS, _tags("seed"))
        local.script(
            "POST",
            _CHAT,
            json_response(200, {"model": "llama3", "message": {"role": "assistant", "content": "decompiled"}, "done": True}),
        )
        provider = OllamaProvider()
        async with _session(provider, local=local.origin):
            message, calls = await provider.chat(
                [Message(role="user", content="decompile main")],
                "llama3",
                tools=[_DECOMPILE_TOOL],
                temperature=0.25,
                max_tokens=64,
                tool_choice=ToolChoice(mode=ToolChoiceMode.SPECIFIC, function_name="ghidra.decompile"),
                thinking=ThinkingConfig(enabled=True),
                enable_cache=True,
            )
        body = local.requests(_CHAT)[0].json_object()
    assert set(body) == {"model", "messages", "stream", "options", "tools", "tool_choice"}
    assert body["stream"] is False
    assert body["options"] == {"temperature": 0.25, "num_predict": 64}
    assert body["messages"] == [{"role": "user", "content": "decompile main"}]
    assert body["tool_choice"] == {"type": "function", "function": {"name": "ghidra__decompile"}}
    assert [(tool["type"], tool["function"]["name"]) for tool in body["tools"]] == [("function", "ghidra__decompile")]
    assert message.content == "decompiled"
    assert calls is None


@pytest.mark.asyncio
async def test_chat_local_non_object_message_gives_an_empty_reply() -> None:
    """A local reply whose ``message`` is not an object yields an empty assistant message and no tool calls."""
    with ScriptedHttpServer() as local:
        local.script("GET", _TAGS, _tags("seed"))
        local.script("POST", _CHAT, json_response(200, {"message": "plain string", "done": True}))
        provider = OllamaProvider()
        async with _session(provider, local=local.origin):
            message, calls = await provider.chat(_hello(), "llama3")
    assert message.role == "assistant"
    assert not message.content
    assert calls is None


@pytest.mark.asyncio
async def test_chat_local_parses_string_null_and_object_tool_arguments() -> None:
    """Local tool calls accept arguments as a JSON string, as null (empty arguments) and as an object."""
    tool_calls = [
        {"function": {"name": "r2__run", "arguments": '{"cmd": "iI"}'}},
        {"function": {"name": "frida__spawn", "arguments": None}},
        {"function": {"name": "ghidra__decompile", "arguments": {"address": "0x40"}}},
    ]
    with ScriptedHttpServer() as local:
        local.script("GET", _TAGS, _tags("seed"))
        local.script(
            "POST",
            _CHAT,
            json_response(200, {"message": {"role": "assistant", "content": "", "tool_calls": tool_calls}, "done": True}),
        )
        provider = OllamaProvider()
        async with _session(provider, local=local.origin):
            _message, calls = await provider.chat(_hello(), "llama3")
    assert calls is not None
    assert [(c.id, c.tool_name, c.function_name, c.arguments) for c in calls] == [
        ("call_0", "r2", "r2.run", {"cmd": "iI"}),
        ("call_1", "frida", "frida.spawn", {}),
        ("call_2", "ghidra", "ghidra.decompile", {"address": "0x40"}),
    ]


@pytest.mark.asyncio
async def test_chat_local_unparsable_usage_counts_are_treated_as_zero() -> None:
    """A non-numeric or null eval counter counts as zero; one good counter still produces usage, two bad ones none."""
    done = {"message": {"role": "assistant", "content": "ok"}, "done": True}
    with ScriptedHttpServer() as local:
        local.script("GET", _TAGS, _tags("seed"))
        local.script(
            "POST",
            _CHAT,
            json_response(200, {**done, "prompt_eval_count": "n/a", "eval_count": 7}),
            json_response(200, {**done, "prompt_eval_count": None, "eval_count": "x"}),
        )
        provider = OllamaProvider()
        async with _session(provider, local=local.origin):
            _ = await provider.chat(_hello(), "llama3")
            first = provider.get_pending_usage()
            _ = await provider.chat(_hello(), "llama3")
            second = provider.get_pending_usage()
    assert first is not None
    assert (first.prompt_tokens, first.completion_tokens, first.total_tokens) == (0, 7, 7)
    assert second is None


@pytest.mark.asyncio
async def test_chat_non_json_reply_is_a_transport_error() -> None:
    """A 200 chat reply that is not JSON raises a transport ``ProviderError`` caused by the decode failure."""
    with ScriptedHttpServer() as local:
        local.script("GET", _TAGS, _tags("seed"))
        local.script("POST", _CHAT, ScriptedResponse(chunks=(b"<html>gateway page</html>",)))
        provider = OllamaProvider()
        async with _session(provider, local=local.origin):
            with pytest.raises(ProviderError) as excinfo:
                _ = await provider.chat(_hello(), "llama3")
    assert type(excinfo.value) is ProviderError
    assert str(excinfo.value).startswith("Ollama request transport error:")
    assert isinstance(excinfo.value.__cause__, ValueError)


@pytest.mark.asyncio
async def test_chat_stalled_server_is_a_transport_error() -> None:
    """A server that never finishes its reply makes ``chat`` raise a transport ``ProviderError`` caused by a timeout."""
    gate = threading.Event()
    with ScriptedHttpServer() as local:
        local.script("GET", _TAGS, _tags("seed"))
        local.script("POST", _CHAT, ScriptedResponse(chunks=(b'{"message": {"role": "assistant", "content": "late"}}',), gates={0: gate}))
        provider = OllamaProvider()
        try:
            async with _session(provider, local=local.origin, http_timeout=_STALL_TIMEOUT):
                with pytest.raises(ProviderError) as excinfo:
                    _ = await provider.chat(_hello(), "llama3")
        finally:
            gate.set()
    assert type(excinfo.value) is ProviderError
    assert str(excinfo.value).startswith("Ollama request transport error:")
    assert isinstance(excinfo.value.__cause__, httpx.TimeoutException)


@pytest.mark.asyncio
async def test_cloud_chat_with_no_choices_gives_an_empty_reply_and_no_usage() -> None:
    """The cloud chat body is the OpenAI shape; a reply with no choices and no usage block gives an empty message."""
    with ScriptedHttpServer() as dead_local, ScriptedHttpServer() as cloud:
        cloud.script("GET", _TAGS, _tags("seed"))
        cloud.script("POST", _CLOUD_CHAT, json_response(200, {"choices": []}))
        provider = _cloud_provider(cloud.origin)
        async with _session(provider, local=dead_local.origin, key=_KEY):
            message, calls = await provider.chat(_hello(), "cloud/llama3")
            usage = provider.get_pending_usage()
        body = cloud.requests(_CLOUD_CHAT)[0].json_object()
    assert body == {
        "model": "llama3",
        "messages": [{"role": "user", "content": "hi"}],
        "temperature": 0.7,
        "max_tokens": 4096,
        "stream": False,
    }
    assert not message.content
    assert calls is None
    assert usage is None


@pytest.mark.asyncio
async def test_cloud_chat_unparsable_usage_is_dropped() -> None:
    """A cloud usage block with a non-numeric count records no usage but the reply text is still returned."""
    reply = {
        "choices": [{"message": {"role": "assistant", "content": "hi there"}}],
        "usage": {"prompt_tokens": "lots", "completion_tokens": 2},
    }
    with ScriptedHttpServer() as dead_local, ScriptedHttpServer() as cloud:
        cloud.script("GET", _TAGS, _tags("seed"))
        cloud.script("POST", _CLOUD_CHAT, json_response(200, reply))
        provider = _cloud_provider(cloud.origin)
        async with _session(provider, local=dead_local.origin, key=_KEY):
            message, _calls = await provider.chat(_hello(), "cloud/llama3")
            usage = provider.get_pending_usage()
    assert message.content == "hi there"
    assert usage is None


@pytest.mark.asyncio
async def test_cloud_chat_parses_dict_null_and_string_tool_arguments() -> None:
    """Cloud tool calls accept arguments as an object, as null (empty arguments) and as a JSON string; a missing id is numbered."""
    tool_calls = [
        {"id": "call_a", "type": "function", "function": {"name": "ghidra__decompile", "arguments": {"address": "0x401000"}}},
        {"id": "call_b", "type": "function", "function": {"name": "r2__run", "arguments": None}},
        {"type": "function", "function": {"name": "frida__spawn", "arguments": '{"program": "notepad"}'}},
    ]
    reply = {"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": tool_calls}}]}
    with ScriptedHttpServer() as dead_local, ScriptedHttpServer() as cloud:
        cloud.script("GET", _TAGS, _tags("seed"))
        cloud.script("POST", _CLOUD_CHAT, json_response(200, reply))
        provider = _cloud_provider(cloud.origin)
        async with _session(provider, local=dead_local.origin, key=_KEY):
            message, calls = await provider.chat(_hello(), "cloud/llama3")
    assert calls is not None
    assert [(c.id, c.tool_name, c.function_name, c.arguments) for c in calls] == [
        ("call_a", "ghidra", "ghidra.decompile", {"address": "0x401000"}),
        ("call_b", "r2", "r2.run", {}),
        ("call_2", "frida", "frida.spawn", {"program": "notepad"}),
    ]
    assert not message.content
    assert message.tool_calls == calls


@pytest.mark.asyncio
async def test_cloud_chat_tool_calls_that_are_not_a_list_are_ignored() -> None:
    """A cloud ``tool_calls`` field that is not an array yields the text reply with no tool calls."""
    reply = {"choices": [{"message": {"role": "assistant", "content": "plain", "tool_calls": "bogus"}}]}
    with ScriptedHttpServer() as dead_local, ScriptedHttpServer() as cloud:
        cloud.script("GET", _TAGS, _tags("seed"))
        cloud.script("POST", _CLOUD_CHAT, json_response(200, reply))
        provider = _cloud_provider(cloud.origin)
        async with _session(provider, local=dead_local.origin, key=_KEY):
            message, calls = await provider.chat(_hello(), "cloud/llama3")
    assert message.content == "plain"
    assert calls is None


@pytest.mark.asyncio
async def test_chat_stream_local_yields_text_and_collects_tool_calls_and_usage() -> None:
    """The local NDJSON stream yields text in order, skips junk lines, and exposes tool calls and usage afterwards."""
    chunks = (
        _line({"model": "llama3", "message": {"role": "assistant", "content": "Hel"}, "done": False}),
        b"not json\n",
        b"\n",
        _line(
            {
                "model": "llama3",
                "message": {
                    "role": "assistant",
                    "content": "lo",
                    "tool_calls": [{"id": "call_x", "function": {"name": "ghidra__decompile", "arguments": {"address": "0x10"}}}],
                },
                "done": False,
            },
        ),
        _line({"model": "llama3", "done": True, "prompt_eval_count": 5, "eval_count": 2}),
    )
    with ScriptedHttpServer() as local:
        local.script("GET", _TAGS, _tags("seed"))
        local.script("POST", _CHAT, _ndjson(*chunks))
        provider = OllamaProvider()
        async with _session(provider, local=local.origin):
            received = await _collect(
                provider.chat_stream(
                    _hello(),
                    "llama3",
                    tools=[_DECOMPILE_TOOL],
                    tool_choice=ToolChoice(mode=ToolChoiceMode.AUTO),
                    thinking=ThinkingConfig(enabled=True),
                    enable_cache=True,
                ),
            )
            calls = provider.get_pending_tool_calls()
            usage = provider.get_pending_usage()
        body = local.requests(_CHAT)[0].json_object()
    assert received == ["Hel", "lo"]
    assert [(c.id, c.tool_name, c.function_name, c.arguments) for c in calls] == [
        ("call_x", "ghidra", "ghidra.decompile", {"address": "0x10"}),
    ]
    assert usage is not None
    assert (usage.prompt_tokens, usage.completion_tokens, usage.total_tokens) == (5, 2, 7)
    assert set(body) == {"model", "messages", "stream", "options", "tools", "tool_choice"}
    assert body["stream"] is True
    assert body["tool_choice"] == "auto"
    assert [tool["function"]["name"] for tool in body["tools"]] == ["ghidra__decompile"]


@pytest.mark.asyncio
async def test_native_stream_stops_after_cancel_request() -> None:
    """After ``cancel_request`` the local stream yields nothing more and publishes no tool calls or usage."""
    chunks = (
        _line({"message": {"role": "assistant", "content": "A"}, "done": False}),
        _line(
            {
                "message": {
                    "role": "assistant",
                    "content": "B",
                    "tool_calls": [{"id": "call_x", "function": {"name": "r2__run", "arguments": {"cmd": "iI"}}}],
                },
                "done": False,
            },
        ),
        _line({"done": True, "prompt_eval_count": 4, "eval_count": 2}),
    )
    with ScriptedHttpServer() as local:
        local.script("GET", _TAGS, _tags("seed"))
        local.script("POST", _CHAT, _ndjson(*chunks))
        provider = OllamaProvider()
        async with _session(provider, local=local.origin):
            received = await _drain_cancelling(provider, provider.chat_stream(_hello(), "llama3"))
            calls = provider.get_pending_tool_calls()
            usage = provider.get_pending_usage()
    assert received == ["A"]
    assert calls == []
    assert usage is None


@pytest.mark.asyncio
async def test_native_stream_transport_failure_is_a_provider_error() -> None:
    """A local stream that stalls after its first line raises a transport ``ProviderError`` once the text so far was delivered."""
    gate = threading.Event()
    first = _line({"message": {"role": "assistant", "content": "A"}, "done": False})
    with ScriptedHttpServer() as local:
        local.script("GET", _TAGS, _tags("seed"))
        local.script("POST", _CHAT, _ndjson(first, b'{"done": true}\n', gates={1: gate}))
        provider = OllamaProvider()
        received: list[str] = []
        try:
            async with _session(provider, local=local.origin, http_timeout=_STALL_TIMEOUT):
                with pytest.raises(ProviderError) as excinfo:
                    await _drain_into(provider.chat_stream(_hello(), "llama3"), received)
        finally:
            gate.set()
    assert received == ["A"]
    assert str(excinfo.value).startswith("Ollama request transport error:")
    assert isinstance(excinfo.value.__cause__, httpx.TimeoutException)


@pytest.mark.asyncio
async def test_native_stream_cancelled_during_a_stall_ends_quietly() -> None:
    """A transport failure after the caller asked to cancel ends the local stream without raising or publishing results."""
    gate = threading.Event()
    first = _line({"message": {"role": "assistant", "content": "A"}, "done": False})
    with ScriptedHttpServer() as local:
        local.script("GET", _TAGS, _tags("seed"))
        local.script("POST", _CHAT, _ndjson(first, b'{"done": true}\n', gates={1: gate}))
        provider = OllamaProvider()
        try:
            async with _session(provider, local=local.origin, http_timeout=_STALL_TIMEOUT):
                received = await _drain_cancelling(provider, provider.chat_stream(_hello(), "llama3"))
                calls = provider.get_pending_tool_calls()
                usage = provider.get_pending_usage()
        finally:
            gate.set()
    assert received == ["A"]
    assert calls == []
    assert usage is None


@pytest.mark.asyncio
async def test_cloud_stream_assembles_text_usage_and_tool_calls() -> None:
    """The cloud event stream yields text, skips framing noise, merges tool-call fragments by index, records usage, stops at ``[DONE]``."""
    events = (
        b": keep-alive\n\n",
        b"data: \n\n",
        b"data: {not json\n\n",
        _sse_frame({"choices": [{"delta": {"role": "assistant"}}]}),
        _sse_frame({"choices": [{"delta": {"content": "Hel"}}]}),
        _sse_frame(
            {
                "choices": [
                    {
                        "delta": {
                            "content": "lo",
                            "tool_calls": [
                                {"index": 0, "id": "call_1", "function": {"name": "ghidra__decompile", "arguments": '{"addr'}},
                                {"index": 1, "id": "call_2", "function": {"name": "frida__spawn"}},
                            ],
                        },
                    },
                ],
            },
        ),
        _sse_frame({"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": 'ess": "0x10"}'}}]}}]}),
        _sse_frame({"choices": [], "usage": {"prompt_tokens": 9, "completion_tokens": 4, "total_tokens": 13}}),
        b"data: [DONE]\n\n",
        _sse_frame({"choices": [{"delta": {"content": "IGNORED"}}]}),
    )
    with ScriptedHttpServer() as dead_local, ScriptedHttpServer() as cloud:
        cloud.script("GET", _TAGS, _tags("seed"))
        cloud.script("POST", _CLOUD_CHAT, sse_response(events))
        provider = _cloud_provider(cloud.origin)
        async with _session(provider, local=dead_local.origin, key=_KEY):
            received = await _collect(provider.chat_stream(_hello(), "cloud/llama3", temperature=0.2, max_tokens=64))
            calls = provider.get_pending_tool_calls()
            usage = provider.get_pending_usage()
        request = cloud.requests(_CLOUD_CHAT)[0]
    assert received == ["Hel", "lo"]
    assert [(c.id, c.tool_name, c.function_name, c.arguments) for c in calls] == [
        ("call_1", "ghidra", "ghidra.decompile", {"address": "0x10"}),
        ("call_2", "frida", "frida.spawn", {}),
    ]
    assert usage is not None
    assert (usage.prompt_tokens, usage.completion_tokens, usage.total_tokens) == (9, 4, 13)
    assert request.json_object() == {
        "model": "llama3",
        "messages": [{"role": "user", "content": "hi"}],
        "temperature": 0.2,
        "max_tokens": 64,
        "stream": True,
        "stream_options": {"include_usage": True},
    }
    assert request.headers["authorization"] == f"Bearer {_KEY}"


@pytest.mark.asyncio
async def test_cloud_stream_without_done_marker_still_finalizes_tool_calls() -> None:
    """A cloud stream that simply ends, with no ``[DONE]`` frame, still publishes the tool calls it carried."""
    events = (
        _sse_frame({"choices": [{"delta": {"content": "x"}}]}),
        _sse_frame(
            {
                "choices": [
                    {
                        "delta": {
                            "tool_calls": [
                                {"index": 0, "id": "call_1", "function": {"name": "ghidra__decompile", "arguments": '{"address": "0x1"}'}},
                            ],
                        },
                    },
                ],
            },
        ),
    )
    with ScriptedHttpServer() as dead_local, ScriptedHttpServer() as cloud:
        cloud.script("GET", _TAGS, _tags("seed"))
        cloud.script("POST", _CLOUD_CHAT, sse_response(events))
        provider = _cloud_provider(cloud.origin)
        async with _session(provider, local=dead_local.origin, key=_KEY):
            received = await _collect(provider.chat_stream(_hello(), "cloud/llama3"))
            calls = provider.get_pending_tool_calls()
    assert received == ["x"]
    assert [(c.id, c.function_name, c.arguments) for c in calls] == [("call_1", "ghidra.decompile", {"address": "0x1"})]


@pytest.mark.asyncio
async def test_cloud_stream_stops_after_cancel_request() -> None:
    """After ``cancel_request`` the cloud stream yields nothing more and does not publish the tool calls it had collected."""
    events = (
        _sse_frame(
            {
                "choices": [
                    {
                        "delta": {
                            "content": "A",
                            "tool_calls": [{"index": 0, "id": "call_1", "function": {"name": "r2__run", "arguments": "{}"}}],
                        },
                    },
                ],
            },
        ),
        _sse_frame({"choices": [{"delta": {"content": "B"}}]}),
    )
    with ScriptedHttpServer() as dead_local, ScriptedHttpServer() as cloud:
        cloud.script("GET", _TAGS, _tags("seed"))
        cloud.script("POST", _CLOUD_CHAT, sse_response(events))
        provider = _cloud_provider(cloud.origin)
        async with _session(provider, local=dead_local.origin, key=_KEY):
            received = await _drain_cancelling(provider, provider.chat_stream(_hello(), "cloud/llama3"))
            calls = provider.get_pending_tool_calls()
    assert received == ["A"]
    assert calls == []


@pytest.mark.asyncio
async def test_cloud_stream_transport_failure_is_a_provider_error() -> None:
    """A cloud stream that stalls after its first event raises a transport ``ProviderError`` once the text so far was delivered."""
    gate = threading.Event()
    first = b"data: " + json.dumps({"choices": [{"delta": {"content": "A"}}]}).encode() + b"\n"
    with ScriptedHttpServer() as dead_local, ScriptedHttpServer() as cloud:
        cloud.script("GET", _TAGS, _tags("seed"))
        cloud.script("POST", _CLOUD_CHAT, sse_response((first, b"data: [DONE]\n"), gates={1: gate}))
        provider = _cloud_provider(cloud.origin)
        received: list[str] = []
        try:
            async with _session(provider, local=dead_local.origin, key=_KEY, http_timeout=_STALL_TIMEOUT):
                with pytest.raises(ProviderError) as excinfo:
                    await _drain_into(provider.chat_stream(_hello(), "cloud/llama3"), received)
        finally:
            gate.set()
    assert received == ["A"]
    assert str(excinfo.value).startswith("Ollama request transport error:")
    assert isinstance(excinfo.value.__cause__, httpx.TimeoutException)


@pytest.mark.asyncio
async def test_cloud_stream_cancelled_during_a_stall_ends_quietly() -> None:
    """A transport failure after the caller asked to cancel ends the cloud stream without raising or publishing results."""
    gate = threading.Event()
    first = b"data: " + json.dumps({"choices": [{"delta": {"content": "A"}}]}).encode() + b"\n"
    with ScriptedHttpServer() as dead_local, ScriptedHttpServer() as cloud:
        cloud.script("GET", _TAGS, _tags("seed"))
        cloud.script("POST", _CLOUD_CHAT, sse_response((first, b"data: [DONE]\n"), gates={1: gate}))
        provider = _cloud_provider(cloud.origin)
        try:
            async with _session(provider, local=dead_local.origin, key=_KEY, http_timeout=_STALL_TIMEOUT):
                received = await _drain_cancelling(provider, provider.chat_stream(_hello(), "cloud/llama3"))
                calls = provider.get_pending_tool_calls()
        finally:
            gate.set()
    assert received == ["A"]
    assert calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(("status", "expected"), _STREAM_ERRORS)
async def test_cloud_stream_http_error_keeps_its_type(status: int, expected: type[ProviderError]) -> None:
    """A failing cloud stream raises the status's own error type.

    Args:
        status: HTTP status the server answers with.
        expected: The exact exception type that status maps to.
    """
    with ScriptedHttpServer() as dead_local, ScriptedHttpServer() as cloud:
        cloud.script("GET", _TAGS, _tags("seed"))
        cloud.script("POST", _CLOUD_CHAT, json_response(status, {"error": {"message": "refused"}}))
        provider = _cloud_provider(cloud.origin)
        async with _session(provider, local=dead_local.origin, key=_KEY):
            with pytest.raises(ProviderError) as excinfo:
                _ = await _collect(provider.chat_stream(_hello(), "cloud/llama3"))
    assert type(excinfo.value) is expected
    assert excinfo.value.status_code == status


def test_native_delta_accumulator_skips_a_non_object_function_and_missing_arguments() -> None:
    """A delta whose ``function`` is not an object leaves an empty entry; one with no arguments leaves them empty."""
    accumulate = cast(
        "Callable[[dict[str, Any], dict[str, dict[str, Any]], list[str]], None]",
        getattr(OllamaProvider, "_accumulate_native_tool_call_deltas"),
    )
    accumulated: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    accumulate({"tool_calls": [{"id": "a", "function": "oops"}, {"id": "b", "function": {"name": "r2__run"}}]}, accumulated, order)
    assert order == ["a", "b"]
    assert accumulated == {
        "a": {"id": "a", "function": {"name": "", "arguments": ""}},
        "b": {"id": "b", "function": {"name": "r2__run", "arguments": ""}},
    }


def test_native_finalize_handles_object_and_missing_arguments() -> None:
    """Finalizing accumulated native calls keeps object arguments and turns missing ones into an empty object."""
    provider = OllamaProvider()
    finalize = cast(
        "Callable[[dict[str, dict[str, Any]], list[str]], list[ToolCall]]",
        getattr(provider, "_finalize_native_tool_calls"),
    )
    accumulated: dict[str, dict[str, Any]] = {
        "c": {"id": "c", "function": {"name": "ghidra__decompile", "arguments": {"address": "0x1"}}},
        "d": {"id": "d", "function": {"name": "r2__run", "arguments": None}},
    }
    calls = finalize(accumulated, ["c", "d"])
    assert [(c.id, c.tool_name, c.function_name, c.arguments) for c in calls] == [
        ("c", "ghidra", "ghidra.decompile", {"address": "0x1"}),
        ("d", "r2", "r2.run", {}),
    ]


def test_openai_delta_accumulator_skips_a_non_object_function_and_locks_object_arguments() -> None:
    """A non-object ``function`` leaves an empty entry, and string fragments never overwrite arguments already given as an object."""
    accumulate = cast(
        "Callable[[list[dict[str, Any]], dict[int, dict[str, Any]]], None]",
        getattr(OllamaProvider, "_accumulate_openai_tool_call_deltas"),
    )
    accumulated: dict[int, dict[str, Any]] = {}
    accumulate(
        [
            {"index": 0, "id": "a", "function": "oops"},
            {"index": 1, "function": {"name": "f", "arguments": {"k": 1}}},
            {"index": 1, "function": {"arguments": "late"}},
        ],
        accumulated,
    )
    assert accumulated == {
        0: {"id": "a", "function": {"name": "", "arguments": ""}},
        1: {"id": None, "function": {"name": "f", "arguments": {"k": 1}}},
    }


def test_messages_convert_to_the_ollama_native_shape() -> None:
    """Assistant tool calls keep their arguments as an object and carry no ``type`` key, as Ollama's native chat expects."""
    provider = OllamaProvider()
    call = ToolCall(id="call_1", tool_name="ghidra", function_name="ghidra.decompile", arguments={"address": "0x10"})
    converted = provider.convert_messages_to_provider_format(
        [Message(role="user", content="hi"), Message(role="assistant", content="", tool_calls=[call])],
    )
    assert converted == [
        {"role": "user", "content": "hi"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [{"id": "call_1", "function": {"name": "ghidra__decompile", "arguments": {"address": "0x10"}}}],
        },
    ]


@pytest.mark.asyncio
async def test_pull_model_strips_the_local_prefix_and_skips_noise() -> None:
    """``pull_model`` pulls the bare model name and yields only non-empty ``status`` values from the progress lines."""
    chunks = (
        b'{"status": "pulling manifest"}\n',
        b"\n",
        b"not json\n",
        b'{"digest": "abc"}\n',
        b'{"status": ""}\n',
        b'{"status": "success"}\n',
    )
    with ScriptedHttpServer() as local:
        local.script("GET", _TAGS, _tags("seed"))
        local.script("POST", _PULL, _ndjson(*chunks))
        provider = OllamaProvider()
        async with _session(provider, local=local.origin):
            statuses = await _collect(provider.pull_model("local/llama3"))
        body = local.requests(_PULL)[0].json_object()
    assert body == {"name": "llama3"}
    assert statuses == ["pulling manifest", "success"]


@pytest.mark.asyncio
@pytest.mark.parametrize(("status", "expected"), _STREAM_ERRORS)
async def test_pull_model_http_error_keeps_its_type(status: int, expected: type[ProviderError]) -> None:
    """A failing ``/api/pull`` raises the status's own error type.

    Args:
        status: HTTP status the server answers with.
        expected: The exact exception type that status maps to.
    """
    with ScriptedHttpServer() as local:
        local.script("GET", _TAGS, _tags("seed"))
        local.script("POST", _PULL, json_response(status, {"error": "refused"}))
        provider = OllamaProvider()
        async with _session(provider, local=local.origin):
            with pytest.raises(ProviderError) as excinfo:
                _ = await _collect(provider.pull_model("llama3"))
    assert type(excinfo.value) is expected
    assert excinfo.value.status_code == status


@pytest.mark.asyncio
async def test_pull_model_transport_failure_is_a_provider_error() -> None:
    """A pull that stalls after its first progress line raises a transport ``ProviderError`` once that status was delivered."""
    gate = threading.Event()
    with ScriptedHttpServer() as local:
        local.script("GET", _TAGS, _tags("seed"))
        local.script("POST", _PULL, _ndjson(b'{"status": "pulling manifest"}\n', b'{"status": "success"}\n', gates={1: gate}))
        provider = OllamaProvider()
        received: list[str] = []
        try:
            async with _session(provider, local=local.origin, http_timeout=_STALL_TIMEOUT):
                with pytest.raises(ProviderError) as excinfo:
                    await _drain_into(provider.pull_model("llama3"), received)
        finally:
            gate.set()
    assert received == ["pulling manifest"]
    assert str(excinfo.value).startswith("Ollama request transport error:")
    assert isinstance(excinfo.value.__cause__, httpx.TimeoutException)
