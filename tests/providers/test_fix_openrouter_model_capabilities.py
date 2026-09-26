# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""OpenRouter requests follow each model's capability record.

A real :class:`OpenRouterProvider` talks to a loopback server that serves an
OpenRouter-shaped ``/models`` listing and records every ``/chat/completions``
body. The listing states per-model ``supported_parameters``; a model that
does not list ``tools`` must be sent none, a model that does not list
``temperature`` must be sent no temperature, and a user's per-model override
must win over both.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.core.types import Message, ProviderCredentials, ToolDefinition, ToolFunction, ToolParameter
from intellicrack.providers.capabilities import CapabilityOverride
from intellicrack.providers.openrouter import OpenRouterProvider
from tests._helpers.scripted_http_server import ScriptedHTTPServer, json_response, sse_response


if TYPE_CHECKING:
    from collections.abc import Iterator


_API_KEY: Final[str] = "sk-or-v1-" + "loopbackRouterKey0123456789"
_BASE: Final[str] = "/api/v1"
_COMPLETIONS: Final[str] = f"{_BASE}/chat/completions"
_TOOLS_MODEL: Final[str] = "openai/gpt-4o"
_NO_TOOLS_MODEL: Final[str] = "some-lab/plain-chat"
_NO_TEMPERATURE_MODEL: Final[str] = "openai/o3"


def _entry(model_id: str, parameters: list[str]) -> dict[str, Any]:
    """Build one OpenRouter ``/models`` entry.

    Args:
        model_id: The model id.
        parameters: The model's ``supported_parameters``.

    Returns:
        dict[str, Any]: The entry.
    """
    return {
        "id": model_id,
        "name": model_id,
        "context_length": 128_000,
        "architecture": {"modality": "text->text", "input_modalities": ["text"]},
        "pricing": {"prompt": "0.000001", "completion": "0.000002"},
        "top_provider": {"context_length": 128_000, "max_completion_tokens": 16_384},
        "supported_parameters": parameters,
    }


_LISTING: Final[dict[str, Any]] = {
    "data": [
        _entry(_TOOLS_MODEL, ["tools", "tool_choice", "temperature", "max_tokens"]),
        _entry(_NO_TOOLS_MODEL, ["temperature", "max_tokens"]),
        _entry(_NO_TEMPERATURE_MODEL, ["tools", "tool_choice", "max_tokens", "reasoning"]),
    ],
}

_STREAM_CHUNKS: Final[list[dict[str, Any]]] = [
    {"id": "gen-2", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": "ok"}}]},
    {"id": "gen-2", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
]

_COMPLETION: Final[dict[str, Any]] = {
    "id": "gen-1",
    "object": "chat.completion",
    "model": _TOOLS_MODEL,
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4},
}


@pytest.fixture
def server() -> Iterator[ScriptedHTTPServer]:
    """Run a loopback OpenRouter endpoint.

    Yields:
        ScriptedHTTPServer: The running server.
    """
    running = ScriptedHTTPServer({
        ("GET", f"{_BASE}/models"): json_response(_LISTING),
        ("POST", _COMPLETIONS): json_response(_COMPLETION),
    })
    yield running
    running.close()


def _tool() -> ToolDefinition:
    """Build one tool definition.

    Returns:
        ToolDefinition: A tool with one function.
    """
    return ToolDefinition(
        tool_name="ghidra",
        description="Static analysis",
        functions=[
            ToolFunction(
                name="ghidra.decompile",
                description="Decompile a function",
                parameters=[ToolParameter(name="address", type="string", description="Function address", required=True)],
                returns="Pseudo-C",
            ),
        ],
    )


async def _listed(server: ScriptedHTTPServer) -> OpenRouterProvider:
    """Connect a real OpenRouter provider and list its models.

    Args:
        server: The running server.

    Returns:
        OpenRouterProvider: The connected provider with ingested model metadata.
    """
    provider = OpenRouterProvider()
    await provider.connect(ProviderCredentials(api_key=_API_KEY, api_base=f"{server.origin}{_BASE}"))
    await provider.list_models()
    return provider


async def _sent(provider: OpenRouterProvider, server: ScriptedHTTPServer, model: str) -> dict[str, Any]:
    """Run one chat turn with a tool and return the body that was sent.

    Args:
        provider: The connected provider.
        server: The running server.
        model: The model id.

    Returns:
        dict[str, Any]: The request body.
    """
    await provider.chat([Message(role="user", content="decompile main")], model, tools=[_tool()], temperature=0.3)
    body: dict[str, Any] = server.requests(_COMPLETIONS)[-1].body
    return body


@pytest.mark.asyncio
async def test_advertised_capabilities_shape_the_request(server: ScriptedHTTPServer) -> None:
    """Tools and temperature are sent only to models whose listing says they take them."""
    provider = await _listed(server)

    full = await _sent(provider, server, _TOOLS_MODEL)
    no_tools = await _sent(provider, server, _NO_TOOLS_MODEL)
    no_temperature = await _sent(provider, server, _NO_TEMPERATURE_MODEL)

    assert full["temperature"] == pytest.approx(0.3)
    assert [tool["function"]["name"] for tool in full["tools"]] == ["ghidra__decompile"]
    assert "tools" not in no_tools
    assert no_tools["temperature"] == pytest.approx(0.3)
    assert "temperature" not in no_temperature
    assert "tools" in no_temperature


@pytest.mark.asyncio
async def test_user_override_wins_and_applies_to_streaming(server: ScriptedHTTPServer) -> None:
    """A per-model override that withdraws tools and temperature applies to streamed requests too."""
    provider = await _listed(server)
    provider.set_capability_override(_TOOLS_MODEL, CapabilityOverride(supports_tools=False, supports_temperature=False))
    stream_server = ScriptedHTTPServer({
        ("GET", f"{_BASE}/models"): json_response(_LISTING),
        ("POST", _COMPLETIONS): sse_response(
            _STREAM_CHUNKS,
            named=False,
            done_marker=True,
        ),
    })
    try:
        await provider.connect(ProviderCredentials(api_key=_API_KEY, api_base=f"{stream_server.origin}{_BASE}"))
        chunks = [
            chunk
            async for chunk in provider.chat_stream(
                [Message(role="user", content="decompile main")],
                _TOOLS_MODEL,
                tools=[_tool()],
                temperature=0.3,
            )
        ]
        body: dict[str, Any] = stream_server.requests(_COMPLETIONS)[-1].body
    finally:
        stream_server.close()

    assert chunks == ["ok"]
    assert body["stream"] is True
    assert "tools" not in body
    assert "temperature" not in body
