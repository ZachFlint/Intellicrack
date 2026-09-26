# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""The Grok provider resolves every request decision through the capability layer.

A real :class:`GrokProvider` drives the real ``openai`` SDK against a
loopback server with xAI's paths. The bodies that reach the wire show that
``reasoning_effort`` goes to every family xAI documents as accepting it (not
only multi-agent ids), that the output-limit field and context window come
from the Grok presets, and that a user's per-model override withdraws tools
and temperature from both the streaming and non-streaming paths.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.core.types import Message, ProviderCredentials, ThinkingConfig, ToolDefinition, ToolFunction, ToolParameter
from intellicrack.providers.capabilities import CapabilityOverride
from intellicrack.providers.grok import GrokProvider
from tests._helpers.scripted_sdk_server import ScriptedHTTPServer, json_response, sse_response


if TYPE_CHECKING:
    from collections.abc import Iterator


_API_KEY: Final[str] = "xai-" + "loopbackGrokKey0123456789"
_COMPLETIONS: Final[str] = "/v1/chat/completions"
_MODEL_IDS: Final[tuple[str, ...]] = ("grok-4.7", "grok-4.5", "grok-4", "grok-3-mini", "grok-4.20-0309-reasoning")


def _completion(model: str) -> dict[str, Any]:
    """Build a non-streaming chat completion.

    Args:
        model: The model id echoed back.

    Returns:
        dict[str, Any]: The completion body.
    """
    return {
        "id": "chatcmpl-grok",
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3},
    }


_STREAM_CHUNKS: Final[list[dict[str, Any]]] = [
    {"id": "c1", "object": "chat.completion.chunk", "created": 0, "model": "grok-4", "choices": [{"index": 0, "delta": {"content": "ok"}}]},
    {
        "id": "c1",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "grok-4",
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
    },
]


def _tool() -> ToolDefinition:
    """Build one tool definition.

    Returns:
        ToolDefinition: A tool with one function.
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


@pytest.fixture
def servers() -> Iterator[list[ScriptedHTTPServer]]:
    """Collect started servers and stop them after the test.

    Yields:
        list[ScriptedHTTPServer]: The list a test appends its servers to.
    """
    started: list[ScriptedHTTPServer] = []
    yield started
    for server in started:
        server.close()


async def _connected(servers: list[ScriptedHTTPServer], *, stream: bool) -> tuple[GrokProvider, ScriptedHTTPServer]:
    """Connect a real Grok provider to a loopback xAI endpoint.

    Args:
        servers: The fixture's list of servers to stop afterwards.
        stream: Whether completions are answered as SSE streams.

    Returns:
        tuple[GrokProvider, ScriptedHTTPServer]: The connected provider and its server.
    """
    listing = {"object": "list", "data": [{"id": model, "object": "model", "created": 0, "owned_by": "xai"} for model in _MODEL_IDS]}
    answer = sse_response(_STREAM_CHUNKS, named=False, done_marker=True) if stream else json_response(_completion("grok"))
    server = ScriptedHTTPServer({("GET", "/v1/models"): json_response(listing), ("POST", _COMPLETIONS): answer})
    servers.append(server)
    provider = GrokProvider()
    await provider.connect(ProviderCredentials(api_key=_API_KEY, api_base=f"{server.origin}/v1"))
    return provider, server


async def _chat_body(provider: GrokProvider, server: ScriptedHTTPServer, model: str) -> dict[str, Any]:
    """Run one thinking turn with a tool and return the body that was sent.

    Args:
        provider: The connected provider.
        server: The running server.
        model: The model id.

    Returns:
        dict[str, Any]: The request body.
    """
    await provider.chat(
        [Message(role="user", content="disassemble main")],
        model,
        tools=[_tool()],
        temperature=0.4,
        max_tokens=1000,
        thinking=ThinkingConfig(enabled=True, budget_tokens=20_000),
    )
    body: dict[str, Any] = server.requests(_COMPLETIONS)[-1].body
    return body


@pytest.mark.asyncio
async def test_reasoning_effort_follows_documented_families(servers: list[ScriptedHTTPServer]) -> None:
    """grok-4.5/4.6/4.7 and grok-3-mini get reasoning_effort mapped onto their own levels; grok-4 does not."""
    provider, server = await _connected(servers, stream=False)

    grok47 = await _chat_body(provider, server, "grok-4.7")
    grok45 = await _chat_body(provider, server, "grok-4.5")
    mini = await _chat_body(provider, server, "grok-3-mini")
    grok4 = await _chat_body(provider, server, "grok-4")
    auto = await _chat_body(provider, server, "grok-4.20-0309-reasoning")

    assert grok47["reasoning_effort"] == "high"
    assert grok45["reasoning_effort"] == "high"
    assert mini["reasoning_effort"] == "high"
    assert "reasoning_effort" not in grok4
    assert "reasoning_effort" not in auto
    assert grok47["max_completion_tokens"] == 1000
    assert "max_tokens" not in grok47
    assert mini["max_tokens"] == 1000


@pytest.mark.asyncio
async def test_list_models_reads_windows_from_presets_and_overrides(servers: list[ScriptedHTTPServer]) -> None:
    """Context windows come from the Grok presets and yield to a per-model override."""
    provider, _ = await _connected(servers, stream=False)
    provider.set_capability_override("grok-4", CapabilityOverride(context_window=64_000))

    models = {model.id: model for model in await provider.list_models()}

    assert models["grok-4.7"].context_window == 500_000
    assert models["grok-4.20-0309-reasoning"].context_window == 1_000_000
    assert models["grok-4"].context_window == 64_000


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [False, True])
async def test_override_withdraws_tools_and_temperature(servers: list[ScriptedHTTPServer], *, stream: bool) -> None:
    """A per-model override that withdraws tools and temperature applies to both request paths."""
    provider, server = await _connected(servers, stream=stream)
    provider.set_capability_override("grok-4", CapabilityOverride(supports_tools=False, supports_temperature=False))
    history = [Message(role="user", content="disassemble main")]

    if stream:
        chunks = [chunk async for chunk in provider.chat_stream(history, "grok-4", tools=[_tool()], temperature=0.4)]
        assert chunks == ["ok"]
    else:
        await provider.chat(history, "grok-4", tools=[_tool()], temperature=0.4)

    body: dict[str, Any] = server.requests(_COMPLETIONS)[-1].body
    assert "tools" not in body
    assert "temperature" not in body
