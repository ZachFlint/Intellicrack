# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Per-model Anthropic thinking and model metadata over the real wire.

Current Claude models reject ``thinking: {"type": "enabled", "budget_tokens":
N}``: Opus 4.7 and later, Sonnet 5 and Fable accept only ``{"type":
"adaptive"}`` with the depth in ``output_config.effort``, while Haiku 4.5 and
the pre-4.6 families accept only the budget. These tests drive the real
``anthropic`` SDK (through :class:`AnthropicProvider`) and the raw-HTTP
Messages dialect (through :class:`ConfigurableProvider`) against a loopback
server, and read the thinking parameters out of the request bodies that
actually reached the wire. They also check that the context window and the
thinking surface a model advertises on ``/v1/models`` are what requests use.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.core.types import Message, ProviderCredentials, ThinkingConfig
from intellicrack.providers.anthropic import AnthropicProvider
from intellicrack.providers.capabilities import ReasoningEffortFormat, effort_for_thinking_budget
from intellicrack.providers.configurable import ConfigurableProvider
from intellicrack.providers.instances import instance_from_preset_id
from intellicrack.providers.model_metadata import ingest_model_entry
from tests._helpers.scripted_http_server import ScriptedHTTPServer, ScriptedResponse, json_response, sse_response


if TYPE_CHECKING:
    from collections.abc import Iterator


_API_KEY: Final[str] = "sk-ant-" + "loopbackThinkingKey0123456789"
_MODELS_PATH: Final[str] = "/v1/models"
_MESSAGES_PATH: Final[str] = "/v1/messages"


def _capabilities(*, adaptive: bool, enabled: bool, effort_levels: tuple[str, ...]) -> dict[str, Any]:
    """Build a ``/v1/models`` capabilities object in Anthropic's shape.

    Args:
        adaptive: Whether ``adaptive`` thinking is supported.
        enabled: Whether ``enabled`` (budget) thinking is supported.
        effort_levels: The effort levels the model supports.

    Returns:
        dict[str, Any]: The capabilities object.
    """
    supported = {"supported": True}
    return {
        "batch": supported,
        "citations": supported,
        "code_execution": supported,
        "context_management": {"supported": True},
        "effort": {
            "supported": bool(effort_levels),
            **{level: {"supported": level in effort_levels} for level in ("low", "medium", "high", "xhigh", "max")},
        },
        "image_input": supported,
        "pdf_input": supported,
        "structured_outputs": supported,
        "thinking": {
            "supported": adaptive or enabled,
            "types": {"adaptive": {"supported": adaptive}, "enabled": {"supported": enabled}},
        },
    }


def _model_entry(model_id: str, *, max_input_tokens: int, capabilities: dict[str, Any]) -> dict[str, Any]:
    """Build one ``/v1/models`` entry.

    Args:
        model_id: The model id.
        max_input_tokens: The advertised context window.
        capabilities: The advertised capabilities.

    Returns:
        dict[str, Any]: The entry.
    """
    return {
        "id": model_id,
        "type": "model",
        "display_name": model_id,
        "created_at": "2026-01-01T00:00:00Z",
        "max_input_tokens": max_input_tokens,
        "max_tokens": 128000,
        "capabilities": capabilities,
    }


_LISTING: Final[dict[str, Any]] = {
    "data": [
        _model_entry(
            "claude-opus-4-7",
            max_input_tokens=1_000_000,
            capabilities=_capabilities(adaptive=True, enabled=False, effort_levels=("low", "medium", "high", "xhigh", "max")),
        ),
        _model_entry(
            "claude-haiku-4-5", max_input_tokens=200_000, capabilities=_capabilities(adaptive=False, enabled=True, effort_levels=())
        ),
        _model_entry(
            "claude-sonnet-4-5",
            max_input_tokens=640_000,
            capabilities=_capabilities(adaptive=True, enabled=True, effort_levels=("low", "medium", "high")),
        ),
    ],
    "has_more": False,
    "first_id": "claude-opus-4-7",
    "last_id": "claude-sonnet-4-5",
}


def _message_body(model: str) -> dict[str, Any]:
    """Build a non-streaming Messages response.

    Args:
        model: The model id echoed back.

    Returns:
        dict[str, Any]: A complete ``message`` object.
    """
    return {
        "id": "msg_loopback",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{"type": "text", "text": "done"}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 3, "output_tokens": 1},
    }


def _text_stream(model: str) -> ScriptedResponse:
    """Build a Messages SSE stream carrying one text block.

    Args:
        model: The model id echoed back.

    Returns:
        ScriptedResponse: The streaming response.
    """
    return sse_response([
        {
            "type": "message_start",
            "message": {**_message_body(model), "content": [], "stop_reason": None, "usage": {"input_tokens": 3, "output_tokens": 0}},
        },
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "done"}},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 1}},
        {"type": "message_stop"},
    ])


@pytest.fixture
def server() -> Iterator[ScriptedHTTPServer]:
    """Run a loopback Anthropic endpoint.

    Yields:
        ScriptedHTTPServer: The running server.
    """
    running = ScriptedHTTPServer({
        ("GET", _MODELS_PATH): json_response(_LISTING),
        ("POST", _MESSAGES_PATH): _text_stream("claude"),
    })
    yield running
    running.close()


async def _anthropic(server: ScriptedHTTPServer) -> AnthropicProvider:
    """Connect a real Anthropic provider to the loopback endpoint.

    Args:
        server: The running server.

    Returns:
        AnthropicProvider: The connected provider.
    """
    provider = AnthropicProvider()
    await provider.connect(ProviderCredentials(api_key=_API_KEY, api_base=server.origin))
    return provider


async def _sent_thinking(
    provider: AnthropicProvider | ConfigurableProvider, server: ScriptedHTTPServer, model: str, budget: int
) -> dict[str, Any]:
    """Stream one thinking turn and return the body the endpoint received.

    Args:
        provider: The connected provider.
        server: The running server.
        model: The model id.
        budget: The thinking budget requested.

    Returns:
        dict[str, Any]: The last Messages request body.
    """
    chunks = [
        chunk
        async for chunk in provider.chat_stream(
            [Message(role="user", content="analyse the sample")],
            model,
            max_tokens=2048,
            thinking=ThinkingConfig(enabled=True, budget_tokens=budget),
        )
    ]
    assert "".join(chunks) == "done"
    body: dict[str, Any] = server.requests(_MESSAGES_PATH)[-1].body
    return body


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("model", "budget", "effort"),
    [
        ("claude-opus-4-7", 10_000, "medium"),
        ("claude-opus-4-8", 50_000, "xhigh"),
        ("claude-sonnet-5", 2_000, "low"),
        ("claude-fable-5-1", 100_000, "max"),
        ("claude-sonnet-4-6", 50_000, "high"),
    ],
)
async def test_current_models_receive_adaptive_thinking_with_effort(
    server: ScriptedHTTPServer, model: str, budget: int, effort: str
) -> None:
    """Opus 4.6+, Sonnet 4.6+/5 and Fable get adaptive thinking and an effort level, never a budget."""
    provider = await _anthropic(server)

    body = await _sent_thinking(provider, server, model, budget)

    assert body["thinking"]["type"] == "adaptive"
    assert "budget_tokens" not in body["thinking"]
    assert body["output_config"] == {"effort": effort}


@pytest.mark.asyncio
@pytest.mark.parametrize("model", ["claude-haiku-4-5", "claude-opus-4-5", "claude-sonnet-4-20250514", "claude-3-7-sonnet-latest"])
async def test_budget_only_models_keep_budget_thinking(server: ScriptedHTTPServer, model: str) -> None:
    """Models that predate adaptive thinking keep the ``budget_tokens`` form."""
    provider = await _anthropic(server)

    body = await _sent_thinking(provider, server, model, 8_000)

    assert body["thinking"] == {"type": "enabled", "budget_tokens": 8_000}
    assert "output_config" not in body


@pytest.mark.asyncio
async def test_messages_dialect_gateway_resolves_thinking_per_model(server: ScriptedHTTPServer) -> None:
    """A user-defined Anthropic-compatible instance picks the thinking form per model too."""
    instance = instance_from_preset_id("anthropic-gateway", instance_id="claude-gw")
    assert instance is not None
    instance.api_base = server.origin
    provider = ConfigurableProvider(instance)
    await provider.connect(ProviderCredentials(api_key=_API_KEY, api_base=server.origin))

    adaptive = await _sent_thinking(provider, server, "claude-opus-4-7", 20_000)
    budget = await _sent_thinking(provider, server, "claude-haiku-4-5", 20_000)

    assert adaptive["thinking"]["type"] == "adaptive"
    assert adaptive["output_config"] == {"effort": "high"}
    assert budget["thinking"] == {"type": "enabled", "budget_tokens": 20_000}


@pytest.mark.asyncio
async def test_list_models_uses_advertised_context_window_and_thinking(server: ScriptedHTTPServer) -> None:
    """``max_input_tokens`` and the advertised thinking types drive the model's record and its requests."""
    provider = await _anthropic(server)

    models = {model.id: model for model in await provider.list_models()}

    assert models["claude-opus-4-7"].context_window == 1_000_000
    assert models["claude-haiku-4-5"].context_window == 200_000
    assert models["claude-sonnet-4-5"].context_window == 640_000
    sonnet = provider.capabilities_for("claude-sonnet-4-5")
    assert sonnet.reasoning.effort_format is ReasoningEffortFormat.ADAPTIVE_EFFORT
    assert sonnet.reasoning.effort_levels == ("low", "medium", "high")
    body = await _sent_thinking(provider, server, "claude-sonnet-4-5", 50_000)
    assert body["thinking"]["type"] == "adaptive"
    assert body["output_config"] == {"effort": "high"}


def test_ingest_reads_anthropic_capability_objects() -> None:
    """An Anthropic ``/v1/models`` entry's capability objects become capability fields."""
    entry = _model_entry(
        "claude-opus-4-7",
        max_input_tokens=1_000_000,
        capabilities=_capabilities(adaptive=True, enabled=False, effort_levels=("low", "medium", "high", "xhigh", "max")),
    )

    ingested = ingest_model_entry(entry)

    assert ingested is not None
    stated = ingested.capabilities
    assert stated.context_window == 1_000_000
    assert stated.max_output_tokens == 128_000
    assert stated.supports_vision is True
    assert stated.reasoning is not None
    assert stated.reasoning.effort_format is ReasoningEffortFormat.ADAPTIVE_EFFORT
    assert stated.reasoning.effort_levels == ("low", "medium", "high", "xhigh", "max")


def test_effort_for_budget_clamps_to_offered_levels() -> None:
    """A budget above the model's top level maps to its highest offered level."""
    assert effort_for_thinking_budget(50_000, ("low", "medium", "high", "max")) == "high"
    assert effort_for_thinking_budget(90_000, ("low", "medium", "high", "max")) == "max"
    assert effort_for_thinking_budget(1_000, ("medium", "high")) == "medium"
    assert effort_for_thinking_budget(1_000, ()) is None


def _tool_use_stream(model: str) -> ScriptedResponse:
    """Build a Messages SSE stream whose turn ends in one tool call.

    Args:
        model: The model id echoed back.

    Returns:
        ScriptedResponse: The streaming response.
    """
    return sse_response([
        {
            "type": "message_start",
            "message": {**_message_body(model), "content": [], "stop_reason": None, "usage": {"input_tokens": 5, "output_tokens": 0}},
        },
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "tool_use", "id": "toolu_1", "name": "frida__spawn", "input": {}},
        },
        {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": '{"target": "calc.exe"}'}},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": None}, "usage": {"output_tokens": 9}},
        {"type": "message_stop"},
    ])


@pytest.mark.asyncio
async def test_streamed_tool_call_is_parsed_to_canonical_name() -> None:
    """A streamed ``tool_use`` block is finalized through the shared tool-call parser."""
    with ScriptedHTTPServer({
        ("GET", _MODELS_PATH): json_response(_LISTING),
        ("POST", _MESSAGES_PATH): _tool_use_stream("claude-opus-4-7"),
    }) as running:
        provider = await _anthropic(running)
        chunks = [chunk async for chunk in provider.chat_stream([Message(role="user", content="spawn")], "claude-opus-4-7")]

    assert chunks == []
    calls = provider.get_pending_tool_calls()
    assert [(call.id, call.tool_name, call.function_name, call.arguments) for call in calls] == [
        ("toolu_1", "frida", "frida.spawn", {"target": "calc.exe"}),
    ]
