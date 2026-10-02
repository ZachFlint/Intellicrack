# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 24: a forced tool choice is sent only to a Claude model that accepts one in its current thinking state.

Claude Fable 5.1 and Opus 5.5 answer ``tool_choice: any`` and ``tool_choice: tool`` with ``400``, and so does every Claude model while
it thinks. The gates connect the real built-in :class:`AnthropicProvider`, through the real ``anthropic`` SDK, and an Anthropic-compatible
gateway instance to a loopback Messages endpoint, and read the bodies it received: forcing is kept where it is accepted, and otherwise
becomes ``auto``, with a choice of one specific tool narrowing the tools sent to that one.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.core.types import (
    Message,
    ProviderCredentials,
    ThinkingConfig,
    ToolChoice,
    ToolChoiceMode,
    ToolDefinition,
    ToolFunction,
    ToolParameter,
)
from intellicrack.providers.anthropic import AnthropicProvider
from intellicrack.providers.configurable import ConfigurableProvider
from intellicrack.providers.instances import instance_from_preset_id
from tests._helpers.scripted_sdk_server import ScriptedHTTPServer, json_response


if TYPE_CHECKING:
    from collections.abc import Iterator

    from intellicrack.providers.base import LLMProviderBase


_API_KEY: Final[str] = "sk-ant-loopbackForcedChoice0123456789"
_MODELS_PATH: Final[str] = "/v1/models"
_MESSAGES_PATH: Final[str] = "/v1/messages"
_THINKING: Final[ThinkingConfig] = ThinkingConfig(enabled=True, budget_tokens=8000)
_REQUIRED: Final[ToolChoice] = ToolChoice(mode=ToolChoiceMode.REQUIRED)
_SPECIFIC: Final[ToolChoice] = ToolChoice(mode=ToolChoiceMode.SPECIFIC, function_name="frida.spawn")
_TOOLS: Final[list[ToolDefinition]] = [
    ToolDefinition(
        tool_name="frida",
        description="Dynamic instrumentation.",
        functions=[
            ToolFunction(
                name="frida.spawn",
                description="Spawn a process.",
                parameters=[ToolParameter(name="target", type="string", description="Executable to spawn.")],
                returns="pid",
            ),
            ToolFunction(
                name="frida.attach",
                description="Attach to a process.",
                parameters=[ToolParameter(name="pid", type="integer", description="Process id.")],
                returns="session",
            ),
        ],
    ),
]


def _message_body() -> dict[str, Any]:
    """Build a non-streaming Messages response.

    Returns:
        dict[str, Any]: A complete ``message`` object.
    """
    return {
        "id": "msg_loopback",
        "type": "message",
        "role": "assistant",
        "model": "claude",
        "content": [{"type": "text", "text": "done"}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 3, "output_tokens": 1},
    }


@pytest.fixture
def server() -> Iterator[ScriptedHTTPServer]:
    """Run a loopback Anthropic endpoint that answers every message the same way.

    Yields:
        ScriptedHTTPServer: The running server.
    """
    running = ScriptedHTTPServer({
        ("GET", _MODELS_PATH): json_response({"data": [], "has_more": False, "first_id": None, "last_id": None}),
        ("POST", _MESSAGES_PATH): json_response(_message_body()),
    })
    yield running
    running.close()


async def _builtin(server: ScriptedHTTPServer) -> LLMProviderBase:
    """Connect the built-in Anthropic provider to the loopback endpoint.

    Args:
        server: The running server.

    Returns:
        LLMProviderBase: The connected provider.
    """
    provider = AnthropicProvider()
    await provider.connect(ProviderCredentials(api_key=_API_KEY, api_base=server.origin))
    return provider


async def _gateway(server: ScriptedHTTPServer) -> LLMProviderBase:
    """Connect an Anthropic-compatible gateway instance to the loopback endpoint.

    Args:
        server: The running server.

    Returns:
        LLMProviderBase: The connected provider.
    """
    instance = instance_from_preset_id("anthropic-gateway", instance_id="claude-gw")
    assert instance is not None
    instance.api_base = server.origin
    provider = ConfigurableProvider(instance)
    await provider.connect(ProviderCredentials(api_key=_API_KEY, api_base=server.origin))
    return provider


def _sent(server: ScriptedHTTPServer, *, gateway: bool, model: str, choice: ToolChoice, thinking: ThinkingConfig | None) -> dict[str, Any]:
    """Run one turn and return the body the endpoint received.

    Args:
        server: The running server.
        gateway: Whether to go through the gateway instance rather than the built-in provider.
        model: The model.
        choice: The tool choice.
        thinking: Thinking configuration, or ``None``.

    Returns:
        dict[str, Any]: The request body.
    """

    async def run() -> None:
        """Connect and run the turn."""
        provider = await (_gateway(server) if gateway else _builtin(server))
        _ = await provider.chat([Message(role="user", content="spawn it")], model, tools=_TOOLS, tool_choice=choice, thinking=thinking)

    asyncio.run(run())
    return server.requests(_MESSAGES_PATH)[-1].body


def _tool_names(body: dict[str, Any]) -> list[str]:
    """List the tool names a request advertised.

    Args:
        body: The request body.

    Returns:
        list[str]: The names, in order.
    """
    return [str(tool["name"]) for tool in body["tools"]]


@pytest.mark.parametrize("gateway", [False, True], ids=["builtin", "gateway"])
@pytest.mark.parametrize("model", ["claude-fable-5-1", "claude-opus-5-5"])
def test_newest_models_are_never_forced(server: ScriptedHTTPServer, model: str, *, gateway: bool) -> None:
    """Fable 5.1 and Opus 5.5 get ``auto`` for ``required``, and ``auto`` over the one named tool for a specific choice.

    Args:
        server: The loopback endpoint.
        model: The model.
        gateway: Whether to go through the gateway instance.
    """
    required = _sent(server, gateway=gateway, model=model, choice=_REQUIRED, thinking=None)
    specific = _sent(server, gateway=gateway, model=model, choice=_SPECIFIC, thinking=None)

    assert required["tool_choice"] == {"type": "auto"}
    assert _tool_names(required) == ["frida__spawn", "frida__attach"]
    assert specific["tool_choice"] == {"type": "auto"}
    assert _tool_names(specific) == ["frida__spawn"]


@pytest.mark.parametrize("gateway", [False, True], ids=["builtin", "gateway"])
@pytest.mark.parametrize("model", ["claude-sonnet-4-5", "claude-opus-4-7"])
def test_forcing_follows_the_thinking_state(server: ScriptedHTTPServer, model: str, *, gateway: bool) -> None:
    """An earlier Claude model is forced while it does not think, and gets ``auto`` while it does.

    Args:
        server: The loopback endpoint.
        model: The model.
        gateway: Whether to go through the gateway instance.
    """
    plain_required = _sent(server, gateway=gateway, model=model, choice=_REQUIRED, thinking=None)
    plain_specific = _sent(server, gateway=gateway, model=model, choice=_SPECIFIC, thinking=None)
    thinking_required = _sent(server, gateway=gateway, model=model, choice=_REQUIRED, thinking=_THINKING)
    thinking_specific = _sent(server, gateway=gateway, model=model, choice=_SPECIFIC, thinking=_THINKING)

    assert plain_required["tool_choice"] == {"type": "any"}
    assert plain_specific["tool_choice"] == {"type": "tool", "name": "frida__spawn"}
    assert _tool_names(plain_specific) == ["frida__spawn", "frida__attach"]
    assert "thinking" in thinking_required
    assert thinking_required["tool_choice"] == {"type": "auto"}
    assert thinking_specific["tool_choice"] == {"type": "auto"}
    assert _tool_names(thinking_specific) == ["frida__spawn"]
