# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""The Google provider over the real ``google-genai`` SDK and a loopback endpoint.

The provider is connected with ``api_base`` pointing at a loopback server
that answers the Gemini REST API with genuine JSON bodies, so every request
travels through the SDK's own HTTP stack. The tests cover model listing
(``supported_actions`` in google-genai 2.x, and entries that omit
``inputTokenLimit``), honouring ``api_base`` at all, and per-model capability
records reaching the request body.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.core.types import Message, ProviderCredentials, ToolDefinition, ToolFunction, ToolParameter
from intellicrack.providers.capabilities import CapabilityOverride
from intellicrack.providers.google import GoogleProvider
from intellicrack.providers.presets import GEMINI_CONTEXT_WINDOW
from tests._helpers.scripted_sdk_server import ScriptedHTTPServer, json_response


if TYPE_CHECKING:
    from collections.abc import Iterator


_API_KEY: Final[str] = "AIza" + "LoopbackGeminiKey0123456789"
_MODELS_PATH: Final[str] = "/v1beta/models"
_GENERATE_METHODS: Final[list[str]] = ["generateContent", "countTokens", "createCachedContent", "batchGenerateContent"]

_LISTING: Final[dict[str, Any]] = {
    "models": [
        {
            "name": "models/gemini-2.5-pro",
            "displayName": "Gemini 2.5 Pro",
            "inputTokenLimit": 1_048_576,
            "outputTokenLimit": 65_536,
            "supportedGenerationMethods": _GENERATE_METHODS,
            "thinking": True,
        },
        {
            "name": "models/gemini-2.0-flash-lite",
            "displayName": "Gemini 2.0 Flash-Lite",
            "inputTokenLimit": 131_072,
            "outputTokenLimit": 8_192,
            "supportedGenerationMethods": _GENERATE_METHODS,
            "thinking": False,
        },
        {"name": "models/gemini-experimental", "displayName": "Gemini Experimental", "supportedGenerationMethods": ["generateContent"]},
        {"name": "models/gemini-embedding-001", "inputTokenLimit": 2048, "supportedGenerationMethods": ["embedContent"]},
        {"name": "models/gemini-aqa", "inputTokenLimit": 7168, "supportedGenerationMethods": ["generateAnswer"]},
    ],
}


def _generate_body(text: str) -> dict[str, Any]:
    """Build a ``generateContent`` response.

    Args:
        text: The model's reply.

    Returns:
        dict[str, Any]: The response body.
    """
    return {
        "candidates": [{"content": {"role": "model", "parts": [{"text": text}]}, "finishReason": "STOP", "index": 0}],
        "usageMetadata": {"promptTokenCount": 4, "candidatesTokenCount": 1, "totalTokenCount": 5},
        "modelVersion": "gemini",
    }


@pytest.fixture
def server() -> Iterator[ScriptedHTTPServer]:
    """Run a loopback Gemini endpoint.

    Yields:
        ScriptedHTTPServer: The running server.
    """
    running = ScriptedHTTPServer({
        ("GET", _MODELS_PATH): json_response(_LISTING),
        ("POST", "/v1beta/models/gemini-2.5-pro:generateContent"): json_response(_generate_body("pro")),
        ("POST", "/v1beta/models/gemini-2.0-flash-lite:generateContent"): json_response(_generate_body("lite")),
    })
    yield running
    running.close()


async def _connected(server: ScriptedHTTPServer) -> GoogleProvider:
    """Connect a real Google provider to the loopback endpoint.

    Args:
        server: The running server.

    Returns:
        GoogleProvider: The connected provider.
    """
    provider = GoogleProvider()
    await provider.connect(ProviderCredentials(api_key=_API_KEY, api_base=server.origin))
    return provider


def _tool() -> ToolDefinition:
    """Build one tool definition.

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


@pytest.mark.asyncio
async def test_connect_uses_configured_api_base(server: ScriptedHTTPServer) -> None:
    """``credentials.api_base`` is where the SDK sends its requests."""
    await _connected(server)

    probes = server.requests(_MODELS_PATH)
    assert probes
    assert probes[0].headers.get("x-goog-api-key") == _API_KEY


@pytest.mark.asyncio
async def test_list_models_reads_supported_actions_and_optional_limits(server: ScriptedHTTPServer) -> None:
    """Chat models are recognised by ``supported_actions``, and a missing input limit falls back to the preset."""
    provider = await _connected(server)

    models = {model.id: model for model in await provider.list_models()}

    assert set(models) == {"gemini-2.5-pro", "gemini-2.0-flash-lite", "gemini-experimental"}
    pro = models["gemini-2.5-pro"]
    assert (pro.supports_tools, pro.supports_streaming, pro.supports_vision) == (True, True, True)
    assert pro.context_window == 1_048_576
    assert models["gemini-2.0-flash-lite"].context_window == 131_072
    assert models["gemini-experimental"].context_window == GEMINI_CONTEXT_WINDOW
    assert provider.capabilities_for("gemini-2.5-pro").max_output_tokens == 65_536
    assert provider.capabilities_for("gemini-2.5-pro").reasoning.supported is True
    assert provider.capabilities_for("gemini-2.0-flash-lite").reasoning.supported is False


@pytest.mark.asyncio
async def test_per_model_override_reaches_the_request(server: ScriptedHTTPServer) -> None:
    """A model whose record says it takes no tools is sent none; its sibling still gets them."""
    provider = await _connected(server)
    provider.set_capability_override("gemini-2.0-flash-lite", CapabilityOverride(supports_tools=False))
    history = [Message(role="user", content="spawn calc")]

    await provider.chat(history, "gemini-2.0-flash-lite", tools=[_tool()])
    await provider.chat(history, "gemini-2.5-pro", tools=[_tool()])

    lite = server.requests("/v1beta/models/gemini-2.0-flash-lite:generateContent")[-1].body
    pro = server.requests("/v1beta/models/gemini-2.5-pro:generateContent")[-1].body
    assert "tools" not in lite
    declared = [declaration["name"] for tool in pro["tools"] for declaration in tool["functionDeclarations"]]
    assert declared == ["frida__spawn"]
