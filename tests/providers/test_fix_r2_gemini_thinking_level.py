# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 25: Gemini 3 is asked to think by ``thinkingLevel``, and Gemini 2.5 by ``thinkingBudget``.

The gates connect the real built-in :class:`GoogleProvider`, through the real ``google-genai`` SDK, and a user-defined Gemini instance to a
loopback Gemini endpoint and read the ``thinkingConfig`` each ``generateContent`` request carried. Gemini 3 Pro takes ``low`` or ``high``,
Gemini 3 Flash takes ``minimal`` to ``high``, and the thinking budget picks among them.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.core.types import Message, ProviderCredentials, ThinkingConfig
from intellicrack.providers.capabilities import ApiDialect
from intellicrack.providers.configurable import ConfigurableProvider
from intellicrack.providers.google import GoogleProvider
from intellicrack.providers.instances import ProviderInstance
from tests._helpers.scripted_sdk_server import ScriptedHTTPServer, json_response


if TYPE_CHECKING:
    from collections.abc import Iterator

    from intellicrack.providers.base import LLMProviderBase


_API_KEY: Final[str] = "AIza" + "LoopbackThinkingLevel0123456789"
_MODELS: Final[tuple[str, ...]] = ("gemini-3-pro-preview", "gemini-3-flash-preview", "gemini-2.5-pro")
_CAMEL: Final[dict[str, str]] = {
    "thinking_level": "thinkingLevel",
    "thinking_budget": "thinkingBudget",
    "include_thoughts": "includeThoughts",
}
"""The google-genai SDK writes ``thinkingConfig``'s fields in snake case, which the API accepts as well."""


def _generate_body() -> dict[str, Any]:
    """Build a ``generateContent`` response.

    Returns:
        dict[str, Any]: The response body.
    """
    return {
        "candidates": [{"content": {"role": "model", "parts": [{"text": "ok"}]}, "finishReason": "STOP", "index": 0}],
        "usageMetadata": {"promptTokenCount": 4, "candidatesTokenCount": 1, "totalTokenCount": 5},
        "modelVersion": "gemini",
    }


@pytest.fixture
def server() -> Iterator[ScriptedHTTPServer]:
    """Run a loopback Gemini endpoint answering every model.

    Yields:
        ScriptedHTTPServer: The running server.
    """
    routes = {("POST", f"/v1beta/models/{model}:generateContent"): json_response(_generate_body()) for model in _MODELS}
    running = ScriptedHTTPServer({("GET", "/v1beta/models"): json_response({"models": []}), **routes})
    yield running
    running.close()


async def _builtin(server: ScriptedHTTPServer) -> LLMProviderBase:
    """Connect the built-in Google provider.

    Args:
        server: The running server.

    Returns:
        LLMProviderBase: The provider.
    """
    provider = GoogleProvider()
    await provider.connect(ProviderCredentials(api_key=_API_KEY, api_base=server.origin))
    return provider


async def _instance(server: ScriptedHTTPServer) -> LLMProviderBase:
    """Connect a Gemini instance configured by hand, with no preset.

    Args:
        server: The running server.

    Returns:
        LLMProviderBase: The provider.
    """
    provider = ConfigurableProvider(ProviderInstance(instance_id="gemini-gw", dialect=ApiDialect.GEMINI, api_base=server.origin))
    await provider.connect(ProviderCredentials(api_key=_API_KEY))
    return provider


def _thinking_sent(server: ScriptedHTTPServer, *, builtin: bool, model: str, budget: int) -> dict[str, Any]:
    """Run one thinking turn and return the ``thinkingConfig`` the endpoint received.

    Args:
        server: The running server.
        builtin: Whether to use the built-in provider rather than the instance.
        model: The model.
        budget: The thinking budget.

    Returns:
        dict[str, Any]: The ``thinkingConfig``, its keys spelled as the REST API documents them whichever spelling the
        client sent.
    """

    async def run() -> None:
        """Connect and run the turn."""
        provider = await (_builtin(server) if builtin else _instance(server))
        _ = await provider.chat(
            [Message(role="user", content="think")],
            model,
            thinking=ThinkingConfig(enabled=True, budget_tokens=budget),
        )

    asyncio.run(run())
    body = server.requests(f"/v1beta/models/{model}:generateContent")[-1].body
    config: dict[str, Any] = body["generationConfig"]["thinkingConfig"]
    return {_CAMEL.get(key, key): value for key, value in config.items()}


@pytest.mark.parametrize("builtin", [True, False], ids=["builtin", "instance"])
@pytest.mark.parametrize(
    ("model", "budget", "level"),
    [
        ("gemini-3-pro-preview", 2_000, "low"),
        ("gemini-3-pro-preview", 30_000, "high"),
        ("gemini-3-flash-preview", 2_000, "low"),
        ("gemini-3-flash-preview", 10_000, "medium"),
        ("gemini-3-flash-preview", 30_000, "high"),
    ],
)
def test_gemini_3_is_sent_a_thinking_level(server: ScriptedHTTPServer, model: str, budget: int, level: str, *, builtin: bool) -> None:
    """Gemini 3 gets the level the budget maps to among the levels the model offers, and no budget.

    Args:
        server: The loopback endpoint.
        model: The model.
        budget: The thinking budget.
        level: The level that must be sent.
        builtin: Whether to use the built-in provider.
    """
    config = _thinking_sent(server, builtin=builtin, model=model, budget=budget)
    assert str(config["thinkingLevel"]).lower() == level
    assert "thinkingBudget" not in config
    assert config["includeThoughts"] is True


@pytest.mark.parametrize("builtin", [True, False], ids=["builtin", "instance"])
def test_gemini_2_5_keeps_its_thinking_budget(server: ScriptedHTTPServer, *, builtin: bool) -> None:
    """Gemini 2.5 is still sent the budget itself.

    Args:
        server: The loopback endpoint.
        builtin: Whether to use the built-in provider.
    """
    config = _thinking_sent(server, builtin=builtin, model="gemini-2.5-pro", budget=6_000)
    assert config["thinkingBudget"] == 6_000
    assert "thinkingLevel" not in config
