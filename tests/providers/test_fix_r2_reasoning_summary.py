# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 23: thinking keeps working for an organization OpenAI will not give reasoning summaries to.

A loopback server answers ``POST /v1/responses`` the way OpenAI answers an unverified organization's thinking-enabled request: ``400``
``invalid_request_error`` with ``param: reasoning.summary``. The gates drive the real built-in :class:`OpenAIProvider` through the real
``openai`` SDK, plainly and streaming, and a real Responses :class:`ConfigurableProvider`, and read the request bodies the server received.
In automatic mode the turn is retried once without ``summary`` and later turns never ask for one; switched on, the refusal surfaces; switched
off, no summary is asked for at all. The mode is read from ``providers.json`` at startup and written by the settings panel.
"""

from __future__ import annotations

import asyncio
import importlib
from typing import TYPE_CHECKING, Any, Final, cast

import pytest
from PyQt6.QtWidgets import QComboBox

from intellicrack.core import config as config_module
from intellicrack.core.logging import get_logger
from intellicrack.core.types import Message, ProviderCredentials, ReasoningSummaryRefusedError, ThinkingConfig
from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.provider_settings import (
    PROVIDER_SETTINGS_FILENAME,
    REASONING_SUMMARIES_KEY,
    ProviderSettingsStore,
    saved_reasoning_summary_mode,
)
from intellicrack.providers.capabilities import ApiDialect, ReasoningSummaryMode
from intellicrack.providers.configurable import ConfigurableProvider
from intellicrack.providers.instances import ProviderInstance
from intellicrack.providers.openai import OpenAIProvider
from intellicrack.ui.provider_config import ProviderSettingsWidget
from tests._helpers.scripted_sdk_server import ScriptedHTTPServer, ScriptedResponse, json_response, sse_response


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence
    from pathlib import Path

    from pytestqt.qtbot import QtBot
    from structlog.stdlib import BoundLogger

    from intellicrack.providers.base import LLMProviderBase


_MODEL: Final[str] = "gpt-5.2"
_API_KEY: Final[str] = "sk-proj-loopbackSummaryKey0123456789"
_MODELS_PATH: Final[str] = "/v1/models"
_RESPONSES_PATH: Final[str] = "/v1/responses"
_THINKING: Final[ThinkingConfig] = ThinkingConfig(enabled=True, budget_tokens=8000)
_apply_saved_capability_overrides = cast(
    "Callable[[LLMProviderBase, str, BoundLogger], None]",
    importlib.import_module("intellicrack.main")._apply_saved_capability_overrides,
)
_REFUSAL: Final[dict[str, Any]] = {
    "error": {
        "message": "Your organization must be verified to generate reasoning summaries. Please go to "
        "https://platform.openai.com/settings/organization/general and click on Verify Organization.",
        "type": "invalid_request_error",
        "param": "reasoning.summary",
        "code": "unsupported_value",
    },
}


def _refused() -> ScriptedResponse:
    """Answer as OpenAI answers an unverified organization's request for a summary.

    Returns:
        ScriptedResponse: The ``400``.
    """
    return json_response(_REFUSAL, status=400)


def _response_object(status: str, **extra: object) -> dict[str, Any]:
    """Build a Responses ``response`` object.

    Args:
        status: The response status.
        **extra: Further fields.

    Returns:
        dict[str, Any]: The object.
    """
    return {
        "id": "resp_loopback",
        "object": "response",
        "created_at": 1_760_000_000,
        "model": _MODEL,
        "status": status,
        "output": [],
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
        "usage": {"input_tokens": 3, "output_tokens": 2, "total_tokens": 5},
        **extra,
    }


def _answered() -> ScriptedResponse:
    """Answer a plain Responses request with one line of text.

    Returns:
        ScriptedResponse: The response.
    """
    message: dict[str, Any] = {
        "type": "message",
        "id": "msg_1",
        "role": "assistant",
        "status": "completed",
        "content": [{"type": "output_text", "text": "thought it through", "annotations": []}],
    }
    return json_response(_response_object("completed", output=[message]))


def _streamed() -> ScriptedResponse:
    """Answer a streaming Responses request with one text delta.

    Returns:
        ScriptedResponse: The event stream.
    """
    return sse_response([
        {"type": "response.created", "sequence_number": 0, "response": _response_object("in_progress")},
        {
            "type": "response.output_text.delta",
            "sequence_number": 1,
            "item_id": "msg_1",
            "output_index": 0,
            "content_index": 0,
            "delta": "streamed thought",
            "logprobs": [],
        },
        {"type": "response.completed", "sequence_number": 2, "response": _response_object("completed")},
    ])


@pytest.fixture
def servers() -> Iterator[list[ScriptedHTTPServer]]:
    """Collect started servers and stop them after the test.

    Yields:
        list[ScriptedHTTPServer]: The servers a test started.
    """
    started: list[ScriptedHTTPServer] = []
    yield started
    for server in started:
        server.close()


def _start(started: list[ScriptedHTTPServer], responses: Sequence[ScriptedResponse]) -> ScriptedHTTPServer:
    """Start a loopback OpenAI endpoint.

    Args:
        started: The fixture's list of servers.
        responses: What ``POST /v1/responses`` answers, in order.

    Returns:
        ScriptedHTTPServer: The running server.
    """
    listing = json_response({"object": "list", "data": [{"id": _MODEL, "object": "model", "created": 0, "owned_by": "openai"}]})
    server = ScriptedHTTPServer({("GET", _MODELS_PATH): listing, ("POST", _RESPONSES_PATH): list(responses)})
    started.append(server)
    return server


async def _openai(server: ScriptedHTTPServer, mode: ReasoningSummaryMode = ReasoningSummaryMode.AUTO) -> OpenAIProvider:
    """Connect the built-in OpenAI provider to the loopback endpoint.

    Args:
        server: The running server.
        mode: The reasoning-summary mode to set.

    Returns:
        OpenAIProvider: The connected provider, whose SDK retries nothing on its own.
    """
    provider = OpenAIProvider()
    provider.set_reasoning_summary_mode(mode)
    await provider.connect(ProviderCredentials(api_key=_API_KEY, api_base=f"{server.origin}/v1"))
    assert provider.client is not None
    provider.client = provider.client.with_options(max_retries=0)
    return provider


def _summaries_sent(server: ScriptedHTTPServer) -> list[bool]:
    """Report, per Responses request received, whether it asked for a reasoning summary.

    Args:
        server: The running server.

    Returns:
        list[bool]: One flag per request, in order.
    """
    flags: list[bool] = []
    for request in server.requests(_RESPONSES_PATH):
        reasoning = request.body.get("reasoning")
        assert isinstance(reasoning, dict), "thinking was not sent"
        assert "effort" in reasoning
        flags.append("summary" in reasoning)
    return flags


async def _ask(provider: LLMProviderBase) -> str:
    """Run one thinking-enabled turn.

    Args:
        provider: The provider.

    Returns:
        str: The assistant's text.
    """
    message, _ = await provider.chat([Message(role="user", content="think about it")], _MODEL, thinking=_THINKING)
    return message.content


async def _ask_streaming(provider: LLMProviderBase) -> str:
    """Stream one thinking-enabled turn.

    Args:
        provider: The provider.

    Returns:
        str: The streamed text.
    """
    chunks = [chunk async for chunk in provider.chat_stream([Message(role="user", content="think about it")], _MODEL, thinking=_THINKING)]
    return "".join(chunks)


def test_builtin_openai_retries_without_summary_and_remembers(servers: list[ScriptedHTTPServer]) -> None:
    """The refused turn is retried once without ``summary`` and answered; the next turn does not ask again.

    Args:
        servers: Started servers.
    """
    server = _start(servers, [_refused(), _answered(), _answered()])

    async def run() -> tuple[str, str]:
        """Run two turns.

        Returns:
            tuple[str, str]: Both answers.
        """
        provider = await _openai(server)
        return await _ask(provider), await _ask(provider)

    assert asyncio.run(run()) == ("thought it through", "thought it through")
    assert _summaries_sent(server) == [True, False, False]


def test_builtin_openai_stream_retries_without_summary(servers: list[ScriptedHTTPServer]) -> None:
    """A refused stream is reopened without ``summary`` before anything is yielded.

    Args:
        servers: Started servers.
    """
    server = _start(servers, [_refused(), _streamed(), _streamed()])

    async def run() -> tuple[str, str]:
        """Stream two turns.

        Returns:
            tuple[str, str]: Both streamed texts.
        """
        provider = await _openai(server)
        return await _ask_streaming(provider), await _ask_streaming(provider)

    assert asyncio.run(run()) == ("streamed thought", "streamed thought")
    assert _summaries_sent(server) == [True, False, False]


def test_summaries_switched_on_surface_the_refusal(servers: list[ScriptedHTTPServer]) -> None:
    """With summaries switched on, the refusal is reported rather than worked around.

    Args:
        servers: Started servers.
    """
    server = _start(servers, [_refused(), _answered()])

    async def run() -> None:
        """Run one turn."""
        await _ask(await _openai(server, ReasoningSummaryMode.ON))

    with pytest.raises(ReasoningSummaryRefusedError, match="verified"):
        asyncio.run(run())
    assert _summaries_sent(server) == [True]


def test_summaries_switched_off_are_never_asked_for(servers: list[ScriptedHTTPServer]) -> None:
    """With summaries switched off, thinking is sent with its effort and no summary.

    Args:
        servers: Started servers.
    """
    server = _start(servers, [_answered()])

    async def run() -> str:
        """Run one turn.

        Returns:
            str: The answer.
        """
        return await _ask(await _openai(server, ReasoningSummaryMode.OFF))

    assert asyncio.run(run()) == "thought it through"
    assert _summaries_sent(server) == [False]


@pytest.mark.parametrize("stream", [False, True], ids=["plain", "streaming"])
def test_responses_instance_retries_without_summary_and_remembers(servers: list[ScriptedHTTPServer], *, stream: bool) -> None:
    """A Responses instance falls back and remembers the same way.

    Args:
        servers: Started servers.
        stream: Whether the turns stream.
    """
    answer = _streamed if stream else _answered
    server = _start(servers, [_refused(), answer(), answer()])
    instance = ProviderInstance(instance_id="gateway", dialect=ApiDialect.RESPONSES, api_base=f"{server.origin}/v1")

    async def run() -> tuple[str, str]:
        """Run two turns.

        Returns:
            tuple[str, str]: Both answers.
        """
        provider = ConfigurableProvider(instance)
        await provider.connect(ProviderCredentials(api_key=_API_KEY))
        ask = _ask_streaming if stream else _ask
        return await ask(provider), await ask(provider)

    expected = "streamed thought" if stream else "thought it through"
    assert asyncio.run(run()) == (expected, expected)
    assert _summaries_sent(server) == [True, False, False]


def test_saved_mode_is_applied_at_startup_and_written_by_the_panel(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The settings panel saves the mode to ``providers.json``, and startup sets it on the provider.

    Args:
        qtbot: The Qt test driver.
        tmp_path: Per-test directory.
        monkeypatch: Points the configuration directory at the test's own.
    """
    config_path = tmp_path / PROVIDER_SETTINGS_FILENAME

    def config_file(name: str) -> Path:
        """Resolve a configuration file inside the test's directory.

        Args:
            name: The file name.

        Returns:
            Path: Its path.
        """
        return tmp_path / name

    monkeypatch.setattr(config_module, "get_config_file", config_file)
    widget = ProviderSettingsWidget(
        provider_id="openai",
        config_path=config_path,
        credential_loader=CredentialLoader(env_path=tmp_path / ".env"),
    )
    qtbot.addWidget(widget)
    combo: QComboBox | None = widget.findChild(QComboBox, "reasoning_summary_combo")
    assert combo is not None
    combo.setCurrentIndex(combo.findData(ReasoningSummaryMode.OFF.value))
    widget.save_settings()

    section = ProviderSettingsStore(config_path).section("openai")
    assert section.get(REASONING_SUMMARIES_KEY) == "off"
    assert saved_reasoning_summary_mode(section) is ReasoningSummaryMode.OFF

    provider = OpenAIProvider()
    _apply_saved_capability_overrides(provider, "openai", get_logger(__name__))
    assert provider.reasoning_summary_mode is ReasoningSummaryMode.OFF
    assert not provider.requests_reasoning_summaries
