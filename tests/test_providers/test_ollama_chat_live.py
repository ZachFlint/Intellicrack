# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Live end-to-end integration tests for the Ollama provider.

These tests exercise a running local Ollama daemon via HTTP. They probe
``/api/tags`` to pick the first installed model and then perform one
``chat()`` call and one ``chat_stream()`` call, asserting that content is
returned and that usage tokens are recorded on ``get_pending_usage()``.

The entire module is skipped when the daemon is unreachable or when no
models are installed, so CI without Ollama simply reports a skip.
"""

from __future__ import annotations

import os
from http import HTTPStatus
from typing import Any, cast

import httpx
import pytest

from intellicrack.core.types import Message, ProviderCredentials
from intellicrack.providers.ollama import OllamaProvider


pytestmark = pytest.mark.asyncio


_OLLAMA_BASE_URL = os.environ.get(
    "INTELLICRACK_OLLAMA_TEST_URL",
    "http://localhost:11434",
).rstrip("/")


def _pick_first_installed_model() -> str | None:
    """Return the first model name from ``/api/tags`` or ``None``.

    Returns:
        str | None: The first model name reported by the local daemon, or
        ``None`` if the daemon is unreachable or reports no models.
    """
    try:
        response = httpx.get(f"{_OLLAMA_BASE_URL}/api/tags", timeout=5.0)
    except (OSError, httpx.HTTPError):
        return None
    if response.status_code != HTTPStatus.OK:
        return None
    try:
        payload: Any = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    payload_dict = cast("dict[str, Any]", payload)
    raw_models = payload_dict.get("models")
    if not isinstance(raw_models, list):
        return None
    raw_list = cast("list[Any]", raw_models)
    for entry in raw_list:
        if not isinstance(entry, dict):
            continue
        entry_dict = cast("dict[str, Any]", entry)
        name = entry_dict.get("name")
        if isinstance(name, str) and name:
            return name
    return None


async def test_live_ollama_chat_and_stream() -> None:
    """Exercise a real Ollama daemon end-to-end.

    Skips if no daemon is reachable or no model is installed. When
    available, performs one non-streaming ``chat()`` and one streaming
    ``chat_stream()`` against the first installed model and asserts that
    content was produced and usage counters were populated.
    """
    model_name = _pick_first_installed_model()
    if model_name is None:
        pytest.skip(
            f"Ollama daemon at {_OLLAMA_BASE_URL} is unreachable or has no installed models",
        )

    provider = OllamaProvider()
    credentials = ProviderCredentials(
        api_key=None,
        api_base=_OLLAMA_BASE_URL,
    )
    await provider.connect(credentials)
    try:
        await _exercise_ollama_chat_and_stream(provider, model_name)
    finally:
        await provider.disconnect()


async def _exercise_ollama_chat_and_stream(provider: OllamaProvider, model_name: str) -> None:
    """Run non-streaming and streaming Ollama exchanges and assert metadata.

    Args:
        provider: Connected OllamaProvider instance.
        model_name: Installed Ollama model name to use (without ``local/`` prefix).
    """
    assert provider.is_connected is True
    assert provider.local_available is True

    messages = [
        Message(role="user", content="Reply with the single word: ready"),
    ]

    await _exercise_ollama_chat(provider, messages, model_name)
    await _exercise_ollama_stream(provider, messages, model_name)


async def _exercise_ollama_chat(
    provider: OllamaProvider,
    messages: list[Message],
    model_name: str,
) -> None:
    """Run one non-streaming chat call and assert content plus usage.

    Args:
        provider: Connected OllamaProvider instance.
        messages: Message list passed to ``chat``.
        model_name: Installed model name (no ``local/`` prefix).
    """
    response_msg, tool_calls = await provider.chat(
        messages=messages,
        model=f"local/{model_name}",
        temperature=0.0,
        max_tokens=32,
    )
    assert response_msg.content is not None
    assert isinstance(response_msg.content, str)
    assert len(response_msg.content.strip()) > 0
    assert tool_calls is None or isinstance(tool_calls, list)

    usage = provider.get_pending_usage()
    assert usage is not None
    assert usage.prompt_tokens > 0
    assert usage.completion_tokens > 0
    assert usage.total_tokens == usage.prompt_tokens + usage.completion_tokens


async def _exercise_ollama_stream(
    provider: OllamaProvider,
    messages: list[Message],
    model_name: str,
) -> None:
    """Run one streaming chat call and assert content plus usage.

    Args:
        provider: Connected OllamaProvider instance.
        messages: Message list passed to ``chat_stream``.
        model_name: Installed model name (no ``local/`` prefix).
    """
    collected: list[str] = []
    stream_iter = provider.chat_stream(
        messages=messages,
        model=f"local/{model_name}",
        temperature=0.0,
        max_tokens=32,
    )
    async for chunk in stream_iter:
        assert isinstance(chunk, str)
        collected.append(chunk)

    streamed_content = "".join(collected)
    assert len(streamed_content.strip()) > 0

    stream_usage = provider.get_pending_usage()
    assert stream_usage is not None
    assert stream_usage.prompt_tokens > 0
    assert stream_usage.completion_tokens > 0
    assert stream_usage.total_tokens == stream_usage.prompt_tokens + stream_usage.completion_tokens
