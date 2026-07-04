# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Live end-to-end tests for ``LocalTransformersProvider`` chat and streaming.

Loads a tiny model (``TinyLlama/TinyLlama-1.1B-Chat-v1.0``) and
exercises the full chat and chat_stream paths, asserting non-empty
responses and populated usage metadata.  Also verifies clean unload
and disconnect.  Falls back to CPU when no GPU/XPU is available - the
tests never skip for device reasons.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio

from intellicrack.core.types import Message, ProviderCredentials
from intellicrack.providers.base import UsageInfo
from intellicrack.providers.local_transformers import LocalTransformersProvider


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

_LIVE_MODEL_ID = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"


def _make_user_messages(prompt: str) -> list[Message]:
    """Build a single-user-message conversation for the live smoke test.

    Args:
        prompt: The user prompt content.

    Returns:
        list[Message]: A one-element list containing a user Message.
    """
    return [Message(role="user", content=prompt, timestamp=datetime.now(tz=UTC))]


@pytest_asyncio.fixture
async def live_provider() -> AsyncIterator[LocalTransformersProvider]:
    """Connect and yield a fresh provider per test, with clean teardown.

    Creates a :class:`LocalTransformersProvider`, connects it, yields it
    to the test, then unloads the model and disconnects.  The provider
    honours its own deterministic CUDA -> XPU -> CPU selection order,
    so when no accelerator is present the provider falls back to CPU
    automatically and the test still runs.

    Yields:
        LocalTransformersProvider: A connected provider ready for
        ``chat()`` / ``chat_stream()`` calls.  The yielded value is
        valid until control returns to the fixture for teardown.
    """
    provider = LocalTransformersProvider(prefer_xpu=True)
    await provider.connect(ProviderCredentials())
    try:
        yield provider
    finally:
        await provider.unload_model()
        await provider.disconnect()


async def test_chat_produces_text_and_usage(
    live_provider: LocalTransformersProvider,
) -> None:
    """Live chat should return non-empty text and populate ``_pending_usage``.

    Args:
        live_provider: Per-test connected provider.
    """
    messages = _make_user_messages("Complete this sentence: The sky is")
    message, tool_calls = await live_provider.chat(
        messages=messages,
        model=_LIVE_MODEL_ID,
        max_tokens=8,
        temperature=0.0,
    )

    assert message.role == "assistant"
    assert len(message.content) > 0
    assert tool_calls is None

    usage = live_provider.get_pending_usage()
    assert usage is not None
    assert isinstance(usage, UsageInfo)
    assert usage.prompt_tokens > 0
    assert usage.completion_tokens > 0
    assert usage.total_tokens == usage.prompt_tokens + usage.completion_tokens


async def test_chat_stream_yields_text_and_usage(
    live_provider: LocalTransformersProvider,
) -> None:
    """Streaming should yield at least one chunk and populate usage on exit.

    Args:
        live_provider: Per-test connected provider.
    """
    messages = _make_user_messages("Name a color:")
    chunks: list[str] = [
        chunk
        async for chunk in live_provider.chat_stream(
            messages=messages,
            model=_LIVE_MODEL_ID,
            max_tokens=8,
            temperature=0.0,
        )
    ]

    full_text = "".join(chunks).strip()
    assert full_text != ""

    usage = live_provider.get_pending_usage()
    assert usage is not None
    assert isinstance(usage, UsageInfo)
    assert usage.prompt_tokens > 0
    assert usage.completion_tokens > 0
    assert usage.total_tokens == usage.prompt_tokens + usage.completion_tokens


async def test_unload_then_disconnect_cleanly() -> None:
    """Unload should drop the model and disconnect should leave state clean.

    This test drives the provider lifecycle directly (not via the
    ``live_provider`` fixture) so the clean-shutdown behaviour can be
    observed independently of the chat-path fixtures above.
    """
    provider = LocalTransformersProvider(prefer_xpu=True)
    await provider.connect(ProviderCredentials())

    messages = _make_user_messages("Hello")
    await provider.chat(
        messages=messages,
        model=_LIVE_MODEL_ID,
        max_tokens=1,
        temperature=0.0,
    )

    await provider.unload_model()
    await provider.disconnect()
    assert provider.connected is False
