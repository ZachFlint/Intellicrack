# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Live end-to-end tests for GoogleProvider chat and streaming.

These tests exercise ``chat()`` and ``chat_stream()`` against the live
Google Gemini API using ``gemini-1.5-flash``. They are skipped when no
``GOOGLE_API_KEY`` is configured in the project ``.env`` so the suite
remains runnable offline.

Tests also assert that usage metadata is populated on the provider's
``_pending_usage`` attribute and retrievable via ``get_pending_usage()``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.core.types import (
    AuthenticationError,
    Message,
    ProviderError,
    ProviderName,
    RateLimitError,
)
from intellicrack.providers.google import GoogleProvider, UsageInfo


if TYPE_CHECKING:
    from intellicrack.credentials.env_loader import CredentialLoader


_MODEL = "gemini-1.5-flash"


def _user_message(text: str) -> list[Message]:
    """Build a minimal single-turn user message list.

    Args:
        text: The user prompt to send.

    Returns:
        list[Message]: Single-item list containing the user message.
    """
    return [Message(role="user", content=text)]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_live_google_chat_populates_usage(
    credential_loader: CredentialLoader,
    *,
    has_google_key: bool,
) -> None:
    """Exercise ``chat()`` once and confirm content plus usage metadata.

    Args:
        credential_loader: Credential loader fixture.
        has_google_key: Whether a Google API key is configured.
    """
    if not has_google_key:
        pytest.skip("GOOGLE_API_KEY not configured in .env")

    provider = GoogleProvider()
    credentials = credential_loader.get_credentials(ProviderName.GOOGLE)
    assert credentials is not None, "Expected credentials after validation"

    await provider.connect(credentials)
    try:
        await _exercise_google_chat(provider)
    finally:
        await provider.disconnect()

    assert provider.is_connected is False


async def _exercise_google_chat(provider: GoogleProvider) -> None:
    """Run a single chat exchange and assert content plus usage metadata.

    Args:
        provider: Connected GoogleProvider instance.
    """
    assert provider.is_connected is True

    try:
        message, tool_calls = await provider.chat(
            messages=_user_message("Reply with exactly the word: ready"),
            model=_MODEL,
            temperature=0.0,
            max_tokens=16,
        )
    except RateLimitError:
        pytest.skip("Google API quota exceeded for this project")
    except AuthenticationError:
        pytest.skip("Google API rejected credentials")
    except ProviderError as exc:
        pytest.skip(f"Google API request failed: {exc}")

    assert message.role == "assistant"
    assert isinstance(message.content, str)
    assert len(message.content.strip()) > 0, "Expected non-empty content"
    assert tool_calls is None or isinstance(tool_calls, list)

    usage = provider.get_pending_usage()
    assert usage is not None, "Expected usage populated after chat()"
    assert isinstance(usage, UsageInfo)
    assert usage.prompt_tokens > 0
    assert usage.completion_tokens >= 0
    assert usage.total_tokens >= usage.prompt_tokens

    assert provider.get_pending_usage() is None, "Expected usage buffer cleared after retrieval"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_live_google_chat_stream_populates_usage(
    credential_loader: CredentialLoader,
    *,
    has_google_key: bool,
) -> None:
    """Exercise ``chat_stream()`` and verify chunks plus usage metadata.

    Args:
        credential_loader: Credential loader fixture.
        has_google_key: Whether a Google API key is configured.
    """
    if not has_google_key:
        pytest.skip("GOOGLE_API_KEY not configured in .env")

    provider = GoogleProvider()
    credentials = credential_loader.get_credentials(ProviderName.GOOGLE)
    assert credentials is not None, "Expected credentials after validation"

    await provider.connect(credentials)
    try:
        await _exercise_google_chat_stream(provider)
    finally:
        await provider.disconnect()

    assert provider.is_connected is False


async def _exercise_google_chat_stream(provider: GoogleProvider) -> None:
    """Stream a chat exchange and assert content plus usage metadata.

    Args:
        provider: Connected GoogleProvider instance.
    """
    collected: list[str] = []
    try:
        async for chunk in provider.chat_stream(
            messages=_user_message("List three primary colors, one per line."),
            model=_MODEL,
            temperature=0.0,
            max_tokens=64,
        ):
            assert isinstance(chunk, str)
            collected.append(chunk)
    except RateLimitError:
        pytest.skip("Google API quota exceeded for this project")
    except AuthenticationError:
        pytest.skip("Google API rejected credentials")
    except ProviderError as exc:
        pytest.skip(f"Google API stream failed: {exc}")

    full_text = "".join(collected)
    assert len(full_text.strip()) > 0, "Expected non-empty streamed content"

    usage = provider.get_pending_usage()
    assert usage is not None, "Expected usage populated after chat_stream()"
    assert isinstance(usage, UsageInfo)
    assert usage.prompt_tokens > 0
    assert usage.completion_tokens >= 0
    assert usage.total_tokens >= usage.prompt_tokens
