# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Live end-to-end tests for GoogleProvider chat and streaming.

These tests exercise ``chat()`` and ``chat_stream()`` against the live Google
Gemini API using the stable ``gemini-flash-latest`` alias. They are skipped
only when no ``GOOGLE_API_KEY`` is configured, or by the provider-suite
``pytest_runtest_call`` hook when the live account's billing/quota cap is
exhausted - both are unmet environment preconditions rather than defects.

Crucially, the tests do NOT swallow ``AuthenticationError`` or generic
``ProviderError``: a rejected key, a retired/unknown model, or any other broken
request propagates and fails the test, because those signal real breakage in the
provider bridge or its configuration. Only the genuinely transient
``RateLimitError`` is treated as a skip.

A deterministic, temperature-0 prompt is used so the assertions check semantic
correctness (the model returns the requested word ``ready``) rather than mere
non-emptiness. Usage metadata is asserted for population and internal
consistency - the model's reported ``total_tokens`` is never less than the sum
of the named prompt and completion components (current Gemini models also count
internal reasoning tokens in the total) - and for the single-shot buffer-clear
contract of ``get_pending_usage()``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.core.types import (
    Message,
    ProviderName,
    RateLimitError,
)
from intellicrack.providers.google import GoogleProvider, UsageInfo


if TYPE_CHECKING:
    from intellicrack.credentials.env_loader import CredentialLoader


_MODEL = "gemini-flash-latest"
_MAX_TOKENS = 512
_READY_PROMPT = "Reply with exactly the single word: ready . Output only that word, with no punctuation."


def _user_message(text: str) -> list[Message]:
    """Build a minimal single-turn user message list.

    Args:
        text: The user prompt to send.

    Returns:
        list[Message]: Single-item list containing the user message.
    """
    return [Message(role="user", content=text)]


async def _run_chat_and_verify(provider: GoogleProvider) -> None:
    """Issue one deterministic chat call and assert content, tool calls, and usage.

    Skips only on the transient :class:`RateLimitError`; every other failure
    (authentication, retired model, blocked response) propagates and fails.

    Args:
        provider: A connected GoogleProvider instance.
    """
    try:
        message, tool_calls = await provider.chat(
            messages=_user_message(_READY_PROMPT),
            model=_MODEL,
            temperature=0.0,
            max_tokens=_MAX_TOKENS,
        )
    except RateLimitError:
        pytest.skip("Google API rate limit hit (transient)")

    assert message.role == "assistant"
    assert isinstance(message.content, str)
    assert "ready" in message.content.strip().lower(), f"Deterministic prompt must elicit 'ready'; got {message.content!r}"
    assert tool_calls is None, "A plain text reply must not carry tool calls"

    _assert_usage_populated_then_cleared(provider)


async def _run_stream_and_verify(provider: GoogleProvider) -> None:
    """Stream one deterministic chat call and assert chunks, content, and usage.

    Skips only on the transient :class:`RateLimitError`; every other failure
    propagates and fails.

    Args:
        provider: A connected GoogleProvider instance.
    """
    collected: list[str] = []
    try:
        async for chunk in provider.chat_stream(
            messages=_user_message(_READY_PROMPT),
            model=_MODEL,
            temperature=0.0,
            max_tokens=_MAX_TOKENS,
        ):
            assert isinstance(chunk, str)
            collected.append(chunk)
    except RateLimitError:
        pytest.skip("Google API rate limit hit (transient)")

    assert collected, "Streaming must yield at least one chunk"
    full_text = "".join(collected)
    assert "ready" in full_text.strip().lower(), f"Deterministic streamed prompt must elicit 'ready'; got {full_text!r}"

    _assert_usage_populated_then_cleared(provider)


def _assert_usage_populated_then_cleared(provider: GoogleProvider) -> UsageInfo:
    """Assert pending usage is populated, internally consistent, then cleared once.

    Args:
        provider: A GoogleProvider that has just completed a request.

    Returns:
        UsageInfo: The retrieved usage record.
    """
    usage = provider.get_pending_usage()
    assert usage is not None, "Expected usage populated after the request"
    assert isinstance(usage, UsageInfo)
    assert usage.prompt_tokens > 0, "Gemini bills the prompt; prompt_tokens must be positive"
    assert usage.completion_tokens > 0, "A non-empty reply must report completion tokens"
    assert usage.total_tokens >= usage.prompt_tokens + usage.completion_tokens, (
        "total_tokens must account for at least the prompt plus completion tokens "
        "(current Gemini models additionally count internal reasoning tokens in the total)"
    )

    assert provider.get_pending_usage() is None, "Pending usage buffer must clear after a single retrieval"
    return usage


@pytest.mark.integration
@pytest.mark.asyncio
async def test_live_google_chat_returns_requested_word_and_usage(
    credential_loader: CredentialLoader,
    *,
    has_google_key: bool,
) -> None:
    """``chat()`` returns the deterministically requested word and populates usage.

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
    assert provider.is_connected is True
    try:
        await _run_chat_and_verify(provider)
    finally:
        await provider.disconnect()

    assert provider.is_connected is False


@pytest.mark.integration
@pytest.mark.asyncio
async def test_live_google_chat_stream_streams_requested_word_and_usage(
    credential_loader: CredentialLoader,
    *,
    has_google_key: bool,
) -> None:
    """``chat_stream()`` streams chunks whose concatenation is the requested word and populates usage.

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
    assert provider.is_connected is True
    try:
        await _run_stream_and_verify(provider)
    finally:
        await provider.disconnect()

    assert provider.is_connected is False
