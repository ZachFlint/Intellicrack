# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Live end-to-end tests for the Anthropic usage and extended-thinking buffers.

These tests exercise :class:`AnthropicProvider` against the real
Anthropic API to confirm the streaming usage buffer and the extended
thinking buffer populated by the provider are observable via
``get_pending_usage()`` and ``get_pending_thinking()``.

The tests skip automatically when ``ANTHROPIC_API_KEY`` is not
available from the credential store.

Run locally with ``INTELLICRACK_LOCAL_TESTS=1 pixi run pytest
tests/test_providers/test_anthropic_buffers_live.py -x``.
"""

from __future__ import annotations

import asyncio

import pytest

from pathlib import Path

from intellicrack.core.types import (
    Message,
    ProviderCredentials,
    ProviderName,
    ThinkingConfig,
)
from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.store import CredentialStore, get_credential_store
from intellicrack.providers.anthropic import AnthropicProvider
from intellicrack.providers.base import UsageInfo


_PROJECT_ROOT = Path("D:/Intellicrack")
_ENV_PATH = _PROJECT_ROOT / ".env"


_SKIP_REASON_NO_KEY = (
    "ANTHROPIC_API_KEY not available in credential store (keyring or .env). "
    "Live Anthropic buffers test skipped."
)
_SKIP_REASON_NO_CREDIT = (
    "Anthropic API returned a credit / payment error before the live buffers "
    "could be validated. Live Anthropic buffers test skipped."
)


_CREDIT_MARKERS: tuple[str, ...] = (
    "credit",
    "payment",
    "billing",
    "quota",
    "insufficient",
)


def _is_credit_error(exc: BaseException) -> bool:
    """Return ``True`` when ``exc`` or any chained cause signals a billing issue.

    The Anthropic SDK wraps a 400 "credit balance too low" body inside an
    ``anthropic.APIError``; our provider translates that to
    :class:`~intellicrack.core.types.ProviderError` with a static message.
    The original body survives on ``__cause__`` / ``__context__``, so we
    walk the exception chain looking for known billing markers.

    Args:
        exc: Exception raised by the provider under test.

    Returns:
        bool: ``True`` when any linked exception text contains a known
        credit / billing marker, ``False`` otherwise.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        text = str(current).lower()
        if any(marker in text for marker in _CREDIT_MARKERS):
            return True
        current = current.__cause__ or current.__context__
    return False


async def _resolve_anthropic_credentials() -> ProviderCredentials | None:
    """Load Anthropic credentials from the secure credential store.

    The global credential store is consulted first.  When it cannot
    locate credentials (for example because the global
    :class:`CredentialLoader` was initialised before the project ``.env``
    was discoverable), the project-root ``.env`` is used as an explicit
    fallback so the live test can run from any working directory.

    Returns:
        ProviderCredentials | None: Loaded credentials when they are
        configured, otherwise ``None``.
    """
    store = get_credential_store()
    creds = await store.get(ProviderName.ANTHROPIC)
    if creds is not None and creds.api_key:
        return creds

    if not _ENV_PATH.exists():
        return None

    fallback_store = CredentialStore(fallback_loader=CredentialLoader(env_path=_ENV_PATH))
    return await fallback_store.get(ProviderName.ANTHROPIC)


async def _pick_chat_model(provider: AnthropicProvider) -> str:
    """Select a live model identifier usable for the chat tests.

    Prefers a Haiku-class model when available because it is cheapest
    for smoke-testing; otherwise falls back to the first model the API
    reports.

    Args:
        provider: Connected :class:`AnthropicProvider` instance.

    Returns:
        str: Model identifier to use with ``chat()`` / ``chat_stream()``.
    """
    models = await provider.list_models()
    assert models, "Anthropic API returned no models"
    for model in models:
        if "haiku" in model.id.lower():
            return model.id
    return models[0].id


async def _pick_thinking_model(provider: AnthropicProvider) -> str | None:
    """Select a live model identifier that supports extended thinking.

    Anthropic exposes extended thinking on Claude 3.7 / 4 Sonnet and
    Opus class models.  Haiku does not support thinking.

    Args:
        provider: Connected :class:`AnthropicProvider` instance.

    Returns:
        str | None: Model identifier that supports extended thinking, or
        ``None`` when none of the listed models are eligible.
    """
    models = await provider.list_models()
    eligible_substrings = ("claude-sonnet-4", "claude-opus-4", "claude-3-7", "claude-sonnet-4-5")
    for model in models:
        lower = model.id.lower()
        if any(token in lower for token in eligible_substrings):
            return model.id
    return None


@pytest.mark.asyncio
async def test_anthropic_chat_and_stream_populate_usage_and_thinking() -> None:
    """Validate chat() and chat_stream() populate usage + thinking buffers.

    The test asserts that ``get_pending_usage()`` returns a populated
    :class:`UsageInfo` after both a non-streaming ``chat()`` call and a
    streaming ``chat_stream()`` call.  When a thinking-capable model is
    available, ``get_pending_thinking()`` is also asserted to be populated
    after a thinking-enabled request.

    Raises:
        AssertionError: If the buffers are not populated as expected.
        Exception: Any non-credit-related error raised by the live API is
            re-raised after the skip check so the test surfaces it.
    """
    credentials = await _resolve_anthropic_credentials()
    if credentials is None:
        pytest.skip(_SKIP_REASON_NO_KEY)

    provider = AnthropicProvider()
    await provider.connect(credentials)
    try:
        chat_model = await _pick_chat_model(provider)
        thinking_model = await _pick_thinking_model(provider)

        chat_messages: list[Message] = [Message(role="user", content="Reply with exactly one word: pong.")]

        try:
            await provider.chat(
                messages=chat_messages,
                model=chat_model,
                max_tokens=16,
                temperature=0.0,
            )
        except Exception as exc:
            if _is_credit_error(exc):
                pytest.skip(_SKIP_REASON_NO_CREDIT)
            raise

        post_chat_usage = provider.get_pending_usage()
        assert post_chat_usage is not None, "chat() did not populate _pending_usage"
        assert isinstance(post_chat_usage, UsageInfo)
        assert post_chat_usage.prompt_tokens > 0
        assert post_chat_usage.completion_tokens > 0
        assert post_chat_usage.total_tokens >= post_chat_usage.prompt_tokens

        stream_messages: list[Message] = [Message(role="user", content="Count aloud to three.")]
        collected_chunks: list[str] = []
        try:
            async for chunk in provider.chat_stream(
                messages=stream_messages,
                model=chat_model,
                max_tokens=64,
                temperature=0.0,
            ):
                collected_chunks.append(chunk)
        except Exception as exc:
            if _is_credit_error(exc):
                pytest.skip(_SKIP_REASON_NO_CREDIT)
            raise

        assert collected_chunks, "chat_stream() yielded no chunks"
        stream_usage = provider.get_pending_usage()
        assert stream_usage is not None, "chat_stream() did not populate _pending_usage"
        assert isinstance(stream_usage, UsageInfo)
        assert stream_usage.prompt_tokens > 0
        assert stream_usage.completion_tokens > 0
        assert stream_usage.total_tokens >= stream_usage.prompt_tokens

        assert provider.get_pending_usage() is None, "get_pending_usage() did not clear buffer"

        if thinking_model is not None:
            thinking_messages: list[Message] = [
                Message(
                    role="user",
                    content="Think about whether 17 is prime, then answer yes or no.",
                ),
            ]
            try:
                async for _chunk in provider.chat_stream(
                    messages=thinking_messages,
                    model=thinking_model,
                    max_tokens=2048,
                    temperature=1.0,
                    thinking=ThinkingConfig(enabled=True, budget_tokens=1024),
                ):
                    pass
            except Exception as exc:
                message = str(exc).lower()
                if any(marker in message for marker in ("credit", "payment", "billing", "quota")):
                    pytest.skip(_SKIP_REASON_NO_CREDIT)
                raise

            thinking_blocks = provider.get_pending_thinking()
            assert thinking_blocks, "chat_stream() with thinking enabled did not populate _pending_thinking"
            assert all(isinstance(block, str) and block for block in thinking_blocks)
            assert provider.get_pending_thinking() == [], "get_pending_thinking() did not clear buffer"
    finally:
        await provider.disconnect()


def test_live_module_importable() -> None:
    """Smoke-check that the module imports and event loop can be created.

    Provides a non-skipped test so the file is still collected when
    credentials are absent, preventing ``pytest`` from returning a
    "no tests ran" failure at the module level.
    """
    loop = asyncio.new_event_loop()
    try:
        assert loop is not None
    finally:
        loop.close()
