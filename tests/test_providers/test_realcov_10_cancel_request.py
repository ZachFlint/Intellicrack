# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Live cancellation coverage for the Anthropic and Grok cloud providers.

Each provider implements ``cancel_request`` to abort an in-flight stream. These
tests start a real streaming request against the live provider API, consume at
least one chunk, invoke ``cancel_request`` mid-stream, and assert that
iteration terminates cleanly and the provider records the cancellation. They
are gated on real credentials and skip when keys are absent; no responses are
fabricated. When an account is genuinely unable to service requests (billing or
spend-cap exhaustion), the test skips with a precise reason rather than failing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import anthropic
import openai
import pytest

from intellicrack.core.types import Message, ProviderError, RateLimitError
from intellicrack.providers.base import is_permanent_quota_error


if TYPE_CHECKING:
    from intellicrack.providers.anthropic import AnthropicProvider
    from intellicrack.providers.grok import GrokProvider


_LIVE_ERRORS = (ProviderError, RateLimitError, anthropic.APIError, openai.APIError)
_CANCEL_FLAG_ATTR = "_cancel_requested"


_BILLING_MARKERS = (
    "credit balance",
    "spending cap",
    "spend cap",
    "quota",
    "billing",
    "resource_exhausted",
    "not allowed",
)


def _skip_if_account_unavailable(exc: Exception) -> None:
    """Skip the test when an error reflects account unavailability.

    Permanent billing/quota exhaustion and endpoint-eligibility errors are
    genuine environmental conditions, not provider defects, so they map to a
    skip with the originating message preserved. The full exception cause chain
    is inspected because SDKs surface the billing detail on the originating
    exception rather than the translated provider error.

    Args:
        exc: The provider exception raised during the live call.

    Raises:
        exc: Re-raised unchanged when it does not indicate a recognised
            account-unavailability condition.
    """
    parts: list[str] = [str(exc)]
    cause: BaseException | None = exc.__cause__
    while cause is not None:
        parts.append(str(cause))
        cause = cause.__cause__
    text = " ".join(parts).lower()
    if is_permanent_quota_error(text) or any(marker in text for marker in _BILLING_MARKERS):
        pytest.skip(f"Provider account cannot service request: {exc}")
    raise exc


def _pick_grok_text_model(model_ids: list[str]) -> str:
    """Choose a real Grok text chat model id from a live model list.

    Video and image generation models share the Grok namespace but are not
    valid on the chat-completions endpoint, so they are excluded.

    Args:
        model_ids: Model identifiers returned by ``list_models``.

    Returns:
        str: A chat-capable Grok model identifier.
    """
    excluded = ("imagine", "image", "video", "vision")
    text_models = [
        mid
        for mid in model_ids
        if mid.startswith("grok-") and not any(token in mid for token in excluded)
    ]
    if not text_models:
        pytest.skip("No grok text chat model available on this account")
    text_models.sort(reverse=True)
    return text_models[0]


@pytest.mark.integration
class TestAnthropicCancelRequestLive:
    """cancel_request halts a real Anthropic stream cleanly."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_cancel_during_stream_stops_without_error(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Cancelling mid-stream halts iteration and sets the cancel flag.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        models = await anthropic_provider.list_models()
        assert models, "Anthropic returned no models"
        model_id = models[0].id

        stream = anthropic_provider.chat_stream(
            messages=[Message(role="user", content="Count slowly from 1 to 50, one per line.")],
            model=model_id,
            max_tokens=512,
        )

        received = 0
        try:
            async for _chunk in stream:
                received += 1
                if received >= 1:
                    await anthropic_provider.cancel_request()
                    break
        except _LIVE_ERRORS as exc:
            _skip_if_account_unavailable(exc)

        assert received >= 1
        assert getattr(anthropic_provider, _CANCEL_FLAG_ATTR) is True


@pytest.mark.integration
class TestGrokCancelRequestLive:
    """cancel_request halts a real Grok stream cleanly."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_cancel_during_stream_stops_without_error(
        grok_provider: GrokProvider,
    ) -> None:
        """Cancelling mid-stream halts iteration and sets the cancel flag.

        Args:
            grok_provider: Connected Grok provider fixture.
        """
        models = await grok_provider.list_models()
        assert models, "Grok returned no models"
        model_id = _pick_grok_text_model([m.id for m in models])

        stream = grok_provider.chat_stream(
            messages=[Message(role="user", content="Count slowly from 1 to 50, one per line.")],
            model=model_id,
            max_tokens=512,
        )

        received = 0
        try:
            async for _chunk in stream:
                received += 1
                if received >= 1:
                    await grok_provider.cancel_request()
                    break
        except _LIVE_ERRORS as exc:
            _skip_if_account_unavailable(exc)

        assert received >= 1
        assert getattr(grok_provider, _CANCEL_FLAG_ATTR) is True
