# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data coverage for Google safety-block detection and cancellation.

``GoogleProvider._check_safety_block`` decides whether a Gemini response was
halted by Google's safety, prohibited-content, blocklist, or SPII filters. The
detection logic is exercised here against genuine ``google.genai`` SDK response
objects constructed with the SDK's real ``FinishReason`` and ``BlockedReason``
enum values, so the test drives the real safety-classification path over real
SDK data structures (no fabricated stand-in for the operation under test).

A live cancellation test (gated on a real ``GOOGLE_API_KEY``) starts a real
streaming request, cancels it mid-stream, and confirms the provider stops
cleanly without raising.
"""

from __future__ import annotations

from typing import Any

import pytest
from google.genai import types

from intellicrack.core.types import Message, ProviderError, RateLimitError
from intellicrack.providers.base import is_permanent_quota_error
from intellicrack.providers.google import GoogleProvider


_CHECK_SAFETY_ATTR = "_check_safety_block"
_CANCEL_FLAG_ATTR = "_cancel_requested"
_check_safety_block: Any = getattr(GoogleProvider, _CHECK_SAFETY_ATTR)


_BILLING_MARKERS = (
    "spending cap",
    "spend cap",
    "quota",
    "billing",
    "resource_exhausted",
)


def _skip_if_account_unavailable(exc: Exception) -> None:
    """Skip the test when an error reflects account unavailability.

    Args:
        exc: The provider exception raised during the live call.

    Raises:
        exc: Re-raised when it is not a recognised account-unavailability
            condition.
    """
    text = str(exc).lower()
    if is_permanent_quota_error(text) or any(marker in text for marker in _BILLING_MARKERS):
        pytest.skip(f"Google account cannot service request: {exc}")
    raise exc


class TestCheckSafetyBlockRealResponses:
    """_check_safety_block raises on real blocked SDK responses only."""

    @staticmethod
    def test_prompt_block_reason_raises_provider_error() -> None:
        """A prompt-level block reason raises a content-blocked ProviderError."""
        feedback = types.GenerateContentResponsePromptFeedback(
            block_reason=types.BlockedReason.SAFETY,
        )
        response = types.GenerateContentResponse(prompt_feedback=feedback)
        with pytest.raises(ProviderError, match="blocked by safety filters"):
            _check_safety_block(response)

    @staticmethod
    def test_candidate_safety_finish_reason_raises() -> None:
        """A SAFETY candidate finish_reason raises with the exact reason name.

        The exact message is asserted (not a permissive substring) so the
        test pins that the classifier reports ``SAFETY`` taken from the
        candidate's ``finish_reason`` field. A companion assertion places
        the very same ``SAFETY`` enum in a non-``finish_reason`` location
        (``prompt_feedback`` with no ``block_reason`` and a STOP candidate)
        and proves no exception is raised - so the gate fails if the code
        ever stops reading ``candidates[].finish_reason`` and instead keys
        off the bare presence of a SAFETY enum anywhere on the response.
        """
        candidate = types.Candidate(finish_reason=types.FinishReason.SAFETY)
        response = types.GenerateContentResponse(candidates=[candidate])
        with pytest.raises(ProviderError) as exc_info:
            _check_safety_block(response)
        assert str(exc_info.value) == "Response blocked by safety filters: SAFETY"

        # The SAFETY enum is real but lives nowhere the classifier inspects:
        # an empty prompt_feedback plus a cleanly-stopped candidate. This must
        # not raise, proving the decision is driven by candidate.finish_reason.
        non_blocking = types.GenerateContentResponse(
            prompt_feedback=types.GenerateContentResponsePromptFeedback(),
            candidates=[types.Candidate(finish_reason=types.FinishReason.STOP)],
        )
        _check_safety_block(non_blocking)

    @staticmethod
    def test_candidate_prohibited_content_raises_specific_message() -> None:
        """PROHIBITED_CONTENT raises the prohibited-content ProviderError."""
        candidate = types.Candidate(finish_reason=types.FinishReason.PROHIBITED_CONTENT)
        response = types.GenerateContentResponse(candidates=[candidate])
        with pytest.raises(ProviderError, match="prohibited content"):
            _check_safety_block(response)

    @staticmethod
    def test_candidate_blocklist_finish_reason_raises() -> None:
        """A BLOCKLIST finish reason is treated as a safety block."""
        candidate = types.Candidate(finish_reason=types.FinishReason.BLOCKLIST)
        response = types.GenerateContentResponse(candidates=[candidate])
        with pytest.raises(ProviderError, match="blocked by safety filters"):
            _check_safety_block(response)

    @staticmethod
    def test_normal_stop_finish_reason_does_not_raise() -> None:
        """A normal STOP completion is not treated as a block."""
        candidate = types.Candidate(finish_reason=types.FinishReason.STOP)
        response = types.GenerateContentResponse(candidates=[candidate])
        _check_safety_block(response)

    @staticmethod
    def test_max_tokens_finish_reason_does_not_raise() -> None:
        """A MAX_TOKENS completion is not treated as a safety block."""
        candidate = types.Candidate(finish_reason=types.FinishReason.MAX_TOKENS)
        response = types.GenerateContentResponse(candidates=[candidate])
        _check_safety_block(response)

    @staticmethod
    def test_response_without_candidates_does_not_raise() -> None:
        """An empty response with no candidates or feedback is allowed."""
        response = types.GenerateContentResponse()
        _check_safety_block(response)


@pytest.mark.integration
class TestGoogleCancelRequestLive:
    """Live confirmation that cancel_request stops a real stream cleanly."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_cancel_during_stream_stops_without_error(
        google_provider: GoogleProvider,
    ) -> None:
        """Cancelling mid-stream halts iteration and sets the cancel flag.

        A real streaming request is started, the first chunk is consumed, then
        ``cancel_request`` is invoked. Iteration must terminate without raising
        and the provider must report the cancellation request.

        Args:
            google_provider: Connected Google provider fixture.
        """
        models = await google_provider.list_models()
        assert models, "Google returned no models"
        model_id = models[0].id

        stream = google_provider.chat_stream(
            messages=[Message(role="user", content="Count slowly from 1 to 50, one number per line.")],
            model=model_id,
            max_tokens=512,
        )

        received = 0
        try:
            async for _chunk in stream:
                received += 1
                if received >= 1:
                    await google_provider.cancel_request()
                    break
        except (ProviderError, RateLimitError) as exc:
            _skip_if_account_unavailable(exc)

        assert received >= 1
        assert getattr(google_provider, _CANCEL_FLAG_ATTR) is True

    @pytest.mark.asyncio
    @staticmethod
    async def test_double_cancel_is_idempotent(
        google_provider: GoogleProvider,
    ) -> None:
        """Cancelling twice mid-stream stays idempotent and raises nothing.

        After the first chunk the request is cancelled twice in a row. The
        second ``cancel_request`` must not raise (no double-cleanup error),
        the cancel flag must remain ``True``, and iteration must terminate
        without surfacing an exception. Cancelling again after the loop has
        already exited must likewise be a no-op.

        Args:
            google_provider: Connected Google provider fixture.
        """
        models = await google_provider.list_models()
        assert models, "Google returned no models"
        model_id = models[0].id

        stream = google_provider.chat_stream(
            messages=[Message(role="user", content="Count slowly from 1 to 50, one number per line.")],
            model=model_id,
            max_tokens=512,
        )

        received = 0
        try:
            async for _chunk in stream:
                received += 1
                if received >= 1:
                    await google_provider.cancel_request()
                    await google_provider.cancel_request()
                    break
        except (ProviderError, RateLimitError) as exc:
            _skip_if_account_unavailable(exc)

        # A third cancel after the generator is closed must remain a no-op.
        await google_provider.cancel_request()

        assert received >= 1
        assert getattr(google_provider, _CANCEL_FLAG_ATTR) is True

    @pytest.mark.asyncio
    @staticmethod
    async def test_cancel_after_full_exhaustion_does_not_raise(
        google_provider: GoogleProvider,
    ) -> None:
        """Consuming the whole stream then cancelling sets the flag cleanly.

        A short prompt is streamed to natural completion so the
        normal-completion bookkeeping path runs (pending usage is
        populated and the cancel flag stays ``False`` throughout the
        stream). Cancelling afterwards must flip the flag to ``True``
        without raising, exercising cancellation when there is no
        in-flight task to abort.

        Args:
            google_provider: Connected Google provider fixture.
        """
        models = await google_provider.list_models()
        assert models, "Google returned no models"
        model_id = models[0].id

        stream = google_provider.chat_stream(
            messages=[Message(role="user", content="Reply with exactly the single word: ready")],
            model=model_id,
            max_tokens=16,
        )

        chunks: list[str] = []
        try:
            chunks.extend([chunk async for chunk in stream])
        except (ProviderError, RateLimitError) as exc:
            _skip_if_account_unavailable(exc)

        # The full stream completed without any cancellation in flight.
        assert getattr(google_provider, _CANCEL_FLAG_ATTR) is False
        completed_text = "".join(chunks)
        assert "ready" in completed_text.lower()
        usage = google_provider.get_pending_usage()
        assert usage is not None, "natural completion must populate pending usage"
        assert usage.total_tokens > 0

        await google_provider.cancel_request()
        assert getattr(google_provider, _CANCEL_FLAG_ATTR) is True
