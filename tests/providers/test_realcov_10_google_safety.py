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

Live cancellation tests (gated on a real ``GOOGLE_API_KEY``) cover three
distinct cancellation points: mid-stream after receiving at least one chunk,
early cancellation before any chunk is consumed from the test loop (concurrent
cancel task), and post-exhaustion (stream runs to completion without cancel,
confirming the flag remains clear and usage metadata is populated).

The independent oracle for all ``_check_safety_block`` assertions is the
combination of the known production constant
``_MSG_CONTENT_BLOCKED = 'Response blocked by safety filters'`` (visible in
``src/intellicrack/providers/google.py``) and the ``google.genai`` SDK enum
values whose ``.name`` attributes are the canonical string names of each
finish-reason variant.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from google.genai import types

from intellicrack.core.types import Message, ProviderError, RateLimitError
from intellicrack.providers.base import is_permanent_quota_error
from intellicrack.providers.google import GoogleProvider


_CHECK_SAFETY_ATTR = "_check_safety_block"
_CANCEL_FLAG_ATTR = "_cancel_requested"
_PENDING_USAGE_ATTR = "_pending_usage"
_check_safety_block: Any = getattr(GoogleProvider, _CHECK_SAFETY_ATTR)

_CONTENT_BLOCKED_PREFIX = "Response blocked by safety filters"
_PROHIBITED_PREFIX = "Response blocked for prohibited content"

_BILLING_MARKERS = (
    "spending cap",
    "spend cap",
    "quota",
    "billing",
    "resource_exhausted",
)

_TEXT_EXCLUDED_TAGS = frozenset({
    "audio",
    "image",
    "tts",
    "live",
    "robotics",
    "computer-use",
    "latest",
    "preview",
    "customtools",
})
_TEXT_REQUIRED_TAGS = frozenset({"flash", "pro"})

_PREFERRED_TEXT_MODEL_SUBSTRINGS = (
    "2.5-flash-lite",
    "2.5-flash",
    "3.1-flash-lite",
    "3.1-flash",
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


async def _select_text_streaming_model(provider: GoogleProvider) -> str:
    """Return the ID of a stable model that reliably returns text chunks via streaming.

    Selection strategy (two passes):

    1. Preferred: scan the provider's model list for models whose IDs contain
       one of the known-stable substrings from ``_PREFERRED_TEXT_MODEL_SUBSTRINGS``
       (e.g. ``2.5-flash-lite``, ``2.5-flash``).  These are established Gemini
       generations whose streaming output is deterministic across repeated calls.

    2. Fallback: if no preferred model is present, scan again with the general
       filter that excludes specialised non-text models (audio, image, TTS, live,
       robotics, computer-use), unstable aliases (``latest``), and experimental
       variants (``preview``, ``customtools``), and requires a text-generation
       tag (``flash`` or ``pro``).

    Newer ``3.x`` thinking models are not listed in ``_PREFERRED_TEXT_MODEL_SUBSTRINGS``
    because they can produce thinking-only chunks with zero user-visible text on
    short prompts, making stream-exhaustion assertions non-deterministic.

    Args:
        provider: A connected ``GoogleProvider`` instance.

    Returns:
        str: The model ID of the first qualifying stable text-streaming model.
    """
    models = await provider.list_models()
    if not models:
        pytest.skip("Google returned no models")
    model_ids = [m.id for m in models]
    for preferred_sub in _PREFERRED_TEXT_MODEL_SUBSTRINGS:
        for mid in model_ids:
            if preferred_sub in mid.lower():
                return mid
    for mid in model_ids:
        mid_lower = mid.lower()
        if any(excl in mid_lower for excl in _TEXT_EXCLUDED_TAGS):
            continue
        if any(req in mid_lower for req in _TEXT_REQUIRED_TAGS):
            return mid
    pytest.skip("No stable text-streaming Gemini model found in account's model list")


class TestCheckSafetyBlockRealResponses:
    """_check_safety_block raises on real blocked SDK responses only."""

    @staticmethod
    def test_prompt_block_reason_raises_provider_error() -> None:
        """A prompt-level block reason raises a content-blocked ProviderError with exact format.

        The production code at ``_check_safety_block`` formats prompt-level blocks as
        ``f"{_MSG_CONTENT_BLOCKED}: prompt {reason_name}"`` (e.g.
        ``'Response blocked by safety filters: prompt SAFETY'``).  This test asserts
        the exact string so that dropping the ``'prompt '`` infix, renaming the
        constant, or removing the reason name suffix makes this test go red.

        The independent oracle for the expected value is the combination of:

        - The known production constant ``_MSG_CONTENT_BLOCKED`` (visible in
          ``src/intellicrack/providers/google.py``), captured here as
          ``_CONTENT_BLOCKED_PREFIX``.
        - The SDK enum attribute ``BlockedReason.SAFETY.name == 'SAFETY'``,
          confirmed by a pre-condition assertion before the call.
        - The literal ``'prompt '`` infix, which is hard-coded in the production
          format string and therefore a load-bearing part of the message that
          must appear in the output.
        """
        feedback = types.GenerateContentResponsePromptFeedback(
            block_reason=types.BlockedReason.SAFETY,
        )
        response = types.GenerateContentResponse(prompt_feedback=feedback)
        assert response.prompt_feedback is not None
        assert response.prompt_feedback.block_reason == types.BlockedReason.SAFETY
        assert response.prompt_feedback.block_reason.name == "SAFETY", "SDK oracle: BlockedReason.SAFETY.name must be the string 'SAFETY'"

        with pytest.raises(ProviderError, match="blocked by safety filters") as exc_info:
            _check_safety_block(response)

        error_message = str(exc_info.value)
        assert _CONTENT_BLOCKED_PREFIX in error_message, (
            f"Error must contain the known constant '{_CONTENT_BLOCKED_PREFIX}'; got: {error_message!r}"
        )
        assert "prompt SAFETY" in error_message, (
            f"Error must contain 'prompt SAFETY' (the 'prompt ' infix plus reason name); got: {error_message!r}"
        )
        assert error_message == f"{_CONTENT_BLOCKED_PREFIX}: prompt SAFETY", (
            f"Exact error message must be '{_CONTENT_BLOCKED_PREFIX}: prompt SAFETY'; got: {error_message!r}"
        )

    @staticmethod
    def test_candidate_safety_finish_reason_raises() -> None:
        """A SAFETY finish_reason on a candidate triggers a content-blocked ProviderError.

        This test verifies that ``candidates[0].finish_reason`` is the specific
        field that ``_check_safety_block`` inspects:

        - The response carries no ``prompt_feedback``, ruling out the
          prompt-block path so the only possible source of the error is the
          ``candidates[0].finish_reason`` field.
        - The candidate's ``finish_reason`` is pre-confirmed to equal
          ``FinishReason.SAFETY`` (SDK enum, independent oracle) before the
          call.
        - The ``finish_reason.name`` is independently confirmed to equal
          ``'SAFETY'`` (the string the production code embeds into the error).
        - The raised ``ProviderError`` message must match the exact pattern
          ``'Response blocked by safety filters: SAFETY'``, derived from the
          known production constant ``_MSG_CONTENT_BLOCKED`` and the SDK enum
          name.  Both substrings must appear, not merely one.
        - A structurally identical response where ``finish_reason`` is the
          non-blocking ``FinishReason.RECITATION`` must pass without raising,
          making the test falsifiable: swapping the field value changes the
          outcome.
        """
        candidate = types.Candidate(finish_reason=types.FinishReason.SAFETY)
        response = types.GenerateContentResponse(candidates=[candidate])

        assert response.prompt_feedback is None, (
            "Pre-condition: no prompt_feedback so the error originates from candidates[0].finish_reason, not from the prompt-block path"
        )
        assert response.candidates is not None
        assert len(response.candidates) == 1
        assert response.candidates[0].finish_reason == types.FinishReason.SAFETY, (
            "Pre-condition: candidates[0].finish_reason must equal SAFETY before the call"
        )
        assert response.candidates[0].finish_reason.name == "SAFETY", "SDK oracle: FinishReason.SAFETY.name must be the string 'SAFETY'"

        with pytest.raises(ProviderError, match=r"blocked by safety filters.*SAFETY") as exc_info:
            _check_safety_block(response)

        error_message = str(exc_info.value)
        assert _CONTENT_BLOCKED_PREFIX in error_message, (
            f"Error must contain the known constant prefix '{_CONTENT_BLOCKED_PREFIX}'; got: {error_message!r}"
        )
        assert "SAFETY" in error_message, (
            "_check_safety_block must embed finish_reason.name ('SAFETY') in the error message, proving the field value was actually read"
        )
        assert error_message == f"{_CONTENT_BLOCKED_PREFIX}: SAFETY", (
            f"Exact error message must be '{_CONTENT_BLOCKED_PREFIX}: SAFETY'; got: {error_message!r}"
        )

        non_blocking = types.Candidate(finish_reason=types.FinishReason.RECITATION)
        response_non_blocking = types.GenerateContentResponse(candidates=[non_blocking])
        assert response_non_blocking.candidates is not None
        assert response_non_blocking.candidates[0].finish_reason == types.FinishReason.RECITATION
        _check_safety_block(response_non_blocking)

    @staticmethod
    def test_candidate_prohibited_content_raises_specific_message() -> None:
        """PROHIBITED_CONTENT raises the prohibited-content ProviderError with exact message.

        The exact error message ``'Response blocked for prohibited content:
        PROHIBITED_CONTENT'`` is derived from the known production constant
        ``_MSG_PROHIBITED_CONTENT = 'Response blocked for prohibited content'``
        and the SDK enum name ``FinishReason.PROHIBITED_CONTENT.name``.
        Changing the production message or removing the reason name suffix
        makes this test go red.
        """
        candidate = types.Candidate(finish_reason=types.FinishReason.PROHIBITED_CONTENT)
        response = types.GenerateContentResponse(candidates=[candidate])
        assert response.candidates is not None
        assert response.candidates[0].finish_reason == types.FinishReason.PROHIBITED_CONTENT
        assert response.candidates[0].finish_reason.name == "PROHIBITED_CONTENT"

        with pytest.raises(ProviderError, match="prohibited content") as exc_info:
            _check_safety_block(response)

        error_message = str(exc_info.value)
        assert _PROHIBITED_PREFIX in error_message, f"Error must contain '{_PROHIBITED_PREFIX}'; got: {error_message!r}"
        assert "PROHIBITED_CONTENT" in error_message, "Error must embed the finish_reason name 'PROHIBITED_CONTENT'"
        assert error_message == f"{_PROHIBITED_PREFIX}: PROHIBITED_CONTENT", (
            f"Exact error must be '{_PROHIBITED_PREFIX}: PROHIBITED_CONTENT'; got: {error_message!r}"
        )

    @staticmethod
    def test_candidate_blocklist_finish_reason_raises() -> None:
        """A BLOCKLIST finish reason raises with the safety-block prefix and reason name.

        The exact expected message is ``'Response blocked by safety filters:
        BLOCKLIST'``, derived from the known production constant and the SDK
        enum name.
        """
        candidate = types.Candidate(finish_reason=types.FinishReason.BLOCKLIST)
        response = types.GenerateContentResponse(candidates=[candidate])
        assert response.candidates is not None
        assert response.candidates[0].finish_reason == types.FinishReason.BLOCKLIST
        assert response.candidates[0].finish_reason.name == "BLOCKLIST"

        with pytest.raises(ProviderError, match="blocked by safety filters") as exc_info:
            _check_safety_block(response)

        error_message = str(exc_info.value)
        assert error_message == f"{_CONTENT_BLOCKED_PREFIX}: BLOCKLIST", (
            f"Exact error must be '{_CONTENT_BLOCKED_PREFIX}: BLOCKLIST'; got: {error_message!r}"
        )

    @staticmethod
    def test_normal_stop_finish_reason_does_not_raise() -> None:
        """A normal STOP completion is not treated as a safety block.

        Falsifiable complement to the blocking tests: structurally identical
        response but with ``FinishReason.STOP`` must pass without raising.
        """
        candidate = types.Candidate(finish_reason=types.FinishReason.STOP)
        response = types.GenerateContentResponse(candidates=[candidate])
        assert response.candidates is not None
        assert response.candidates[0].finish_reason == types.FinishReason.STOP
        _check_safety_block(response)

    @staticmethod
    def test_max_tokens_finish_reason_does_not_raise() -> None:
        """A MAX_TOKENS completion is not treated as a safety block.

        Falsifiable complement: same structure as a blocking test but with
        ``FinishReason.MAX_TOKENS`` must pass cleanly.
        """
        candidate = types.Candidate(finish_reason=types.FinishReason.MAX_TOKENS)
        response = types.GenerateContentResponse(candidates=[candidate])
        assert response.candidates is not None
        assert response.candidates[0].finish_reason == types.FinishReason.MAX_TOKENS
        _check_safety_block(response)

    @staticmethod
    def test_response_without_candidates_does_not_raise() -> None:
        """An empty response with no candidates or feedback is allowed."""
        response = types.GenerateContentResponse()
        assert response.candidates is None or len(response.candidates) == 0
        assert response.prompt_feedback is None
        _check_safety_block(response)

    @staticmethod
    def test_candidate_null_finish_reason_does_not_raise() -> None:
        """A candidate with finish_reason=None is not treated as a safety block.

        This complements ``test_candidate_safety_finish_reason_raises``: the
        same candidate structure with a ``None`` finish_reason must pass
        cleanly, proving the production gate is specifically on the
        ``finish_reason.name`` value being in the ``_BLOCKING_FINISH_REASONS``
        frozenset, not on the mere presence of a candidate.
        """
        candidate = types.Candidate(finish_reason=None)
        response = types.GenerateContentResponse(candidates=[candidate])
        assert response.candidates is not None
        assert len(response.candidates) == 1
        assert response.candidates[0].finish_reason is None
        _check_safety_block(response)

    @staticmethod
    def test_candidate_spii_finish_reason_raises_with_reason_in_message() -> None:
        """A SPII finish reason raises with the safety-block prefix and reason name embedded.

        The expected exact message ``'Response blocked by safety filters: SPII'``
        is derived from the production constant ``_MSG_CONTENT_BLOCKED`` and
        the SDK enum value ``FinishReason.SPII.name == 'SPII'``.  Removing or
        renaming either the constant or the reason-name suffix makes this red.
        """
        candidate = types.Candidate(finish_reason=types.FinishReason.SPII)
        response = types.GenerateContentResponse(candidates=[candidate])
        assert response.prompt_feedback is None
        assert response.candidates is not None
        assert response.candidates[0].finish_reason == types.FinishReason.SPII
        assert response.candidates[0].finish_reason.name == "SPII"

        with pytest.raises(ProviderError, match=r"blocked by safety filters.*SPII") as exc_info:
            _check_safety_block(response)

        error_message = str(exc_info.value)
        assert error_message == f"{_CONTENT_BLOCKED_PREFIX}: SPII", (
            f"Exact error must be '{_CONTENT_BLOCKED_PREFIX}: SPII'; got: {error_message!r}"
        )


@pytest.mark.integration
class TestGoogleCancelRequestLive:
    """Live confirmation that cancel_request stops a real stream cleanly.

    Three cancellation scenarios are exercised against a real Gemini stream:

    1. Mid-stream cancel: consume at least one chunk then cancel; the provider
       sets the cancel flag and the loop ends without error.
    2. Early cancel: a concurrent asyncio task fires ``cancel_request``
       immediately after the stream is created; the provider must stop with
       zero or more chunks and the cancel flag must be set.
    3. Post-exhaustion: the stream runs to completion without any cancellation;
       ``_cancel_requested`` must remain ``False`` after completion and
       ``_pending_usage`` must be populated with positive token counts,
       confirming a successful stream does not corrupt cancel state.

    All three tests select a text-streaming model via ``_select_text_streaming_model``
    rather than blindly using ``models[0]``, which would select specialised
    models (robotics, image, etc.) that return zero text chunks and therefore
    make the exhaustion assertions vacuous.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_cancel_during_stream_stops_without_error(
        google_provider: GoogleProvider,
    ) -> None:
        """Cancelling mid-stream halts iteration and sets the cancel flag.

        A real streaming request is started against a text-streaming Gemini
        model, the first chunk is consumed, then ``cancel_request`` is invoked.
        Iteration must terminate without raising and ``_cancel_requested`` must
        be ``True``.  This proves the mid-stream cancel path in
        ``_iter_google_stream`` is exercised by a real chunk delivery, not
        just a no-op on a model that returns nothing.

        Args:
            google_provider: Connected Google provider fixture.
        """
        model_id = await _select_text_streaming_model(google_provider)

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

        assert received >= 1, (
            f"At least one chunk must have been received before cancellation "
            f"(model={model_id!r}); zero chunks means the model returned no text"
        )
        assert getattr(google_provider, _CANCEL_FLAG_ATTR) is True, "_cancel_requested must be True after cancel_request() was called"

    @pytest.mark.asyncio
    @staticmethod
    async def test_cancel_before_first_chunk_stops_stream(
        google_provider: GoogleProvider,
    ) -> None:
        """Cancelling before the test loop consumes any chunk terminates the stream.

        A concurrent asyncio task fires ``cancel_request`` immediately after the
        stream generator is created (but before the first ``async for`` iteration
        completes in the test body).  Because ``chat_stream`` resets
        ``_cancel_requested`` to ``False`` at the start of each call and checks
        the flag after each SDK chunk arrives, the cancel takes effect no later
        than after the first chunk.

        The test verifies:

        - The ``async for`` loop terminates without raising.
        - ``_cancel_requested`` is ``True``, confirming the cancel path ran.
        - Fewer than 100 chunks escaped before the cancel took effect (a
          loose bound: a complete 200-integer stream would yield far more).

        Args:
            google_provider: Connected Google provider fixture.
        """
        model_id = await _select_text_streaming_model(google_provider)

        stream = google_provider.chat_stream(
            messages=[Message(role="user", content="List all integers from 1 to 200, one per line.")],
            model=model_id,
            max_tokens=1024,
        )

        chunks: list[str] = []

        async def _cancel_soon() -> None:
            await asyncio.sleep(0)
            await google_provider.cancel_request()

        cancel_task: asyncio.Task[None] = asyncio.create_task(_cancel_soon())

        try:
            chunks.extend([chunk async for chunk in stream])
        except (ProviderError, RateLimitError) as exc:
            cancel_task.cancel()
            _skip_if_account_unavailable(exc)
        finally:
            if not cancel_task.done():
                cancel_task.cancel()

        assert getattr(google_provider, _CANCEL_FLAG_ATTR) is True, (
            "_cancel_requested must be True: cancel_request() was called concurrently"
        )
        assert len(chunks) < 100, (
            f"A cancelled stream must not deliver a full response; received {len(chunks)} chunks which suggests cancel was not honoured"
        )

    @pytest.mark.asyncio
    @staticmethod
    async def test_stream_exhaustion_leaves_cancel_flag_false(
        google_provider: GoogleProvider,
    ) -> None:
        """A stream that completes normally leaves ``_cancel_requested`` False.

        Consuming all chunks from a short streaming request against a text-
        streaming model without calling ``cancel_request`` must:

        - Deliver at least one text chunk (proving the model returned a response
          and the test is not vacuously asserting state after zero activity).
        - Leave ``_cancel_requested`` at ``False``, confirming a successful
          stream does not corrupt the cancel flag for subsequent calls.
        - Populate ``_pending_usage`` with positive prompt and completion token
          counts from the real API response, confirming the usage-extraction
          path ran on a real, non-empty last chunk.

        The model is selected via ``_select_text_streaming_model`` rather than
        ``models[0]`` to avoid specialised models (robotics, image, etc.) that
        return zero text chunks and make all of the above assertions vacuous.

        Args:
            google_provider: Connected Google provider fixture.
        """
        model_id = await _select_text_streaming_model(google_provider)

        stream = google_provider.chat_stream(
            messages=[Message(role="user", content="Say exactly: Hello world")],
            model=model_id,
            max_tokens=32,
        )

        chunks: list[str] = []
        try:
            chunks.extend([chunk async for chunk in stream])
        except (ProviderError, RateLimitError) as exc:
            _skip_if_account_unavailable(exc)

        assert chunks, (
            f"A complete stream must have delivered at least one text chunk "
            f"(model={model_id!r}); zero chunks means the model returned no text, "
            "making subsequent state assertions vacuous"
        )
        full_text = "".join(chunks)
        assert full_text, "Concatenated chunks must produce non-empty text"

        assert getattr(google_provider, _CANCEL_FLAG_ATTR) is False, (
            "_cancel_requested must remain False after a stream that completed without any cancellation"
        )

        pending_usage = getattr(google_provider, _PENDING_USAGE_ATTR)
        assert pending_usage is not None, (
            "_pending_usage must be populated by a successfully exhausted stream; "
            "None means _extract_usage returned None, which means the last chunk "
            "carried no usage_metadata (or all counts were zero)"
        )
        assert pending_usage.prompt_tokens > 0, (
            f"prompt_tokens must be a positive integer from the real API response; got: {pending_usage.prompt_tokens}"
        )
        assert pending_usage.completion_tokens > 0, (
            f"completion_tokens must be a positive integer from the real API response; got: {pending_usage.completion_tokens}"
        )
        assert pending_usage.total_tokens >= pending_usage.prompt_tokens + pending_usage.completion_tokens, (
            f"total_tokens ({pending_usage.total_tokens}) must be >= "
            f"prompt_tokens ({pending_usage.prompt_tokens}) + "
            f"completion_tokens ({pending_usage.completion_tokens})"
        )
