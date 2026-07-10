# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for the provider HTTP-status -> typed-exception helper.

Validates :meth:`intellicrack.providers.base.LLMProviderBase._raise_typed_for_status`
and :class:`intellicrack.providers.base.HttpErrorMessages` against the
exact behaviour the OpenRouter and HuggingFace providers depend on.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from intellicrack.core.types import (
    AuthenticationError,
    ProviderError,
    RateLimitError,
)
from intellicrack.providers.base import (
    HttpErrorMessages,
    LLMProviderBase,
    is_permanent_quota_error,
)


_RAISE_TYPED_FOR_STATUS_ATTR = "_raise_typed_for_status"

_raise_typed_for_status: Any = getattr(LLMProviderBase, _RAISE_TYPED_FOR_STATUS_ATTR)


_HF_MESSAGES = HttpErrorMessages(
    auth_invalid="Invalid HuggingFace API token: %s",
    rate_limited="HuggingFace rate limit exceeded: %s",
    service_unavailable="HuggingFace model is loading and not yet ready: %s",
)

_OR_REST_MESSAGES = HttpErrorMessages(
    auth_invalid="Invalid OpenRouter API key: %s",
    rate_limited="OpenRouter rate limit exceeded: %s",
    service_unavailable="OpenRouter API error: %s",
)


def _extract_503(_exc: Exception) -> str:
    """Extract a deterministic 503 body for tests.

    Args:
        _exc: The exception being inspected (unused in tests).

    Returns:
        str: A fixed string standing in for the decoded body.
    """
    return "model is loading"


@pytest.mark.parametrize(
    "status_code",
    [500, 502, 504, 400, 404],
)
def test_returns_none_for_unmatched_status(status_code: int) -> None:
    """Status codes outside 401/403/429/503 yield ``None``, never raise, and have no side effects.

    The helper is documented to return ``None`` for any code not in its known set so
    the caller can apply a provider-specific fall-through raise. This test parametrizes
    all boundary-adjacent unmatched codes to prevent silent regressions where a new
    branch is added that handles previously-unhandled codes. The side-effect check
    confirms the 503 extract callback is never invoked for non-503 codes.

    Args:
        status_code: An HTTP status code that is not 401, 403, 429, or 503.
    """
    side_effect_log: list[int] = []

    def _probe_extract(_exc: Exception) -> str:
        """Record that the extract callback was invoked (it must not be).

        Args:
            _exc: The originating exception (unused).

        Returns:
            str: A fixed string for the message template.
        """
        side_effect_log.append(status_code)
        return "should not be reached"

    cause = RuntimeError("server error")
    result = _raise_typed_for_status(
        status_code,
        cause,
        messages=_HF_MESSAGES,
        extract_503_message=_probe_extract,
    )
    assert result is None
    assert not side_effect_log, f"extract_503_message was unexpectedly invoked for status {status_code}"


def test_returns_none_for_zero_sentinel_status() -> None:
    """A ``0`` sentinel (no status) yields ``None`` for caller fall-through."""
    cause = RuntimeError("no status")
    result = _raise_typed_for_status(
        0,
        cause,
        messages=_HF_MESSAGES,
        extract_503_message=_extract_503,
    )
    assert result is None


@pytest.mark.parametrize("status_code", [401, 403])
def test_auth_status_raises_authentication_error(status_code: int) -> None:
    """HTTP 401 and 403 raise :class:`AuthenticationError` chained from ``exc``.

    Args:
        status_code: The HTTP status code under test.
    """
    cause = RuntimeError("bad creds")
    with pytest.raises(AuthenticationError) as info:
        _raise_typed_for_status(
            status_code,
            cause,
            messages=_HF_MESSAGES,
        )
    assert "Invalid HuggingFace API token" in str(info.value)
    assert "bad creds" in str(info.value)
    assert info.value.__cause__ is cause


def test_rate_limited_raises_rate_limit_error() -> None:
    """HTTP 429 raises :class:`RateLimitError` chained from ``exc``."""
    cause = RuntimeError("too many requests")
    with pytest.raises(RateLimitError) as info:
        _raise_typed_for_status(
            429,
            cause,
            messages=_OR_REST_MESSAGES,
        )
    assert str(info.value) == "OpenRouter rate limit exceeded: too many requests"
    assert info.value.__cause__ is cause


def test_service_unavailable_raises_provider_error_with_extract() -> None:
    """HTTP 503 with ``extract_503_message`` raises :class:`ProviderError`."""
    cause = RuntimeError("model loading")
    with pytest.raises(ProviderError) as info:
        _raise_typed_for_status(
            503,
            cause,
            messages=_HF_MESSAGES,
            extract_503_message=_extract_503,
        )
    assert str(info.value) == "HuggingFace model is loading and not yet ready: model is loading"
    assert info.value.__cause__ is cause


def test_service_unavailable_returns_none_without_extract_callback() -> None:
    """HTTP 503 without ``extract_503_message`` falls through to caller."""
    cause = RuntimeError("loading")
    result = _raise_typed_for_status(
        503,
        cause,
        messages=_HF_MESSAGES,
    )
    assert result is None


def test_openrouter_rest_auth_format_matches_inline_block() -> None:
    """OpenRouter REST auth raises with ``_ERR_INVALID_KEY % str(exc)`` text."""
    cause = RuntimeError("401 Unauthorized")
    with pytest.raises(AuthenticationError) as info:
        _raise_typed_for_status(
            401,
            cause,
            messages=_OR_REST_MESSAGES,
        )
    assert str(info.value) == "Invalid OpenRouter API key: 401 Unauthorized"
    assert info.value.__cause__ is cause


def test_extract_503_callback_receives_originating_exception() -> None:
    """The ``extract_503_message`` callable receives the originating exception."""
    seen: list[Exception] = []

    def _capture(exc: Exception) -> str:
        """Record the inbound exception and return a fixed message.

        Args:
            exc: The originating exception passed by the helper.

        Returns:
            str: A fixed string standing in for the decoded body.
        """
        seen.append(exc)
        return "captured"

    cause = RuntimeError("captured-cause")
    with pytest.raises(ProviderError):
        _raise_typed_for_status(
            503,
            cause,
            messages=_HF_MESSAGES,
            extract_503_message=_capture,
        )
    assert seen == [cause]


def test_http_error_messages_is_frozen_dataclass() -> None:
    """``HttpErrorMessages`` instances cannot be mutated post-construction."""
    msgs = HttpErrorMessages(
        auth_invalid="a",
        rate_limited="b",
        service_unavailable="c",
    )
    assert dataclasses.is_dataclass(msgs)
    fields = dataclasses.fields(msgs)
    field_names = {f.name for f in fields}
    assert field_names == {"auth_invalid", "rate_limited", "service_unavailable"}
    attribute_to_mutate = "auth_invalid"
    mutable: object = msgs
    with pytest.raises((AttributeError, TypeError)):
        setattr(mutable, attribute_to_mutate, "x")


def test_http_error_messages_uses_slots() -> None:
    """``HttpErrorMessages`` declares ``__slots__`` to forbid extra attributes."""
    msgs = HttpErrorMessages(
        auth_invalid="a",
        rate_limited="b",
        service_unavailable="c",
    )
    cls_slots = type(msgs).__slots__
    assert set(cls_slots) == {"auth_invalid", "rate_limited", "service_unavailable"}
    attribute_to_inject = "extra_attribute"
    mutable: object = msgs
    with pytest.raises((AttributeError, TypeError)):
        setattr(mutable, attribute_to_inject, "y")


@pytest.mark.parametrize(
    "message",
    [
        "429 RESOURCE_EXHAUSTED. Your project has exceeded its monthly spending cap.",
        "You exceeded your current quota, please check your plan and billing details.",
        "Error code: 429 - insufficient_quota",
        "Request blocked: billing hard limit has been reached",
    ],
)
def test_permanent_quota_messages_detected(message: str) -> None:
    """Billing and spend-cap exhaustion messages classify as permanent.

    Args:
        message: A provider 429 message describing a non-retryable
            billing or quota-cap condition.
    """
    assert is_permanent_quota_error(message) is True


@pytest.mark.parametrize(
    "message",
    [
        "429 Too Many Requests: rate limit exceeded, retry after 20s",
        "Resource has been exhausted (e.g. check quota) per-minute limit",
        "Quota exceeded for requests per minute. Try again later.",
        "Internal server error",
    ],
)
def test_transient_rate_limit_messages_not_permanent(message: str) -> None:
    """Transient per-interval throttling must remain retryable (not permanent).

    Args:
        message: A provider 429 message describing a transient, retryable
            rate limit that must not be misclassified as a hard cap.
    """
    assert is_permanent_quota_error(message) is False
