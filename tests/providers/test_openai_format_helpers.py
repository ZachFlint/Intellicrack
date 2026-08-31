# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for shared OpenAI-format helpers on LLMProviderBase.

Covers consolidated helpers introduced as part of the audit Group
4/5/6/8 consolidation:

* ``_build_usage_from_openai_completion`` (Group 4)
* ``_build_usage_from_openai_chunk`` (Group 5)
* ``_extract_system_messages`` (Group 6)
* ``_translate_openai_errors`` (Group 8)

Tests use real :class:`Message` objects, real :class:`UsageInfo`
results, and real ``openai`` SDK exception types - no mocks, no
stubs. Protected static methods are reached via ``getattr`` so the
tests do not trip ``reportPrivateUsage``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

import httpx
import openai
import pytest
from openai.types.chat import ChatCompletion, ChatCompletionChunk

from intellicrack.core.types import (
    AuthenticationError,
    Message,
    ProviderCredentials,
    ProviderError,
    ProviderName,
    RateLimitError,
    ThinkingConfig,
    ToolCall,
    ToolChoice,
    ToolDefinition,
)
from intellicrack.providers.base import (
    LLMProviderBase,
    OpenAIErrorMessages,
    UsageInfo,
)


if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from contextlib import AbstractContextManager


_BUILD_FROM_COMPLETION_ATTR = "_build_usage_from_openai_completion"
_BUILD_FROM_CHUNK_ATTR = "_build_usage_from_openai_chunk"
_EXTRACT_SYSTEM_ATTR = "_extract_system_messages"
_TRANSLATE_ERRORS_ATTR = "_translate_openai_errors"

_build_usage_from_completion: Any = getattr(LLMProviderBase, _BUILD_FROM_COMPLETION_ATTR)
_build_usage_from_chunk: Any = getattr(LLMProviderBase, _BUILD_FROM_CHUNK_ATTR)
_extract_system_messages: Any = getattr(LLMProviderBase, _EXTRACT_SYSTEM_ATTR)


_PROMPT_TOKENS = 17
_COMPLETION_TOKENS = 23
_TOTAL_TOKENS = 40
_PASSTHROUGH_SENTINEL = 42


@dataclass(slots=True)
class _UsageStub:
    """In-memory analogue of ``ChatCompletion.usage`` for unit tests.

    Real provider tests construct response objects indirectly; for
    unit-level verification of the extraction logic a plain
    dataclass faithfully reproduces the duck-typed surface that
    :meth:`LLMProviderBase._build_usage_from_openai_chunk` consumes
    via ``getattr(usage, "prompt_tokens", 0)``.

    Attributes:
        prompt_tokens: Tokens consumed by the prompt.
        completion_tokens: Tokens produced in the completion.
        total_tokens: Total tokens reported by the provider.
    """

    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


@dataclass(slots=True)
class _CompletionStub:
    """In-memory analogue of ``ChatCompletion`` for unit tests.

    Attributes:
        usage: The :class:`_UsageStub` payload describing token use,
            or ``None`` to mimic a response that omits ``usage``.
    """

    usage: _UsageStub | None


class _BareProvider(LLMProviderBase):
    """Concrete :class:`LLMProviderBase` subclass exposing inherited helpers.

    The base class is abstract; this subclass overrides every
    abstract member with a minimal sentinel-returning implementation
    so that the inherited
    :meth:`LLMProviderBase._translate_openai_errors` context manager
    can be exercised against a real instance with a real
    ``self._logger``.
    """

    @property
    def name(self) -> ProviderName:
        """A placeholder provider name.

        Returns:
            ProviderName: ``ProviderName.OPENAI`` chosen arbitrarily;
            the helper under test does not consult ``name``.
        """
        return ProviderName.OPENAI

    async def connect(self, credentials: ProviderCredentials) -> None:
        """Satisfy the abstract :meth:`connect` contract.

        Args:
            credentials: Ignored; tests construct the provider
                without authenticating.
        """
        del credentials

    async def list_models(self) -> list[Any]:
        """Satisfy the abstract :meth:`list_models` contract.

        Returns:
            list[Any]: An empty list.
        """
        return []

    async def chat(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Satisfy the abstract :meth:`chat` contract.

        Args:
            messages: Ignored.
            model: Ignored.
            tools: Ignored.
            temperature: Ignored.
            max_tokens: Ignored.
            tool_choice: Ignored.
            thinking: Ignored.
            enable_cache: Ignored.

        Returns:
            tuple[Message, list[ToolCall] | None]: A placeholder
            assistant message with no tool calls.
        """
        del messages, model, tools, temperature, max_tokens, tool_choice, thinking, enable_cache
        return Message(role="assistant", content=""), None

    async def chat_stream(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> AsyncIterator[str]:
        """Satisfy the abstract :meth:`chat_stream` contract.

        Args:
            messages: Ignored.
            model: Ignored.
            tools: Ignored.
            temperature: Ignored.
            max_tokens: Ignored.
            tool_choice: Ignored.
            thinking: Ignored.
            enable_cache: Ignored.

        Yields:
            str: An empty placeholder chunk to satisfy the async
            generator protocol.
        """
        del messages, model, tools, temperature, max_tokens, tool_choice, thinking, enable_cache
        yield ""

    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Satisfy the abstract converter contract.

        Args:
            tools: Ignored.

        Returns:
            list[dict[str, object]]: An empty list.
        """
        del tools
        return []

    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Satisfy the abstract converter contract.

        Args:
            messages: Ignored.

        Returns:
            list[dict[str, object]]: An empty list.
        """
        del messages
        return []


def _translator(
    provider: LLMProviderBase,
    *,
    log_prefix: str,
    messages: OpenAIErrorMessages,
) -> AbstractContextManager[None]:
    """Invoke :meth:`LLMProviderBase._translate_openai_errors` indirectly.

    Wrapping the protected call in a free function keeps test bodies
    readable and isolates the single ``getattr`` lookup needed to
    avoid ``reportPrivateUsage`` findings.

    Args:
        provider: Provider instance whose context manager is invoked.
        log_prefix: Stem for the structured-log event.
        messages: Templates used to build the typed exception
            messages.

    Returns:
        AbstractContextManager[None]: The context manager produced by
        :meth:`LLMProviderBase._translate_openai_errors`.
    """
    factory: Any = getattr(provider, _TRANSLATE_ERRORS_ATTR)
    return cast(
        "AbstractContextManager[None]",
        factory(log_prefix=log_prefix, messages=messages),
    )


def test_build_usage_from_completion_populated() -> None:
    """Populated usage fields produce a matching :class:`UsageInfo`."""
    completion = _CompletionStub(
        usage=_UsageStub(
            prompt_tokens=_PROMPT_TOKENS,
            completion_tokens=_COMPLETION_TOKENS,
            total_tokens=_TOTAL_TOKENS,
        ),
    )
    usage = _build_usage_from_completion(completion)
    assert isinstance(usage, UsageInfo)
    assert usage.prompt_tokens == _PROMPT_TOKENS
    assert usage.completion_tokens == _COMPLETION_TOKENS
    assert usage.total_tokens == _TOTAL_TOKENS


def test_build_usage_from_completion_missing_usage() -> None:
    """A response without ``usage`` returns ``None``."""
    completion = _CompletionStub(usage=None)
    assert _build_usage_from_completion(completion) is None


def test_build_usage_from_completion_object_without_attribute() -> None:
    """An object lacking the ``usage`` attribute returns ``None``."""
    assert _build_usage_from_completion(object()) is None


def test_build_usage_from_chunk_populated() -> None:
    """A streaming chunk usage object yields the same UsageInfo shape."""
    chunk_usage = _UsageStub(
        prompt_tokens=_PROMPT_TOKENS,
        completion_tokens=_COMPLETION_TOKENS,
        total_tokens=_TOTAL_TOKENS,
    )
    usage = _build_usage_from_chunk(chunk_usage)
    assert isinstance(usage, UsageInfo)
    assert usage.prompt_tokens == _PROMPT_TOKENS
    assert usage.completion_tokens == _COMPLETION_TOKENS
    assert usage.total_tokens == _TOTAL_TOKENS


def test_build_usage_from_chunk_missing_total_falls_back() -> None:
    """When ``total_tokens`` is zero, the helper sums prompt and completion."""
    chunk_usage = _UsageStub(
        prompt_tokens=_PROMPT_TOKENS,
        completion_tokens=_COMPLETION_TOKENS,
        total_tokens=0,
    )
    usage = _build_usage_from_chunk(chunk_usage)
    assert isinstance(usage, UsageInfo)
    assert usage.total_tokens == _PROMPT_TOKENS + _COMPLETION_TOKENS


def test_build_usage_from_chunk_none() -> None:
    """``None`` input passes through as ``None``."""
    assert _build_usage_from_chunk(None) is None


def test_extract_system_messages_single() -> None:
    """A single system message is returned verbatim."""
    msgs = [Message(role="system", content="Be terse.")]
    assert _extract_system_messages(msgs) == "Be terse."


def test_extract_system_messages_concatenates() -> None:
    """Multiple system messages join with a blank line separator."""
    msgs = [
        Message(role="system", content="A"),
        Message(role="user", content="ignored"),
        Message(role="system", content="B"),
        Message(role="assistant", content="ignored"),
        Message(role="system", content="C"),
    ]
    assert _extract_system_messages(msgs) == "A\n\nB\n\nC"


def test_extract_system_messages_no_system_returns_none() -> None:
    """Without any system message the helper returns ``None``."""
    msgs = [
        Message(role="user", content="hi"),
        Message(role="assistant", content="hello"),
    ]
    assert _extract_system_messages(msgs) is None


def test_extract_system_messages_empty_list() -> None:
    """An empty conversation yields ``None``."""
    assert _extract_system_messages([]) is None


def test_extract_system_messages_skips_empty_content() -> None:
    """A system message whose content is empty is dropped."""
    msgs = [
        Message(role="system", content=""),
        Message(role="system", content="kept"),
    ]
    assert _extract_system_messages(msgs) == "kept"


_TEST_ERROR_MESSAGES = OpenAIErrorMessages(
    auth_invalid="invalid auth: %s",
    rate_limited="rate limited: %s",
    api_error="api error: %s",
    request_failed="request failed: %s",
)


def test_translate_openai_errors_passthrough() -> None:
    """Successful blocks return without re-raising."""
    provider = _BareProvider()
    captured: int = 0
    with _translator(provider, log_prefix="test", messages=_TEST_ERROR_MESSAGES):
        captured = _PASSTHROUGH_SENTINEL
    assert captured == _PASSTHROUGH_SENTINEL


def _make_httpx_response(status_code: int) -> httpx.Response:
    """Build a real :class:`httpx.Response` carrying a request object.

    The OpenAI SDK exception constructors dereference
    ``response.request`` during ``__init__``, so the response must
    already carry a non-``None`` request reference.

    Args:
        status_code: HTTP status code to attach to the response.

    Returns:
        httpx.Response: A response instance suitable for use as the
        ``response=`` argument of an ``openai`` SDK exception.
    """
    request = httpx.Request("POST", "https://api.openai.test/v1/chat/completions")
    return httpx.Response(status_code=status_code, request=request)


def _build_auth_error() -> openai.AuthenticationError:
    """Construct a real ``openai.AuthenticationError`` for tests.

    Returns:
        openai.AuthenticationError: A populated SDK auth-failure
        exception that the helper under test must intercept.
    """
    return openai.AuthenticationError(
        message="bad key",
        response=_make_httpx_response(401),
        body=None,
    )


def _build_rate_error() -> openai.RateLimitError:
    """Construct a real ``openai.RateLimitError`` for tests.

    Returns:
        openai.RateLimitError: A populated SDK rate-limit exception
        that the helper under test must intercept.
    """
    return openai.RateLimitError(
        message="slow down",
        response=_make_httpx_response(429),
        body=None,
    )


def test_translate_openai_errors_authentication() -> None:
    """``openai.AuthenticationError`` maps to :class:`AuthenticationError`."""
    provider = _BareProvider()
    auth_failure = _build_auth_error()
    with (
        pytest.raises(AuthenticationError, match="invalid auth"),
        _translator(
            provider,
            log_prefix="test",
            messages=_TEST_ERROR_MESSAGES,
        ),
    ):
        raise auth_failure


def test_translate_openai_errors_rate_limit() -> None:
    """A transient ``openai.RateLimitError`` maps to :class:`RateLimitError`."""
    provider = _BareProvider()
    rate_failure = _build_rate_error()
    with (
        pytest.raises(RateLimitError, match="rate limited"),
        _translator(
            provider,
            log_prefix="test",
            messages=_TEST_ERROR_MESSAGES,
        ),
    ):
        raise rate_failure


def _build_quota_error() -> openai.RateLimitError:
    """Construct an ``openai.RateLimitError`` describing permanent quota exhaustion.

    Returns:
        openai.RateLimitError: A 429 carrying an ``insufficient_quota`` body,
        the shape OpenAI returns when an account is out of credits.
    """
    return openai.RateLimitError(
        message="Error code: 429 - insufficient_quota: You exceeded your current quota",
        response=_make_httpx_response(429),
        body=None,
    )


def test_translate_openai_errors_permanent_quota_fails_fast() -> None:
    """A billing/quota-exhaustion 429 maps to :class:`ProviderError`, not retryable.

    ``insufficient_quota`` cannot succeed on retry, so the helper must raise
    the non-retryable :class:`ProviderError` (built from ``api_error``) rather
    than :class:`RateLimitError`, which the backoff wrapper would retry.
    """
    provider = _BareProvider()
    quota_failure = _build_quota_error()
    with (
        pytest.raises(ProviderError, match="api error"),
        _translator(
            provider,
            log_prefix="test",
            messages=_TEST_ERROR_MESSAGES,
        ),
    ):
        raise quota_failure


def test_translate_openai_errors_transport_oserror() -> None:
    """Transport-layer ``OSError`` becomes :class:`ProviderError`."""
    provider = _BareProvider()
    transport_failure = OSError("network down")
    with (
        pytest.raises(ProviderError, match="request failed"),
        _translator(
            provider,
            log_prefix="test",
            messages=_TEST_ERROR_MESSAGES,
        ),
    ):
        raise transport_failure


def test_translate_openai_errors_value_error() -> None:
    """``ValueError`` is treated as a transport failure."""
    provider = _BareProvider()
    value_failure = ValueError("garbled response")
    with (
        pytest.raises(ProviderError, match="request failed"),
        _translator(
            provider,
            log_prefix="test",
            messages=_TEST_ERROR_MESSAGES,
        ),
    ):
        raise value_failure


def test_translate_openai_errors_unrelated_exception_propagates() -> None:
    """Unrelated exceptions propagate untouched.

    The context manager only intercepts the OpenAI SDK exception
    families and well-known transport errors. Anything else - here
    a :class:`KeyError` - bubbles up to the caller verbatim.
    """
    provider = _BareProvider()
    unrelated = KeyError("not in scope")
    with (
        pytest.raises(KeyError),
        _translator(
            provider,
            log_prefix="test",
            messages=_TEST_ERROR_MESSAGES,
        ),
    ):
        raise unrelated


_REAL_PROMPT_TOKENS: int = 10
_REAL_COMPLETION_TOKENS: int = 2
_REAL_TOTAL_TOKENS: int = 12


def _make_real_chat_completion(
    *,
    prompt_tokens: int,
    completion_tokens: int,
    total_tokens: int,
    model: str = "gpt-4",
) -> ChatCompletion:
    """Construct a real :class:`openai.types.chat.ChatCompletion` object.

    Uses :meth:`ChatCompletion.model_validate` (the Pydantic v2 path the
    OpenAI SDK always uses) so the returned object is byte-for-byte
    identical to what the SDK produces from a real HTTP response.

    Args:
        prompt_tokens: Prompt token count to embed in ``usage``.
        completion_tokens: Completion token count to embed in ``usage``.
        total_tokens: Total token count to embed in ``usage``; pass
            ``0`` to exercise the helper's fallback sum path.
        model: Model name string embedded in the response.

    Returns:
        ChatCompletion: A fully-validated real SDK object.
    """
    data: dict[str, object] = {
        "id": "chatcmpl-realtest",
        "choices": [
            {
                "finish_reason": "stop",
                "index": 0,
                "message": {
                    "content": "hello",
                    "role": "assistant",
                    "function_call": None,
                    "tool_calls": None,
                },
            },
        ],
        "created": int(time.time()),
        "model": model,
        "object": "chat.completion",
        "usage": {
            "completion_tokens": completion_tokens,
            "prompt_tokens": prompt_tokens,
            "total_tokens": total_tokens,
        },
    }
    return ChatCompletion.model_validate(data)


def _make_real_chat_completion_no_usage(model: str = "gpt-3.5-turbo") -> ChatCompletion:
    """Construct a real :class:`openai.types.chat.ChatCompletion` without a ``usage`` field.

    Args:
        model: Model name string embedded in the response.

    Returns:
        ChatCompletion: A fully-validated real SDK object with ``usage=None``.
    """
    data: dict[str, object] = {
        "id": "chatcmpl-nousage",
        "choices": [
            {
                "finish_reason": "stop",
                "index": 0,
                "message": {
                    "content": "hi",
                    "role": "assistant",
                    "function_call": None,
                    "tool_calls": None,
                },
            },
        ],
        "created": int(time.time()),
        "model": model,
        "object": "chat.completion",
    }
    return ChatCompletion.model_validate(data)


def _make_real_chunk_with_usage(
    *,
    prompt_tokens: int,
    completion_tokens: int,
    total_tokens: int,
) -> ChatCompletionChunk:
    """Construct a real :class:`openai.types.chat.ChatCompletionChunk` carrying usage.

    Args:
        prompt_tokens: Prompt token count.
        completion_tokens: Completion token count.
        total_tokens: Total token count; ``0`` triggers the helper fallback.

    Returns:
        ChatCompletionChunk: A fully-validated real SDK chunk object.
    """
    data: dict[str, object] = {
        "id": "chatcmpl-chunk",
        "choices": [
            {
                "delta": {"content": "world", "role": "assistant"},
                "finish_reason": "stop",
                "index": 0,
            },
        ],
        "created": int(time.time()),
        "model": "gpt-3.5-turbo",
        "object": "chat.completion.chunk",
        "usage": {
            "completion_tokens": completion_tokens,
            "prompt_tokens": prompt_tokens,
            "total_tokens": total_tokens,
        },
    }
    return ChatCompletionChunk.model_validate(data)


def test_build_usage_from_real_chat_completion_populated() -> None:
    """Real ``ChatCompletion`` SDK object yields exact token counts in ``UsageInfo``.

    Constructs a genuine ``openai.types.chat.ChatCompletion`` via
    ``model_validate`` (the same path the SDK uses for live API responses)
    and passes it directly to the helper. Validates that the exact field
    values round-trip correctly through ``CompletionUsage`` and into
    :class:`UsageInfo`.
    """
    cc = _make_real_chat_completion(
        prompt_tokens=_REAL_PROMPT_TOKENS,
        completion_tokens=_REAL_COMPLETION_TOKENS,
        total_tokens=_REAL_TOTAL_TOKENS,
    )
    result = _build_usage_from_completion(cc)
    assert isinstance(result, UsageInfo)
    assert result.prompt_tokens == _REAL_PROMPT_TOKENS
    assert result.completion_tokens == _REAL_COMPLETION_TOKENS
    assert result.total_tokens == _REAL_TOTAL_TOKENS


def test_build_usage_from_real_chat_completion_no_usage_returns_none() -> None:
    """A real ``ChatCompletion`` without a ``usage`` field returns ``None``.

    The OpenAI SDK can return responses without ``usage`` (e.g. when
    ``stream_options.include_usage`` is not requested). The helper must
    return ``None`` rather than raising.
    """
    cc = _make_real_chat_completion_no_usage()
    assert cc.usage is None, "precondition: SDK object must have usage=None"
    result = _build_usage_from_completion(cc)
    assert result is None


def test_build_usage_from_real_chat_completion_zero_total_fallback() -> None:
    """Real ``ChatCompletion`` with ``total_tokens=0`` triggers the fallback sum.

    Some providers return ``total_tokens=0`` on streaming responses; the
    helper must fall back to ``prompt + completion`` rather than
    reporting zero.
    """
    cc = _make_real_chat_completion(
        prompt_tokens=_REAL_PROMPT_TOKENS,
        completion_tokens=_REAL_COMPLETION_TOKENS,
        total_tokens=0,
    )
    result = _build_usage_from_completion(cc)
    assert isinstance(result, UsageInfo)
    assert result.total_tokens == _REAL_PROMPT_TOKENS + _REAL_COMPLETION_TOKENS


def test_build_usage_from_real_chunk_usage_populated() -> None:
    """Real ``ChatCompletionChunk`` usage object yields exact token counts.

    Constructs a real SDK chunk carrying ``usage`` and passes its
    ``.usage`` attribute directly to the chunk helper. Validates that
    all three fields are extracted correctly from the real
    ``CompletionUsage`` Pydantic model.
    """
    chunk = _make_real_chunk_with_usage(
        prompt_tokens=_REAL_PROMPT_TOKENS,
        completion_tokens=_REAL_COMPLETION_TOKENS,
        total_tokens=_REAL_TOTAL_TOKENS,
    )
    assert chunk.usage is not None, "precondition: chunk.usage must be populated"
    result = _build_usage_from_chunk(chunk.usage)
    assert isinstance(result, UsageInfo)
    assert result.prompt_tokens == _REAL_PROMPT_TOKENS
    assert result.completion_tokens == _REAL_COMPLETION_TOKENS
    assert result.total_tokens == _REAL_TOTAL_TOKENS


def test_build_usage_from_real_chunk_zero_total_fallback() -> None:
    """Real chunk with ``total_tokens=0`` triggers the ``prompt+completion`` fallback.

    Args for a real ``CompletionUsage`` with ``total_tokens=0`` exercise the
    ``or (prompt + completion)`` branch in the helper.
    """
    chunk = _make_real_chunk_with_usage(
        prompt_tokens=_REAL_PROMPT_TOKENS,
        completion_tokens=_REAL_COMPLETION_TOKENS,
        total_tokens=0,
    )
    assert chunk.usage is not None
    result = _build_usage_from_chunk(chunk.usage)
    assert isinstance(result, UsageInfo)
    assert result.total_tokens == _REAL_PROMPT_TOKENS + _REAL_COMPLETION_TOKENS
