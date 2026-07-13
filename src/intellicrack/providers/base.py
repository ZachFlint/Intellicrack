# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Base protocol for LLM providers.

This module defines the abstract interface that all LLM provider implementations must follow, enabling consistent interaction across
Anthropic, OpenAI, Google, Ollama, and OpenRouter.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final, TypedDict, TypeVar, cast

import openai

from intellicrack.core.error_logging import log_passthrough
from intellicrack.core.logging import get_logger, log_provider_response
from intellicrack.core.types import (
    AuthenticationError,
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    RateLimitError,
    ThinkingConfig,
    ToolCall,
    ToolChoice,
    ToolChoiceMode,
    ToolDefinition,
    ToolParameter,
)


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable, Generator

    import structlog
    from openai.types.chat.chat_completion_message import ChatCompletionMessage

    from intellicrack.core.types import ProviderName

_T = TypeVar("_T")

_logger = get_logger(__name__)
_secure_rng = random.SystemRandom()


@dataclass(slots=True)
class UsageInfo:
    """Token usage statistics reported by a provider.

    Attributes:
        prompt_tokens: Tokens consumed by the prompt / input messages.
        completion_tokens: Tokens generated in the completion / output.
        total_tokens: Sum of prompt and completion tokens as reported
            by the provider when available.
        cache_read_tokens: Prompt tokens served from a provider-side
            prompt cache (Anthropic ``cache_read_input_tokens``); ``0``
            when the provider reports no cache hit or lacks the field.
        cache_creation_tokens: Prompt tokens written into the
            provider-side prompt cache (Anthropic
            ``cache_creation_input_tokens``); ``0`` when not reported.
    """

    prompt_tokens: int = field(default=0)
    completion_tokens: int = field(default=0)
    total_tokens: int = field(default=0)
    cache_read_tokens: int = field(default=0)
    cache_creation_tokens: int = field(default=0)


@dataclass(frozen=True, slots=True)
class OpenAIErrorMessages:
    """Provider-specific message templates for OpenAI SDK error translation.

    Each template is a printf-style format string carrying a single
    string substitution slot for the underlying exception text.
    Templates are interpolated when a matching SDK exception is
    intercepted by
    :meth:`LLMProviderBase._translate_openai_errors`.

    Attributes:
        auth_invalid: Template raised on
            :class:`openai.AuthenticationError`.
        rate_limited: Template raised on
            :class:`openai.RateLimitError`.
        api_error: Template raised on :class:`openai.APIError`.
        request_failed: Template raised on transport failures
            (``ConnectionError``, ``TimeoutError``, ``OSError``,
            ``ValueError``).
    """

    auth_invalid: str
    rate_limited: str
    api_error: str
    request_failed: str


class JSONSchemaProperty(TypedDict, total=False):
    """JSON Schema property definition for tool parameters."""

    type: str
    description: str
    enum: list[str]
    default: str | int | float | bool | None
    items: JSONSchemaProperty
    properties: dict[str, JSONSchemaProperty]
    required: list[str]


class JSONSchemaParameters(TypedDict):
    """JSON Schema parameters object for tool functions."""

    type: str
    properties: dict[str, JSONSchemaProperty]
    required: list[str]


class AnthropicToolSchema(TypedDict):
    """Anthropic tool schema format."""

    name: str
    description: str
    input_schema: JSONSchemaParameters


class OpenAIFunctionSchema(TypedDict):
    """OpenAI function definition within a tool."""

    name: str
    description: str
    parameters: JSONSchemaParameters


class OpenAIToolSchema(TypedDict):
    """OpenAI tool schema format."""

    type: str
    function: OpenAIFunctionSchema


class GoogleFunctionDeclaration(TypedDict):
    """Google Gemini function declaration format."""

    name: str
    description: str
    parameters: JSONSchemaParameters


def serialize_tool_result(result: object) -> str:
    """Serialize a tool result to a string for API consumption.

    Args:
        result: The tool result value, either a string or a
            JSON-serializable object.

    Returns:
        str: The result as a string, JSON-encoded if not already a string.
    """
    return result if isinstance(result, str) else json.dumps(result)


def parse_tool_call(
    *,
    call_id: str,
    function_name: str,
    raw_arguments: str | dict[str, object],
) -> ToolCall:
    """Parse a tool call from provider-specific data into a ToolCall.

    Handles JSON argument parsing and tool name extraction from
    dotted function names.

    Args:
        call_id: Unique identifier for the tool call.
        function_name: Function name from the provider response.
        raw_arguments: Arguments as a JSON string or pre-parsed dict.

    Returns:
        ToolCall: Parsed ToolCall instance.
    """
    parsed_args: dict[str, Any]
    if isinstance(raw_arguments, str):
        try:
            parsed_args = json.loads(raw_arguments)
        except json.JSONDecodeError:
            _logger.warning("tool_call_args_json_decode_failed", function=function_name)
            parsed_args = {}
    else:
        parsed_args = dict(raw_arguments)

    tool_name = function_name.split(".", maxsplit=1)[0] if "." in function_name else function_name
    return ToolCall(
        id=call_id,
        tool_name=tool_name,
        function_name=function_name,
        arguments=parsed_args,
    )


@dataclass(frozen=True, slots=True)
class HttpErrorMessages:
    """Provider-specific message templates for HTTP-status exception translation.

    Used by :meth:`LLMProviderBase._raise_typed_for_status` to translate
    HTTP error responses (401, 403, 429, 503) returned by REST-based
    providers into Intellicrack typed exceptions
    (:class:`AuthenticationError`, :class:`RateLimitError`,
    :class:`ProviderError`).

    Each template is a printf-style format string carrying a single
    ``%s`` substitution slot. The helper interpolates the originating
    exception (or, for HTTP 503, the result of
    ``extract_503_message``) into that slot before raising.

    Attributes:
        auth_invalid: Template raised on HTTP 401 / 403, interpolated
            with the originating exception text.
        rate_limited: Template raised on HTTP 429, interpolated with
            the originating exception text.
        service_unavailable: Template raised on HTTP 503, interpolated
            with the result of ``extract_503_message``.
    """

    auth_invalid: str
    rate_limited: str
    service_unavailable: str


HTTP_UNAUTHORIZED: int = 401
HTTP_FORBIDDEN: int = 403
HTTP_RATE_LIMITED: int = 429
HTTP_SERVICE_UNAVAILABLE: int = 503

_AUTH_STATUS_CODES: frozenset[int] = frozenset({HTTP_UNAUTHORIZED, HTTP_FORBIDDEN})

REASONING_EFFORT_LOW_THRESHOLD: int = 4000
REASONING_EFFORT_MEDIUM_THRESHOLD: int = 16000
REASONING_EFFORT_HIGH_THRESHOLD: int = 32000


def map_thinking_budget_to_effort(
    budget_tokens: int,
    *,
    allow_xhigh: bool = False,
) -> str:
    """Map a :attr:`ThinkingConfig.budget_tokens` to a reasoning_effort level.

    Shared mapping for OpenAI-compatible APIs (OpenAI o-series,
    Grok-multi-agent, OpenRouter) that expose a discrete ``"low"`` /
    ``"medium"`` / ``"high"`` knob rather than a token budget.  The
    thresholds match OpenAI's documented effort tiers and are reused
    verbatim across providers so a single ``ThinkingConfig`` propagates
    consistently.

    Args:
        budget_tokens: Caller-supplied thinking budget in tokens.
        allow_xhigh: When ``True``, budgets above
            :data:`REASONING_EFFORT_HIGH_THRESHOLD` map to ``"xhigh"``
            instead of ``"high"``.  Grok exposes ``"xhigh"``; OpenAI and
            OpenRouter currently top out at ``"high"``.

    Returns:
        str: One of ``"low"``, ``"medium"``, ``"high"``, or
        ``"xhigh"``.
    """
    if budget_tokens <= REASONING_EFFORT_LOW_THRESHOLD:
        return "low"
    if budget_tokens <= REASONING_EFFORT_MEDIUM_THRESHOLD:
        return "medium"
    if not allow_xhigh:
        return "high"
    return "high" if budget_tokens <= REASONING_EFFORT_HIGH_THRESHOLD else "xhigh"


_ERR_EMPTY_MESSAGES: Final[str] = "messages must contain at least one message"


class LLMProviderBase(ABC):
    """Abstract base class for LLM providers.

    All provider implementations must inherit from this class and implement the abstract methods defined here. This ensures a consistent
    interface for the orchestrator to interact with any LLM provider.
    """

    def __init__(self) -> None:
        """Initialize the LLMProviderBase instance."""
        self._credentials: ProviderCredentials | None = None
        self.connected: bool = False
        self._cancel_requested: bool = False
        self._pending_tool_calls: list[ToolCall] = []
        self._pending_usage: UsageInfo | None = None
        self._pending_thinking: list[str] = []
        self._logger = get_logger(__name__)
        self._logger.info("provider_base_initialized")

    @property
    @abstractmethod
    def name(self) -> ProviderName:
        """The provider's name.

        Returns:
            ProviderName: The ProviderName enum value for this provider.
        """

    @property
    def is_connected(self) -> bool:
        """Check if the provider is connected and authenticated.

        Returns:
            bool: True if the provider is ready to accept requests.
        """
        return self.connected

    @staticmethod
    def _httpx_client_rebind_target(
        bound_loop: asyncio.AbstractEventLoop | None,
    ) -> asyncio.AbstractEventLoop | None:
        """Return the running loop when an httpx client must be rebuilt.

        httpcore binds a connection pool's internal asyncio
        synchronization primitives to the event loop on which the client
        first issues a request. A raw :class:`httpx.AsyncClient` created
        during :meth:`connect` therefore cannot be reused from a
        different running loop: doing so raises
        ``RuntimeError: ... is bound to a different event loop``. This is
        exactly the situation that occurs when providers connect on the
        application bootstrap loop but model discovery (and subsequent
        chat traffic) runs on the persistent background bridge loop. The
        official OpenAI / Anthropic / google-genai SDK clients rebind
        their transport transparently; providers backed by a raw
        ``httpx.AsyncClient`` must rebuild the client explicitly.

        Args:
            bound_loop: The loop the existing client was bound to, or
                ``None`` when no client exists yet.

        Returns:
            asyncio.AbstractEventLoop | None: The current running loop
            when a rebuild is required (``bound_loop`` is ``None`` or
            differs from the running loop); ``None`` when the existing
            client is still valid for the running loop.
        """
        running = asyncio.get_running_loop()
        return None if bound_loop is running else running

    @abstractmethod
    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect to the provider with given credentials.

        Args:
            credentials: API credentials for authentication.

        Raises:
            AuthenticationError: If credentials are invalid.
            ProviderError: If unable to connect to provider.
        """

    async def disconnect(self) -> None:
        """Disconnect from the provider.

        Cleans up any resources and invalidates the connection.
        """
        self.connected = False
        self._credentials = None
        self._cancel_requested = False
        self._pending_tool_calls.clear()
        self._pending_usage = None
        self._pending_thinking.clear()
        self._logger.debug("provider_base_disconnected")

    @abstractmethod
    async def list_models(self) -> list[ModelInfo]:
        """Dynamically fetch available models from the provider.

        Returns:
            list[ModelInfo]: List of available models with their capabilities.

        Raises:
            ProviderError: If not connected or request fails.
        """

    @abstractmethod
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
        """Send a chat completion request.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature (0.0 to 1.0).
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration.
            enable_cache: Whether to enable prompt caching.

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of (assistant message, tool calls if any).

        Raises:
            ModelNotFoundError: If model doesn't exist.
            RateLimitError: If rate limited.
            ProviderError: For other API errors.
        """

    @abstractmethod
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
        """Stream a chat completion response.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature (0.0 to 1.0).
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration.
            enable_cache: Whether to enable prompt caching.

        Yields:
            str: Text chunks as they arrive.

        Note:
            Implementations should raise ModelNotFoundError if the model
            doesn't exist, RateLimitError if rate limited, or ProviderError
            for other API errors.
        """
        # Abstract async generator - yield required for type checker
        yield ""

    def get_pending_tool_calls(self) -> list[ToolCall]:
        """Retrieve tool calls accumulated during the last streaming call.

        After a ``chat_stream()`` call completes, providers store any tool
        calls that were signalled in the stream deltas.  Consumers call
        this method once to collect them.  The internal buffer is cleared
        on each call so results are never returned twice.

        Returns:
            list[ToolCall]: List of ToolCall objects accumulated during streaming.
        """
        calls = list(self._pending_tool_calls)
        self._pending_tool_calls.clear()
        return calls

    def get_pending_usage(self) -> UsageInfo | None:
        """Retrieve token usage captured during the last request.

        After a ``chat()`` or ``chat_stream()`` call completes, providers
        store token-usage statistics reported by the backend (when
        available).  Consumers call this method once to collect them.
        The internal buffer is cleared on each call so the same usage
        record is never returned twice.

        Returns:
            UsageInfo | None: Captured UsageInfo if the provider reported
            any usage, otherwise ``None``.
        """
        usage = self._pending_usage
        self._pending_usage = None
        return usage

    def get_pending_thinking(self) -> list[str]:
        """Retrieve extended-thinking text emitted during the last request.

        After a streaming call that enabled extended thinking, providers
        store each thinking block seen on the wire.  Consumers call this
        method once to collect them.  The internal buffer is cleared on
        each call so the same block is never returned twice.

        Returns:
            list[str]: List of thinking block texts accumulated during the
            last request.  Empty when thinking was not enabled or not
            emitted.
        """
        thinking = list(self._pending_thinking)
        self._pending_thinking.clear()
        return thinking

    async def cancel_request(self) -> None:
        """Cancel any in-flight request.

        This method should safely abort ongoing API calls without raising exceptions.
        """
        self._logger.info("provider_cancel_requested")
        self._cancel_requested = True

    async def _retry_with_backoff(
        self,
        coro_factory: Callable[[], Awaitable[_T]],
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        retryable_exceptions: tuple[type[Exception], ...] = (RateLimitError,),
    ) -> _T:
        """Execute an async operation with exponential backoff retry.

        Retries on transient failures using exponential backoff with jitter.
        ``AuthenticationError`` is never retried regardless of the
        ``retryable_exceptions`` parameter.

        Args:
            coro_factory: Zero-argument callable that creates the awaitable
                to execute on each attempt.
            max_retries: Maximum number of retry attempts after the initial
                try.
            base_delay: Initial delay in seconds before the first retry.
            max_delay: Upper bound on the delay between retries.
            retryable_exceptions: Tuple of exception types that should
                trigger a retry.

        Returns:
            _T: The result of the awaitable produced by *coro_factory*.

        Raises:
            AuthenticationError: If the operation fails with bad credentials.
            ProviderError: If all retry attempts are exhausted with no captured
                exception to re-raise.
            retryable_exceptions: The most recent caught exception when
                ``max_retries`` is exhausted. Re-raised verbatim from the
                ``except retryable_exceptions`` block.
        """
        for attempt in range(max_retries + 1):
            try:
                return await coro_factory()
            except AuthenticationError as exc:
                log_passthrough(
                    self._logger,
                    "provider_retry_auth_passthrough",
                    exc,
                    attempt=attempt + 1,
                    max_retries=max_retries,
                )
                raise
            except retryable_exceptions as exc:
                if attempt >= max_retries:
                    self._logger.exception(
                        "provider_retry_exhausted",
                        attempt=attempt + 1,
                        max_retries=max_retries,
                    )
                    raise
                delay = min(base_delay * (2**attempt), max_delay)
                jitter = _secure_rng.uniform(0, delay * 0.1)
                self._logger.warning(
                    "provider_retry_backoff",
                    attempt=attempt + 1,
                    max_retries=max_retries,
                    delay=delay + jitter,
                    error=str(exc),
                )
                await asyncio.sleep(delay + jitter)
        msg = "retry_with_backoff exhausted without capturing an exception"
        raise ProviderError(msg)

    @abstractmethod
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Convert internal tool format to provider-specific format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            list[dict[str, object]]: List of tool definitions in provider's format.
        """

    @abstractmethod
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Convert internal message format to provider-specific format.

        Args:
            messages: List of Message objects.

        Returns:
            list[dict[str, object]]: List of messages in provider's format.
        """

    def convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Convert internal tool format to provider-specific format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            list[dict[str, object]]: List of tool definitions in provider's format.
        """
        return self._convert_tools_to_provider_format(tools)

    @staticmethod
    def _convert_tools_to_openai_format(
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Build OpenAI-compatible tool dicts from internal tool definitions.

        Shared conversion helper for providers that consume the OpenAI
        function-calling tool schema (OpenAI, Grok, OpenRouter,
        HuggingFace, Ollama).

        Args:
            tools: List of internal :class:`ToolDefinition` objects to
                convert.

        Returns:
            list[dict[str, object]]: List of tool dicts in the OpenAI
            ``{"type": "function", "function": {...}}`` format.
        """
        openai_tools: list[dict[str, object]] = []
        for tool in tools:
            tool_schemas = create_openai_tool_schema(tool)
            openai_tools.extend(dict(schema) for schema in tool_schemas)
        return openai_tools

    def convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Convert internal message format to provider-specific format.

        Args:
            messages: List of Message objects.

        Returns:
            list[dict[str, object]]: List of messages in provider's format.
        """
        return self._convert_messages_to_provider_format(messages)

    @staticmethod
    def _build_chat_response(
        *,
        provider: str,
        model: str,
        content: str,
        tool_calls: list[ToolCall],
        duration_ms: float,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Create a standard chat response tuple and log the response.

        Args:
            provider: Provider name for logging.
            model: Model identifier for logging.
            content: Response text content.
            tool_calls: Parsed tool calls from the response.
            duration_ms: Request duration in milliseconds.

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of (assistant message, tool calls or None).
        """
        message = Message(
            role="assistant",
            content=content,
            tool_calls=tool_calls or None,
            timestamp=datetime.now(tz=UTC),
        )
        log_provider_response(
            provider=provider,
            model=model,
            tool_calls_count=len(tool_calls),
            duration_ms=duration_ms,
        )
        return message, tool_calls or None

    @staticmethod
    def _parse_tool_call_common(
        *,
        call_id: str,
        function_name: str,
        raw_arguments: str | dict[str, object],
    ) -> ToolCall:
        """Parse a tool call from provider-specific data into a ToolCall.

        Handles JSON argument parsing and tool name extraction from
        dotted function names.

        Args:
            call_id: Unique identifier for the tool call.
            function_name: Function name from the provider response.
            raw_arguments: Arguments as a JSON string or pre-parsed dict.

        Returns:
            ToolCall: Parsed ToolCall instance.
        """
        return parse_tool_call(
            call_id=call_id,
            function_name=function_name,
            raw_arguments=raw_arguments,
        )

    def _parse_openai_format_tool_calls(
        self,
        response_message: ChatCompletionMessage,
    ) -> list[ToolCall]:
        """Parse tool calls from an OpenAI-compatible response message.

        Iterates ``response_message.tool_calls`` and converts each entry
        whose ``function`` attribute is present into a :class:`ToolCall`
        via :meth:`_parse_tool_call_common`. Entries missing a
        ``function`` attribute (e.g. custom tool calls or non-function
        union members) are silently skipped.

        Uses ``getattr`` so the helper works both with the strongly
        typed OpenAI SDK response shape and with the looser response
        shapes returned by OpenAI-compatible backends such as Grok.

        Args:
            response_message: The assistant message returned by an
                OpenAI-compatible chat completion endpoint.

        Returns:
            list[ToolCall]: List of parsed :class:`ToolCall` instances,
            in the same order they appeared in ``response_message``.
        """
        tool_calls: list[ToolCall] = []
        if not response_message.tool_calls:
            return tool_calls

        for tc in response_message.tool_calls:
            tc_function = getattr(tc, "function", None)
            if tc_function is None:
                continue
            function_name = getattr(tc_function, "name", None)
            raw_arguments = getattr(tc_function, "arguments", None)
            if not isinstance(function_name, str) or not isinstance(raw_arguments, str):
                continue
            tool_call = self._parse_tool_call_common(
                call_id=tc.id,
                function_name=function_name,
                raw_arguments=raw_arguments,
            )
            tool_calls.append(tool_call)
            self._logger.debug(
                "tool_call_parsed",
                tool_name=tool_call.tool_name,
                arguments_count=len(tool_call.arguments),
            )
        return tool_calls

    @staticmethod
    def _serialize_tool_result(result: object) -> str:
        """Serialize a tool result to a string for API consumption.

        Args:
            result: The tool result value, either a string or a
                JSON-serializable object.

        Returns:
            str: The result as a string, JSON-encoded if not already a string.
        """
        return serialize_tool_result(result)

    @staticmethod
    def _reject_empty_messages(messages: list[Message]) -> None:
        """Reject a chat request that carries no messages.

        Every provider treats an empty ``messages`` list as invalid input: a
        chat completion needs at least one message to respond to. Providers
        call this at the top of ``chat`` and ``chat_stream`` so the misuse
        surfaces as a typed :class:`ProviderError` before any connection state
        check or network call, uniformly across every backend.

        Args:
            messages: The conversation messages supplied by the caller.

        Raises:
            ProviderError: When ``messages`` is empty.
        """
        if not messages:
            _logger.warning("chat_rejected_empty_messages")
            raise ProviderError(_ERR_EMPTY_MESSAGES)

    @staticmethod
    def _convert_tool_choice_to_openai_format(
        tool_choice: ToolChoice,
    ) -> str | dict[str, object]:
        """Convert a ToolChoice to the OpenAI-compatible tool_choice parameter.

        Args:
            tool_choice: The tool choice configuration.

        Returns:
            str | dict[str, object]: A string or dict suitable for the ``tool_choice`` API parameter.

        Raises:
            ProviderError: When ``tool_choice.mode`` is
                :data:`ToolChoiceMode.SPECIFIC` but ``function_name`` is
                missing or empty.  Sending an empty function name to an
                OpenAI-compatible endpoint produces a 400 server-side;
                surface the misuse as a typed error here.
        """
        if tool_choice.mode == ToolChoiceMode.AUTO:
            return "auto"
        if tool_choice.mode == ToolChoiceMode.NONE:
            return "none"
        if tool_choice.mode == ToolChoiceMode.REQUIRED:
            return "required"
        function_name = tool_choice.function_name
        if not function_name:
            _logger.warning("tool_choice_specific_missing_function_name")
            msg = "ToolChoiceMode.SPECIFIC requires a non-empty function_name"
            raise ProviderError(msg)
        return {
            "type": "function",
            "function": {"name": function_name},
        }

    @staticmethod
    def _convert_messages_to_openai_format(
        messages: list[Message],
        *,
        serialize_tool_arguments: bool = True,
        include_tool_call_type: bool = True,
    ) -> list[dict[str, object]]:
        """Convert internal messages to OpenAI-compatible format.

        Shared conversion logic for providers that use the OpenAI message
        schema (OpenAI, Grok, HuggingFace, OpenRouter, Ollama).

        Args:
            messages: List of Message objects to convert.
            serialize_tool_arguments: When True, tool call arguments are
                JSON-serialized to a string. When False, the dict is
                passed through as-is (Ollama).
            include_tool_call_type: When True, each tool call dict
                includes ``"type": "function"``. When False, the key
                is omitted (Ollama).

        Returns:
            list[dict[str, object]]: List of message dicts in OpenAI-compatible format.
        """
        converted: list[dict[str, object]] = []

        for msg in messages:
            if msg.role in {"system", "user"}:
                converted.append({
                    "role": msg.role,
                    "content": msg.content,
                })
            elif msg.role == "assistant":
                assistant_msg: dict[str, object] = {
                    "role": "assistant",
                    "content": msg.content,
                }

                if msg.tool_calls:
                    tc_list: list[dict[str, object]] = []
                    for tc in msg.tool_calls:
                        tc_dict: dict[str, object] = {
                            "id": tc.id,
                            "function": {
                                "name": tc.function_name,
                                "arguments": json.dumps(tc.arguments) if serialize_tool_arguments else tc.arguments,
                            },
                        }
                        if include_tool_call_type:
                            tc_dict["type"] = "function"
                        tc_list.append(tc_dict)
                    assistant_msg["tool_calls"] = tc_list

                converted.append(assistant_msg)
            elif msg.role == "tool" and msg.tool_results:
                converted.extend(
                    {
                        "role": "tool",
                        "tool_call_id": tr.call_id,
                        "content": serialize_tool_result(tr.result),
                    }
                    for tr in msg.tool_results
                )

        return converted

    @staticmethod
    def _build_usage_from_openai_completion(response: object) -> UsageInfo | None:
        """Extract token-usage statistics from an OpenAI ``ChatCompletion``.

        Reads the ``usage`` attribute from a non-streaming chat
        completion response and constructs a :class:`UsageInfo`
        instance. Falls back to ``prompt + completion`` when the
        provider omits ``total_tokens``. Returns ``None`` when the
        response has no ``usage`` attribute or it is ``None``.

        Args:
            response: The OpenAI-compatible chat completion response.

        Returns:
            UsageInfo | None: Populated UsageInfo when usage is present
            on the response, otherwise ``None``.
        """
        usage = getattr(response, "usage", None)
        return LLMProviderBase._build_usage_from_openai_chunk(usage)

    @staticmethod
    def _build_usage_from_openai_chunk(chunk_usage: object) -> UsageInfo | None:
        """Extract token-usage statistics from an OpenAI streaming chunk.

        Reads ``prompt_tokens``, ``completion_tokens``, and
        ``total_tokens`` from a chunk's ``usage`` field, falling back
        to ``prompt + completion`` when ``total_tokens`` is missing or
        zero.

        Args:
            chunk_usage: The ``usage`` attribute from a streaming chunk
                or other OpenAI-compatible usage object.

        Returns:
            UsageInfo | None: Populated UsageInfo when usage is present,
            otherwise ``None``.
        """
        if chunk_usage is None:
            return None
        prompt = int(getattr(chunk_usage, "prompt_tokens", 0) or 0)
        completion = int(getattr(chunk_usage, "completion_tokens", 0) or 0)
        total = int(getattr(chunk_usage, "total_tokens", 0) or 0) or (prompt + completion)
        return UsageInfo(
            prompt_tokens=prompt,
            completion_tokens=completion,
            total_tokens=total,
        )

    @staticmethod
    def _extract_system_messages(messages: list[Message]) -> str | None:
        """Concatenate every ``system``-role message into a single string.

        Iterates ``messages`` in order, keeping only messages whose
        ``role`` is ``"system"`` and whose ``content`` is non-empty,
        and joins their content with double-newline separators.
        Returns ``None`` when no system message contributes any
        content, mirroring the behaviour of provider SDKs (Anthropic,
        Google) that treat the absence of a system instruction as a
        distinct request shape.

        Args:
            messages: Conversation messages to scan.

        Returns:
            str | None: The joined system instruction text, or ``None``
            when no system message contributed any content.
        """
        system_parts: list[str] = [msg.content for msg in messages if msg.role == "system" and msg.content]
        return "\n\n".join(system_parts) if system_parts else None

    @staticmethod
    def _raise_typed_for_status(
        status_code: int,
        exc: Exception,
        *,
        messages: HttpErrorMessages,
        extract_503_message: Callable[[Exception], str] | None = None,
    ) -> None:
        """Raise an Intellicrack typed exception for a known HTTP status code.

        Translates the HTTP status codes that providers consistently
        map to typed exceptions (401/403 to
        :class:`AuthenticationError`, 429 to :class:`RateLimitError`,
        503 to :class:`ProviderError`) by raising the matching
        Intellicrack typed exception in place, chained from ``exc``
        via ``raise ... from exc``. Status codes that do not match any
        known typed mapping return ``None`` so the caller can apply a
        provider-specific fall-through ``raise ProviderError(...)`` on
        the next line.

        Args:
            status_code: HTTP status code from the failing response.
            exc: The originating exception that the helper chains via
                ``raise ... from exc``. Its ``str(exc)`` is also
                interpolated into the matching message template.
            messages: Provider-specific :class:`HttpErrorMessages`
                carrying the printf-style templates raised by the
                helper.
            extract_503_message: Optional callable that extracts a
                human-readable model-loading message from ``exc``.
                When supplied and ``status_code`` is 503, the
                callable's return value is interpolated into
                ``messages.service_unavailable`` and a
                :class:`ProviderError` is raised. When omitted, HTTP
                503 falls through to the caller's default handling.

        Raises:
            AuthenticationError: When ``status_code`` is 401 or 403.
            ProviderError: When ``status_code`` is 503 and
                ``extract_503_message`` is supplied.
            RateLimitError: When ``status_code`` is 429.
        """
        if status_code in _AUTH_STATUS_CODES:
            raise AuthenticationError(messages.auth_invalid % exc) from exc
        if status_code == HTTP_RATE_LIMITED:
            raise RateLimitError(messages.rate_limited % exc) from exc
        if status_code == HTTP_SERVICE_UNAVAILABLE and extract_503_message is not None:
            raise ProviderError(messages.service_unavailable % extract_503_message(exc)) from exc

    @contextlib.contextmanager
    def _translate_openai_errors(
        self,
        *,
        log_prefix: str,
        messages: OpenAIErrorMessages,
        log_extra: dict[str, object] | None = None,
    ) -> Generator[None]:
        """Convert ``openai`` SDK exceptions into Intellicrack typed errors.

        Wraps a region of OpenAI SDK calls so that
        :class:`openai.AuthenticationError`,
        :class:`openai.RateLimitError`, :class:`openai.APIError`, and
        common transport failures (``ConnectionError``,
        ``TimeoutError``, ``OSError``, ``ValueError``) are logged
        using the provider's structured logger and re-raised as the
        Intellicrack-typed equivalents
        (:class:`AuthenticationError`, :class:`RateLimitError`,
        :class:`ProviderError`).

        Args:
            log_prefix: Stem for the structured-log event (e.g.
                ``"openai_chat"`` produces
                ``"openai_chat_auth_failed"``,
                ``"openai_chat_rate_limited"``, etc.).
            messages: Provider-specific format-string templates used
                to build the typed exception messages.
            log_extra: Optional structured-log keyword fields to
                attach to every emitted warning (e.g.
                ``{"model": "gpt-4o"}``).

        Yields:
            None: Execution proceeds inside the protected block.

        Raises:
            AuthenticationError: When the SDK reports authentication
                failure.
            ProviderError: When the SDK reports a non-rate-limit API
                error or a transport-level failure.
            RateLimitError: When the SDK reports rate limiting.
        """
        extra: dict[str, object] = dict(log_extra) if log_extra else {}
        try:
            yield
        except openai.AuthenticationError as exc:
            self._logger.warning("provider_call_auth_failed", log_prefix=log_prefix, error=str(exc), **extra)
            raise AuthenticationError(messages.auth_invalid % exc) from exc
        except openai.RateLimitError as exc:
            if is_permanent_quota_error(str(exc)):
                self._logger.warning("provider_call_quota_exhausted", log_prefix=log_prefix, error=str(exc), **extra)
                raise ProviderError(messages.api_error % exc) from exc
            self._logger.warning("provider_call_rate_limited", log_prefix=log_prefix, error=str(exc), **extra)
            raise RateLimitError(messages.rate_limited % exc) from exc
        except openai.APIError as exc:
            self._logger.warning("provider_call_api_error", log_prefix=log_prefix, error=str(exc), **extra)
            raise ProviderError(messages.api_error % exc) from exc
        except (ConnectionError, TimeoutError, OSError, ValueError) as exc:
            self._logger.warning("provider_call_failed", log_prefix=log_prefix, error=str(exc), **extra)
            raise ProviderError(messages.request_failed % exc) from exc

    @staticmethod
    def _safe_parse_stream_json(
        line: str,
        *,
        logger: structlog.stdlib.BoundLogger,
        event: str = "stream_json_parse_skipped",
    ) -> dict[str, Any] | None:
        """Parse a streaming response line as JSON, skipping malformed lines.

        Streaming providers receive responses one chunk per line. Some lines
        can be empty, contain SSE control framing, or be truncated when a
        connection drops mid-chunk. This helper centralises the
        parse-or-skip behaviour: it returns the parsed dict on success,
        returns ``None`` on JSON decode failure (after emitting a structured
        warning), and returns ``None`` for empty/whitespace-only lines.

        Args:
            line: The raw line from the streaming response.
            logger: Bound structlog logger used to emit a structured
                warning when JSON parsing fails. Provider-specific
                bindings (e.g. ``provider="ollama"``) flow through.
            event: Structured-log event name emitted on parse failure.
                Defaults to ``"stream_json_parse_skipped"`` to preserve
                the existing event taxonomy used by openrouter and
                ollama.

        Returns:
            dict[str, Any] | None: The parsed JSON object when ``line``
            decodes to a JSON object, or ``None`` when the line is
            empty, decodes to a non-object value, or fails to parse.
        """
        if not line:
            return None
        try:
            decoded: object = json.loads(line)
        except json.JSONDecodeError as exc:
            logger.warning(event, error=str(exc))
            return None
        return cast("dict[str, Any]", decoded) if isinstance(decoded, dict) else None


class ToolCallBufferManager:
    """Accumulates streaming tool call deltas into complete ToolCall objects.

    Used by providers that consume OpenAI-compatible SSE streams where tool call fragments arrive incrementally across multiple chunks.
    """

    def __init__(self) -> None:
        """Initialize the ToolCallBufferManager instance."""
        self._buffers: dict[int, dict[str, str]] = {}

    def accumulate(
        self,
        *,
        index: int,
        call_id: str | None = None,
        name: str | None = None,
        arguments: str | None = None,
    ) -> None:
        """Merge a single streaming delta into the buffer.

        Args:
            index: Tool-call index from the SSE delta.
            call_id: Unique identifier for the tool call (first chunk only).
            name: Function name (first chunk only).
            arguments: Partial JSON argument fragment to append.
        """
        if index not in self._buffers:
            self._buffers[index] = {"id": "", "name": "", "arguments": ""}
        buf = self._buffers[index]
        if call_id:
            buf["id"] = call_id
        if name:
            buf["name"] = name
        if arguments:
            buf["arguments"] += arguments

    def finalize(self) -> list[ToolCall]:
        """Convert all complete buffered entries to ToolCall objects and reset.

        Entries missing an ``id`` or ``name`` are silently discarded.

        Returns:
            list[ToolCall]: List of parsed ToolCall instances.
        """
        results = [
            parse_tool_call(
                call_id=buf["id"],
                function_name=buf["name"],
                raw_arguments=buf["arguments"],
            )
            for buf in self._buffers.values()
            if buf["id"] and buf["name"]
        ]
        self._buffers.clear()
        return results


_PERMANENT_QUOTA_MARKERS: Final = (
    "spending cap",
    "spend cap",
    "monthly spending",
    "insufficient_quota",
    "exceeded your current quota",
    "billing hard limit",
)


def is_permanent_quota_error(message: str) -> bool:
    """Determine whether a 429 message signals permanent quota/billing exhaustion.

    Providers return HTTP 429 for two very different conditions: a transient
    per-interval rate limit (safe to retry with backoff) and a permanent
    billing or spend-cap exhaustion (cannot succeed on retry within the
    session). This helper detects the latter so callers can fail fast with an
    actionable message instead of exhausting retries against a hard cap.

    Args:
        message: The provider error message text to inspect.

    Returns:
        bool: True if the message indicates a permanent, non-retryable quota
            or billing exhaustion; False for transient rate limits.
    """
    lowered = message.lower()
    return any(marker in lowered for marker in _PERMANENT_QUOTA_MARKERS)


def _build_items_schema(
    items_type: str,
    item_properties: list[ToolParameter] | None,
    *,
    uppercase: bool,
) -> JSONSchemaProperty:
    """Build the ``items`` schema for an array property.

    Args:
        items_type: JSON Schema type of the array elements.
        item_properties: Nested property definitions when ``items_type`` is
            ``"object"``; describes the element object's shape.
        uppercase: Whether type strings must be uppercased for the target
            provider (Google Gemini) rather than left lowercase
            (Anthropic, OpenAI).

    Returns:
        JSONSchemaProperty: Schema describing a single array element.
    """
    element_type = items_type.upper() if uppercase else items_type
    items: JSONSchemaProperty = {"type": element_type}
    if items_type == "object" and item_properties:
        properties: dict[str, JSONSchemaProperty] = {}
        required: list[str] = []
        for param in item_properties:
            properties[param.name] = _build_schema_property(
                param_type=param.type.upper() if uppercase else param.type,
                description=param.description,
                enum_values=param.enum,
                default=param.default,
                items_type=param.items_type,
                item_properties=param.item_properties,
            )
            if param.required:
                required.append(param.name)
        items["properties"] = properties
        items["required"] = required
    return items


def _build_schema_property(
    param_type: str,
    description: str,
    enum_values: list[str] | None = None,
    default: object = None,
    items_type: str = "string",
    item_properties: list[ToolParameter] | None = None,
) -> JSONSchemaProperty:
    """Build a JSON Schema property from parameters.

    Args:
        param_type: The JSON Schema type string. Uppercase (e.g. ``"ARRAY"``)
            signals Google Gemini formatting; lowercase signals
            Anthropic/OpenAI formatting.
        description: Description of the parameter.
        enum_values: Optional list of allowed values.
        default: Optional default value.
        items_type: JSON Schema type of array elements when ``param_type`` is
            an array. Emitted as the required ``items`` definition.
        item_properties: Nested property definitions for object array
            elements when ``items_type`` is ``"object"``.

    Returns:
        JSONSchemaProperty: JSONSchemaProperty with the specified values.
    """
    prop: JSONSchemaProperty = {
        "type": param_type,
        "description": description,
    }
    if param_type.upper() == "ARRAY":
        prop["items"] = _build_items_schema(items_type, item_properties, uppercase=param_type.isupper())
    if enum_values is not None:
        prop["enum"] = enum_values
    if default is not None and isinstance(default, (str, int, float, bool)):
        prop["default"] = default
    return prop


def create_anthropic_tool_schema(
    tool: ToolDefinition,
) -> list[AnthropicToolSchema]:
    """Convert ToolDefinition to Anthropic's tool format.

    Args:
        tool: The tool definition to convert.

    Returns:
        list[AnthropicToolSchema]: List of tools in Anthropic's format.
    """
    _logger.debug("create_anthropic_tool_schema", function_count=len(tool.functions))
    tools: list[AnthropicToolSchema] = []

    for func in tool.functions:
        properties: dict[str, JSONSchemaProperty] = {}
        required: list[str] = []

        for param in func.parameters:
            properties[param.name] = _build_schema_property(
                param_type=param.type,
                description=param.description,
                enum_values=param.enum,
                default=param.default,
                items_type=param.items_type,
                item_properties=param.item_properties,
            )
            if param.required:
                required.append(param.name)

        tool_schema: AnthropicToolSchema = {
            "name": func.name,
            "description": func.description,
            "input_schema": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        }
        tools.append(tool_schema)

    _logger.debug("create_anthropic_tool_schema_complete", tools_created=len(tools))
    return tools


def create_openai_tool_schema(
    tool: ToolDefinition,
) -> list[OpenAIToolSchema]:
    """Convert ToolDefinition to OpenAI's tool format.

    Args:
        tool: The tool definition to convert.

    Returns:
        list[OpenAIToolSchema]: List of tools in OpenAI's format.
    """
    _logger.debug("create_openai_tool_schema", function_count=len(tool.functions))
    tools: list[OpenAIToolSchema] = []

    for func in tool.functions:
        properties: dict[str, JSONSchemaProperty] = {}
        required: list[str] = []

        for param in func.parameters:
            properties[param.name] = _build_schema_property(
                param_type=param.type,
                description=param.description,
                enum_values=param.enum,
                default=param.default,
                items_type=param.items_type,
                item_properties=param.item_properties,
            )
            if param.required:
                required.append(param.name)

        tool_schema: OpenAIToolSchema = {
            "type": "function",
            "function": {
                "name": func.name,
                "description": func.description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            },
        }
        tools.append(tool_schema)

    _logger.debug("create_openai_tool_schema_complete", tools_created=len(tools))
    return tools


def create_google_tool_schema(
    tool: ToolDefinition,
) -> list[GoogleFunctionDeclaration]:
    """Convert ToolDefinition to Google Gemini's function declaration format.

    Args:
        tool: The tool definition to convert.

    Returns:
        list[GoogleFunctionDeclaration]: List of function declarations in Google's format with uppercase types.
    """
    _logger.debug("create_google_tool_schema", function_count=len(tool.functions))
    tools: list[GoogleFunctionDeclaration] = []

    for func in tool.functions:
        properties: dict[str, JSONSchemaProperty] = {}
        required: list[str] = []

        for param in func.parameters:
            properties[param.name] = _build_schema_property(
                param_type=param.type.upper(),
                description=param.description,
                enum_values=param.enum,
                default=param.default,
                items_type=param.items_type,
                item_properties=param.item_properties,
            )
            if param.required:
                required.append(param.name)

        tool_schema: GoogleFunctionDeclaration = {
            "name": func.name,
            "description": func.description,
            "parameters": {
                "type": "OBJECT",
                "properties": properties,
                "required": required,
            },
        }
        tools.append(tool_schema)

    _logger.debug("create_google_tool_schema_complete", tools_created=len(tools))
    return tools


LLMProvider = LLMProviderBase
