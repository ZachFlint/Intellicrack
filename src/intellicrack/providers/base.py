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
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
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
    ReasoningItem,
    ThinkingConfig,
    ToolCall,
    ToolChoice,
    ToolChoiceMode,
    ToolDefinition,
)
from intellicrack.providers.capabilities import (
    ApiDialect,
    CapabilityOverride,
    ModelCapabilities,
    ToolSearchStyle,
    merge_capabilities,
)
from intellicrack.providers.dialects import adapter_for
from intellicrack.providers.dialects.base import (
    DialectAdapter,
    StreamDelta,
    ToolCallFragment,
    UsageInfo,
    parse_tool_call,
    serialize_tool_result,
)
from intellicrack.providers.presets import preset_capabilities
from intellicrack.providers.tool_names import to_wire_name


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable, Generator

    import structlog
    from openai.types.chat.chat_completion_message import ChatCompletionMessage

_T = TypeVar("_T")

_logger = get_logger(__name__)
_secure_rng = random.SystemRandom()

REDACTION_MARKER: Final[str] = "[REDACTED]"
MAX_ERROR_BODY_CHARS: Final[int] = 500

_SECRET_SUBSTITUTIONS: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    (
        re.compile(
            r'(?i)("?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|x-api-key|secret)"?\s*[:=]\s*"?)'
            r'([^"\s,}\]]{4,})',
        ),
        rf"\1{REDACTION_MARKER}",
    ),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"), f"Bearer {REDACTION_MARKER}"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"), REDACTION_MARKER),
    (re.compile(r"\bhf_[A-Za-z0-9]{8,}"), REDACTION_MARKER),
    (re.compile(r"\bxai-[A-Za-z0-9]{8,}"), REDACTION_MARKER),
    (re.compile(r"\bAIza[A-Za-z0-9_-]{10,}"), REDACTION_MARKER),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}"), REDACTION_MARKER),
)


def redact_secrets(text: str) -> str:
    """Blank out credential-shaped tokens in provider-supplied text.

    A provider's error body routinely echoes back what was sent: an
    ``Authorization`` header, an ``api_key`` field, or a key embedded in a
    URL. That text is about to reach a log file and a user-visible message,
    so every recognised credential shape is replaced before it travels. Both
    key/value fields and bare key prefixes are covered, because an echoed key
    can arrive either way.

    Args:
        text: Raw text from a provider response, header, or exception.

    Returns:
        str: The text with every recognised credential shape replaced by
        :data:`REDACTION_MARKER`.
    """
    redacted = text
    for pattern, replacement in _SECRET_SUBSTITUTIONS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


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

_MODEL_SUFFIX_SEPARATORS: Final[tuple[str, ...]] = (":", "@")
"""Separators that introduce a variant suffix on an otherwise known model id.

An endpoint routinely advertises ``my-model:free`` or ``my-model@2026-01`` for
what is capability-wise the same model. Stripping the suffix is what lets the
base record resolve instead of the request being refused for want of a context
window.
"""


@dataclass(frozen=True, slots=True)
class SentToolReport:
    """What actually happened to the tool set on the last request.

    The wire layer is handed a final, priority-ordered tool list and never
    reorders it, but it does decide what ships in reach, what ships deferred
    and what does not fit at all. Without a report of that decision the caller
    cannot tell a model that chose not to call a tool from a tool that never
    reached the model.

    Attributes:
        sent: Canonical dotted names callable at the start of the turn.
        deferred: Canonical dotted names that shipped but are reachable only
            through the endpoint's tool search.
        truncated: Canonical dotted names dropped from a tool definition that
            partly fit within the count cap.
        dropped: Canonical dotted names dropped entirely, because the cap was
            already exhausted before their definition was reached.
    """

    sent: tuple[str, ...] = ()
    deferred: tuple[str, ...] = ()
    truncated: tuple[str, ...] = ()
    dropped: tuple[str, ...] = ()

    @property
    def total(self) -> int:
        """Total number of tool functions accounted for.

        Returns:
            int: Sent plus deferred plus truncated plus dropped.
        """
        return len(self.sent) + len(self.deferred) + len(self.truncated) + len(self.dropped)


class LLMProviderBase(ABC):
    """Abstract base class for LLM providers.

    All provider implementations must inherit from this class and implement the abstract methods defined here. This ensures a consistent
    interface for the orchestrator to interact with any LLM provider.

    Attributes:
        TOOL_COUNT_CAP: Maximum number of flattened tool functions this
            provider accepts in a single request, or ``None`` when the
            provider imposes no such limit. Subclasses whose backend
            rejects function-calling requests past a fixed count (OpenAI,
            Grok, OpenRouter) override this; :meth:`_enforce_tool_count_cap`
            reads it to trim the active tool set before conversion.
    """

    TOOL_COUNT_CAP: int | None = None

    def __init__(self) -> None:
        """Initialize the LLMProviderBase instance."""
        self._credentials: ProviderCredentials | None = None
        self.connected: bool = False
        self._cancel_requested: bool = False
        self._pending_tool_calls: list[ToolCall] = []
        self._pending_usage: UsageInfo | None = None
        self._pending_thinking: list[str] = []
        self._pending_reasoning: list[ReasoningItem] = []
        self._model_capabilities: dict[str, ModelCapabilities] = {}
        self._capability_overrides: dict[str, CapabilityOverride] = {}
        self._last_sent_tools: SentToolReport = SentToolReport()
        self._logger = get_logger(__name__)
        self._logger.info("provider_base_initialized")

    @property
    @abstractmethod
    def name(self) -> str:
        """The provider instance id.

        Returns:
            str: The instance id this provider is registered under.
        """

    @property
    def is_connected(self) -> bool:
        """Check if the provider is connected and authenticated.

        Returns:
            bool: True if the provider is ready to accept requests.
        """
        return self.connected

    @property
    def dialect(self) -> ApiDialect | None:
        """The wire format this provider speaks.

        Returns:
            ApiDialect | None: The dialect, or ``None`` for a provider that is
            not an HTTP endpoint at all. ``local_transformers`` runs the model
            in-process and has no wire format, so every caller that maps a
            provider to a dialect must tolerate ``None``.
        """
        return None

    def adapter(self) -> DialectAdapter | None:
        """Construct the adapter for this provider's dialect.

        Returns:
            DialectAdapter | None: A fresh adapter, or ``None`` when the
            provider has no dialect.
        """
        dialect = self.dialect
        return None if dialect is None else adapter_for(dialect)

    def ingest_model_capabilities(self, model: str, capabilities: ModelCapabilities) -> None:
        """Record capabilities discovered from the endpoint's own metadata.

        This is layer two of the three-layer merge. Providers call it while
        parsing ``/models`` so a later request resolves against what the
        endpoint actually advertised rather than against a dialect default.

        Args:
            model: The model id the metadata describes.
            capabilities: The record built from the endpoint's metadata.
        """
        self._model_capabilities[model] = capabilities

    def set_capability_override(self, model: str, override: CapabilityOverride | None) -> None:
        """Record or clear the user's per-model capability override.

        This is layer three of the three-layer merge and always wins, because
        it is the only layer that can correct an endpoint whose metadata is
        wrong or absent.

        Args:
            model: The model id the override applies to.
            override: The override, or ``None`` to clear it.
        """
        if override is None or override.is_empty():
            self._capability_overrides.pop(model, None)
            return
        self._capability_overrides[model] = override

    def capability_overrides(self) -> dict[str, CapabilityOverride]:
        """Return every per-model override currently configured.

        Returns:
            dict[str, CapabilityOverride]: Overrides keyed by model id.
        """
        return dict(self._capability_overrides)

    @property
    def preset_id(self) -> str:
        """The preset this provider's capability defaults come from.

        Returns:
            str: The preset id, which for a built-in provider equals its
            instance id. A user-defined instance reports the preset it was
            created from instead.
        """
        return self.name

    def capabilities_for(self, model: str) -> ModelCapabilities:
        """Resolve one model's capability record through the layered merge.

        Resolution order is the dialect's defaults, then the preset's known
        capabilities for that model family, then metadata ingested from the
        endpoint's own ``/models`` payload, then the per-model user override,
        which always wins. A model id that matches nothing exactly is retried
        with its variant suffix stripped, so ``my-model:free`` resolves
        against ``my-model`` rather than falling back to the dialect default.

        Args:
            model: The model id to resolve.

        Returns:
            ModelCapabilities: The merged record.
        """
        adapter = self.adapter()
        base = adapter.default_capabilities() if adapter is not None else ModelCapabilities()
        base = merge_capabilities(base, preset_capabilities(self.preset_id, model))
        ingested = self._lookup_model_entry(self._model_capabilities, model)
        if ingested is not None:
            base = ingested
        override = self._lookup_model_entry(self._capability_overrides, model)
        return merge_capabilities(base, override)

    @staticmethod
    def _lookup_model_entry[EntryT](table: dict[str, EntryT], model: str) -> EntryT | None:
        """Look a model id up, retrying without its variant suffix.

        Args:
            table: The per-model table to search.
            model: The model id to resolve.

        Returns:
            EntryT | None: The matching entry, or ``None``.
        """
        exact = table.get(model)
        if exact is not None:
            return exact
        for separator in _MODEL_SUFFIX_SEPARATORS:
            stem, found, _ = model.partition(separator)
            if found:
                trimmed = table.get(stem)
                if trimmed is not None:
                    return trimmed
        return None

    def get_last_sent_tools(self) -> SentToolReport:
        """Report what happened to the tool set on the last request.

        Mirrors :meth:`get_pending_tool_calls` and :meth:`get_pending_usage`:
        the record is produced by the request path and read once by the
        caller. Unlike those, it is not cleared on read, because it describes
        the request rather than buffering an event -- reading it twice must
        give the same answer.

        Returns:
            SentToolReport: What was sent, deferred, truncated and dropped.
        """
        return self._last_sent_tools

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
        self._pending_reasoning.clear()
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

    def get_pending_reasoning(self) -> list[ReasoningItem]:
        """Retrieve the reasoning blocks captured during the last request.

        Mirrors :meth:`get_pending_thinking`, but returns the full blocks
        rather than their display text, so the provider-opaque payloads that
        must be echoed back verbatim -- an Anthropic signature, an OpenAI
        Responses item id and encrypted content -- survive into the assistant
        message the caller builds. The buffer is cleared on each call so the
        same block is never returned twice.

        Returns:
            list[ReasoningItem]: Reasoning blocks accumulated during the last
            request. Empty when reasoning was not enabled or not emitted.
        """
        reasoning = list(self._pending_reasoning)
        self._pending_reasoning.clear()
        return reasoning

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

    def _effective_tool_budget(self, capabilities: ModelCapabilities | None) -> int | None:
        """Resolve how many tool functions may be callable at the start of a turn.

        Without native tool search this is the whole budget: every function
        ships in reach, so the endpoint's flat cap applies to all of them.
        With Anthropic deferred loading the budget is the deferral ceiling,
        because all ~715 functions ship and only the non-deferred head is in
        reach. With OpenAI namespaces the cap applies only to the functions
        callable at turn start, which is the first namespace.

        Args:
            capabilities: The resolved capability record for the target model,
                or ``None`` when the caller has not resolved one.

        Returns:
            int | None: The budget, or ``None`` when the endpoint imposes no
            limit.
        """
        if capabilities is None:
            return self.TOOL_COUNT_CAP
        style = capabilities.tool_search.style
        if style is ToolSearchStyle.ANTHROPIC_DEFERRED:
            return capabilities.tool_search.max_deferred_tools + 1
        if style is ToolSearchStyle.OPENAI_TOOL_SEARCH:
            return None
        declared = capabilities.tool_count_cap
        return declared if declared is not None else self.TOOL_COUNT_CAP

    def _enforce_tool_count_cap(
        self,
        tools: list[ToolDefinition],
        capabilities: ModelCapabilities | None = None,
    ) -> list[ToolDefinition]:
        """Trim tool definitions to fit this model's callable-function budget.

        Several endpoints reject function-calling requests once the flattened
        function count (every ``ToolFunction`` across every
        :class:`ToolDefinition`) exceeds their cap. Intellicrack's registry
        exposes hundreds more functions than that, so the active set handed to
        a capped endpoint must be reduced before the request leaves the
        process. An endpoint with native tool search has no such problem: the
        whole set ships and deferral keeps it out of reach until searched.

        Tools are kept in their existing (already deterministic) order and
        included whole wherever possible. The tool whose inclusion would push
        the running total past the budget is truncated to the leading
        functions that still fit, so every tool earlier in the list stays
        fully intact and no tool is dropped arbitrarily. Callers that place
        the dynamic-loading meta-tool and always-on core tools first guarantee
        this truncation can never drop them.

        The outcome is recorded for :meth:`get_last_sent_tools` so a caller can
        tell a tool the model declined to call from one it never saw.

        Args:
            tools: Tool definitions to trim, in priority order.
            capabilities: The resolved capability record for the target model.
                When ``None``, the provider's own :attr:`TOOL_COUNT_CAP`
                applies, preserving the pre-capability behaviour.

        Returns:
            list[ToolDefinition]: A new list of tool definitions whose combined
            function count does not exceed the budget. Returned unchanged
            (same object) when uncapped or already within it.

        Raises:
            ProviderError: If the budget is too small to hold even a single
                tool function.
        """
        cap = self._effective_tool_budget(capabilities)
        all_names = [func.name for tool in tools for func in tool.functions]
        deferred_style = capabilities.tool_search.style if capabilities is not None else ToolSearchStyle.NONE

        if cap is None:
            self._last_sent_tools = self._report_for_uncapped(tools, deferred_style)
            return tools

        function_count = len(all_names)
        self._logger.debug(
            "tool_conversion_function_count",
            provider=self.name,
            container_count=len(tools),
            function_count=function_count,
            cap=cap,
        )
        if function_count <= cap:
            self._last_sent_tools = self._report_for_uncapped(tools, deferred_style)
            return tools

        if cap < 1:
            message = f"{self.name} tool-count cap ({cap}) cannot hold any tool function; {function_count} functions were requested."
            self._logger.error(
                "tool_count_cap_unsatisfiable",
                provider=self.name,
                cap=cap,
                function_count=function_count,
            )
            raise ProviderError(message)

        trimmed: list[ToolDefinition] = []
        dropped: list[str] = []
        truncated: list[str] = []
        dropped_labels: list[str] = []
        remaining = cap
        for tool in tools:
            tool_function_count = len(tool.functions)
            if tool_function_count <= remaining:
                trimmed.append(tool)
                remaining -= tool_function_count
                continue
            if remaining > 0:
                trimmed.append(
                    ToolDefinition(
                        tool_name=tool.tool_name,
                        description=tool.description,
                        functions=tool.functions[:remaining],
                    ),
                )
                truncated.extend(func.name for func in tool.functions[remaining:])
                dropped_labels.append(f"{tool.tool_name}:{tool_function_count - remaining}_truncated")
                remaining = 0
            else:
                dropped.extend(func.name for func in tool.functions)
                dropped_labels.append(f"{tool.tool_name}:{tool_function_count}_dropped")

        self._logger.warning(
            "tool_count_cap_exceeded",
            provider=self.name,
            cap=cap,
            function_count=function_count,
            kept_count=cap,
            dropped_tools=dropped_labels,
        )
        kept = [func.name for tool in trimmed for func in tool.functions]
        self._last_sent_tools = SentToolReport(
            sent=tuple(kept),
            truncated=tuple(truncated),
            dropped=tuple(dropped),
        )
        return trimmed

    @staticmethod
    def _report_for_uncapped(tools: list[ToolDefinition], style: ToolSearchStyle) -> SentToolReport:
        """Build the sent-tool report for a request that trimmed nothing.

        With native tool search only part of the set is callable at the start
        of the turn, so the report splits the set the same way the adapter
        does rather than claiming everything was in reach.

        Args:
            tools: The tool definitions that shipped, in priority order.
            style: The endpoint's native large-toolset mechanism.

        Returns:
            SentToolReport: What was sent and what shipped deferred.
        """
        if style is ToolSearchStyle.NONE:
            return SentToolReport(sent=tuple(func.name for tool in tools for func in tool.functions))
        if style is ToolSearchStyle.ANTHROPIC_DEFERRED:
            names = [func.name for tool in tools for func in tool.functions]
            return SentToolReport(sent=tuple(names[:1]), deferred=tuple(names[1:]))
        head = tools[0] if tools else None
        sent = tuple(func.name for func in head.functions) if head is not None else ()
        deferred = tuple(func.name for tool in tools[1:] for func in tool.functions)
        return SentToolReport(sent=sent, deferred=deferred)

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
            "function": {"name": to_wire_name(function_name)},
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
                                "name": to_wire_name(tc.function_name),
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
    def _http_error_detail(exc: Exception, body: str) -> str:
        """Combine an HTTP exception with its response body for display.

        ``httpx`` builds ``HTTPStatusError``'s message from the status line and
        URL only, so on its own it tells the user nothing about *why* the call
        was rejected. The provider's own message lives in the response body,
        which is redacted and truncated here before it is allowed anywhere near
        a log or a dialog.

        Args:
            exc: The originating HTTP exception.
            body: Raw response body text, or an empty string when unavailable.

        Returns:
            str: ``str(exc)`` alone when the body is empty, otherwise the
            exception text followed by the redacted, truncated body.
        """
        stripped = body.strip()
        if not stripped:
            return str(exc)
        redacted = redact_secrets(stripped)[:MAX_ERROR_BODY_CHARS]
        return f"{exc}: {redacted}"

    @staticmethod
    def _raise_typed_for_status(
        status_code: int,
        exc: Exception,
        *,
        messages: HttpErrorMessages,
        extract_503_message: Callable[[Exception], str] | None = None,
        detail: str | None = None,
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
                interpolated into the matching message template when
                ``detail`` is not supplied.
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
            detail: Pre-built, already redacted failure text to
                interpolate instead of ``str(exc)``. Callers that can
                reach the response body pass it here (see
                :meth:`_http_error_detail`), because the transport
                exception's own text carries only the status line and
                URL, never the provider's explanation.

        Raises:
            AuthenticationError: When ``status_code`` is 401 or 403.
            ProviderError: When ``status_code`` is 503 and
                ``extract_503_message`` is supplied.
            RateLimitError: When ``status_code`` is 429.
        """
        described = detail if detail is not None else str(exc)
        if status_code in _AUTH_STATUS_CODES:
            raise AuthenticationError(messages.auth_invalid % described) from exc
        if status_code == HTTP_RATE_LIMITED:
            raise RateLimitError(messages.rate_limited % described) from exc
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
    """Accumulates streaming tool-call fragments into complete ToolCall objects.

    Every dialect fragments a streamed tool call differently -- Chat
    Completions by array index, Responses by the output item's id, Messages by
    content-block index, Gemini not at all -- so fragments are keyed by an
    opaque correlation token the adapter chooses rather than by any one
    dialect's shape. Insertion order is preserved, so finalized calls come out
    in the order the endpoint started them.
    """

    def __init__(self) -> None:
        """Initialize the ToolCallBufferManager instance."""
        self._buffers: dict[str, dict[str, str]] = {}

    def accumulate(
        self,
        *,
        index: int | str | None = None,
        token: str | None = None,
        call_id: str | None = None,
        name: str | None = None,
        arguments: str | None = None,
    ) -> None:
        """Merge a single streaming fragment into the buffer.

        Args:
            index: Legacy positional correlation key, kept so existing
                OpenAI-shaped callers continue to work unchanged. Used when
                ``token`` is not supplied.
            token: Opaque per-dialect correlation token. Fragments sharing a
                token belong to the same tool call.
            call_id: Unique identifier for the tool call (first fragment only).
            name: Wire function name (first fragment only).
            arguments: Partial JSON argument fragment to append.
        """
        key = token if token is not None else str(index)
        buf = self._buffers.setdefault(key, {"id": "", "name": "", "arguments": ""})
        if call_id:
            buf["id"] = call_id
        if name:
            buf["name"] = name
        if arguments:
            buf["arguments"] += arguments

    def absorb(self, delta: StreamDelta) -> None:
        """Merge a normalized stream delta's tool-call fragment, if it has one.

        Args:
            delta: A delta produced by a dialect adapter.
        """
        fragment: ToolCallFragment | None = delta.tool_call_fragment
        if fragment is None:
            return
        self.accumulate(
            token=fragment.token,
            call_id=fragment.call_id,
            name=fragment.name,
            arguments=fragment.arguments,
        )

    def finalize(self) -> list[ToolCall]:
        """Convert all complete buffered entries to ToolCall objects and reset.

        Entries missing an ``id`` or ``name`` are silently discarded.

        Returns:
            list[ToolCall]: List of parsed ToolCall instances, in the order the
            endpoint started them.
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


def create_anthropic_tool_schema(
    tool: ToolDefinition,
) -> list[AnthropicToolSchema]:
    """Convert ToolDefinition to Anthropic's tool format.

    Delegates to :class:`~intellicrack.providers.dialects.messages.MessagesAdapter`,
    the single owner of the Messages wire format, so this entry point and the
    provider path can no longer disagree about a tool's advertised name.

    Args:
        tool: The tool definition to convert.

    Returns:
        list[AnthropicToolSchema]: List of tools in Anthropic's format.
    """
    adapter = adapter_for(ApiDialect.MESSAGES)
    schemas = adapter.build_tool_schemas([tool], adapter.default_capabilities())
    _logger.debug("create_anthropic_tool_schema_complete", tools_created=len(schemas))
    return [cast("AnthropicToolSchema", schema) for schema in schemas]


def create_openai_tool_schema(
    tool: ToolDefinition,
) -> list[OpenAIToolSchema]:
    """Convert ToolDefinition to OpenAI's tool format.

    Delegates to
    :class:`~intellicrack.providers.dialects.chat_completions.ChatCompletionsAdapter`.

    Args:
        tool: The tool definition to convert.

    Returns:
        list[OpenAIToolSchema]: List of tools in OpenAI's format.
    """
    adapter = adapter_for(ApiDialect.CHAT_COMPLETIONS)
    schemas = adapter.build_tool_schemas([tool], adapter.default_capabilities())
    _logger.debug("create_openai_tool_schema_complete", tools_created=len(schemas))
    return [cast("OpenAIToolSchema", schema) for schema in schemas]


def create_google_tool_schema(
    tool: ToolDefinition,
) -> list[GoogleFunctionDeclaration]:
    """Convert ToolDefinition to Google Gemini's function declaration format.

    Delegates to :class:`~intellicrack.providers.dialects.gemini.GeminiAdapter`,
    which returns a single ``functionDeclarations`` tool; the declarations are
    unwrapped here so callers keep receiving one entry per function.

    Args:
        tool: The tool definition to convert.

    Returns:
        list[GoogleFunctionDeclaration]: List of function declarations in Google's format with uppercase types.
    """
    adapter = adapter_for(ApiDialect.GEMINI)
    declarations: list[GoogleFunctionDeclaration] = []
    for entry in adapter.build_tool_schemas([tool], adapter.default_capabilities()):
        raw_declarations = entry.get("functionDeclarations")
        if isinstance(raw_declarations, list):
            members: list[Any] = raw_declarations
            declarations.extend(cast("GoogleFunctionDeclaration", member) for member in members)
    _logger.debug("create_google_tool_schema_complete", tools_created=len(declarations))
    return declarations


LLMProvider = LLMProviderBase


__all__ = [
    "MAX_ERROR_BODY_CHARS",
    "REASONING_EFFORT_HIGH_THRESHOLD",
    "REASONING_EFFORT_LOW_THRESHOLD",
    "REASONING_EFFORT_MEDIUM_THRESHOLD",
    "REDACTION_MARKER",
    "AnthropicToolSchema",
    "GoogleFunctionDeclaration",
    "HttpErrorMessages",
    "JSONSchemaParameters",
    "JSONSchemaProperty",
    "LLMProvider",
    "LLMProviderBase",
    "OpenAIErrorMessages",
    "OpenAIFunctionSchema",
    "OpenAIToolSchema",
    "SentToolReport",
    "ToolCallBufferManager",
    "UsageInfo",
    "create_anthropic_tool_schema",
    "create_google_tool_schema",
    "create_openai_tool_schema",
    "is_permanent_quota_error",
    "map_thinking_budget_to_effort",
    "parse_tool_call",
    "redact_secrets",
    "serialize_tool_result",
]
