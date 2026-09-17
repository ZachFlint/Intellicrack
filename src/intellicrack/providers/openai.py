# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""OpenAI API provider implementation.

This module provides integration with OpenAI's GPT models for chat completion and tool/function calling.
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, TypedDict, cast, override

import httpx
import openai
from openai import AsyncStream

from intellicrack.core.logging import get_logger, log_provider_request, log_provider_response
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
    ToolDefinition,
)
from intellicrack.providers import ids as provider_ids
from intellicrack.providers.base import (
    LLMProviderBase,
    OpenAIErrorMessages,
    ToolCallBufferManager,
    is_permanent_quota_error,
    map_thinking_budget_to_effort,
)
from intellicrack.providers.capabilities import ApiDialect, TokenLimitField
from intellicrack.providers.dialects.base import DialectRequest
from intellicrack.providers.dialects.chat_completions import ChatCompletionsAdapter
from intellicrack.providers.dialects.responses import ResponsesAdapter


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from openai.types.chat import (
        ChatCompletionChunk,
        ChatCompletionMessageParam,
        ChatCompletionStreamOptionsParam,
        ChatCompletionToolChoiceOptionParam,
        ChatCompletionToolParam,
    )
    from openai.types.chat.chat_completion import ChatCompletion
    from openai.types.responses import ResponseStreamEvent
    from openai.types.shared import ReasoningEffort


_ERR_NOT_CONNECTED = "Not connected to OpenAI API"
_ERR_KEY_REQUIRED = "OpenAI API key is required"
_ERR_INVALID_KEY = "Invalid OpenAI API key: %s"
_ERR_CONNECT_FAILED = "Failed to connect to OpenAI: %s"
_ERR_LIST_MODELS_FAILED = "Failed to list OpenAI models: %s"
_ERR_RATE_LIMITED = "OpenAI rate limit exceeded: %s"
_ERR_API_ERROR = "OpenAI API error: %s"
_ERR_REQUEST_FAILED = "OpenAI request failed: %s"
_ERR_STREAM_FAILED = "OpenAI stream failed: %s"

_OPENAI_CHAT_ERRORS = OpenAIErrorMessages(
    auth_invalid=_ERR_INVALID_KEY,
    rate_limited=_ERR_RATE_LIMITED,
    api_error=_ERR_API_ERROR,
    request_failed=_ERR_REQUEST_FAILED,
)

_FIXED_REASONING_TEMPERATURE: float = 1.0
"""The only temperature a model that rejects sampling control will accept."""

_RESPONSES_PATH: str = "/responses"
"""Path of the Responses endpoint, relative to the client's base URL."""


def _event_mapping(event: object) -> dict[str, Any]:
    """Decode one streamed Responses event into a plain mapping.

    The SDK hands back a typed event model; the adapter works on the wire
    shape, so the model is dumped by field alias to recover exactly what the
    endpoint sent.

    Args:
        event: The streamed event object.

    Returns:
        dict[str, Any]: The event's wire form, or an empty mapping when the
        object cannot be dumped.
    """
    dump = getattr(event, "model_dump", None)
    if callable(dump):
        dumped: object = dump(by_alias=True, exclude_none=True)
        if isinstance(dumped, dict):
            return cast("dict[str, Any]", dumped)
    return {}


class OpenAIMessageContent(TypedDict, total=False):
    """OpenAI message content structure."""

    type: str
    text: str


class OpenAIMessage(TypedDict, total=False):
    """OpenAI message structure."""

    role: str
    content: str | list[OpenAIMessageContent] | None
    tool_calls: list[dict[str, object]]
    tool_call_id: str
    name: str


class OpenAIProvider(LLMProviderBase):
    """OpenAI GPT API provider implementation.

    Provides integration with OpenAI's GPT models including support for tool/function calling and streaming responses.

    Attributes:
        TOOL_COUNT_CAP: Maximum number of flattened tool functions OpenAI
            accepts in a single function-calling request. OpenAI enforces
            this as a hard limit, rejecting requests that exceed it.
    """

    TOOL_COUNT_CAP: int | None = 128

    def __init__(self) -> None:
        """Initialize the OpenAIProvider instance."""
        super().__init__()
        self.client: openai.AsyncOpenAI | None = None
        self._chat_adapter = ChatCompletionsAdapter()
        self._responses_adapter = ResponsesAdapter()
        self._current_task: asyncio.Task[object] | None = None
        self._logger = get_logger(__name__).bind(provider="openai")
        self._logger.info("openai_provider_initialized")

    @property
    def name(self) -> str:
        """The provider instance id.

        Returns:
            str: The ``openai`` built-in provider id.
        """
        return provider_ids.OPENAI

    @property
    @override
    def dialect(self) -> ApiDialect:
        """The wire format this instance speaks by default.

        Returns:
            ApiDialect: :data:`ApiDialect.CHAT_COMPLETIONS`. A model whose
            capability record names :data:`ApiDialect.RESPONSES` is routed
            there instead, per model rather than per instance.
        """
        return ApiDialect.CHAT_COMPLETIONS

    def _dialect_for(self, model: str) -> ApiDialect:
        """Resolve which wire format one model is reached over.

        Args:
            model: The model id being addressed.

        Returns:
            ApiDialect: The model's own dialect when its capability record
            states one, otherwise this instance's default.
        """
        return self.capabilities_for(model).dialect or self.dialect

    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect to OpenAI API.

        Args:
            credentials: Must contain api_key. ``api_base``, ``organization_id``
                and ``project_id`` are forwarded to the SDK client, and
                ``timeout`` replaces the SDK's default request timeout when set.

        Raises:
            AuthenticationError: If API key is invalid.
            ProviderError: If connection fails.
        """
        if not credentials.api_key:
            raise AuthenticationError(_ERR_KEY_REQUIRED)

        try:
            self.client = openai.AsyncOpenAI(
                api_key=credentials.api_key,
                base_url=credentials.api_base,
                organization=credentials.organization_id,
                project=credentials.project_id,
                timeout=credentials.timeout if credentials.timeout is not None else openai.NOT_GIVEN,
            )
            await self.client.models.list()
        except openai.AuthenticationError as e:
            self.connected = False
            self.client = None
            self._logger.warning(
                "openai_connect_auth_failed",
                error=str(e),
            )
            raise AuthenticationError(_ERR_INVALID_KEY % e) from e
        except (ConnectionError, TimeoutError, OSError, openai.APIError) as e:
            self.connected = False
            self.client = None
            self._logger.warning(
                "openai_connect_failed",
                error=str(e),
            )
            raise ProviderError(_ERR_CONNECT_FAILED % e) from e
        else:
            self._credentials = credentials
            self.connected = True
            self._logger.info(
                "openai_connected",
                has_custom_base=credentials.api_base is not None,
                has_organization=credentials.organization_id is not None,
                has_project=credentials.project_id is not None,
            )

    async def disconnect(self) -> None:
        """Disconnect from OpenAI API."""
        try:
            await super().disconnect()
            self.client = None
            self._current_task = None
            self._logger.info("openai_disconnected", success=True)
        except (ConnectionError, TimeoutError, OSError, RuntimeError) as exc:
            self._logger.warning("disconnect_cleanup_error", error=str(exc))
            self.connected = False

    @staticmethod
    def _is_chat_model(model_id: str) -> bool:
        """Determine if a model ID corresponds to a chat-capable model.

        Args:
            model_id: OpenAI model identifier.

        Returns:
            bool: True if the model supports chat completions.
        """
        non_chat_prefixes = (
            "text-embedding-",
            "dall-e-",
            "whisper-",
            "tts-",
            "text-moderation-",
            "omni-moderation-",
            "davinci-",
            "babbage-",
            "canary-",
            "codex-",
            "text-davinci-",
            "text-babbage-",
            "text-curie-",
            "text-ada-",
            "code-davinci-",
            "code-cushman-",
            "sora-",
            "gpt-image-",
        )
        return not model_id.startswith(non_chat_prefixes)

    async def list_models(self) -> list[ModelInfo]:
        """Dynamically fetch available models from OpenAI.

        Returns:
            list[ModelInfo]: List of available GPT models.

        Raises:
            ProviderError: If not connected.
        """
        if not self.connected or self.client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        try:
            sorted_models = await self._fetch_and_sort_models()
        except (ConnectionError, TimeoutError, OSError, openai.APIError) as e:
            self._logger.warning(
                "openai_list_models_failed",
                error=str(e),
            )
            raise ProviderError(_ERR_LIST_MODELS_FAILED % e) from e
        else:
            return sorted_models

    async def _fetch_and_sort_models(self) -> list[ModelInfo]:
        """Fetch chat-capable models from the OpenAI API and sort them.

        Returns:
            list[ModelInfo]: Available chat models sorted by identifier in
            reverse order.

        Raises:
            ProviderError: If the OpenAI client has not been initialised.
        """
        if self.client is None:
            self._logger.error(
                "openai_fetch_models_client_not_initialised",
                provider="openai",
            )
            raise ProviderError(_ERR_NOT_CONNECTED)
        response = await self.client.models.list()
        models: list[ModelInfo] = []

        for model_data in response.data:
            model_id = model_data.id
            if not self._is_chat_model(model_id):
                continue
            capabilities = self.capabilities_for(model_id)
            models.append(
                ModelInfo(
                    id=model_id,
                    name=model_id,
                    provider=provider_ids.OPENAI,
                    context_window=capabilities.context_window or 0,
                    supports_tools=capabilities.supports_tools,
                    supports_vision=capabilities.supports_vision,
                    supports_streaming=capabilities.supports_streaming,
                    input_cost_per_1m_tokens=capabilities.input_cost_per_1m_tokens,
                    output_cost_per_1m_tokens=capabilities.output_cost_per_1m_tokens,
                ),
            )

        sorted_models = sorted(models, key=lambda m: m.id, reverse=True)
        self._logger.info(
            "openai_models_listed",
            count=len(sorted_models),
        )
        return sorted_models

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
        """Send a chat completion request to OpenAI.

        Which API the request goes to is decided per model, from its
        capability record rather than from its id: a model whose record names
        the Responses dialect posts to ``/responses`` with
        ``max_output_tokens``, nested ``reasoning.effort``, no temperature and
        ``store: false`` plus encrypted reasoning content; every other model
        keeps the Chat Completions path unchanged.

        OpenAI's prompt caching is automatic on the server side for prompts
        greater than 1024 tokens, so ``enable_cache`` is logged for symmetry
        but no client-side opt-in is required. When ``thinking`` is enabled
        and the model reasons, ``thinking.budget_tokens`` is mapped to the
        effort knob the model's dialect exposes.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration. Honoured whenever the
                model's capability record says it reasons.
            enable_cache: Whether to enable prompt caching.  OpenAI
                auto-caches prompts > 1024 tokens with no client-side
                opt-in; the parameter is logged for symmetry.

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of (assistant message, tool calls if any).

        Raises:
            ProviderError: If not connected or request fails.
        """
        self._reject_empty_messages(messages)
        if not self.connected or self.client is None:
            self._logger.error("openai_chat_not_connected", model=model)
            raise ProviderError(_ERR_NOT_CONNECTED)

        self._cancel_requested = False
        self._pending_usage = None
        self._pending_reasoning.clear()

        if self._dialect_for(model) is ApiDialect.RESPONSES:
            log_provider_request(
                provider="openai",
                model=model,
                messages_count=len(messages),
                tools_count=len(tools) if tools else 0,
            )
            return await self._responses_chat(
                messages=messages,
                model=model,
                tools=tools,
                temperature=temperature,
                max_tokens=max_tokens,
                tool_choice=tool_choice,
                thinking=thinking,
                enable_cache=enable_cache,
            )

        openai_messages = self.convert_messages_to_provider_format(messages)
        openai_tools = self.convert_tools_to_provider_format(tools) if tools else None

        tool_choice_param: ChatCompletionToolChoiceOptionParam | None = None
        if tool_choice is not None and openai_tools:
            tool_choice_param = cast(
                "ChatCompletionToolChoiceOptionParam",
                self._convert_tool_choice_to_openai_format(tool_choice),
            )
        reasoning_effort = self._reasoning_effort_for(model=model, thinking=thinking)
        if enable_cache:
            self._logger.debug("openai_cache_auto", model=model)

        log_provider_request(
            provider="openai",
            model=model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
        )

        typed_messages = cast("list[ChatCompletionMessageParam]", openai_messages)
        typed_tools = cast("list[ChatCompletionToolParam]", openai_tools) if openai_tools else None
        start_time = time.perf_counter()
        api_task: asyncio.Task[ChatCompletion] = asyncio.create_task(
            self._retry_with_backoff(
                lambda: self._make_openai_api_call(
                    model=model,
                    messages=typed_messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    tools=typed_tools,
                    tool_choice=tool_choice_param,
                    reasoning_effort=reasoning_effort,
                ),
            ),
        )
        self._current_task = cast("asyncio.Task[object]", api_task)
        try:
            response = await api_task
        finally:
            self._current_task = None
        duration_ms = (time.perf_counter() - start_time) * 1000

        response_message = response.choices[0].message
        content = response_message.content if response_message.content is not None else ""
        tool_calls = self._parse_openai_format_tool_calls(response_message)
        self._pending_usage = self._build_usage_from_openai_completion(response)

        return self._build_chat_response(
            provider="openai",
            model=model,
            content=content,
            tool_calls=tool_calls,
            duration_ms=duration_ms,
        )

    def _reasoning_effort_for(
        self,
        *,
        model: str,
        thinking: ThinkingConfig | None,
    ) -> ReasoningEffort | None:
        """Resolve the Chat Completions ``reasoning_effort`` value for a request.

        Whether a model has the knob at all is a capability, not something to
        be inferred from its id: an endpoint can serve a reasoning model under
        any name, and a name that looks like a reasoning model can be anything.

        Args:
            model: OpenAI model identifier.
            thinking: Caller-supplied thinking configuration, or ``None``.

        Returns:
            ReasoningEffort | None: The effort to send, or ``None`` when the
            parameter must be omitted.
        """
        if thinking is None or not thinking.enabled:
            return None
        capabilities = self.capabilities_for(model)
        if not capabilities.reasoning.supported:
            self._logger.debug("openai_thinking_ignored_non_reasoning_model", model=model)
            return None
        return cast("ReasoningEffort", map_thinking_budget_to_effort(thinking.budget_tokens))

    def _supports_max_completion_tokens(self, model_id: str) -> bool:
        """Determine whether a model requires ``max_completion_tokens``.

        Reasoning models take ``max_completion_tokens`` where the rest take
        ``max_tokens``. The answer comes from the model's capability record,
        so a reasoning model served under an unfamiliar name is still sent the
        field it actually accepts.

        Args:
            model_id: OpenAI model identifier.

        Returns:
            bool: True if the model expects ``max_completion_tokens``.
        """
        return self.capabilities_for(model_id).token_limit_field is TokenLimitField.MAX_COMPLETION_TOKENS

    def _effective_temperature(self, model_id: str, temperature: float) -> float:
        """Resolve the temperature a model will actually accept.

        Args:
            model_id: OpenAI model identifier.
            temperature: The caller's requested temperature.

        Returns:
            float: The requested temperature, or the fixed value a model that
            rejects sampling control requires.
        """
        return temperature if self.capabilities_for(model_id).supports_temperature else _FIXED_REASONING_TEMPERATURE

    async def _open_openai_stream(
        self,
        *,
        model: str,
        messages: list[ChatCompletionMessageParam],
        temperature: float,
        max_tokens: int,
        tools: list[ChatCompletionToolParam] | None,
        tool_choice: ChatCompletionToolChoiceOptionParam | None,
        reasoning_effort: ReasoningEffort | None,
    ) -> AsyncStream[ChatCompletionChunk]:
        """Open an OpenAI streaming chat completion with correct parameter dispatch.

        Picks the right typed overload of
        ``chat.completions.create(stream=True)`` based on whether
        ``tools``, ``tool_choice``, and ``reasoning_effort`` are present,
        and dispatches between ``max_completion_tokens`` (o-series) and
        ``max_tokens`` (all other models) so basedpyright keeps full type
        information for the returned stream and the chunks it yields.
        O-series models also require ``temperature=1.0``.

        Args:
            model: Model identifier.
            messages: Formatted messages for the API.
            temperature: Sampling temperature (overridden to 1.0 when
                targeting an o-series model).
            max_tokens: Maximum response tokens.
            tools: Formatted tools, or ``None``.
            tool_choice: Tool selection mode, or ``None``.
            reasoning_effort: ``reasoning_effort`` value for o-series
                reasoning models, or ``None``.

        Returns:
            AsyncStream[ChatCompletionChunk]: Live SSE stream of
            chat-completion chunks.

        Raises:
            ProviderError: If the SDK client is not yet connected.
        """
        if self.client is None:
            self._logger.warning("open_openai_stream_raise_pending", error_type="ProviderError")
            raise ProviderError(_ERR_NOT_CONNECTED)
        stream_options: ChatCompletionStreamOptionsParam = {"include_usage": True}
        use_max_completion_tokens = self._supports_max_completion_tokens(model)
        effective_temperature = self._effective_temperature(model, temperature)
        if tools is not None and tool_choice is not None:
            if use_max_completion_tokens:
                if reasoning_effort is not None:
                    return await self.client.chat.completions.create(
                        model=model,
                        messages=messages,
                        temperature=effective_temperature,
                        max_completion_tokens=max_tokens,
                        stream=True,
                        stream_options=stream_options,
                        tools=tools,
                        tool_choice=tool_choice,
                        reasoning_effort=reasoning_effort,
                    )
                return await self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=effective_temperature,
                    max_completion_tokens=max_tokens,
                    stream=True,
                    stream_options=stream_options,
                    tools=tools,
                    tool_choice=tool_choice,
                )
            if reasoning_effort is not None:
                return await self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=effective_temperature,
                    max_tokens=max_tokens,
                    stream=True,
                    stream_options=stream_options,
                    tools=tools,
                    tool_choice=tool_choice,
                    reasoning_effort=reasoning_effort,
                )
            return await self.client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=effective_temperature,
                max_tokens=max_tokens,
                stream=True,
                stream_options=stream_options,
                tools=tools,
                tool_choice=tool_choice,
            )
        if tools is not None:
            if use_max_completion_tokens:
                if reasoning_effort is not None:
                    return await self.client.chat.completions.create(
                        model=model,
                        messages=messages,
                        temperature=effective_temperature,
                        max_completion_tokens=max_tokens,
                        stream=True,
                        stream_options=stream_options,
                        tools=tools,
                        reasoning_effort=reasoning_effort,
                    )
                return await self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=effective_temperature,
                    max_completion_tokens=max_tokens,
                    stream=True,
                    stream_options=stream_options,
                    tools=tools,
                )
            if reasoning_effort is not None:
                return await self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=effective_temperature,
                    max_tokens=max_tokens,
                    stream=True,
                    stream_options=stream_options,
                    tools=tools,
                    reasoning_effort=reasoning_effort,
                )
            return await self.client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=effective_temperature,
                max_tokens=max_tokens,
                stream=True,
                stream_options=stream_options,
                tools=tools,
            )
        if use_max_completion_tokens:
            if reasoning_effort is not None:
                return await self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=effective_temperature,
                    max_completion_tokens=max_tokens,
                    stream=True,
                    stream_options=stream_options,
                    reasoning_effort=reasoning_effort,
                )
            return await self.client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=effective_temperature,
                max_completion_tokens=max_tokens,
                stream=True,
                stream_options=stream_options,
            )
        if reasoning_effort is not None:
            return await self.client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=effective_temperature,
                max_tokens=max_tokens,
                stream=True,
                stream_options=stream_options,
                reasoning_effort=reasoning_effort,
            )
        return await self.client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=effective_temperature,
            max_tokens=max_tokens,
            stream=True,
            stream_options=stream_options,
        )

    async def _make_openai_api_call(
        self,
        *,
        model: str,
        messages: list[ChatCompletionMessageParam],
        temperature: float,
        max_tokens: int,
        tools: list[ChatCompletionToolParam] | None,
        tool_choice: ChatCompletionToolChoiceOptionParam | None = None,
        reasoning_effort: ReasoningEffort | None = None,
    ) -> ChatCompletion:
        """Execute the OpenAI API chat completion call with error handling.

        OpenAI SDK exceptions surface inside the call are translated to
        Intellicrack typed errors by
        :meth:`LLMProviderBase._translate_openai_errors`.  O-series models
        require ``max_completion_tokens`` instead of ``max_tokens`` and must
        receive ``temperature=1.0``; this method dispatches both accordingly.

        Args:
            model: Model ID to use.
            messages: Formatted messages for the API.
            temperature: Sampling temperature (overridden to 1.0 when
                targeting an o-series model).
            max_tokens: Maximum tokens in response.
            tools: Formatted tools for the API, or None.
            tool_choice: How the model should select tools.
            reasoning_effort: ``reasoning_effort`` value for o-series
                reasoning models, or ``None`` to omit the parameter.

        Returns:
            ChatCompletion: The chat completion response object.

        Raises:
            ProviderError: If the client is not yet connected.
        """
        if self.client is None:
            self._logger.warning("openai_api_call_not_connected", model=model)
            raise ProviderError(_ERR_NOT_CONNECTED)

        use_max_completion_tokens = self._supports_max_completion_tokens(model)
        effective_temperature = self._effective_temperature(model, temperature)

        self._logger.debug(
            "openai_api_call_starting",
            model=model,
            has_tools=bool(tools),
            reasoning_effort=reasoning_effort,
            use_max_completion_tokens=use_max_completion_tokens,
        )
        with self._translate_openai_errors(
            log_prefix="openai_chat",
            messages=_OPENAI_CHAT_ERRORS,
            log_extra={"model": model},
        ):
            if tools is not None and tool_choice is not None:
                if use_max_completion_tokens:
                    if reasoning_effort is not None:
                        return await self.client.chat.completions.create(
                            model=model,
                            messages=messages,
                            temperature=effective_temperature,
                            max_completion_tokens=max_tokens,
                            tools=tools,
                            tool_choice=tool_choice,
                            reasoning_effort=reasoning_effort,
                        )
                    return await self.client.chat.completions.create(
                        model=model,
                        messages=messages,
                        temperature=effective_temperature,
                        max_completion_tokens=max_tokens,
                        tools=tools,
                        tool_choice=tool_choice,
                    )
                if reasoning_effort is not None:
                    return await self.client.chat.completions.create(
                        model=model,
                        messages=messages,
                        temperature=effective_temperature,
                        max_tokens=max_tokens,
                        tools=tools,
                        tool_choice=tool_choice,
                        reasoning_effort=reasoning_effort,
                    )
                return await self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=effective_temperature,
                    max_tokens=max_tokens,
                    tools=tools,
                    tool_choice=tool_choice,
                )
            if tools is not None:
                if use_max_completion_tokens:
                    if reasoning_effort is not None:
                        return await self.client.chat.completions.create(
                            model=model,
                            messages=messages,
                            temperature=effective_temperature,
                            max_completion_tokens=max_tokens,
                            tools=tools,
                            reasoning_effort=reasoning_effort,
                        )
                    return await self.client.chat.completions.create(
                        model=model,
                        messages=messages,
                        temperature=effective_temperature,
                        max_completion_tokens=max_tokens,
                        tools=tools,
                    )
                if reasoning_effort is not None:
                    return await self.client.chat.completions.create(
                        model=model,
                        messages=messages,
                        temperature=effective_temperature,
                        max_tokens=max_tokens,
                        tools=tools,
                        reasoning_effort=reasoning_effort,
                    )
                return await self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=effective_temperature,
                    max_tokens=max_tokens,
                    tools=tools,
                )
            if use_max_completion_tokens:
                if reasoning_effort is not None:
                    return await self.client.chat.completions.create(
                        model=model,
                        messages=messages,
                        temperature=effective_temperature,
                        max_completion_tokens=max_tokens,
                        reasoning_effort=reasoning_effort,
                    )
                return await self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=effective_temperature,
                    max_completion_tokens=max_tokens,
                )
            if reasoning_effort is not None:
                return await self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=effective_temperature,
                    max_tokens=max_tokens,
                    reasoning_effort=reasoning_effort,
                )
            return await self.client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=effective_temperature,
                max_tokens=max_tokens,
            )

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
        """Stream a chat completion response from OpenAI.

        Which API the stream opens against is decided per model from its
        capability record, exactly as in :meth:`chat`.

        OpenAI's prompt caching is automatic on the server side for prompts
        greater than 1024 tokens. When ``thinking`` is enabled and the model
        reasons, ``thinking.budget_tokens`` is mapped to the effort knob the
        model's dialect exposes.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration. Honoured whenever the
                model's capability record says it reasons.
            enable_cache: Whether to enable prompt caching.  OpenAI
                auto-caches prompts > 1024 tokens with no client-side
                opt-in; the parameter is logged for symmetry.

        Yields:
            str: Text chunks as they arrive.

        Raises:
            AuthenticationError: If the API key is invalid.
            ProviderError: If not connected or request fails.
            RateLimitError: If rate limited by OpenAI.
        """
        self._reject_empty_messages(messages)
        if not self.connected or self.client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        self._cancel_requested = False
        self._pending_usage = None
        self._pending_reasoning.clear()
        if enable_cache:
            self._logger.debug("openai_stream_cache_auto", model=model)

        if self._dialect_for(model) is ApiDialect.RESPONSES:
            body = self._responses_body(
                messages=messages,
                model=model,
                tools=tools,
                temperature=temperature,
                max_tokens=max_tokens,
                tool_choice=tool_choice,
                thinking=thinking,
                enable_cache=enable_cache,
                stream=True,
            )
            async for responses_chunk in self._iter_responses_stream(body):
                yield responses_chunk
            return

        openai_messages = self.convert_messages_to_provider_format(messages)
        openai_tools = self.convert_tools_to_provider_format(tools) if tools else None

        tool_choice_value: ChatCompletionToolChoiceOptionParam | None = None
        if tool_choice is not None and openai_tools:
            tool_choice_value = cast(
                "ChatCompletionToolChoiceOptionParam",
                self._convert_tool_choice_to_openai_format(tool_choice),
            )

        reasoning_effort = self._reasoning_effort_for(model=model, thinking=thinking)

        try:
            async for text_chunk in self._iter_openai_stream(
                model=model,
                openai_messages=openai_messages,
                temperature=temperature,
                max_tokens=max_tokens,
                openai_tools=openai_tools,
                tool_choice_value=tool_choice_value,
                reasoning_effort=reasoning_effort,
            ):
                yield text_chunk
        except openai.AuthenticationError as e:
            self._logger.warning("openai_stream_auth_failed", model=model, error=str(e))
            raise AuthenticationError(_ERR_INVALID_KEY % e) from e
        except openai.RateLimitError as e:
            if is_permanent_quota_error(str(e)):
                self._logger.warning("openai_stream_quota_exhausted", model=model, error=str(e))
                raise ProviderError(_ERR_API_ERROR % e) from e
            self._logger.warning("openai_stream_rate_limited", model=model, error=str(e))
            raise RateLimitError(_ERR_RATE_LIMITED % e) from e
        except openai.APIError as e:
            self._logger.warning("openai_stream_api_error", model=model, error=str(e))
            raise ProviderError(_ERR_API_ERROR % e) from e
        except (ConnectionError, TimeoutError, OSError, ValueError) as e:
            self._logger.warning(
                "openai_stream_failed",
                model=model,
                error=str(e),
                cancel_requested=self._cancel_requested,
            )
            raise ProviderError(_ERR_STREAM_FAILED % e) from e

    async def _iter_openai_stream(
        self,
        *,
        model: str,
        openai_messages: list[dict[str, object]],
        temperature: float,
        max_tokens: int,
        openai_tools: list[dict[str, object]] | None,
        tool_choice_value: ChatCompletionToolChoiceOptionParam | None,
        reasoning_effort: ReasoningEffort | None,
    ) -> AsyncIterator[str]:
        """Open the OpenAI stream and yield content chunks.

        Updates ``self._pending_usage`` and ``self._pending_tool_calls``
        as the stream progresses and on completion.

        Args:
            model: Model ID to use.
            openai_messages: Messages already converted to OpenAI format.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            openai_tools: Tool definitions in OpenAI format, if any.
            tool_choice_value: OpenAI-format tool-choice value, if any.
            reasoning_effort: Resolved reasoning effort, if any.

        Yields:
            str: Text chunks as they arrive.
        """
        typed_messages = cast("list[ChatCompletionMessageParam]", openai_messages)
        stream: AsyncStream[ChatCompletionChunk] = await self._open_openai_stream(
            model=model,
            messages=typed_messages,
            temperature=temperature,
            max_tokens=max_tokens,
            tools=cast("list[ChatCompletionToolParam] | None", openai_tools) if openai_tools else None,
            tool_choice=tool_choice_value,
            reasoning_effort=reasoning_effort,
        )

        tc_buffer = ToolCallBufferManager()

        async for chunk in stream:
            if self._cancel_requested:
                break
            chunk_usage = getattr(chunk, "usage", None)
            if chunk_usage is not None:
                self._pending_usage = self._build_usage_from_openai_chunk(chunk_usage)
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta
            if delta.content:
                yield delta.content
            if delta.tool_calls:
                for tc_delta in delta.tool_calls:
                    tc_buffer.accumulate(
                        index=tc_delta.index,
                        call_id=tc_delta.id,
                        name=tc_delta.function.name if tc_delta.function else None,
                        arguments=tc_delta.function.arguments if tc_delta.function else None,
                    )

        self._pending_tool_calls = tc_buffer.finalize()

    def _responses_body(
        self,
        *,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None,
        temperature: float,
        max_tokens: int,
        tool_choice: ToolChoice | None,
        thinking: ThinkingConfig | None,
        enable_cache: bool,
        stream: bool,
    ) -> dict[str, Any]:
        """Build the Responses request body for one chat call.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature, omitted when the model rejects one.
            max_tokens: Maximum tokens in the response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration.
            enable_cache: Whether to request prompt caching.
            stream: Whether the request streams.

        Returns:
            dict[str, Any]: The JSON body to POST to ``/responses``.
        """
        capabilities = self.capabilities_for(model)
        capped_tools = self._enforce_tool_count_cap(tools, capabilities) if tools else []
        return self._responses_adapter.build_request(
            DialectRequest(
                model=model,
                messages=messages,
                capabilities=capabilities,
                tools=capped_tools,
                temperature=temperature,
                max_tokens=max_tokens,
                tool_choice=tool_choice,
                thinking=thinking,
                enable_cache=enable_cache,
                stream=stream,
            ),
        )

    async def _post_responses(self, body: dict[str, Any]) -> dict[str, Any]:
        """POST a Responses request and return the decoded body.

        Args:
            body: The request body built by the Responses adapter.

        Returns:
            dict[str, Any]: The decoded response body.

        Raises:
            ProviderError: If the client is not connected or the response is
                not a JSON object.
        """
        if self.client is None:
            self._logger.warning("openai_responses_not_connected", model=body.get("model"))
            raise ProviderError(_ERR_NOT_CONNECTED)
        with self._translate_openai_errors(
            log_prefix="openai_responses",
            messages=_OPENAI_CHAT_ERRORS,
            log_extra={"model": str(body.get("model", ""))},
        ):
            raw = await self.client.post(
                _RESPONSES_PATH,
                cast_to=httpx.Response,
                body=body,
            )
        decoded: object = raw.json()
        if not isinstance(decoded, dict):
            self._logger.warning("openai_responses_payload_not_an_object")
            raise ProviderError(_ERR_API_ERROR % "response body was not a JSON object")
        return cast("dict[str, Any]", decoded)

    async def _responses_chat(
        self,
        *,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None,
        temperature: float,
        max_tokens: int,
        tool_choice: ToolChoice | None,
        thinking: ThinkingConfig | None,
        enable_cache: bool,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Run one non-streaming chat turn over the Responses API.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in the response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration.
            enable_cache: Whether to request prompt caching.

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of (assistant message, tool calls if any).
        """
        body = self._responses_body(
            messages=messages,
            model=model,
            tools=tools,
            temperature=temperature,
            max_tokens=max_tokens,
            tool_choice=tool_choice,
            thinking=thinking,
            enable_cache=enable_cache,
            stream=False,
        )
        start_time = time.perf_counter()
        api_task: asyncio.Task[dict[str, Any]] = asyncio.create_task(
            self._retry_with_backoff(lambda: self._post_responses(body)),
        )
        self._current_task = cast("asyncio.Task[object]", api_task)
        try:
            payload = await api_task
        finally:
            self._current_task = None
        duration_ms = (time.perf_counter() - start_time) * 1000

        parsed = self._responses_adapter.parse_response(payload)
        self._pending_usage = parsed.usage
        self._pending_reasoning = list(parsed.reasoning)
        self._pending_thinking.extend(item.text for item in parsed.reasoning if item.text)
        tool_calls = list(parsed.tool_calls)
        message = Message(
            role="assistant",
            content=parsed.content,
            tool_calls=tool_calls or None,
            reasoning=list(parsed.reasoning) or None,
            timestamp=datetime.now(tz=UTC),
        )
        log_provider_response(
            provider="openai",
            model=model,
            tool_calls_count=len(tool_calls),
            duration_ms=duration_ms,
        )
        return message, tool_calls or None

    async def _iter_responses_stream(self, body: dict[str, Any]) -> AsyncIterator[str]:
        """Open a Responses stream and yield its visible text deltas.

        Args:
            body: The request body built by the Responses adapter.

        Yields:
            str: Text chunks as they arrive.

        Raises:
            ProviderError: If the client is not connected.
        """
        if self.client is None:
            self._logger.warning("openai_responses_stream_not_connected", model=body.get("model"))
            raise ProviderError(_ERR_NOT_CONNECTED)
        stream = cast(
            "AsyncStream[ResponseStreamEvent]",
            await self.client.post(
                _RESPONSES_PATH,
                cast_to=httpx.Response,
                body=body,
                stream=True,
                stream_cls=AsyncStream[cast("type[Any]", object)],
            ),
        )
        buffer = ToolCallBufferManager()
        reasoning: list[ReasoningItem] = []
        async for event in stream:
            if self._cancel_requested:
                break
            for delta in self._responses_adapter.parse_stream_event(_event_mapping(event)):
                buffer.absorb(delta)
                if delta.usage is not None:
                    self._pending_usage = delta.usage
                if delta.reasoning_item is not None:
                    reasoning.append(delta.reasoning_item)
                if delta.reasoning:
                    self._pending_thinking.append(delta.reasoning)
                if delta.text:
                    yield delta.text
        self._pending_tool_calls = buffer.finalize()
        self._pending_reasoning = reasoning

    async def cancel_request(self) -> None:
        """Cancel any in-flight request."""
        self._cancel_requested = True
        if self._current_task is not None and not self._current_task.done():
            self._current_task.cancel()
        self._logger.info(
            "openai_request_cancelled",
            had_active_task=self._current_task is not None,
        )

    @override
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Convert internal messages to OpenAI format.

        Args:
            messages: List of Message objects.

        Returns:
            list[dict[str, object]]: List of messages in OpenAI's format.
        """
        return self._convert_messages_to_openai_format(messages)

    @override
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Convert internal tools to OpenAI format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            list[dict[str, object]]: List of tools in OpenAI's format.
        """
        capped_tools = self._enforce_tool_count_cap(tools)
        return self._convert_tools_to_openai_format(capped_tools)
