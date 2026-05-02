# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""X.AI Grok API provider implementation.

This module provides integration with X.AI's Grok models for chat completion and tool/function calling. Grok uses an OpenAI-compatible API,
so this implementation leverages the OpenAI SDK with a custom base URL.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, TypedDict, cast, override

import openai
from openai import AsyncStream

from intellicrack.core.logging import get_logger, log_provider_request
from intellicrack.core.types import (
    AuthenticationError,
    Message,
    ModelInfo,
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
    ToolCallBufferManager,
    map_thinking_budget_to_effort,
)


_GROK_4_CONTEXT_WINDOW = 256000
_GROK_3_CONTEXT_WINDOW = 131072
_GROK_2_CONTEXT_WINDOW = 131072
_GROK_1_CONTEXT_WINDOW = 8192
_GROK_DEFAULT_CONTEXT_WINDOW = 131072

_ERR_KEY_REQUIRED = "Grok API key is required"
_ERR_NOT_CONNECTED = "Not connected to Grok API"
_ERR_INVALID_API_KEY = "Invalid Grok API key: %s"
_ERR_API_REQUEST = "Grok API request error: %s"
_ERR_CONNECT_FAILED = "Failed to connect to Grok: %s"
_ERR_LIST_MODELS_FAILED = "Failed to list Grok models: %s"
_ERR_RATE_LIMITED = "Grok rate limit exceeded: %s"
_ERR_API_ERROR = "Grok API error: %s"
_ERR_REQUEST_FAILED = "Grok request failed: %s"
_ERR_STREAM_FAILED = "Grok stream failed: %s"

_GROK_CHAT_ERRORS = OpenAIErrorMessages(
    auth_invalid=_ERR_INVALID_API_KEY,
    rate_limited=_ERR_RATE_LIMITED,
    api_error=_ERR_API_ERROR,
    request_failed=_ERR_REQUEST_FAILED,
)

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
    from openai.types.shared import ReasoningEffort


class GrokMessageContent(TypedDict, total=False):
    """Grok message content structure."""

    type: str
    text: str


class GrokMessage(TypedDict, total=False):
    """Grok message structure."""

    role: str
    content: str | list[GrokMessageContent] | None
    tool_calls: list[dict[str, object]]
    tool_call_id: str
    name: str


class GrokProvider(LLMProviderBase):
    """X.AI Grok API provider implementation.

    Provides integration with X.AI's Grok models including
    support for tool/function calling and streaming responses.
    Uses the OpenAI SDK with a custom base URL for API compatibility.

    Attributes:
        BASE_URL: The X.AI API base URL.
    """

    BASE_URL: str = "https://api.x.ai/v1"

    def __init__(self) -> None:
        """Initialize the GrokProvider instance."""
        super().__init__()
        self.client: openai.AsyncOpenAI | None = None
        self._current_task: asyncio.Task[object] | None = None
        self._logger = get_logger(__name__).bind(provider="grok")
        self._logger.info("grok_provider_initialized")

    @property
    def name(self) -> ProviderName:
        """Get the provider's name.

        Returns:
            ProviderName: ProviderName.GROK
        """
        return ProviderName.GROK

    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect to X.AI Grok API.

        Args:
            credentials: Must contain api_key. Optionally api_base for custom URL.

        Raises:
            AuthenticationError: If API key is invalid.
            ProviderError: If connection fails.
        """
        if not credentials.api_key:
            raise AuthenticationError(_ERR_KEY_REQUIRED)

        base_url = credentials.api_base or self.BASE_URL

        try:
            self.client = openai.AsyncOpenAI(
                api_key=credentials.api_key,
                base_url=base_url,
            )
            await self.client.models.list()
        except openai.AuthenticationError as e:
            self.connected = False
            self.client = None
            self._logger.warning("grok_auth_failed", error=str(e))
            raise AuthenticationError(_ERR_INVALID_API_KEY % e) from e
        except openai.BadRequestError as e:
            self.connected = False
            self.client = None
            self._logger.warning("grok_bad_request", error=str(e))
            error_str = str(e).lower()
            if "api key" in error_str or "incorrect" in error_str:
                raise AuthenticationError(_ERR_INVALID_API_KEY % e) from e
            raise ProviderError(_ERR_API_REQUEST % e) from e
        except (ConnectionError, TimeoutError, OSError) as e:
            self.connected = False
            self.client = None
            self._logger.warning("grok_connect_failed", error=str(e))
            raise ProviderError(_ERR_CONNECT_FAILED % e) from e
        else:
            self._credentials = credentials
            self.connected = True
            self._logger.info("grok_api_connected", base_url=base_url)

    async def disconnect(self) -> None:
        """Disconnect from Grok API."""
        try:
            await super().disconnect()
            self.client = None
            self._current_task = None
            self._logger.info("grok_disconnected", provider="grok")
        except (ConnectionError, TimeoutError, OSError, RuntimeError) as exc:
            self._logger.warning("disconnect_cleanup_error", error=str(exc))
            self.connected = False

    @staticmethod
    def _is_chat_model(model_id: str) -> bool:
        """Determine if a model ID corresponds to a chat-capable model.

        Args:
            model_id: Grok model identifier.

        Returns:
            bool: True if the model supports chat completions.
        """
        non_chat_prefixes = (
            "embed-",
            "embedding-",
            "moderation-",
        )
        return not model_id.startswith(non_chat_prefixes)

    @staticmethod
    def _infer_context_window(model_id: str) -> int:
        """Infer context window size from model ID prefix patterns.

        Args:
            model_id: Grok model identifier.

        Returns:
            int: Estimated context window in tokens.
        """
        if "grok-4" in model_id:
            return _GROK_4_CONTEXT_WINDOW
        if "grok-3" in model_id:
            return _GROK_3_CONTEXT_WINDOW
        if "grok-2" in model_id:
            return _GROK_2_CONTEXT_WINDOW
        if "grok-1" in model_id:
            return _GROK_1_CONTEXT_WINDOW
        return _GROK_DEFAULT_CONTEXT_WINDOW

    @staticmethod
    def _supports_max_completion_tokens(model_id: str) -> bool:
        """Determine whether a model uses ``max_completion_tokens``.

        Grok-4 and any future newer Grok generation use OpenAI's newer
        ``max_completion_tokens`` request field instead of the legacy
        ``max_tokens`` parameter.  Older Grok generations continue to use
        ``max_tokens``.

        Args:
            model_id: Grok model identifier.

        Returns:
            bool: True if the model expects ``max_completion_tokens``.
        """
        return "grok-4" in model_id or "grok-5" in model_id or "grok-6" in model_id

    @staticmethod
    def _infer_supports_vision(model_id: str) -> bool:
        """Infer vision support from model ID.

        Args:
            model_id: Grok model identifier.

        Returns:
            bool: True if the model likely supports image inputs.
        """
        return "vision" in model_id or "image" in model_id

    async def list_models(self) -> list[ModelInfo]:
        """Dynamically fetch available models from Grok.

        Returns:
            list[ModelInfo]: List of available Grok models.

        Raises:
            ProviderError: If not connected.
        """
        if not self.connected or self.client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        try:
            response = await self.client.models.list()
            models: list[ModelInfo] = []

            for model_data in response.data:
                model_id = model_data.id
                if not self._is_chat_model(model_id):
                    continue
                models.append(
                    ModelInfo(
                        id=model_id,
                        name=model_id,
                        provider=ProviderName.GROK,
                        context_window=self._infer_context_window(model_id),
                        supports_tools=True,
                        supports_vision=self._infer_supports_vision(model_id),
                        supports_streaming=True,
                        input_cost_per_1m_tokens=None,
                        output_cost_per_1m_tokens=None,
                    ),
                )

            return sorted(models, key=lambda m: m.id, reverse=True)
        except (ConnectionError, TimeoutError, OSError, openai.APIError) as e:
            self._logger.warning("grok_list_models_failed", error=str(e))
            raise ProviderError(_ERR_LIST_MODELS_FAILED % e) from e

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
        """Send a chat completion request to Grok.

        ``thinking`` is honoured on Grok models that expose it through
        the OpenAI-compatible ``reasoning_effort`` parameter
        (``grok-4-multi-agent``).  Grok-4 / Grok-4-fast reason
        automatically, so the parameter is intentionally omitted there.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration.  Forwarded as
                ``reasoning_effort`` for ``grok-*-multi-agent`` models.
            enable_cache: Whether to enable prompt caching.  Grok caches
                automatically when the same prompt prefix is reused; the
                parameter is logged for symmetry.

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of (assistant message, tool calls if any).

        Raises:
            ProviderError: If not connected or request fails.
        """
        if not self.connected or self.client is None:
            self._logger.error("grok_chat_not_connected", model=model)
            raise ProviderError(_ERR_NOT_CONNECTED)

        self._cancel_requested = False
        self._pending_usage = None

        grok_messages_raw = self.convert_messages_to_provider_format(messages)
        grok_messages_typed = cast("list[ChatCompletionMessageParam]", grok_messages_raw)

        grok_tools_typed: list[ChatCompletionToolParam] | None = None
        if tools:
            grok_tools_raw = self.convert_tools_to_provider_format(tools)
            grok_tools_typed = cast("list[ChatCompletionToolParam]", grok_tools_raw)

        tool_choice_param: ChatCompletionToolChoiceOptionParam | None = None
        if tool_choice is not None and grok_tools_typed:
            tool_choice_param = cast(
                "ChatCompletionToolChoiceOptionParam",
                self._convert_tool_choice_to_openai_format(tool_choice),
            )
        reasoning_effort = self._reasoning_effort_for(model=model, thinking=thinking)
        if enable_cache:
            self._logger.debug("grok_cache_auto", model=model)

        log_provider_request(
            provider="grok",
            model=model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
        )

        start_time = time.perf_counter()
        api_task: asyncio.Task[ChatCompletion] = asyncio.create_task(
            self._retry_with_backoff(
                lambda: self._make_grok_api_call(
                    model=model,
                    messages=grok_messages_typed,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    tools=grok_tools_typed,
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
            provider="grok",
            model=model,
            content=content,
            tool_calls=tool_calls,
            duration_ms=duration_ms,
        )

    @staticmethod
    def _supports_reasoning_effort(model_id: str) -> bool:
        """Return True when the Grok model accepts ``reasoning_effort``.

        Per X.AI's documentation, ``reasoning_effort`` is only honoured
        on the multi-agent variants such as ``grok-4-multi-agent``.
        ``grok-4`` and ``grok-4-fast`` reason automatically and reject
        the parameter, so it must be omitted for those families.

        Args:
            model_id: Grok model identifier.

        Returns:
            bool: ``True`` if the model accepts ``reasoning_effort``.
        """
        return "multi-agent" in model_id

    def _reasoning_effort_for(
        self,
        *,
        model: str,
        thinking: ThinkingConfig | None,
    ) -> ReasoningEffort | None:
        """Resolve the ``reasoning_effort`` value for a Grok request.

        Args:
            model: Grok model identifier.
            thinking: Caller-supplied thinking configuration, or
                ``None``.

        Returns:
            ReasoningEffort | None: ``"low"``, ``"medium"``,
            ``"high"``, or ``"xhigh"`` when the request should set
            ``reasoning_effort``; ``None`` when the parameter must be
            omitted.
        """
        if thinking is None or not thinking.enabled:
            return None
        if not self._supports_reasoning_effort(model):
            self._logger.debug("grok_thinking_ignored_auto_reasoning_model", model=model)
            return None
        return cast(
            "ReasoningEffort",
            map_thinking_budget_to_effort(thinking.budget_tokens, allow_xhigh=True),
        )

    async def _make_grok_api_call(
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
        """Execute the Grok API chat completion call with error handling.

        OpenAI SDK exceptions surface inside the call are translated to
        Intellicrack typed errors by
        :meth:`LLMProviderBase._translate_openai_errors`.

        Args:
            model: Model ID to use.
            messages: Formatted messages for the API.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            tools: Formatted tools for the API, or None.
            tool_choice: How the model should select tools.
            reasoning_effort: ``reasoning_effort`` value for Grok models
                that expose it (multi-agent variants), or ``None``.

        Returns:
            ChatCompletion: The chat completion response object.

        Raises:
            ProviderError: If the client is not yet connected.
        """
        if self.client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        with self._translate_openai_errors(
            log_prefix="grok_chat",
            messages=_GROK_CHAT_ERRORS,
        ):
            return await self._dispatch_grok_create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                tools=tools,
                tool_choice=tool_choice,
                reasoning_effort=reasoning_effort,
            )

    async def _dispatch_grok_create(
        self,
        *,
        model: str,
        messages: list[ChatCompletionMessageParam],
        temperature: float,
        max_tokens: int,
        tools: list[ChatCompletionToolParam] | None,
        tool_choice: ChatCompletionToolChoiceOptionParam | None,
        reasoning_effort: ReasoningEffort | None,
    ) -> ChatCompletion:
        """Pick the right Grok ``chat.completions.create`` overload.

        Grok-4 / Grok-5 require ``max_completion_tokens`` while the
        legacy Grok-3 family uses ``max_tokens``.  This helper expands
        every meaningful combination of ``tools``, ``tool_choice``,
        ``reasoning_effort``, and the ``max_tokens`` field name into
        explicit keyword-argument calls so basedpyright keeps full
        type information for the response.

        Args:
            model: Grok model identifier.
            messages: Formatted messages for the API.
            temperature: Sampling temperature.
            max_tokens: Maximum response tokens.
            tools: Formatted tools, or ``None``.
            tool_choice: Tool selection mode, or ``None``.
            reasoning_effort: ``reasoning_effort`` value, or ``None``.

        Returns:
            ChatCompletion: Chat completion response.

        Raises:
            ProviderError: If the SDK client is not yet connected.
        """
        if self.client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)
        use_max_completion_tokens = self._supports_max_completion_tokens(model)
        if tools is not None and tool_choice is not None:
            if use_max_completion_tokens:
                if reasoning_effort is not None:
                    return await self.client.chat.completions.create(
                        model=model,
                        messages=messages,
                        temperature=temperature,
                        max_completion_tokens=max_tokens,
                        tools=tools,
                        tool_choice=tool_choice,
                        reasoning_effort=reasoning_effort,
                    )
                return await self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    max_completion_tokens=max_tokens,
                    tools=tools,
                    tool_choice=tool_choice,
                )
            if reasoning_effort is not None:
                return await self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    tools=tools,
                    tool_choice=tool_choice,
                    reasoning_effort=reasoning_effort,
                )
            return await self.client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
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
                        temperature=temperature,
                        max_completion_tokens=max_tokens,
                        tools=tools,
                        reasoning_effort=reasoning_effort,
                    )
                return await self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    max_completion_tokens=max_tokens,
                    tools=tools,
                )
            if reasoning_effort is not None:
                return await self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    tools=tools,
                    reasoning_effort=reasoning_effort,
                )
            return await self.client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                tools=tools,
            )
        if use_max_completion_tokens:
            if reasoning_effort is not None:
                return await self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    max_completion_tokens=max_tokens,
                    reasoning_effort=reasoning_effort,
                )
            return await self.client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_completion_tokens=max_tokens,
            )
        if reasoning_effort is not None:
            return await self.client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                reasoning_effort=reasoning_effort,
            )
        return await self.client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    async def _open_grok_stream(
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
        """Open a Grok streaming chat completion with the right kw overload.

        Mirrors :meth:`_dispatch_grok_create` for streaming so
        basedpyright keeps full type information for the returned
        stream.

        Args:
            model: Grok model identifier.
            messages: Formatted messages for the API.
            temperature: Sampling temperature.
            max_tokens: Maximum response tokens.
            tools: Formatted tools, or ``None``.
            tool_choice: Tool selection mode, or ``None``.
            reasoning_effort: ``reasoning_effort`` value, or ``None``.

        Returns:
            AsyncStream[ChatCompletionChunk]: SSE stream of chunks.

        Raises:
            ProviderError: If the SDK client is not yet connected.
        """
        if self.client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)
        use_max_completion_tokens = self._supports_max_completion_tokens(model)
        stream_options: ChatCompletionStreamOptionsParam = {"include_usage": True}
        if tools is not None and tool_choice is not None:
            if use_max_completion_tokens:
                if reasoning_effort is not None:
                    return await self.client.chat.completions.create(
                        model=model,
                        messages=messages,
                        temperature=temperature,
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
                    temperature=temperature,
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
                    temperature=temperature,
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
                temperature=temperature,
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
                        temperature=temperature,
                        max_completion_tokens=max_tokens,
                        stream=True,
                        stream_options=stream_options,
                        tools=tools,
                        reasoning_effort=reasoning_effort,
                    )
                return await self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    max_completion_tokens=max_tokens,
                    stream=True,
                    stream_options=stream_options,
                    tools=tools,
                )
            if reasoning_effort is not None:
                return await self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    stream=True,
                    stream_options=stream_options,
                    tools=tools,
                    reasoning_effort=reasoning_effort,
                )
            return await self.client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
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
                    temperature=temperature,
                    max_completion_tokens=max_tokens,
                    stream=True,
                    stream_options=stream_options,
                    reasoning_effort=reasoning_effort,
                )
            return await self.client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_completion_tokens=max_tokens,
                stream=True,
                stream_options=stream_options,
            )
        if reasoning_effort is not None:
            return await self.client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                stream=True,
                stream_options=stream_options,
                reasoning_effort=reasoning_effort,
            )
        return await self.client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
            stream_options=stream_options,
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
        """Stream a chat completion response from Grok.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration.  Forwarded as
                ``reasoning_effort`` for ``grok-*-multi-agent`` models;
                ignored on grok-4 / grok-4-fast (auto-reasoning).
            enable_cache: Whether to enable prompt caching.  Grok caches
                automatically; the parameter is logged for symmetry.

        Yields:
            str: Text chunks as they arrive.

        Raises:
            AuthenticationError: If the API key is invalid.
            ProviderError: If not connected or request fails.
            RateLimitError: If rate limit is exceeded.
        """
        if not self.connected or self.client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        self._cancel_requested = False
        self._pending_usage = None
        if enable_cache:
            self._logger.debug("grok_stream_cache_auto", model=model)

        grok_messages_raw = self.convert_messages_to_provider_format(messages)
        grok_messages_typed = cast("list[ChatCompletionMessageParam]", grok_messages_raw)

        grok_tools_typed: list[ChatCompletionToolParam] | None = None
        if tools:
            grok_tools_raw = self.convert_tools_to_provider_format(tools)
            grok_tools_typed = cast("list[ChatCompletionToolParam]", grok_tools_raw)

        tool_choice_value: ChatCompletionToolChoiceOptionParam | None = None
        if tool_choice is not None and grok_tools_typed:
            tool_choice_value = cast(
                "ChatCompletionToolChoiceOptionParam",
                self._convert_tool_choice_to_openai_format(tool_choice),
            )

        reasoning_effort = self._reasoning_effort_for(model=model, thinking=thinking)

        try:
            stream = await self._open_grok_stream(
                model=model,
                messages=grok_messages_typed,
                temperature=temperature,
                max_tokens=max_tokens,
                tools=grok_tools_typed,
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

        except openai.AuthenticationError as e:
            self._logger.warning("grok_stream_auth_failed", error=str(e))
            raise AuthenticationError(_ERR_INVALID_API_KEY % e) from e
        except openai.RateLimitError as e:
            self._logger.warning("grok_stream_rate_limited", error=str(e))
            raise RateLimitError(_ERR_RATE_LIMITED % e) from e
        except openai.APIError as e:
            self._logger.warning("grok_stream_api_error", error=str(e))
            raise ProviderError(_ERR_API_ERROR % e) from e
        except (ConnectionError, TimeoutError, OSError, ValueError) as e:
            self._logger.warning(
                "grok_stream_failed",
                error=str(e),
                cancel_requested=self._cancel_requested,
            )
            raise ProviderError(_ERR_STREAM_FAILED % e) from e

    async def cancel_request(self) -> None:
        """Cancel any in-flight request."""
        self._cancel_requested = True
        had_active_task = self._current_task is not None and not self._current_task.done()
        if had_active_task and self._current_task is not None:
            self._current_task.cancel()
        self._logger.info(
            "grok_request_cancelled",
            had_active_task=had_active_task,
        )

    @override
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Convert internal messages to Grok/OpenAI format.

        Args:
            messages: List of Message objects.

        Returns:
            list[dict[str, object]]: List of messages in Grok's format.
        """
        return self._convert_messages_to_openai_format(messages)

    @override
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Convert internal tools to Grok/OpenAI format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            list[dict[str, object]]: List of tools in Grok's format.
        """
        return self._convert_tools_to_openai_format(tools)
