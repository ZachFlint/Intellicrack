# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""
X.AI Grok API provider implementation.

This module provides integration with X.AI's Grok models for chat completion and tool/function calling. Grok uses an OpenAI-compatible API,
so this implementation leverages the OpenAI SDK with a custom base URL.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, TypedDict, cast, override

import openai

from ..core.logging import get_logger, log_provider_request
from ..core.types import (
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
from .base import LLMProviderBase, ToolCallBufferManager, create_openai_tool_schema


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

if TYPE_CHECKING:
    import asyncio
    from collections.abc import AsyncIterator

    from openai.types.chat import ChatCompletionMessageParam, ChatCompletionToolChoiceOptionParam, ChatCompletionToolParam
    from openai.types.chat.chat_completion import ChatCompletion
    from openai.types.chat.chat_completion_message import ChatCompletionMessage


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
    """
    X.AI Grok API provider implementation.

    Provides integration with X.AI's Grok models including
    support for tool/function calling and streaming responses.
    Uses the OpenAI SDK with a custom base URL for API compatibility.

    Attributes:
        BASE_URL: The X.AI API base URL.
    """

    BASE_URL: str = "https://api.x.ai/v1"

    def __init__(self) -> None:
        super().__init__()
        self._client: openai.AsyncOpenAI | None = None
        self._current_task: asyncio.Task[object] | None = None
        self._logger = get_logger("providers.grok").bind(provider="grok")

    @property
    def name(self) -> ProviderName:
        """
        Get the provider's name.

        Returns:
            ProviderName: ProviderName.GROK
        """
        return ProviderName.GROK

    async def connect(self, credentials: ProviderCredentials) -> None:
        """
        Connect to X.AI Grok API.

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
            self._client = openai.AsyncOpenAI(
                api_key=credentials.api_key,
                base_url=base_url,
            )
            await self._client.models.list()
            self._credentials = credentials
            self._connected = True
            self._logger.info("grok_api_connected", base_url=base_url)
        except openai.AuthenticationError as e:
            self._logger.warning("grok_auth_failed", error=str(e))
            raise AuthenticationError(_ERR_INVALID_API_KEY % e) from e
        except openai.BadRequestError as e:
            self._logger.warning("grok_bad_request", error=str(e))
            error_str = str(e).lower()
            if "api key" in error_str or "incorrect" in error_str:
                raise AuthenticationError(_ERR_INVALID_API_KEY % e) from e
            raise ProviderError(_ERR_API_REQUEST % e) from e
        except Exception as e:
            self._logger.warning("grok_connect_failed", error=str(e))
            raise ProviderError(_ERR_CONNECT_FAILED % e) from e

    async def disconnect(self) -> None:
        """Disconnect from Grok API."""
        try:
            await super().disconnect()
            self._client = None
            self._current_task = None
            self._logger.info("grok_disconnected", provider="grok")
        except Exception as exc:
            self._logger.warning("disconnect_cleanup_error", error=str(exc))
            self._connected = False

    @staticmethod
    def _is_chat_model(model_id: str) -> bool:
        """
        Determine if a model ID corresponds to a chat-capable model.

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
        """
        Infer context window size from model ID prefix patterns.

        Args:
            model_id: Grok model identifier.

        Returns:
            int: Estimated context window in tokens.
        """
        if "grok-3" in model_id:
            return 131072
        if "grok-2" in model_id:
            return 131072
        return 8192 if "grok-1" in model_id else 131072

    @staticmethod
    def _infer_supports_vision(model_id: str) -> bool:
        """
        Infer vision support from model ID.

        Args:
            model_id: Grok model identifier.

        Returns:
            bool: True if the model likely supports image inputs.
        """
        return "vision" in model_id or "image" in model_id

    async def list_models(self) -> list[ModelInfo]:
        """
        Dynamically fetch available models from Grok.

        Returns:
            list[ModelInfo]: List of available Grok models.

        Raises:
            ProviderError: If not connected.
        """
        if not self._connected or self._client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        try:
            response = await self._client.models.list()
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
                    )
                )

            return sorted(models, key=lambda m: m.id, reverse=True)
        except Exception as e:
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
        enable_cache: bool = False,
    ) -> tuple[Message, list[ToolCall] | None]:
        """
        Send a chat completion request to Grok.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration (ignored by Grok).
            enable_cache: Whether to enable prompt caching (ignored by Grok).

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of (assistant message, tool calls if any).

        Raises:
            ProviderError: If not connected or request fails.
        """
        if not self._connected or self._client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        self._cancel_requested = False

        grok_messages_raw = self._convert_messages_to_provider_format(messages)
        grok_messages_typed = cast("list[ChatCompletionMessageParam]", grok_messages_raw)

        grok_tools_typed: list[ChatCompletionToolParam] | None = None
        if tools:
            grok_tools_raw = self._convert_tools_to_provider_format(tools)
            grok_tools_typed = cast("list[ChatCompletionToolParam]", grok_tools_raw)

        tool_choice_param: ChatCompletionToolChoiceOptionParam | None = None
        if tool_choice is not None and grok_tools_typed:
            tool_choice_param = cast(
                "ChatCompletionToolChoiceOptionParam",
                self._convert_tool_choice_to_openai_format(tool_choice),
            )
        if thinking is not None and thinking.enabled:
            self._logger.debug("grok_thinking_ignored")
        if enable_cache:
            self._logger.debug("grok_cache_ignored")

        log_provider_request(
            provider="grok",
            model=model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
        )

        start_time = time.perf_counter()
        response = await self._make_grok_api_call(
            model=model,
            messages=grok_messages_typed,
            temperature=temperature,
            max_tokens=max_tokens,
            tools=grok_tools_typed,
            tool_choice=tool_choice_param,
        )
        duration_ms = (time.perf_counter() - start_time) * 1000

        response_message = response.choices[0].message
        content = response_message.content or ""
        tool_calls = self._parse_grok_tool_calls(response_message)

        return self._build_chat_response(
            provider="grok",
            model=model,
            content=content,
            tool_calls=tool_calls,
            duration_ms=duration_ms,
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
    ) -> ChatCompletion:
        """
        Execute the Grok API chat completion call with error handling.

        Args:
            model: Model ID to use.
            messages: Formatted messages for the API.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            tools: Formatted tools for the API, or None.
            tool_choice: How the model should select tools.

        Returns:
            ChatCompletion: The chat completion response object.

        Raises:
            ProviderError: If the API call fails.
            RateLimitError: If rate limited.
        """
        if self._client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        try:
            if tools and tool_choice is not None:
                return await self._client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    tools=tools,
                    tool_choice=tool_choice,
                )
            if tools:
                return await self._client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    tools=tools,
                )
            return await self._client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        except openai.RateLimitError as e:
            self._logger.warning("grok_chat_rate_limited", error=str(e))
            raise RateLimitError(_ERR_RATE_LIMITED % e) from e
        except openai.APIError as e:
            self._logger.warning("grok_chat_api_error", error=str(e))
            raise ProviderError(_ERR_API_ERROR % e) from e
        except Exception as e:
            self._logger.warning("grok_chat_request_failed", error=str(e))
            raise ProviderError(_ERR_REQUEST_FAILED % e) from e

    def _parse_grok_tool_calls(
        self,
        response_message: ChatCompletionMessage,
    ) -> list[ToolCall]:
        """
        Parse tool calls from a Grok API response message.

        Args:
            response_message: The message from the Grok API response.

        Returns:
            list[ToolCall]: List of parsed ToolCall instances.
        """
        tool_calls: list[ToolCall] = []
        if not response_message.tool_calls:
            return tool_calls

        for tc in response_message.tool_calls:
            tc_function = getattr(tc, "function", None)
            if tc_function is None:
                continue
            tool_call = self._parse_tool_call_common(
                call_id=tc.id,
                function_name=tc_function.name,
                raw_arguments=tc_function.arguments,
            )
            tool_calls.append(tool_call)
            self._logger.debug(
                "tool_call_parsed",
                tool_name=tool_call.tool_name,
                arguments_count=len(tool_call.arguments),
            )
        return tool_calls

    async def chat_stream(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        enable_cache: bool = False,
    ) -> AsyncIterator[str]:
        """
        Stream a chat completion response from Grok.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration (ignored by Grok).
            enable_cache: Whether to enable prompt caching (ignored by Grok).

        Yields:
            str: Text chunks as they arrive.

        Raises:
            ProviderError: If not connected or request fails.
            RateLimitError: If rate limit is exceeded.
        """
        if not self._connected or self._client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        self._cancel_requested = False
        if thinking is not None and thinking.enabled:
            self._logger.debug("grok_stream_thinking_ignored")
        if enable_cache:
            self._logger.debug("grok_stream_cache_ignored")

        grok_messages_raw = self._convert_messages_to_provider_format(messages)
        grok_messages_typed = cast("list[ChatCompletionMessageParam]", grok_messages_raw)

        grok_tools_typed: list[ChatCompletionToolParam] | None = None
        if tools:
            grok_tools_raw = self._convert_tools_to_provider_format(tools)
            grok_tools_typed = cast("list[ChatCompletionToolParam]", grok_tools_raw)

        tool_choice_value: ChatCompletionToolChoiceOptionParam | None = None
        if tool_choice is not None and grok_tools_typed:
            tool_choice_value = cast(
                "ChatCompletionToolChoiceOptionParam",
                self._convert_tool_choice_to_openai_format(tool_choice),
            )

        try:
            if grok_tools_typed and tool_choice_value is not None:
                stream = await self._client.chat.completions.create(
                    model=model,
                    messages=grok_messages_typed,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    stream=True,
                    tools=grok_tools_typed,
                    tool_choice=tool_choice_value,
                )
            elif grok_tools_typed:
                stream = await self._client.chat.completions.create(
                    model=model,
                    messages=grok_messages_typed,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    stream=True,
                    tools=grok_tools_typed,
                )
            else:
                stream = await self._client.chat.completions.create(
                    model=model,
                    messages=grok_messages_typed,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    stream=True,
                )

            tc_buffer = ToolCallBufferManager()

            async for chunk in stream:
                if self._cancel_requested:
                    break
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

        except openai.RateLimitError as e:
            self._logger.warning("grok_stream_rate_limited", error=str(e))
            raise RateLimitError(_ERR_RATE_LIMITED % e) from e
        except openai.APIError as e:
            self._logger.warning("grok_stream_api_error", error=str(e))
            raise ProviderError(_ERR_API_ERROR % e) from e
        except Exception as e:
            if not self._cancel_requested:
                self._logger.warning("grok_stream_failed", error=str(e))
                raise ProviderError(_ERR_STREAM_FAILED % e) from e

    async def cancel_request(self) -> None:
        """Cancel any in-flight request."""
        self._cancel_requested = True
        if self._current_task is not None and not self._current_task.done():
            self._current_task.cancel()

    @override
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """
        Convert internal messages to Grok/OpenAI format.

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
        """
        Convert internal tools to Grok/OpenAI format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            list[dict[str, object]]: List of tools in Grok's format.
        """
        grok_tools: list[dict[str, object]] = []
        for tool in tools:
            tool_schemas = create_openai_tool_schema(tool)
            grok_tools.extend(dict(schema) for schema in tool_schemas)
        return grok_tools
