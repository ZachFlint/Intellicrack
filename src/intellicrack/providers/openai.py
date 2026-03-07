# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""OpenAI API provider implementation.

This module provides integration with OpenAI's GPT models for
chat completion and tool/function calling.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, TypedDict, cast, override

import openai
from openai import AsyncStream
from openai.types.chat.chat_completion_message_function_tool_call import (
    ChatCompletionMessageFunctionToolCall,
)


if TYPE_CHECKING:
    import asyncio
    from collections.abc import AsyncIterator

    from openai.types.chat import (
        ChatCompletionChunk,
        ChatCompletionMessageParam,
        ChatCompletionToolParam,
    )
    from openai.types.chat.chat_completion import ChatCompletion
    from openai.types.chat.chat_completion_message import ChatCompletionMessage

from ..core.logging import get_logger, log_provider_request
from ..core.types import (
    AuthenticationError,
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    ProviderName,
    RateLimitError,
    ToolCall,
    ToolDefinition,
)
from .base import LLMProviderBase, ToolCallBufferManager, create_openai_tool_schema


_ERR_NOT_CONNECTED = "Not connected to OpenAI API"
_ERR_KEY_REQUIRED = "OpenAI API key is required"
_ERR_INVALID_KEY = "Invalid OpenAI API key: %s"
_ERR_CONNECT_FAILED = "Failed to connect to OpenAI: %s"
_ERR_LIST_MODELS_FAILED = "Failed to list OpenAI models: %s"
_ERR_RATE_LIMITED = "OpenAI rate limit exceeded: %s"
_ERR_API_ERROR = "OpenAI API error: %s"
_ERR_REQUEST_FAILED = "OpenAI request failed: %s"
_ERR_STREAM_FAILED = "OpenAI stream failed: %s"


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

    Provides integration with OpenAI's GPT models including
    support for tool/function calling and streaming responses.

    Attributes:
        _client: The async OpenAI client instance.
        _current_task: Reference to any in-flight async task.
    """

    def __init__(self) -> None:
        """Initialize the OpenAI provider."""
        super().__init__()
        self._client: openai.AsyncOpenAI | None = None
        self._current_task: asyncio.Task[object] | None = None
        self._logger = get_logger("providers.openai")

    @property
    def name(self) -> ProviderName:
        """Get the provider's name.

        Returns:
            ProviderName.OPENAI
        """
        return ProviderName.OPENAI

    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect to OpenAI API.

        Args:
            credentials: Must contain api_key.

        Raises:
            AuthenticationError: If API key is invalid.
            ProviderError: If connection fails.
        """
        if not credentials.api_key:
            raise AuthenticationError(_ERR_KEY_REQUIRED)

        try:
            self._client = openai.AsyncOpenAI(
                api_key=credentials.api_key,
                base_url=credentials.api_base,
                organization=credentials.organization_id,
                project=credentials.project_id,
            )
            await self._client.models.list()
            self._credentials = credentials
            self._connected = True
            self._logger.info(
                "openai_connected",
                extra={
                    "has_custom_base": credentials.api_base is not None,
                    "has_organization": credentials.organization_id is not None,
                    "has_project": credentials.project_id is not None,
                },
            )
        except openai.AuthenticationError as e:
            self._logger.exception(
                "openai_connect_auth_failed",
                extra={"error": str(e)},
            )
            raise AuthenticationError(_ERR_INVALID_KEY % e) from e
        except Exception as e:
            self._logger.exception(
                "openai_connect_failed",
                extra={"error": str(e)},
            )
            raise ProviderError(_ERR_CONNECT_FAILED % e) from e

    async def disconnect(self) -> None:
        """Disconnect from OpenAI API."""
        try:
            await super().disconnect()
            self._client = None
            self._current_task = None
            self._logger.info("openai_disconnected", extra={"success": True})
        except Exception as exc:
            self._logger.warning("disconnect_cleanup_error", extra={"error": str(exc)})
            self._connected = False

    @staticmethod
    def _is_chat_model(model_id: str) -> bool:
        """Determine if a model ID corresponds to a chat-capable model.

        Args:
            model_id: OpenAI model identifier.

        Returns:
            True if the model supports chat completions.
        """
        non_chat_prefixes = (
            "text-embedding-",
            "dall-e-",
            "whisper-",
            "tts-",
            "text-moderation-",
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
        )
        return not model_id.startswith(non_chat_prefixes)

    @staticmethod
    def _infer_context_window(model_id: str) -> int:
        """Infer context window size from model ID prefix patterns.

        Args:
            model_id: OpenAI model identifier.

        Returns:
            Estimated context window in tokens.
        """
        if model_id.startswith(("o1", "o3", "o4")):
            return 200000
        if model_id.startswith(("gpt-4o", "gpt-4-turbo", "gpt-4.1", "gpt-4.5")):
            return 128000
        if model_id.startswith("gpt-4-") and "turbo" not in model_id:
            return 8192
        if model_id.startswith("gpt-3.5"):
            return 16385
        return 128000

    @staticmethod
    def _infer_supports_vision(model_id: str) -> bool:
        """Infer vision support from model ID prefix patterns.

        Args:
            model_id: OpenAI model identifier.

        Returns:
            True if the model likely supports image inputs.
        """
        if model_id.startswith(("gpt-4o", "o1", "o3", "o4", "gpt-4-turbo", "gpt-4.1", "gpt-4.5")):
            return True
        return "vision" in model_id

    async def list_models(self) -> list[ModelInfo]:
        """Dynamically fetch available models from OpenAI.

        Returns:
            List of available GPT models.

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
                        provider=ProviderName.OPENAI,
                        context_window=self._infer_context_window(model_id),
                        supports_tools=True,
                        supports_vision=self._infer_supports_vision(model_id),
                        supports_streaming=True,
                        input_cost_per_1m_tokens=None,
                        output_cost_per_1m_tokens=None,
                    )
                )

            sorted_models = sorted(models, key=lambda m: m.id, reverse=True)
            self._logger.info(
                "openai_models_listed",
                extra={"count": len(sorted_models)},
            )
        except Exception as e:
            self._logger.exception(
                "openai_list_models_failed",
                extra={"error": str(e)},
            )
            raise ProviderError(_ERR_LIST_MODELS_FAILED % e) from e
        else:
            return sorted_models

    async def chat(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Send a chat completion request to OpenAI.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.

        Returns:
            Tuple of (assistant message, tool calls if any).

        Raises:
            ProviderError: If not connected or request fails.
        """
        if not self._connected or self._client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        self._cancel_requested = False

        openai_messages = self._convert_messages_to_provider_format(messages)
        openai_tools = self._convert_tools_to_provider_format(tools) if tools else None
        log_provider_request(
            provider="openai",
            model=model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
        )

        start_time = time.perf_counter()
        response = await self._make_openai_api_call(
            model=model,
            messages=cast("list[ChatCompletionMessageParam]", openai_messages),
            temperature=temperature,
            max_tokens=max_tokens,
            tools=cast("list[ChatCompletionToolParam]", openai_tools) if openai_tools else None,
        )
        duration_ms = (time.perf_counter() - start_time) * 1000

        response_message = response.choices[0].message
        content = response_message.content or ""
        tool_calls = self._parse_openai_tool_calls(response_message)

        return self._build_chat_response(
            provider="openai",
            model=model,
            content=content,
            tool_calls=tool_calls,
            duration_ms=duration_ms,
        )

    async def _make_openai_api_call(
        self,
        *,
        model: str,
        messages: list[ChatCompletionMessageParam],
        temperature: float,
        max_tokens: int,
        tools: list[ChatCompletionToolParam] | None,
    ) -> ChatCompletion:
        """Execute the OpenAI API chat completion call with error handling.

        Args:
            model: Model ID to use.
            messages: Formatted messages for the API.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            tools: Formatted tools for the API, or None.

        Returns:
            The chat completion response object.

        Raises:
            ProviderError: If the API call fails.
            RateLimitError: If rate limited.
        """
        if self._client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        try:
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
            self._logger.exception(
                "openai_chat_rate_limited",
                extra={"model": model, "error": str(e)},
            )
            raise RateLimitError(_ERR_RATE_LIMITED % e) from e
        except openai.APIError as e:
            self._logger.exception(
                "openai_chat_api_error",
                extra={"model": model, "error": str(e)},
            )
            raise ProviderError(_ERR_API_ERROR % e) from e
        except Exception as e:
            self._logger.exception(
                "openai_chat_failed",
                extra={"model": model, "error": str(e)},
            )
            raise ProviderError(_ERR_REQUEST_FAILED % e) from e

    def _parse_openai_tool_calls(
        self,
        response_message: ChatCompletionMessage,
    ) -> list[ToolCall]:
        """Parse tool calls from an OpenAI API response message.

        Args:
            response_message: The message from the OpenAI API response.

        Returns:
            List of parsed ToolCall instances.
        """
        tool_calls: list[ToolCall] = []
        if not response_message.tool_calls:
            return tool_calls

        for tc in response_message.tool_calls:
            if not isinstance(tc, ChatCompletionMessageFunctionToolCall):
                continue
            tool_call = self._parse_tool_call_common(
                call_id=tc.id,
                function_name=tc.function.name,
                raw_arguments=tc.function.arguments,
            )
            tool_calls.append(tool_call)
            self._logger.debug(
                "tool_call_parsed",
                extra={
                    "tool_name": tool_call.tool_name,
                    "arguments_count": len(tool_call.arguments),
                },
            )
        return tool_calls

    async def chat_stream(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AsyncIterator[str]:
        """Stream a chat completion response from OpenAI.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.

        Yields:
            Text chunks as they arrive.

        Raises:
            ProviderError: If not connected or request fails.
            RateLimitError: If rate limited by OpenAI.
        """
        if not self._connected or self._client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        self._cancel_requested = False

        openai_messages = self._convert_messages_to_provider_format(messages)
        openai_tools = self._convert_tools_to_provider_format(tools) if tools else None
        try:
            typed_messages = cast("list[ChatCompletionMessageParam]", openai_messages)
            stream: AsyncStream[ChatCompletionChunk]
            if openai_tools:
                typed_tools = cast("list[ChatCompletionToolParam]", openai_tools)
                stream = await self._client.chat.completions.create(
                    model=model,
                    messages=typed_messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    stream=True,
                    tools=typed_tools,
                )
            else:
                stream = await self._client.chat.completions.create(
                    model=model,
                    messages=typed_messages,
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
            self._logger.exception(
                "openai_stream_rate_limited",
                extra={"model": model, "error": str(e)},
            )
            raise RateLimitError(_ERR_RATE_LIMITED % e) from e
        except openai.APIError as e:
            self._logger.exception(
                "openai_stream_api_error",
                extra={"model": model, "error": str(e)},
            )
            raise ProviderError(_ERR_API_ERROR % e) from e
        except Exception as e:
            if not self._cancel_requested:
                self._logger.exception(
                    "openai_stream_failed",
                    extra={"model": model, "error": str(e)},
                )
                raise ProviderError(_ERR_STREAM_FAILED % e) from e

    async def cancel_request(self) -> None:
        """Cancel any in-flight request."""
        self._cancel_requested = True
        if self._current_task is not None and not self._current_task.done():
            self._current_task.cancel()
        self._logger.info(
            "openai_request_cancelled",
            extra={"had_active_task": self._current_task is not None},
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
            List of messages in OpenAI's format.
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
            List of tools in OpenAI's format.
        """
        openai_tools: list[dict[str, object]] = []
        for tool in tools:
            tool_schemas = create_openai_tool_schema(tool)
            openai_tools.extend(dict(schema) for schema in tool_schemas)
        return openai_tools
