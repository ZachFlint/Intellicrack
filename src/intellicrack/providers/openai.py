"""OpenAI API provider implementation.

This module provides integration with OpenAI's GPT models for
chat completion and tool/function calling.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from datetime import datetime
from typing import TYPE_CHECKING, Any, TypedDict, cast

import openai
from openai import AsyncStream
from openai.types.chat.chat_completion_message_function_tool_call import (
    ChatCompletionMessageFunctionToolCall,
)


if TYPE_CHECKING:
    from openai.types.chat import (
        ChatCompletionChunk,
        ChatCompletionMessageParam,
        ChatCompletionToolParam,
    )

from ..core.logging import get_logger, log_provider_request, log_provider_response
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
from .base import LLMProviderBase, create_openai_tool_schema


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
            raise AuthenticationError("OpenAI API key is required")

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
            raise AuthenticationError(f"Invalid OpenAI API key: {e}") from e
        except Exception as e:
            self._logger.exception(
                "openai_connect_failed",
                extra={"error": str(e)},
            )
            raise ProviderError(f"Failed to connect to OpenAI: {e}") from e

    async def disconnect(self) -> None:
        """Disconnect from OpenAI API."""
        await super().disconnect()
        self._client = None
        self._current_task = None
        self._logger.info("openai_disconnected", extra={"success": True})

    async def list_models(self) -> list[ModelInfo]:
        """Dynamically fetch available models from OpenAI.

        Returns:
            List of available GPT models.

        Raises:
            ProviderError: If not connected.
        """
        if not self._connected or self._client is None:
            raise ProviderError("Not connected to OpenAI API")

        try:
            response = await self._client.models.list()
            models: list[ModelInfo] = []

            for model_data in response.data:
                model_id = model_data.id
                if not self._is_chat_model(model_id):
                    continue

                context_window = self._get_context_window(model_id)
                supports_tools = self._supports_tools(model_id)
                supports_vision = self._supports_vision(model_id)

                models.append(
                    ModelInfo(
                        id=model_id,
                        name=model_id,
                        provider=ProviderName.OPENAI,
                        context_window=context_window,
                        supports_tools=supports_tools,
                        supports_vision=supports_vision,
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
            return sorted_models
        except Exception as e:
            self._logger.exception(
                "openai_list_models_failed",
                extra={"error": str(e)},
            )
            raise ProviderError(f"Failed to list OpenAI models: {e}") from e

    def _is_chat_model(self, model_id: str) -> bool:
        """Check if model supports chat completions.

        Args:
            model_id: The model identifier.

        Returns:
            True if model supports chat.
        """
        chat_prefixes = ("gpt-4", "gpt-3.5", "o1", "o3", "chatgpt")
        return any(model_id.startswith(prefix) for prefix in chat_prefixes)

    def _get_context_window(self, model_id: str) -> int:
        """Get context window size for a model.

        Args:
            model_id: The model identifier.

        Returns:
            Context window size in tokens.
        """
        if "128k" in model_id or "gpt-4o" in model_id or "gpt-4-turbo" in model_id:
            return 128000
        if "32k" in model_id:
            return 32768
        if "16k" in model_id:
            return 16384
        if "gpt-4" in model_id:
            return 8192
        if "gpt-3.5" in model_id:
            return 4096
        return 8192

    def _supports_tools(self, model_id: str) -> bool:
        """Check if model supports function calling.

        Args:
            model_id: The model identifier.

        Returns:
            True if model supports tools.
        """
        return "gpt-4" in model_id or "gpt-3.5-turbo" in model_id

    def _supports_vision(self, model_id: str) -> bool:
        """Check if model supports image input.

        Args:
            model_id: The model identifier.

        Returns:
            True if model supports vision.
        """
        return "vision" in model_id or "gpt-4o" in model_id or "gpt-4-turbo" in model_id

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
            RateLimitError: If rate limited.
        """
        if not self._connected or self._client is None:
            raise ProviderError("Not connected to OpenAI API")

        self._cancel_requested = False

        openai_messages = self._convert_messages_to_provider_format(messages)
        openai_tools: list[dict[str, object]] | None = None
        if tools:
            openai_tools = self._convert_tools_to_provider_format(tools)

        log_provider_request(
            provider="openai",
            model=model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
        )

        start_time = time.perf_counter()

        try:
            typed_messages = cast("list[ChatCompletionMessageParam]", openai_messages)
            if openai_tools:
                typed_tools = cast("list[ChatCompletionToolParam]", openai_tools)
                response = await self._client.chat.completions.create(
                    model=model,
                    messages=typed_messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    tools=typed_tools,
                )
            else:
                response = await self._client.chat.completions.create(
                    model=model,
                    messages=typed_messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )

            duration_ms = (time.perf_counter() - start_time) * 1000

            choice = response.choices[0]
            response_message = choice.message

            content = response_message.content or ""
            tool_calls: list[ToolCall] = []

            if response_message.tool_calls:
                for tc in response_message.tool_calls:
                    if not isinstance(tc, ChatCompletionMessageFunctionToolCall):
                        continue
                    arguments: dict[str, Any]
                    try:
                        arguments = json.loads(tc.function.arguments)
                    except json.JSONDecodeError:
                        arguments = {}

                    func_name: str = tc.function.name
                    tool_call = ToolCall(
                        id=tc.id,
                        tool_name=func_name.split(".", maxsplit=1)[0] if "." in func_name else func_name,
                        function_name=func_name,
                        arguments=arguments,
                    )
                    tool_calls.append(tool_call)

            message = Message(
                role="assistant",
                content=content,
                tool_calls=tool_calls if tool_calls else None,
                timestamp=datetime.now(),
            )

            log_provider_response(
                provider="openai",
                model=model,
                tool_calls_count=len(tool_calls),
                duration_ms=duration_ms,
            )

            return message, tool_calls if tool_calls else None

        except openai.RateLimitError as e:
            self._logger.exception(
                "openai_chat_rate_limited",
                extra={"model": model, "error": str(e)},
            )
            raise RateLimitError(f"OpenAI rate limit exceeded: {e}") from e
        except openai.APIError as e:
            self._logger.exception(
                "openai_chat_api_error",
                extra={"model": model, "error": str(e)},
            )
            raise ProviderError(f"OpenAI API error: {e}") from e
        except Exception as e:
            self._logger.exception(
                "openai_chat_failed",
                extra={"model": model, "error": str(e)},
            )
            raise ProviderError(f"OpenAI request failed: {e}") from e

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
            raise ProviderError("Not connected to OpenAI API")

        self._cancel_requested = False

        openai_messages = self._convert_messages_to_provider_format(messages)
        openai_tools: list[dict[str, object]] | None = None
        if tools:
            openai_tools = self._convert_tools_to_provider_format(tools)

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

            async for chunk in stream:
                if self._cancel_requested:
                    break
                if chunk.choices and chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content

        except openai.RateLimitError as e:
            self._logger.exception(
                "openai_stream_rate_limited",
                extra={"model": model, "error": str(e)},
            )
            raise RateLimitError(f"OpenAI rate limit exceeded: {e}") from e
        except openai.APIError as e:
            self._logger.exception(
                "openai_stream_api_error",
                extra={"model": model, "error": str(e)},
            )
            raise ProviderError(f"OpenAI API error: {e}") from e
        except Exception as e:
            if not self._cancel_requested:
                self._logger.exception(
                    "openai_stream_failed",
                    extra={"model": model, "error": str(e)},
                )
                raise ProviderError(f"OpenAI stream failed: {e}") from e

    async def cancel_request(self) -> None:
        """Cancel any in-flight request."""
        self._cancel_requested = True
        if self._current_task is not None and not self._current_task.done():
            self._current_task.cancel()
        self._logger.info(
            "openai_request_cancelled",
            extra={"had_active_task": self._current_task is not None},
        )

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
        openai_messages: list[dict[str, object]] = []

        for msg in messages:
            if msg.role == "system":
                openai_messages.append({
                    "role": "system",
                    "content": msg.content,
                })
            elif msg.role == "user":
                openai_messages.append({
                    "role": "user",
                    "content": msg.content,
                })
            elif msg.role == "assistant":
                assistant_msg: dict[str, object] = {
                    "role": "assistant",
                    "content": msg.content,
                }

                if msg.tool_calls:
                    assistant_msg["tool_calls"] = [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function_name,
                                "arguments": json.dumps(tc.arguments),
                            },
                        }
                        for tc in msg.tool_calls
                    ]

                openai_messages.append(assistant_msg)
            elif msg.role == "tool" and msg.tool_results:
                for tr in msg.tool_results:
                    result_content = tr.result if isinstance(tr.result, str) else json.dumps(tr.result)
                    openai_messages.append({
                        "role": "tool",
                        "tool_call_id": tr.call_id,
                        "content": result_content,
                    })

        return openai_messages

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
