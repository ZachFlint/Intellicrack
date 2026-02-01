"""X.AI Grok API provider implementation.

This module provides integration with X.AI's Grok models for
chat completion and tool/function calling. Grok uses an OpenAI-compatible
API, so this implementation leverages the OpenAI SDK with a custom base URL.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime
from typing import TYPE_CHECKING, Any, TypedDict, cast

import openai

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


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from openai.types.chat import ChatCompletionMessageParam, ChatCompletionToolParam


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
        _client: The async OpenAI client instance configured for Grok.
        _current_task: Reference to any in-flight async task.
    """

    BASE_URL: str = "https://api.x.ai/v1"

    def __init__(self) -> None:
        """Initialize the Grok provider."""
        super().__init__()
        self._client: openai.AsyncOpenAI | None = None
        self._current_task: asyncio.Task[object] | None = None
        self._logger = get_logger("providers.grok")

    @property
    def name(self) -> ProviderName:
        """Get the provider's name.

        Returns:
            ProviderName.GROK
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
            raise AuthenticationError("Grok API key is required")

        base_url = credentials.api_base or self.BASE_URL

        try:
            self._client = openai.AsyncOpenAI(
                api_key=credentials.api_key,
                base_url=base_url,
            )
            await self._client.models.list()
            self._credentials = credentials
            self._connected = True
            self._logger.info("grok_api_connected", extra={"base_url": base_url})
        except openai.AuthenticationError as e:
            raise AuthenticationError(f"Invalid Grok API key: {e}") from e
        except openai.BadRequestError as e:
            error_str = str(e).lower()
            if "api key" in error_str or "incorrect" in error_str:
                raise AuthenticationError(f"Invalid Grok API key: {e}") from e
            raise ProviderError(f"Grok API request error: {e}") from e
        except Exception as e:
            raise ProviderError(f"Failed to connect to Grok: {e}") from e

    async def disconnect(self) -> None:
        """Disconnect from Grok API."""
        await super().disconnect()
        self._client = None
        self._current_task = None
        self._logger.info("Disconnected from Grok API")

    async def list_models(self) -> list[ModelInfo]:
        """Dynamically fetch available models from Grok.

        Returns:
            List of available Grok models.

        Raises:
            ProviderError: If not connected.
        """
        if not self._connected or self._client is None:
            raise ProviderError("Not connected to Grok API")

        try:
            response = await self._client.models.list()
            models: list[ModelInfo] = []

            for model_data in response.data:
                model_id = model_data.id
                if not self._is_grok_model(model_id):
                    continue

                context_window = self._get_context_window(model_id)
                supports_tools = self._supports_tools(model_id)
                supports_vision = self._supports_vision(model_id)

                models.append(
                    ModelInfo(
                        id=model_id,
                        name=model_id,
                        provider=ProviderName.GROK,
                        context_window=context_window,
                        supports_tools=supports_tools,
                        supports_vision=supports_vision,
                        supports_streaming=True,
                        input_cost_per_1m_tokens=None,
                        output_cost_per_1m_tokens=None,
                    )
                )

            return sorted(models, key=lambda m: m.id, reverse=True)
        except Exception as e:
            raise ProviderError(f"Failed to list Grok models: {e}") from e

    def _is_grok_model(self, model_id: str) -> bool:
        """Check if model is a valid Grok chat model.

        Args:
            model_id: The model identifier.

        Returns:
            True if model is a Grok model.
        """
        return model_id.startswith("grok-")

    def _get_context_window(self, model_id: str) -> int:
        """Get context window size for a Grok model.

        Args:
            model_id: The model identifier.

        Returns:
            Context window size in tokens.
        """
        if "grok-4" in model_id:
            return 131072
        if "grok-3" in model_id:
            return 131072
        return 32768

    def _supports_tools(self, model_id: str) -> bool:
        """Check if model supports function calling.

        Args:
            model_id: The model identifier.

        Returns:
            True if model supports tools.
        """
        return model_id.startswith("grok-")

    def _supports_vision(self, model_id: str) -> bool:
        """Check if model supports image input.

        Args:
            model_id: The model identifier.

        Returns:
            True if model supports vision.
        """
        return "grok-4" in model_id

    async def chat(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Send a chat completion request to Grok.

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
            raise ProviderError("Not connected to Grok API")

        self._cancel_requested = False

        grok_messages_raw = self._convert_messages_to_provider_format(messages)
        grok_messages_typed = cast("list[ChatCompletionMessageParam]", grok_messages_raw)

        grok_tools_typed: list[ChatCompletionToolParam] | None = None
        if tools:
            grok_tools_raw = self._convert_tools_to_provider_format(tools)
            grok_tools_typed = cast("list[ChatCompletionToolParam]", grok_tools_raw)

        log_provider_request(
            provider="grok",
            model=model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
        )

        start_time = time.perf_counter()

        try:
            if grok_tools_typed:
                response = await self._client.chat.completions.create(
                    model=model,
                    messages=grok_messages_typed,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    tools=grok_tools_typed,
                )
            else:
                response = await self._client.chat.completions.create(
                    model=model,
                    messages=grok_messages_typed,
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
                    tc_function = getattr(tc, "function", None)
                    if tc_function is None:
                        continue
                    try:
                        parsed_args: dict[str, Any] = json.loads(tc_function.arguments)
                    except json.JSONDecodeError:
                        parsed_args = {}

                    func_name = tc_function.name
                    tool_name = func_name.split(".")[0] if "." in func_name else func_name
                    tool_call = ToolCall(
                        id=tc.id,
                        tool_name=tool_name,
                        function_name=func_name,
                        arguments=parsed_args,
                    )
                    tool_calls.append(tool_call)

            message = Message(
                role="assistant",
                content=content,
                tool_calls=tool_calls if tool_calls else None,
                timestamp=datetime.now(),
            )

            log_provider_response(
                provider="grok",
                model=model,
                tool_calls_count=len(tool_calls),
                duration_ms=duration_ms,
            )

            return message, tool_calls if tool_calls else None

        except openai.RateLimitError as e:
            raise RateLimitError(f"Grok rate limit exceeded: {e}") from e
        except openai.APIError as e:
            raise ProviderError(f"Grok API error: {e}") from e
        except Exception as e:
            raise ProviderError(f"Grok request failed: {e}") from e

    async def chat_stream(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AsyncIterator[str]:
        """Stream a chat completion response from Grok.

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
            RateLimitError: If rate limit is exceeded.
        """
        if not self._connected or self._client is None:
            raise ProviderError("Not connected to Grok API")

        self._cancel_requested = False

        grok_messages_raw = self._convert_messages_to_provider_format(messages)
        grok_messages_typed = cast("list[ChatCompletionMessageParam]", grok_messages_raw)

        grok_tools_typed: list[ChatCompletionToolParam] | None = None
        if tools:
            grok_tools_raw = self._convert_tools_to_provider_format(tools)
            grok_tools_typed = cast("list[ChatCompletionToolParam]", grok_tools_raw)

        try:
            if grok_tools_typed:
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

            async for chunk in stream:
                if self._cancel_requested:
                    break
                if chunk.choices and chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content

        except openai.RateLimitError as e:
            raise RateLimitError(f"Grok rate limit exceeded: {e}") from e
        except openai.APIError as e:
            raise ProviderError(f"Grok API error: {e}") from e
        except Exception as e:
            if not self._cancel_requested:
                raise ProviderError(f"Grok stream failed: {e}") from e

    async def cancel_request(self) -> None:
        """Cancel any in-flight request."""
        self._cancel_requested = True
        if self._current_task is not None and not self._current_task.done():
            self._current_task.cancel()

    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Convert internal messages to Grok/OpenAI format.

        Args:
            messages: List of Message objects.

        Returns:
            List of messages in Grok's format.
        """
        grok_messages: list[dict[str, object]] = []

        for msg in messages:
            if msg.role == "system":
                grok_messages.append({
                    "role": "system",
                    "content": msg.content,
                })
            elif msg.role == "user":
                grok_messages.append({
                    "role": "user",
                    "content": msg.content,
                })
            elif msg.role == "assistant":
                assistant_msg: dict[str, object] = {
                    "role": "assistant",
                    "content": msg.content,
                }

                if msg.tool_calls:
                    tool_calls_list: list[dict[str, object]] = [
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
                    assistant_msg["tool_calls"] = tool_calls_list

                grok_messages.append(assistant_msg)
            elif msg.role == "tool" and msg.tool_results:
                for tr in msg.tool_results:
                    result_content = tr.result if isinstance(tr.result, str) else json.dumps(tr.result)

                    grok_messages.append({
                        "role": "tool",
                        "tool_call_id": tr.call_id,
                        "content": result_content,
                    })

        return grok_messages

    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Convert internal tools to Grok/OpenAI format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            List of tools in Grok's format.
        """
        grok_tools: list[dict[str, object]] = []
        for tool in tools:
            tool_schemas = create_openai_tool_schema(tool)
            grok_tools.extend(dict(schema) for schema in tool_schemas)
        return grok_tools
