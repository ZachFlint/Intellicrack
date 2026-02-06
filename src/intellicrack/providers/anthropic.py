"""Anthropic Claude API provider implementation.

This module provides integration with Anthropic's Claude models for
chat completion and tool/function calling.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar, cast, override

import anthropic
from anthropic.types import (
    Message as AnthropicMessage,
    MessageParam,
    TextBlock,
    ToolParam,
    ToolUseBlock,
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
from .base import LLMProviderBase, create_anthropic_tool_schema


if TYPE_CHECKING:
    from asyncio import Task
    from collections.abc import AsyncIterator


_MSG_API_KEY_REQUIRED = "API key required"
_MSG_NOT_CONNECTED = "Not connected"
_MSG_INVALID_API_KEY = "Invalid API key"
_MSG_CONNECTION_FAILED = "Connection failed"
_MSG_REQUEST_FAILED = "Request failed"
_MSG_RATE_LIMITED = "Rate limited"
_MSG_STREAM_FAILED = "Stream failed"


class AnthropicProvider(LLMProviderBase):
    """Anthropic Claude API provider implementation.

    Provides integration with Anthropic's Claude models including
    support for tool/function calling and streaming responses.

    Attributes:
        _client: The async Anthropic client instance.
        _current_task: Reference to any in-flight async task.
    """

    KNOWN_MODELS: ClassVar[list[tuple[str, str, int, bool, bool]]] = [
        ("claude-sonnet-4-20250514", "Claude Sonnet 4", 200000, True, True),
        ("claude-opus-4-20250514", "Claude Opus 4", 200000, True, True),
        ("claude-3-7-sonnet-20250219", "Claude 3.7 Sonnet", 200000, True, True),
        ("claude-3-5-sonnet-20241022", "Claude 3.5 Sonnet", 200000, True, True),
        ("claude-3-5-haiku-20241022", "Claude 3.5 Haiku", 200000, True, True),
        ("claude-3-opus-20240229", "Claude 3 Opus", 200000, True, True),
        ("claude-3-sonnet-20240229", "Claude 3 Sonnet", 200000, True, True),
        ("claude-3-haiku-20240307", "Claude 3 Haiku", 200000, True, True),
    ]

    def __init__(self) -> None:
        """Initialize the Anthropic provider."""
        super().__init__()
        self._client: anthropic.AsyncAnthropic | None = None
        self._current_task: Task[Any] | None = None
        self._logger: logging.Logger = get_logger("providers.anthropic")

    @property
    def name(self) -> ProviderName:
        """Get the provider's name.

        Returns:
            ProviderName.ANTHROPIC
        """
        return ProviderName.ANTHROPIC

    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect to Anthropic API.

        Args:
            credentials: Must contain api_key.

        Raises:
            AuthenticationError: If API key is invalid.
            ProviderError: If connection fails.
        """
        if not credentials.api_key:
            raise AuthenticationError(_MSG_API_KEY_REQUIRED)

        try:
            self._client = anthropic.AsyncAnthropic(
                api_key=credentials.api_key,
                base_url=credentials.api_base,
            )
            await self._client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=1,
                messages=[{"role": "user", "content": "test"}],
            )
        except anthropic.AuthenticationError as e:
            raise AuthenticationError(_MSG_INVALID_API_KEY) from e
        except Exception as e:
            raise ProviderError(_MSG_CONNECTION_FAILED) from e
        else:
            self._credentials = credentials
            self._connected = True
            self._logger.info(
                "anthropic_connected",
                extra={"has_custom_base": credentials.api_base is not None},
            )

    async def disconnect(self) -> None:
        """Disconnect from Anthropic API."""
        await super().disconnect()
        self._client = None
        self._current_task = None
        self._logger.info("anthropic_disconnected", extra={})

    async def list_models(self) -> list[ModelInfo]:
        """Dynamically fetch available Claude models from Anthropic API.

        Uses the /v1/models endpoint to retrieve the current list of
        available models, handling pagination as needed.

        Returns:
            List of available Claude models with their capabilities.

        Raises:
            ProviderError: If not connected or the request fails.
        """
        if not self._connected or self._client is None:
            raise ProviderError(_MSG_NOT_CONNECTED)

        try:
            models: list[ModelInfo] = []
            after_id: str | None = None

            while True:
                if after_id:
                    response = await self._client.models.list(after_id=after_id)
                else:
                    response = await self._client.models.list()

                for model_data in response.data:
                    model_id = model_data.id
                    display_name_attr: object = getattr(model_data, "display_name", model_id)
                    display_name: str = str(display_name_attr) if display_name_attr else model_id

                    models.append(
                        ModelInfo(
                            id=model_id,
                            name=display_name,
                            provider=ProviderName.ANTHROPIC,
                            context_window=self._get_context_window(model_id),
                            supports_tools=self._supports_tools(model_id),
                            supports_vision=self._supports_vision(model_id),
                            supports_streaming=True,
                            input_cost_per_1m_tokens=None,
                            output_cost_per_1m_tokens=None,
                        )
                    )

                if not response.has_more:
                    break
                after_id = response.last_id
        except Exception as e:
            self._logger.warning("anthropic_list_models_failed", extra={"error": str(e)})
            raise ProviderError(_MSG_REQUEST_FAILED) from e
        else:
            self._logger.info("anthropic_models_listed", extra={"count": len(models)})
            return models

    @staticmethod
    def _get_context_window(model_id: str) -> int:
        """Get context window size for a model.

        Args:
            model_id: The model identifier.

        Returns:
            Context window size in tokens.
        """
        return 200000

    @staticmethod
    def _supports_tools(model_id: str) -> bool:
        """Check if model supports function calling.

        Args:
            model_id: The model identifier.

        Returns:
            True if model supports tools.
        """
        return "claude-3" in model_id or "claude-sonnet" in model_id or "claude-opus" in model_id

    @staticmethod
    def _supports_vision(model_id: str) -> bool:
        """Check if model supports image input.

        Args:
            model_id: The model identifier.

        Returns:
            True if model supports vision.
        """
        return "claude-3" in model_id or "claude-sonnet" in model_id or "claude-opus" in model_id

    async def chat(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Send a chat completion request to Claude.

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
            raise ProviderError(_MSG_NOT_CONNECTED)

        self._cancel_requested = False

        system_prompt = self.get_system_prompt(messages)
        anthropic_messages = self._convert_messages_to_provider_format(messages)
        typed_messages = cast("list[MessageParam]", anthropic_messages)
        anthropic_tools: list[dict[str, object]] | None = None
        if tools:
            anthropic_tools = self._convert_tools_to_provider_format(tools)

        log_provider_request(
            provider="anthropic",
            model=model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
        )

        start_time = time.perf_counter()

        try:
            response: AnthropicMessage
            if system_prompt is not None and anthropic_tools:
                response = await self._client.messages.create(
                    model=model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    system=system_prompt,
                    messages=typed_messages,
                    tools=cast("list[ToolParam]", anthropic_tools),
                )
            elif system_prompt is not None:
                response = await self._client.messages.create(
                    model=model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    system=system_prompt,
                    messages=typed_messages,
                )
            elif anthropic_tools:
                response = await self._client.messages.create(
                    model=model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    messages=typed_messages,
                    tools=cast("list[ToolParam]", anthropic_tools),
                )
            else:
                response = await self._client.messages.create(
                    model=model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    messages=typed_messages,
                )

            duration_ms = (time.perf_counter() - start_time) * 1000

            content = ""
            tool_calls: list[ToolCall] = []

            for block in response.content:
                if isinstance(block, TextBlock):
                    content += block.text
                elif isinstance(block, ToolUseBlock):
                    block_input = block.input
                    arguments: dict[str, Any] = dict(block_input)
                    tool_call = ToolCall(
                        id=block.id,
                        tool_name=block.name.split(".")[0] if "." in block.name else block.name,
                        function_name=block.name,
                        arguments=arguments,
                    )
                    tool_calls.append(tool_call)
                    self._logger.debug(
                        "tool_call_parsed",
                        extra={
                            "tool_name": tool_call.tool_name,
                            "arguments_count": len(tool_call.arguments),
                        },
                    )

            message = Message(
                role="assistant",
                content=content,
                tool_calls=tool_calls or None,
                timestamp=datetime.now(),
            )

            log_provider_response(
                provider="anthropic",
                model=model,
                tool_calls_count=len(tool_calls),
                duration_ms=duration_ms,
            )

        except anthropic.RateLimitError as e:
            raise RateLimitError(_MSG_RATE_LIMITED) from e
        except anthropic.APIError as e:
            raise ProviderError(_MSG_REQUEST_FAILED) from e
        except Exception as e:
            raise ProviderError(_MSG_REQUEST_FAILED) from e
        else:
            return message, tool_calls or None

    async def chat_stream(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AsyncIterator[str]:
        """Stream a chat completion response from Claude.

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
            RateLimitError: If rate limited.
        """
        if not self._connected or self._client is None:
            raise ProviderError(_MSG_NOT_CONNECTED)

        self._cancel_requested = False

        system_prompt = self.get_system_prompt(messages)
        anthropic_messages = self._convert_messages_to_provider_format(messages)
        typed_messages = cast("list[MessageParam]", anthropic_messages)
        anthropic_tools: list[dict[str, object]] | None = None
        if tools:
            anthropic_tools = self._convert_tools_to_provider_format(tools)

        try:
            if system_prompt is not None and anthropic_tools:
                stream_context = self._client.messages.stream(
                    model=model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    system=system_prompt,
                    messages=typed_messages,
                    tools=cast("list[ToolParam]", anthropic_tools),
                )
            elif system_prompt is not None:
                stream_context = self._client.messages.stream(
                    model=model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    system=system_prompt,
                    messages=typed_messages,
                )
            elif anthropic_tools:
                stream_context = self._client.messages.stream(
                    model=model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    messages=typed_messages,
                    tools=cast("list[ToolParam]", anthropic_tools),
                )
            else:
                stream_context = self._client.messages.stream(
                    model=model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    messages=typed_messages,
                )

            async with stream_context as stream:
                async for text in stream.text_stream:
                    if self._cancel_requested:
                        break
                    yield text

        except anthropic.RateLimitError as e:
            raise RateLimitError(_MSG_RATE_LIMITED) from e
        except anthropic.APIError as e:
            raise ProviderError(_MSG_REQUEST_FAILED) from e
        except Exception as e:
            if not self._cancel_requested:
                raise ProviderError(_MSG_STREAM_FAILED) from e

    async def cancel_request(self) -> None:
        """Cancel any in-flight request."""
        self._cancel_requested = True
        had_task = False
        if self._current_task is not None and not self._current_task.done():
            self._current_task.cancel()
            had_task = True
        self._logger.info("anthropic_request_cancelled", extra={"had_active_task": had_task})

    @override
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Convert internal messages to Anthropic format.

        Args:
            messages: List of Message objects.

        Returns:
            List of messages in Anthropic's format.
        """
        anthropic_messages: list[dict[str, object]] = []

        for msg in messages:
            if msg.role == "system":
                continue

            if msg.role == "user":
                anthropic_messages.append({
                    "role": "user",
                    "content": msg.content,
                })
            elif msg.role == "assistant":
                content: list[dict[str, object]] = []

                if msg.content:
                    content.append({"type": "text", "text": msg.content})

                if msg.tool_calls:
                    content.extend([
                        {
                            "type": "tool_use",
                            "id": tc.id,
                            "name": tc.function_name,
                            "input": tc.arguments,
                        }
                        for tc in msg.tool_calls
                    ])

                anthropic_messages.append({
                    "role": "assistant",
                    "content": content or msg.content,
                })
            elif msg.role == "tool" and msg.tool_results:
                tool_results: list[dict[str, object]] = []
                for tr in msg.tool_results:
                    result_content = tr.result if isinstance(tr.result, str) else json.dumps(tr.result)

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tr.call_id,
                        "content": result_content,
                        "is_error": not tr.success,
                    })

                anthropic_messages.append({
                    "role": "user",
                    "content": tool_results,
                })

        return anthropic_messages

    @override
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Convert internal tools to Anthropic format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            List of tools in Anthropic's format.
        """
        anthropic_tools: list[dict[str, object]] = []
        for tool in tools:
            tool_schemas = create_anthropic_tool_schema(tool)
            anthropic_tools.extend(cast("dict[str, object]", schema) for schema in tool_schemas)
        return anthropic_tools

    @staticmethod
    def get_system_prompt(messages: list[Message]) -> str | None:
        """Extract and concatenate all system messages into a single prompt.

        Args:
            messages: List of messages to scan.

        Returns:
            Concatenated system prompt content, or None if no system messages.
        """
        system_parts: list[str] = [msg.content for msg in messages if msg.role == "system" and msg.content]
        return "\n\n".join(system_parts) if system_parts else None
