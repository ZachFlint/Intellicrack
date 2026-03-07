# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Anthropic Claude API provider implementation.

This module provides integration with Anthropic's Claude models for
chat completion and tool/function calling.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, cast, override

import anthropic
from anthropic.types import (
    Message as AnthropicMessage,
    MessageParam,
    TextBlock,
    ToolParam,
    ToolUseBlock,
)

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
from .base import LLMProviderBase, create_anthropic_tool_schema


if TYPE_CHECKING:
    import logging
    from asyncio import Task
    from collections.abc import AsyncIterator


_MSG_API_KEY_REQUIRED = "API key required"
_MSG_NOT_CONNECTED = "Not connected"
_MSG_INVALID_API_KEY = "Invalid API key"
_MSG_CONNECTION_FAILED = "Connection failed"
_MSG_REQUEST_FAILED = "Request failed"
_MSG_RATE_LIMITED = "Rate limited"
_MSG_STREAM_FAILED = "Stream failed"
_MSG_NO_MODELS_AVAILABLE = "No models available from Anthropic API"
_MSG_FETCH_MODELS_FAILED = "Failed to fetch models from Anthropic API"


class AnthropicProvider(LLMProviderBase):
    """Anthropic Claude API provider implementation.

    Provides integration with Anthropic's Claude models including
    support for tool/function calling and streaming responses.

    Attributes:
        _client: The async Anthropic client instance.
        _current_task: Reference to any in-flight async task.
    """

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
            await self._client.models.list(limit=1)
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
        try:
            await super().disconnect()
            self._client = None
            self._current_task = None
            self._logger.info("anthropic_disconnected", extra={})
        except Exception as exc:
            self._logger.warning("disconnect_cleanup_error", extra={"error": str(exc)})
            self._connected = False

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
            models = await self._fetch_all_models()
        except Exception as e:
            self._logger.warning(
                "anthropic_list_models_api_failed",
                extra={"error": str(e)},
            )
            raise ProviderError(_MSG_FETCH_MODELS_FAILED) from e
        else:
            self._logger.info("anthropic_models_listed", extra={"count": len(models)})
            return models

    async def _fetch_all_models(self) -> list[ModelInfo]:
        """Paginate through the models endpoint and collect all results.

        Returns:
            Complete list of ModelInfo objects from all pages.
        """
        client = self._client
        if client is None:
            return []

        models: list[ModelInfo] = []
        after_id: str | None = None

        while True:
            page = await client.models.list(after_id=after_id) if after_id else await client.models.list()
            models.extend(self._build_model_info(m.id, getattr(m, "display_name", m.id)) for m in page.data)
            if not page.has_more:
                break
            after_id = page.last_id

        return models

    @staticmethod
    def _build_model_info(model_id: str, display_name_raw: object) -> ModelInfo:
        """Construct a ModelInfo from API model data.

        All Anthropic chat models support tools, vision, and streaming with
        a 200k token context window.  No hardcoded model-name checks are
        used; capabilities default to permissive values.

        Args:
            model_id: The model identifier string.
            display_name_raw: Raw display name attribute from the API.

        Returns:
            Populated ModelInfo instance.
        """
        display_name: str = str(display_name_raw) if display_name_raw else model_id
        return ModelInfo(
            id=model_id,
            name=display_name,
            provider=ProviderName.ANTHROPIC,
            context_window=200000,
            supports_tools=True,
            supports_vision=True,
            supports_streaming=True,
            input_cost_per_1m_tokens=None,
            output_cost_per_1m_tokens=None,
        )

    @staticmethod
    def _build_api_kwargs(
        *,
        model: str,
        max_tokens: int,
        temperature: float,
        messages: list[MessageParam],
        system_prompt: str | None,
        tools: list[dict[str, object]] | None,
    ) -> dict[str, Any]:
        """Build keyword arguments for the Anthropic messages API.

        Args:
            model: Model ID to use.
            max_tokens: Maximum tokens in response.
            temperature: Sampling temperature.
            messages: Formatted message list.
            system_prompt: Optional system prompt text.
            tools: Optional formatted tools list.

        Returns:
            Keyword arguments dict for messages.create or messages.stream.
        """
        kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": messages,
        }
        if system_prompt is not None:
            kwargs["system"] = system_prompt
        if tools:
            provider_tools: list[ToolParam] = cast("list[ToolParam]", tools)
            kwargs["tools"] = provider_tools
        return kwargs

    def _parse_response_blocks(
        self,
        response: AnthropicMessage,
    ) -> tuple[str, list[ToolCall]]:
        """Extract text content and tool calls from response content blocks.

        Args:
            response: The Anthropic API response message.

        Returns:
            Tuple of (concatenated text content, list of parsed tool calls).
        """
        content = ""
        tool_calls: list[ToolCall] = []

        for block in response.content:
            if isinstance(block, TextBlock):
                content += block.text
            elif isinstance(block, ToolUseBlock):
                tool_call = self._parse_tool_call_common(
                    call_id=block.id,
                    function_name=block.name,
                    raw_arguments=block.input,
                )
                tool_calls.append(tool_call)
                self._logger.debug(
                    "tool_call_parsed",
                    extra={
                        "tool_name": tool_call.tool_name,
                        "arguments_count": len(tool_call.arguments),
                    },
                )

        return content, tool_calls

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
        api_kwargs = self._build_api_kwargs(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=typed_messages,
            system_prompt=system_prompt,
            tools=anthropic_tools,
        )

        try:
            response = cast("AnthropicMessage", await self._client.messages.create(**api_kwargs))
            duration_ms = (time.perf_counter() - start_time) * 1000
            content, tool_calls = self._parse_response_blocks(response)
            return self._build_chat_response(
                provider="anthropic",
                model=model,
                content=content,
                tool_calls=tool_calls,
                duration_ms=duration_ms,
            )
        except anthropic.RateLimitError as e:
            raise RateLimitError(_MSG_RATE_LIMITED) from e
        except Exception as e:
            raise ProviderError(_MSG_REQUEST_FAILED) from e

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

        api_kwargs = self._build_api_kwargs(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=typed_messages,
            system_prompt=system_prompt,
            tools=anthropic_tools,
        )

        try:
            stream_context = self._client.messages.stream(**api_kwargs)
            async with stream_context as stream:
                async for text in stream.text_stream:
                    if self._cancel_requested:
                        break
                    yield text

                if not self._cancel_requested:
                    final_message = await stream.get_final_message()
                    tool_calls: list[ToolCall] = []
                    for block in final_message.content:
                        if block.type == "tool_use":
                            args: dict[str, object] = dict(block.input)
                            tool_calls.append(
                                ToolCall(
                                    id=block.id,
                                    tool_name=block.name.split(".")[0] if "." in block.name else block.name,
                                    function_name=block.name,
                                    arguments=args,
                                )
                            )
                    self._pending_tool_calls = tool_calls

        except anthropic.RateLimitError as e:
            raise RateLimitError(_MSG_RATE_LIMITED) from e
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
        result: list[dict[str, object]] = []
        for msg in messages:
            converted = self._convert_single_message(msg)
            if converted is not None:
                result.append(converted)
        return result

    def _convert_single_message(self, msg: Message) -> dict[str, object] | None:
        """Route a single message to its role-specific formatter.

        Args:
            msg: The message to convert.

        Returns:
            Formatted message dict, or None if the role should be skipped.
        """
        if msg.role == "system":
            return None
        if msg.role == "user":
            return self._format_user_message(msg)
        if msg.role == "assistant":
            return self._format_assistant_message(msg)
        return self._format_tool_message(msg)

    @staticmethod
    def _format_user_message(msg: Message) -> dict[str, object]:
        """Format a user message for the Anthropic API.

        Args:
            msg: The user message.

        Returns:
            Anthropic-formatted user message dict.
        """
        return {"role": "user", "content": msg.content}

    @staticmethod
    def _format_assistant_message(msg: Message) -> dict[str, object]:
        """Format an assistant message for the Anthropic API.

        Args:
            msg: The assistant message.

        Returns:
            Anthropic-formatted assistant message dict.
        """
        content: list[dict[str, object]] = []
        if msg.content:
            content.append({"type": "text", "text": msg.content})
        if msg.tool_calls:
            content.extend(
                {
                    "type": "tool_use",
                    "id": tc.id,
                    "name": tc.function_name,
                    "input": tc.arguments,
                }
                for tc in msg.tool_calls
            )
        return {"role": "assistant", "content": content or msg.content}

    @staticmethod
    def _format_tool_message(msg: Message) -> dict[str, object] | None:
        """Format a tool result message for the Anthropic API.

        Args:
            msg: The tool result message.

        Returns:
            Anthropic-formatted tool result dict, or None if no results.
        """
        if not msg.tool_results:
            return None
        tool_results: list[dict[str, object]] = [
            {
                "type": "tool_result",
                "tool_use_id": tr.call_id,
                "content": LLMProviderBase._serialize_tool_result(tr.result),
                "is_error": not tr.success,
            }
            for tr in msg.tool_results
        ]
        return {"role": "user", "content": tool_results}

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
