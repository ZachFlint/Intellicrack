# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""OpenRouter API provider implementation.

This module provides integration with OpenRouter which provides access
to many different LLM providers through a unified API.
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from typing import TYPE_CHECKING, Any, cast, override

import httpx

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
from .base import LLMProviderBase


if TYPE_CHECKING:
    from collections.abc import AsyncIterator


_ERR_NOT_CONNECTED = "Not connected to OpenRouter"
_ERR_KEY_REQUIRED = "OpenRouter API key is required"
_ERR_INVALID_KEY = "Invalid OpenRouter API key: %s"
_ERR_CONNECT_FAILED = "Failed to connect to OpenRouter: %s"
_ERR_LIST_MODELS_FAILED = "Failed to list OpenRouter models: %s"
_ERR_API_ERROR = "OpenRouter API error: %s"
_ERR_RATE_LIMITED = "OpenRouter rate limit exceeded"
_ERR_NO_RESPONSE_CHOICES = "No response choices returned"
_ERR_STREAM_FAILED = "OpenRouter stream failed: %s"
_ERR_GET_GENERATION_FAILED = "Failed to get generation: %s"

HTTP_UNAUTHORIZED = 401
HTTP_RATE_LIMITED = 429


class OpenRouterProvider(LLMProviderBase):
    """OpenRouter API provider implementation.

    Provides access to many different LLM models through OpenRouter's
    unified API interface.

    Attributes:
        _client: The httpx async client for API calls.
        _api_key: The OpenRouter API key.
    """

    BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(self) -> None:
        """Initialize the OpenRouter provider."""
        super().__init__()
        self._client: httpx.AsyncClient | None = None
        self._api_key: str | None = None
        self._logger = get_logger("providers.openrouter")

    @property
    def name(self) -> ProviderName:
        """Get the provider's name.

        Returns:
            ProviderName.OPENROUTER
        """
        return ProviderName.OPENROUTER

    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect to OpenRouter API.

        Args:
            credentials: Must contain api_key.

        Raises:
            AuthenticationError: If API key is invalid.
            ProviderError: If connection fails.
        """
        if not credentials.api_key:
            raise AuthenticationError(_ERR_KEY_REQUIRED)

        try:
            self._api_key = credentials.api_key
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(120.0),
                headers={
                    "Authorization": f"Bearer {credentials.api_key}",
                    "HTTP-Referer": "https://intellicrack.local",
                    "X-Title": "Intellicrack",
                },
            )

            response = await self._client.get(f"{self.BASE_URL}/models")
            response.raise_for_status()

            self._credentials = credentials
            self._connected = True
            self._logger.info(
                "openrouter_connected",
                extra={"has_custom_base": credentials.api_base is not None},
            )
        except httpx.HTTPStatusError as e:
            self._logger.warning(
                "openrouter_connect_failed",
                extra={"status_code": e.response.status_code},
            )
            if e.response.status_code == HTTP_UNAUTHORIZED:
                raise AuthenticationError(_ERR_INVALID_KEY % e) from e
            raise ProviderError(_ERR_CONNECT_FAILED % e) from e
        except Exception as e:
            self._logger.warning("openrouter_connect_failed", extra={"error": str(e)})
            raise ProviderError(_ERR_CONNECT_FAILED % e) from e

    async def disconnect(self) -> None:
        """Disconnect from OpenRouter API."""
        await super().disconnect()
        if self._client:
            await self._client.aclose()
            self._client = None
        self._api_key = None
        self._logger.info("openrouter_disconnected", extra={"was_connected": True})

    async def list_models(self) -> list[ModelInfo]:
        """Dynamically fetch available models from OpenRouter.

        Returns:
            List of available models.

        Raises:
            ProviderError: If not connected.
        """
        if not self._connected or self._client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        try:
            response = await self._client.get(f"{self.BASE_URL}/models")
            response.raise_for_status()
            data = response.json()

            models: list[ModelInfo] = []
            for model_data in data.get("data", []):
                model_id = model_data.get("id", "")
                name = model_data.get("name", model_id)
                context_length = model_data.get("context_length", 4096)

                pricing = model_data.get("pricing", {})
                input_cost = pricing.get("prompt")
                output_cost = pricing.get("completion")

                if input_cost is not None:
                    input_cost = float(input_cost) * 1000000
                if output_cost is not None:
                    output_cost = float(output_cost) * 1000000

                models.append(
                    ModelInfo(
                        id=model_id,
                        name=name,
                        provider=ProviderName.OPENROUTER,
                        context_window=context_length,
                        supports_tools=self._estimate_tool_support(model_id),
                        supports_vision=self._estimate_vision_support(model_id),
                        supports_streaming=True,
                        input_cost_per_1m_tokens=input_cost,
                        output_cost_per_1m_tokens=output_cost,
                    )
                )

            sorted_models = sorted(models, key=lambda m: m.id)
            self._logger.info(
                "openrouter_models_listed",
                extra={"count": len(sorted_models)},
            )
        except Exception as e:
            self._logger.warning(
                "openrouter_list_models_failed",
                extra={"error": str(e)},
            )
            raise ProviderError(_ERR_LIST_MODELS_FAILED % e) from e
        else:
            return sorted_models

    @staticmethod
    def _estimate_tool_support(model_id: str) -> bool:
        """Estimate if model supports tool calling.

        Args:
            model_id: The model identifier.

        Returns:
            True if model likely supports tools.
        """
        model_lower = model_id.lower()
        tool_capable_patterns = [
            "gpt-4",
            "gpt-3.5",
            "claude-3",
            "claude-2",
            "gemini",
            "mistral",
            "mixtral",
            "llama-3",
            "llama3",
            "command-r",
        ]
        return any(pattern in model_lower for pattern in tool_capable_patterns)

    @staticmethod
    def _estimate_vision_support(model_id: str) -> bool:
        """Estimate if model supports vision.

        Args:
            model_id: The model identifier.

        Returns:
            True if model likely supports vision.
        """
        model_lower = model_id.lower()
        vision_patterns = [
            "vision",
            "gpt-4o",
            "gpt-4-turbo",
            "claude-3",
            "gemini",
            "llava",
        ]
        return any(pattern in model_lower for pattern in vision_patterns)

    async def chat(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Send a chat completion request through OpenRouter.

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
            raise ProviderError(_ERR_NOT_CONNECTED)

        self._cancel_requested = False

        openrouter_messages = self._convert_messages_to_provider_format(messages)

        tools_count = len(tools) if tools else 0
        self._logger.info(
            "openrouter_chat_started",
            extra={
                "model": model,
                "messages_count": len(messages),
                "tools_count": tools_count,
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
        )

        log_provider_request(
            provider="openrouter",
            model=model,
            messages_count=len(messages),
            tools_count=tools_count,
        )

        start_time = time.perf_counter()

        request_body: dict[str, object] = {
            "model": model,
            "messages": openrouter_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if tools:
            request_body["tools"] = self._convert_tools_to_provider_format(tools)

        try:
            response = await self._client.post(
                f"{self.BASE_URL}/chat/completions",
                json=request_body,
            )
        except httpx.HTTPStatusError as e:
            self._logger.warning(
                "openrouter_chat_http_error",
                extra={"model": model, "status_code": e.response.status_code},
            )
            raise ProviderError(_ERR_API_ERROR % e) from e

        if response.status_code == HTTP_RATE_LIMITED:
            self._logger.warning(
                "openrouter_rate_limited",
                extra={"model": model},
            )
            raise RateLimitError(_ERR_RATE_LIMITED)

        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            self._logger.warning(
                "openrouter_chat_http_error",
                extra={"model": model, "status_code": e.response.status_code},
            )
            raise ProviderError(_ERR_API_ERROR % e) from e

        data = response.json()
        duration_ms = (time.perf_counter() - start_time) * 1000

        choices = data.get("choices", [])
        if not choices:
            raise ProviderError(_ERR_NO_RESPONSE_CHOICES)

        response_message = choices[0].get("message", {})
        content = response_message.get("content", "") or ""
        tool_calls = self._parse_tool_calls_from_response(response_message)

        message = Message(
            role="assistant",
            content=content,
            tool_calls=tool_calls or None,
            timestamp=datetime.now(),
        )

        log_provider_response(
            provider="openrouter",
            model=model,
            tool_calls_count=len(tool_calls),
            duration_ms=duration_ms,
        )

        self._logger.info(
            "openrouter_chat_completed",
            extra={
                "model": model,
                "tool_calls_count": len(tool_calls),
                "duration_ms": round(duration_ms, 2),
                "content_length": len(content),
            },
        )

        return message, tool_calls or None

    def _parse_tool_calls_from_response(
        self,
        response_message: dict[str, Any],
    ) -> list[ToolCall]:
        """Parse tool calls from an OpenRouter response message.

        Args:
            response_message: The message dict from the API response.

        Returns:
            List of parsed ToolCall objects.
        """
        tool_calls: list[ToolCall] = []

        if "tool_calls" not in response_message:
            return tool_calls

        for tc in response_message["tool_calls"]:
            func_data = tc.get("function", {})
            func_name = func_data.get("name", "")
            args_str = func_data.get("arguments", "{}")
            parsed_args: dict[str, Any]
            try:
                parsed_args = json.loads(str(args_str))
            except json.JSONDecodeError:
                self._logger.debug("tool_argument_parse_failed", extra={"raw_args": str(args_str)[:200]})
                parsed_args = {}

            tool_call = ToolCall(
                id=tc.get("id", f"call_{len(tool_calls)}"),
                tool_name=func_name.split(".")[0] if "." in func_name else func_name,
                function_name=func_name,
                arguments=parsed_args,
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
        """Stream a chat completion response from OpenRouter.

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
        """
        if not self._connected or self._client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        self._cancel_requested = False

        openrouter_messages = self._convert_messages_to_provider_format(messages)

        tools_count = len(tools) if tools else 0
        self._logger.info(
            "openrouter_chat_stream_started",
            extra={
                "model": model,
                "messages_count": len(messages),
                "tools_count": tools_count,
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
        )

        chunks_yielded = 0
        try:
            request_body: dict[str, object] = {
                "model": model,
                "messages": openrouter_messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "stream": True,
            }

            if tools:
                request_body["tools"] = self._convert_tools_to_provider_format(tools)

            async with self._client.stream(
                "POST",
                f"{self.BASE_URL}/chat/completions",
                json=request_body,
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if self._cancel_requested:
                        self._logger.info(
                            "openrouter_chat_stream_cancelled",
                            extra={"model": model, "chunks_yielded": chunks_yielded},
                        )
                        break
                    if line.startswith("data: "):
                        data_str = line[6:]
                        if data_str == "[DONE]":
                            break
                        try:
                            data = json.loads(data_str)
                            if choices := data.get("choices", []):
                                delta = choices[0].get("delta", {})
                                if content := delta.get("content", ""):
                                    chunks_yielded += 1
                                    yield content
                        except json.JSONDecodeError as exc:
                            self._logger.debug("stream_json_parse_skipped", extra={"error": str(exc)})
                            continue

            self._logger.info(
                "openrouter_chat_stream_completed",
                extra={"model": model, "chunks_yielded": chunks_yielded},
            )

        except Exception as e:
            if not self._cancel_requested:
                self._logger.warning(
                    "openrouter_chat_stream_failed",
                    extra={"model": model, "chunks_yielded": chunks_yielded, "error": str(e)},
                )
                raise ProviderError(_ERR_STREAM_FAILED % e) from e

    async def cancel_request(self) -> None:
        """Cancel any in-flight request."""
        self._cancel_requested = True
        self._logger.info("openrouter_request_cancelled", extra={"connected": self._connected})

    @override
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Convert internal messages to OpenRouter format.

        Uses OpenAI-compatible format.

        Args:
            messages: List of Message objects.

        Returns:
            List of messages in OpenRouter's format.
        """
        openrouter_messages: list[dict[str, object]] = []

        for msg in messages:
            if msg.role == "system":
                openrouter_messages.append({
                    "role": "system",
                    "content": msg.content,
                })
            elif msg.role == "user":
                openrouter_messages.append({
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

                openrouter_messages.append(assistant_msg)
            elif msg.role == "tool" and msg.tool_results:
                for tr in msg.tool_results:
                    result_content = tr.result if isinstance(tr.result, str) else json.dumps(tr.result)

                    openrouter_messages.append({
                        "role": "tool",
                        "tool_call_id": tr.call_id,
                        "content": result_content,
                    })

        return openrouter_messages

    @override
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Convert internal tools to OpenRouter format.

        Uses OpenAI-compatible format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            List of tools in OpenRouter's format.
        """
        openrouter_tools: list[dict[str, object]] = []

        for tool in tools:
            for func in tool.functions:
                properties: dict[str, dict[str, object]] = {}
                required: list[str] = []

                for param in func.parameters:
                    prop: dict[str, object] = {
                        "type": param.type,
                        "description": param.description,
                    }
                    if param.enum:
                        prop["enum"] = param.enum
                    properties[param.name] = prop
                    if param.required:
                        required.append(param.name)

                openrouter_tools.append({
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
                })

        return openrouter_tools

    async def get_generation(self, generation_id: str) -> dict[str, object]:
        """Get details about a specific generation.

        Args:
            generation_id: The generation ID from a previous response.

        Returns:
            Generation details including cost and tokens used.

        Raises:
            ProviderError: If not connected or request fails.
        """
        if not self._connected or self._client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        self._logger.info(
            "openrouter_get_generation_started",
            extra={"generation_id": generation_id},
        )

        try:
            response = await self._client.get(
                f"{self.BASE_URL}/generation",
                params={"id": generation_id},
            )
            response.raise_for_status()
            result: dict[str, object] = cast("dict[str, object]", response.json())
            self._logger.info(
                "openrouter_get_generation_completed",
                extra={"generation_id": generation_id},
            )
        except Exception as e:
            self._logger.warning(
                "openrouter_get_generation_failed",
                extra={"generation_id": generation_id, "error": str(e)},
            )
            raise ProviderError(_ERR_GET_GENERATION_FAILED % e) from e
        else:
            return result
