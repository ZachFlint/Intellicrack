# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""OpenRouter API provider implementation.

This module provides integration with OpenRouter which provides access to many different LLM providers through a unified API.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast, override

import httpx

from intellicrack.core.logging import get_logger, log_provider_request, log_provider_response
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
    ToolCallBufferManager,
    UsageInfo,
    create_openai_tool_schema,
)


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

HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_RATE_LIMITED = 429

_logger = get_logger(__name__)


class OpenRouterProvider(LLMProviderBase):
    """OpenRouter API provider implementation.

    Provides access to many different LLM models through OpenRouter's
    unified API interface.

    Attributes:
        BASE_URL: OpenRouter unified LLM API base URL.
    """

    BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(self) -> None:
        """Initialize the OpenRouterProvider instance."""
        super().__init__()
        self.client: httpx.AsyncClient | None = None
        self._api_key: str | None = None
        self._logger = get_logger(__name__).bind(provider="openrouter")
        self._logger.info("openrouter_provider_initialized")

    @property
    def name(self) -> ProviderName:
        """Get the provider's name.

        Returns:
            ProviderName: ProviderName.OPENROUTER
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
            self._logger.error("openrouter_connect_no_api_key")
            raise AuthenticationError(_ERR_KEY_REQUIRED)

        if self.client is not None:
            try:
                await self.client.aclose()
            except (ConnectionError, TimeoutError, OSError, RuntimeError, httpx.HTTPError) as exc:
                self._logger.warning(
                    "openrouter_existing_client_close_error",
                    error=str(exc),
                )
            self.client = None

        try:
            self._api_key = credentials.api_key
            self.client = httpx.AsyncClient(
                timeout=httpx.Timeout(credentials.timeout or 120.0),
                headers={
                    "Authorization": f"Bearer {credentials.api_key}",
                    "HTTP-Referer": credentials.api_base or "http://localhost",
                    "X-Title": "Intellicrack",
                },
            )

            response = await self.client.get(f"{self.BASE_URL}/models")
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            self.connected = False
            self._api_key = None
            if self.client is not None:
                await self.client.aclose()
                self.client = None
            self._logger.warning(
                "openrouter_connect_failed",
                status_code=e.response.status_code,
            )
            if e.response.status_code == HTTP_UNAUTHORIZED:
                raise AuthenticationError(_ERR_INVALID_KEY % e) from e
            raise ProviderError(_ERR_CONNECT_FAILED % e) from e
        except (ConnectionError, TimeoutError, OSError, httpx.HTTPError) as e:
            self.connected = False
            self._api_key = None
            if self.client is not None:
                await self.client.aclose()
                self.client = None
            self._logger.warning("openrouter_connect_failed", error=str(e))
            raise ProviderError(_ERR_CONNECT_FAILED % e) from e
        else:
            self._credentials = credentials
            self.connected = True
            self._logger.info(
                "openrouter_connected",
                has_custom_base=credentials.api_base is not None,
            )

    async def disconnect(self) -> None:
        """Disconnect from OpenRouter API."""
        try:
            await super().disconnect()
            if self.client:
                await self.client.aclose()
                self.client = None
            self._api_key = None
            self._logger.info("openrouter_disconnected", was_connected=True)
        except (ConnectionError, TimeoutError, OSError, RuntimeError) as exc:
            self._logger.warning("disconnect_cleanup_error", error=str(exc))
            self.connected = False

    async def list_models(self) -> list[ModelInfo]:
        """Dynamically fetch available models from OpenRouter.

        Returns:
            list[ModelInfo]: List of available models.

        Raises:
            ProviderError: If not connected.
        """
        if not self.connected or self.client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        try:
            response = await self.client.get(f"{self.BASE_URL}/models")
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
                    try:
                        input_cost = float(input_cost) * 1000000
                    except (ValueError, TypeError):
                        self._logger.debug("input_cost_parse_failed", model=model_id)
                        input_cost = None
                if output_cost is not None:
                    try:
                        output_cost = float(output_cost) * 1000000
                    except (ValueError, TypeError):
                        self._logger.debug("output_cost_parse_failed", model=model_id)
                        output_cost = None

                architecture: dict[str, object] = model_data.get("architecture", {})
                modality = str(architecture.get("modality", ""))
                supports_vision = "image" in modality

                supported_params: list[str] = [str(p) for p in model_data.get("supported_parameters", [])]
                supports_tools = "tools" in supported_params or "tool_choice" in supported_params
                if not supports_tools and not supported_params:
                    supports_tools = any(family in model_id.lower() for family in ("claude", "gpt", "gemini", "llama-3", "qwen"))

                models.append(
                    ModelInfo(
                        id=model_id,
                        name=name,
                        provider=ProviderName.OPENROUTER,
                        context_window=context_length,
                        supports_tools=supports_tools,
                        supports_vision=supports_vision,
                        supports_streaming=True,
                        input_cost_per_1m_tokens=input_cost,
                        output_cost_per_1m_tokens=output_cost,
                    ),
                )

            sorted_models = sorted(models, key=lambda m: m.id)
            self._logger.info(
                "openrouter_models_listed",
                count=len(sorted_models),
            )
        except (ConnectionError, TimeoutError, OSError, httpx.HTTPError, ValueError) as e:
            self._logger.warning(
                "openrouter_list_models_failed",
                error=str(e),
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
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Send a chat completion request through OpenRouter.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration (ignored by OpenRouter).
            enable_cache: Whether to enable prompt caching (ignored by OpenRouter).

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of (assistant message, tool calls if any).

        Raises:
            AuthenticationError: If the API key is rejected by OpenRouter.
            ProviderError: If not connected or request fails.
            RateLimitError: If rate limited.
        """
        if not self.connected or self.client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        self._cancel_requested = False
        self._pending_usage = None

        openrouter_messages = self.convert_messages_to_provider_format(messages)

        tools_count = len(tools) if tools else 0
        self._logger.info(
            "openrouter_chat_started",
            model=model,
            messages_count=len(messages),
            tools_count=tools_count,
            temperature=temperature,
            max_tokens=max_tokens,
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
            request_body["tools"] = self.convert_tools_to_provider_format(tools)
        if tool_choice is not None and tools:
            request_body["tool_choice"] = self._convert_tool_choice_to_openai_format(tool_choice)
        if thinking is not None and thinking.enabled:
            self._logger.debug("openrouter_thinking_ignored")
        if enable_cache:
            self._logger.debug("openrouter_cache_ignored")

        try:
            response = await self.client.post(
                f"{self.BASE_URL}/chat/completions",
                json=request_body,
            )
        except httpx.RequestError as e:
            self._logger.warning(
                "openrouter_chat_request_error",
                model=model,
                error=str(e),
            )
            raise ProviderError(_ERR_API_ERROR % e) from e

        if response.status_code == HTTP_RATE_LIMITED:
            self._logger.warning(
                "openrouter_rate_limited",
                model=model,
            )
            raise RateLimitError(_ERR_RATE_LIMITED)

        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            self._logger.warning(
                "openrouter_chat_http_error",
                model=model,
                status_code=e.response.status_code,
            )
            if e.response.status_code == HTTP_UNAUTHORIZED:
                raise AuthenticationError(_ERR_INVALID_KEY % e) from e
            raise ProviderError(_ERR_API_ERROR % e) from e

        data = response.json()
        duration_ms = (time.perf_counter() - start_time) * 1000

        choices = data.get("choices", [])
        if not choices:
            raise ProviderError(_ERR_NO_RESPONSE_CHOICES)

        response_message = choices[0].get("message", {})
        content_raw = response_message.get("content")
        content = content_raw if isinstance(content_raw, str) else ""
        tool_calls = self._parse_tool_calls_from_response(response_message)
        self._pending_usage = self._build_usage_from_data(data)

        message = Message(
            role="assistant",
            content=content,
            tool_calls=tool_calls or None,
            timestamp=datetime.now(tz=UTC),
        )

        log_provider_response(
            provider="openrouter",
            model=model,
            tool_calls_count=len(tool_calls),
            duration_ms=duration_ms,
        )

        self._logger.info(
            "openrouter_chat_completed",
            model=model,
            tool_calls_count=len(tool_calls),
            duration_ms=round(duration_ms, 2),
            content_length=len(content),
        )

        return message, tool_calls or None

    @staticmethod
    def _raise_stream_http_error(status_code: int, body_text: str) -> None:
        """Translate a stream HTTP error into the appropriate typed exception.

        Args:
            status_code: HTTP status code returned by OpenRouter.
            body_text: Decoded response body text from OpenRouter.

        Raises:
            AuthenticationError: If OpenRouter returned HTTP 401.
            RateLimitError: If OpenRouter returned HTTP 429.
            ProviderError: For any other non-success HTTP status.
        """
        if status_code == HTTP_UNAUTHORIZED:
            msg = f"{_ERR_INVALID_KEY % status_code}: {body_text}"
            _logger.warning("openrouter_stream_unauthorized", status_code=status_code)
            raise AuthenticationError(msg)
        if status_code == HTTP_RATE_LIMITED:
            msg = f"{_ERR_RATE_LIMITED}: {body_text}"
            _logger.warning("openrouter_stream_rate_limited", status_code=status_code)
            raise RateLimitError(msg)
        _logger.error("openrouter_stream_http_error", status_code=status_code)
        raise ProviderError(_ERR_STREAM_FAILED % f"HTTP {status_code}: {body_text}")

    @staticmethod
    def _build_usage_from_data(data: dict[str, Any]) -> UsageInfo | None:
        """Extract token-usage statistics from an OpenRouter response body.

        Args:
            data: The decoded JSON response body.

        Returns:
            UsageInfo | None: Populated UsageInfo when usage is present on
            the response, otherwise ``None``.
        """
        usage_raw = data.get("usage")
        if not isinstance(usage_raw, dict):
            return None
        usage_dict: dict[str, Any] = cast("dict[str, Any]", usage_raw)
        try:
            prompt = int(usage_dict.get("prompt_tokens") or 0)
            completion = int(usage_dict.get("completion_tokens") or 0)
            total = int(usage_dict.get("total_tokens") or 0) or (prompt + completion)
        except (TypeError, ValueError):
            return None
        return UsageInfo(
            prompt_tokens=prompt,
            completion_tokens=completion,
            total_tokens=total,
        )

    def _parse_tool_calls_from_response(
        self,
        response_message: dict[str, Any],
    ) -> list[ToolCall]:
        """Parse tool calls from an OpenRouter response message.

        Args:
            response_message: The message dict from the API response.

        Returns:
            list[ToolCall]: List of parsed ToolCall objects.
        """
        tool_calls: list[ToolCall] = []

        if "tool_calls" not in response_message:
            return tool_calls

        for tc in response_message["tool_calls"]:
            func_data = tc.get("function", {})
            tool_call = self._parse_tool_call_common(
                call_id=tc.get("id", f"call_{uuid.uuid4().hex}"),
                function_name=func_data.get("name", ""),
                raw_arguments=func_data.get("arguments", "{}"),
            )
            tool_calls.append(tool_call)

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
        *,
        enable_cache: bool = False,
    ) -> AsyncIterator[str]:
        """Stream a chat completion response from OpenRouter.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration (ignored by OpenRouter).
            enable_cache: Whether to enable prompt caching (ignored by OpenRouter).

        Yields:
            str: Text chunks as they arrive.

        Raises:
            AuthenticationError: If the API key is rejected by OpenRouter.
            RateLimitError: If OpenRouter returns HTTP 429 during streaming.
            ProviderError: If not connected or request fails.
        """
        if not self.connected or self.client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        self._cancel_requested = False
        self._pending_usage = None
        if thinking is not None and thinking.enabled:
            self._logger.debug("openrouter_stream_thinking_ignored")
        if enable_cache:
            self._logger.debug("openrouter_stream_cache_ignored")

        openrouter_messages = self.convert_messages_to_provider_format(messages)

        tools_count = len(tools) if tools else 0
        self._logger.info(
            "openrouter_chat_stream_started",
            model=model,
            messages_count=len(messages),
            tools_count=tools_count,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        chunks_yielded = 0
        tc_buffer = ToolCallBufferManager()
        try:
            request_body: dict[str, object] = {
                "model": model,
                "messages": openrouter_messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "stream": True,
                "stream_options": {"include_usage": True},
            }

            if tools:
                request_body["tools"] = self.convert_tools_to_provider_format(tools)
            if tool_choice is not None and tools:
                request_body["tool_choice"] = self._convert_tool_choice_to_openai_format(tool_choice)

            async with self.client.stream(
                "POST",
                f"{self.BASE_URL}/chat/completions",
                json=request_body,
            ) as response:
                if response.status_code >= HTTP_BAD_REQUEST:
                    body_bytes = await response.aread()
                    body_text = body_bytes.decode("utf-8", errors="replace")
                    self._logger.warning(
                        "openrouter_chat_stream_http_error",
                        model=model,
                        status_code=response.status_code,
                        response_size=len(body_bytes),
                        response_excerpt=body_text[:256],
                    )
                    self._raise_stream_http_error(response.status_code, body_text)
                async for line in response.aiter_lines():
                    if self._cancel_requested:
                        self._logger.info(
                            "openrouter_chat_stream_cancelled",
                            model=model,
                            chunks_yielded=chunks_yielded,
                        )
                        break
                    if line.startswith("data: "):
                        data_str = line[6:]
                        if data_str == "[DONE]":
                            break
                        try:
                            data = json.loads(data_str)
                            chunk_usage = self._build_usage_from_data(data)
                            if chunk_usage is not None:
                                self._pending_usage = chunk_usage
                            if choices := data.get("choices", []):
                                delta = choices[0].get("delta", {})
                                if content := delta.get("content", ""):
                                    chunks_yielded += 1
                                    yield content
                                if tc_deltas := delta.get("tool_calls"):
                                    for tc_d in tc_deltas:
                                        fn = cast("dict[str, Any]", tc_d.get("function") or {})
                                        tc_buffer.accumulate(
                                            index=cast("int", tc_d.get("index", 0)),
                                            call_id=cast("str | None", tc_d.get("id")),
                                            name=cast("str | None", fn.get("name")),
                                            arguments=cast("str | None", fn.get("arguments")),
                                        )
                        except json.JSONDecodeError as exc:
                            self._logger.warning("stream_json_parse_skipped", error=str(exc))
                            continue

            self._pending_tool_calls = tc_buffer.finalize()

            self._logger.info(
                "openrouter_chat_stream_completed",
                model=model,
                chunks_yielded=chunks_yielded,
            )

        except (AuthenticationError, RateLimitError, ProviderError):
            raise
        except (ConnectionError, TimeoutError, OSError, httpx.HTTPError, ValueError) as e:
            if not self._cancel_requested:
                self._logger.warning(
                    "openrouter_chat_stream_failed",
                    model=model,
                    chunks_yielded=chunks_yielded,
                    error=str(e),
                )
                raise ProviderError(_ERR_STREAM_FAILED % e) from e

    async def cancel_request(self) -> None:
        """Cancel any in-flight request."""
        self._cancel_requested = True
        self._logger.info("openrouter_request_cancelled", connected=self.connected)

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
            list[dict[str, object]]: List of messages in OpenRouter's format.
        """
        return self._convert_messages_to_openai_format(messages)

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
            list[dict[str, object]]: List of tools in OpenRouter's format.
        """
        openrouter_tools: list[dict[str, object]] = []
        for tool in tools:
            tool_schemas = create_openai_tool_schema(tool)
            openrouter_tools.extend(dict(schema) for schema in tool_schemas)
        return openrouter_tools

    async def get_generation(self, generation_id: str) -> dict[str, object]:
        """Get details about a specific generation.

        Args:
            generation_id: The generation ID from a previous response.

        Returns:
            dict[str, object]: Generation details including cost and tokens used.

        Raises:
            ProviderError: If not connected or request fails.
        """
        if not self.connected or self.client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        self._logger.info(
            "openrouter_get_generation_started",
            generation_id=generation_id,
        )

        try:
            response = await self.client.get(
                f"{self.BASE_URL}/generation",
                params={"id": generation_id},
            )
            response.raise_for_status()
            result: dict[str, object] = cast("dict[str, object]", response.json())
            self._logger.info(
                "openrouter_get_generation_completed",
                generation_id=generation_id,
            )
        except (ConnectionError, TimeoutError, OSError, httpx.HTTPError, ValueError) as e:
            self._logger.warning(
                "openrouter_get_generation_failed",
                generation_id=generation_id,
                error=str(e),
            )
            raise ProviderError(_ERR_GET_GENERATION_FAILED % e) from e
        else:
            return result
