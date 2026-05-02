# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""OpenRouter API provider implementation.

This module provides integration with OpenRouter which provides access to many different LLM providers through a unified API.
"""

from __future__ import annotations

import asyncio
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
    HttpErrorMessages,
    LLMProviderBase,
    ToolCallBufferManager,
    UsageInfo,
)


if TYPE_CHECKING:
    from collections.abc import AsyncIterator


_ERR_NOT_CONNECTED = "Not connected to OpenRouter"
_ERR_KEY_REQUIRED = "OpenRouter API key is required"
_ERR_INVALID_KEY = "Invalid OpenRouter API key: %s"
_ERR_CONNECT_FAILED = "Failed to connect to OpenRouter: %s"
_ERR_LIST_MODELS_FAILED = "Failed to list OpenRouter models: %s"
_ERR_API_ERROR = "OpenRouter API error: %s"
_ERR_RATE_LIMITED = "OpenRouter rate limit exceeded: %s"
_ERR_NO_RESPONSE_CHOICES = "No response choices returned"
_ERR_STREAM_FAILED = "OpenRouter stream failed: %s"
_ERR_GET_GENERATION_FAILED = "Failed to get generation: %s"

HTTP_BAD_REQUEST = 400

_REST_HTTP_MSGS = HttpErrorMessages(
    auth_invalid=_ERR_INVALID_KEY,
    rate_limited=_ERR_RATE_LIMITED,
    service_unavailable=_ERR_API_ERROR,
)


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
        self._current_task: asyncio.Task[object] | None = None
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

        HTTP errors raised by the connect probe are translated to
        Intellicrack typed errors by
        :meth:`LLMProviderBase._raise_typed_for_status`.

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
            self._raise_typed_for_status(e.response.status_code, e, messages=_REST_HTTP_MSGS)
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

        HTTP errors are translated to Intellicrack typed errors by
        :meth:`LLMProviderBase._raise_typed_for_status`.  Transient
        rate-limit failures are retried via
        :meth:`LLMProviderBase._retry_with_backoff`.  ``enable_cache``
        attaches OpenRouter's ``cache_control: ephemeral`` extension to
        the last user message (and last system message) so Anthropic /
        Gemini routes activate prompt caching.  ``thinking`` is
        forwarded as ``reasoning_effort`` (low/medium/high) when set.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration.  Forwarded as
                ``reasoning_effort`` when enabled.
            enable_cache: Whether to enable prompt caching.  When
                ``True``, ``cache_control: ephemeral`` is attached to
                the last system and user message so OpenRouter's
                Anthropic / Gemini backends activate caching.

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of (assistant message, tool calls if any).

        Raises:
            ProviderError: If not connected or request fails.
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

        if enable_cache:
            self._apply_cache_control(openrouter_messages)

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
        reasoning_effort = self._reasoning_effort_for(thinking)
        if reasoning_effort is not None:
            request_body["reasoning"] = {"effort": reasoning_effort}

        chat_task: asyncio.Task[httpx.Response] = asyncio.create_task(
            self._retry_with_backoff(lambda: self._post_chat_completion(request_body=request_body, model=model)),
        )
        self._current_task = cast("asyncio.Task[object]", chat_task)
        try:
            response = await chat_task
        finally:
            self._current_task = None

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

    async def _post_chat_completion(
        self,
        *,
        request_body: dict[str, object],
        model: str,
    ) -> httpx.Response:
        """POST a chat completion request and translate HTTP errors.

        Used as the inner coroutine for
        :meth:`LLMProviderBase._retry_with_backoff` so transient
        rate-limit responses propagate as :class:`RateLimitError` and
        get retried with exponential backoff.

        Args:
            request_body: JSON body for ``POST /chat/completions``.
            model: Model identifier, included in structured logs.

        Returns:
            httpx.Response: Successful response with status 2xx.

        Raises:
            AuthenticationError: When the API rejects credentials.
            ProviderError: On non-retryable failures.
            RateLimitError: On HTTP 429.
        """
        if self.client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)
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
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            self._logger.warning(
                "openrouter_chat_http_error",
                model=model,
                status_code=e.response.status_code,
            )
            self._raise_typed_for_status(e.response.status_code, e, messages=_REST_HTTP_MSGS)
            raise ProviderError(_ERR_API_ERROR % e) from e
        return response

    @staticmethod
    def _reasoning_effort_for(thinking: ThinkingConfig | None) -> str | None:
        """Map a :class:`ThinkingConfig` to OpenRouter's ``reasoning.effort``.

        OpenRouter accepts ``reasoning: {effort: "low" | "medium" |
        "high"}`` and forwards it to backends that support reasoning
        effort (OpenAI o-series, Grok-multi-agent, Claude with
        extended thinking).  Backends that ignore the field receive the
        request unchanged.

        Args:
            thinking: Caller-supplied thinking configuration, or
                ``None``.

        Returns:
            str | None: ``"low"``, ``"medium"``, ``"high"`` when the
            request should set ``reasoning.effort``; ``None`` when the
            parameter must be omitted.
        """
        if thinking is None or not thinking.enabled:
            return None
        budget = thinking.budget_tokens
        if budget <= 4000:
            return "low"
        return "medium" if budget <= 16000 else "high"

    @staticmethod
    def _apply_cache_control(messages: list[dict[str, object]]) -> None:
        """Attach OpenRouter ``cache_control`` markers to long messages.

        OpenRouter exposes Anthropic-style ephemeral prompt caching as
        a per-content-block ``cache_control: {"type": "ephemeral"}``
        marker.  This helper rewrites the last system and last user
        message into the structured-block form (``[{"type": "text",
        "text": ..., "cache_control": {...}}]``) so OpenRouter routes
        cached requests to backends that honour the marker (Anthropic,
        Gemini).  Mutates ``messages`` in place.

        Args:
            messages: List of OpenAI-format message dicts.
        """
        OpenRouterProvider._mark_role_for_cache(messages, role="system")
        OpenRouterProvider._mark_role_for_cache(messages, role="user")

    @staticmethod
    def _mark_role_for_cache(
        messages: list[dict[str, object]],
        *,
        role: str,
    ) -> None:
        """Tag the last message with the given role for caching.

        Walks ``messages`` in reverse, finds the most recent message
        whose ``role`` matches, and rewrites its ``content`` so the
        final block carries ``cache_control: {"type": "ephemeral"}``.

        Args:
            messages: List of OpenAI-format message dicts to mutate.
            role: ``"system"`` or ``"user"``.
        """
        for msg in reversed(messages):
            if msg.get("role") != role:
                continue
            content = msg.get("content")
            if isinstance(content, str):
                msg["content"] = [
                    {
                        "type": "text",
                        "text": content,
                        "cache_control": {"type": "ephemeral"},
                    },
                ]
                return
            if isinstance(content, list) and content:
                blocks = cast("list[dict[str, Any]]", content)
                blocks[-1] = {
                    **blocks[-1],
                    "cache_control": {"type": "ephemeral"},
                }
                return
            return

    @classmethod
    def _raise_for_stream_status(cls, status_code: int, body_text: str) -> None:
        """Raise an Intellicrack typed exception for a streaming HTTP error.

        Wraps the streaming status/body in a synthetic
        :class:`ProviderError` and delegates to
        :meth:`LLMProviderBase._raise_typed_for_status` so 401, 403,
        429, and 503 responses raise the expected typed exception
        (:class:`AuthenticationError` for 401/403,
        :class:`RateLimitError` for 429,
        :class:`ProviderError` for 503). For any other non-success
        status the helper falls through and this method raises a
        :class:`ProviderError` formatted with
        :data:`_ERR_STREAM_FAILED`.

        Args:
            status_code: HTTP status code returned by the streaming
                endpoint.
            body_text: Decoded response body text (or replacement
                bytes when decoding failed).

        Raises:
            ProviderError: For any non-success status that the base
                helper does not translate to a more specific typed
                exception.
        """
        stream_detail = f"HTTP {status_code}: {body_text}"
        stream_exc = ProviderError(stream_detail)
        cls._raise_typed_for_status(status_code, stream_exc, messages=_REST_HTTP_MSGS)
        raise ProviderError(_ERR_STREAM_FAILED % stream_detail) from stream_exc

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

        ``enable_cache`` attaches OpenRouter's ``cache_control:
        ephemeral`` extension to the last user / system message so
        Anthropic and Gemini routes activate caching.  ``thinking`` is
        forwarded as ``reasoning: {effort: ...}`` for backends that
        support it.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration.  Forwarded as
                ``reasoning.effort`` when enabled.
            enable_cache: Whether to enable prompt caching.  Adds the
                ``cache_control: ephemeral`` extension to the last
                user / system message.

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
        if enable_cache:
            self._logger.debug("openrouter_stream_cache_enabled", model=model)

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
        if enable_cache:
            self._apply_cache_control(openrouter_messages)
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
            reasoning_effort = self._reasoning_effort_for(thinking)
            if reasoning_effort is not None:
                request_body["reasoning"] = {"effort": reasoning_effort}

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
                    self._raise_for_stream_status(response.status_code, body_text)
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
                        data = self._safe_parse_stream_json(data_str, logger=self._logger)
                        if data is None:
                            continue
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
        """Cancel any in-flight request.

        Sets the cancel flag (which streaming loops poll) and cancels
        the active non-streaming task when one is registered, so both
        ``chat`` and ``chat_stream`` paths abort cleanly.
        """
        self._cancel_requested = True
        had_active_task = self._current_task is not None and not self._current_task.done()
        if had_active_task and self._current_task is not None:
            self._current_task.cancel()
        self._logger.info(
            "openrouter_request_cancelled",
            connected=self.connected,
            had_active_task=had_active_task,
        )

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
        return self._convert_tools_to_openai_format(tools)

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
