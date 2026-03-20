# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""HuggingFace Inference API provider implementation.

This module provides integration with HuggingFace's Inference API for
accessing various open-source LLM models through the serverless API.
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any, ClassVar, override

import httpx


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

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


_ERR_NOT_CONNECTED = "Not connected to HuggingFace"
_ERR_CREDENTIAL_REQUIRED = "HuggingFace API token is required"
_ERR_CREDENTIAL_INVALID = "Invalid HuggingFace API token: %s"
_ERR_CONNECT_FAILED = "Failed to connect to HuggingFace: %s"
_ERR_LIST_MODELS_FAILED = "Failed to list HuggingFace models: %s"
_ERR_NO_RESPONSE_CHOICES = "No response choices returned"
_ERR_API_ERROR = "HuggingFace API error: %s"
_ERR_RATE_LIMITED = "HuggingFace rate limit exceeded"
_ERR_MODEL_LOADING = "Model is loading: %s"
_ERR_MODEL_LOADING_WAIT = "Model is loading. Please wait and try again."
_ERR_STREAM_FAILED = "HuggingFace stream failed: %s"

HTTP_UNAUTHORIZED = 401
HTTP_RATE_LIMITED = 429
HTTP_SERVICE_UNAVAILABLE = 503


class HuggingFaceProvider(LLMProviderBase):
    """HuggingFace Inference API provider implementation.

    Provides access to open-source LLM models through HuggingFace's
    Inference API using the OpenAI-compatible chat completions endpoint.

    Attributes:
        _client: The httpx async client for API calls.
        _api_token: The HuggingFace API token.
    """

    BASE_URL: ClassVar[str] = "https://api-inference.huggingface.co"
    MODELS_API_URL: ClassVar[str] = "https://huggingface.co/api/models"

    def __init__(self) -> None:
        """Initialize the HuggingFace provider."""
        super().__init__()
        self._client: httpx.AsyncClient | None = None
        self._api_token: str | None = None
        self._base_url: str = self.BASE_URL
        self._logger = get_logger("providers.huggingface").bind(provider="huggingface")

    @property
    def name(self) -> ProviderName:
        """Get the provider's name.

        Returns:
            The provider name enum value.
        """
        return ProviderName.HUGGINGFACE

    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect to HuggingFace Inference API.

        Args:
            credentials: Must contain api_key (HuggingFace token).

        Raises:
            AuthenticationError: If API token is invalid or missing.
            ProviderError: If connection fails.
        """
        if not credentials.api_key:
            raise AuthenticationError(_ERR_CREDENTIAL_REQUIRED)

        try:
            self._api_token = credentials.api_key
            if credentials.api_base:
                self._base_url = credentials.api_base
            else:
                self._base_url = self.BASE_URL

            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(credentials.timeout or 120.0),
                headers={
                    "Authorization": f"Bearer {credentials.api_key}",
                },
            )

            response = await self._client.get(
                self.MODELS_API_URL,
                params={
                    "filter": "text-generation",
                    "limit": 1,
                },
            )
            response.raise_for_status()

            self._credentials = credentials
            self._connected = True
            self._logger.info(
                "huggingface_connected",
                has_custom_base=credentials.api_base is not None,
            )
        except httpx.HTTPStatusError as e:
            self._logger.warning(
                "huggingface_connect_failed",
                status_code=e.response.status_code,
            )
            if e.response.status_code == HTTP_UNAUTHORIZED:
                raise AuthenticationError(_ERR_CREDENTIAL_INVALID % e) from e
            raise ProviderError(_ERR_CONNECT_FAILED % e) from e
        except Exception as e:
            self._logger.warning(
                "huggingface_connect_failed",
                error_type=type(e).__name__,
            )
            raise ProviderError(_ERR_CONNECT_FAILED % e) from e

    async def disconnect(self) -> None:
        """Disconnect from HuggingFace API and clean up resources."""
        try:
            was_connected = self._connected
            await super().disconnect()
            if self._client:
                await self._client.aclose()
                self._client = None
            self._api_token = None
            self._base_url = self.BASE_URL
            self._logger.info(
                "huggingface_disconnected",
                was_connected=was_connected,
            )
        except Exception as exc:
            self._logger.warning("disconnect_cleanup_error", error=str(exc))
            self._connected = False

    async def list_models(self) -> list[ModelInfo]:
        """Dynamically fetch available text-generation models from HuggingFace.

        Fetches models from the HuggingFace Hub API, filtering for
        text-generation and conversational pipeline tags. Also includes
        recommended models that may not appear in the default listing.

        Returns:
            List of available models with their capabilities.

        Raises:
            ProviderError: If not connected or request fails.
        """
        if not self._connected or self._client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        try:
            response = await self._client.get(
                self.MODELS_API_URL,
                params={
                    "filter": "text-generation-inference",
                    "sort": "downloads",
                    "direction": -1,
                    "limit": 100,
                },
            )
            response.raise_for_status()
            data = response.json()

            models: list[ModelInfo] = []
            seen_ids: set[str] = set()

            for model_data in data:
                model_id = model_data.get("id", "")
                if not model_id or model_id in seen_ids:
                    continue

                pipeline_tag: str = model_data.get("pipeline_tag", "")
                if pipeline_tag not in {"text-generation", "conversational"}:
                    continue

                seen_ids.add(model_id)

                tags: list[str] = [str(t).lower() for t in model_data.get("tags", [])]

                tool_indicators = frozenset({
                    "function-calling",
                    "tool-use",
                    "tool_use",
                    "function_calling",
                })
                supports_tools = bool(tool_indicators & set(tags))

                vision_indicators = frozenset({
                    "vision",
                    "image-text-to-text",
                    "multimodal",
                    "visual-question-answering",
                })
                supports_vision = bool(vision_indicators & set(tags)) or pipeline_tag in {"image-text-to-text", "visual-question-answering"}

                models.append(
                    ModelInfo(
                        id=model_id,
                        name=model_id.split("/")[-1] if "/" in model_id else model_id,
                        provider=ProviderName.HUGGINGFACE,
                        context_window=4096,
                        supports_tools=supports_tools,
                        supports_vision=supports_vision,
                        supports_streaming=True,
                        input_cost_per_1m_tokens=None,
                        output_cost_per_1m_tokens=None,
                    )
                )

            self._logger.info(
                "huggingface_models_listed",
                count=len(models),
            )
        except Exception as e:
            self._logger.warning(
                "huggingface_list_models_failed",
                error_type=type(e).__name__,
            )
            raise ProviderError(_ERR_LIST_MODELS_FAILED % e) from e
        else:
            return models

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
        """Send a chat completion request through HuggingFace Inference API.

        Args:
            messages: Conversation history.
            model: Model ID to use (e.g., 'meta-llama/Llama-3.1-8B-Instruct').
            tools: Available tools for function calling.
            temperature: Sampling temperature (0.0 to 2.0).
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration (ignored by HuggingFace).
            enable_cache: Whether to enable prompt caching (ignored by HuggingFace).

        Returns:
            Tuple of (assistant message, tool calls if any).

        Raises:
            ProviderError: If not connected, model loading, or request fails.
        """
        if not self._connected or self._client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        self._cancel_requested = False
        if thinking is not None and thinking.enabled:
            self._logger.debug("huggingface_thinking_ignored")
        if enable_cache:
            self._logger.debug("huggingface_cache_ignored")

        hf_messages = self._convert_messages_to_provider_format(messages)

        log_provider_request(
            provider="huggingface",
            model=model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
        )

        request_body: dict[str, object] = {
            "model": model,
            "messages": hf_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }
        if tools:
            request_body["tools"] = self._convert_tools_to_provider_format(tools)
        if tool_choice is not None and tools:
            request_body["tool_choice"] = self._convert_tool_choice_to_openai_format(tool_choice)

        start_time = time.perf_counter()
        data = await self._make_hf_api_call(model=model, request_body=request_body)
        duration_ms = (time.perf_counter() - start_time) * 1000

        choices = data.get("choices", [])
        if not choices:
            raise ProviderError(_ERR_NO_RESPONSE_CHOICES)

        response_message = choices[0].get("message", {})
        content = response_message.get("content", "") or ""
        tool_calls = self._parse_hf_tool_calls(response_message)

        self._logger.info(
            "huggingface_chat_completed",
            model=model,
            messages_count=len(messages),
            tool_calls_count=len(tool_calls),
            duration_ms=round(duration_ms, 2),
            has_tools=tools is not None,
        )

        return self._build_chat_response(
            provider="huggingface",
            model=model,
            content=content,
            tool_calls=tool_calls,
            duration_ms=duration_ms,
        )

    async def _make_hf_api_call(
        self,
        *,
        model: str,
        request_body: dict[str, object],
    ) -> dict[str, Any]:
        """Execute the HuggingFace API chat call with error handling.

        Args:
            model: Model ID for URL construction and logging.
            request_body: The request payload.

        Returns:
            Parsed JSON response dictionary.

        Raises:
            ProviderError: If the API call fails or model is loading.
            RateLimitError: If rate limited by the API.
        """
        if self._client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        try:
            response = await self._client.post(
                f"{self._base_url}/models/{model}/v1/chat/completions",
                json=request_body,
            )
        except httpx.HTTPStatusError as e:
            self._logger.warning(
                "huggingface_chat_http_error",
                model=model,
                status_code=e.response.status_code,
            )
            raise ProviderError(_ERR_API_ERROR % e) from e

        if response.status_code == HTTP_RATE_LIMITED:
            self._logger.warning(
                "huggingface_rate_limited",
                model=model,
            )
            raise RateLimitError(_ERR_RATE_LIMITED)
        if response.status_code == HTTP_SERVICE_UNAVAILABLE:
            error_data = response.json()
            error_msg = error_data.get("error", "Model is loading")
            raise ProviderError(_ERR_MODEL_LOADING % error_msg)

        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            self._logger.warning(
                "huggingface_chat_http_error",
                model=model,
                status_code=e.response.status_code,
            )
            raise ProviderError(_ERR_API_ERROR % e) from e

        try:
            result: dict[str, Any] = response.json()
        except (json.JSONDecodeError, ValueError) as e:
            self._logger.warning(
                "huggingface_json_decode_error",
                model=model,
                status_code=response.status_code,
            )
            raise ProviderError(_ERR_API_ERROR % f"Invalid JSON response: {e}") from e
        return result

    def _parse_hf_tool_calls(
        self,
        response_message: dict[str, Any],
    ) -> list[ToolCall]:
        """Parse tool calls from a HuggingFace API response message.

        Args:
            response_message: The message dict from the API response.

        Returns:
            List of parsed ToolCall instances.
        """
        tool_calls: list[ToolCall] = []
        if not response_message.get("tool_calls"):
            return tool_calls

        for tc in response_message["tool_calls"]:
            func_data = tc.get("function", {})
            func_name = func_data.get("name", "")
            args_str = func_data.get("arguments", "{}")

            tool_call = self._parse_tool_call_common(
                call_id=tc.get("id", f"call_{len(tool_calls)}"),
                function_name=func_name,
                raw_arguments=args_str,
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
        """Stream a chat completion response from HuggingFace.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration (ignored by HuggingFace).
            enable_cache: Whether to enable prompt caching (ignored by HuggingFace).

        Yields:
            Text chunks as they arrive from the API.

        Raises:
            ProviderError: If not connected, model loading, or request fails.
        """
        if not self._connected or self._client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        self._cancel_requested = False
        if thinking is not None and thinking.enabled:
            self._logger.debug("huggingface_stream_thinking_ignored")
        if enable_cache:
            self._logger.debug("huggingface_stream_cache_ignored")

        hf_messages = self._convert_messages_to_provider_format(messages)

        self._logger.info(
            "huggingface_stream_started",
            model=model,
            messages_count=len(messages),
            has_tools=tools is not None,
        )

        chunk_count = 0
        tc_buffer = ToolCallBufferManager()
        try:
            request_body: dict[str, object] = {
                "model": model,
                "messages": hf_messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "stream": True,
            }

            if tools:
                request_body["tools"] = self._convert_tools_to_provider_format(tools)
            if tool_choice is not None and tools:
                request_body["tool_choice"] = self._convert_tool_choice_to_openai_format(tool_choice)

            async with self._client.stream(
                "POST",
                f"{self._base_url}/models/{model}/v1/chat/completions",
                json=request_body,
            ) as response:
                self._check_stream_response_status(response, model)
                response.raise_for_status()

                async for line in response.aiter_lines():
                    if self._cancel_requested:
                        self._logger.info(
                            "huggingface_stream_cancelled",
                            model=model,
                            chunks_received=chunk_count,
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
                                    chunk_count += 1
                                    yield content
                                if tc_deltas := delta.get("tool_calls"):
                                    for tc_d in tc_deltas:
                                        fn: dict[str, str] = tc_d.get("function") or {}
                                        tc_buffer.accumulate(
                                            index=tc_d.get("index", 0),
                                            call_id=tc_d.get("id"),
                                            name=fn.get("name"),
                                            arguments=fn.get("arguments"),
                                        )
                        except json.JSONDecodeError as exc:
                            self._logger.debug("stream_json_parse_skipped", error=str(exc))
                            continue

            self._pending_tool_calls = tc_buffer.finalize()

            self._logger.info(
                "huggingface_stream_completed",
                model=model,
                chunks_received=chunk_count,
            )

        except ProviderError:
            raise
        except Exception as e:
            if not self._cancel_requested:
                self._logger.warning(
                    "huggingface_stream_failed",
                    model=model,
                    error_type=type(e).__name__,
                )
                raise ProviderError(_ERR_STREAM_FAILED % e) from e

    async def cancel_request(self) -> None:
        """Cancel any in-flight request."""
        self._cancel_requested = True
        self._logger.info(
            "huggingface_cancel_requested",
            was_connected=self._connected,
        )

    def _check_stream_response_status(self, response: httpx.Response, model: str) -> None:
        """Check streaming response status and raise appropriate errors.

        Args:
            response: The HTTP response from the streaming request.
            model: The model name for error logging.

        Raises:
            ProviderError: If the model is loading or unavailable.
        """
        if response.status_code == HTTP_SERVICE_UNAVAILABLE:
            self._logger.warning(
                "huggingface_model_loading",
                model=model,
            )
            raise ProviderError(_ERR_MODEL_LOADING_WAIT)

    @override
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Convert internal messages to HuggingFace format.

        Uses OpenAI-compatible format for the chat completions endpoint.

        Args:
            messages: List of Message objects.

        Returns:
            List of messages in HuggingFace's OpenAI-compatible format.
        """
        return self._convert_messages_to_openai_format(messages)

    @override
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Convert internal tools to HuggingFace format.

        Uses OpenAI-compatible function calling format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            List of tools in HuggingFace's OpenAI-compatible format.
        """
        hf_tools: list[dict[str, object]] = []
        for tool in tools:
            tool_schemas = create_openai_tool_schema(tool)
            hf_tools.extend(dict(schema) for schema in tool_schemas)
        return hf_tools
