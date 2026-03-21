# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Ollama LLM provider implementation with dual local/cloud support.

This module provides integration with both locally running Ollama models
and the Ollama cloud API for chat completion and tool/function calling.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, cast, override

import httpx


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

from ..core.logging import get_logger, log_provider_request
from ..core.types import (
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    ProviderName,
    ThinkingConfig,
    ToolCall,
    ToolChoice,
    ToolDefinition,
)
from .base import LLMProviderBase, create_openai_tool_schema


_logger = get_logger("providers.ollama")

_MSG_NOT_CONNECTED = "Not connected"
_ERR_CONNECT_BOTH_FAILED = "Could not connect to local or cloud Ollama. Ensure local Ollama is running or provide a valid API key."
_ERR_CLOUD_NOT_AVAILABLE = "Ollama cloud not available"
_ERR_LOCAL_NOT_AVAILABLE = "Local Ollama not available"
_ERR_NO_CLIENT = "No Ollama client available"
_ERR_API_ERROR = "Ollama API error: %s"
_ERR_REQUEST_FAILED = "Ollama request failed: %s"
_ERR_STREAM_FAILED = "Ollama stream failed: %s"
_ERR_LOCAL_PULL_UNAVAILABLE = "Local Ollama not available for model pull"
_ERR_PULL_FAILED = "Failed to pull model %s: %s"


class OllamaProvider(LLMProviderBase):
    """Ollama LLM provider implementation with dual local/cloud support.

    Provides simultaneous integration with local Ollama instances and the
    Ollama cloud API at https://ollama.com/api. Models from each source are
    prefixed to distinguish their origin (local/ or cloud/).

    Attributes:
        DEFAULT_LOCAL_URL: Base URL for the local Ollama REST API server.
        CLOUD_API_URL: Ollama cloud API endpoint URL.
    """

    DEFAULT_LOCAL_URL = "http://localhost:11434"
    CLOUD_API_URL = os.environ.get("INTELLICRACK_OLLAMA_CLOUD_URL", "https://ollama.com/api")

    def __init__(self) -> None:
        super().__init__()
        self._local_client: httpx.AsyncClient | None = None
        self._cloud_client: httpx.AsyncClient | None = None
        self._local_url: str = self.DEFAULT_LOCAL_URL
        self._cloud_api_key: str | None = None
        self._local_available: bool = False
        self._cloud_available: bool = False
        self._connect_timeout: float = 300.0
        self._logger = get_logger("providers.ollama").bind(provider="ollama")

    @property
    def name(self) -> ProviderName:
        """Get the provider's name.

        Returns:
            ProviderName: ProviderName.OLLAMA
        """
        return ProviderName.OLLAMA

    @property
    def local_available(self) -> bool:
        """Check if local Ollama is available.

        Returns:
            bool: True if local Ollama instance is connected.
        """
        return self._local_available

    @property
    def cloud_available(self) -> bool:
        """Check if Ollama cloud is available.

        Returns:
            bool: True if cloud API is connected.
        """
        return self._cloud_available

    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect to both local and cloud Ollama if available.

        Attempts to connect to both local Ollama instance and cloud API.
        Connection succeeds if at least one source is available.

        Args:
            credentials: Contains api_key for cloud API, api_base for custom local URL.

        Raises:
            ProviderError: If neither local nor cloud connection succeeds.
        """
        self._cloud_api_key = credentials.api_key
        if credentials.api_base:
            self._local_url = credentials.api_base.rstrip("/")
        if credentials.timeout is not None:
            self._connect_timeout = credentials.timeout

        await asyncio.gather(self._connect_local(), self._connect_cloud())

        if not self._local_available and not self._cloud_available:
            raise ProviderError(_ERR_CONNECT_BOTH_FAILED)

        self._credentials = credentials
        self._connected = True

    async def _connect_local(self) -> None:
        """Attempt to connect to local Ollama instance."""
        try:
            self._local_client = httpx.AsyncClient(timeout=httpx.Timeout(self._connect_timeout))
            response = await self._local_client.get(f"{self._local_url}/api/tags")
            response.raise_for_status()
            self._local_available = True
            self._logger.info("local_ollama_connected", url=self._local_url)
        except Exception as e:
            self._local_available = False
            self._logger.debug("local_ollama_unavailable", error=str(e))
            if self._local_client:
                await self._local_client.aclose()
                self._local_client = None

    async def _connect_cloud(self) -> None:
        """Attempt to connect to Ollama cloud API."""
        if not self._cloud_api_key:
            return

        try:
            self._cloud_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._connect_timeout),
                headers={"Authorization": f"Bearer {self._cloud_api_key}"},
            )
            response = await self._cloud_client.get(f"{self.CLOUD_API_URL}/tags")
            response.raise_for_status()
            self._cloud_available = True
            self._logger.info("cloud_ollama_connected", cloud_url=self.CLOUD_API_URL)
        except httpx.HTTPStatusError as e:
            self._cloud_available = False
            if e.response.status_code == HTTPStatus.UNAUTHORIZED:
                self._logger.warning("cloud_api_key_invalid", status_code=e.response.status_code)
            else:
                self._logger.warning(
                    "cloud_ollama_unavailable",
                    error=str(e),
                    url=self.CLOUD_API_URL,
                    hint="Set INTELLICRACK_OLLAMA_CLOUD_URL to a valid remote Ollama endpoint",
                )
            if self._cloud_client:
                await self._cloud_client.aclose()
                self._cloud_client = None
        except Exception as e:
            self._cloud_available = False
            self._logger.warning(
                "cloud_ollama_unavailable",
                error=str(e),
                url=self.CLOUD_API_URL,
                hint="Set INTELLICRACK_OLLAMA_CLOUD_URL to a valid remote Ollama endpoint",
            )
            if self._cloud_client:
                await self._cloud_client.aclose()
                self._cloud_client = None

    async def disconnect(self) -> None:
        """Disconnect from both local and cloud Ollama."""
        try:
            await super().disconnect()
            if self._local_client:
                await self._local_client.aclose()
                self._local_client = None
            if self._cloud_client:
                await self._cloud_client.aclose()
                self._cloud_client = None
            self._local_available = False
            self._cloud_available = False
            self._logger.info("ollama_disconnected", provider="ollama")
        except Exception as exc:
            self._logger.warning("disconnect_cleanup_error", error=str(exc))
            self._connected = False

    async def list_models(self) -> list[ModelInfo]:
        """Fetch available models from both local and cloud Ollama.

        Returns models prefixed with their source (local/ or cloud/).

        Returns:
            list[ModelInfo]: List of available models from all connected sources.

        Raises:
            ProviderError: If not connected.
        """
        if not self._connected:
            raise ProviderError(_MSG_NOT_CONNECTED)

        self._logger.debug("ollama_listing_models")
        models: list[ModelInfo] = []

        if self._local_available and self._local_client:
            local_models = await self._fetch_local_models()
            models.extend(local_models)

        if self._cloud_available and self._cloud_client:
            cloud_models = await self._fetch_cloud_models()
            models.extend(cloud_models)

        return sorted(models, key=lambda m: m.name)

    async def _fetch_local_models(self) -> list[ModelInfo]:
        """Fetch models from local Ollama instance.

        Returns:
            list[ModelInfo]: List of local models with 'local/' prefix.
        """
        models: list[ModelInfo] = []
        if not self._local_client:
            return models

        self._logger.debug("local_models_fetching", url=self._local_url)
        try:
            response = await self._local_client.get(f"{self._local_url}/api/tags")
            response.raise_for_status()
            data = response.json()

            model_names = [m.get("name", "") for m in data.get("models", []) if m.get("name")]
            model_metadata = await self._fetch_model_metadata(
                self._local_client,
                self._local_url,
                model_names,
            )

            for model_name in model_names:
                ctx_window, has_tools = model_metadata.get(model_name, (4096, False))
                name_lower = model_name.lower()
                has_vision = any(v in name_lower for v in ("vision", "llava"))
                models.append(
                    ModelInfo(
                        id=f"local/{model_name}",
                        name=f"[Local] {model_name}",
                        provider=ProviderName.OLLAMA,
                        context_window=ctx_window,
                        supports_tools=has_tools,
                        supports_vision=has_vision,
                        supports_streaming=True,
                        input_cost_per_1m_tokens=None,
                        output_cost_per_1m_tokens=None,
                    )
                )
        except Exception as e:
            self._logger.warning("local_models_list_failed", error=str(e))

        return models

    async def _fetch_cloud_models(self) -> list[ModelInfo]:
        """Fetch models from Ollama cloud API.

        Returns:
            list[ModelInfo]: List of cloud models with 'cloud/' prefix.
        """
        models: list[ModelInfo] = []
        if not self._cloud_client:
            return models

        try:
            response = await self._cloud_client.get(f"{self.CLOUD_API_URL}/tags")
            response.raise_for_status()
            data = response.json()

            model_names = [m.get("name", "") for m in data.get("models", []) if m.get("name")]
            model_metadata = await self._fetch_model_metadata(
                self._cloud_client,
                self.CLOUD_API_URL,
                model_names,
            )

            for model_name in model_names:
                ctx_window, has_tools = model_metadata.get(model_name, (4096, False))
                name_lower = model_name.lower()
                has_vision = any(v in name_lower for v in ("vision", "llava"))
                models.append(
                    ModelInfo(
                        id=f"cloud/{model_name}",
                        name=f"[Cloud] {model_name}",
                        provider=ProviderName.OLLAMA,
                        context_window=ctx_window,
                        supports_tools=has_tools,
                        supports_vision=has_vision,
                        supports_streaming=True,
                        input_cost_per_1m_tokens=None,
                        output_cost_per_1m_tokens=None,
                    )
                )
        except Exception as e:
            self._logger.warning("cloud_models_list_failed", error=str(e))

        return models

    def _get_client_and_model(self, model: str) -> tuple[httpx.AsyncClient, str, str]:
        """Get appropriate client and base URL for the specified model.

        Args:
            model: Model ID, optionally prefixed with 'local/' or 'cloud/'.

        Returns:
            tuple[httpx.AsyncClient, str, str]: Tuple of (client, base_url, actual_model_name).

        Raises:
            ProviderError: If requested source is not available.
        """
        if model.startswith("cloud/"):
            if not self._cloud_available or not self._cloud_client:
                raise ProviderError(_ERR_CLOUD_NOT_AVAILABLE)
            return self._cloud_client, self.CLOUD_API_URL, model[6:]

        if model.startswith("local/"):
            if not self._local_available or not self._local_client:
                raise ProviderError(_ERR_LOCAL_NOT_AVAILABLE)
            return self._local_client, self._local_url, model[6:]

        if self._local_available and self._local_client:
            return self._local_client, self._local_url, model
        if self._cloud_available and self._cloud_client:
            return self._cloud_client, self.CLOUD_API_URL, model

        raise ProviderError(_ERR_NO_CLIENT)

    async def _fetch_model_metadata(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        model_names: list[str],
    ) -> dict[str, tuple[int, bool]]:
        """Fetch context window sizes and tool support from /api/show.

        Uses ``asyncio.gather`` to query models in parallel.  Tool support
        is detected by searching the model template for the Ollama
        ``{{ .Tools }}`` directive.

        Args:
            client: The httpx client to use.
            base_url: The Ollama API base URL.
            model_names: List of model names to query.

        Returns:
            dict[str, tuple[int, bool]]: Mapping of model name to (context_window, supports_tools) tuple.
        """

        async def _query_single(name: str) -> tuple[str, int, bool]:
            ctx_window = 4096
            has_tools = False
            try:
                resp = await client.post(
                    f"{base_url}/api/show",
                    json={"name": name},
                )
                resp.raise_for_status()
                show_data = resp.json()
                params_str: str = show_data.get("parameters", "")
                for line in params_str.splitlines():
                    parts = line.strip().split()
                    min_parts = 2
                    if len(parts) >= min_parts and parts[0] == "num_ctx":
                        ctx_window = int(parts[1])
                template: str = show_data.get("template", "")
                if re.search(r"\{\{-?\s*\.Tools\s*-?\}\}", template):
                    has_tools = True
            except Exception:
                self._logger.debug(
                    "ollama_show_failed",
                    model=name,
                )
            return name, ctx_window, has_tools

        results = await asyncio.gather(*[_query_single(n) for n in model_names])
        return {name: (ctx, tools) for name, ctx, tools in results}

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
        """Send a chat completion request to Ollama.

        Automatically routes to local or cloud based on model prefix.

        Args:
            messages: Conversation history.
            model: Model name to use (optionally prefixed with local/ or cloud/).
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools (ignored by Ollama).
            thinking: Extended thinking configuration (ignored by Ollama).
            enable_cache: Whether to enable prompt caching (ignored by Ollama).

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of (assistant message, tool calls if any).

        Raises:
            ProviderError: If not connected or request fails.
        """
        if not self._connected:
            raise ProviderError(_MSG_NOT_CONNECTED)

        self._cancel_requested = False
        if tool_choice is not None:
            self._logger.debug("ollama_tool_choice_ignored", mode=tool_choice.mode.value)
        if thinking is not None and thinking.enabled:
            self._logger.debug("ollama_thinking_ignored")
        if enable_cache:
            self._logger.debug("ollama_cache_ignored")

        client, base_url, actual_model = self._get_client_and_model(model)
        ollama_messages = self._convert_messages_to_provider_format(messages)

        log_provider_request(
            provider="ollama",
            model=actual_model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
        )

        request_body: dict[str, object] = {
            "model": actual_model,
            "messages": ollama_messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if tools:
            request_body["tools"] = self._convert_tools_to_provider_format(tools)

        start_time = time.perf_counter()
        data = await self._make_ollama_api_call(
            client=client,
            base_url=base_url,
            request_body=request_body,
        )
        duration_ms = (time.perf_counter() - start_time) * 1000

        content = data.get("message", {}).get("content", "")
        tool_calls = self._parse_ollama_tool_calls(data)

        return self._build_chat_response(
            provider="ollama",
            model=actual_model,
            content=content,
            tool_calls=tool_calls,
            duration_ms=duration_ms,
        )

    @staticmethod
    async def _make_ollama_api_call(
        *,
        client: httpx.AsyncClient,
        base_url: str,
        request_body: dict[str, object],
    ) -> dict[str, Any]:
        """Execute the Ollama API chat call with error handling.

        Args:
            client: The httpx async client to use.
            base_url: The base URL for the Ollama API.
            request_body: The request payload.

        Returns:
            dict[str, Any]: Parsed JSON response dictionary.

        Raises:
            ProviderError: If the API call fails.
        """
        try:
            response = await client.post(
                f"{base_url}/api/chat",
                json=request_body,
            )
            response.raise_for_status()
            return cast("dict[str, Any]", response.json())
        except httpx.HTTPStatusError as e:
            _logger.warning("ollama_api_error", error=str(e))
            raise ProviderError(_ERR_API_ERROR % e) from e
        except Exception as e:
            _logger.warning("ollama_request_failed", error=str(e))
            raise ProviderError(_ERR_REQUEST_FAILED % e) from e

    def _parse_ollama_tool_calls(self, data: dict[str, Any]) -> list[ToolCall]:
        """Parse tool calls from an Ollama API response.

        Args:
            data: The parsed JSON response from Ollama.

        Returns:
            list[ToolCall]: List of parsed ToolCall instances.
        """
        tool_calls: list[ToolCall] = []
        message_data = data.get("message")
        if not isinstance(message_data, dict) or "tool_calls" not in message_data:
            return tool_calls

        raw_tool_calls = cast("list[dict[str, Any]]", message_data["tool_calls"])
        for idx, tc in enumerate(raw_tool_calls):
            func_data: dict[str, Any] = tc.get("function", {})
            func_name: str = str(func_data.get("name", ""))
            raw_args: Any = func_data.get("arguments", {})

            raw_arguments: str | dict[str, object]
            if isinstance(raw_args, str):
                raw_arguments = raw_args
            elif isinstance(raw_args, dict):
                raw_arguments = cast("dict[str, object]", raw_args)
            else:
                raw_arguments = "{}"

            tool_call = self._parse_tool_call_common(
                call_id=f"call_{idx}",
                function_name=func_name,
                raw_arguments=raw_arguments,
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
        """Stream a chat completion response from Ollama.

        Automatically routes to local or cloud based on model prefix.
        When tools are provided, falls back to a non-streaming request
        internally to ensure reliable tool call capture.

        Args:
            messages: Conversation history.
            model: Model name to use (optionally prefixed with local/ or cloud/).
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools (ignored by Ollama).
            thinking: Extended thinking configuration (ignored by Ollama).
            enable_cache: Whether to enable prompt caching (ignored by Ollama).

        Yields:
            str: Text chunks as they arrive.

        Raises:
            ProviderError: If not connected or request fails.
        """
        if not self._connected:
            raise ProviderError(_MSG_NOT_CONNECTED)

        self._cancel_requested = False
        if tool_choice is not None:
            self._logger.debug("ollama_tool_choice_ignored", mode=tool_choice.mode.value)
        if thinking is not None and thinking.enabled:
            self._logger.debug("ollama_thinking_ignored")
        if enable_cache:
            self._logger.debug("ollama_cache_ignored")

        if tools:
            response_msg, tool_calls_result = await self.chat(
                messages=messages,
                model=model,
                tools=tools,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            if response_msg.content:
                yield response_msg.content
            if tool_calls_result:
                self._pending_tool_calls = list(tool_calls_result)
            return

        client, base_url, actual_model = self._get_client_and_model(model)
        ollama_messages = self._convert_messages_to_provider_format(messages)

        try:
            request_body: dict[str, object] = {
                "model": actual_model,
                "messages": ollama_messages,
                "stream": True,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            }

            last_chunk_data: dict[str, Any] = {}
            async with client.stream(
                "POST",
                f"{base_url}/api/chat",
                json=request_body,
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if self._cancel_requested:
                        break
                    if line:
                        try:
                            chunk_data = json.loads(line)
                            last_chunk_data = chunk_data
                            if content := last_chunk_data.get("message", {}).get("content", ""):
                                yield content
                        except json.JSONDecodeError as exc:
                            self._logger.debug("stream_json_parse_skipped", error=str(exc))
                            continue

            if not self._cancel_requested and last_chunk_data:
                self._pending_tool_calls = self._parse_ollama_tool_calls(
                    last_chunk_data,
                )

        except Exception as e:
            if not self._cancel_requested:
                self._logger.warning("ollama_stream_failed", error=str(e))
                raise ProviderError(_ERR_STREAM_FAILED % e) from e

    async def cancel_request(self) -> None:
        """Cancel any in-flight request."""
        self._cancel_requested = True

    @override
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Convert internal messages to Ollama format.

        Args:
            messages: List of Message objects.

        Returns:
            list[dict[str, object]]: List of messages in Ollama's format.
        """
        return self._convert_messages_to_openai_format(
            messages,
            serialize_tool_arguments=False,
            include_tool_call_type=False,
        )

    @override
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Convert internal tools to Ollama format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            list[dict[str, object]]: List of tools in Ollama's format.
        """
        ollama_tools: list[dict[str, object]] = []
        for tool in tools:
            tool_schemas = create_openai_tool_schema(tool)
            ollama_tools.extend(dict(schema) for schema in tool_schemas)
        return ollama_tools

    async def pull_model(self, model_name: str) -> AsyncIterator[str]:
        """Pull a model from Ollama library to local instance.

        Args:
            model_name: Name of model to pull (may be prefixed with local/).

        Yields:
            str: Progress status messages.

        Raises:
            ProviderError: If local Ollama not connected or pull fails.
        """
        if not self._local_available or not self._local_client:
            raise ProviderError(_ERR_LOCAL_PULL_UNAVAILABLE)

        actual_model = model_name
        if model_name.startswith("local/"):
            actual_model = model_name[6:]

        try:
            async with self._local_client.stream(
                "POST",
                f"{self._local_url}/api/pull",
                json={"name": actual_model},
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line:
                        try:
                            data = json.loads(line)
                            if status := data.get("status", ""):
                                yield status
                        except json.JSONDecodeError:
                            self._logger.warning("pull_status_json_decode_failed")
                            continue
        except Exception as e:
            self._logger.warning("ollama_pull_failed", model=actual_model, error=str(e))
            raise ProviderError(_ERR_PULL_FAILED % (actual_model, e)) from e
