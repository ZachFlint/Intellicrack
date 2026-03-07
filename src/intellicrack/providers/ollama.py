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
    ToolCall,
    ToolDefinition,
)
from .base import LLMProviderBase, create_openai_tool_schema


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
        _local_client: HTTP client for local Ollama instance.
        _cloud_client: HTTP client for Ollama cloud API.
        _local_url: Base URL for local Ollama.
        _cloud_api_key: API key for Ollama cloud authentication.
        _local_available: Whether local Ollama is connected.
        _cloud_available: Whether cloud API is connected.
    """

    DEFAULT_LOCAL_URL = "http://localhost:11434"
    CLOUD_API_URL = os.environ.get("INTELLICRACK_OLLAMA_CLOUD_URL", "https://ollama.com/api")

    def __init__(self) -> None:
        """Initialize the Ollama provider with dual-client support."""
        super().__init__()
        self._local_client: httpx.AsyncClient | None = None
        self._cloud_client: httpx.AsyncClient | None = None
        self._local_url: str = self.DEFAULT_LOCAL_URL
        self._cloud_api_key: str | None = None
        self._local_available: bool = False
        self._cloud_available: bool = False
        self._connect_timeout: float = 300.0
        self._logger = get_logger("providers.ollama")

    @property
    def name(self) -> ProviderName:
        """Get the provider's name.

        Returns:
            ProviderName.OLLAMA
        """
        return ProviderName.OLLAMA

    @property
    def local_available(self) -> bool:
        """Check if local Ollama is available.

        Returns:
            True if local Ollama instance is connected.
        """
        return self._local_available

    @property
    def cloud_available(self) -> bool:
        """Check if Ollama cloud is available.

        Returns:
            True if cloud API is connected.
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
            self._logger.info("local_ollama_connected", extra={"url": self._local_url})
        except Exception as e:
            self._local_available = False
            self._logger.debug("local_ollama_unavailable", extra={"error": str(e)})
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
            self._logger.info("cloud_ollama_connected")
        except httpx.HTTPStatusError as e:
            self._cloud_available = False
            if e.response.status_code == HTTPStatus.UNAUTHORIZED:
                self._logger.warning("cloud_api_key_invalid")
            else:
                self._logger.warning(
                    "cloud_ollama_unavailable",
                    extra={
                        "error": str(e),
                        "url": self.CLOUD_API_URL,
                        "hint": "Set INTELLICRACK_OLLAMA_CLOUD_URL to a valid remote Ollama endpoint",
                    },
                )
            if self._cloud_client:
                await self._cloud_client.aclose()
                self._cloud_client = None
        except Exception as e:
            self._cloud_available = False
            self._logger.warning(
                "cloud_ollama_unavailable",
                extra={
                    "error": str(e),
                    "url": self.CLOUD_API_URL,
                    "hint": "Set INTELLICRACK_OLLAMA_CLOUD_URL to a valid remote Ollama endpoint",
                },
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
            self._logger.info("ollama_disconnected")
        except Exception as exc:
            self._logger.warning("disconnect_cleanup_error", extra={"error": str(exc)})
            self._connected = False

    async def list_models(self) -> list[ModelInfo]:
        """Fetch available models from both local and cloud Ollama.

        Returns models prefixed with their source (local/ or cloud/).

        Returns:
            List of available models from all connected sources.

        Raises:
            ProviderError: If not connected.
        """
        if not self._connected:
            raise ProviderError(_MSG_NOT_CONNECTED)

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
            List of local models with 'local/' prefix.
        """
        models: list[ModelInfo] = []
        if not self._local_client:
            return models

        try:
            response = await self._local_client.get(f"{self._local_url}/api/tags")
            response.raise_for_status()
            data = response.json()

            model_names = [m.get("name", "") for m in data.get("models", []) if m.get("name")]
            ctx_windows = await self._fetch_context_windows(
                self._local_client,
                self._local_url,
                model_names,
            )

            models.extend(
                ModelInfo(
                    id=f"local/{model_name}",
                    name=f"[Local] {model_name}",
                    provider=ProviderName.OLLAMA,
                    context_window=ctx_windows.get(model_name, 4096),
                    supports_tools=True,
                    supports_vision=True,
                    supports_streaming=True,
                    input_cost_per_1m_tokens=None,
                    output_cost_per_1m_tokens=None,
                )
                for model_name in model_names
            )
        except Exception as e:
            self._logger.warning("local_models_list_failed", extra={"error": str(e)})

        return models

    async def _fetch_cloud_models(self) -> list[ModelInfo]:
        """Fetch models from Ollama cloud API.

        Returns:
            List of cloud models with 'cloud/' prefix.
        """
        models: list[ModelInfo] = []
        if not self._cloud_client:
            return models

        try:
            response = await self._cloud_client.get(f"{self.CLOUD_API_URL}/tags")
            response.raise_for_status()
            data = response.json()

            model_names = [m.get("name", "") for m in data.get("models", []) if m.get("name")]
            ctx_windows = await self._fetch_context_windows(
                self._cloud_client,
                self.CLOUD_API_URL,
                model_names,
            )

            models.extend(
                ModelInfo(
                    id=f"cloud/{model_name}",
                    name=f"[Cloud] {model_name}",
                    provider=ProviderName.OLLAMA,
                    context_window=ctx_windows.get(model_name, 4096),
                    supports_tools=True,
                    supports_vision=True,
                    supports_streaming=True,
                    input_cost_per_1m_tokens=None,
                    output_cost_per_1m_tokens=None,
                )
                for model_name in model_names
            )
        except Exception as e:
            self._logger.warning("cloud_models_list_failed", extra={"error": str(e)})

        return models

    def _get_client_and_model(self, model: str) -> tuple[httpx.AsyncClient, str, str]:
        """Get appropriate client and base URL for the specified model.

        Args:
            model: Model ID, optionally prefixed with 'local/' or 'cloud/'.

        Returns:
            Tuple of (client, base_url, actual_model_name).

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

    async def _fetch_context_windows(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        model_names: list[str],
    ) -> dict[str, int]:
        """Fetch context window sizes from /api/show for each model.

        Uses ``asyncio.gather`` to query models in parallel.

        Args:
            client: The httpx client to use.
            base_url: The Ollama API base URL.
            model_names: List of model names to query.

        Returns:
            Mapping of model name to context window size.
        """

        async def _query_single(name: str) -> tuple[str, int]:
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
                        return name, int(parts[1])
            except Exception:
                self._logger.debug(
                    "ollama_show_failed",
                    extra={"model": name},
                )
            return name, 4096

        results = await asyncio.gather(*[_query_single(n) for n in model_names])
        return dict(results)

    async def chat(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Send a chat completion request to Ollama.

        Automatically routes to local or cloud based on model prefix.

        Args:
            messages: Conversation history.
            model: Model name to use (optionally prefixed with local/ or cloud/).
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.

        Returns:
            Tuple of (assistant message, tool calls if any).

        Raises:
            ProviderError: If not connected or request fails.
        """
        if not self._connected:
            raise ProviderError(_MSG_NOT_CONNECTED)

        self._cancel_requested = False

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
            Parsed JSON response dictionary.

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
            raise ProviderError(_ERR_API_ERROR % e) from e
        except Exception as e:
            raise ProviderError(_ERR_REQUEST_FAILED % e) from e

    def _parse_ollama_tool_calls(self, data: dict[str, Any]) -> list[ToolCall]:
        """Parse tool calls from an Ollama API response.

        Args:
            data: The parsed JSON response from Ollama.

        Returns:
            List of parsed ToolCall instances.
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
        """Stream a chat completion response from Ollama.

        Automatically routes to local or cloud based on model prefix.

        Args:
            messages: Conversation history.
            model: Model name to use (optionally prefixed with local/ or cloud/).
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.

        Yields:
            Text chunks as they arrive.

        Raises:
            ProviderError: If not connected or request fails.
        """
        if not self._connected:
            raise ProviderError(_MSG_NOT_CONNECTED)

        self._cancel_requested = False

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

            if tools:
                request_body["tools"] = self._convert_tools_to_provider_format(tools)

            last_chunk_data: dict[str, object] = {}
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
                            if content := chunk_data.get("message", {}).get("content", ""):
                                yield content
                        except json.JSONDecodeError as exc:
                            self._logger.debug("stream_json_parse_skipped", extra={"error": str(exc)})
                            continue

            if not self._cancel_requested and last_chunk_data:
                self._pending_tool_calls = self._parse_ollama_tool_calls(
                    cast("dict[str, Any]", last_chunk_data),
                )

        except Exception as e:
            if not self._cancel_requested:
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
            List of messages in Ollama's format.
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
            List of tools in Ollama's format.
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
            Progress status messages.

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
                            continue
        except Exception as e:
            raise ProviderError(_ERR_PULL_FAILED % (actual_model, e)) from e
