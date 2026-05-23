# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Ollama LLM provider implementation with dual local/cloud support.

This module provides integration with both locally running Ollama models and the Ollama cloud API for chat completion, tool/function
calling, embeddings, and model management.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, TypedDict, cast, override

import httpx

from intellicrack.core.error_logging import log_passthrough
from intellicrack.core.logging import get_logger, log_provider_request
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
from intellicrack.providers.base import LLMProviderBase, UsageInfo, create_openai_tool_schema


if TYPE_CHECKING:
    from collections.abc import AsyncIterator


_logger = get_logger(__name__)

_CLOUD_HOST_FRAGMENTS: tuple[str, ...] = ("ollama.com", "ollama.ai")

_MSG_NOT_CONNECTED = "Not connected"
_ERR_CONNECT_BOTH_FAILED = "Could not connect to local or cloud Ollama. Ensure local Ollama is running or provide a valid API key."
_ERR_CLOUD_NOT_AVAILABLE = "Ollama cloud not available"
_ERR_LOCAL_NOT_AVAILABLE = "Local Ollama not available"
_ERR_NO_CLIENT = "No Ollama client available"
_ERR_LOCAL_PULL_UNAVAILABLE = "Local Ollama not available for model pull"
_ERR_UNKNOWN_SOURCE = "Unknown Ollama source: %r"
_ERR_AUTH = "Ollama authentication failed (HTTP %d): %s"
_ERR_RATE_LIMIT = "Ollama rate limit exceeded (HTTP %d): %s"
_ERR_SERVER = "Ollama server error (HTTP %d): %s"
_ERR_HTTP = "Ollama HTTP error (HTTP %d): %s"
_ERR_TRANSPORT = "Ollama request transport error: %s"


class OllamaTagEntry(TypedDict, total=False):
    """Typed representation of a single model in ``/api/tags``."""

    name: str
    model: str
    modified_at: str
    size: int
    digest: str


class OllamaTagsResponse(TypedDict, total=False):
    """Typed response body for ``/api/tags``."""

    models: list[OllamaTagEntry]


class OllamaShowResponse(TypedDict, total=False):
    """Typed response body for ``/api/show``."""

    modelfile: str
    parameters: str
    template: str
    details: dict[str, Any]
    model_info: dict[str, Any]
    capabilities: list[str]


class OllamaGenerateResponse(TypedDict, total=False):
    """Typed response body for a non-streaming ``/api/generate`` call."""

    model: str
    created_at: str
    response: str
    done: bool
    context: list[int]
    total_duration: int
    load_duration: int
    prompt_eval_count: int
    prompt_eval_duration: int
    eval_count: int
    eval_duration: int


class OllamaEmbeddingsResponse(TypedDict, total=False):
    """Typed response body for ``/api/embeddings``."""

    embedding: list[float]


class OllamaRunningModel(TypedDict, total=False):
    """Typed representation of a single entry in ``/api/ps``."""

    name: str
    model: str
    size: int
    digest: str
    expires_at: str
    size_vram: int


class OllamaPsResponse(TypedDict, total=False):
    """Typed response body for ``/api/ps``."""

    models: list[OllamaRunningModel]


class OllamaProvider(LLMProviderBase):
    """Ollama LLM provider implementation with dual local/cloud support.

    Provides simultaneous integration with local Ollama instances and the
    Ollama cloud API at https://ollama.com. Models from each source are
    prefixed to distinguish their origin (local/ or cloud/).

    Attributes:
        DEFAULT_LOCAL_URL: Base URL for the local Ollama REST API server.
        CLOUD_API_URL: Ollama cloud API endpoint URL.
    """

    DEFAULT_LOCAL_URL = "http://localhost:11434"
    CLOUD_API_URL = os.environ.get("INTELLICRACK_OLLAMA_CLOUD_URL", "https://ollama.com")

    def __init__(self) -> None:
        """Initialize the OllamaProvider instance."""
        super().__init__()
        self._local_client: httpx.AsyncClient | None = None
        self._cloud_client: httpx.AsyncClient | None = None
        self._local_url: str = self.DEFAULT_LOCAL_URL
        self._cloud_api_key: str | None = None
        self._local_available: bool = False
        self._cloud_available: bool = False
        self._connect_timeout: float = 300.0
        self._logger = get_logger(__name__).bind(provider="ollama")
        self._logger.info("ollama_provider_initialized")

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

        Attempts to connect to both local Ollama instance and cloud API by
        probing ``/api/tags``. Connection succeeds if at least one source is
        reachable. ``self.connected`` is set to ``True`` on successful probe
        and left ``False`` if neither source is reachable.

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

        if self.CLOUD_API_URL.rstrip("/").endswith("/api"):
            self._logger.warning(
                "cloud_url_ends_with_api",
                cloud_url=self.CLOUD_API_URL,
                hint="INTELLICRACK_OLLAMA_CLOUD_URL should be a base URL without /api suffix",
            )

        await asyncio.gather(self._connect_local(), self._connect_cloud())

        if not self._local_available and not self._cloud_available:
            self.connected = False
            raise ProviderError(_ERR_CONNECT_BOTH_FAILED, provider_name="ollama")

        self._credentials = credentials
        self.connected = True

    async def _connect_local(self) -> None:
        """Probe the local Ollama ``/api/tags`` endpoint and record availability."""
        try:
            self._local_client = httpx.AsyncClient(timeout=httpx.Timeout(self._connect_timeout))
            response = await self._local_client.get(f"{self._local_url}/api/tags")
            self._raise_for_status(response)
            self._local_available = True
            self._logger.info("local_ollama_connected", url=self._local_url)
        except AuthenticationError as e:
            self._local_available = False
            self._logger.warning("local_ollama_auth_failed", error=str(e))
            if self._local_client:
                await self._local_client.aclose()
                self._local_client = None
        except (ConnectionError, TimeoutError, OSError, httpx.HTTPError, ProviderError) as e:
            self._local_available = False
            self._logger.warning("local_ollama_unavailable", error=str(e))
            if self._local_client:
                await self._local_client.aclose()
                self._local_client = None

    async def _connect_cloud(self) -> None:
        """Probe the Ollama cloud ``/api/tags`` endpoint and record availability."""
        if not self._cloud_api_key:
            return

        try:
            self._cloud_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._connect_timeout),
                headers={"Authorization": f"Bearer {self._cloud_api_key}"},
            )
            response = await self._cloud_client.get(f"{self.CLOUD_API_URL}/api/tags")
            self._raise_for_status(response)
            self._cloud_available = True
            self._logger.info("cloud_ollama_connected", cloud_url=self.CLOUD_API_URL)
        except AuthenticationError as e:
            self._cloud_available = False
            self._logger.warning("cloud_api_key_invalid", error=str(e))
            if self._cloud_client:
                await self._cloud_client.aclose()
                self._cloud_client = None
        except (ConnectionError, TimeoutError, OSError, httpx.HTTPError, ProviderError) as e:
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
            self._pending_usage = None
            self._logger.info("ollama_disconnected", provider="ollama")
        except (ConnectionError, TimeoutError, OSError, RuntimeError) as exc:
            self._logger.warning("disconnect_cleanup_error", error=str(exc))
            self.connected = False

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        """Map an ``httpx.Response`` status code to the typed provider errors.

        Non-2xx responses are converted into the appropriate Intellicrack
        exception: ``AuthenticationError`` for 401/403,
        ``RateLimitError`` for 429, and ``ProviderError`` for any other
        non-success status.

        Args:
            response: The ``httpx.Response`` to evaluate.

        Raises:
            AuthenticationError: If the server returned HTTP 401 or 403.
            RateLimitError: If the server returned HTTP 429.
            ProviderError: If the server returned any other non-2xx status.
        """
        status = response.status_code
        if HTTPStatus.OK <= status < HTTPStatus.MULTIPLE_CHOICES:
            return

        body_preview = OllamaProvider._safe_response_text(response)
        if status in {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}:
            raise AuthenticationError(
                _ERR_AUTH % (status, body_preview),
                provider_name="ollama",
                status_code=status,
                response_body=body_preview,
            )
        if status == HTTPStatus.TOO_MANY_REQUESTS:
            raise RateLimitError(
                _ERR_RATE_LIMIT % (status, body_preview),
                provider_name="ollama",
                status_code=status,
                response_body=body_preview,
            )
        if status >= HTTPStatus.INTERNAL_SERVER_ERROR:
            raise ProviderError(
                _ERR_SERVER % (status, body_preview),
                provider_name="ollama",
                status_code=status,
                response_body=body_preview,
            )
        raise ProviderError(
            _ERR_HTTP % (status, body_preview),
            provider_name="ollama",
            status_code=status,
            response_body=body_preview,
        )

    @staticmethod
    def _safe_response_text(response: httpx.Response) -> str:
        """Return a short, safe textual preview of an ``httpx.Response`` body.

        Streaming responses may not have a readable ``text`` attribute; this
        helper catches the relevant exceptions and returns an empty string
        so error construction never raises.

        Args:
            response: The ``httpx.Response`` whose body should be previewed.

        Returns:
            str: Truncated response text, or an empty string if unavailable.
        """
        try:
            text = response.text
        except (httpx.HTTPError, RuntimeError, UnicodeDecodeError):
            _logger.debug("ollama_response_text_unreadable")
            return ""
        max_len = 512
        if len(text) > max_len:
            return text[:max_len] + "..."
        return text

    async def list_models(self) -> list[ModelInfo]:
        """Fetch available models from both local and cloud Ollama.

        Returns models prefixed with their source (local/ or cloud/).

        Returns:
            list[ModelInfo]: List of available models from all connected sources.

        Raises:
            ProviderError: If not connected.
        """
        if not self.connected:
            self._logger.error("ollama_list_models_not_connected")
            raise ProviderError(_MSG_NOT_CONNECTED, provider_name="ollama")

        self._logger.debug("ollama_listing_models")
        models: list[ModelInfo] = []

        if self._local_available and self._local_client:
            local_models = await self._fetch_local_models()
            models.extend(local_models)

        if self._cloud_available and self._cloud_client:
            cloud_models = await self._fetch_cloud_models()
            models.extend(cloud_models)

        return sorted(models, key=lambda m: m.name)

    async def list_tags(
        self,
        *,
        source: str = "local",
    ) -> OllamaTagsResponse:
        """Return the raw ``/api/tags`` response for a given source.

        Args:
            source: Either ``"local"`` or ``"cloud"`` to select which
                Ollama endpoint to query.

        Returns:
            OllamaTagsResponse: Typed tag dict with a ``models`` list.

        Raises:
            ProviderError: If not connected, the chosen source is
                unavailable, or the server returns a non-success HTTP
                status. Authentication and rate-limit failures propagate
                as the appropriate ``ProviderError`` subclass.
        """
        client, base_url = self._get_source_client(source)
        try:
            response = await client.get(f"{base_url}/api/tags")
            self._raise_for_status(response)
            return cast("OllamaTagsResponse", response.json())
        except ProviderError as exc:
            log_passthrough(
                self._logger,
                "ollama_list_tags_passthrough",
                exc,
                provider="ollama",
                source=source,
            )
            raise
        except (ConnectionError, TimeoutError, OSError, httpx.HTTPError, ValueError) as exc:
            self._logger.warning(
                "ollama_list_tags_transport_failed",
                provider="ollama",
                source=source,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            raise ProviderError(_ERR_TRANSPORT % exc, provider_name="ollama") from exc

    async def list_running_models(
        self,
        *,
        source: str = "local",
    ) -> OllamaPsResponse:
        """Return models currently loaded in memory via ``/api/ps``.

        Args:
            source: Either ``"local"`` or ``"cloud"`` to select which
                Ollama endpoint to query.

        Returns:
            OllamaPsResponse: Typed dict with a ``models`` list describing
            models currently resident in the runner's memory.

        Raises:
            ProviderError: If not connected, the chosen source is
                unavailable, or the server returns a non-success HTTP
                status. Authentication and rate-limit failures propagate
                as the appropriate ``ProviderError`` subclass.
        """
        client, base_url = self._get_source_client(source)
        try:
            response = await client.get(f"{base_url}/api/ps")
            self._raise_for_status(response)
            return cast("OllamaPsResponse", response.json())
        except ProviderError as exc:
            log_passthrough(
                self._logger,
                "ollama_list_running_models_passthrough",
                exc,
                provider="ollama",
                source=source,
            )
            raise
        except (ConnectionError, TimeoutError, OSError, httpx.HTTPError, ValueError) as exc:
            self._logger.warning(
                "ollama_list_running_models_transport_failed",
                provider="ollama",
                source=source,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            raise ProviderError(_ERR_TRANSPORT % exc, provider_name="ollama") from exc

    async def show_model(
        self,
        model: str,
    ) -> OllamaShowResponse:
        """Return detailed metadata for a model via ``/api/show``.

        Args:
            model: Model identifier, optionally prefixed with ``local/`` or
                ``cloud/`` to route the request to a specific source.

        Returns:
            OllamaShowResponse: Typed dict containing ``modelfile``,
            ``parameters``, ``template``, ``details``, and ``capabilities``.

        Raises:
            ProviderError: If not connected, no client is available for
                the requested model, or the server returns a non-success
                HTTP status. Authentication and rate-limit failures
                propagate as the appropriate ``ProviderError`` subclass.
        """
        client, base_url, actual_model = self._get_client_and_model(model)
        try:
            response = await client.post(
                f"{base_url}/api/show",
                json={"name": actual_model},
            )
            self._raise_for_status(response)
            return cast("OllamaShowResponse", response.json())
        except ProviderError as exc:
            log_passthrough(
                self._logger,
                "ollama_show_model_passthrough",
                exc,
                provider="ollama",
                model=actual_model,
            )
            raise
        except (ConnectionError, TimeoutError, OSError, httpx.HTTPError, ValueError) as exc:
            self._logger.warning(
                "ollama_show_model_transport_failed",
                provider="ollama",
                model=actual_model,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            raise ProviderError(_ERR_TRANSPORT % exc, provider_name="ollama") from exc

    async def generate(
        self,
        model: str,
        prompt: str,
        *,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        system: str | None = None,
        context: list[int] | None = None,
    ) -> OllamaGenerateResponse:
        """Generate a non-chat completion via ``/api/generate``.

        This is a single-turn text completion endpoint. For multi-turn
        conversations use :meth:`chat` instead.

        Args:
            model: Model identifier, optionally prefixed with ``local/`` or
                ``cloud/`` to select the source.
            prompt: Raw prompt text to send to the model.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens to generate (``num_predict``).
            system: Optional system prompt override.
            context: Optional prior-context token list returned from a
                previous ``/api/generate`` response.

        Returns:
            OllamaGenerateResponse: Typed response including the full text
            in ``response`` plus ``prompt_eval_count`` and ``eval_count``
            token counters when reported by the server.

        Raises:
            ProviderError: If not connected, no client is available for
                the requested model, or the server returns a non-success
                HTTP status. Authentication and rate-limit failures
                propagate as the appropriate ``ProviderError`` subclass.
        """
        if not self.connected:
            self._logger.error("ollama_generate_not_connected", model=model)
            raise ProviderError(_MSG_NOT_CONNECTED, provider_name="ollama")

        self._logger.info("ollama_generate_starting", model=model, max_tokens=max_tokens)
        client, base_url, actual_model = self._get_client_and_model(model)
        body: dict[str, object] = {
            "model": actual_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if system is not None:
            body["system"] = system
        if context is not None:
            body["context"] = context

        response = await client.post(f"{base_url}/api/generate", json=body)
        self._raise_for_status(response)
        data = cast("OllamaGenerateResponse", response.json())

        prompt_tokens = int(data.get("prompt_eval_count", 0))
        completion_tokens = int(data.get("eval_count", 0))
        self._pending_usage = UsageInfo(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        )
        return data

    async def embeddings(
        self,
        model: str,
        prompt: str,
    ) -> OllamaEmbeddingsResponse:
        """Compute an embedding vector for ``prompt`` via ``/api/embeddings``.

        Args:
            model: Embedding model identifier, optionally prefixed with
                ``local/`` or ``cloud/``.
            prompt: Text to embed.

        Returns:
            OllamaEmbeddingsResponse: Typed dict with an ``embedding`` field
            containing the vector of floats returned by the server.

        Raises:
            ProviderError: If not connected, no client is available for
                the requested model, or the server returns a non-success
                HTTP status. Authentication and rate-limit failures
                propagate as the appropriate ``ProviderError`` subclass.
        """
        if not self.connected:
            self._logger.error("ollama_embeddings_not_connected", model=model)
            raise ProviderError(_MSG_NOT_CONNECTED, provider_name="ollama")

        client, base_url, actual_model = self._get_client_and_model(model)
        body = {"model": actual_model, "prompt": prompt}
        response = await client.post(f"{base_url}/api/embeddings", json=body)
        self._raise_for_status(response)
        return cast("OllamaEmbeddingsResponse", response.json())

    @classmethod
    def _is_cloud_url(cls, url: str) -> bool:
        """Determine whether ``url`` points at the Ollama cloud service.

        Args:
            url: Base URL of an Ollama endpoint.

        Returns:
            bool: True when the URL host matches one of the recognised
            Ollama cloud host fragments.
        """
        lowered = url.lower()
        return any(fragment in lowered for fragment in _CLOUD_HOST_FRAGMENTS)

    def _is_cloud_endpoint(self, base_url: str) -> bool:
        """Decide whether requests for ``base_url`` should use the cloud path layout.

        Cloud Ollama exposes OpenAI-compatible ``/v1/`` endpoints in addition
        to the legacy ``/api/`` ones; chat traffic uses ``/v1/chat/completions``
        when the host is the cloud service or whenever a cloud API key is
        configured for the matching client.

        Args:
            base_url: Base URL associated with the active Ollama client.

        Returns:
            bool: True if the chat call should target the OpenAI-compatible
            ``/v1/chat/completions`` route.
        """
        if self._is_cloud_url(base_url):
            return True
        return base_url == self.CLOUD_API_URL and self._cloud_api_key is not None

    def _chat_endpoint(self, base_url: str) -> str:
        """Return the chat endpoint path appropriate for ``base_url``.

        Args:
            base_url: Base URL associated with the active Ollama client.

        Returns:
            str: ``/v1/chat/completions`` for cloud endpoints, otherwise the
            legacy ``/api/chat`` path used by local Ollama servers.
        """
        return "/v1/chat/completions" if self._is_cloud_endpoint(base_url) else "/api/chat"

    def _get_source_client(self, source: str) -> tuple[httpx.AsyncClient, str]:
        """Resolve a client and base URL by explicit source name.

        Args:
            source: Either ``"local"`` or ``"cloud"``.

        Returns:
            tuple[httpx.AsyncClient, str]: The selected client and its base URL.

        Raises:
            ProviderError: If not connected, the source is unknown, or the
                selected source is unavailable.
        """
        if not self.connected:
            raise ProviderError(_MSG_NOT_CONNECTED, provider_name="ollama")
        normalized = source.lower()
        if normalized == "local":
            if not self._local_available or not self._local_client:
                raise ProviderError(_ERR_LOCAL_NOT_AVAILABLE, provider_name="ollama")
            return self._local_client, self._local_url
        if normalized == "cloud":
            if not self._cloud_available or not self._cloud_client:
                raise ProviderError(_ERR_CLOUD_NOT_AVAILABLE, provider_name="ollama")
            return self._cloud_client, self.CLOUD_API_URL
        msg = _ERR_UNKNOWN_SOURCE % source
        raise ProviderError(msg, provider_name="ollama")

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
            self._raise_for_status(response)
            data = cast("OllamaTagsResponse", response.json())

            raw_models = data.get("models", [])
            model_names = [m.get("name", "") for m in raw_models if m.get("name")]
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
                    ),
                )
        except (ConnectionError, TimeoutError, OSError, httpx.HTTPError, ProviderError) as e:
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
            response = await self._cloud_client.get(f"{self.CLOUD_API_URL}/api/tags")
            self._raise_for_status(response)
            data = cast("OllamaTagsResponse", response.json())

            raw_models = data.get("models", [])
            model_names = [m.get("name", "") for m in raw_models if m.get("name")]
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
                    ),
                )
        except (ConnectionError, TimeoutError, OSError, httpx.HTTPError, ProviderError) as e:
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
                self._logger.error("ollama_cloud_unavailable", model=model)
                raise ProviderError(_ERR_CLOUD_NOT_AVAILABLE, provider_name="ollama")
            return self._cloud_client, self.CLOUD_API_URL, model[6:]

        if model.startswith("local/"):
            if not self._local_available or not self._local_client:
                self._logger.error("ollama_local_unavailable", model=model)
                raise ProviderError(_ERR_LOCAL_NOT_AVAILABLE, provider_name="ollama")
            return self._local_client, self._local_url, model[6:]

        if self._local_available and self._local_client:
            return self._local_client, self._local_url, model
        if self._cloud_available and self._cloud_client:
            return self._cloud_client, self.CLOUD_API_URL, model

        self._logger.error("ollama_no_client_available", model=model)
        raise ProviderError(_ERR_NO_CLIENT, provider_name="ollama")

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
            """Fetch ``num_ctx`` and tool-support flags for a single model.

            Args:
                name: Ollama model name to query via ``/api/show``.

            Returns:
                tuple[str, int, bool]: The model name, its detected context
                window (defaulting to 4096 on failure), and whether its
                template declares a ``.Tools`` directive.
            """
            ctx_window = 4096
            has_tools = False
            try:
                resp = await client.post(
                    f"{base_url}/api/show",
                    json={"name": name},
                )
                self._raise_for_status(resp)
                show_data = cast("OllamaShowResponse", resp.json())
                params_str: str = show_data.get("parameters", "")
                for line in params_str.splitlines():
                    parts = line.strip().split()
                    min_parts = 2
                    if len(parts) >= min_parts and parts[0] == "num_ctx":
                        ctx_window = int(parts[1])
                template: str = show_data.get("template", "")
                if re.search(r"\{\{-?\s*\.Tools\s*-?\}\}", template):
                    has_tools = True
            except (ConnectionError, TimeoutError, OSError, httpx.HTTPError, ValueError, ProviderError) as show_exc:
                self._logger.warning(
                    "ollama_show_failed",
                    model=name,
                    error=str(show_exc),
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
        *,
        enable_cache: bool = False,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Send a chat completion request to Ollama.

        Automatically routes to local or cloud based on model prefix.
        Populates ``self._pending_usage`` with ``UsageInfo`` reflecting the
        ``prompt_eval_count`` and ``eval_count`` tokens reported by the
        server.

        Args:
            messages: Conversation history.
            model: Model name to use (optionally prefixed with local/ or cloud/).
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration (ignored by Ollama).
            enable_cache: Whether to enable prompt caching (ignored by Ollama).

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of (assistant message, tool calls if any).

        Raises:
            ProviderError: If not connected, no client is available for
                the requested model, or the server returns a non-success
                HTTP status. Authentication and rate-limit failures
                propagate as the appropriate ``ProviderError`` subclass.
        """
        if not self.connected:
            self._logger.error("ollama_chat_not_connected", model=model)
            raise ProviderError(_MSG_NOT_CONNECTED, provider_name="ollama")

        self._cancel_requested = False
        if thinking is not None and thinking.enabled:
            self._logger.debug("ollama_thinking_ignored")
        if enable_cache:
            self._logger.debug("ollama_cache_ignored")

        client, base_url, actual_model = self._get_client_and_model(model)
        ollama_messages = self.convert_messages_to_provider_format(messages)
        endpoint = self._chat_endpoint(base_url)
        is_cloud = self._is_cloud_endpoint(base_url)

        log_provider_request(
            provider="ollama",
            model=actual_model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
        )

        request_body: dict[str, object]
        if is_cloud:
            request_body = {
                "model": actual_model,
                "messages": ollama_messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "stream": False,
            }
        else:
            request_body = {
                "model": actual_model,
                "messages": ollama_messages,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            }
        if tools:
            request_body["tools"] = self.convert_tools_to_provider_format(tools)
            if tool_choice is not None:
                request_body["tool_choice"] = self._convert_tool_choice_to_openai_format(tool_choice)

        start_time = time.perf_counter()
        data = await self._make_ollama_api_call(
            client=client,
            base_url=base_url,
            endpoint=endpoint,
            request_body=request_body,
        )
        duration_ms = (time.perf_counter() - start_time) * 1000

        content, tool_calls = self._parse_chat_response(data, is_cloud=is_cloud)
        self._record_usage_from_chat(data, is_cloud=is_cloud)

        return self._build_chat_response(
            provider="ollama",
            model=actual_model,
            content=content,
            tool_calls=tool_calls,
            duration_ms=duration_ms,
        )

    async def _make_ollama_api_call(
        self,
        *,
        client: httpx.AsyncClient,
        base_url: str,
        endpoint: str,
        request_body: dict[str, object],
    ) -> dict[str, Any]:
        """Execute an Ollama chat call with typed error mapping.

        Args:
            client: The httpx async client to use.
            base_url: The base URL for the Ollama API.
            endpoint: Path appended to ``base_url`` for the request, either
                ``/api/chat`` for local or ``/v1/chat/completions`` for cloud.
            request_body: The request payload.

        Returns:
            dict[str, Any]: Parsed JSON response dictionary.

        Raises:
            ProviderError: If a transport error occurs or the server
                returns a non-success HTTP status. Authentication and
                rate-limit failures propagate as the appropriate
                ``ProviderError`` subclass.
        """
        try:
            response = await client.post(
                f"{base_url}{endpoint}",
                json=request_body,
            )
        except (ConnectionError, TimeoutError, OSError, httpx.HTTPError, ValueError) as e:
            self._logger.warning("ollama_request_failed", error=str(e))
            raise ProviderError(_ERR_TRANSPORT % e, provider_name="ollama") from e

        self._raise_for_status(response)
        try:
            return cast("dict[str, Any]", response.json())
        except (ValueError, json.JSONDecodeError) as e:
            self._logger.warning("ollama_response_decode_failed", error=str(e))
            raise ProviderError(_ERR_TRANSPORT % e, provider_name="ollama") from e

    def _parse_chat_response(
        self,
        data: dict[str, Any],
        *,
        is_cloud: bool,
    ) -> tuple[str, list[ToolCall]]:
        """Extract content and tool calls from a chat response payload.

        Cloud responses use the OpenAI-compatible ``choices[0].message``
        envelope; local ``/api/chat`` responses use a ``message`` object at
        the top level.

        Args:
            data: Parsed JSON response from the Ollama server.
            is_cloud: True when the response came from a cloud
                ``/v1/chat/completions`` call.

        Returns:
            tuple[str, list[ToolCall]]: Pair of ``(content, tool_calls)``.
        """
        if is_cloud:
            choices = cast("list[dict[str, Any]]", data.get("choices") or [])
            if not choices:
                return "", []
            cloud_message: dict[str, Any] = cast("dict[str, Any]", choices[0].get("message", {}) or {})
            cloud_content_raw: object = cloud_message.get("content")
            cloud_content = cloud_content_raw if isinstance(cloud_content_raw, str) else ""
            cloud_tool_calls = self._parse_openai_compatible_tool_calls(cloud_message)
            return cloud_content, cloud_tool_calls

        local_message_obj: object = data.get("message") or {}
        local_content_raw: object = ""
        if isinstance(local_message_obj, dict):
            local_content_raw = cast("dict[str, Any]", local_message_obj).get("content")
        local_content = local_content_raw if isinstance(local_content_raw, str) else ""
        local_tool_calls = self._parse_ollama_tool_calls(data)
        return local_content, local_tool_calls

    def _record_usage_from_chat(
        self,
        data: dict[str, Any],
        *,
        is_cloud: bool,
    ) -> None:
        """Update ``self._pending_usage`` from a chat response.

        Args:
            data: Parsed JSON response from the Ollama server.
            is_cloud: True when the response came from a cloud
                ``/v1/chat/completions`` call.
        """
        if is_cloud:
            self._record_usage_from_openai_payload(data)
        else:
            self._record_usage_from_chunk(data)

    def _record_usage_from_openai_payload(self, data: dict[str, Any]) -> None:
        """Update ``self._pending_usage`` from an OpenAI-compatible payload.

        Args:
            data: Parsed JSON payload (full response or streaming chunk)
                with an OpenAI ``usage`` field.
        """
        usage_obj_raw: object = data.get("usage")
        if not isinstance(usage_obj_raw, dict):
            return
        usage_obj: dict[str, Any] = cast("dict[str, Any]", usage_obj_raw)
        try:
            prompt_tokens = int(usage_obj.get("prompt_tokens", 0) or 0)
            completion_tokens = int(usage_obj.get("completion_tokens", 0) or 0)
            total_tokens = int(usage_obj.get("total_tokens", 0) or 0) or (prompt_tokens + completion_tokens)
        except (TypeError, ValueError) as exc:
            self._logger.debug("openai_usage_parse_failed", error=str(exc))
            return
        if prompt_tokens == 0 and completion_tokens == 0:
            return
        self._pending_usage = UsageInfo(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
        )

    def _parse_openai_compatible_tool_calls(
        self,
        message_data: dict[str, Any],
    ) -> list[ToolCall]:
        """Parse tool calls from an OpenAI-compatible chat message.

        Args:
            message_data: The ``choices[0].message`` dict from an OpenAI-
                compatible chat completion response.

        Returns:
            list[ToolCall]: Parsed tool calls, possibly empty.
        """
        tool_calls: list[ToolCall] = []
        raw_calls_obj: object = message_data.get("tool_calls") or []
        if not isinstance(raw_calls_obj, list):
            return tool_calls
        raw_calls: list[Any] = cast("list[Any]", raw_calls_obj)
        for idx, tc in enumerate(cast("list[dict[str, Any]]", raw_calls)):
            func_data: dict[str, Any] = tc.get("function", {}) or {}
            func_name = str(func_data.get("name", ""))
            raw_args: Any = func_data.get("arguments", "{}")
            raw_arguments: str | dict[str, object]
            if isinstance(raw_args, str):
                raw_arguments = raw_args
            elif isinstance(raw_args, dict):
                raw_arguments = cast("dict[str, object]", raw_args)
            else:
                raw_arguments = "{}"
            tool_call = self._parse_tool_call_common(
                call_id=str(tc.get("id") or f"call_{idx}"),
                function_name=func_name,
                raw_arguments=raw_arguments,
            )
            tool_calls.append(tool_call)
        return tool_calls

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

    def _record_usage_from_chunk(self, data: dict[str, Any]) -> None:
        """Update ``self._pending_usage`` from an Ollama response chunk.

        Ollama reports ``prompt_eval_count`` and ``eval_count`` on the
        final frame of a chat or generate response. This helper extracts
        them, coerces to ``int``, and stores a :class:`UsageInfo` snapshot.
        Non-numeric or missing values are treated as zero.

        Args:
            data: The parsed chunk or full response dict.
        """
        try:
            prompt_tokens = int(data.get("prompt_eval_count", 0))
        except (TypeError, ValueError) as exc:
            self._logger.debug("usage_prompt_tokens_parse_failed", error=str(exc))
            prompt_tokens = 0
        try:
            completion_tokens = int(data.get("eval_count", 0))
        except (TypeError, ValueError) as exc:
            self._logger.debug("usage_completion_tokens_parse_failed", error=str(exc))
            completion_tokens = 0
        if prompt_tokens == 0 and completion_tokens == 0:
            return
        self._pending_usage = UsageInfo(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        )

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
        """Stream a chat completion response from Ollama.

        Automatically routes to local or cloud based on model prefix and
        accumulates streamed tool-call deltas in both transports.  The
        final NDJSON frame's ``prompt_eval_count`` and ``eval_count``
        fields (or the OpenAI-compatible ``usage`` block on cloud) are
        recorded in ``self._pending_usage``.

        Args:
            messages: Conversation history.
            model: Model name to use (optionally prefixed with local/ or cloud/).
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration (ignored by Ollama).
            enable_cache: Whether to enable prompt caching (ignored by Ollama).

        Yields:
            str: Text chunks as they arrive.

        Raises:
            ProviderError: If not connected, no client is available for the
                requested model, a transport error occurs, or the server
                returns any other non-2xx status.  ``AuthenticationError``
                (HTTP 401/403) and ``RateLimitError`` (HTTP 429) raised by
                the underlying transport propagate unchanged.
        """
        if not self.connected:
            self._logger.error("ollama_chat_stream_not_connected", model=model)
            raise ProviderError(_MSG_NOT_CONNECTED, provider_name="ollama")

        self._cancel_requested = False
        if thinking is not None and thinking.enabled:
            self._logger.debug("ollama_thinking_ignored")
        if enable_cache:
            self._logger.debug("ollama_cache_ignored")

        client, base_url, actual_model = self._get_client_and_model(model)
        ollama_messages = self.convert_messages_to_provider_format(messages)
        endpoint = self._chat_endpoint(base_url)
        is_cloud = self._is_cloud_endpoint(base_url)

        request_body: dict[str, object]
        if is_cloud:
            request_body = {
                "model": actual_model,
                "messages": ollama_messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "stream": True,
                "stream_options": {"include_usage": True},
            }
        else:
            request_body = {
                "model": actual_model,
                "messages": ollama_messages,
                "stream": True,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            }
        if tools:
            request_body["tools"] = self.convert_tools_to_provider_format(tools)
            if tool_choice is not None:
                request_body["tool_choice"] = self._convert_tool_choice_to_openai_format(tool_choice)

        if is_cloud:
            async for chunk in self._stream_openai_compatible(
                client=client,
                base_url=base_url,
                endpoint=endpoint,
                request_body=request_body,
            ):
                yield chunk
            return

        async for chunk in self._stream_native(
            client=client,
            base_url=base_url,
            endpoint=endpoint,
            request_body=request_body,
        ):
            yield chunk

    async def _stream_native(
        self,
        *,
        client: httpx.AsyncClient,
        base_url: str,
        endpoint: str,
        request_body: dict[str, object],
    ) -> AsyncIterator[str]:
        """Stream a chat completion via the local NDJSON ``/api/chat`` route.

        Captures streamed tool-call deltas as they arrive so callers may
        consume them via ``_pending_tool_calls`` once the stream completes.

        Args:
            client: The httpx async client to use.
            base_url: Base URL of the local Ollama instance.
            endpoint: The ``/api/chat`` path appended to ``base_url``.
            request_body: The fully constructed request payload.

        Yields:
            str: Content chunks as they arrive.

        Raises:
            AuthenticationError: If the server returns HTTP 401 or 403.
            RateLimitError: If the server returns HTTP 429.
            ProviderError: If a transport error occurs or the server returns
                any other non-2xx status.
        """
        last_chunk_data: dict[str, Any] = {}
        accumulated_tool_calls: dict[str, dict[str, Any]] = {}
        tool_call_order: list[str] = []
        try:
            async with client.stream(
                "POST",
                f"{base_url}{endpoint}",
                json=request_body,
            ) as response:
                self._raise_for_status(response)
                async for line in response.aiter_lines():
                    if self._cancel_requested:
                        break
                    chunk_data = self._safe_parse_stream_json(line, logger=self._logger)
                    if chunk_data is None:
                        continue
                    last_chunk_data = chunk_data
                    message_obj_raw: object = last_chunk_data.get("message")
                    if isinstance(message_obj_raw, dict):
                        message_obj: dict[str, Any] = cast("dict[str, Any]", message_obj_raw)
                        content_part = message_obj.get("content")
                        if isinstance(content_part, str) and content_part:
                            yield content_part
                        self._accumulate_native_tool_call_deltas(
                            message_obj,
                            accumulated_tool_calls,
                            tool_call_order,
                        )
        except (AuthenticationError, RateLimitError, ProviderError) as exc:
            log_passthrough(
                self._logger,
                "ollama_stream_native_passthrough",
                exc,
                provider="ollama",
                endpoint=endpoint,
            )
            raise
        except (ConnectionError, TimeoutError, OSError, httpx.HTTPError, ValueError) as e:
            if not self._cancel_requested:
                self._logger.warning("ollama_stream_failed", error=str(e))
                raise ProviderError(_ERR_TRANSPORT % e, provider_name="ollama") from e

        if not self._cancel_requested and last_chunk_data:
            if accumulated_tool_calls:
                self._pending_tool_calls = self._finalize_native_tool_calls(
                    accumulated_tool_calls,
                    tool_call_order,
                )
            else:
                self._pending_tool_calls = self._parse_ollama_tool_calls(last_chunk_data)
            self._record_usage_from_chunk(last_chunk_data)

    @staticmethod
    def _accumulate_native_tool_call_deltas(
        message_obj: dict[str, Any],
        accumulated: dict[str, dict[str, Any]],
        order: list[str],
    ) -> None:
        """Merge tool-call deltas from ``message_obj`` into ``accumulated``.

        Args:
            message_obj: The ``message`` dict from a single NDJSON chunk.
            accumulated: Mapping of stable call ID to the merged payload.
            order: Insertion order of unique call IDs encountered so far.
        """
        deltas_obj: object = message_obj.get("tool_calls")
        if not isinstance(deltas_obj, list):
            return
        deltas = cast("list[dict[str, Any]]", deltas_obj)
        for idx, raw in enumerate(deltas):
            call_id = str(raw.get("id") or f"call_{idx}")
            entry = accumulated.get(call_id)
            if entry is None:
                entry = {"id": call_id, "function": {"name": "", "arguments": ""}}
                accumulated[call_id] = entry
                order.append(call_id)
            func_obj: object = raw.get("function") or {}
            if not isinstance(func_obj, dict):
                continue
            func: dict[str, Any] = cast("dict[str, Any]", func_obj)
            entry_func: dict[str, Any] = cast("dict[str, Any]", entry["function"])
            name_val = func.get("name")
            if isinstance(name_val, str) and name_val:
                entry_func["name"] = name_val
            args_val: object = func.get("arguments")
            if isinstance(args_val, str):
                entry_func["arguments"] = cast("str", entry_func["arguments"]) + args_val
            elif isinstance(args_val, dict):
                entry_func["arguments"] = args_val

    def _finalize_native_tool_calls(
        self,
        accumulated: dict[str, dict[str, Any]],
        order: list[str],
    ) -> list[ToolCall]:
        """Convert accumulated streamed tool-call deltas into ``ToolCall`` objects.

        Args:
            accumulated: Mapping of call IDs to merged tool-call payloads.
            order: Insertion order of unique call IDs.

        Returns:
            list[ToolCall]: Parsed tool calls in their original order.
        """
        results: list[ToolCall] = []
        for call_id in order:
            entry = accumulated[call_id]
            func: dict[str, Any] = cast("dict[str, Any]", entry.get("function") or {})
            raw_args: Any = func.get("arguments", "{}")
            raw_arguments: str | dict[str, object]
            if isinstance(raw_args, str):
                raw_arguments = raw_args or "{}"
            elif isinstance(raw_args, dict):
                raw_arguments = cast("dict[str, object]", raw_args)
            else:
                raw_arguments = "{}"
            results.append(
                self._parse_tool_call_common(
                    call_id=str(entry.get("id") or call_id),
                    function_name=str(func.get("name", "")),
                    raw_arguments=raw_arguments,
                ),
            )
        return results

    async def _stream_openai_compatible(
        self,
        *,
        client: httpx.AsyncClient,
        base_url: str,
        endpoint: str,
        request_body: dict[str, object],
    ) -> AsyncIterator[str]:
        """Stream a chat completion via the cloud OpenAI-compatible route.

        Parses Server-Sent Events ``data: {...}`` frames, accumulates
        OpenAI-style tool-call deltas, and finalises tool calls plus usage
        on completion.

        Args:
            client: The httpx async client to use.
            base_url: Base URL of the cloud Ollama instance.
            endpoint: The ``/v1/chat/completions`` path appended to
                ``base_url``.
            request_body: The fully constructed OpenAI-compatible payload.

        Yields:
            str: Content chunks as they arrive.

        Raises:
            AuthenticationError: If the server returns HTTP 401 or 403.
            RateLimitError: If the server returns HTTP 429.
            ProviderError: If a transport error occurs or the server returns
                any other non-2xx status.
        """
        accumulated_tool_calls: dict[int, dict[str, Any]] = {}
        try:
            async with client.stream(
                "POST",
                f"{base_url}{endpoint}",
                json=request_body,
            ) as response:
                self._raise_for_status(response)
                async for line in response.aiter_lines():
                    if self._cancel_requested:
                        break
                    if not line.startswith("data: "):
                        continue
                    payload = line[6:].strip()
                    if not payload:
                        continue
                    if payload == "[DONE]":
                        break
                    chunk_data = self._safe_parse_stream_json(payload, logger=self._logger)
                    if chunk_data is None:
                        continue
                    self._record_usage_from_openai_payload(chunk_data)
                    choices = cast("list[dict[str, Any]]", chunk_data.get("choices") or [])
                    if not choices:
                        continue
                    delta: dict[str, Any] = cast("dict[str, Any]", choices[0].get("delta", {}) or {})
                    content_delta = delta.get("content")
                    if isinstance(content_delta, str) and content_delta:
                        yield content_delta
                    tc_deltas = delta.get("tool_calls")
                    if isinstance(tc_deltas, list):
                        self._accumulate_openai_tool_call_deltas(
                            cast("list[dict[str, Any]]", tc_deltas),
                            accumulated_tool_calls,
                        )
        except (AuthenticationError, RateLimitError, ProviderError) as exc:
            log_passthrough(
                self._logger,
                "ollama_stream_openai_compatible_passthrough",
                exc,
                provider="ollama",
                endpoint=endpoint,
            )
            raise
        except (ConnectionError, TimeoutError, OSError, httpx.HTTPError, ValueError) as e:
            if not self._cancel_requested:
                self._logger.warning("ollama_stream_failed", error=str(e))
                raise ProviderError(_ERR_TRANSPORT % e, provider_name="ollama") from e

        if not self._cancel_requested and accumulated_tool_calls:
            self._pending_tool_calls = self._finalize_openai_tool_calls(accumulated_tool_calls)

    @staticmethod
    def _accumulate_openai_tool_call_deltas(
        deltas: list[dict[str, Any]],
        accumulated: dict[int, dict[str, Any]],
    ) -> None:
        """Merge OpenAI-style tool-call deltas keyed by index.

        Mirrors :meth:`_accumulate_native_tool_call_deltas` for the cloud
        OpenAI-compatible streaming route. ``arguments`` may arrive either
        as incremental string deltas (the canonical OpenAI shape) or as a
        complete dict object on a single chunk (Ollama Cloud emits this
        form for some models). Both shapes are preserved without loss; a
        later string fragment never overwrites an already-captured dict
        because once a dict has been recorded the entry is locked.

        Args:
            deltas: The ``tool_calls`` array from a single streaming chunk.
            accumulated: Mapping of delta ``index`` to the merged payload.
        """
        for delta in deltas:
            index = int(delta.get("index", 0))
            entry = accumulated.get(index)
            if entry is None:
                entry = {"id": delta.get("id"), "function": {"name": "", "arguments": ""}}
                accumulated[index] = entry
            id_val = delta.get("id")
            if isinstance(id_val, str) and id_val:
                entry["id"] = id_val
            func_obj: object = delta.get("function") or {}
            if not isinstance(func_obj, dict):
                continue
            func_delta: dict[str, Any] = cast("dict[str, Any]", func_obj)
            entry_func: dict[str, Any] = cast("dict[str, Any]", entry["function"])
            name_val = func_delta.get("name")
            if isinstance(name_val, str) and name_val:
                entry_func["name"] = name_val
            args_val: object = func_delta.get("arguments")
            current_args: object = entry_func.get("arguments", "")
            if isinstance(args_val, str) and args_val and isinstance(current_args, str):
                entry_func["arguments"] = current_args + args_val
            elif isinstance(args_val, dict):
                entry_func["arguments"] = cast("dict[str, object]", args_val)

    def _finalize_openai_tool_calls(
        self,
        accumulated: dict[int, dict[str, Any]],
    ) -> list[ToolCall]:
        """Convert merged OpenAI tool-call deltas into ``ToolCall`` objects.

        Args:
            accumulated: Mapping of delta indices to merged tool-call payloads.

        Returns:
            list[ToolCall]: Parsed tool calls in delta-index order.
        """
        results: list[ToolCall] = []
        for index in sorted(accumulated.keys()):
            entry = accumulated[index]
            func: dict[str, Any] = cast("dict[str, Any]", entry.get("function") or {})
            raw_args_obj: object = func.get("arguments")
            raw_arguments: str | dict[str, object]
            if isinstance(raw_args_obj, dict):
                raw_arguments = cast("dict[str, object]", raw_args_obj)
            elif isinstance(raw_args_obj, str) and raw_args_obj:
                raw_arguments = raw_args_obj
            else:
                raw_arguments = "{}"
            call_id_val: object = entry.get("id")
            call_id = call_id_val if isinstance(call_id_val, str) and call_id_val else f"call_{index}"
            results.append(
                self._parse_tool_call_common(
                    call_id=str(call_id),
                    function_name=str(func.get("name", "")),
                    raw_arguments=raw_arguments,
                ),
            )
        return results

    async def cancel_request(self) -> None:
        """Cancel any in-flight request."""
        self._logger.info("ollama_cancel_requested")
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
            AuthenticationError: If the server returns HTTP 401 or 403.
            RateLimitError: If the server returns HTTP 429.
            ProviderError: If local Ollama is not connected, a transport
                error occurs, or the server returns any other non-2xx
                status.
        """
        if not self._local_available or not self._local_client:
            raise ProviderError(_ERR_LOCAL_PULL_UNAVAILABLE, provider_name="ollama")

        actual_model = model_name
        if model_name.startswith("local/"):
            actual_model = model_name[6:]

        try:
            async with self._local_client.stream(
                "POST",
                f"{self._local_url}/api/pull",
                json={"name": actual_model},
            ) as response:
                self._raise_for_status(response)
                async for line in response.aiter_lines():
                    if line:
                        try:
                            data = json.loads(line)
                        except json.JSONDecodeError:
                            self._logger.warning("pull_status_json_decode_failed")
                            continue
                        if status := data.get("status", ""):
                            yield status
        except (AuthenticationError, RateLimitError, ProviderError) as exc:
            log_passthrough(
                self._logger,
                "ollama_pull_model_passthrough",
                exc,
                provider="ollama",
                model=actual_model,
            )
            raise
        except (ConnectionError, TimeoutError, OSError, httpx.HTTPError) as e:
            self._logger.warning("ollama_pull_failed", model=actual_model, error=str(e))
            raise ProviderError(_ERR_TRANSPORT % e, provider_name="ollama") from e
