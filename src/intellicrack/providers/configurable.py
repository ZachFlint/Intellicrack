# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""One HTTP provider class, driven entirely by a configured instance record.

There is nothing endpoint-specific in this file. Which wire format to speak,
where to send it, what headers it wants, what body parameters to add or drop
and what its models can do all come from the
:class:`~intellicrack.providers.instances.ProviderInstance` it was built with,
and every wire detail lives behind the dialect adapter that instance names.

That is what makes an arbitrary endpoint a first-class provider rather than a
special case: a corporate gateway, a LiteLLM proxy, vLLM, Together, Groq,
Cerebras, DeepSeek or a second OpenAI account is a record, not a class.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final, override

import httpx

from intellicrack.core.json_payload import is_json_array, is_json_object
from intellicrack.core.logging import get_logger, log_provider_request, log_provider_response
from intellicrack.core.types import (
    AuthenticationError,
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
)
from intellicrack.providers.base import (
    HttpErrorMessages,
    LLMProviderBase,
    ToolCallBufferManager,
)
from intellicrack.providers.capabilities import ApiDialect, merge_capabilities
from intellicrack.providers.dialects import adapter_for
from intellicrack.providers.dialects.base import DialectRequest
from intellicrack.providers.model_metadata import ingest_models


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from intellicrack.core.types import (
        ReasoningItem,
        ThinkingConfig,
        ToolCall,
        ToolChoice,
        ToolDefinition,
    )
    from intellicrack.providers.capabilities import ModelCapabilities
    from intellicrack.providers.dialects.base import DialectAdapter
    from intellicrack.providers.instances import ProviderInstance


_logger = get_logger(__name__)

DEFAULT_TIMEOUT_SECONDS: Final[float] = 120.0
"""Request timeout applied when the instance states none."""

SSE_DATA_PREFIX: Final[str] = "data:"
"""Prefix of an SSE payload line."""

SSE_DONE_SENTINEL: Final[str] = "[DONE]"
"""Payload an OpenAI-compatible stream sends to mark the end."""

_MODEL_LIST_PATHS: Final[dict[ApiDialect, str]] = {
    ApiDialect.CHAT_COMPLETIONS: "models",
    ApiDialect.RESPONSES: "models",
    ApiDialect.MESSAGES: "v1/models",
    ApiDialect.GEMINI: "v1beta/models",
}
"""Where each dialect lists its models, relative to the instance's base URL."""

_ERR_NOT_CONNECTED: Final[str] = "Not connected"
_ERR_NO_BASE_URL: Final[str] = "This provider instance has no base URL configured"
_ERR_MISSING_KEY: Final[str] = "An API key is required for provider instance %s"
_ERR_LIST_MODELS_FAILED: Final[str] = "Failed to list models for %s: %s"
_ERR_REQUEST_FAILED: Final[str] = "Request to %s failed: %s"
_ERR_STREAM_FAILED: Final[str] = "Stream from %s failed: %s"
_ERR_PAYLOAD_NOT_OBJECT: Final[str] = "Response from %s was not a JSON object"

_ERR_KEY_WITHHELD: Final[str] = (
    "This instance sends plain HTTP to a public host. Acknowledge the insecure transport in Provider Settings "
    "before its API key is attached."
)

_HTTP_ERRORS = HttpErrorMessages(
    auth_invalid="Invalid credentials for this provider instance: %s",
    rate_limited="Provider instance rate limit exceeded: %s",
    service_unavailable="Provider instance is unavailable: %s",
)


class ConfigurableProvider(LLMProviderBase):
    """An HTTP provider whose entire behaviour comes from its instance record.

    Attributes:
        instance: The configured endpoint this provider talks to.
    """

    instance: ProviderInstance

    def __init__(self, instance: ProviderInstance) -> None:
        """Initialize the provider for one configured endpoint.

        Args:
            instance: The endpoint record driving every request.
        """
        super().__init__()
        self.instance = instance
        self._adapter: DialectAdapter = adapter_for(instance.dialect)
        self._client: httpx.AsyncClient | None = None
        self._client_loop: asyncio.AbstractEventLoop | None = None
        self._logger = get_logger(__name__).bind(provider=instance.instance_id)
        for model_id, model_override in instance.model_overrides.items():
            self.set_capability_override(model_id, model_override)
        self._logger.info("configurable_provider_initialized", dialect=instance.dialect.value)

    @property
    @override
    def name(self) -> str:
        """The provider instance id.

        Returns:
            str: The id this instance is registered under.
        """
        return self.instance.instance_id

    @property
    @override
    def preset_id(self) -> str:
        """The preset supplying this instance's capability defaults.

        Returns:
            str: The preset id, falling back to the instance id when the
            instance was configured entirely by hand.
        """
        return self.instance.preset_id or self.instance.instance_id

    @property
    @override
    def dialect(self) -> ApiDialect:
        """The wire format this instance speaks.

        Returns:
            ApiDialect: The instance's configured dialect.
        """
        return self.instance.dialect

    @override
    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect to the configured endpoint.

        Args:
            credentials: Credentials for the endpoint. ``api_base`` overrides
                the instance's configured base URL for this session.

        Raises:
            AuthenticationError: If the endpoint requires a key and none is
                available, or the transport policy withholds the one there is.
            ProviderError: If no base URL is configured for this instance.
        """
        self._credentials = credentials
        base_url = (credentials.api_base or self.instance.api_base or "").strip()
        if not base_url:
            self._logger.error("configurable_connect_no_base_url")
            raise ProviderError(_ERR_NO_BASE_URL, provider_name=self.name)

        api_key = credentials.api_key
        if self.instance.requires_api_key and not api_key:
            self._logger.warning("configurable_connect_missing_key")
            raise AuthenticationError(_ERR_MISSING_KEY % self.name)
        if api_key and not self.instance.may_send_api_key():
            self._logger.warning("configurable_connect_insecure_transport_unacknowledged", base_url=base_url)
            raise AuthenticationError(_ERR_KEY_WITHHELD)

        timeout = credentials.timeout or self.instance.timeout_seconds or DEFAULT_TIMEOUT_SECONDS
        await self._close_client()
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/") + "/",
            headers=self._request_headers(),
            timeout=httpx.Timeout(timeout),
        )
        self._client_loop = asyncio.get_running_loop()
        self.connected = True
        self._logger.info("configurable_provider_connected", base_url=base_url, dialect=self.dialect.value)

    @override
    async def disconnect(self) -> None:
        """Disconnect and release the HTTP client."""
        await self._close_client()
        await super().disconnect()

    async def _close_client(self) -> None:
        """Close the HTTP client if one is open."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
            self._client_loop = None

    def _request_headers(self) -> dict[str, str]:
        """Build the headers every request carries.

        The adapter's inferred auth header is suppressed whenever the instance
        supplies one of its own, so a gateway never receives two credentials
        that disagree.

        Returns:
            dict[str, str]: The headers to send.
        """
        api_key = self._credentials.api_key if self._credentials is not None else None
        if api_key and not self.instance.may_send_api_key():
            api_key = None
        headers = self._adapter.resolve_headers(api_key, self.instance.headers)
        headers.setdefault("Content-Type", "application/json")
        return headers

    async def _require_client(self) -> httpx.AsyncClient:
        """Return the HTTP client, rebuilding it for the running loop if needed.

        httpcore binds a pool's synchronization primitives to the loop the
        client first issues a request on, so a client built during ``connect``
        on one loop cannot be reused from another.

        Returns:
            httpx.AsyncClient: A client valid for the running loop.

        Raises:
            ProviderError: If the provider is not connected.
        """
        if self._client is None or not self.connected:
            raise ProviderError(_ERR_NOT_CONNECTED, provider_name=self.name)
        target = self._httpx_client_rebind_target(self._client_loop)
        if target is None:
            return self._client
        base_url = str(self._client.base_url)
        timeout = self._client.timeout
        await self._client.aclose()
        self._client = httpx.AsyncClient(base_url=base_url, headers=self._request_headers(), timeout=timeout)
        self._client_loop = target
        return self._client

    @override
    async def list_models(self) -> list[ModelInfo]:
        """List the endpoint's models, ingesting whatever metadata it states.

        Returns:
            list[ModelInfo]: The endpoint's models, sorted by id.

        Raises:
            ProviderError: If not connected or the request fails.
        """
        client = await self._require_client()
        path = _MODEL_LIST_PATHS[self.instance.dialect]
        try:
            response = await client.get(path)
            response.raise_for_status()
            payload: object = response.json()
        except httpx.HTTPStatusError as exc:
            self._raise_typed_for_status(
                exc.response.status_code,
                exc,
                messages=_HTTP_ERRORS,
                detail=self._http_error_detail(exc, _safe_body(exc.response)),
            )
            raise ProviderError(_ERR_LIST_MODELS_FAILED % (self.name, exc)) from exc
        except (httpx.HTTPError, ValueError) as exc:
            self._logger.warning("configurable_list_models_failed", error=str(exc))
            raise ProviderError(_ERR_LIST_MODELS_FAILED % (self.name, exc)) from exc

        if not is_json_object(payload):
            self._logger.warning("configurable_model_payload_not_an_object")
            return []

        models: list[ModelInfo] = []
        for ingested in ingest_models(payload):
            base = self.capabilities_for(ingested.model_id)
            capabilities = merge_capabilities(base, ingested.capabilities)
            self.ingest_model_capabilities(ingested.model_id, capabilities)
            info = ingested.to_model_info(self.name, capabilities.context_window or 0)
            info.capabilities = capabilities
            info.supports_tools = capabilities.supports_tools
            info.supports_vision = capabilities.supports_vision
            info.supports_streaming = capabilities.supports_streaming
            models.append(info)

        models.sort(key=lambda model: model.id)
        self._logger.info("configurable_models_listed", count=len(models))
        return models

    def _build_body(
        self,
        *,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None,
        temperature: float,
        max_tokens: int,
        tool_choice: ToolChoice | None,
        thinking: ThinkingConfig | None,
        enable_cache: bool,
        stream: bool,
    ) -> tuple[dict[str, Any], ModelCapabilities]:
        """Build one request body through this instance's adapter.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in the response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration.
            enable_cache: Whether to request prompt caching.
            stream: Whether the request streams.

        Returns:
            tuple[dict[str, Any], ModelCapabilities]: The JSON body and the
            capability record it was built against.
        """
        capabilities = self.capabilities_for(model)
        capped = self._enforce_tool_count_cap(tools, capabilities) if tools else []
        body = self._adapter.build_request(
            DialectRequest(
                model=model,
                messages=messages,
                capabilities=capabilities,
                tools=capped,
                temperature=temperature,
                max_tokens=max_tokens,
                tool_choice=tool_choice,
                thinking=thinking,
                enable_cache=enable_cache,
                stream=stream,
                store=self.instance.store_responses,
                extra_body=self.instance.extra_body,
                drop_params=self.instance.drop_params,
                tool_name_style=self.instance.tool_name_style,
            ),
        )
        return body, capabilities

    @override
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
        """Send a chat completion request to the configured endpoint.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration.
            enable_cache: Whether to enable prompt caching.

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of (assistant message, tool calls if any).

        Note:
            A transport or HTTP failure surfaces as the typed error
            :meth:`_post_json` raises -- ``AuthenticationError``,
            ``RateLimitError`` or ``ProviderError`` -- and a provider that is
            not connected raises ``ProviderError`` from
            :meth:`_require_client`.
        """
        self._reject_empty_messages(messages)
        self._cancel_requested = False
        self._pending_usage = None
        self._pending_reasoning.clear()

        client = await self._require_client()
        body, _ = self._build_body(
            messages=messages,
            model=model,
            tools=tools,
            temperature=temperature,
            max_tokens=max_tokens,
            tool_choice=tool_choice,
            thinking=thinking,
            enable_cache=enable_cache,
            stream=False,
        )
        log_provider_request(
            provider=self.name,
            model=model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
            temperature=temperature,
        )

        path = self._adapter.endpoint_path(model=model, stream=False)
        start_time = time.perf_counter()
        payload = await self._retry_with_backoff(lambda: self._post_json(client, path, body))
        duration_ms = (time.perf_counter() - start_time) * 1000

        parsed = self._adapter.parse_response(payload)
        self._pending_usage = parsed.usage
        self._pending_reasoning = list(parsed.reasoning)
        self._pending_thinking.extend(item.text for item in parsed.reasoning if item.text)
        tool_calls = list(parsed.tool_calls)
        message = Message(
            role="assistant",
            content=parsed.content,
            tool_calls=tool_calls or None,
            reasoning=list(parsed.reasoning) or None,
            timestamp=datetime.now(tz=UTC),
        )
        log_provider_response(
            provider=self.name,
            model=model,
            tool_calls_count=len(tool_calls),
            duration_ms=duration_ms,
        )
        return message, tool_calls or None

    async def _post_json(self, client: httpx.AsyncClient, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST a request body and decode the JSON response.

        Args:
            client: The HTTP client to send through.
            path: Request path relative to the instance's base URL.
            body: The JSON body to send.

        Returns:
            dict[str, Any]: The decoded response body.

        Raises:
            ProviderError: If the request fails or the body is not an object.
        """
        try:
            response = await client.post(path, json=body)
            response.raise_for_status()
            decoded: object = response.json()
        except httpx.HTTPStatusError as exc:
            self._raise_typed_for_status(
                exc.response.status_code,
                exc,
                messages=_HTTP_ERRORS,
                detail=self._http_error_detail(exc, _safe_body(exc.response)),
            )
            raise ProviderError(_ERR_REQUEST_FAILED % (self.name, exc)) from exc
        except (httpx.HTTPError, ValueError) as exc:
            self._logger.warning("configurable_request_failed", error=str(exc))
            raise ProviderError(_ERR_REQUEST_FAILED % (self.name, exc)) from exc
        if not is_json_object(decoded):
            raise ProviderError(_ERR_PAYLOAD_NOT_OBJECT % self.name)
        return decoded

    @override
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
        """Stream a chat completion response from the configured endpoint.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration.
            enable_cache: Whether to enable prompt caching.

        Yields:
            str: Text chunks as they arrive.

        Note:
            A transport or HTTP failure surfaces as the typed error
            :meth:`_open_stream` raises, and a provider that is not connected
            raises ``ProviderError`` from :meth:`_require_client`.
        """
        self._reject_empty_messages(messages)
        self._cancel_requested = False
        self._pending_usage = None
        self._pending_reasoning.clear()

        client = await self._require_client()
        body, _ = self._build_body(
            messages=messages,
            model=model,
            tools=tools,
            temperature=temperature,
            max_tokens=max_tokens,
            tool_choice=tool_choice,
            thinking=thinking,
            enable_cache=enable_cache,
            stream=True,
        )
        log_provider_request(
            provider=self.name,
            model=model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
            temperature=temperature,
        )

        path = self._adapter.endpoint_path(model=model, stream=True)
        buffer = ToolCallBufferManager()
        reasoning: list[ReasoningItem] = []
        async for event in self._open_stream(client, path, body):
            if self._cancel_requested:
                break
            for delta in self._adapter.parse_stream_event(event):
                buffer.absorb(delta)
                if delta.usage is not None:
                    self._pending_usage = delta.usage
                if delta.reasoning_item is not None:
                    reasoning.append(delta.reasoning_item)
                if delta.reasoning:
                    self._pending_thinking.append(delta.reasoning)
                if delta.text:
                    yield delta.text

        self._pending_tool_calls = buffer.finalize()
        self._pending_reasoning = reasoning

    async def _open_stream(
        self,
        client: httpx.AsyncClient,
        path: str,
        body: dict[str, Any],
    ) -> AsyncIterator[dict[str, Any]]:
        """Open the streaming request and yield its decoded events.

        The streaming context is held on an :class:`~contextlib.AsyncExitStack`
        rather than a ``with`` block, so the generator's own cleanup closes the
        response even when the consumer stops iterating early -- which is what
        a mid-stream cancel does.

        Args:
            client: The HTTP client to send through.
            path: Request path relative to the instance's base URL.
            body: The JSON body to send.

        Yields:
            dict[str, Any]: One decoded event per payload.

        Raises:
            ProviderError: If the stream cannot be opened or fails mid-flight.
        """
        stack = contextlib.AsyncExitStack()
        try:
            response = await stack.enter_async_context(client.stream("POST", path, json=body))
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            await stack.aclose()
            await _read_error_body(exc.response)
            self._raise_typed_for_status(
                exc.response.status_code,
                exc,
                messages=_HTTP_ERRORS,
                detail=self._http_error_detail(exc, _safe_body(exc.response)),
            )
            raise ProviderError(_ERR_STREAM_FAILED % (self.name, exc)) from exc
        except (httpx.HTTPError, ValueError) as exc:
            await stack.aclose()
            self._logger.warning("configurable_stream_open_failed", error=str(exc))
            raise ProviderError(_ERR_STREAM_FAILED % (self.name, exc)) from exc

        try:
            async for event in self._iter_events(response):
                yield event
        except (httpx.HTTPError, ValueError) as exc:
            self._logger.warning(
                "configurable_stream_failed",
                error=str(exc),
                cancel_requested=self._cancel_requested,
            )
            raise ProviderError(_ERR_STREAM_FAILED % (self.name, exc)) from exc
        finally:
            await stack.aclose()

    async def _iter_events(self, response: httpx.Response) -> AsyncIterator[dict[str, Any]]:
        """Decode a streaming response into events.

        Server-sent events carry one JSON payload per ``data:`` line; Gemini
        streams newline-delimited JSON instead. Both reduce to the same thing
        here, so the adapter never sees a transport framing difference.

        Args:
            response: The open streaming response.

        Yields:
            dict[str, Any]: One decoded event per payload.
        """
        async for raw_line in response.aiter_lines():
            line = raw_line.strip()
            if not line:
                continue
            payload_text = line[len(SSE_DATA_PREFIX) :].strip() if line.startswith(SSE_DATA_PREFIX) else line
            if not payload_text or payload_text == SSE_DONE_SENTINEL:
                continue
            if payload_text.startswith(("event:", "id:", "retry:", ":")):
                continue
            decoded = self._safe_parse_stream_json(payload_text.lstrip("[,").rstrip(",]"), logger=self._logger)
            if decoded is not None:
                yield decoded

    @override
    async def cancel_request(self) -> None:
        """Cancel any in-flight request.

        Setting the flag stops the stream loop at its next event, which closes the ``httpx`` streaming context and disconnects server-side
        rather than draining the response.
        """
        self._cancel_requested = True
        self._logger.info("configurable_request_cancelled")

    @override
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Convert internal tools to this instance's wire format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            list[dict[str, object]]: Tool schemas in the dialect's format.
        """
        capabilities = self.capabilities_for(self.instance.default_model)
        schemas = self._adapter.build_tool_schemas(
            self._enforce_tool_count_cap(tools, capabilities),
            capabilities,
            name_style=self.instance.tool_name_style,
        )
        return [dict(schema) for schema in schemas]

    @override
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Convert internal messages to this instance's wire format.

        Args:
            messages: List of Message objects.

        Returns:
            list[dict[str, object]]: The message array the dialect's request
            body would carry.
        """
        body, _ = self._build_body(
            messages=messages,
            model=self.instance.default_model,
            tools=None,
            temperature=0.7,
            max_tokens=1,
            tool_choice=None,
            thinking=None,
            enable_cache=False,
            stream=False,
        )
        for key in ("messages", "input", "contents"):
            raw = body.get(key)
            if is_json_array(raw):
                entries: list[Any] = raw
                return [entry for entry in entries if is_json_object(entry)]
        return []


def _safe_body(response: httpx.Response) -> str:
    """Read a failed response's body without letting the read itself fail.

    ``httpx`` refuses ``.text`` on a response whose content was never read.
    Losing the body is acceptable; losing the HTTP error to a secondary
    exception is not.

    Args:
        response: The failing response.

    Returns:
        str: The body text, or an empty string when it cannot be read.
    """
    try:
        return response.text
    except (httpx.ResponseNotRead, httpx.StreamError, UnicodeDecodeError, ValueError):
        return ""


async def _read_error_body(response: httpx.Response) -> None:
    """Read a failed streaming response so its body is available for the error.

    Args:
        response: The failing streaming response.
    """
    with contextlib.suppress(httpx.HTTPError, ValueError):
        await response.aread()


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "ConfigurableProvider",
]
