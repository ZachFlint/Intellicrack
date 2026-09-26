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
import email.utils
import json
import math
import re
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final, NoReturn, override

import httpx

from intellicrack.core.json_payload import is_json_array, is_json_object
from intellicrack.core.logging import get_logger, log_provider_request, log_provider_response
from intellicrack.core.types import (
    AuthenticationError,
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    RateLimitError,
)
from intellicrack.providers.base import (
    HttpErrorMessages,
    LLMProviderBase,
    ToolCallBufferManager,
    is_permanent_quota_error,
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

SSE_DATA_FIELD: Final[str] = "data"
"""Name of the SSE field carrying an event's payload."""

_SSE_FIELDS: Final[frozenset[str]] = frozenset({SSE_DATA_FIELD, "event", "id", "retry"})
"""Every field name the SSE format defines."""

SSE_DONE_SENTINEL: Final[str] = "[DONE]"
"""Payload an OpenAI-compatible stream sends to mark the end."""

_MODEL_LIST_PATHS: Final[dict[ApiDialect, str]] = {
    ApiDialect.CHAT_COMPLETIONS: "models",
    ApiDialect.RESPONSES: "models",
    ApiDialect.MESSAGES: "v1/models",
    ApiDialect.GEMINI: "v1beta/models",
}
"""Where each dialect lists its models, relative to the instance's base URL."""

_MODEL_PAGE_SIZE: Final[int] = 1000
"""Largest page both paginated model listings accept (Anthropic ``limit``, Gemini ``pageSize``)."""

_MAX_RETRY_WAIT_SECONDS: Final[float] = 60.0
"""Longest wait honoured between rate-limit retries; a longer server-requested wait fails fast instead."""

_HTTP_TOO_MANY_REQUESTS: Final[int] = 429

_RETRY_INFO_TYPE_SUFFIX: Final[str] = "google.rpc.RetryInfo"
"""``@type`` suffix of the Google error detail carrying a ``retryDelay``."""

_DURATION_PATTERN: Final[re.Pattern[str]] = re.compile(r"^\s*(\d+(?:\.\d+)?)s\s*$")
"""A protobuf ``Duration`` in its JSON form, for example ``"37s"`` or ``"1.5s"``."""

_ERR_NOT_CONNECTED: Final[str] = "Not connected"
_ERR_NO_BASE_URL: Final[str] = "This provider instance has no base URL configured"
_ERR_MISSING_KEY: Final[str] = "An API key is required for provider instance %s"
_ERR_LIST_MODELS_FAILED: Final[str] = "Failed to list models for %s: %s"
_ERR_REQUEST_FAILED: Final[str] = "Request to %s failed: %s"
_ERR_STREAM_FAILED: Final[str] = "Stream from %s failed: %s"
_ERR_PAYLOAD_NOT_OBJECT: Final[str] = "Response from %s was not a JSON object"
_ERR_BODY_NOT_JSON: Final[str] = "Request body for %s cannot be encoded as JSON: %s"
_ERR_QUOTA_EXHAUSTED: Final[str] = "Provider instance %s quota or spending cap exhausted: %s"

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

        Anthropic and Gemini page their listings, so every page is fetched
        and the entries are ingested together.

        Returns:
            list[ModelInfo]: The endpoint's models, sorted by id.

        Note:
            A transport or HTTP failure surfaces as the typed error
            :meth:`_get_model_page` raises, and a provider that is not
            connected raises ``ProviderError`` from :meth:`_require_client`.
        """
        client = await self._require_client()
        payload = await self._fetch_model_listing(client)
        if payload is None:
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

    async def _fetch_model_listing(self, client: httpx.AsyncClient) -> dict[str, Any] | None:
        """Fetch every page of the model listing and merge them into one payload.

        Anthropic pages with ``limit``/``after_id`` and reports ``has_more``
        and ``last_id``; Gemini pages with ``pageSize``/``pageToken`` and
        reports ``nextPageToken``. The other dialects answer in one response.

        Args:
            client: The HTTP client to send through.

        Returns:
            dict[str, Any] | None: The first page with its entry list
            replaced by the entries of every page, or ``None`` when the first
            page is not a JSON object.
        """
        dialect = self.instance.dialect
        path = _MODEL_LIST_PATHS[dialect]
        if dialect is ApiDialect.MESSAGES:
            entries_key, size_param, cursor_param = "data", "limit", "after_id"
        elif dialect is ApiDialect.GEMINI:
            entries_key, size_param, cursor_param = "models", "pageSize", "pageToken"
        else:
            return await self._get_model_page(client, path, {})

        params: dict[str, str | int] = {size_param: _MODEL_PAGE_SIZE}
        first: dict[str, Any] | None = None
        entries: list[Any] = []
        seen_cursors: set[str] = set()
        while True:
            page = await self._get_model_page(client, path, params)
            if page is None:
                break
            if first is None:
                first = page
            raw_entries = page.get(entries_key)
            if is_json_array(raw_entries):
                page_entries: list[Any] = raw_entries
                entries.extend(page_entries)
            cursor = _next_model_page_cursor(page, dialect)
            if cursor is None or cursor in seen_cursors:
                break
            seen_cursors.add(cursor)
            params[cursor_param] = cursor
        if first is None:
            return None
        return {**first, entries_key: entries}

    async def _get_model_page(
        self,
        client: httpx.AsyncClient,
        path: str,
        params: dict[str, str | int],
    ) -> dict[str, Any] | None:
        """GET one page of the model listing.

        Args:
            client: The HTTP client to send through.
            path: Listing path relative to the instance's base URL.
            params: Query parameters for this page.

        Returns:
            dict[str, Any] | None: The decoded page, or ``None`` when it is
            not a JSON object.

        Raises:
            ProviderError: If the request fails or the body is not JSON.
        """
        try:
            response = await client.get(path, params=params)
            response.raise_for_status()
            payload: object = response.json()
        except httpx.HTTPStatusError as exc:
            self._raise_for_http_status(exc, _ERR_LIST_MODELS_FAILED)
        except (httpx.HTTPError, ValueError) as exc:
            self._logger.warning("configurable_list_models_failed", error=str(exc))
            raise ProviderError(_ERR_LIST_MODELS_FAILED % (self.name, exc), provider_name=self.name) from exc
        return payload if is_json_object(payload) else None

    def _raise_for_http_status(self, exc: httpx.HTTPStatusError, template: str) -> NoReturn:
        """Raise the typed error for a failed HTTP response, keeping its detail.

        Every status carries the response body's redacted detail. A ``429``
        becomes a :class:`RateLimitError` carrying the server's requested
        wait -- ``Retry-After`` in seconds or as an HTTP-date, or Google's
        ``RetryInfo.retryDelay`` -- unless the server gave no wait and the
        body reports a permanent quota or billing exhaustion, which no retry
        can fix and so becomes a plain :class:`ProviderError`.

        Args:
            exc: The HTTP status error, whose response body has been read.
            template: Message template taking the instance name and detail,
                used for statuses without a dedicated typed error.

        Raises:
            ProviderError: For a permanent quota exhaustion or any status
                without a dedicated typed error.
            RateLimitError: For a transient ``429``.
        """
        response = exc.response
        status = response.status_code
        body = _safe_body(response)
        detail = self._http_error_detail(exc, body)
        if status == _HTTP_TOO_MANY_REQUESTS:
            retry_after = _retry_after_seconds(response.headers.get("retry-after"), body)
            if retry_after is None and is_permanent_quota_error(detail):
                self._logger.warning("configurable_quota_exhausted", status=status)
                raise ProviderError(
                    _ERR_QUOTA_EXHAUSTED % (self.name, detail),
                    provider_name=self.name,
                    status_code=status,
                ) from exc
            raise RateLimitError(
                _HTTP_ERRORS.rate_limited % detail,
                retry_after=retry_after,
                provider_name=self.name,
                status_code=status,
            ) from exc
        self._raise_typed_for_status(status, exc, messages=_HTTP_ERRORS, detail=detail)
        raise ProviderError(template % (self.name, detail), provider_name=self.name, status_code=status) from exc

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
        payload = await self._retry_with_backoff(
            lambda: self._post_json(client, path, body),
            max_delay=_MAX_RETRY_WAIT_SECONDS,
        )
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
            ProviderError: If the body cannot be encoded, the request fails
                or the response is not an object.
        """
        content = self._encode_body(body)
        try:
            response = await client.post(path, content=content)
            response.raise_for_status()
            decoded: object = response.json()
        except httpx.HTTPStatusError as exc:
            self._raise_for_http_status(exc, _ERR_REQUEST_FAILED)
        except (httpx.HTTPError, ValueError) as exc:
            self._logger.warning("configurable_request_failed", error=str(exc))
            raise ProviderError(_ERR_REQUEST_FAILED % (self.name, exc), provider_name=self.name) from exc
        if not is_json_object(decoded):
            raise ProviderError(_ERR_PAYLOAD_NOT_OBJECT % self.name, provider_name=self.name)
        return decoded

    def _encode_body(self, body: dict[str, Any]) -> bytes:
        """Encode a request body as UTF-8 JSON, the way ``httpx`` would.

        Encoding here rather than through ``httpx``'s ``json=`` turns a body
        holding a value JSON cannot represent -- ``bytes``, a set, ``NaN`` --
        into this provider's error type instead of a bare ``TypeError`` from
        inside the transport.

        Args:
            body: The JSON body to send.

        Returns:
            bytes: The encoded body.

        Raises:
            ProviderError: If the body holds a value JSON cannot represent.
        """
        try:
            return json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            self._logger.exception("configurable_request_body_not_json")
            raise ProviderError(_ERR_BODY_NOT_JSON % (self.name, exc), provider_name=self.name) from exc

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
            :meth:`_open_stream_response` raises, and a provider that is not
            connected raises ``ProviderError`` from :meth:`_require_client`.
            A rate-limited stream is retried before any text is yielded.
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
        stream_adapter = adapter_for(self.instance.dialect)
        buffer = ToolCallBufferManager()
        reasoning: list[ReasoningItem] = []
        stack, response = await self._retry_with_backoff(
            lambda: self._open_stream_response(client, path, body),
            max_delay=_MAX_RETRY_WAIT_SECONDS,
        )
        async for event in self._stream_events(stack, response):
            if self._cancel_requested:
                break
            for delta in stream_adapter.parse_stream_event(event):
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

    async def _open_stream_response(
        self,
        client: httpx.AsyncClient,
        path: str,
        body: dict[str, Any],
    ) -> tuple[contextlib.AsyncExitStack, httpx.Response]:
        """Open the streaming request and check its status before any event is read.

        The streaming context is held on an :class:`~contextlib.AsyncExitStack`
        rather than a ``with`` block, so :meth:`_stream_events` can close the
        response even when the consumer stops iterating early -- which is what
        a mid-stream cancel does. A failed response's body is read while the
        stream is still open, so the error carries the endpoint's own
        explanation. Nothing has been yielded when this raises, which is what
        makes a rate-limited stream safe to retry.

        Args:
            client: The HTTP client to send through.
            path: Request path relative to the instance's base URL.
            body: The JSON body to send.

        Returns:
            tuple[contextlib.AsyncExitStack, httpx.Response]: The stack owning
            the open response, and the response itself.

        Raises:
            ProviderError: If the body cannot be encoded or the stream cannot
                be opened.
        """
        content = self._encode_body(body)
        stack = contextlib.AsyncExitStack()
        try:
            response = await stack.enter_async_context(client.stream("POST", path, content=content))
        except httpx.HTTPError as exc:
            await stack.aclose()
            self._logger.warning("configurable_stream_open_failed", error=str(exc))
            raise ProviderError(_ERR_STREAM_FAILED % (self.name, exc), provider_name=self.name) from exc
        if response.is_success:
            return stack, response
        await _read_error_body(response)
        await stack.aclose()
        try:
            _ = response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            self._raise_for_http_status(exc, _ERR_STREAM_FAILED)
        return stack, response

    async def _stream_events(
        self,
        stack: contextlib.AsyncExitStack,
        response: httpx.Response,
    ) -> AsyncIterator[dict[str, Any]]:
        """Yield an open stream's decoded events, closing it when done.

        Args:
            stack: The stack owning the open response.
            response: The open streaming response.

        Yields:
            dict[str, Any]: One decoded event per payload.

        Raises:
            ProviderError: If the stream fails mid-flight.
        """
        try:
            async for event in self._iter_events(response):
                yield event
        except (httpx.HTTPError, ValueError) as exc:
            self._logger.warning(
                "configurable_stream_failed",
                error=str(exc),
                cancel_requested=self._cancel_requested,
            )
            raise ProviderError(_ERR_STREAM_FAILED % (self.name, exc), provider_name=self.name) from exc
        finally:
            await stack.aclose()

    async def _iter_events(self, response: httpx.Response) -> AsyncIterator[dict[str, Any]]:
        """Decode a streaming response into events.

        Server-sent events are assembled per the SSE rules: every ``data:``
        line of an event is joined with a newline and the event is dispatched
        at the blank line that ends it, so a payload split across several
        ``data:`` lines still decodes. ``event:``, ``id:``, ``retry:`` and
        comment lines carry nothing the adapters read. A line that is not an
        SSE field at all is taken as one newline-delimited JSON payload, the
        framing some gateways stream in.

        Args:
            response: The open streaming response.

        Yields:
            dict[str, Any]: One decoded event per payload.
        """
        data_lines: list[str] = []
        async for raw_line in response.aiter_lines():
            line = raw_line.rstrip("\r\n")
            if not line:
                if data_lines:
                    decoded = self._decode_event_payload("\n".join(data_lines))
                    data_lines.clear()
                    if decoded is not None:
                        yield decoded
                continue
            if line.startswith(":"):
                continue
            field, separator, value = line.partition(":")
            if separator and field in _SSE_FIELDS:
                if field == SSE_DATA_FIELD:
                    data_lines.append(value.removeprefix(" "))
                continue
            decoded = self._decode_event_payload(line)
            if decoded is not None:
                yield decoded
        if data_lines:
            decoded = self._decode_event_payload("\n".join(data_lines))
            if decoded is not None:
                yield decoded

    def _decode_event_payload(self, payload_text: str) -> dict[str, Any] | None:
        """Decode one event payload, skipping the end-of-stream sentinel.

        Args:
            payload_text: The event's joined data.

        Returns:
            dict[str, Any] | None: The decoded payload, or ``None`` for the
            sentinel, an empty payload or one that does not decode.
        """
        stripped = payload_text.strip()
        if not stripped or stripped == SSE_DONE_SENTINEL:
            return None
        return self._safe_parse_stream_json(stripped, logger=self._logger)

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


def _next_model_page_cursor(page: dict[str, Any], dialect: ApiDialect) -> str | None:
    """Read the cursor for the next page of a paginated model listing.

    Args:
        page: One decoded listing page.
        dialect: The dialect whose paging fields to read.

    Returns:
        str | None: Anthropic's ``last_id`` while ``has_more`` is true, or
        Gemini's ``nextPageToken``; ``None`` on the last page.
    """
    if dialect is ApiDialect.MESSAGES:
        last_id = page.get("last_id")
        return last_id if page.get("has_more") is True and isinstance(last_id, str) and last_id else None
    token = page.get("nextPageToken")
    return token if isinstance(token, str) and token else None


def _retry_after_seconds(header: str | None, body: str) -> float | None:
    """Read how long a rate-limited response asks the client to wait.

    ``Retry-After`` is either a number of seconds or an HTTP-date. Gemini
    states the wait in its error body instead, as a ``google.rpc.RetryInfo``
    detail whose ``retryDelay`` is a protobuf duration such as ``"37s"``.

    Args:
        header: The ``Retry-After`` header value, if any.
        body: The response body text.

    Returns:
        float | None: The wait in seconds, never negative, or ``None`` when
        the response states none.
    """
    if header is not None and (value := header.strip()):
        try:
            seconds = float(value)
        except ValueError:
            seconds = None
        if seconds is not None:
            return max(seconds, 0.0) if math.isfinite(seconds) else None
        try:
            when = email.utils.parsedate_to_datetime(value)
        except (TypeError, ValueError):
            when = None
        if when is not None:
            moment = when if when.tzinfo is not None else when.replace(tzinfo=UTC)
            return max((moment - datetime.now(tz=UTC)).total_seconds(), 0.0)
    return _google_retry_delay(body)


def _google_retry_delay(body: str) -> float | None:
    """Read the ``RetryInfo.retryDelay`` of a Google API error body.

    Args:
        body: The response body text.

    Returns:
        float | None: The delay in seconds, or ``None`` when the body states
        none.
    """
    try:
        decoded: object = json.loads(body)
    except ValueError:
        return None
    if not is_json_object(decoded):
        return None
    error = decoded.get("error")
    if not is_json_object(error):
        return None
    details = error.get("details")
    if not is_json_array(details):
        return None
    for detail in details:
        if not is_json_object(detail):
            continue
        type_url = detail.get("@type")
        delay = detail.get("retryDelay")
        if isinstance(type_url, str) and type_url.endswith(_RETRY_INFO_TYPE_SUFFIX) and isinstance(delay, str):
            match = _DURATION_PATTERN.match(delay)
            if match is not None:
                return float(match.group(1))
    return None


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
    except (httpx.ResponseNotRead, httpx.StreamError, ValueError):
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
