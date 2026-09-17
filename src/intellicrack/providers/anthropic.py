# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Anthropic Claude API provider implementation.

This module provides integration with Anthropic's Claude models for chat completion and tool/function calling.
"""

from __future__ import annotations

import asyncio
import time
from contextlib import AsyncExitStack
from typing import TYPE_CHECKING, Any, cast, override

import anthropic
from anthropic.types import (
    Message as AnthropicMessage,
    RedactedThinkingBlock,
    TextBlock,
    ThinkingBlock,
    ToolUseBlock,
)

from intellicrack.core.error_logging import log_passthrough
from intellicrack.core.logging import get_logger, log_provider_request, log_provider_response
from intellicrack.core.types import (
    AuthenticationError,
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    RateLimitError,
    ReasoningItem,
    ThinkingConfig,
    ToolCall,
    ToolChoice,
    ToolDefinition,
)
from intellicrack.providers import ids as provider_ids
from intellicrack.providers.base import (
    LLMProviderBase,
    UsageInfo,
)
from intellicrack.providers.capabilities import ApiDialect
from intellicrack.providers.dialects.base import DialectRequest
from intellicrack.providers.dialects.messages import MessagesAdapter, parse_thinking_block
from intellicrack.providers.tool_names import from_wire_name


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from anthropic.lib.streaming import AsyncMessageStream

_MSG_API_KEY_REQUIRED = "API key required"
_MSG_NOT_CONNECTED = "Not connected"
_MSG_INVALID_API_KEY = "Invalid API key"
_MSG_CONNECTION_FAILED = "Connection failed"
_MSG_REQUEST_FAILED = "Request failed"
_MSG_RATE_LIMITED = "Rate limited"
_MSG_STREAM_FAILED = "Stream failed"
_MSG_NO_MODELS_AVAILABLE = "No models available from Anthropic API"
_MSG_FETCH_MODELS_FAILED = "Failed to fetch models from Anthropic API"

_HTTP_SERVER_ERROR_MIN = 500


class AnthropicProvider(LLMProviderBase):
    """Anthropic Claude API provider implementation.

    Provides integration with Anthropic's Claude models including support for tool/function calling and streaming responses.
    """

    def __init__(self) -> None:
        """Initialize the AnthropicProvider instance."""
        super().__init__()
        self._client: anthropic.AsyncAnthropic | None = None
        self._adapter = MessagesAdapter()
        self._current_task: asyncio.Task[Any] | None = None
        self._logger = get_logger(__name__).bind(provider="anthropic")
        self._logger.info("anthropic_provider_initialized")

    @property
    def name(self) -> str:
        """The provider instance id.

        Returns:
            str: The ``anthropic`` built-in provider id.
        """
        return provider_ids.ANTHROPIC

    @property
    @override
    def dialect(self) -> ApiDialect:
        """The wire format this provider speaks.

        Returns:
            ApiDialect: Always :data:`ApiDialect.MESSAGES`.
        """
        return ApiDialect.MESSAGES

    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect to Anthropic API.

        Args:
            credentials: Must contain api_key. ``api_base`` is forwarded to the
                SDK client, and ``timeout`` replaces the SDK's default request
                timeout when set.

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
                timeout=credentials.timeout if credentials.timeout is not None else anthropic.NOT_GIVEN,
            )
            await self._client.models.list(limit=1)
        except anthropic.AuthenticationError as e:
            self._logger.warning("anthropic_auth_failed", error=str(e))
            raise AuthenticationError(_MSG_INVALID_API_KEY) from e
        except (ConnectionError, TimeoutError, OSError, anthropic.APIError) as e:
            self._logger.warning("anthropic_connect_failed", error=str(e))
            raise ProviderError(_MSG_CONNECTION_FAILED) from e
        else:
            self._credentials = credentials
            self.connected = True
            self._logger.info(
                "anthropic_connected",
                has_custom_base=credentials.api_base is not None,
            )

    async def disconnect(self) -> None:
        """Disconnect from Anthropic API."""
        try:
            await super().disconnect()
            self._client = None
            self._current_task = None
            self._logger.info("anthropic_disconnected")
        except (ConnectionError, TimeoutError, OSError, RuntimeError) as exc:
            self._logger.warning("disconnect_cleanup_error", error=str(exc))
            self.connected = False

    async def list_models(self) -> list[ModelInfo]:
        """Dynamically fetch available Claude models from Anthropic API.

        Uses the /v1/models endpoint to retrieve the current list of
        available models, handling pagination as needed.

        Returns:
            list[ModelInfo]: List of available Claude models with their capabilities.

        Raises:
            ProviderError: If not connected or the request fails.
        """
        if not self.connected or self._client is None:
            raise ProviderError(_MSG_NOT_CONNECTED)

        try:
            models = await self._fetch_all_models()
        except (ConnectionError, TimeoutError, OSError, anthropic.APIError) as e:
            self._logger.warning(
                "anthropic_list_models_api_failed",
                error=str(e),
            )
            raise ProviderError(_MSG_FETCH_MODELS_FAILED) from e
        else:
            self._logger.info("anthropic_models_listed", count=len(models))
            return models

    async def _fetch_all_models(self, *, limit: int | None = None) -> list[ModelInfo]:
        """Paginate through the models endpoint and collect all results.

        Args:
            limit: Optional per-page size to forward to the Anthropic
                ``client.models.list`` call.  ``None`` (the default)
                lets the SDK pick its server-side default.  Passing an
                explicit value lets callers (e.g. ``connect``) match
                the request shape used during their probe.

        Returns:
            list[ModelInfo]: Complete list of ModelInfo objects from all pages.
        """
        client = self._client
        if client is None:
            return []

        models: list[ModelInfo] = []
        after_id: str | None = None
        page_count = 0

        while True:
            if limit is not None and after_id is not None:
                page = await client.models.list(limit=limit, after_id=after_id)
            elif limit is not None:
                page = await client.models.list(limit=limit)
            elif after_id is not None:
                page = await client.models.list(after_id=after_id)
            else:
                page = await client.models.list()
            models.extend(self._build_model_info(m.id, getattr(m, "display_name", m.id)) for m in page.data)
            page_count += 1
            if not page.has_more:
                break
            after_id = page.last_id

        self._logger.debug(
            "anthropic_models_fetched",
            page_count=page_count,
            model_count=len(models),
            limit=limit,
        )
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
            ModelInfo: Populated ModelInfo instance.
        """
        display_name: str = str(display_name_raw) if display_name_raw else model_id
        return ModelInfo(
            id=model_id,
            name=display_name,
            provider=provider_ids.ANTHROPIC,
            context_window=200000,
            supports_tools=True,
            supports_vision=True,
            supports_streaming=True,
            input_cost_per_1m_tokens=None,
            output_cost_per_1m_tokens=None,
        )

    def _build_api_kwargs(
        self,
        *,
        model: str,
        max_tokens: int,
        messages: list[Message],
        tools: list[ToolDefinition] | None,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        enable_cache: bool = False,
    ) -> dict[str, Any]:
        """Build keyword arguments for the Anthropic messages API.

        Delegates the whole body to
        :class:`~intellicrack.providers.dialects.messages.MessagesAdapter`,
        which is the single owner of the Messages wire format, so this
        provider and a user-defined Anthropic-compatible instance produce the
        same request for the same inputs.

        Sampling parameters (``temperature``/``top_p``/``top_k``) are
        intentionally absent: the anthropic 1.x SDK removed them from
        ``messages.create``/``messages.stream``, and current Claude models
        reject them at the API layer. Callers still accept a ``temperature``
        on the provider interface for cross-provider uniformity; it simply
        does not reach the Anthropic request.

        Args:
            model: Model ID to use.
            max_tokens: Maximum tokens in response.
            messages: Conversation history in Intellicrack's message model.
            tools: Optional tool definitions to advertise.
            tool_choice: Tool selection mode.
            thinking: Extended thinking configuration.
            enable_cache: Whether to enable prompt caching.

        Returns:
            dict[str, Any]: Keyword arguments dict for messages.create or messages.stream.
        """
        return self._adapter.build_request(
            DialectRequest(
                model=model,
                messages=messages,
                capabilities=self.capabilities_for(model),
                tools=tools or (),
                max_tokens=max_tokens,
                tool_choice=tool_choice,
                thinking=thinking,
                enable_cache=enable_cache,
            ),
        )

    @staticmethod
    def _apply_cache_breakpoints(
        kwargs: dict[str, Any],
        *,
        system_prompt: str | None,
    ) -> None:
        """Insert ``cache_control`` breakpoints across system, tools, and messages.

        Delegates to
        :meth:`~intellicrack.providers.dialects.messages.MessagesAdapter.apply_cache_breakpoints`,
        which owns the placement rule: Anthropic accepts at most four
        breakpoints per request and renders ``tools`` -> ``system`` ->
        ``messages`` as the cache prefix, so one goes on the last system
        block, one on the last tool entry and one on the final content block
        of the last turn.

        Args:
            kwargs: Mutable request kwargs dict for ``messages.create``
                or ``messages.stream``. Updated in place.
            system_prompt: System prompt text used to construct the
                request, or ``None`` when no system instruction is set.
                Required because the helper rewrites ``kwargs["system"]``
                from a plain string to the structured-block form when a
                breakpoint is added.
        """
        MessagesAdapter.apply_cache_breakpoints(kwargs, system_prompt=system_prompt)

    @staticmethod
    def _cache_last_message_block(messages: list[dict[str, Any]]) -> None:
        """Tag the last content block of the final user/assistant turn for caching.

        Args:
            messages: List of message dicts in Anthropic's wire format.
                Each entry has a ``role`` and a ``content`` value that
                is either a string or a list of content-block dicts.
        """
        MessagesAdapter.cache_last_message_block(cast("list[Any]", messages))

    @staticmethod
    def _build_usage_from_message(response: AnthropicMessage) -> UsageInfo | None:
        """Extract token-usage statistics from an Anthropic message.

        Args:
            response: The Anthropic API response message.

        Returns:
            UsageInfo | None: Populated UsageInfo when usage is present on
            the response, otherwise ``None``.
        """
        usage = getattr(response, "usage", None)
        if usage is None:
            return None
        input_tokens = int(getattr(usage, "input_tokens", 0) or 0)
        output_tokens = int(getattr(usage, "output_tokens", 0) or 0)
        cache_read_tokens = int(getattr(usage, "cache_read_input_tokens", 0) or 0)
        cache_creation_tokens = int(getattr(usage, "cache_creation_input_tokens", 0) or 0)
        return UsageInfo(
            prompt_tokens=input_tokens,
            completion_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            cache_read_tokens=cache_read_tokens,
            cache_creation_tokens=cache_creation_tokens,
        )

    def _parse_response_blocks(
        self,
        response: AnthropicMessage,
    ) -> tuple[str, list[ToolCall], list[ReasoningItem]]:
        """Extract text, tool calls, and reasoning from response content blocks.

        A thinking block is captured with its ``signature`` and a redacted
        block with its ``data``. Anthropic requires the signature back
        verbatim on the next turn that carries a tool result, so dropping it
        -- which is what happened before -- silently degraded extended
        thinking plus multi-turn tool calling.

        Args:
            response: The Anthropic API response message.

        Returns:
            tuple[str, list[ToolCall], list[ReasoningItem]]: Tuple of (text
            content, parsed tool calls, captured reasoning blocks).
        """
        content = ""
        tool_calls: list[ToolCall] = []
        reasoning: list[ReasoningItem] = []

        for block in response.content:
            if isinstance(block, TextBlock):
                content += block.text
            elif isinstance(block, (ThinkingBlock, RedactedThinkingBlock)):
                reasoning.append(parse_thinking_block(cast("dict[str, Any]", block.model_dump())))
            elif isinstance(block, ToolUseBlock):
                tool_call = self._parse_tool_call_common(
                    call_id=block.id,
                    function_name=block.name,
                    raw_arguments=block.input,
                )
                tool_calls.append(tool_call)
                self._logger.debug(
                    "tool_call_parsed",
                    tool_name=tool_call.tool_name,
                    arguments_count=len(tool_call.arguments),
                )

        return content, tool_calls, reasoning

    async def _make_anthropic_api_call(self, api_kwargs: dict[str, Any]) -> AnthropicMessage:
        """Execute the Anthropic messages API call with exception translation.

        Rate-limit errors and 5xx server errors are translated to
        :class:`intellicrack.core.types.RateLimitError` so the retry
        wrapper treats them as transient.  Other ``APIStatusError``
        instances propagate unchanged to the caller.

        Args:
            api_kwargs: Keyword arguments to pass to messages.create.

        Returns:
            AnthropicMessage: The Anthropic API response message.

        Raises:
            ProviderError: If the client is not initialized.
            RateLimitError: If the API returns a rate limit (429) or 5xx
                server error response.
            anthropic.APIStatusError: If the API returns a non-retryable
                4xx status code other than 401/429.
        """
        if self._client is None:
            self._logger.error("anthropic_api_call_not_connected")
            raise ProviderError(_MSG_NOT_CONNECTED)
        try:
            return cast("AnthropicMessage", await self._client.messages.create(**api_kwargs))
        except anthropic.RateLimitError as e:
            self._logger.warning("anthropic_rate_limited", error=str(e))
            raise RateLimitError(_MSG_RATE_LIMITED) from e
        except anthropic.APIStatusError as e:
            status_code = int(getattr(e, "status_code", 0) or 0)
            if status_code >= _HTTP_SERVER_ERROR_MIN:
                self._logger.warning(
                    "anthropic_server_error_retryable",
                    status_code=status_code,
                    error=str(e),
                )
                raise RateLimitError(_MSG_REQUEST_FAILED) from e
            log_passthrough(
                self._logger,
                "anthropic_api_status_error_passthrough",
                e,
                status_code=status_code,
            )
            raise

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
        """Send a chat completion request to Claude.

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

        Raises:
            ProviderError: If not connected or request fails.
            RateLimitError: If rate limited.
        """
        self._reject_empty_messages(messages)
        if not self.connected or self._client is None:
            raise ProviderError(_MSG_NOT_CONNECTED)

        self._cancel_requested = False
        self._pending_usage = None
        self._pending_thinking.clear()

        log_provider_request(
            provider="anthropic",
            model=model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
            temperature=temperature,
        )

        start_time = time.perf_counter()
        api_kwargs = self._build_api_kwargs(
            model=model,
            max_tokens=max_tokens,
            messages=messages,
            tools=tools,
            tool_choice=tool_choice,
            thinking=thinking,
            enable_cache=enable_cache,
        )

        api_task: asyncio.Task[AnthropicMessage] = asyncio.create_task(
            self._retry_with_backoff(lambda: self._make_anthropic_api_call(api_kwargs)),
        )
        self._current_task = cast("asyncio.Task[Any]", api_task)
        try:
            return await self._await_anthropic_chat(api_task=api_task, model=model, start_time=start_time)
        except RateLimitError as exc:
            log_passthrough(
                self._logger,
                "anthropic_chat_rate_limit_passthrough",
                exc,
                provider="anthropic",
                model=model,
            )
            raise
        except (ConnectionError, TimeoutError, OSError, anthropic.APIError, ValueError) as e:
            self._logger.warning("anthropic_request_failed", error=str(e))
            raise ProviderError(_MSG_REQUEST_FAILED) from e

    async def _await_anthropic_chat(
        self,
        *,
        api_task: asyncio.Task[AnthropicMessage],
        model: str,
        start_time: float,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Await the chat API task and build the response payload.

        Args:
            api_task: The active ``asyncio.Task`` wrapping the Anthropic
                ``messages.create`` call.
            model: Model ID associated with the request, used for logging.
            start_time: ``time.perf_counter()`` reference captured before
                the request was dispatched.

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of (assistant
            message, tool calls if any).
        """
        try:
            response = await api_task
        finally:
            self._current_task = None
        duration_ms = (time.perf_counter() - start_time) * 1000
        content, tool_calls, reasoning = self._parse_response_blocks(response)
        self._pending_usage = self._build_usage_from_message(response)
        if reasoning:
            self._pending_thinking.extend(item.text for item in reasoning if item.text)
            message = Message(
                role="assistant",
                content=content,
                tool_calls=tool_calls or None,
                reasoning=reasoning,
            )
            log_provider_response(
                provider="anthropic",
                model=model,
                tool_calls_count=len(tool_calls),
                duration_ms=duration_ms,
            )
            return message, tool_calls or None
        return self._build_chat_response(
            provider="anthropic",
            model=model,
            content=content,
            tool_calls=tool_calls,
            duration_ms=duration_ms,
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
        """Stream a chat completion response from Claude.

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

        Raises:
            ProviderError: If not connected or request fails.
            RateLimitError: If rate limited.
        """
        self._reject_empty_messages(messages)
        if not self.connected or self._client is None:
            raise ProviderError(_MSG_NOT_CONNECTED)

        self._cancel_requested = False
        self._pending_usage = None
        self._pending_thinking.clear()

        log_provider_request("anthropic", model, len(messages), len(tools or []), temperature=temperature)
        api_kwargs = self._build_api_kwargs(
            model=model,
            max_tokens=max_tokens,
            messages=messages,
            tools=tools,
            tool_choice=tool_choice,
            thinking=thinking,
            enable_cache=enable_cache,
        )

        try:
            async for text in self._iter_anthropic_stream(api_kwargs):
                yield text
        except anthropic.RateLimitError as e:
            self._logger.warning("anthropic_stream_rate_limited", error=str(e))
            raise RateLimitError(_MSG_RATE_LIMITED) from e
        except anthropic.APIStatusError as e:
            status_code = int(getattr(e, "status_code", 0) or 0)
            if status_code >= _HTTP_SERVER_ERROR_MIN:
                self._logger.warning(
                    "anthropic_stream_server_error",
                    status_code=status_code,
                    error=str(e),
                )
                raise RateLimitError(_MSG_STREAM_FAILED) from e
            self._logger.warning(
                "anthropic_stream_status_error",
                status_code=status_code,
                error=str(e),
                cancel_requested=self._cancel_requested,
            )
            raise ProviderError(_MSG_STREAM_FAILED) from e
        except (ConnectionError, TimeoutError, OSError, anthropic.APIError, ValueError) as e:
            self._logger.warning(
                "anthropic_stream_failed",
                error=str(e),
                cancel_requested=self._cancel_requested,
            )
            raise ProviderError(_MSG_STREAM_FAILED) from e

    async def _iter_anthropic_stream(self, api_kwargs: dict[str, Any]) -> AsyncIterator[str]:
        """Open the Anthropic stream, yield text deltas, and capture final state.

        After the visible text stream is consumed, the helper inspects
        the final message to populate ``self._pending_tool_calls``,
        ``self._pending_thinking``, and ``self._pending_usage``.

        Args:
            api_kwargs: Keyword arguments forwarded to
                ``self._client.messages.stream``.

        Yields:
            str: Text chunks as they arrive from the API.

        Raises:
            ProviderError: If the Anthropic client has not been
                initialised.
        """
        if self._client is None:
            self._logger.error(
                "anthropic_stream_client_not_initialised",
                provider="anthropic",
                model=api_kwargs.get("model"),
            )
            raise ProviderError(_MSG_NOT_CONNECTED)
        stack = AsyncExitStack()
        stream = await stack.enter_async_context(self._client.messages.stream(**api_kwargs))
        try:
            async for text in stream.text_stream:
                if self._cancel_requested:
                    break
                yield text

            if not self._cancel_requested:
                await self._finalize_anthropic_stream(stream)
        finally:
            await stack.aclose()

    async def _finalize_anthropic_stream(self, stream: AsyncMessageStream) -> None:
        """Capture tool calls, thinking, and usage from the final message.

        Args:
            stream: The active Anthropic stream context whose
                ``get_final_message`` coroutine will be awaited.
        """
        final_message = await stream.get_final_message()
        tool_calls: list[ToolCall] = []
        reasoning: list[ReasoningItem] = []
        for block in final_message.content:
            if block.type == "tool_use":
                args: dict[str, object] = dict(block.input)
                canonical_name = from_wire_name(block.name)
                tool_calls.append(
                    ToolCall(
                        id=block.id,
                        tool_name=canonical_name.split(".")[0] if "." in canonical_name else canonical_name,
                        function_name=canonical_name,
                        arguments=args,
                    ),
                )
            elif block.type in {"thinking", "redacted_thinking"}:
                item = parse_thinking_block(cast("dict[str, Any]", block.model_dump()))
                reasoning.append(item)
                self._logger.debug(
                    "stream_thinking_captured",
                    length=len(item.text),
                    signed=item.signature is not None,
                )
        self._pending_tool_calls = tool_calls
        self._pending_reasoning = reasoning
        if reasoning:
            self._pending_thinking.extend(item.text for item in reasoning if item.text)
        self._pending_usage = self._build_usage_from_message(final_message)

    async def cancel_request(self) -> None:
        """Cancel any in-flight request."""
        self._cancel_requested = True
        had_task = False
        if self._current_task is not None and not self._current_task.done():
            self._current_task.cancel()
            had_task = True
        self._logger.info("anthropic_request_cancelled", had_active_task=had_task)

    @override
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Convert internal messages to Anthropic format.

        Args:
            messages: List of Message objects.

        Returns:
            list[dict[str, object]]: List of messages in Anthropic's format.
        """
        result = cast(
            "list[dict[str, object]]",
            self._adapter.build_messages(messages, self.capabilities_for("")),
        )
        self._logger.debug("messages_converted", input_count=len(messages), output_count=len(result))
        return result

    def _convert_single_message(self, msg: Message) -> dict[str, object] | None:
        """Route a single message to its role-specific formatter.

        Args:
            msg: The message to convert.

        Returns:
            dict[str, object] | None: Formatted message dict, or None if the role should be skipped.
        """
        converted = self._convert_messages_to_provider_format([msg])
        return converted[0] if converted else None

    def _format_user_message(self, msg: Message) -> dict[str, object]:
        """Format a user message for the Anthropic API.

        Args:
            msg: The user message.

        Returns:
            dict[str, object]: Anthropic-formatted user message dict.
        """
        return self._convert_single_message(msg) or {"role": "user", "content": msg.content}

    def _format_assistant_message(self, msg: Message) -> dict[str, object]:
        """Format an assistant message for the Anthropic API.

        Args:
            msg: The assistant message.

        Returns:
            dict[str, object]: Anthropic-formatted assistant message dict.
        """
        return self._convert_single_message(msg) or {"role": "assistant", "content": msg.content}

    def _format_tool_message(self, msg: Message) -> dict[str, object] | None:
        """Format a tool result message for the Anthropic API.

        Args:
            msg: The tool result message.

        Returns:
            dict[str, object] | None: Anthropic-formatted tool result dict, or None if no results.
        """
        return self._convert_single_message(msg)

    @override
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Convert internal tools to Anthropic format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            list[dict[str, object]]: List of tools in Anthropic's format.
        """
        return cast(
            "list[dict[str, object]]",
            self._adapter.build_tool_schemas(tools, self.capabilities_for("")),
        )


__all__ = ["AnthropicProvider"]
