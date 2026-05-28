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
from typing import TYPE_CHECKING, Any, cast, override

import anthropic
from anthropic.types import (
    Message as AnthropicMessage,
    MessageParam,
    TextBlock,
    ThinkingBlock,
    ToolParam,
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
    ProviderName,
    RateLimitError,
    ThinkingConfig,
    ToolCall,
    ToolChoice,
    ToolChoiceMode,
    ToolDefinition,
)
from intellicrack.providers.base import (
    LLMProviderBase,
    UsageInfo,
    create_anthropic_tool_schema,
    serialize_tool_result,
)


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
        self._current_task: asyncio.Task[Any] | None = None
        self._logger = get_logger(__name__).bind(provider="anthropic")
        self._logger.info("anthropic_provider_initialized")

    @property
    def name(self) -> ProviderName:
        """Get the provider's name.

        Returns:
            ProviderName: ProviderName.ANTHROPIC
        """
        return ProviderName.ANTHROPIC

    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect to Anthropic API.

        Args:
            credentials: Must contain api_key.

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
            provider=ProviderName.ANTHROPIC,
            context_window=200000,
            supports_tools=True,
            supports_vision=True,
            supports_streaming=True,
            input_cost_per_1m_tokens=None,
            output_cost_per_1m_tokens=None,
        )

    @staticmethod
    def _build_api_kwargs(
        *,
        model: str,
        max_tokens: int,
        temperature: float,
        messages: list[MessageParam],
        system_prompt: str | None,
        tools: list[dict[str, object]] | None,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        enable_cache: bool = False,
    ) -> dict[str, Any]:
        """Build keyword arguments for the Anthropic messages API.

        Args:
            model: Model ID to use.
            max_tokens: Maximum tokens in response.
            temperature: Sampling temperature.
            messages: Formatted message list.
            system_prompt: Optional system prompt text.
            tools: Optional formatted tools list.
            tool_choice: Tool selection mode.
            thinking: Extended thinking configuration.
            enable_cache: Whether to enable prompt caching.

        Returns:
            dict[str, Any]: Keyword arguments dict for messages.create or messages.stream.
        """
        kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": messages,
        }
        if system_prompt is not None:
            kwargs["system"] = system_prompt
        if tools:
            provider_tools: list[ToolParam] = cast("list[ToolParam]", tools)
            kwargs["tools"] = provider_tools

        if tool_choice is not None and tools:
            if tool_choice.mode == ToolChoiceMode.AUTO:
                kwargs["tool_choice"] = {"type": "auto"}
            elif tool_choice.mode == ToolChoiceMode.REQUIRED:
                kwargs["tool_choice"] = {"type": "any"}
            elif tool_choice.mode == ToolChoiceMode.NONE:
                kwargs.pop("tools", None)
            elif tool_choice.mode == ToolChoiceMode.SPECIFIC and tool_choice.function_name:
                kwargs["tool_choice"] = {"type": "tool", "name": tool_choice.function_name}

        if thinking is not None and thinking.enabled:
            kwargs["thinking"] = {"type": "enabled", "budget_tokens": thinking.budget_tokens}
            kwargs["temperature"] = 1.0
            kwargs["max_tokens"] = max(kwargs["max_tokens"], thinking.budget_tokens + 1024)

        if enable_cache:
            AnthropicProvider._apply_cache_breakpoints(kwargs, system_prompt=system_prompt)
        return kwargs

    @staticmethod
    def _apply_cache_breakpoints(
        kwargs: dict[str, Any],
        *,
        system_prompt: str | None,
    ) -> None:
        """Insert ``cache_control`` breakpoints across system, tools, and messages.

        Anthropic accepts at most four ``cache_control`` breakpoints
        per request and renders ``tools`` -> ``system`` -> ``messages``
        as the cache prefix.  This helper places ephemeral breakpoints
        on (1) the last/only system block, (2) the last tool entry,
        and (3) the final content block of the last message turn so
        callers get the full cross-prefix benefit promised by
        ``enable_cache``.

        Args:
            kwargs: Mutable request kwargs dict for ``messages.create``
                or ``messages.stream``.  Updated in place.
            system_prompt: System prompt text used to construct the
                request, or ``None`` when no system instruction is set.
                Required because the helper rewrites ``kwargs["system"]``
                from a plain string to the structured-block form when a
                breakpoint is added.
        """
        if system_prompt is not None:
            kwargs["system"] = [
                {
                    "type": "text",
                    "text": system_prompt,
                    "cache_control": {"type": "ephemeral"},
                },
            ]

        tools_obj = kwargs.get("tools")
        if isinstance(tools_obj, list) and tools_obj:
            tools_list = cast("list[dict[str, Any]]", tools_obj)
            cached_tools: list[dict[str, Any]] = [dict(tool) for tool in tools_list]
            cached_tools[-1] = {
                **cached_tools[-1],
                "cache_control": {"type": "ephemeral"},
            }
            kwargs["tools"] = cast("list[ToolParam]", cached_tools)

        messages_obj = kwargs.get("messages")
        if isinstance(messages_obj, list) and messages_obj:
            messages_list = cast("list[dict[str, Any]]", messages_obj)
            AnthropicProvider._cache_last_message_block(messages_list)
            kwargs["messages"] = cast("list[MessageParam]", messages_list)

    @staticmethod
    def _cache_last_message_block(messages: list[dict[str, Any]]) -> None:
        """Tag the last content block of the final user/assistant turn for caching.

        Walks ``messages`` from the end and converts the most recent
        message's content into the structured block form (a list of
        block dicts) when needed, then attaches
        ``cache_control: {"type": "ephemeral"}`` to the final block.
        Mutates ``messages`` in place.

        Args:
            messages: List of message dicts in Anthropic's wire format.
                Each entry has a ``role`` and a ``content`` value that
                is either a string or a list of content-block dicts.
        """
        last_msg = messages[-1]
        content = last_msg.get("content")
        if isinstance(content, str):
            content_blocks: list[dict[str, Any]] = [
                {
                    "type": "text",
                    "text": content,
                    "cache_control": {"type": "ephemeral"},
                },
            ]
            last_msg["content"] = content_blocks
            return
        if isinstance(content, list) and content:
            blocks_list = cast("list[dict[str, Any]]", content)
            blocks_list[-1] = {
                **blocks_list[-1],
                "cache_control": {"type": "ephemeral"},
            }

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
        return UsageInfo(
            prompt_tokens=input_tokens,
            completion_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
        )

    def _parse_response_blocks(
        self,
        response: AnthropicMessage,
    ) -> tuple[str, list[ToolCall], str]:
        """Extract text, tool calls, and thinking from response content blocks.

        Args:
            response: The Anthropic API response message.

        Returns:
            tuple[str, list[ToolCall], str]: Tuple of (text content, parsed tool calls, thinking text).
        """
        content = ""
        tool_calls: list[ToolCall] = []
        thinking_text = ""

        for block in response.content:
            if isinstance(block, TextBlock):
                content += block.text
            elif isinstance(block, ThinkingBlock):
                thinking_text += block.thinking
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

        return content, tool_calls, thinking_text

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
        if not self.connected or self._client is None:
            raise ProviderError(_MSG_NOT_CONNECTED)

        self._cancel_requested = False
        self._pending_usage = None
        self._pending_thinking.clear()

        system_prompt = self._extract_system_messages(messages)
        anthropic_messages = self.convert_messages_to_provider_format(messages)
        typed_messages = cast("list[MessageParam]", anthropic_messages)
        anthropic_tools: list[dict[str, object]] | None = None
        if tools:
            anthropic_tools = self.convert_tools_to_provider_format(tools)

        log_provider_request(
            provider="anthropic",
            model=model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
        )

        start_time = time.perf_counter()
        api_kwargs = self._build_api_kwargs(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=typed_messages,
            system_prompt=system_prompt,
            tools=anthropic_tools,
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
        content, tool_calls, thinking_text = self._parse_response_blocks(response)
        self._pending_usage = self._build_usage_from_message(response)
        if thinking_text:
            self._pending_thinking.append(thinking_text)
            message = Message(
                role="assistant",
                content=content,
                tool_calls=tool_calls or None,
                thinking_content=thinking_text,
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
        if not self.connected or self._client is None:
            raise ProviderError(_MSG_NOT_CONNECTED)

        self._cancel_requested = False
        self._pending_usage = None
        self._pending_thinking.clear()

        log_provider_request("anthropic", model, len(messages), len(tools or []))
        system_prompt = self._extract_system_messages(messages)
        anthropic_messages = self.convert_messages_to_provider_format(messages)
        typed_messages = cast("list[MessageParam]", anthropic_messages)
        anthropic_tools: list[dict[str, object]] | None = None
        if tools:
            anthropic_tools = self.convert_tools_to_provider_format(tools)

        api_kwargs = self._build_api_kwargs(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=typed_messages,
            system_prompt=system_prompt,
            tools=anthropic_tools,
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
        stream_context = self._client.messages.stream(**api_kwargs)
        async with stream_context as stream:
            async for text in stream.text_stream:
                if self._cancel_requested:
                    break
                yield text

            if not self._cancel_requested:
                await self._finalize_anthropic_stream(stream)

    async def _finalize_anthropic_stream(self, stream: AsyncMessageStream) -> None:
        """Capture tool calls, thinking, and usage from the final message.

        Args:
            stream: The active Anthropic stream context whose
                ``get_final_message`` coroutine will be awaited.
        """
        final_message = await stream.get_final_message()
        tool_calls: list[ToolCall] = []
        thinking_blocks: list[str] = []
        for block in final_message.content:
            if block.type == "tool_use":
                args: dict[str, object] = dict(block.input)
                tool_calls.append(
                    ToolCall(
                        id=block.id,
                        tool_name=block.name.split(".")[0] if "." in block.name else block.name,
                        function_name=block.name,
                        arguments=args,
                    ),
                )
            elif block.type == "thinking" and hasattr(block, "thinking"):
                thinking_text = block.thinking
                thinking_blocks.append(thinking_text)
                self._logger.debug(
                    "stream_thinking_captured",
                    length=len(thinking_text),
                )
        self._pending_tool_calls = tool_calls
        if thinking_blocks:
            self._pending_thinking.extend(thinking_blocks)
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
        result: list[dict[str, object]] = []
        for msg in messages:
            converted = self._convert_single_message(msg)
            if converted is not None:
                result.append(converted)
        self._logger.debug("messages_converted", input_count=len(messages), output_count=len(result))
        return result

    def _convert_single_message(self, msg: Message) -> dict[str, object] | None:
        """Route a single message to its role-specific formatter.

        Args:
            msg: The message to convert.

        Returns:
            dict[str, object] | None: Formatted message dict, or None if the role should be skipped.
        """
        if msg.role == "system":
            return None
        if msg.role == "user":
            return self._format_user_message(msg)
        if msg.role == "assistant":
            return self._format_assistant_message(msg)
        return self._format_tool_message(msg)

    @staticmethod
    def _format_user_message(msg: Message) -> dict[str, object]:
        """Format a user message for the Anthropic API.

        Args:
            msg: The user message.

        Returns:
            dict[str, object]: Anthropic-formatted user message dict.
        """
        return {"role": "user", "content": msg.content}

    @staticmethod
    def _format_assistant_message(msg: Message) -> dict[str, object]:
        """Format an assistant message for the Anthropic API.

        Args:
            msg: The assistant message.

        Returns:
            dict[str, object]: Anthropic-formatted assistant message dict.
        """
        content: list[dict[str, object]] = []
        if msg.content:
            content.append({"type": "text", "text": msg.content})
        if msg.tool_calls:
            content.extend(
                {
                    "type": "tool_use",
                    "id": tc.id,
                    "name": tc.function_name,
                    "input": tc.arguments,
                }
                for tc in msg.tool_calls
            )
        return {"role": "assistant", "content": content or msg.content}

    @staticmethod
    def _format_tool_message(msg: Message) -> dict[str, object] | None:
        """Format a tool result message for the Anthropic API.

        Args:
            msg: The tool result message.

        Returns:
            dict[str, object] | None: Anthropic-formatted tool result dict, or None if no results.
        """
        if not msg.tool_results:
            return None
        tool_results: list[dict[str, object]] = [
            {
                "type": "tool_result",
                "tool_use_id": tr.call_id,
                "content": serialize_tool_result(tr.result),
                "is_error": not tr.success,
            }
            for tr in msg.tool_results
        ]
        return {"role": "user", "content": tool_results}

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
        anthropic_tools: list[dict[str, object]] = []
        for tool in tools:
            tool_schemas = create_anthropic_tool_schema(tool)
            anthropic_tools.extend(cast("dict[str, object]", schema) for schema in tool_schemas)
        return anthropic_tools
