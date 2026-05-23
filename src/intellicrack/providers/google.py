# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Google Gemini API provider implementation.

This module provides integration with Google's Gemini models for chat completion and tool/function calling using the modern google-genai
SDK.
"""

from __future__ import annotations

import asyncio
import os
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final, cast, override

from google import genai
from google.genai import types
from google.genai.errors import APIError

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
from intellicrack.providers.base import LLMProviderBase, UsageInfo, create_google_tool_schema


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from google.genai.types import GenerateContentResponse


_MSG_API_KEY_REQUIRED = "API key required"
_MSG_NOT_CONNECTED = "Not connected"
_MSG_INVALID_API_KEY = "Invalid API key"
_MSG_CONNECTION_FAILED = "Connection failed"
_MSG_REQUEST_FAILED = "Request failed"
_MSG_FETCH_MODELS_FAILED = "Failed to fetch models from Google API"
_MSG_RATE_LIMITED = "Rate limited"
_MSG_STREAM_FAILED = "Stream failed"
_MSG_CONTENT_BLOCKED = "Response blocked by safety filters"
_MSG_PROHIBITED_CONTENT = "Response blocked for prohibited content"

_AUTH_STATUS_CODES: Final = frozenset({401, 403})
_RATE_LIMIT_STATUS_CODES: Final = frozenset({429})
_HTTP_SERVER_ERROR_MIN: Final[int] = 500

_BLOCKING_FINISH_REASONS: Final = frozenset({
    "SAFETY",
    "PROHIBITED_CONTENT",
    "BLOCKLIST",
    "SPII",
    "IMAGE_SAFETY",
    "IMAGE_PROHIBITED_CONTENT",
})

_logger = get_logger(__name__)


class GoogleProvider(LLMProviderBase):
    """Google Gemini API provider implementation.

    Provides integration with Google's Gemini models including support for tool/function calling and streaming responses.
    """

    def __init__(self) -> None:
        """Initialize the GoogleProvider instance."""
        super().__init__()
        self.client: genai.Client | None = None
        self._current_task: asyncio.Task[object] | None = None
        self._logger = get_logger(__name__).bind(provider="google")
        self._logger.info("google_provider_initialized")

    @property
    def name(self) -> ProviderName:
        """Get the provider's name.

        Returns:
            ProviderName: The provider name enum value.
        """
        return ProviderName.GOOGLE

    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect to Google AI API.

        Args:
            credentials: Provider credentials containing the API key.

        Raises:
            AuthenticationError: If the API key is invalid or missing.
            ProviderError: If connection to the API fails.
            RateLimitError: If the API rate limit is exceeded during the probe.
        """
        if not credentials.api_key:
            raise AuthenticationError(_MSG_API_KEY_REQUIRED)

        saved_gemini_key = os.environ.pop("GEMINI_API_KEY", None)
        try:
            self.client = genai.Client(api_key=credentials.api_key)

            models_iter = await asyncio.to_thread(self.client.models.list)
            _ = next(iter(models_iter), None)

            self._credentials = credentials
            self.connected = True
            self._logger.info(
                "google_connected",
                has_custom_base=credentials.api_base is not None,
            )

        except APIError as e:
            self.connected = False
            self.client = None
            self._logger.warning(
                "google_connect_failed",
                error=str(e),
                code=e.code,
            )
            if e.code in _AUTH_STATUS_CODES:
                raise AuthenticationError(_MSG_INVALID_API_KEY) from e
            if e.code in _RATE_LIMIT_STATUS_CODES:
                raise RateLimitError(_MSG_RATE_LIMITED) from e
            raise ProviderError(_MSG_CONNECTION_FAILED) from e
        except (ConnectionError, TimeoutError, OSError, ValueError, RuntimeError) as e:
            self.connected = False
            self.client = None
            self._logger.warning(
                "google_connect_failed",
                error=str(e),
            )
            raise ProviderError(_MSG_CONNECTION_FAILED) from e
        finally:
            if saved_gemini_key is not None:
                os.environ["GEMINI_API_KEY"] = saved_gemini_key

    async def disconnect(self) -> None:
        """Disconnect from Google AI API.

        Cleans up the client instance and resets connection state.
        """
        try:
            await super().disconnect()
            self.client = None
            self._current_task = None
            self._pending_usage = None
            self._logger.info("google_disconnected")
        except (ConnectionError, TimeoutError, OSError, RuntimeError) as exc:
            self._logger.warning("disconnect_cleanup_error", error=str(exc))
            self.connected = False

    async def list_models(self) -> list[ModelInfo]:
        """Dynamically fetch available Gemini models from Google AI API.

        Uses the models.list() endpoint to retrieve the current list of
        available generative models.

        Returns:
            list[ModelInfo]: List of ModelInfo objects describing available models.

        Raises:
            AuthenticationError: If credentials are rejected by the API.
            RateLimitError: If the API rate limit is exceeded.
            ProviderError: If not connected or the request fails.
        """
        if not self.connected or self.client is None:
            raise ProviderError(_MSG_NOT_CONNECTED)

        try:
            models_response = await asyncio.to_thread(self.client.models.list)

            models: list[ModelInfo] = []
            for model_data in models_response:
                model_name = getattr(model_data, "name", "")
                name_lower = model_name.lower()
                if "gemini" not in name_lower or "embedding" in name_lower:
                    continue

                display_name = getattr(model_data, "display_name", model_name)
                input_limit: int = getattr(model_data, "input_token_limit", 1048576)

                model_id = model_name
                model_id = model_id.removeprefix("models/")

                gen_methods: list[str] = getattr(
                    model_data,
                    "supported_generation_methods",
                    [],
                )
                supports_tools = "generateContent" in gen_methods
                supports_streaming = "streamGenerateContent" in gen_methods
                supports_vision = supports_tools

                models.append(
                    ModelInfo(
                        id=model_id,
                        name=display_name or model_id,
                        provider=ProviderName.GOOGLE,
                        context_window=input_limit,
                        supports_vision=supports_vision,
                        supports_vision=supports_vision,
                        supports_streaming=supports_streaming,
                        input_cost_per_1m_tokens=None,
                        output_cost_per_1m_tokens=None,
                    )
                )
            sorted_models = sorted(models, key=lambda m: m.id, reverse=True)
            self._logger.info(
                "google_models_listed",
                count=len(sorted_models),
            )
        except APIError as e:
            self._logger.warning(
                "google_list_models_api_failed",
                error=str(e),
                code=e.code,
            )
            if e.code in _AUTH_STATUS_CODES:
                raise AuthenticationError(_MSG_INVALID_API_KEY) from e
            if e.code in _RATE_LIMIT_STATUS_CODES:
                raise RateLimitError(_MSG_RATE_LIMITED) from e
            raise ProviderError(_MSG_FETCH_MODELS_FAILED) from e
        except (ConnectionError, TimeoutError, OSError, ValueError) as e:
            self._logger.warning(
                "google_list_models_api_failed",
                error=str(e),
            )
            raise ProviderError(_MSG_FETCH_MODELS_FAILED) from e
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
        """Send a chat completion request to Gemini.

        Args:
            messages: List of conversation messages.
            model: The model identifier to use.
            tools: Optional list of tool definitions for function calling.
            temperature: Sampling temperature between 0.0 and 1.0.
            max_tokens: Maximum number of tokens in the response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration (ignored by Google).
            enable_cache: Whether to enable prompt caching.

        Returns:
            tuple[Message, list[ToolCall] | None]: A tuple containing the assistant message and optional tool calls.

        Raises:
            AuthenticationError: If credentials are rejected by the API.
            ProviderError: If not connected, the request fails, or the response is blocked.
            RateLimitError: If the API rate limit is exceeded.
        """
        if not self.connected or self.client is None:
            raise ProviderError(_MSG_NOT_CONNECTED)

        self._cancel_requested = False
        self._pending_usage = None
        self._logger.debug(
            "google_chat_started",
            model=model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        if enable_cache:
            self._logger.debug("google_cache_implicit", model=model)

        system_instruction = self._extract_system_messages(messages)
        gemini_contents = self.convert_messages_to_provider_format(messages)
        gemini_tools = self._build_tool_declarations(tools) if tools else None

        log_provider_request(
            provider="google",
            model=model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
        )

        start_time = time.perf_counter()

        try:
            config = self._create_config(
                temperature,
                max_tokens,
                gemini_tools,
                system_instruction,
                tool_choice=tool_choice,
                thinking=thinking,
            )

            client = self.client
            typed_contents = cast("types.ContentListUnionDict", gemini_contents)

            generate_task: asyncio.Task[GenerateContentResponse] = asyncio.create_task(
                self._retry_with_backoff(
                    lambda: self._call_generate_content(
                        client=client,
                        model=model,
                        contents=typed_contents,
                        config=config,
                    ),
                ),
            )
            self._current_task = cast("asyncio.Task[object]", generate_task)
            try:
                response = await generate_task
            finally:
                self._current_task = None

            duration_ms = (time.perf_counter() - start_time) * 1000

            self._check_safety_block(response)

            content, tool_calls = self._parse_response(response)
            self._pending_usage = self._extract_usage(response)
            if thinking_text := self._extract_thinking_text(response):
                self._pending_thinking.append(thinking_text)

            for tc in tool_calls:
                self._logger.debug(
                    "tool_call_parsed",
                    tool_name=tc.tool_name,
                    arguments_count=len(tc.arguments),
                )

            message = Message(
                role="assistant",
                content=content,
                tool_calls=tool_calls or None,
                timestamp=datetime.now(tz=UTC),
            )

            log_provider_response(
                provider="google",
                model=model,
                tool_calls_count=len(tool_calls),
                duration_ms=duration_ms,
            )

            self._logger.info(
                "google_chat_completed",
                model=model,
                duration_ms=duration_ms,
                tool_calls_count=len(tool_calls),
                content_length=len(content),
            )

        except (AuthenticationError, ProviderError, RateLimitError) as exc:
            log_passthrough(
                self._logger,
                "google_chat_passthrough",
                exc,
                provider="google",
                model=model,
            )
            raise
        except APIError as e:
            self._logger.warning(
                "google_chat_failed",
                model=model,
                error=str(e),
                code=e.code,
            )
            if e.code in _AUTH_STATUS_CODES:
                raise AuthenticationError(_MSG_INVALID_API_KEY) from e
            if e.code in _RATE_LIMIT_STATUS_CODES:
                raise RateLimitError(_MSG_RATE_LIMITED) from e
            raise ProviderError(_MSG_REQUEST_FAILED) from e
        except (ConnectionError, TimeoutError, OSError, ValueError) as e:
            self._logger.warning(
                "google_chat_failed",
                model=model,
                error=str(e),
            )
            raise ProviderError(_MSG_REQUEST_FAILED) from e
        else:
            return message, tool_calls or None

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
        """Stream a chat completion response from Gemini.

        Args:
            messages: List of conversation messages.
            model: The model identifier to use.
            tools: Optional list of tool definitions for function calling.
            temperature: Sampling temperature between 0.0 and 1.0.
            max_tokens: Maximum number of tokens in the response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration (ignored by Google).
            enable_cache: Whether to enable prompt caching.

        Yields:
            str: Text chunks as they arrive from the API.

        Raises:
            AuthenticationError: If credentials are rejected by the API.
            ProviderError: If not connected, the stream fails, or the response is blocked.
            RateLimitError: If the API rate limit is exceeded.
        """
        if not self.connected or self.client is None:
            raise ProviderError(_MSG_NOT_CONNECTED)

        self._cancel_requested = False
        self._pending_usage = None
        self._pending_thinking.clear()
        if enable_cache:
            self._logger.debug("google_stream_cache_implicit", model=model)
        self._logger.debug(
            "google_chat_stream_started",
            model=model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        system_instruction = self._extract_system_messages(messages)
        gemini_contents = self.convert_messages_to_provider_format(messages)
        gemini_tools = self._build_tool_declarations(tools) if tools else None
        chunk_count = 0

        try:
            config = self._create_config(
                temperature,
                max_tokens,
                gemini_tools,
                system_instruction,
                tool_choice=tool_choice,
                thinking=thinking,
            )

            client = self.client
            typed_contents = cast("types.ContentListUnionDict", gemini_contents)

            stream_init_task: asyncio.Task[AsyncIterator[GenerateContentResponse]] = asyncio.create_task(
                client.aio.models.generate_content_stream(
                    model=model,
                    contents=typed_contents,
                    config=config,
                ),
            )
            self._current_task = cast("asyncio.Task[object]", stream_init_task)
            try:
                response_stream: AsyncIterator[GenerateContentResponse] = await stream_init_task
            finally:
                self._current_task = None

            last_chunk: GenerateContentResponse | None = None
            thinking_parts: list[str] = []
            async for chunk in response_stream:
                if self._cancel_requested:
                    self._logger.info(
                        "google_chat_stream_cancelled",
                        model=model,
                        chunks_received=chunk_count,
                    )
                    break
                last_chunk = chunk
                self._check_safety_block(chunk)
                if chunk_thinking := self._extract_thinking_text(chunk):
                    thinking_parts.append(chunk_thinking)
                if visible_text := self._extract_visible_chunk_text(chunk):
                    chunk_count += 1
                    yield visible_text

            if not self._cancel_requested and last_chunk is not None:
                self._pending_usage = self._extract_usage(last_chunk)
                if thinking_parts:
                    self._pending_thinking.extend(thinking_parts)
                self._pending_tool_calls = self._extract_function_calls(last_chunk)
                self._logger.info(
                    "google_chat_stream_completed",
                    model=model,
                    chunks_received=chunk_count,
                )

        except (AuthenticationError, ProviderError, RateLimitError) as exc:
            log_passthrough(
                self._logger,
                "google_chat_stream_passthrough",
                exc,
                provider="google",
                model=model,
                chunks_received=chunk_count,
            )
            raise
        except APIError as e:
            self._logger.warning(
                "google_chat_stream_failed",
                model=model,
                error=str(e),
                code=e.code,
                chunks_received=chunk_count,
                cancel_requested=self._cancel_requested,
            )
            if e.code in _AUTH_STATUS_CODES:
                raise AuthenticationError(_MSG_INVALID_API_KEY) from e
            if e.code in _RATE_LIMIT_STATUS_CODES:
                raise RateLimitError(_MSG_RATE_LIMITED) from e
            raise ProviderError(_MSG_STREAM_FAILED) from e
        except (ConnectionError, TimeoutError, OSError, ValueError) as e:
            self._logger.warning(
                "google_chat_stream_failed",
                model=model,
                error=str(e),
                chunks_received=chunk_count,
                cancel_requested=self._cancel_requested,
            )
            raise ProviderError(_MSG_STREAM_FAILED) from e

    async def cancel_request(self) -> None:
        """Cancel any in-flight request.

        Sets the cancellation flag and cancels the current async task if present.
        """
        had_active_task = self._current_task is not None and not self._current_task.done()
        self._cancel_requested = True
        if had_active_task and self._current_task is not None:
            self._current_task.cancel()
        self._logger.info(
            "google_request_cancelled",
            had_active_task=had_active_task,
        )

    @staticmethod
    def _extract_usage(
        response: GenerateContentResponse,
    ) -> UsageInfo | None:
        """Extract usage information from a Gemini response or stream chunk.

        Args:
            response: A Gemini response object that may carry
                ``usage_metadata`` with token counts.

        Returns:
            UsageInfo | None: Parsed usage information, or None when the
            response does not carry usable metadata.
        """
        metadata = getattr(response, "usage_metadata", None)
        if metadata is None:
            return None

        prompt_tokens = getattr(metadata, "prompt_token_count", None) or 0
        completion_tokens = getattr(metadata, "candidates_token_count", None) or 0
        total_tokens = getattr(metadata, "total_token_count", None)
        if total_tokens is None:
            total_tokens = prompt_tokens + completion_tokens

        if prompt_tokens == 0 and completion_tokens == 0 and total_tokens == 0:
            return None

        return UsageInfo(
            prompt_tokens=int(prompt_tokens),
            completion_tokens=int(completion_tokens),
            total_tokens=int(total_tokens),
        )

    @staticmethod
    def _check_safety_block(
        response: GenerateContentResponse,
    ) -> None:
        """Inspect a response or stream chunk for safety or policy blocks.

        Raises ``ProviderError`` when the response indicates that generation
        was halted for safety, prohibited content, blocklist, SPII, or image
        safety reasons.

        Args:
            response: A Gemini response object.

        Raises:
            ProviderError: If the response was blocked by Google's safety or
                policy filters.
        """
        prompt_feedback = getattr(response, "prompt_feedback", None)
        if prompt_feedback is not None:
            block_reason = getattr(prompt_feedback, "block_reason", None)
            if block_reason is not None:
                reason_name = getattr(block_reason, "name", str(block_reason))
                msg = f"{_MSG_CONTENT_BLOCKED}: prompt {reason_name}"
                _logger.warning("google_prompt_blocked", reason=reason_name)
                raise ProviderError(msg)

        candidates = getattr(response, "candidates", None)
        if not candidates:
            return

        for candidate in candidates:
            finish_reason = getattr(candidate, "finish_reason", None)
            if finish_reason is None:
                continue
            reason_name = getattr(finish_reason, "name", str(finish_reason))
            if reason_name in _BLOCKING_FINISH_REASONS:
                if reason_name == "PROHIBITED_CONTENT":
                    msg = f"{_MSG_PROHIBITED_CONTENT}: {reason_name}"
                    _logger.warning("google_response_prohibited_content", reason=reason_name)
                    raise ProviderError(msg)
                msg = f"{_MSG_CONTENT_BLOCKED}: {reason_name}"
                _logger.warning("google_response_blocked", reason=reason_name)
                raise ProviderError(msg)

    async def _call_generate_content(
        self,
        *,
        client: genai.Client,
        model: str,
        contents: types.ContentListUnionDict,
        config: types.GenerateContentConfig,
    ) -> GenerateContentResponse:
        """Invoke ``client.aio.models.generate_content`` with retry-friendly errors.

        Translates 429 rate-limit responses and 5xx server errors into
        :class:`RateLimitError` so the caller's
        :meth:`LLMProviderBase._retry_with_backoff` wrapper retries
        them as transient failures.

        Args:
            client: The active ``genai.Client`` instance.
            model: Model identifier.
            contents: Formatted contents for the API.
            config: Pre-built :class:`types.GenerateContentConfig`.

        Returns:
            GenerateContentResponse: The Gemini API response.

        Raises:
            APIError: Re-raised for non-retryable status codes after
                the helper inspects them.
            RateLimitError: When the API returns 429 or any 5xx status.
        """
        try:
            return await client.aio.models.generate_content(
                model=model,
                contents=contents,
                config=config,
            )
        except APIError as exc:
            code = int(exc.code or 0)
            if code in _RATE_LIMIT_STATUS_CODES or code >= _HTTP_SERVER_ERROR_MIN:
                self._logger.warning(
                    "google_chat_retryable",
                    model=model,
                    code=code,
                    error=str(exc),
                )
                raise RateLimitError(_MSG_RATE_LIMITED) from exc
            log_passthrough(
                self._logger,
                "google_generate_content_passthrough",
                exc,
                provider="google",
                model=model,
                code=code,
            )
            raise

    @staticmethod
    def _create_config(
        temperature: float,
        max_tokens: int,
        gemini_tools: list[types.Tool] | None,
        system_instruction: str | None = None,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
    ) -> types.GenerateContentConfig:
        """Create a GenerateContentConfig with the given parameters.

        Args:
            temperature: Sampling temperature.
            max_tokens: Maximum output tokens.
            gemini_tools: Optional list of tool declarations.
            system_instruction: Optional system instruction text.
            tool_choice: How the model should select tools.
            thinking: Extended-thinking configuration.  When enabled the
                helper attaches a Google ``ThinkingConfig`` with the
                requested ``thinking_budget`` and ``include_thoughts``
                so reasoning summaries flow back through
                ``self._pending_thinking``.

        Returns:
            types.GenerateContentConfig: Configured GenerateContentConfig instance.
        """
        tools_for_config: types.ToolListUnion | None = None
        if gemini_tools is not None:
            tools_for_config = []
            tools_for_config.extend(gemini_tools)

        tool_config: types.ToolConfig | None = None
        if tool_choice is not None and gemini_tools is not None:
            fc_mode = types.FunctionCallingConfigMode
            if tool_choice.mode == ToolChoiceMode.AUTO:
                tool_config = types.ToolConfig(function_calling_config=types.FunctionCallingConfig(mode=fc_mode.AUTO))
            elif tool_choice.mode == ToolChoiceMode.NONE:
                tool_config = types.ToolConfig(function_calling_config=types.FunctionCallingConfig(mode=fc_mode.NONE))
            elif tool_choice.mode == ToolChoiceMode.REQUIRED:
                tool_config = types.ToolConfig(function_calling_config=types.FunctionCallingConfig(mode=fc_mode.ANY))
            elif tool_choice.mode == ToolChoiceMode.SPECIFIC and tool_choice.function_name:
                tool_config = types.ToolConfig(
                    function_calling_config=types.FunctionCallingConfig(
                        mode=fc_mode.ANY,
                        allowed_function_names=[tool_choice.function_name],
                    ),
                )

        thinking_config: types.ThinkingConfig | None = None
        if thinking is not None and thinking.enabled:
            thinking_config = types.ThinkingConfig(
                thinking_budget=thinking.budget_tokens,
                include_thoughts=True,
            )

        return types.GenerateContentConfig(
            temperature=temperature,
            max_output_tokens=max_tokens,
            tools=tools_for_config,
            system_instruction=system_instruction,
            tool_config=tool_config,
            thinking_config=thinking_config,
        )

    @staticmethod
    def _parse_response(
        response: GenerateContentResponse,
    ) -> tuple[str, list[ToolCall]]:
        """Parse the Gemini response into content and tool calls.

        Args:
            response: The raw Gemini API response.

        Returns:
            tuple[str, list[ToolCall]]: Tuple of (content string, list of ToolCall objects).
        """
        tool_calls: list[ToolCall] = []

        content = response.text if hasattr(response, "text") and response.text else ""
        if hasattr(response, "function_calls") and response.function_calls:
            for idx, fc in enumerate(response.function_calls):
                func_name = fc.name or ""
                args = dict(fc.args) if fc.args else {}

                tool_name = func_name.split(".")[0] if "." in func_name else func_name
                tool_calls.append(
                    ToolCall(
                        id=f"call_{idx}",
                        tool_name=tool_name,
                        function_name=func_name,
                        arguments=args,
                    ),
                )

        if not content and hasattr(response, "candidates") and response.candidates:
            candidate = response.candidates[0]
            if hasattr(candidate, "content") and candidate.content and (parts := candidate.content.parts):
                content = "".join(
                    part.text for part in parts if hasattr(part, "text") and part.text and not getattr(part, "thought", False)
                )

        return content, tool_calls

    @staticmethod
    def _extract_function_calls(chunk: GenerateContentResponse) -> list[ToolCall]:
        """Convert ``response.function_calls`` into :class:`ToolCall` entries.

        Streaming and non-streaming Gemini responses surface tool
        invocations through the ``function_calls`` accessor.  This
        helper converts each entry into a :class:`ToolCall`, deriving
        ``tool_name`` from the dotted prefix of the function name when
        present and assigning a synthetic ``call_<idx>`` identifier so
        downstream tool routing has a stable id.

        Args:
            chunk: Gemini streaming chunk or response object.

        Returns:
            list[ToolCall]: Parsed tool calls in source order, or an
            empty list when the chunk has no function calls.
        """
        function_calls = getattr(chunk, "function_calls", None)
        if not function_calls:
            return []
        tool_calls: list[ToolCall] = []
        for idx, fc in enumerate(function_calls):
            func_name = fc.name or ""
            args = dict(fc.args) if fc.args else {}
            tool_name = func_name.split(".")[0] if "." in func_name else func_name
            tool_calls.append(
                ToolCall(
                    id=f"call_{idx}",
                    tool_name=tool_name,
                    function_name=func_name,
                    arguments=args,
                ),
            )
        return tool_calls

    @staticmethod
    def _extract_visible_chunk_text(chunk: GenerateContentResponse) -> str:
        """Return text from a stream chunk excluding thought parts.

        ``GenerateContentResponse.text`` returns the concatenation of
        every textual part on the chunk, including parts whose
        ``thought`` flag is ``True`` when ``include_thoughts=True``.
        Streaming consumers want only the user-visible text, so this
        helper walks the candidates manually and filters out thought
        parts before joining.

        Args:
            chunk: A streaming Gemini response chunk.

        Returns:
            str: User-visible text from the chunk, or an empty string
            when the chunk has only thought parts (or no text at all).
        """
        candidates = getattr(chunk, "candidates", None)
        if not candidates:
            return chunk.text or "" if hasattr(chunk, "text") else ""
        pieces: list[str] = []
        for candidate in candidates:
            content_obj = getattr(candidate, "content", None)
            if content_obj is None:
                continue
            parts = getattr(content_obj, "parts", None)
            if not parts:
                continue
            for part in parts:
                if getattr(part, "thought", False):
                    continue
                text = getattr(part, "text", None)
                if isinstance(text, str) and text:
                    pieces.append(text)
        return "".join(pieces)

    @staticmethod
    def _extract_thinking_text(response: GenerateContentResponse) -> str:
        """Extract reasoning text from thought parts on a Gemini response.

        Gemini surfaces extended-thinking summaries as ``Part`` entries
        whose ``thought`` flag is ``True``.  When ``include_thoughts``
        is set on :class:`google.genai.types.ThinkingConfig`, this
        helper concatenates every such part into a single string for
        downstream consumers.

        Args:
            response: The raw Gemini API response (or stream chunk).

        Returns:
            str: Concatenated thinking text, or an empty string when no
            thought parts are present.
        """
        candidates = getattr(response, "candidates", None)
        if not candidates:
            return ""
        thoughts: list[str] = []
        for candidate in candidates:
            content_obj = getattr(candidate, "content", None)
            if content_obj is None:
                continue
            parts = getattr(content_obj, "parts", None)
            if not parts:
                continue
            for part in parts:
                if not getattr(part, "thought", False):
                    continue
                text = getattr(part, "text", None)
                if isinstance(text, str) and text:
                    thoughts.append(text)
        return "\n\n".join(thoughts)

    @override
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Convert internal messages to Gemini format.

        System messages are excluded here because they are passed separately
        via the native system_instruction parameter in GenerateContentConfig.

        Builds a call_id-to-function_name mapping from assistant messages so
        that tool result ``function_response.name`` fields contain the actual
        function name (required by Google's API), not the opaque call ID.

        Args:
            messages: List of Message objects to convert.

        Returns:
            list[dict[str, object]]: List of content dictionaries in Gemini's expected format.
        """
        call_id_to_name: dict[str, str] = {}
        for msg in messages:
            if msg.role == "assistant" and msg.tool_calls:
                for tc in msg.tool_calls:
                    call_id_to_name[tc.id] = tc.function_name

        contents: list[dict[str, object]] = []

        for msg in messages:
            if msg.role == "system":
                continue
            if msg.role == "user":
                contents.append({
                    "role": "user",
                    "parts": [{"text": msg.content}],
                })
            elif msg.role == "assistant":
                parts: list[dict[str, object]] = []
                if msg.content:
                    parts.append({"text": msg.content})

                if msg.tool_calls:
                    parts.extend([
                        {
                            "function_call": {
                                "name": tc.function_name,
                                "args": tc.arguments,
                            },
                        }
                        for tc in msg.tool_calls
                    ])

                contents.append({
                    "role": "model",
                    "parts": parts,
                })
            elif msg.role == "tool" and msg.tool_results:
                parts_list: list[dict[str, object]] = [
                    {
                        "function_response": {
                            "name": call_id_to_name.get(tr.call_id, tr.call_id),
                            "response": {"result": tr.result},
                        },
                    }
                    for tr in msg.tool_results
                ]

                contents.append({
                    "role": "user",
                    "parts": parts_list,
                })

        return contents

    @staticmethod
    def _build_tool_declarations(
        tools: list[ToolDefinition],
    ) -> list[types.Tool]:
        """Build Gemini tool declarations from ToolDefinitions.

        Args:
            tools: List of ToolDefinition objects to convert.

        Returns:
            list[types.Tool]: List of Gemini Tool objects for function calling.
        """
        function_declarations: list[types.FunctionDeclaration] = []
        for tool in tools:
            google_schemas = create_google_tool_schema(tool)
            for decl in google_schemas:
                params = decl["parameters"]
                func_decl = types.FunctionDeclaration(
                    name=decl["name"],
                    description=decl["description"],
                    parameters=types.Schema(
                        type=types.Type.OBJECT,
                        properties={k: types.Schema(**cast("dict[str, Any]", dict(v))) for k, v in params["properties"].items()},
                        required=params["required"],
                    ),
                )
                function_declarations.append(func_decl)
        return [types.Tool(function_declarations=function_declarations)]

    @override
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Convert internal tools to Gemini dict format.

        Args:
            tools: List of ToolDefinition objects to convert.

        Returns:
            list[dict[str, object]]: List of tool dictionaries in Gemini's expected format.
        """
        result: list[dict[str, object]] = []
        for tool in tools:
            google_schemas = create_google_tool_schema(tool)
            result.extend(dict(schema) for schema in google_schemas)
        return result


__all__ = ["GoogleProvider", "UsageInfo"]
