# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Google Gemini API provider implementation.

This module provides integration with Google's Gemini models for
chat completion and tool/function calling using the modern google-genai SDK.
"""

from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime
from typing import TYPE_CHECKING, Any, Final, cast, override

from google import genai
from google.genai import types
from google.genai.errors import ClientError

from ..core.logging import get_logger, log_provider_request, log_provider_response
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
    ToolChoiceMode,
    ToolDefinition,
)
from .base import LLMProviderBase, create_google_tool_schema


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterable

    from google.genai.types import GenerateContentResponse


_MSG_API_KEY_REQUIRED = "API key required"
_MSG_NOT_CONNECTED = "Not connected"
_MSG_INVALID_API_KEY = "Invalid API key"
_MSG_CONNECTION_FAILED = "Connection failed"
_MSG_REQUEST_FAILED = "Request failed"
_MSG_FETCH_MODELS_FAILED = "Failed to fetch models from Google API"
_MSG_RATE_LIMITED = "Rate limited"
_MSG_STREAM_FAILED = "Stream failed"

_STREAM_SENTINEL: Final = object()


class GoogleProvider(LLMProviderBase):
    """Google Gemini API provider implementation.

    Provides integration with Google's Gemini models including
    support for tool/function calling and streaming responses.

    Attributes:
        _client: The Gemini API client.
        _current_task: Reference to any in-flight async task.
    """

    def __init__(self) -> None:
        """Initialize the Google provider."""
        super().__init__()
        self._client: genai.Client | None = None
        self._current_task: asyncio.Task[object] | None = None
        self._logger = get_logger("providers.google").bind(provider="google")

    @property
    def name(self) -> ProviderName:
        """Get the provider's name.

        Returns:
            The provider name enum value.
        """
        return ProviderName.GOOGLE

    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect to Google AI API.

        Args:
            credentials: Provider credentials containing the API key.

        Raises:
            AuthenticationError: If the API key is invalid or missing.
            ProviderError: If connection to the API fails.
        """
        if not credentials.api_key:
            raise AuthenticationError(_MSG_API_KEY_REQUIRED)

        saved_gemini_key = os.environ.pop("GEMINI_API_KEY", None)
        try:
            self._client = genai.Client(api_key=credentials.api_key)

            models_iter = await asyncio.to_thread(self._client.models.list)
            _ = next(iter(models_iter), None)

            self._credentials = credentials
            self._connected = True
            self._logger.info(
                "google_connected",
                has_custom_base=credentials.api_base is not None,
            )

        except ClientError as e:
            self._logger.exception(
                "google_connect_failed",
                error=str(e),
                code=e.code,
            )
            if e.code in {401, 403}:
                raise AuthenticationError(_MSG_INVALID_API_KEY) from e
            raise ProviderError(_MSG_CONNECTION_FAILED) from e
        except Exception as e:
            self._logger.exception(
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
            self._client = None
            self._current_task = None
            self._logger.info("google_disconnected")
        except Exception as exc:
            self._logger.warning("disconnect_cleanup_error", error=str(exc))
            self._connected = False

    async def list_models(self) -> list[ModelInfo]:
        """Dynamically fetch available Gemini models from Google AI API.

        Uses the models.list() endpoint to retrieve the current list of
        available generative models.

        Returns:
            List of ModelInfo objects describing available models.

        Raises:
            ProviderError: If not connected or the request fails.
        """
        if not self._connected or self._client is None:
            raise ProviderError(_MSG_NOT_CONNECTED)

        try:
            models_response = await asyncio.to_thread(self._client.models.list)

            models: list[ModelInfo] = []
            for model_data in models_response:
                model_name = getattr(model_data, "name", "")
                name_lower = model_name.lower()
                if "gemini" not in name_lower or "embedding" in name_lower:
                    continue

                display_name = getattr(model_data, "display_name", model_name)
                input_limit: int = getattr(model_data, "input_token_limit", 1048576)

                model_id = model_name
                if model_id.startswith("models/"):
                    model_id = model_id[7:]

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
                        supports_tools=supports_tools,
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
        except Exception as e:
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
            A tuple containing the assistant message and optional tool calls.

        Raises:
            ProviderError: If not connected or the request fails.
            RateLimitError: If the API rate limit is exceeded.
        """
        if not self._connected or self._client is None:
            raise ProviderError(_MSG_NOT_CONNECTED)

        self._cancel_requested = False
        self._logger.debug(
            "google_chat_started",
            model=model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        if thinking is not None and thinking.enabled:
            self._logger.debug("google_thinking_ignored")
        if enable_cache:
            self._logger.debug("google_cache_ignored")

        system_instruction = self._extract_system_instruction(messages)
        gemini_contents = self._convert_messages_to_provider_format(messages)
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
            )

            client = self._client
            typed_contents = cast("types.ContentListUnionDict", gemini_contents)

            def _generate() -> GenerateContentResponse:
                return client.models.generate_content(
                    model=model,
                    contents=typed_contents,
                    config=config,
                )

            response = await asyncio.to_thread(_generate)

            duration_ms = (time.perf_counter() - start_time) * 1000
            content, tool_calls = self._parse_response(response)

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
                timestamp=datetime.now(),
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

        except Exception as e:
            self._logger.exception(
                "google_chat_failed",
                model=model,
                error=str(e),
            )
            error_msg = str(e).lower()
            if "quota" in error_msg or "rate" in error_msg or "429" in error_msg:
                raise RateLimitError(_MSG_RATE_LIMITED) from e
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
            Text chunks as they arrive from the API.

        Raises:
            ProviderError: If not connected or the stream fails.
        """
        if not self._connected or self._client is None:
            raise ProviderError(_MSG_NOT_CONNECTED)

        self._cancel_requested = False
        self._logger.debug(
            "google_chat_stream_started",
            model=model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        system_instruction = self._extract_system_instruction(messages)
        gemini_contents = self._convert_messages_to_provider_format(messages)
        gemini_tools = self._build_tool_declarations(tools) if tools else None
        chunk_count = 0

        try:
            config = self._create_config(
                temperature,
                max_tokens,
                gemini_tools,
                system_instruction,
                tool_choice=tool_choice,
            )

            client = self._client
            typed_contents = cast("types.ContentListUnionDict", gemini_contents)

            def _start_stream() -> Iterable[GenerateContentResponse]:
                return client.models.generate_content_stream(
                    model=model,
                    contents=typed_contents,
                    config=config,
                )

            response_stream = iter(await asyncio.to_thread(_start_stream))

            last_chunk: GenerateContentResponse | None = None
            while True:
                raw_chunk = await asyncio.to_thread(next, response_stream, _STREAM_SENTINEL)
                if raw_chunk is _STREAM_SENTINEL:
                    break
                chunk = cast("GenerateContentResponse", raw_chunk)
                if self._cancel_requested:
                    self._logger.info(
                        "google_chat_stream_cancelled",
                        model=model,
                        chunks_received=chunk_count,
                    )
                    break
                last_chunk = chunk
                if hasattr(chunk, "text") and chunk.text:
                    chunk_count += 1
                    yield chunk.text

            if not self._cancel_requested:
                if last_chunk is not None and hasattr(last_chunk, "function_calls") and last_chunk.function_calls:
                    tool_calls: list[ToolCall] = []
                    for idx, fc in enumerate(last_chunk.function_calls):
                        func_name = fc.name or ""
                        args = dict(fc.args) if fc.args else {}
                        tool_name = func_name.split(".")[0] if "." in func_name else func_name
                        tool_calls.append(
                            ToolCall(
                                id=f"call_{idx}",
                                tool_name=tool_name,
                                function_name=func_name,
                                arguments=args,
                            )
                        )
                    self._pending_tool_calls = tool_calls

                self._logger.info(
                    "google_chat_stream_completed",
                    model=model,
                    chunks_received=chunk_count,
                )

        except Exception as e:
            self._logger.exception(
                "google_chat_stream_failed",
                model=model,
                error=str(e),
                chunks_received=chunk_count,
            )
            if not self._cancel_requested:
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
    def _extract_system_instruction(
        messages: list[Message],
    ) -> str | None:
        """Extract and concatenate all system messages into a single instruction.

        Args:
            messages: List of Message objects to scan.

        Returns:
            Concatenated system instruction text, or None if no system messages.
        """
        system_parts: list[str] = [msg.content for msg in messages if msg.role == "system" and msg.content]
        return "\n\n".join(system_parts) if system_parts else None

    @staticmethod
    def _create_config(
        temperature: float,
        max_tokens: int,
        gemini_tools: list[types.Tool] | None,
        system_instruction: str | None = None,
        tool_choice: ToolChoice | None = None,
    ) -> types.GenerateContentConfig:
        """Create a GenerateContentConfig with the given parameters.

        Args:
            temperature: Sampling temperature.
            max_tokens: Maximum output tokens.
            gemini_tools: Optional list of tool declarations.
            system_instruction: Optional system instruction text.
            tool_choice: How the model should select tools.

        Returns:
            Configured GenerateContentConfig instance.
        """
        tools_for_config: types.ToolListUnion | None = None
        if gemini_tools is not None:
            tools_for_config = []
            tools_for_config.extend(gemini_tools)

        tool_config: types.ToolConfig | None = None
        if tool_choice is not None and gemini_tools is not None:
            fc_mode = types.FunctionCallingConfigMode
            if tool_choice.mode == ToolChoiceMode.AUTO:
                tool_config = types.ToolConfig(
                    function_calling_config=types.FunctionCallingConfig(mode=fc_mode.AUTO)
                )
            elif tool_choice.mode == ToolChoiceMode.NONE:
                tool_config = types.ToolConfig(
                    function_calling_config=types.FunctionCallingConfig(mode=fc_mode.NONE)
                )
            elif tool_choice.mode == ToolChoiceMode.REQUIRED:
                tool_config = types.ToolConfig(
                    function_calling_config=types.FunctionCallingConfig(mode=fc_mode.ANY)
                )
            elif tool_choice.mode == ToolChoiceMode.SPECIFIC and tool_choice.function_name:
                tool_config = types.ToolConfig(
                    function_calling_config=types.FunctionCallingConfig(
                        mode=fc_mode.ANY,
                        allowed_function_names=[tool_choice.function_name],
                    )
                )

        return types.GenerateContentConfig(
            temperature=temperature,
            max_output_tokens=max_tokens,
            tools=tools_for_config,
            system_instruction=system_instruction,
            tool_config=tool_config,
        )

    @staticmethod
    def _parse_response(
        response: GenerateContentResponse,
    ) -> tuple[str, list[ToolCall]]:
        """Parse the Gemini response into content and tool calls.

        Args:
            response: The raw Gemini API response.

        Returns:
            Tuple of (content string, list of ToolCall objects).
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
                    )
                )

        if not content and hasattr(response, "candidates") and response.candidates:
            candidate = response.candidates[0]
            if hasattr(candidate, "content") and candidate.content and (parts := candidate.content.parts):
                content = "".join(part.text for part in parts if hasattr(part, "text") and part.text)

        return content, tool_calls

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
            List of content dictionaries in Gemini's expected format.
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
                            }
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
                        }
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
            List of Gemini Tool objects for function calling.
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
            List of tool dictionaries in Gemini's expected format.
        """
        result: list[dict[str, object]] = []
        for tool in tools:
            google_schemas = create_google_tool_schema(tool)
            result.extend(dict(schema) for schema in google_schemas)
        return result
