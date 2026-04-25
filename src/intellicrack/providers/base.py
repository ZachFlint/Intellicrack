# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Base protocol for LLM providers.

This module defines the abstract interface that all LLM provider implementations must follow, enabling consistent interaction across
Anthropic, OpenAI, Google, Ollama, and OpenRouter.
"""

from __future__ import annotations

import asyncio
import json
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, TypedDict, TypeVar

from intellicrack.core.logging import get_logger, log_provider_response
from intellicrack.core.types import (
    AuthenticationError,
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    RateLimitError,
    ThinkingConfig,
    ToolCall,
    ToolChoice,
    ToolChoiceMode,
    ToolDefinition,
)


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable

    from intellicrack.core.types import ProviderName

_T = TypeVar("_T")

_logger = get_logger("providers.base")
_secure_rng = random.SystemRandom()


@dataclass(slots=True)
class UsageInfo:
    """Token usage statistics reported by a provider.

    Attributes:
        prompt_tokens: Tokens consumed by the prompt / input messages.
        completion_tokens: Tokens generated in the completion / output.
        total_tokens: Sum of prompt and completion tokens as reported
            by the provider when available.
    """

    prompt_tokens: int = field(default=0)
    completion_tokens: int = field(default=0)
    total_tokens: int = field(default=0)


class JSONSchemaProperty(TypedDict, total=False):
    """JSON Schema property definition for tool parameters."""

    type: str
    description: str
    enum: list[str]
    default: str | int | float | bool | None


class JSONSchemaParameters(TypedDict):
    """JSON Schema parameters object for tool functions."""

    type: str
    properties: dict[str, JSONSchemaProperty]
    required: list[str]


class AnthropicToolSchema(TypedDict):
    """Anthropic tool schema format."""

    name: str
    description: str
    input_schema: JSONSchemaParameters


class OpenAIFunctionSchema(TypedDict):
    """OpenAI function definition within a tool."""

    name: str
    description: str
    parameters: JSONSchemaParameters


class OpenAIToolSchema(TypedDict):
    """OpenAI tool schema format."""

    type: str
    function: OpenAIFunctionSchema


class GoogleFunctionDeclaration(TypedDict):
    """Google Gemini function declaration format."""

    name: str
    description: str
    parameters: JSONSchemaParameters


def serialize_tool_result(result: object) -> str:
    """Serialize a tool result to a string for API consumption.

    Args:
        result: The tool result value, either a string or a
            JSON-serializable object.

    Returns:
        str: The result as a string, JSON-encoded if not already a string.
    """
    return result if isinstance(result, str) else json.dumps(result)


def parse_tool_call(
    *,
    call_id: str,
    function_name: str,
    raw_arguments: str | dict[str, object],
) -> ToolCall:
    """Parse a tool call from provider-specific data into a ToolCall.

    Handles JSON argument parsing and tool name extraction from
    dotted function names.

    Args:
        call_id: Unique identifier for the tool call.
        function_name: Function name from the provider response.
        raw_arguments: Arguments as a JSON string or pre-parsed dict.

    Returns:
        ToolCall: Parsed ToolCall instance.
    """
    parsed_args: dict[str, Any]
    if isinstance(raw_arguments, str):
        try:
            parsed_args = json.loads(raw_arguments)
        except json.JSONDecodeError:
            _logger.warning("tool_call_args_json_decode_failed", function=function_name)
            parsed_args = {}
    else:
        parsed_args = dict(raw_arguments)

    tool_name = function_name.split(".", maxsplit=1)[0] if "." in function_name else function_name
    return ToolCall(
        id=call_id,
        tool_name=tool_name,
        function_name=function_name,
        arguments=parsed_args,
    )


class LLMProviderBase(ABC):
    """Abstract base class for LLM providers.

    All provider implementations must inherit from this class and implement the abstract methods defined here. This ensures a consistent
    interface for the orchestrator to interact with any LLM provider.
    """

    def __init__(self) -> None:
        """Initialize the LLMProviderBase instance."""
        self._credentials: ProviderCredentials | None = None
        self.connected: bool = False
        self._cancel_requested: bool = False
        self._pending_tool_calls: list[ToolCall] = []
        self._pending_usage: UsageInfo | None = None
        self._pending_thinking: list[str] = []
        self._logger = get_logger("providers.base")

    @property
    @abstractmethod
    def name(self) -> ProviderName:
        """Get the provider's name.

        Returns:
            ProviderName: The ProviderName enum value for this provider.
        """

    @property
    def is_connected(self) -> bool:
        """Check if the provider is connected and authenticated.

        Returns:
            bool: True if the provider is ready to accept requests.
        """
        return self.connected

    @abstractmethod
    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect to the provider with given credentials.

        Args:
            credentials: API credentials for authentication.

        Raises:
            AuthenticationError: If credentials are invalid.
            ProviderError: If unable to connect to provider.
        """

    async def disconnect(self) -> None:
        """Disconnect from the provider.

        Cleans up any resources and invalidates the connection.
        """
        self.connected = False
        self._credentials = None
        self._cancel_requested = False
        self._pending_tool_calls.clear()
        self._pending_usage = None
        self._pending_thinking.clear()
        self._logger.debug("provider_base_disconnected")

    @abstractmethod
    async def list_models(self) -> list[ModelInfo]:
        """Dynamically fetch available models from the provider.

        Returns:
            list[ModelInfo]: List of available models with their capabilities.

        Raises:
            ProviderError: If not connected or request fails.
        """

    @abstractmethod
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
        """Send a chat completion request.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature (0.0 to 1.0).
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration.
            enable_cache: Whether to enable prompt caching.

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of (assistant message, tool calls if any).

        Raises:
            ModelNotFoundError: If model doesn't exist.
            RateLimitError: If rate limited.
            ProviderError: For other API errors.
        """

    @abstractmethod
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
        """Stream a chat completion response.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature (0.0 to 1.0).
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration.
            enable_cache: Whether to enable prompt caching.

        Yields:
            str: Text chunks as they arrive.

        Note:
            Implementations should raise ModelNotFoundError if the model
            doesn't exist, RateLimitError if rate limited, or ProviderError
            for other API errors.
        """
        # Abstract async generator - yield required for type checker
        yield ""

    def get_pending_tool_calls(self) -> list[ToolCall]:
        """Retrieve tool calls accumulated during the last streaming call.

        After a ``chat_stream()`` call completes, providers store any tool
        calls that were signalled in the stream deltas.  Consumers call
        this method once to collect them.  The internal buffer is cleared
        on each call so results are never returned twice.

        Returns:
            list[ToolCall]: List of ToolCall objects accumulated during streaming.
        """
        calls = list(self._pending_tool_calls)
        self._pending_tool_calls.clear()
        return calls

    def get_pending_usage(self) -> UsageInfo | None:
        """Retrieve token usage captured during the last request.

        After a ``chat()`` or ``chat_stream()`` call completes, providers
        store token-usage statistics reported by the backend (when
        available).  Consumers call this method once to collect them.
        The internal buffer is cleared on each call so the same usage
        record is never returned twice.

        Returns:
            UsageInfo | None: Captured UsageInfo if the provider reported
            any usage, otherwise ``None``.
        """
        usage = self._pending_usage
        self._pending_usage = None
        return usage

    def get_pending_thinking(self) -> list[str]:
        """Retrieve extended-thinking text emitted during the last request.

        After a streaming call that enabled extended thinking, providers
        store each thinking block seen on the wire.  Consumers call this
        method once to collect them.  The internal buffer is cleared on
        each call so the same block is never returned twice.

        Returns:
            list[str]: List of thinking block texts accumulated during the
            last request.  Empty when thinking was not enabled or not
            emitted.
        """
        thinking = list(self._pending_thinking)
        self._pending_thinking.clear()
        return thinking

    async def cancel_request(self) -> None:
        """Cancel any in-flight request.

        This method should safely abort ongoing API calls without raising exceptions.
        """
        self._cancel_requested = True

    async def _retry_with_backoff(
        self,
        coro_factory: Callable[[], Awaitable[_T]],
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        retryable_exceptions: tuple[type[Exception], ...] = (RateLimitError,),
    ) -> _T:
        """Execute an async operation with exponential backoff retry.

        Retries on transient failures using exponential backoff with jitter.
        ``AuthenticationError`` is never retried regardless of the
        ``retryable_exceptions`` parameter.

        Args:
            coro_factory: Zero-argument callable that creates the awaitable
                to execute on each attempt.
            max_retries: Maximum number of retry attempts after the initial
                try.
            base_delay: Initial delay in seconds before the first retry.
            max_delay: Upper bound on the delay between retries.
            retryable_exceptions: Tuple of exception types that should
                trigger a retry.

        Returns:
            _T: The result of the awaitable produced by *coro_factory*.

        Raises:
            AuthenticationError: If the operation fails with bad credentials.
            ProviderError: If all retry attempts are exhausted with no captured
                exception to re-raise.
            retryable_exceptions: The most recent caught exception when
                ``max_retries`` is exhausted. Re-raised verbatim from the
                ``except retryable_exceptions`` block.
        """
        for attempt in range(max_retries + 1):
            try:
                return await coro_factory()
            except AuthenticationError:
                raise
            except retryable_exceptions as exc:
                if attempt >= max_retries:
                    raise
                delay = min(base_delay * (2**attempt), max_delay)
                jitter = _secure_rng.uniform(0, delay * 0.1)
                self._logger.warning(
                    "provider_retry_backoff",
                    attempt=attempt + 1,
                    max_retries=max_retries,
                    delay=delay + jitter,
                    error=str(exc),
                )
                await asyncio.sleep(delay + jitter)
        msg = "retry_with_backoff exhausted without capturing an exception"
        raise ProviderError(msg)

    @abstractmethod
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Convert internal tool format to provider-specific format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            list[dict[str, object]]: List of tool definitions in provider's format.
        """

    @abstractmethod
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Convert internal message format to provider-specific format.

        Args:
            messages: List of Message objects.

        Returns:
            list[dict[str, object]]: List of messages in provider's format.
        """

    def convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Convert internal tool format to provider-specific format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            list[dict[str, object]]: List of tool definitions in provider's format.
        """
        return self._convert_tools_to_provider_format(tools)

    def convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Convert internal message format to provider-specific format.

        Args:
            messages: List of Message objects.

        Returns:
            list[dict[str, object]]: List of messages in provider's format.
        """
        return self._convert_messages_to_provider_format(messages)

    @staticmethod
    def _build_chat_response(
        *,
        provider: str,
        model: str,
        content: str,
        tool_calls: list[ToolCall],
        duration_ms: float,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Create a standard chat response tuple and log the response.

        Args:
            provider: Provider name for logging.
            model: Model identifier for logging.
            content: Response text content.
            tool_calls: Parsed tool calls from the response.
            duration_ms: Request duration in milliseconds.

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of (assistant message, tool calls or None).
        """
        message = Message(
            role="assistant",
            content=content,
            tool_calls=tool_calls or None,
            timestamp=datetime.now(tz=UTC),
        )
        log_provider_response(
            provider=provider,
            model=model,
            tool_calls_count=len(tool_calls),
            duration_ms=duration_ms,
        )
        return message, tool_calls or None

    @staticmethod
    def _parse_tool_call_common(
        *,
        call_id: str,
        function_name: str,
        raw_arguments: str | dict[str, object],
    ) -> ToolCall:
        """Parse a tool call from provider-specific data into a ToolCall.

        Handles JSON argument parsing and tool name extraction from
        dotted function names.

        Args:
            call_id: Unique identifier for the tool call.
            function_name: Function name from the provider response.
            raw_arguments: Arguments as a JSON string or pre-parsed dict.

        Returns:
            ToolCall: Parsed ToolCall instance.
        """
        return parse_tool_call(
            call_id=call_id,
            function_name=function_name,
            raw_arguments=raw_arguments,
        )

    @staticmethod
    def _serialize_tool_result(result: object) -> str:
        """Serialize a tool result to a string for API consumption.

        Args:
            result: The tool result value, either a string or a
                JSON-serializable object.

        Returns:
            str: The result as a string, JSON-encoded if not already a string.
        """
        return serialize_tool_result(result)

    @staticmethod
    def _convert_tool_choice_to_openai_format(
        tool_choice: ToolChoice,
    ) -> str | dict[str, object]:
        """Convert a ToolChoice to the OpenAI-compatible tool_choice parameter.

        Args:
            tool_choice: The tool choice configuration.

        Returns:
            str | dict[str, object]: A string or dict suitable for the ``tool_choice`` API parameter.
        """
        if tool_choice.mode == ToolChoiceMode.AUTO:
            return "auto"
        if tool_choice.mode == ToolChoiceMode.NONE:
            return "none"
        if tool_choice.mode == ToolChoiceMode.REQUIRED:
            return "required"
        return {
            "type": "function",
            "function": {"name": tool_choice.function_name or ""},
        }

    @staticmethod
    def _convert_messages_to_openai_format(
        messages: list[Message],
        *,
        serialize_tool_arguments: bool = True,
        include_tool_call_type: bool = True,
    ) -> list[dict[str, object]]:
        """Convert internal messages to OpenAI-compatible format.

        Shared conversion logic for providers that use the OpenAI message
        schema (OpenAI, Grok, HuggingFace, OpenRouter, Ollama).

        Args:
            messages: List of Message objects to convert.
            serialize_tool_arguments: When True, tool call arguments are
                JSON-serialized to a string. When False, the dict is
                passed through as-is (Ollama).
            include_tool_call_type: When True, each tool call dict
                includes ``"type": "function"``. When False, the key
                is omitted (Ollama).

        Returns:
            list[dict[str, object]]: List of message dicts in OpenAI-compatible format.
        """
        converted: list[dict[str, object]] = []

        for msg in messages:
            if msg.role in {"system", "user"}:
                converted.append({
                    "role": msg.role,
                    "content": msg.content,
                })
            elif msg.role == "assistant":
                assistant_msg: dict[str, object] = {
                    "role": "assistant",
                    "content": msg.content,
                }

                if msg.tool_calls:
                    tc_list: list[dict[str, object]] = []
                    for tc in msg.tool_calls:
                        tc_dict: dict[str, object] = {
                            "id": tc.id,
                            "function": {
                                "name": tc.function_name,
                                "arguments": json.dumps(tc.arguments) if serialize_tool_arguments else tc.arguments,
                            },
                        }
                        if include_tool_call_type:
                            tc_dict["type"] = "function"
                        tc_list.append(tc_dict)
                    assistant_msg["tool_calls"] = tc_list

                converted.append(assistant_msg)
            elif msg.role == "tool" and msg.tool_results:
                converted.extend(
                    {
                        "role": "tool",
                        "tool_call_id": tr.call_id,
                        "content": serialize_tool_result(tr.result),
                    }
                    for tr in msg.tool_results
                )

        return converted


class ToolCallBufferManager:
    """Accumulates streaming tool call deltas into complete ToolCall objects.

    Used by providers that consume OpenAI-compatible SSE streams where tool call fragments arrive incrementally across multiple chunks.
    """

    def __init__(self) -> None:
        """Initialize the ToolCallBufferManager instance."""
        self._buffers: dict[int, dict[str, str]] = {}

    def accumulate(
        self,
        *,
        index: int,
        call_id: str | None = None,
        name: str | None = None,
        arguments: str | None = None,
    ) -> None:
        """Merge a single streaming delta into the buffer.

        Args:
            index: Tool-call index from the SSE delta.
            call_id: Unique identifier for the tool call (first chunk only).
            name: Function name (first chunk only).
            arguments: Partial JSON argument fragment to append.
        """
        if index not in self._buffers:
            self._buffers[index] = {"id": "", "name": "", "arguments": ""}
        buf = self._buffers[index]
        if call_id:
            buf["id"] = call_id
        if name:
            buf["name"] = name
        if arguments:
            buf["arguments"] += arguments

    def finalize(self) -> list[ToolCall]:
        """Convert all complete buffered entries to ToolCall objects and reset.

        Entries missing an ``id`` or ``name`` are silently discarded.

        Returns:
            list[ToolCall]: List of parsed ToolCall instances.
        """
        results = [
            parse_tool_call(
                call_id=buf["id"],
                function_name=buf["name"],
                raw_arguments=buf["arguments"],
            )
            for buf in self._buffers.values()
            if buf["id"] and buf["name"]
        ]
        self._buffers.clear()
        return results


def _build_schema_property(
    param_type: str,
    description: str,
    enum_values: list[str] | None = None,
    default: object = None,
) -> JSONSchemaProperty:
    """Build a JSON Schema property from parameters.

    Args:
        param_type: The JSON Schema type string.
        description: Description of the parameter.
        enum_values: Optional list of allowed values.
        default: Optional default value.

    Returns:
        JSONSchemaProperty: JSONSchemaProperty with the specified values.
    """
    _logger.debug("build_schema_property", param_type=param_type, has_enum=enum_values is not None)
    prop: JSONSchemaProperty = {
        "type": param_type,
        "description": description,
    }
    if enum_values is not None:
        prop["enum"] = enum_values
    if default is not None and isinstance(default, (str, int, float, bool)):
        prop["default"] = default
    return prop


def create_anthropic_tool_schema(
    tool: ToolDefinition,
) -> list[AnthropicToolSchema]:
    """Convert ToolDefinition to Anthropic's tool format.

    Args:
        tool: The tool definition to convert.

    Returns:
        list[AnthropicToolSchema]: List of tools in Anthropic's format.
    """
    _logger.debug("create_anthropic_tool_schema", function_count=len(tool.functions))
    tools: list[AnthropicToolSchema] = []

    for func in tool.functions:
        properties: dict[str, JSONSchemaProperty] = {}
        required: list[str] = []

        for param in func.parameters:
            properties[param.name] = _build_schema_property(
                param_type=param.type,
                description=param.description,
                enum_values=param.enum,
                default=param.default,
            )
            if param.required:
                required.append(param.name)

        tool_schema: AnthropicToolSchema = {
            "name": func.name,
            "description": func.description,
            "input_schema": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        }
        tools.append(tool_schema)

    _logger.debug("create_anthropic_tool_schema_complete", tools_created=len(tools))
    return tools


def create_openai_tool_schema(
    tool: ToolDefinition,
) -> list[OpenAIToolSchema]:
    """Convert ToolDefinition to OpenAI's tool format.

    Args:
        tool: The tool definition to convert.

    Returns:
        list[OpenAIToolSchema]: List of tools in OpenAI's format.
    """
    _logger.debug("create_openai_tool_schema", function_count=len(tool.functions))
    tools: list[OpenAIToolSchema] = []

    for func in tool.functions:
        properties: dict[str, JSONSchemaProperty] = {}
        required: list[str] = []

        for param in func.parameters:
            properties[param.name] = _build_schema_property(
                param_type=param.type,
                description=param.description,
                enum_values=param.enum,
                default=param.default,
            )
            if param.required:
                required.append(param.name)

        tool_schema: OpenAIToolSchema = {
            "type": "function",
            "function": {
                "name": func.name,
                "description": func.description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            },
        }
        tools.append(tool_schema)

    _logger.debug("create_openai_tool_schema_complete", tools_created=len(tools))
    return tools


def create_google_tool_schema(
    tool: ToolDefinition,
) -> list[GoogleFunctionDeclaration]:
    """Convert ToolDefinition to Google Gemini's function declaration format.

    Args:
        tool: The tool definition to convert.

    Returns:
        list[GoogleFunctionDeclaration]: List of function declarations in Google's format with uppercase types.
    """
    _logger.debug("create_google_tool_schema", function_count=len(tool.functions))
    tools: list[GoogleFunctionDeclaration] = []

    for func in tool.functions:
        properties: dict[str, JSONSchemaProperty] = {}
        required: list[str] = []

        for param in func.parameters:
            properties[param.name] = _build_schema_property(
                param_type=param.type.upper(),
                description=param.description,
                enum_values=param.enum,
                default=param.default,
            )
            if param.required:
                required.append(param.name)

        tool_schema: GoogleFunctionDeclaration = {
            "name": func.name,
            "description": func.description,
            "parameters": {
                "type": "OBJECT",
                "properties": properties,
                "required": required,
            },
        }
        tools.append(tool_schema)

    _logger.debug("create_google_tool_schema_complete", tools_created=len(tools))
    return tools


LLMProvider = LLMProviderBase
