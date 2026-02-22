"""Base protocol for LLM providers.

This module defines the abstract interface that all LLM provider implementations
must follow, enabling consistent interaction across Anthropic, OpenAI, Google,
Ollama, and OpenRouter.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime
from typing import TYPE_CHECKING, Any, TypedDict

from ..core.logging import get_logger, log_provider_response
from ..core.types import (
    Message,
    ModelInfo,
    ProviderCredentials,
    ToolCall,
    ToolDefinition,
)


if TYPE_CHECKING:
    import logging
    from collections.abc import AsyncIterator

    from ..core.types import ProviderName


_logger = get_logger("providers.base")


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


class LLMProviderBase(ABC):
    """Abstract base class for LLM providers.

    All provider implementations must inherit from this class and implement
    the abstract methods defined here. This ensures a consistent interface
    for the orchestrator to interact with any LLM provider.

    Attributes:
        _credentials: The stored credentials for this provider.
        _connected: Whether the provider is currently connected.
        _cancel_requested: Whether a cancellation has been requested.
    """

    def __init__(self) -> None:
        """Initialize the base provider."""
        self._credentials: ProviderCredentials | None = None
        self._connected: bool = False
        self._cancel_requested: bool = False
        self._logger: logging.Logger = get_logger("providers.base")

    @property
    @abstractmethod
    def name(self) -> ProviderName:
        """Get the provider's name.

        Returns:
            The ProviderName enum value for this provider.
        """

    @property
    def is_connected(self) -> bool:
        """Check if the provider is connected and authenticated.

        Returns:
            True if the provider is ready to accept requests.
        """
        return self._connected

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
        self._connected = False
        self._credentials = None
        self._cancel_requested = False
        self._logger.debug("provider_base_disconnected", extra={})

    @abstractmethod
    async def list_models(self) -> list[ModelInfo]:
        """Dynamically fetch available models from the provider.

        Returns:
            List of available models with their capabilities.

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
    ) -> tuple[Message, list[ToolCall] | None]:
        """Send a chat completion request.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature (0.0 to 1.0).
            max_tokens: Maximum tokens in response.

        Returns:
            Tuple of (assistant message, tool calls if any).

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
    ) -> AsyncIterator[str]:
        """Stream a chat completion response.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature (0.0 to 1.0).
            max_tokens: Maximum tokens in response.

        Yields:
            Text chunks as they arrive.

        Note:
            Implementations should raise ModelNotFoundError if the model
            doesn't exist, RateLimitError if rate limited, or ProviderError
            for other API errors.
        """
        # Abstract async generator - yield required for type checker
        yield ""

    async def cancel_request(self) -> None:
        """Cancel any in-flight request.

        This method should safely abort ongoing API calls without
        raising exceptions.
        """
        self._cancel_requested = True

    @abstractmethod
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Convert internal tool format to provider-specific format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            List of tool definitions in provider's format.
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
            List of messages in provider's format.
        """

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
            Tuple of (assistant message, tool calls or None).
        """
        message = Message(
            role="assistant",
            content=content,
            tool_calls=tool_calls or None,
            timestamp=datetime.now(),
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
            Parsed ToolCall instance.
        """
        parsed_args: dict[str, Any]
        if isinstance(raw_arguments, str):
            try:
                parsed_args = json.loads(raw_arguments)
            except json.JSONDecodeError:
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
        JSONSchemaProperty with the specified values.
    """
    _logger.debug("build_schema_property", extra={"param_type": param_type, "has_enum": enum_values is not None})
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
        List of tools in Anthropic's format.
    """
    _logger.debug("create_anthropic_tool_schema", extra={"function_count": len(tool.functions)})
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

    _logger.debug("create_anthropic_tool_schema_complete", extra={"tools_created": len(tools)})
    return tools


def create_openai_tool_schema(
    tool: ToolDefinition,
) -> list[OpenAIToolSchema]:
    """Convert ToolDefinition to OpenAI's tool format.

    Args:
        tool: The tool definition to convert.

    Returns:
        List of tools in OpenAI's format.
    """
    _logger.debug("create_openai_tool_schema", extra={"function_count": len(tool.functions)})
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

    _logger.debug("create_openai_tool_schema_complete", extra={"tools_created": len(tools)})
    return tools


LLMProvider = LLMProviderBase
