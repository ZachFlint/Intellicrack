# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""The OpenAI Chat Completions dialect.

This is the format every OpenAI-compatible gateway mirrors -- LiteLLM, vLLM,
Together, Groq, Cerebras, DeepSeek, Ollama, OpenRouter, Grok, HuggingFace -- so
it is the fallback an unknown endpoint is assumed to speak until it says
otherwise.

Two deviations are configurable because real endpoints require them: Ollama
takes tool-call arguments as an object rather than a JSON string and omits the
``type`` discriminator, and both are per-endpoint rather than per-dialect.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, ClassVar, Final, override

from intellicrack.bridges.json_schema import function_parameters
from intellicrack.core.logging import get_logger
from intellicrack.core.types import (
    ReasoningItem,
    ReasoningKind,
    ToolChoiceMode,
)
from intellicrack.providers.capabilities import (
    DEFAULT_EFFORT_LEVELS,
    TIKTOKEN_O200K,
    ApiDialect,
    ModelCapabilities,
    ReasoningEffortFormat,
    ReasoningSupport,
    TokenLimitField,
)
from intellicrack.providers.dialects.base import (
    DialectAdapter,
    DialectRequest,
    DialectResponse,
    StreamDelta,
    ToolCallFragment,
    ToolNameStyle,
    UsageInfo,
    image_parts,
    parse_tool_call,
    tool_result_text,
    wire_function_name,
)


if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from intellicrack.core.types import Message, ToolChoice, ToolDefinition, ToolResult


_logger = get_logger(__name__)

_DEFAULT_REASONING_KEY: Final[str] = "reasoning_content"
"""Key OpenAI-compatible gateways use for reasoning text (LibreChat ``reasoningKey``)."""

_CHAT_COMPLETIONS_TOKEN_FIELDS: Final[frozenset[TokenLimitField]] = frozenset({
    TokenLimitField.MAX_TOKENS,
    TokenLimitField.MAX_COMPLETION_TOKENS,
})
"""The only two output-limit fields Chat Completions understands."""


class ChatCompletionsAdapter(DialectAdapter):
    """Adapter for the OpenAI ``/chat/completions`` wire format.

    Attributes:
        dialect: Always :data:`ApiDialect.CHAT_COMPLETIONS`.
    """

    dialect: ClassVar[ApiDialect] = ApiDialect.CHAT_COMPLETIONS

    def __init__(
        self,
        *,
        serialize_tool_arguments: bool = True,
        include_tool_call_type: bool = True,
    ) -> None:
        """Initialize the adapter with a per-endpoint tool-call shape.

        Args:
            serialize_tool_arguments: When ``True``, an assistant tool call's
                arguments are JSON-encoded to a string, as OpenAI requires.
                Ollama takes the object itself.
            include_tool_call_type: When ``True``, each replayed tool call
                carries ``"type": "function"``. Ollama omits it.
        """
        self._serialize_tool_arguments = serialize_tool_arguments
        self._include_tool_call_type = include_tool_call_type

    @override
    def default_capabilities(self) -> ModelCapabilities:
        """Return the baseline record for an OpenAI-compatible chat model.

        Returns:
            ModelCapabilities: Tools and streaming on, no reasoning, output
            limit in ``max_tokens``, o200k token estimation.
        """
        return ModelCapabilities(
            dialect=ApiDialect.CHAT_COMPLETIONS,
            supports_tools=True,
            supports_streaming=True,
            token_limit_field=TokenLimitField.MAX_TOKENS,
            tokenizer=TIKTOKEN_O200K,
            reasoning=ReasoningSupport(reasoning_key=_DEFAULT_REASONING_KEY),
        )

    @staticmethod
    def reasoning_capabilities(
        *,
        effort_levels: tuple[str, ...] = DEFAULT_EFFORT_LEVELS,
        tool_calling_requires_none_effort: bool = False,
    ) -> ReasoningSupport:
        """Build the reasoning record a Chat Completions reasoning model has.

        Args:
            effort_levels: Accepted ``reasoning_effort`` values, ascending.
            tool_calling_requires_none_effort: Whether the endpoint refuses
                tool calling unless the effort is ``"none"``, as OpenAI Chat
                Completions does from GPT-5.4 onward.

        Returns:
            ReasoningSupport: The reasoning record.
        """
        return ReasoningSupport(
            supported=True,
            effort_levels=effort_levels,
            effort_format=ReasoningEffortFormat.TOP_LEVEL_EFFORT,
            reasoning_key=_DEFAULT_REASONING_KEY,
            tool_calling_requires_none_effort=tool_calling_requires_none_effort,
        )

    @override
    def build_tool_schemas(
        self,
        tools: Sequence[ToolDefinition],
        capabilities: ModelCapabilities,
        *,
        name_style: ToolNameStyle = ToolNameStyle.DOUBLE_UNDERSCORE,
    ) -> list[dict[str, Any]]:
        """Describe every tool function as an OpenAI function tool.

        A function carrying a raw JSON Schema passes it through untouched:
        Chat Completions accepts 2020-12, including ``$ref`` and ``$defs``.

        Args:
            tools: Tool definitions in final priority order.
            capabilities: The resolved capability record for the target model.
            name_style: How canonical dotted names are written onto the wire.

        Returns:
            list[dict[str, Any]]: Function tool schemas in input order.
        """
        if not capabilities.supports_tools:
            _logger.debug("chat_completions_tools_suppressed_unsupported")
            return []
        schemas: list[dict[str, Any]] = []
        for tool in tools:
            schemas.extend(
                {
                    "type": "function",
                    "function": {
                        "name": wire_function_name(func.name, name_style),
                        "description": func.description,
                        "parameters": function_parameters(func),
                    },
                }
                for func in tool.functions
            )
        return schemas

    def build_messages(
        self,
        messages: Sequence[Message],
        capabilities: ModelCapabilities,
        *,
        name_style: ToolNameStyle = ToolNameStyle.DOUBLE_UNDERSCORE,
    ) -> list[dict[str, Any]]:
        """Convert Intellicrack messages to the OpenAI message array.

        Args:
            messages: Conversation history.
            capabilities: The resolved capability record for the target model,
                consulted for reasoning replay and for whether an image
                tool-result part can survive as an image.
            name_style: How canonical dotted names are written onto the wire.

        Returns:
            list[dict[str, Any]]: Messages ready to send.
        """
        converted: list[dict[str, Any]] = []
        for msg in messages:
            if msg.role in {"system", "user"}:
                converted.append({
                    "role": msg.role,
                    "content": msg.content,
                })
            elif msg.role == "assistant":
                converted.append(self._build_assistant_message(msg, capabilities, name_style=name_style))
            elif msg.role == "tool" and msg.tool_results:
                for result in msg.tool_results:
                    converted.extend(self.render_tool_result(result, capabilities))
        return converted

    def _build_assistant_message(
        self,
        msg: Message,
        capabilities: ModelCapabilities,
        *,
        name_style: ToolNameStyle,
    ) -> dict[str, Any]:
        """Build one assistant message, replaying reasoning and tool calls.

        Args:
            msg: The assistant message.
            capabilities: The resolved capability record for the target model.
            name_style: How canonical dotted names are written onto the wire.

        Returns:
            dict[str, Any]: The assistant message to send.
        """
        assistant_msg: dict[str, Any] = {
            "role": "assistant",
            "content": msg.content,
        }
        if msg.tool_calls:
            tc_list: list[dict[str, Any]] = []
            for tc in msg.tool_calls:
                tc_dict: dict[str, Any] = {
                    "id": tc.id,
                    "function": {
                        "name": wire_function_name(tc.function_name, name_style),
                        "arguments": json.dumps(tc.arguments) if self._serialize_tool_arguments else tc.arguments,
                    },
                }
                if self._include_tool_call_type:
                    tc_dict["type"] = "function"
                tc_list.append(tc_dict)
            assistant_msg["tool_calls"] = tc_list

        reasoning_key = capabilities.reasoning.reasoning_key
        if msg.reasoning and reasoning_key and capabilities.reasoning.include_reasoning_history:
            replayed = self.render_reasoning(msg.reasoning)
            if replayed:
                assistant_msg[reasoning_key] = replayed[0]["text"]
        return assistant_msg

    @override
    def build_request(self, request: DialectRequest) -> dict[str, Any]:
        """Shape a normalized request into a Chat Completions body.

        Args:
            request: The normalized request.

        Returns:
            dict[str, Any]: The JSON body to POST.
        """
        capabilities = request.capabilities
        body: dict[str, Any] = {
            "model": request.model,
            "messages": self.build_messages(request.messages, capabilities, name_style=request.tool_name_style),
        }
        body[self.token_limit_field(capabilities)] = request.max_tokens
        if capabilities.supports_temperature:
            body["temperature"] = request.temperature

        tools = self.build_tool_schemas(request.tools, capabilities, name_style=request.tool_name_style)
        if tools:
            body["tools"] = tools
            if request.tool_choice is not None:
                body["tool_choice"] = self.tool_choice_param(request.tool_choice, name_style=request.tool_name_style)
            if not capabilities.supports_parallel_tool_calls:
                body["parallel_tool_calls"] = False

        effort = self.reasoning_effort(request, has_tools=bool(tools))
        if effort is not None:
            body["reasoning_effort"] = effort

        if request.stream:
            body["stream"] = True
            body["stream_options"] = {"include_usage": True}

        if request.enable_cache and capabilities.supports_prompt_cache_key:
            body["prompt_cache_key"] = request.model

        return self.apply_body_overrides(body, request)

    @staticmethod
    def reasoning_effort(request: DialectRequest, *, has_tools: bool) -> str | None:
        """Resolve the ``reasoning_effort`` value for a request.

        From GPT-5.4, Chat Completions refuses tool calling with any effort
        other than ``"none"``. When the capability record says so and the
        request advertises tools, the effort is forced to ``"none"`` rather
        than left to produce a 400 at the endpoint.

        Args:
            request: The normalized request.
            has_tools: Whether the request advertises any tool.

        Returns:
            str | None: The effort to send, or ``None`` to omit the parameter.
        """
        reasoning = request.capabilities.reasoning
        if not reasoning.supported or reasoning.effort_format is not ReasoningEffortFormat.TOP_LEVEL_EFFORT:
            return None
        if has_tools and reasoning.tool_calling_requires_none_effort:
            return "none" if "none" in reasoning.effort_levels else None
        thinking = request.thinking
        if thinking is None or not thinking.enabled:
            return None
        return _effort_for_budget(thinking.budget_tokens, reasoning.effort_levels)

    @staticmethod
    def tool_choice_param(
        tool_choice: ToolChoice,
        *,
        name_style: ToolNameStyle = ToolNameStyle.DOUBLE_UNDERSCORE,
    ) -> str | dict[str, Any]:
        """Convert a tool choice to the OpenAI ``tool_choice`` parameter.

        Args:
            tool_choice: The tool choice configuration.
            name_style: How canonical dotted names are written onto the wire.

        Returns:
            str | dict[str, Any]: The value for the ``tool_choice`` key. A
            :data:`ToolChoiceMode.SPECIFIC` choice with no function name
            degrades to ``"required"``, which asks for a tool without naming
            an empty one the endpoint would reject.
        """
        if tool_choice.mode == ToolChoiceMode.AUTO:
            return "auto"
        if tool_choice.mode == ToolChoiceMode.NONE:
            return "none"
        if tool_choice.mode == ToolChoiceMode.REQUIRED:
            return "required"
        function_name = tool_choice.function_name
        if not function_name:
            _logger.warning("tool_choice_specific_missing_function_name")
            return "required"
        return {
            "type": "function",
            "function": {"name": wire_function_name(function_name, name_style)},
        }

    @override
    def parse_response(self, payload: Mapping[str, Any]) -> DialectResponse:
        """Parse a Chat Completions response body.

        Args:
            payload: The decoded response body.

        Returns:
            DialectResponse: The normalized response.
        """
        raw_choices = payload.get("choices")
        choices: list[Any] = raw_choices if isinstance(raw_choices, list) else []
        if not choices:
            return DialectResponse(usage=parse_usage(payload.get("usage")))
        first = choices[0]
        choice: dict[str, Any] = first if isinstance(first, dict) else {}
        raw_message = choice.get("message")
        message: dict[str, Any] = raw_message if isinstance(raw_message, dict) else {}

        content = message.get("content")
        tool_calls = tuple(self._parse_tool_calls(message.get("tool_calls")))
        reasoning = tuple(_parse_reasoning_content(message))
        finish = choice.get("finish_reason")
        return DialectResponse(
            content=content if isinstance(content, str) else "",
            tool_calls=tool_calls,
            reasoning=reasoning,
            usage=parse_usage(payload.get("usage")),
            finish_reason=finish if isinstance(finish, str) else None,
        )

    @staticmethod
    def _parse_tool_calls(raw: object) -> list[Any]:
        """Parse the ``tool_calls`` array of a Chat Completions message.

        Args:
            raw: The raw ``tool_calls`` value.

        Returns:
            list[Any]: Parsed :class:`~intellicrack.core.types.ToolCall`
            instances, skipping entries that carry no usable function.
        """
        if not isinstance(raw, list):
            return []
        entries: list[Any] = raw
        parsed: list[Any] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            call: dict[str, Any] = entry
            function = call.get("function")
            if not isinstance(function, dict):
                continue
            function_map: dict[str, Any] = function
            name = function_map.get("name")
            arguments = function_map.get("arguments")
            if not isinstance(name, str):
                continue
            raw_arguments: str | dict[str, object]
            if isinstance(arguments, str):
                raw_arguments = arguments
            elif isinstance(arguments, dict):
                raw_arguments = dict(arguments)
            else:
                raw_arguments = "{}"
            parsed.append(
                parse_tool_call(
                    call_id=str(call.get("id", "")),
                    function_name=name,
                    raw_arguments=raw_arguments,
                ),
            )
        return parsed

    @override
    def parse_stream_event(self, event: Mapping[str, Any]) -> list[StreamDelta]:
        """Translate one Chat Completions SSE chunk into normalized deltas.

        Args:
            event: One decoded chunk.

        Returns:
            list[StreamDelta]: Zero or more deltas, in wire order.
        """
        deltas: list[StreamDelta] = []
        usage = parse_usage(event.get("usage"))
        raw_choices = event.get("choices")
        choices: list[Any] = raw_choices if isinstance(raw_choices, list) else []
        for entry in choices:
            if not isinstance(entry, dict):
                continue
            choice: dict[str, Any] = entry
            raw_delta = choice.get("delta")
            delta: dict[str, Any] = raw_delta if isinstance(raw_delta, dict) else {}
            content = delta.get("content")
            if isinstance(content, str) and content:
                deltas.append(StreamDelta(text=content))
            reasoning_text = delta.get(_DEFAULT_REASONING_KEY)
            if isinstance(reasoning_text, str) and reasoning_text:
                deltas.append(StreamDelta(reasoning=reasoning_text))
            deltas.extend(_parse_tool_call_deltas(delta.get("tool_calls")))
            finish = choice.get("finish_reason")
            if isinstance(finish, str):
                deltas.append(StreamDelta(finish=finish))
        if usage is not None:
            deltas.append(StreamDelta(usage=usage))
        return deltas

    @override
    def render_tool_result(
        self,
        result: ToolResult,
        capabilities: ModelCapabilities,
        *,
        function_name: str | None = None,
    ) -> list[dict[str, Any]]:
        """Render a tool result as a ``tool`` message, plus images if usable.

        Chat Completions carries text only in a tool message. An image part
        therefore rides in a following ``user`` message as an ``image_url``
        data URI when the model reports vision, and degrades to the shared
        deterministic text description when it does not.

        Args:
            result: The tool result to render.
            capabilities: The resolved capability record for the target model.
            function_name: Unused; Chat Completions correlates by call id.

        Returns:
            list[dict[str, Any]]: The tool message, optionally followed by a
            user message carrying the images.
        """
        del function_name
        text = tool_result_text(result)
        if result.is_error and result.success:
            text = f"[tool reported an error]\n{text}"
        rendered: list[dict[str, Any]] = [
            {
                "role": "tool",
                "tool_call_id": result.call_id,
                "content": text,
            },
        ]
        images = image_parts(result)
        if images and capabilities.supports_vision:
            rendered.append({
                "role": "user",
                "content": [
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:{part.mime_type};base64,{part.data}"},
                    }
                    for part in images
                ],
            })
        return rendered

    @override
    def render_reasoning(self, reasoning: Sequence[ReasoningItem]) -> list[dict[str, Any]]:
        """Render captured reasoning as a single ``reasoning_content`` string.

        Chat Completions has no structured reasoning item, so the only replay
        surface is the gateway's reasoning key. Items that carry no readable
        text contribute nothing rather than being fabricated into text.

        Args:
            reasoning: Reasoning blocks captured from an earlier turn.

        Returns:
            list[dict[str, Any]]: A single ``{"text": ...}`` entry, or an
            empty list when no block carries readable text.
        """
        parts = [item.text for item in reasoning if item.text]
        return [{"text": "\n\n".join(parts)}] if parts else []

    @override
    def auth_headers(self, api_key: str | None) -> dict[str, str]:
        """Build the bearer auth header.

        Args:
            api_key: The instance's API key, or ``None``.

        Returns:
            dict[str, str]: ``Authorization: Bearer <key>``, or empty.
        """
        return {"Authorization": f"Bearer {api_key}"} if api_key else {}

    @override
    def endpoint_path(self, *, model: str, stream: bool) -> str:
        """Return the Chat Completions path.

        Args:
            model: Unused; the model travels in the body.
            stream: Unused; streaming is a body flag.

        Returns:
            str: ``"chat/completions"``.
        """
        del model, stream
        return "chat/completions"

    @override
    def token_limit_field(self, capabilities: ModelCapabilities) -> str:
        """Return the output-limit field this model expects.

        Args:
            capabilities: The resolved capability record for the target model.

        Returns:
            str: ``"max_completion_tokens"`` for a reasoning model, otherwise
            ``"max_tokens"``. A record naming Responses' ``max_output_tokens``
            is corrected here rather than sent to an endpoint that would
            reject it.
        """
        declared = capabilities.token_limit_field
        if declared in _CHAT_COMPLETIONS_TOKEN_FIELDS:
            return declared.value
        _logger.warning("chat_completions_token_field_corrected", declared=declared.value)
        return TokenLimitField.MAX_TOKENS.value


def _effort_for_budget(budget_tokens: int, levels: Sequence[str]) -> str | None:
    """Map a thinking budget onto the effort ladder an endpoint accepts.

    Args:
        budget_tokens: The caller's thinking budget.
        levels: Accepted effort values, in ascending order.

    Returns:
        str | None: The chosen level, or ``None`` when the endpoint accepts
        no discrete level at all.
    """
    usable = [level for level in levels if level != "none"]
    if not usable:
        return None
    if budget_tokens <= _EFFORT_LOW_THRESHOLD:
        return usable[0]
    if budget_tokens <= _EFFORT_MEDIUM_THRESHOLD:
        return usable[len(usable) // 2]
    return usable[-1]


_EFFORT_LOW_THRESHOLD: Final[int] = 4000
_EFFORT_MEDIUM_THRESHOLD: Final[int] = 16000


def parse_usage(raw: object) -> UsageInfo | None:
    """Parse an OpenAI-compatible ``usage`` object.

    Args:
        raw: The raw ``usage`` value from a response or chunk.

    Returns:
        UsageInfo | None: Populated usage, or ``None`` when absent.
    """
    if not isinstance(raw, dict):
        return None
    usage: dict[str, Any] = raw
    prompt = _as_int(usage.get("prompt_tokens"))
    completion = _as_int(usage.get("completion_tokens"))
    total = _as_int(usage.get("total_tokens")) or (prompt + completion)
    details = usage.get("prompt_tokens_details")
    cached = _as_int(details.get("cached_tokens")) if isinstance(details, dict) else 0
    completion_details = usage.get("completion_tokens_details")
    reasoning = _as_int(completion_details.get("reasoning_tokens")) if isinstance(completion_details, dict) else 0
    return UsageInfo(
        prompt_tokens=prompt,
        completion_tokens=completion,
        total_tokens=total,
        cache_read_tokens=cached,
        reasoning_tokens=reasoning,
    )


def _as_int(raw: object) -> int:
    """Coerce a JSON number to an int, defaulting to zero.

    Args:
        raw: The raw value.

    Returns:
        int: The coerced value, or ``0``.
    """
    if isinstance(raw, bool):
        return 0
    return int(raw) if isinstance(raw, (int, float)) else 0


def _parse_reasoning_content(message: Mapping[str, Any]) -> list[ReasoningItem]:
    """Capture an OpenAI-compatible gateway's reasoning text from a message.

    Args:
        message: The assistant message from the response.

    Returns:
        list[ReasoningItem]: A single reasoning item, or an empty list.
    """
    raw = message.get(_DEFAULT_REASONING_KEY)
    if isinstance(raw, str) and raw:
        return [ReasoningItem(kind=ReasoningKind.REASONING_CONTENT, text=raw)]
    return []


def _parse_tool_call_deltas(raw: object) -> list[StreamDelta]:
    """Translate a chunk's ``tool_calls`` array into fragment deltas.

    Chat Completions correlates streamed fragments by their position in the
    array, so the index is the opaque correlation token.

    Args:
        raw: The raw ``tool_calls`` value from a streaming delta.

    Returns:
        list[StreamDelta]: One delta per fragment, in wire order.
    """
    if not isinstance(raw, list):
        return []
    entries: list[Any] = raw
    deltas: list[StreamDelta] = []
    for position, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        call: dict[str, Any] = entry
        index = call.get("index")
        token = str(index if isinstance(index, int) else position)
        function = call.get("function")
        function_map: dict[str, Any] = function if isinstance(function, dict) else {}
        name = function_map.get("name")
        arguments = function_map.get("arguments")
        call_id = call.get("id")
        deltas.append(
            StreamDelta(
                tool_call_fragment=ToolCallFragment(
                    token=token,
                    call_id=call_id if isinstance(call_id, str) else None,
                    name=name if isinstance(name, str) else None,
                    arguments=arguments if isinstance(arguments, str) else None,
                ),
            ),
        )
    return deltas
