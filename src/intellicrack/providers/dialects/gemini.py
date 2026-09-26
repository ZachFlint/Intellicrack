# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""The Google Gemini dialect.

Gemini differs from the other three in almost every structural detail: the model travels in the URL rather than the body, types are
uppercase, messages are ``contents`` with an assistant role of ``model``, and a tool result identifies itself by *function name* rather than
by call id -- so the layer has to remember which name each call used.

Two Gemini-specific pieces of state matter for multi-turn tool use. Gemini 3.x signs each function call with a ``thought_signature`` that
must be echoed back verbatim or the next request fails with ``Function call is missing a thought_signature``; and
``functionResponse.response`` takes structured JSON natively, so a structured tool-result part survives here without degrading to text.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import TYPE_CHECKING, Any, ClassVar, Final, override

from intellicrack.bridges.json_schema import function_parameters
from intellicrack.core.json_payload import is_json_array, is_json_object
from intellicrack.core.logging import get_logger
from intellicrack.core.types import (
    ReasoningItem,
    ReasoningKind,
    ToolCall,
    ToolChoiceMode,
)
from intellicrack.providers.capabilities import (
    TIKTOKEN_CL100K,
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
    render_parts_as_text,
    structured_parts,
    tool_result_text,
    wire_function_name,
)


if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from intellicrack.core.types import Message, ToolChoice, ToolDefinition, ToolResult


_logger = get_logger(__name__)

GEMINI_API_KEY_HEADER: Final[str] = "x-goog-api-key"
"""Header Gemini authenticates with when the key is not in the query string."""

_THOUGHT_SIGNATURE_KEY: Final[str] = "thought_signature"


_NARRATIVE_KEY: Final[str] = "content"
"""Reserved ``functionResponse.response`` key carrying the non-structured parts."""


class GeminiAdapter(DialectAdapter):
    """Adapter for the Google Gemini ``generateContent`` wire format.

    Attributes:
        dialect: Always :data:`ApiDialect.GEMINI`.
    """

    dialect: ClassVar[ApiDialect] = ApiDialect.GEMINI

    @override
    def default_capabilities(self) -> ModelCapabilities:
        """Return the baseline record for a Gemini model.

        Returns:
            ModelCapabilities: Tools, vision and streaming on, thinking
            expressed as a generation-config token budget, output limit in
            ``maxOutputTokens``, cl100k token estimation as the conservative
            default for a non-OpenAI tokenizer.
        """
        return ModelCapabilities(
            dialect=ApiDialect.GEMINI,
            supports_tools=True,
            supports_vision=True,
            supports_streaming=True,
            token_limit_field=TokenLimitField.MAX_OUTPUT_TOKENS,
            tokenizer=TIKTOKEN_CL100K,
            reasoning=ReasoningSupport(
                supported=True,
                effort_format=ReasoningEffortFormat.GENERATION_BUDGET,
            ),
        )

    @override
    def build_tool_schemas(
        self,
        tools: Sequence[ToolDefinition],
        capabilities: ModelCapabilities,
        *,
        name_style: ToolNameStyle = ToolNameStyle.DOUBLE_UNDERSCORE,
    ) -> list[dict[str, Any]]:
        """Describe every tool function as a Gemini function declaration.

        Gemini takes one ``Tool`` carrying every declaration rather than one
        entry per function, so the return value is a single-element list. A
        function carrying a raw JSON Schema is reduced to Gemini's supported
        subset first, since Gemini rejects ``$ref``, composition keywords and
        lowercase type names outright.

        Args:
            tools: Tool definitions in final priority order.
            capabilities: The resolved capability record for the target model.
            name_style: How canonical dotted names are written onto the wire.

        Returns:
            list[dict[str, Any]]: A single ``functionDeclarations`` tool, or
            an empty list when there is nothing to declare.
        """
        if not capabilities.supports_tools:
            _logger.debug("gemini_tools_suppressed_unsupported")
            return []
        declarations: list[dict[str, Any]] = []
        for tool in tools:
            declarations.extend(
                {
                    "name": wire_function_name(func.name, name_style),
                    "description": func.description,
                    "parameters": function_parameters(func, uppercase_types=True),
                }
                for func in tool.functions
            )
        return [{"functionDeclarations": declarations}] if declarations else []

    def build_contents(
        self,
        messages: Sequence[Message],
        capabilities: ModelCapabilities,
        *,
        name_style: ToolNameStyle = ToolNameStyle.DOUBLE_UNDERSCORE,
    ) -> list[dict[str, Any]]:
        """Convert Intellicrack messages to the Gemini ``contents`` array.

        A ``functionResponse`` must name the same function as the
        ``functionCall`` it answers, so the call-id to wire-name mapping is
        built up front from the assistant turns and used when a tool result is
        rendered.

        Args:
            messages: Conversation history.
            capabilities: The resolved capability record for the target model.
            name_style: How canonical dotted names are written onto the wire.

        Returns:
            list[dict[str, Any]]: Contents ready to send.
        """
        call_id_to_name: dict[str, str] = {}
        for msg in messages:
            if msg.role == "assistant" and msg.tool_calls:
                for tc in msg.tool_calls:
                    call_id_to_name[tc.id] = wire_function_name(tc.function_name, name_style)

        contents: list[dict[str, Any]] = []
        for msg in messages:
            if msg.role == "system":
                continue
            if msg.role == "user":
                contents.append({"role": "user", "parts": [{"text": msg.content}]})
            elif msg.role == "assistant":
                contents.append(self._model_content(msg, name_style=name_style))
            elif msg.role == "tool" and msg.tool_results:
                parts: list[dict[str, Any]] = []
                for result in msg.tool_results:
                    parts.extend(
                        self.render_tool_result(
                            result,
                            capabilities,
                            function_name=call_id_to_name.get(result.call_id, result.call_id),
                        ),
                    )
                if parts:
                    contents.append({"role": "user", "parts": parts})
        return contents

    def _model_content(self, msg: Message, *, name_style: ToolNameStyle) -> dict[str, Any]:
        """Build one ``model`` turn, re-attaching each call's thought signature.

        Args:
            msg: The assistant message.
            name_style: How canonical dotted names are written onto the wire.

        Returns:
            dict[str, Any]: The model content entry.
        """
        parts: list[dict[str, Any]] = []
        if msg.reasoning:
            parts.extend(self.render_reasoning(msg.reasoning))
        if msg.content:
            parts.append({"text": msg.content})
        if msg.tool_calls:
            parts.extend(self.build_function_call_part(tc, name_style=name_style) for tc in msg.tool_calls)
        return {"role": "model", "parts": parts}

    @staticmethod
    def build_function_call_part(tool_call: ToolCall, *, name_style: ToolNameStyle) -> dict[str, Any]:
        """Build a Gemini function-call part, preserving its thought signature.

        Gemini 3.x signs each function call and rejects the next request with
        ``400 INVALID_ARGUMENT: Function call is missing a thought_signature``
        if the signature does not come back. Older models never produce one,
        so the key is omitted entirely rather than sent empty.

        Args:
            tool_call: The tool call being replayed.
            name_style: How canonical dotted names are written onto the wire.

        Returns:
            dict[str, Any]: A Gemini ``Part``-shaped dict carrying the
            function call and, when present, the decoded signature bytes.
        """
        part: dict[str, Any] = {
            "function_call": {
                "name": wire_function_name(tool_call.function_name, name_style),
                "args": tool_call.arguments,
            },
        }
        if tool_call.thought_signature:
            try:
                part[_THOUGHT_SIGNATURE_KEY] = base64.b64decode(tool_call.thought_signature)
            except (binascii.Error, ValueError):
                _logger.warning("gemini_thought_signature_undecodable", call_id=tool_call.id)
        return part

    @override
    def build_request(self, request: DialectRequest) -> dict[str, Any]:
        """Shape a normalized request into a Gemini ``generateContent`` body.

        Args:
            request: The normalized request.

        Returns:
            dict[str, Any]: The JSON body to POST.
        """
        self.rehydrate_tool_names(request)
        capabilities = request.capabilities
        body: dict[str, Any] = {
            "contents": self.build_contents(request.messages, capabilities, name_style=request.tool_name_style),
        }
        if instruction := self.system_instruction(request):
            body["systemInstruction"] = {"parts": [{"text": instruction}]}

        generation_config: dict[str, Any] = {"maxOutputTokens": request.max_tokens}
        if capabilities.supports_temperature:
            generation_config["temperature"] = request.temperature
        thinking = request.thinking
        if thinking is not None and thinking.enabled and capabilities.reasoning.supported:
            generation_config["thinkingConfig"] = {
                "thinkingBudget": thinking.budget_tokens,
                "includeThoughts": True,
            }
        body["generationConfig"] = generation_config

        if tools := self.build_tool_schemas(request.tools, capabilities, name_style=request.tool_name_style):
            body["tools"] = tools
            if request.tool_choice is not None:
                body["toolConfig"] = self.tool_config(request.tool_choice, name_style=request.tool_name_style)

        return self.apply_body_overrides(body, request)

    @staticmethod
    def tool_config(
        tool_choice: ToolChoice,
        *,
        name_style: ToolNameStyle = ToolNameStyle.DOUBLE_UNDERSCORE,
    ) -> dict[str, Any]:
        """Convert a tool choice to Gemini's ``toolConfig``.

        Args:
            tool_choice: The tool choice configuration.
            name_style: How canonical dotted names are written onto the wire.

        Returns:
            dict[str, Any]: The ``toolConfig`` object. A
            :data:`ToolChoiceMode.SPECIFIC` choice with no function name
            degrades to ``ANY``, which asks for a tool without naming an
            empty one.
        """
        if tool_choice.mode == ToolChoiceMode.NONE:
            return {"functionCallingConfig": {"mode": "NONE"}}
        if tool_choice.mode == ToolChoiceMode.REQUIRED:
            return {"functionCallingConfig": {"mode": "ANY"}}
        if tool_choice.mode == ToolChoiceMode.SPECIFIC and tool_choice.function_name:
            return {
                "functionCallingConfig": {
                    "mode": "ANY",
                    "allowedFunctionNames": [wire_function_name(tool_choice.function_name, name_style)],
                },
            }
        return {"functionCallingConfig": {"mode": "AUTO"}}

    @override
    def parse_response(
        self,
        payload: Mapping[str, Any],
        *,
        capabilities: ModelCapabilities | None = None,
    ) -> DialectResponse:
        """Parse a Gemini ``generateContent`` response body.

        Args:
            payload: The decoded response body.
            capabilities: Unused; Gemini's response shape does not vary by
                model.

        Returns:
            DialectResponse: The normalized response.
        """
        del capabilities
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        reasoning: list[ReasoningItem] = []

        for part in _iter_candidate_parts(payload):
            if part.get("thought") is True:
                text = part.get("text")
                if isinstance(text, str) and text:
                    reasoning.append(ReasoningItem(kind=ReasoningKind.THINKING, text=text))
                continue
            text = part.get("text")
            if isinstance(text, str) and text:
                text_parts.append(text)
            call = _parse_function_call_part(part)
            if call is not None:
                tool_calls.append(call)

        return DialectResponse(
            content="".join(text_parts),
            tool_calls=tuple(tool_calls),
            reasoning=tuple(reasoning),
            usage=parse_usage(payload.get("usageMetadata")),
            finish_reason=_finish_reason(payload),
        )

    @override
    def parse_stream_event(
        self,
        event: Mapping[str, Any],
        *,
        capabilities: ModelCapabilities | None = None,
    ) -> list[StreamDelta]:
        """Translate one streamed Gemini chunk into normalized deltas.

        Gemini streams whole parts rather than fragments, so a function call
        arrives complete and its fragment carries the full argument JSON in
        one piece.

        Args:
            event: One decoded chunk.
            capabilities: Unused; Gemini's stream shape does not vary by
                model.

        Returns:
            list[StreamDelta]: Zero or more deltas, in wire order.
        """
        del capabilities
        deltas: list[StreamDelta] = []
        for position, part in enumerate(_iter_candidate_parts(event)):
            if part.get("thought") is True:
                text = part.get("text")
                if isinstance(text, str) and text:
                    deltas.append(StreamDelta(reasoning=text))
                continue
            text = part.get("text")
            if isinstance(text, str) and text:
                deltas.append(StreamDelta(text=text))
            raw_call = part.get("functionCall") or part.get("function_call")
            if is_json_object(raw_call):
                call: dict[str, Any] = raw_call
                name = call.get("name")
                args = call.get("args")
                deltas.append(
                    StreamDelta(
                        tool_call_fragment=ToolCallFragment(
                            token=f"{name}:{position}",
                            call_id=f"{name}:{position}",
                            name=name if isinstance(name, str) else None,
                            arguments=json.dumps(args) if is_json_object(args) else "{}",
                        ),
                    ),
                )
        usage = parse_usage(event.get("usageMetadata"))
        if usage is not None:
            deltas.append(StreamDelta(usage=usage))
        finish = _finish_reason(event)
        if finish is not None:
            deltas.append(StreamDelta(finish=finish))
        return deltas

    @override
    def render_tool_result(
        self,
        result: ToolResult,
        capabilities: ModelCapabilities,
        *,
        function_name: str | None = None,
    ) -> list[dict[str, Any]]:
        """Render a tool result as a Gemini ``functionResponse`` part.

        ``functionResponse.response`` takes structured JSON natively, so a
        structured part is passed through rather than serialized to text. A
        result that mixes structured output with text or resource parts keeps
        both: the structured fields at the top level and the rest rendered
        into a reserved key, because discarding them would hand the model a
        JSON object and silently drop everything the tool said in prose.
        Images ride as ``inlineData`` parts in the same user content when the
        model reports vision, and degrade to the shared deterministic text
        description when it does not.

        Args:
            result: The tool result to render.
            capabilities: The resolved capability record for the target model.
            function_name: Wire name of the function this result answers.
                Gemini rejects a ``functionResponse`` whose name does not
                match the ``functionCall`` it answers, so the caller supplies
                the name it sent.

        Returns:
            list[dict[str, Any]]: The response part, followed by any image
            parts.
        """
        if structured := structured_parts(result):
            response: dict[str, Any] = {}
            for part in structured:
                response |= part.content
            if narrative := render_parts_as_text([part for part in result.content or () if part not in structured]):
                response[_NARRATIVE_KEY] = narrative
        elif result.content:
            response = {"result": tool_result_text(result)}
        else:
            response = {"result": result.result}
        if result.is_error or not result.success:
            response["error"] = result.error or "tool reported an error"

        parts: list[dict[str, Any]] = [
            {
                "function_response": {
                    "name": function_name or result.call_id,
                    "response": response,
                },
            },
        ]
        images = image_parts(result)
        if images and capabilities.supports_vision:
            parts.extend({"inline_data": {"mime_type": part.mime_type, "data": part.data}} for part in images)
        return parts

    @override
    def render_reasoning(self, reasoning: Sequence[ReasoningItem]) -> list[dict[str, Any]]:
        """Render captured reasoning as Gemini thought parts.

        Gemini carries reasoning as a text part flagged ``thought``; it has no
        opaque replay payload of its own, so only items with readable text are
        replayed.

        Args:
            reasoning: Reasoning blocks captured from an earlier turn.

        Returns:
            list[dict[str, Any]]: Thought parts, in order.
        """
        return [{"text": item.text, "thought": True} for item in reasoning if item.text]

    @override
    def auth_headers(self, api_key: str | None) -> dict[str, str]:
        """Build the Gemini API-key header.

        Args:
            api_key: The instance's API key, or ``None``.

        Returns:
            dict[str, str]: ``x-goog-api-key``, or empty.
        """
        return {GEMINI_API_KEY_HEADER: api_key} if api_key else {}

    @override
    def endpoint_path(self, *, model: str, stream: bool) -> str:
        """Return the model-scoped generate path.

        Args:
            model: The target model id, which Gemini encodes into the path.
            stream: Whether the request streams, which selects
                ``streamGenerateContent``.

        Returns:
            str: ``"v1beta/models/<model>:generateContent"`` or its streaming
            counterpart.
        """
        method = "streamGenerateContent" if stream else "generateContent"
        return f"v1beta/models/{model}:{method}"

    @override
    def token_limit_field(self, capabilities: ModelCapabilities) -> str:
        """Return the output-limit field Gemini expects.

        Args:
            capabilities: Unused; Gemini always uses the same field.

        Returns:
            str: ``"maxOutputTokens"``.
        """
        del capabilities
        return "maxOutputTokens"


def _iter_candidate_parts(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Collect every content part of a response's first candidate.

    Args:
        payload: The decoded response body or chunk.

    Returns:
        list[dict[str, Any]]: Parts in wire order, or an empty list.
    """
    raw_candidates = payload.get("candidates")
    if not is_json_array(raw_candidates) or not raw_candidates:
        return []
    candidates: list[Any] = raw_candidates
    first = candidates[0]
    if not is_json_object(first):
        return []
    candidate: dict[str, Any] = first
    raw_content = candidate.get("content")
    if not is_json_object(raw_content):
        return []
    content: dict[str, Any] = raw_content
    raw_parts = content.get("parts")
    if not is_json_array(raw_parts):
        return []
    parts: list[Any] = raw_parts
    return [part for part in parts if is_json_object(part)]


def _finish_reason(payload: Mapping[str, Any]) -> str | None:
    """Read the finish reason of a response's first candidate.

    Args:
        payload: The decoded response body or chunk.

    Returns:
        str | None: The finish reason, or ``None`` when absent.
    """
    raw_candidates = payload.get("candidates")
    if not is_json_array(raw_candidates) or not raw_candidates:
        return None
    candidates: list[Any] = raw_candidates
    first = candidates[0]
    if not is_json_object(first):
        return None
    candidate: dict[str, Any] = first
    reason = candidate.get("finishReason")
    return reason if isinstance(reason, str) else None


def _parse_function_call_part(part: Mapping[str, Any]) -> ToolCall | None:
    """Parse one Gemini function-call part, keeping its thought signature.

    Args:
        part: The content part.

    Returns:
        ToolCall | None: The parsed call, or ``None`` when the part carries
        no function call.
    """
    raw_call = part.get("functionCall") or part.get("function_call")
    if not is_json_object(raw_call):
        return None
    call: dict[str, Any] = raw_call
    name = call.get("name")
    if not isinstance(name, str):
        return None
    raw_args = call.get("args")
    arguments: str | dict[str, object] = dict(raw_args) if is_json_object(raw_args) else "{}"
    parsed = parse_tool_call(call_id=str(call.get("id", name)), function_name=name, raw_arguments=arguments)
    signature = part.get("thoughtSignature") or part.get(_THOUGHT_SIGNATURE_KEY)
    if isinstance(signature, bytes):
        parsed.thought_signature = base64.b64encode(signature).decode("ascii")
    elif isinstance(signature, str) and signature:
        parsed.thought_signature = signature
    return parsed


def parse_usage(raw: object) -> UsageInfo | None:
    """Parse a Gemini ``usageMetadata`` object.

    Args:
        raw: The raw ``usageMetadata`` value.

    Returns:
        UsageInfo | None: Populated usage, or ``None`` when absent.
    """
    if not is_json_object(raw):
        return None
    usage: dict[str, Any] = raw
    prompt = _as_int(usage.get("promptTokenCount"))
    completion = _as_int(usage.get("candidatesTokenCount"))
    total = _as_int(usage.get("totalTokenCount")) or (prompt + completion)
    return UsageInfo(
        prompt_tokens=prompt,
        completion_tokens=completion,
        total_tokens=total,
        cache_read_tokens=_as_int(usage.get("cachedContentTokenCount")),
        reasoning_tokens=_as_int(usage.get("thoughtsTokenCount")),
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
