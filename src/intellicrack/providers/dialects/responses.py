# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""The OpenAI Responses dialect.

Responses is the API OpenAI recommends for new projects and the only one that carries reasoning items, which current reasoning models
require to be replayed on every turn that also carries a function call. From GPT-5.4 Chat Completions additionally refuses tool calling with
any ``reasoning_effort`` other than ``none``, so reasoning plus tool calling is only fully available here.

Two properties shape everything below. Function definitions are internally tagged and flat -- ``{"type": "function", "name": ...,
"parameters": ...}`` rather than Chat Completions' nested ``function`` object -- and every item in a turn correlates by ``call_id`` rather
than by position.

The default posture is ``store: false`` with ``include: ["reasoning.encrypted_content"]``: multi-turn reasoning keeps working, and OpenAI
retains none of the binary-analysis context that passes through it.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, ClassVar, Final, override

from intellicrack.bridges.json_schema import function_parameters, to_strict_subset
from intellicrack.core.json_payload import is_json_array, is_json_object
from intellicrack.core.logging import get_logger
from intellicrack.core.types import (
    ReasoningItem,
    ReasoningKind,
    ToolCall,
    ToolChoiceMode,
)
from intellicrack.providers.capabilities import (
    EXTENDED_EFFORT_LEVELS,
    TIKTOKEN_O200K,
    ApiDialect,
    ModelCapabilities,
    ReasoningEffortFormat,
    ReasoningSupport,
    TokenLimitField,
    ToolSearchStyle,
    ToolSearchSupport,
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
from intellicrack.providers.tool_names import from_wire_name, from_wire_pair, to_wire_pair


if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from intellicrack.core.types import Message, ToolChoice, ToolDefinition, ToolFunction, ToolResult


_logger = get_logger(__name__)

ENCRYPTED_REASONING_INCLUDE: Final[str] = "reasoning.encrypted_content"
"""``include`` entry that keeps reasoning usable while ``store`` is ``False``."""

TOOL_SEARCH_TYPE: Final[str] = "tool_search"
"""Tool entry that turns on OpenAI's native tool search (``gpt-5.4`` and later)."""

NAMESPACE_TYPE: Final[str] = "namespace"
"""Tool entry that groups functions under one namespace."""

_EFFORT_LOW_THRESHOLD: Final[int] = 4000
_EFFORT_MEDIUM_THRESHOLD: Final[int] = 16000

_TOOL_SEARCH_ITEM_TYPES: Final[frozenset[str]] = frozenset({"tool_search_call", "tool_search_output"})
"""Output items a tool search produces.

A search result is not a tool call: it makes a deferred tool callable, and returning a ``function_call_output`` for one is a protocol error.
"""

_TOOL_SEARCH_EVENT_TYPES: Final[frozenset[str]] = frozenset({
    "response.tool_search_call.in_progress",
    "response.tool_search_call.completed",
    "response.tool_search_output.added",
})
"""Streaming events a tool search emits."""

_OPENAI_TOOL_COUNT_CAP: Final[int] = 128
"""Functions callable at the start of a turn, before tool search is enabled."""


class ResponsesAdapter(DialectAdapter):
    """Adapter for the OpenAI ``/responses`` wire format.

    Attributes:
        dialect: Always :data:`ApiDialect.RESPONSES`.
    """

    dialect: ClassVar[ApiDialect] = ApiDialect.RESPONSES

    @override
    def default_capabilities(self) -> ModelCapabilities:
        """Return the baseline record for a Responses model.

        Returns:
            ModelCapabilities: Reasoning on with the full effort ladder and
            encrypted reasoning content, output limit in
            ``max_output_tokens``, o200k token estimation.
        """
        return ModelCapabilities(
            dialect=ApiDialect.RESPONSES,
            supports_tools=True,
            supports_streaming=True,
            supports_structured_outputs=True,
            supports_prompt_cache=True,
            supports_prompt_cache_key=True,
            supports_temperature=False,
            token_limit_field=TokenLimitField.MAX_OUTPUT_TOKENS,
            tokenizer=TIKTOKEN_O200K,
            tool_count_cap=_OPENAI_TOOL_COUNT_CAP,
            reasoning=ReasoningSupport(
                supported=True,
                effort_levels=EXTENDED_EFFORT_LEVELS,
                effort_format=ReasoningEffortFormat.NESTED_EFFORT,
                encrypted_content=True,
            ),
        )

    @staticmethod
    def tool_search_capabilities() -> ToolSearchSupport:
        """Build the tool-search record a ``gpt-5.4``-class model has.

        Returns:
            ToolSearchSupport: OpenAI tool search with namespace grouping.
        """
        return ToolSearchSupport(style=ToolSearchStyle.OPENAI_TOOL_SEARCH)

    @override
    def build_tool_schemas(
        self,
        tools: Sequence[ToolDefinition],
        capabilities: ModelCapabilities,
        *,
        name_style: ToolNameStyle = ToolNameStyle.DOUBLE_UNDERSCORE,
    ) -> list[dict[str, Any]]:
        """Describe every tool function as a flat Responses function entry.

        When the model supports OpenAI tool search, functions are grouped into
        ``namespace`` entries built through
        :func:`~intellicrack.providers.tool_names.to_wire_pair` and every
        namespace past the first is deferred, so a large toolset ships without
        putting hundreds of functions in reach at the start of a turn. The
        first namespace stays non-deferred so the model always has something
        callable before it searches.

        Args:
            tools: Tool definitions in final priority order. Input order is
                wire order; nothing here reorders them.
            capabilities: The resolved capability record for the target model.
            name_style: How canonical dotted names are written onto the wire.

        Returns:
            list[dict[str, Any]]: Tool entries ready to place in a request.
        """
        if not capabilities.supports_tools:
            _logger.debug("responses_tools_suppressed_unsupported")
            return []
        if capabilities.tool_search.style is ToolSearchStyle.OPENAI_TOOL_SEARCH:
            return self._build_namespaced_tools(tools, capabilities)
        entries: list[dict[str, Any]] = []
        for tool in tools:
            entries.extend(self._function_entry(func.name, func.description, func, name_style=name_style) for func in tool.functions)
        return entries

    def _build_namespaced_tools(
        self,
        tools: Sequence[ToolDefinition],
        capabilities: ModelCapabilities,
    ) -> list[dict[str, Any]]:
        """Group functions into ``namespace`` entries alongside a tool search.

        Args:
            tools: Tool definitions in final priority order.
            capabilities: The resolved capability record for the target model.

        Returns:
            list[dict[str, Any]]: The tool-search entry followed by one
            namespace entry per tool definition, in input order.
        """
        entries: list[dict[str, Any]] = [{"type": TOOL_SEARCH_TYPE}]
        for position, tool in enumerate(tools):
            members: list[dict[str, Any]] = []
            namespace_name = tool.tool_name
            for func in tool.functions:
                namespace, wire_name = to_wire_pair(func.name)
                if namespace:
                    namespace_name = namespace
                member = self._function_entry(wire_name, func.description, func, name_style=ToolNameStyle.DOTTED)
                if position > 0:
                    member["defer_loading"] = True
                members.append(member)
            if not members:
                continue
            entries.append({
                "type": NAMESPACE_TYPE,
                "name": namespace_name,
                "description": tool.description,
                "tools": members,
            })
        _logger.debug(
            "responses_namespaces_built",
            namespace_count=len(entries) - 1,
            deferred_namespaces=max(len(entries) - 2, 0),
            max_deferred=capabilities.tool_search.max_deferred_tools,
        )
        return entries

    @staticmethod
    def _function_entry(
        wire_name: str,
        description: str,
        func: ToolFunction,
        *,
        name_style: ToolNameStyle,
    ) -> dict[str, Any]:
        """Build one flat Responses function entry.

        Strict mode is claimed only when the schema survives reduction
        faithfully; a schema that uses composition strict mode cannot express
        ships with ``strict: false`` rather than a guarantee it does not carry.

        Args:
            wire_name: The function name to send, already in wire form when
                ``name_style`` is :data:`ToolNameStyle.DOTTED`.
            description: The function description.
            func: The tool function whose argument schema is built.
            name_style: How canonical dotted names are written onto the wire.

        Returns:
            dict[str, Any]: The function entry.
        """
        raw = function_parameters(func)
        parameters, strict = to_strict_subset(raw)
        name = wire_name if name_style is ToolNameStyle.DOTTED else wire_function_name(wire_name, name_style)
        return {
            "type": "function",
            "name": name,
            "description": description,
            "parameters": parameters,
            "strict": strict,
        }

    def build_input(
        self,
        messages: Sequence[Message],
        capabilities: ModelCapabilities,
        *,
        name_style: ToolNameStyle = ToolNameStyle.DOUBLE_UNDERSCORE,
    ) -> list[dict[str, Any]]:
        """Convert Intellicrack messages to the Responses ``input`` array.

        Reasoning items are replayed before the function calls they preceded,
        which is the order OpenAI requires on a turn that carries both.

        Args:
            messages: Conversation history.
            capabilities: The resolved capability record for the target model.
            name_style: How canonical dotted names are written onto the wire.

        Returns:
            list[dict[str, Any]]: Input items ready to send.
        """
        items: list[dict[str, Any]] = []
        for msg in messages:
            if msg.role == "system":
                continue
            if msg.role == "user":
                items.append({"role": "user", "content": [{"type": "input_text", "text": msg.content}]})
            elif msg.role == "assistant":
                items.extend(self._assistant_items(msg, name_style=name_style))
            elif msg.role == "tool" and msg.tool_results:
                for result in msg.tool_results:
                    items.extend(self.render_tool_result(result, capabilities))
        return items

    def _assistant_items(self, msg: Message, *, name_style: ToolNameStyle) -> list[dict[str, Any]]:
        """Build the input items for one assistant turn.

        Args:
            msg: The assistant message.
            name_style: How canonical dotted names are written onto the wire.

        Returns:
            list[dict[str, Any]]: Reasoning items, then text, then function
            calls -- the order OpenAI expects on replay.
        """
        items: list[dict[str, Any]] = []
        if msg.reasoning:
            items.extend(self.render_reasoning(msg.reasoning))
        if msg.content:
            items.append({"role": "assistant", "content": [{"type": "output_text", "text": msg.content}]})
        if msg.tool_calls:
            items.extend(
                {
                    "type": "function_call",
                    "call_id": tc.id,
                    "name": _call_wire_name(tc, name_style),
                    "arguments": _encode_arguments(tc),
                }
                for tc in msg.tool_calls
            )
        return items

    @override
    def build_request(self, request: DialectRequest) -> dict[str, Any]:
        """Shape a normalized request into a Responses body.

        Args:
            request: The normalized request.

        Returns:
            dict[str, Any]: The JSON body to POST.
        """
        self.rehydrate_tool_names(request)
        capabilities = request.capabilities
        body: dict[str, Any] = {
            "model": request.model,
            "input": self.build_input(request.messages, capabilities, name_style=request.tool_name_style),
        }
        instructions = self.system_instruction(request)
        if instructions:
            body["instructions"] = instructions
        body[self.token_limit_field(capabilities)] = request.max_tokens
        if capabilities.supports_temperature:
            body["temperature"] = request.temperature

        tools = self.build_tool_schemas(request.tools, capabilities, name_style=request.tool_name_style)
        if tools:
            body["tools"] = tools
            if request.tool_choice is not None:
                body["tool_choice"] = self.tool_choice_param(request.tool_choice, name_style=request.tool_name_style)
            body["parallel_tool_calls"] = capabilities.supports_parallel_tool_calls

        reasoning = self.reasoning_param(request)
        if reasoning is not None:
            body["reasoning"] = reasoning

        store = request.store if request.store is not None else False
        body["store"] = store
        if not store and capabilities.reasoning.encrypted_content:
            body["include"] = [ENCRYPTED_REASONING_INCLUDE]

        if request.stream:
            body["stream"] = True

        if request.enable_cache and capabilities.supports_prompt_cache_key:
            body["prompt_cache_key"] = request.model

        return self.apply_body_overrides(body, request)

    @staticmethod
    def reasoning_param(request: DialectRequest) -> dict[str, Any] | None:
        """Resolve the nested ``reasoning`` object for a request.

        Args:
            request: The normalized request.

        Returns:
            dict[str, Any] | None: The ``reasoning`` object, or ``None`` when
            the model does not reason or thinking is off.
        """
        reasoning = request.capabilities.reasoning
        if not reasoning.supported or reasoning.effort_format is not ReasoningEffortFormat.NESTED_EFFORT:
            return None
        thinking = request.thinking
        if thinking is None or not thinking.enabled:
            return None
        effort = _effort_for_budget(thinking.budget_tokens, reasoning.effort_levels)
        return {"effort": effort} if effort is not None else None

    @staticmethod
    def tool_choice_param(
        tool_choice: ToolChoice,
        *,
        name_style: ToolNameStyle = ToolNameStyle.DOUBLE_UNDERSCORE,
    ) -> str | dict[str, Any]:
        """Convert a tool choice to the Responses ``tool_choice`` parameter.

        Args:
            tool_choice: The tool choice configuration.
            name_style: How canonical dotted names are written onto the wire.

        Returns:
            str | dict[str, Any]: The value for the ``tool_choice`` key. A
            :data:`ToolChoiceMode.SPECIFIC` choice with no function name
            degrades to ``"required"``.
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
        return {"type": "function", "name": wire_function_name(function_name, name_style)}

    @override
    def parse_response(self, payload: Mapping[str, Any]) -> DialectResponse:
        """Parse a Responses response body.

        Args:
            payload: The decoded response body.

        Returns:
            DialectResponse: The normalized response.
        """
        raw_output = payload.get("output")
        output: list[Any] = raw_output if is_json_array(raw_output) else []
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        reasoning: list[ReasoningItem] = []
        loaded: list[str] = []

        for entry in output:
            if not is_json_object(entry):
                continue
            item: dict[str, Any] = entry
            item_type = item.get("type")
            if item_type == "message":
                text_parts.extend(_message_text(item))
            elif item_type == "function_call":
                call = _parse_function_call(item)
                if call is not None:
                    tool_calls.append(call)
            elif item_type == "reasoning":
                reasoning.append(_parse_reasoning_item(item))
            elif item_type in _TOOL_SEARCH_ITEM_TYPES:
                loaded.extend(canonical_names_in_tool_search_output(item))

        if loaded:
            _logger.info("responses_tool_search_loaded", tools=loaded)
        status = payload.get("status")
        return DialectResponse(
            content="".join(text_parts),
            tool_calls=tuple(tool_calls),
            reasoning=tuple(reasoning),
            usage=parse_usage(payload.get("usage")),
            finish_reason=status if isinstance(status, str) else None,
        )

    @override
    def parse_stream_event(self, event: Mapping[str, Any]) -> list[StreamDelta]:
        """Translate one Responses semantic event into normalized deltas.

        Args:
            event: One decoded event.

        Returns:
            list[StreamDelta]: Zero or more deltas, in wire order.
        """
        event_type = event.get("type")
        if not isinstance(event_type, str):
            return []
        if event_type == "response.output_text.delta":
            delta = event.get("delta")
            return [StreamDelta(text=delta)] if isinstance(delta, str) and delta else []
        if event_type == "response.reasoning_summary_text.delta":
            delta = event.get("delta")
            return [StreamDelta(reasoning=delta)] if isinstance(delta, str) and delta else []
        if event_type == "response.output_item.added":
            return _added_item_deltas(event)
        if event_type == "response.output_item.done":
            return _completed_item_deltas(event)
        if event_type in _TOOL_SEARCH_EVENT_TYPES:
            _log_tool_search_event(event)
            return []
        if event_type == "response.function_call_arguments.delta":
            return _argument_delta(event)
        if event_type == "response.completed":
            return _completed_deltas(event)
        if event_type == "error":
            message = event.get("message")
            _logger.warning("responses_stream_error", message=message if isinstance(message, str) else "")
            return [StreamDelta(finish="error")]
        return []

    @override
    def render_tool_result(
        self,
        result: ToolResult,
        capabilities: ModelCapabilities,
        *,
        function_name: str | None = None,
    ) -> list[dict[str, Any]]:
        """Render a tool result as a ``function_call_output`` item.

        Images ride in a following user message as ``input_image`` items when
        the model reports vision, and degrade to the shared deterministic text
        description when it does not.

        Args:
            result: The tool result to render.
            capabilities: The resolved capability record for the target model.
            function_name: Unused; Responses correlates by ``call_id``.

        Returns:
            list[dict[str, Any]]: The output item, optionally followed by a
            user message carrying the images.
        """
        del function_name
        text = tool_result_text(result)
        if result.is_error and result.success:
            text = f"[tool reported an error]\n{text}"
        items: list[dict[str, Any]] = [
            {
                "type": "function_call_output",
                "call_id": result.call_id,
                "output": text,
            },
        ]
        images = image_parts(result)
        if images and capabilities.supports_vision:
            items.append({
                "role": "user",
                "content": [
                    {
                        "type": "input_image",
                        "image_url": f"data:{part.mime_type};base64,{part.data}",
                    }
                    for part in images
                ],
            })
        return items

    @override
    def render_reasoning(self, reasoning: Sequence[ReasoningItem]) -> list[dict[str, Any]]:
        """Replay captured reasoning items verbatim.

        Only items that carry a Responses identity are replayed: an item
        captured from another dialect has no ``id`` OpenAI would recognise,
        and inventing one corrupts the chain rather than extending it.

        Args:
            reasoning: Reasoning blocks captured from an earlier turn.

        Returns:
            list[dict[str, Any]]: Responses reasoning items, in order.
        """
        items: list[dict[str, Any]] = []
        for entry in reasoning:
            if entry.kind is not ReasoningKind.RESPONSES_ITEM or entry.item_id is None:
                continue
            item: dict[str, Any] = {"type": "reasoning", "id": entry.item_id}
            if entry.summary:
                item["summary"] = [{"type": "summary_text", "text": text} for text in entry.summary]
            if entry.encrypted_content is not None:
                item["encrypted_content"] = entry.encrypted_content
            items.append(item)
        return items

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
        """Return the Responses path.

        Args:
            model: Unused; the model travels in the body.
            stream: Unused; streaming is a body flag.

        Returns:
            str: ``"responses"``.
        """
        del model, stream
        return "responses"

    @override
    def token_limit_field(self, capabilities: ModelCapabilities) -> str:
        """Return the output-limit field Responses expects.

        Args:
            capabilities: Unused; Responses always uses the same field.

        Returns:
            str: ``"max_output_tokens"``.
        """
        del capabilities
        return TokenLimitField.MAX_OUTPUT_TOKENS.value


def _call_wire_name(call: ToolCall, name_style: ToolNameStyle) -> str:
    """Write a replayed tool call's function name onto the wire.

    Args:
        call: The tool call being replayed.
        name_style: How canonical dotted names are written onto the wire.

    Returns:
        str: The function name to send.
    """
    return wire_function_name(call.function_name, name_style)


def _encode_arguments(call: ToolCall) -> str:
    """Encode a replayed tool call's arguments as the JSON string Responses takes.

    Args:
        call: The tool call being replayed.

    Returns:
        str: The JSON-encoded arguments.
    """
    return json.dumps(call.arguments)


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


def _message_text(item: Mapping[str, Any]) -> list[str]:
    """Collect the output text of one Responses message item.

    Args:
        item: The message item.

    Returns:
        list[str]: Every ``output_text`` chunk, in order.
    """
    raw_content = item.get("content")
    if not is_json_array(raw_content):
        return []
    content: list[Any] = raw_content
    texts: list[str] = []
    for entry in content:
        if not is_json_object(entry):
            continue
        part: dict[str, Any] = entry
        if part.get("type") == "output_text":
            text = part.get("text")
            if isinstance(text, str):
                texts.append(text)
    return texts


def _parse_function_call(item: Mapping[str, Any]) -> ToolCall | None:
    """Parse one Responses ``function_call`` item.

    Args:
        item: The function-call item.

    Returns:
        ToolCall | None: The parsed call, or ``None`` when the item names no
        function.
    """
    name = item.get("name")
    if not isinstance(name, str):
        return None
    arguments = item.get("arguments")
    call_id = item.get("call_id")
    return parse_tool_call(
        call_id=str(call_id) if isinstance(call_id, str) else "",
        function_name=name,
        raw_arguments=arguments if isinstance(arguments, str) else "{}",
    )


def _parse_reasoning_item(item: Mapping[str, Any]) -> ReasoningItem:
    """Parse one Responses ``reasoning`` item, keeping its payload verbatim.

    Args:
        item: The reasoning item.

    Returns:
        ReasoningItem: The captured item.
    """
    raw_summary = item.get("summary")
    summary: tuple[str, ...] = ()
    if is_json_array(raw_summary):
        entries: list[Any] = raw_summary
        collected: list[str] = []
        for entry in entries:
            if is_json_object(entry):
                part: dict[str, Any] = entry
                text = part.get("text")
                if isinstance(text, str):
                    collected.append(text)
            elif isinstance(entry, str):
                collected.append(entry)
        summary = tuple(collected)
    item_id = item.get("id")
    encrypted = item.get("encrypted_content")
    return ReasoningItem(
        kind=ReasoningKind.RESPONSES_ITEM,
        text="\n\n".join(summary),
        item_id=item_id if isinstance(item_id, str) else None,
        encrypted_content=encrypted if isinstance(encrypted, str) else None,
        summary=summary,
    )


def _added_item_deltas(event: Mapping[str, Any]) -> list[StreamDelta]:
    """Translate ``response.output_item.added`` into a tool-call fragment.

    The added event is where a function call's ``call_id`` and name first
    appear; the argument text follows as separate delta events keyed by the
    same item id.

    Args:
        event: The decoded event.

    Returns:
        list[StreamDelta]: One fragment delta, or an empty list.
    """
    raw_item = event.get("item")
    if not is_json_object(raw_item):
        return []
    item: dict[str, Any] = raw_item
    if item.get("type") != "function_call":
        return []
    name = item.get("name")
    call_id = item.get("call_id")
    item_id = item.get("id")
    token = str(item_id) if isinstance(item_id, str) else str(call_id)
    return [
        StreamDelta(
            tool_call_fragment=ToolCallFragment(
                token=token,
                call_id=call_id if isinstance(call_id, str) else None,
                name=name if isinstance(name, str) else None,
            ),
        ),
    ]


def _completed_item_deltas(event: Mapping[str, Any]) -> list[StreamDelta]:
    """Translate ``response.output_item.done`` into a completed reasoning item.

    Args:
        event: The decoded event.

    Returns:
        list[StreamDelta]: One reasoning-item delta, or an empty list.
    """
    raw_item = event.get("item")
    if not is_json_object(raw_item):
        return []
    item: dict[str, Any] = raw_item
    if item.get("type") != "reasoning":
        return []
    return [StreamDelta(reasoning_item=_parse_reasoning_item(item))]


def _argument_delta(event: Mapping[str, Any]) -> list[StreamDelta]:
    """Translate ``response.function_call_arguments.delta`` into a fragment.

    Args:
        event: The decoded event.

    Returns:
        list[StreamDelta]: One fragment delta, or an empty list.
    """
    delta = event.get("delta")
    item_id = event.get("item_id")
    if not isinstance(delta, str) or not delta:
        return []
    return [
        StreamDelta(
            tool_call_fragment=ToolCallFragment(
                token=str(item_id) if isinstance(item_id, str) else "",
                arguments=delta,
            ),
        ),
    ]


def _completed_deltas(event: Mapping[str, Any]) -> list[StreamDelta]:
    """Translate ``response.completed`` into usage and finish deltas.

    Args:
        event: The decoded event.

    Returns:
        list[StreamDelta]: A usage delta when usage is present, then a finish
        delta.
    """
    raw_response = event.get("response")
    response: dict[str, Any] = raw_response if is_json_object(raw_response) else {}
    deltas: list[StreamDelta] = []
    usage = parse_usage(response.get("usage"))
    if usage is not None:
        deltas.append(StreamDelta(usage=usage))
    status = response.get("status")
    deltas.append(StreamDelta(finish=status if isinstance(status, str) else "completed"))
    return deltas


def parse_usage(raw: object) -> UsageInfo | None:
    """Parse a Responses ``usage`` object.

    Args:
        raw: The raw ``usage`` value.

    Returns:
        UsageInfo | None: Populated usage, or ``None`` when absent.
    """
    if not is_json_object(raw):
        return None
    usage: dict[str, Any] = raw
    prompt = _as_int(usage.get("input_tokens"))
    completion = _as_int(usage.get("output_tokens"))
    total = _as_int(usage.get("total_tokens")) or (prompt + completion)
    input_details = usage.get("input_tokens_details")
    cached = _as_int(input_details.get("cached_tokens")) if is_json_object(input_details) else 0
    output_details = usage.get("output_tokens_details")
    reasoning = _as_int(output_details.get("reasoning_tokens")) if is_json_object(output_details) else 0
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


def canonical_names_in_tool_search_output(item: Mapping[str, Any]) -> list[str]:
    """Resolve the canonical names a tool-search result made callable.

    A search result names tools by their wire identity, which under
    namespaces is the ``(namespace, name)`` pair. Reversing it through
    :func:`~intellicrack.providers.tool_names.from_wire_pair` is what lets a
    subsequent call on a tool that was never in the active set still route to
    its canonical dotted name.

    Args:
        item: The ``tool_search_call`` or ``tool_search_output`` item.

    Returns:
        list[str]: Canonical dotted names, in result order.
    """
    raw_results = item.get("results") or item.get("tools")
    if not is_json_array(raw_results):
        return []
    results: list[Any] = raw_results
    names: list[str] = []
    for entry in results:
        if isinstance(entry, str):
            names.append(canonical_from_tool_search_output("", entry))
            continue
        if not is_json_object(entry):
            continue
        result: dict[str, Any] = entry
        name = result.get("name")
        if not isinstance(name, str):
            continue
        namespace = result.get("namespace")
        names.append(canonical_from_tool_search_output(namespace if isinstance(namespace, str) else "", name))
    return names


def _log_tool_search_event(event: Mapping[str, Any]) -> None:
    """Record which tools a streamed tool search made callable.

    Args:
        event: The decoded tool-search event.
    """
    raw_item = event.get("item")
    item: dict[str, Any] = raw_item if is_json_object(raw_item) else {}
    names = canonical_names_in_tool_search_output(item)
    if names:
        _logger.info("responses_tool_search_loaded", tools=names)


def canonical_from_tool_search_output(namespace: str, name: str) -> str:
    """Resolve a tool-search result back to its canonical dotted name.

    Args:
        namespace: The namespace the search result named, or the empty string.
        name: The function name the search result named.

    Returns:
        str: The canonical dotted tool-function name.
    """
    return from_wire_pair(namespace, name) if namespace else from_wire_name(name)
