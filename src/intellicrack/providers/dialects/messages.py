# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""The Anthropic Messages dialect.

Messages is the richest of the four wire formats for this workload: tool results carry text and images natively along with an explicit
``is_error`` flag, prompt caching is explicit and placed by the caller, and extended thinking is a first-class content block.

Two of its properties drive the code below. Thinking blocks are *signed*, and Anthropic rejects a replayed block whose signature is missing
or altered, so the signature is captured and echoed verbatim rather than reconstructed from the display text. And tool search lets all ~715
of Intellicrack's tool functions ship at once: every definition is still sent on every request, but all but one are marked ``defer_loading``
so only the non-deferred head is in reach at the start of a turn. At least one tool must stay non-deferred, which is enforced here rather
than left to a 400 from the endpoint.

Sampling parameters are deliberately absent: the anthropic 1.x SDK removed ``temperature``/``top_p``/``top_k`` from ``messages.create``, and
current Claude models reject them at the API layer.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, ClassVar, Final, override

from intellicrack.bridges.json_schema import function_parameters
from intellicrack.core.json_payload import is_json_array, is_json_object
from intellicrack.core.logging import get_logger
from intellicrack.core.types import (
    ProviderError,
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
    ToolSearchStyle,
    ToolSearchSupport,
    effort_for_thinking_budget,
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

ANTHROPIC_VERSION: Final[str] = "2023-06-01"
"""Value of the required ``anthropic-version`` request header."""

TOOL_SEARCH_REGEX_TYPE: Final[str] = "tool_search_tool_regex_20251119"
"""Server tool that searches deferred tool definitions by regular expression."""

TOOL_SEARCH_BM25_TYPE: Final[str] = "tool_search_tool_bm25_20251119"
"""Server tool that searches deferred tool definitions by BM25 relevance."""

SERVER_TOOL_USE_ID_PREFIX: Final[str] = "srvtoolu_"
"""Prefix of a server-executed tool-use id, which must never receive a ``tool_result``."""

SERVER_TOOL_USE_TYPE: Final[str] = "server_tool_use"
"""Content block recording a call to a server-executed tool, such as tool search."""

SERVER_TOOL_RESULT_SUFFIX: Final[str] = "_tool_result"
"""Suffix of every server-executed tool's result block (``tool_search_tool_result``, ``web_search_tool_result``, ...)."""

PAUSE_TURN_STOP_REASON: Final[str] = "pause_turn"
"""Stop reason Anthropic returns when a server-executed tool loop yields mid-turn."""

MAX_DEFERRED_TOOLS: Final[int] = 10000
"""Anthropic's documented ceiling on deferred tool definitions."""

THINKING_MIN_HEADROOM_TOKENS: Final[int] = 1024
"""Output tokens reserved above the thinking budget, so the answer still fits."""

_CACHE_CONTROL: Final[dict[str, str]] = {"type": "ephemeral"}

_ERR_ALL_TOOLS_DEFERRED = "Every tool was deferred; Anthropic requires at least one non-deferred tool definition"


class MessagesAdapter(DialectAdapter):
    """Adapter for the Anthropic ``/v1/messages`` wire format.

    Attributes:
        dialect: Always :data:`ApiDialect.MESSAGES`.
    """

    dialect: ClassVar[ApiDialect] = ApiDialect.MESSAGES

    def __init__(self) -> None:
        """Initialize the adapter's per-stream block and usage state."""
        self._open_blocks: dict[str, dict[str, Any]] = {}
        self._server_tool_input: dict[str, str] = {}
        self._start_usage: dict[str, Any] = {}

    @override
    def default_capabilities(self) -> ModelCapabilities:
        """Return the baseline record for an Anthropic-compatible model.

        Returns:
            ModelCapabilities: Tools, vision, streaming and prompt caching on,
            thinking expressed as a token budget, output limit in
            ``max_tokens``, cl100k token estimation as the conservative
            default for a non-OpenAI tokenizer.
        """
        return ModelCapabilities(
            dialect=ApiDialect.MESSAGES,
            supports_tools=True,
            supports_vision=True,
            supports_streaming=True,
            supports_prompt_cache=True,
            supports_temperature=False,
            token_limit_field=TokenLimitField.MAX_TOKENS,
            tokenizer=TIKTOKEN_CL100K,
            reasoning=ReasoningSupport(
                supported=True,
                effort_format=ReasoningEffortFormat.THINKING_BUDGET,
                interleaved=True,
            ),
        )

    @staticmethod
    def tool_search_capabilities() -> ToolSearchSupport:
        """Build the tool-search record an Anthropic tool-search model has.

        Returns:
            ToolSearchSupport: Deferred loading with Anthropic's documented
            ceiling and default result count.
        """
        return ToolSearchSupport(
            style=ToolSearchStyle.ANTHROPIC_DEFERRED,
            max_deferred_tools=MAX_DEFERRED_TOOLS,
        )

    @override
    def build_tool_schemas(
        self,
        tools: Sequence[ToolDefinition],
        capabilities: ModelCapabilities,
        *,
        name_style: ToolNameStyle = ToolNameStyle.DOUBLE_UNDERSCORE,
    ) -> list[dict[str, Any]]:
        """Describe every tool function as an Anthropic tool definition.

        Without tool search this is the historical shape exactly: one
        ``{"name", "description", "input_schema"}`` entry per function, in
        input order.

        With tool search the same entries are emitted, preceded by the regex
        and BM25 server tools, and every function past the first is marked
        ``defer_loading``. Every definition is still sent on every request --
        deferring changes what is in reach at the start of a turn, not what
        travels.

        Args:
            tools: Tool definitions in final priority order.
            capabilities: The resolved capability record for the target model.
            name_style: How canonical dotted names are written onto the wire.

        Returns:
            list[dict[str, Any]]: Tool definitions ready to place in a request.
        """
        if not capabilities.supports_tools:
            _logger.debug("messages_tools_suppressed_unsupported")
            return []

        definitions: list[dict[str, Any]] = []
        for tool in tools:
            definitions.extend(
                {
                    "name": wire_function_name(func.name, name_style),
                    "description": func.description,
                    "input_schema": function_parameters(func),
                }
                for func in tool.functions
            )

        if capabilities.tool_search.style is not ToolSearchStyle.ANTHROPIC_DEFERRED or not definitions:
            return definitions
        return self._apply_deferred_loading(definitions, capabilities)

    @staticmethod
    def _apply_deferred_loading(
        definitions: list[dict[str, Any]],
        capabilities: ModelCapabilities,
    ) -> list[dict[str, Any]]:
        """Prepend the search server tools and defer all but the first tool.

        Args:
            definitions: Tool definitions in input order.
            capabilities: The resolved capability record for the target model.

        Returns:
            list[dict[str, Any]]: The search tools followed by the definitions,
            with every entry past the first deferred.

        Raises:
            ProviderError: If the deferred count exceeds the endpoint's ceiling
                or deferral would leave no non-deferred tool.
        """
        deferred_count = len(definitions) - 1
        ceiling = capabilities.tool_search.max_deferred_tools or MAX_DEFERRED_TOOLS
        if deferred_count > ceiling:
            message = f"{deferred_count} tools would be deferred, above the endpoint's ceiling of {ceiling}"
            _logger.error("messages_deferred_tools_over_ceiling", deferred=deferred_count, ceiling=ceiling)
            raise ProviderError(message)

        prepared: list[dict[str, Any]] = [
            {"type": TOOL_SEARCH_REGEX_TYPE, "name": "tool_search_tool_regex"},
            {"type": TOOL_SEARCH_BM25_TYPE, "name": "tool_search_tool_bm25"},
        ]
        non_deferred = 0
        for position, definition in enumerate(definitions):
            if position == 0:
                prepared.append(definition)
                non_deferred += 1
                continue
            prepared.append({**definition, "defer_loading": True})
        if non_deferred == 0:
            _logger.error("messages_all_tools_deferred")
            raise ProviderError(_ERR_ALL_TOOLS_DEFERRED)
        _logger.debug("messages_deferred_loading_applied", total=len(definitions), deferred=deferred_count)
        return prepared

    def build_messages(
        self,
        messages: Sequence[Message],
        capabilities: ModelCapabilities,
        *,
        name_style: ToolNameStyle = ToolNameStyle.DOUBLE_UNDERSCORE,
    ) -> list[dict[str, Any]]:
        """Convert Intellicrack messages to the Anthropic message array.

        ``system``-role messages are dropped here because Anthropic carries
        the system instruction as a top-level request field instead.

        Args:
            messages: Conversation history.
            capabilities: The resolved capability record for the target model.
            name_style: How canonical dotted names are written onto the wire.

        Returns:
            list[dict[str, Any]]: Messages ready to send.
        """
        converted: list[dict[str, Any]] = []
        for msg in messages:
            if msg.role == "system":
                continue
            if msg.role == "user":
                converted.append({"role": "user", "content": msg.content})
            elif msg.role == "assistant":
                converted.append(self._assistant_message(msg, name_style=name_style))
            elif msg.role == "tool" and msg.tool_results:
                converted.extend(self._tool_messages(msg, capabilities))
        return converted

    def _assistant_message(self, msg: Message, *, name_style: ToolNameStyle) -> dict[str, Any]:
        """Build one assistant message, replaying signed thinking first.

        Anthropic requires the thinking blocks from a turn to precede the
        ``tool_use`` blocks they produced, each with its signature intact.

        Args:
            msg: The assistant message.
            name_style: How canonical dotted names are written onto the wire.

        Returns:
            dict[str, Any]: The assistant message to send.
        """
        content: list[dict[str, Any]] = []
        if msg.reasoning:
            content.extend(self.render_reasoning(msg.reasoning))
        if msg.content:
            content.append({"type": "text", "text": msg.content})
        if msg.tool_calls:
            content.extend(
                {
                    "type": "tool_use",
                    "id": tc.id,
                    "name": wire_function_name(tc.function_name, name_style),
                    "input": tc.arguments,
                }
                for tc in msg.tool_calls
            )
        return {"role": "assistant", "content": content or msg.content}

    def _tool_messages(self, msg: Message, capabilities: ModelCapabilities) -> list[dict[str, Any]]:
        """Build the user turn that carries a message's tool results.

        Args:
            msg: The tool-result message.
            capabilities: The resolved capability record for the target model.

        Returns:
            list[dict[str, Any]]: A single user message carrying every result
            block, or an empty list when the message carries none.
        """
        if not msg.tool_results:
            return []
        blocks: list[dict[str, Any]] = []
        for result in msg.tool_results:
            blocks.extend(self.render_tool_result(result, capabilities))
        return [{"role": "user", "content": blocks}] if blocks else []

    @override
    def build_request(self, request: DialectRequest) -> dict[str, Any]:
        """Shape a normalized request into an Anthropic Messages body.

        Args:
            request: The normalized request.

        Returns:
            dict[str, Any]: The JSON body to POST.
        """
        self.rehydrate_tool_names(request)
        capabilities = request.capabilities
        body: dict[str, Any] = {
            "model": request.model,
            "max_tokens": request.max_tokens,
            "messages": self.build_messages(request.messages, capabilities, name_style=request.tool_name_style),
        }
        system_prompt = self.system_instruction(request)
        if system_prompt is not None:
            body["system"] = system_prompt

        tools = self.build_tool_schemas(request.tools, capabilities, name_style=request.tool_name_style)
        if tools:
            body["tools"] = tools

        if request.tool_choice is not None and tools:
            self._apply_tool_choice(body, request.tool_choice, name_style=request.tool_name_style)

        thinking = request.thinking
        if thinking is not None and thinking.enabled:
            reasoning = capabilities.reasoning
            if reasoning.effort_format is ReasoningEffortFormat.ADAPTIVE_EFFORT:
                body["thinking"] = {"type": "adaptive", "display": "summarized"}
                effort = effort_for_thinking_budget(thinking.budget_tokens, reasoning.effort_levels)
                if effort is not None:
                    body["output_config"] = {"effort": effort}
            else:
                body["thinking"] = {"type": "enabled", "budget_tokens": thinking.budget_tokens}
            body["max_tokens"] = max(body["max_tokens"], thinking.budget_tokens + THINKING_MIN_HEADROOM_TOKENS)

        if request.enable_cache and capabilities.supports_prompt_cache:
            self.apply_cache_breakpoints(body, system_prompt=system_prompt)

        return self.apply_body_overrides(body, request)

    @staticmethod
    def _apply_tool_choice(
        body: dict[str, Any],
        tool_choice: ToolChoice,
        *,
        name_style: ToolNameStyle,
    ) -> None:
        """Write the Anthropic ``tool_choice`` field, or withdraw the tools.

        Anthropic has no ``"none"`` choice: the way to forbid tool use is to
        send no tools at all, which is what :data:`ToolChoiceMode.NONE` does
        here.

        Args:
            body: The request body, mutated in place.
            tool_choice: The tool choice configuration.
            name_style: How canonical dotted names are written onto the wire.
        """
        if tool_choice.mode == ToolChoiceMode.AUTO:
            body["tool_choice"] = {"type": "auto"}
        elif tool_choice.mode == ToolChoiceMode.REQUIRED:
            body["tool_choice"] = {"type": "any"}
        elif tool_choice.mode == ToolChoiceMode.NONE:
            body.pop("tools", None)
        elif tool_choice.mode == ToolChoiceMode.SPECIFIC and tool_choice.function_name:
            body["tool_choice"] = {"type": "tool", "name": wire_function_name(tool_choice.function_name, name_style)}

    @staticmethod
    def apply_cache_breakpoints(body: dict[str, Any], *, system_prompt: str | None) -> None:
        """Insert ``cache_control`` breakpoints across system, tools and messages.

        Anthropic accepts at most four breakpoints per request and renders the
        cache prefix as tools, then system, then messages. Placing one on the
        last system block, the last tool entry and the final content block of
        the last turn gives the full cross-prefix benefit ``enable_cache``
        promises. Under tool search the tool prefix is what makes deferred
        loading affordable, so the breakpoint placement is unchanged there.

        Args:
            body: The request body, mutated in place.
            system_prompt: The system instruction, or ``None``. Needed because
                adding a breakpoint rewrites ``system`` from a plain string
                into the structured block form.
        """
        if system_prompt is not None:
            body["system"] = [
                {
                    "type": "text",
                    "text": system_prompt,
                    "cache_control": dict(_CACHE_CONTROL),
                },
            ]

        tools_obj = body.get("tools")
        if is_json_array(tools_obj) and tools_obj:
            tools_list: list[Any] = tools_obj
            if cached_tools := [dict(tool) for tool in tools_list if is_json_object(tool)]:
                cached_tools[-1] = {**cached_tools[-1], "cache_control": dict(_CACHE_CONTROL)}
                body["tools"] = cached_tools

        messages_obj = body.get("messages")
        if is_json_array(messages_obj) and messages_obj:
            messages_list: list[Any] = messages_obj
            MessagesAdapter.cache_last_message_block(messages_list)

    @staticmethod
    def cache_last_message_block(messages: list[Any]) -> None:
        """Tag the last content block of the final turn for caching.

        Args:
            messages: Message dicts in Anthropic wire format, mutated in place.
        """
        last_msg = messages[-1]
        if not is_json_object(last_msg):
            return
        message: dict[str, Any] = last_msg
        content = message.get("content")
        if isinstance(content, str):
            message["content"] = [
                {
                    "type": "text",
                    "text": content,
                    "cache_control": dict(_CACHE_CONTROL),
                },
            ]
            return
        if is_json_array(content) and content:
            blocks: list[Any] = content
            last_block = blocks[-1]
            if is_json_object(last_block):
                block: dict[str, Any] = last_block
                blocks[-1] = {**block, "cache_control": dict(_CACHE_CONTROL)}

    @override
    def parse_response(
        self,
        payload: Mapping[str, Any],
        *,
        capabilities: ModelCapabilities | None = None,
    ) -> DialectResponse:
        """Parse an Anthropic Messages response body.

        Server-executed tool blocks -- ``server_tool_use`` and its
        ``*_tool_result`` -- are kept, in position among the thinking blocks,
        as provider items: Anthropic requires them back unchanged on the next
        request.

        Args:
            payload: The decoded response body.
            capabilities: Unused; the Messages shape does not vary by model.

        Returns:
            DialectResponse: The normalized response.
        """
        del capabilities
        raw_content = payload.get("content")
        blocks: list[Any] = raw_content if is_json_array(raw_content) else []
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        reasoning: list[ReasoningItem] = []

        for entry in blocks:
            if not is_json_object(entry):
                continue
            block: dict[str, Any] = entry
            block_type = block.get("type")
            if block_type == "text":
                text = block.get("text")
                if isinstance(text, str):
                    text_parts.append(text)
            elif block_type in {"thinking", "redacted_thinking"}:
                reasoning.append(parse_thinking_block(block))
            elif block_type == "tool_use":
                call = _parse_tool_use(block)
                if call is not None:
                    tool_calls.append(call)
            elif is_server_tool_block_type(block_type):
                _logger.debug("messages_server_tool_block_observed", block_type=block_type, block_id=block.get("id"))
                reasoning.append(server_tool_item(block))

        stop_reason = payload.get("stop_reason")
        return DialectResponse(
            content="".join(text_parts),
            tool_calls=tuple(tool_calls),
            reasoning=tuple(reasoning),
            usage=parse_usage(payload.get("usage")),
            finish_reason=stop_reason if isinstance(stop_reason, str) else None,
        )

    @override
    def parse_stream_event(
        self,
        event: Mapping[str, Any],
        *,
        capabilities: ModelCapabilities | None = None,
    ) -> list[StreamDelta]:
        """Translate one Anthropic stream event into normalized deltas.

        A thinking block's signature arrives on ``content_block_stop`` rather
        than on the deltas, so the completed reasoning item is emitted there;
        a server tool block completes there too. Input and cache-token usage
        arrives only on ``message_start`` and output usage on
        ``message_delta``, whose counts are cumulative and overwrite only the
        fields they carry, so the two are merged.

        Args:
            event: One decoded event.
            capabilities: Unused; the Messages shape does not vary by model.

        Returns:
            list[StreamDelta]: Zero or more deltas, in wire order.
        """
        del capabilities
        event_type = event.get("type")
        if not isinstance(event_type, str):
            return []
        if event_type == "message_start":
            return self._message_start_deltas(event)
        if event_type == "content_block_start":
            return self._block_start_deltas(event)
        if event_type == "content_block_delta":
            return self._block_delta_deltas(event)
        if event_type == "content_block_stop":
            return self._block_stop_deltas(event)
        if event_type == "message_delta":
            return self._message_delta_deltas(event)
        if event_type == "error":
            error = _stream_error_text(event.get("error"))
            _logger.warning("messages_stream_error", error=error)
            return [StreamDelta(finish="error", error=error)]
        return []

    def _message_start_deltas(self, event: Mapping[str, Any]) -> list[StreamDelta]:
        """Handle ``message_start``, recording the input-side usage it carries.

        Args:
            event: The decoded event.

        Returns:
            list[StreamDelta]: A usage delta when the message states usage.
        """
        self.reset_stream_state()
        raw_message = event.get("message")
        message: dict[str, Any] = raw_message if is_json_object(raw_message) else {}
        raw_usage = message.get("usage")
        if not is_json_object(raw_usage):
            return []
        start_usage: dict[str, Any] = raw_usage
        self._start_usage = dict(start_usage)
        usage = parse_usage(self._start_usage)
        return [StreamDelta(usage=usage)] if usage is not None else []

    def _message_delta_deltas(self, event: Mapping[str, Any]) -> list[StreamDelta]:
        """Translate ``message_delta`` into merged usage and finish deltas.

        Args:
            event: The decoded event.

        Returns:
            list[StreamDelta]: Zero or more deltas.
        """
        deltas: list[StreamDelta] = []
        raw_usage = event.get("usage")
        if is_json_object(raw_usage):
            delta_usage: dict[str, Any] = raw_usage
            merged = dict(self._start_usage)
            merged.update({key: value for key, value in delta_usage.items() if value is not None})
            self._start_usage = merged
            usage = parse_usage(merged)
            if usage is not None:
                deltas.append(StreamDelta(usage=usage))
        raw_delta = event.get("delta")
        delta: dict[str, Any] = raw_delta if is_json_object(raw_delta) else {}
        stop_reason = delta.get("stop_reason")
        if isinstance(stop_reason, str):
            deltas.append(StreamDelta(finish=stop_reason))
        return deltas

    def _block_start_deltas(self, event: Mapping[str, Any]) -> list[StreamDelta]:
        """Handle ``content_block_start``, opening a tool call or a thinking block.

        Args:
            event: The decoded event.

        Returns:
            list[StreamDelta]: Zero or more deltas.
        """
        index = event.get("index")
        raw_block = event.get("content_block")
        block: dict[str, Any] = raw_block if is_json_object(raw_block) else {}
        block_type = block.get("type")
        self._open_blocks.pop(str(index), None)
        self._server_tool_input.pop(str(index), None)
        if is_server_tool_block_type(block_type):
            _logger.debug("messages_server_tool_block_streamed", block_type=block_type, block_id=block.get("id"))
            self._open_blocks[str(index)] = dict(block)
            if block_type == SERVER_TOOL_USE_TYPE:
                self._server_tool_input[str(index)] = ""
            return []
        if block_type != "tool_use":
            if block_type in {"thinking", "redacted_thinking"}:
                self._open_blocks[str(index)] = dict(block)
            return []
        name = block.get("name")
        block_id = block.get("id")
        return [
            StreamDelta(
                tool_call_fragment=ToolCallFragment(
                    token=str(index),
                    call_id=block_id if isinstance(block_id, str) else None,
                    name=name if isinstance(name, str) else None,
                ),
            ),
        ]

    def _block_delta_deltas(self, event: Mapping[str, Any]) -> list[StreamDelta]:
        """Handle ``content_block_delta`` for text, arguments and thinking.

        Args:
            event: The decoded event.

        Returns:
            list[StreamDelta]: Zero or more deltas.
        """
        index = event.get("index")
        raw_delta = event.get("delta")
        delta: dict[str, Any] = raw_delta if is_json_object(raw_delta) else {}
        delta_type = delta.get("type")
        if delta_type == "text_delta":
            text = delta.get("text")
            return [StreamDelta(text=text)] if isinstance(text, str) and text else []
        if delta_type == "input_json_delta":
            partial = delta.get("partial_json")
            if not isinstance(partial, str) or not partial:
                return []
            if str(index) in self._server_tool_input:
                self._server_tool_input[str(index)] += partial
                return []
            return [StreamDelta(tool_call_fragment=ToolCallFragment(token=str(index), arguments=partial))]
        if delta_type == "thinking_delta":
            thinking = delta.get("thinking")
            if not isinstance(thinking, str) or not thinking:
                return []
            open_block = self._open_blocks.setdefault(str(index), {"type": "thinking", "thinking": ""})
            open_block["thinking"] = f"{open_block.get('thinking', '')}{thinking}"
            return [StreamDelta(reasoning=thinking)]
        if delta_type == "signature_delta":
            signature = delta.get("signature")
            if isinstance(signature, str) and signature:
                open_block = self._open_blocks.setdefault(str(index), {"type": "thinking", "thinking": ""})
                open_block["signature"] = f"{open_block.get('signature', '')}{signature}"
            return []
        return []

    def _block_stop_deltas(self, event: Mapping[str, Any]) -> list[StreamDelta]:
        """Handle ``content_block_stop``, closing a thinking or server tool block.

        Args:
            event: The decoded event.

        Returns:
            list[StreamDelta]: A reasoning-item delta when a thinking block or
            a server tool block closed, otherwise an empty list.
        """
        index = str(event.get("index"))
        block = self._open_blocks.pop(index, None)
        streamed_input = self._server_tool_input.pop(index, None)
        if block is None:
            return []
        if not is_server_tool_block_type(block.get("type")):
            return [StreamDelta(reasoning_item=parse_thinking_block(block))]
        if streamed_input:
            try:
                decoded: object = json.loads(streamed_input)
            except json.JSONDecodeError:
                _logger.warning("messages_server_tool_input_undecodable", block_id=block.get("id"))
                decoded = None
            if is_json_object(decoded):
                block["input"] = decoded
        return [StreamDelta(reasoning_item=server_tool_item(block))]

    def reset_stream_state(self) -> None:
        """Discard any partially accumulated blocks and usage.

        Called when a stream starts, ends or is cancelled so a subsequent stream on the same adapter cannot inherit a half-built block or
        another response's input-token count.
        """
        self._open_blocks.clear()
        self._server_tool_input.clear()
        self._start_usage = {}

    @override
    def render_tool_result(
        self,
        result: ToolResult,
        capabilities: ModelCapabilities,
        *,
        function_name: str | None = None,
    ) -> list[dict[str, Any]]:
        """Render a tool result as an Anthropic ``tool_result`` block.

        Text and images both ride inside the block natively, and the failure
        state travels as ``is_error`` rather than as a text prefix. A resource
        link degrades to the shared deterministic text description.

        Args:
            result: The tool result to render.
            capabilities: The resolved capability record for the target model.
            function_name: Unused; Anthropic correlates by ``tool_use_id``.

        Returns:
            list[dict[str, Any]]: A single ``tool_result`` block.
        """
        del function_name
        text = tool_result_text(result)
        images = image_parts(result)
        if images and capabilities.supports_vision:
            blocks: list[dict[str, Any]] = []
            if text:
                blocks.append({"type": "text", "text": text})
            blocks.extend(
                {
                    "type": "image",
                    "source": {"type": "base64", "media_type": part.mime_type, "data": part.data},
                }
                for part in images
            )
            content: str | list[dict[str, Any]] = blocks
        else:
            content = text
        return [
            {
                "type": "tool_result",
                "tool_use_id": result.call_id,
                "content": content,
                "is_error": result.is_error or not result.success,
            },
        ]

    @override
    def render_reasoning(self, reasoning: Sequence[ReasoningItem]) -> list[dict[str, Any]]:
        """Replay captured thinking blocks with their signatures intact.

        A thinking block with no signature is dropped rather than sent
        unsigned: Anthropic rejects the request outright, and dropping the
        block only loses reasoning context that is already unusable. Server
        tool blocks are echoed exactly as they arrived, which is what lets a
        deferred tool the search loaded stay callable.

        Args:
            reasoning: Reasoning blocks captured from an earlier turn.

        Returns:
            list[dict[str, Any]]: Anthropic content blocks, in order.
        """
        blocks: list[dict[str, Any]] = []
        for item in reasoning:
            if item.kind is ReasoningKind.PROVIDER_ITEM:
                if item.payload is not None and is_server_tool_block_type(item.payload.get("type")):
                    blocks.append(dict(item.payload))
            elif item.kind is ReasoningKind.REDACTED_THINKING and item.redacted_data is not None:
                blocks.append({"type": "redacted_thinking", "data": item.redacted_data})
            elif item.kind is ReasoningKind.THINKING and item.signature:
                blocks.append({"type": "thinking", "thinking": item.text, "signature": item.signature})
            elif item.kind is ReasoningKind.THINKING:
                _logger.debug("messages_unsigned_thinking_block_dropped")
        return blocks

    @override
    def auth_headers(self, api_key: str | None) -> dict[str, str]:
        """Build the Anthropic auth and version headers.

        Args:
            api_key: The instance's API key, or ``None``.

        Returns:
            dict[str, str]: ``x-api-key`` plus ``anthropic-version``. The
            version header is sent whether or not a key is configured,
            because the endpoint requires it on every request.
        """
        headers: dict[str, str] = {"anthropic-version": ANTHROPIC_VERSION}
        if api_key:
            headers["x-api-key"] = api_key
        return headers

    @override
    def endpoint_path(self, *, model: str, stream: bool) -> str:
        """Return the Messages path.

        Args:
            model: Unused; the model travels in the body.
            stream: Unused; streaming is a body flag.

        Returns:
            str: ``"v1/messages"``.
        """
        del model, stream
        return "v1/messages"

    @override
    def token_limit_field(self, capabilities: ModelCapabilities) -> str:
        """Return the output-limit field Anthropic expects.

        Args:
            capabilities: Unused; Messages always uses the same field.

        Returns:
            str: ``"max_tokens"``.
        """
        del capabilities
        return TokenLimitField.MAX_TOKENS.value

    @staticmethod
    @override
    def continues_turn(finish_reason: str | None) -> bool:
        """Report whether the response stopped with ``pause_turn``.

        Anthropic pauses a turn when a server-executed tool loop -- tool
        search, web search -- yields before the model has finished. The
        partial assistant turn must be sent straight back, unchanged, for the
        model to resume it.

        Args:
            finish_reason: The response's stop reason, if any.

        Returns:
            bool: ``True`` for ``pause_turn``.
        """
        return finish_reason == PAUSE_TURN_STOP_REASON


def is_server_tool_block_type(block_type: object) -> bool:
    """Report whether a content block type belongs to a server-executed tool.

    Args:
        block_type: The block's ``type`` value.

    Returns:
        bool: ``True`` for ``server_tool_use`` and every server tool result
        block (``tool_search_tool_result``, ``web_search_tool_result``, ...).
        The client ``tool_result`` block is not one.
    """
    if not isinstance(block_type, str):
        return False
    return block_type == SERVER_TOOL_USE_TYPE or (block_type.endswith(SERVER_TOOL_RESULT_SUFFIX) and block_type != "tool_result")


def server_tool_item(block: Mapping[str, Any]) -> ReasoningItem:
    """Capture a server-executed tool block for verbatim replay.

    Args:
        block: The ``server_tool_use`` or server tool result block.

    Returns:
        ReasoningItem: A provider item holding the complete block.
    """
    block_id = block.get("id")
    return ReasoningItem(
        kind=ReasoningKind.PROVIDER_ITEM,
        item_id=block_id if isinstance(block_id, str) else None,
        payload=dict(block),
    )


def _stream_error_text(raw: object) -> str:
    """Render an Anthropic stream ``error`` object as ``"<type>: <message>"``.

    Args:
        raw: The event's ``error`` value.

    Returns:
        str: The error type and message, whichever are present, or a generic
        description when the event states neither.
    """
    detail: dict[str, Any] = raw if is_json_object(raw) else {}
    parts = [str(detail[key]) for key in ("type", "message") if isinstance(detail.get(key), str) and detail[key]]
    return ": ".join(parts) if parts else "The endpoint reported an error without a message"


def is_server_tool_use_id(call_id: str) -> bool:
    """Report whether an id belongs to a server-executed tool call.

    Anthropic executes its own search tools server-side and rejects a request
    that returns a ``tool_result`` for one, so the dispatch layer must skip
    these rather than treat them as tool calls of its own.

    Args:
        call_id: The tool-use id from a response block.

    Returns:
        bool: ``True`` when the id carries the server-tool prefix.
    """
    return call_id.startswith(SERVER_TOOL_USE_ID_PREFIX)


def parse_thinking_block(block: Mapping[str, Any]) -> ReasoningItem:
    """Capture a thinking or redacted-thinking block, payload intact.

    Args:
        block: The content block.

    Returns:
        ReasoningItem: The captured item, carrying the signature that
        Anthropic requires back verbatim on the next tool-use turn.
    """
    if block.get("type") == "redacted_thinking":
        data = block.get("data")
        return ReasoningItem(
            kind=ReasoningKind.REDACTED_THINKING,
            redacted_data=data if isinstance(data, str) else None,
        )
    thinking = block.get("thinking")
    signature = block.get("signature")
    return ReasoningItem(
        kind=ReasoningKind.THINKING,
        text=thinking if isinstance(thinking, str) else "",
        signature=signature if isinstance(signature, str) else None,
    )


def _parse_tool_use(block: Mapping[str, Any]) -> ToolCall | None:
    """Parse one Anthropic ``tool_use`` block.

    Args:
        block: The content block.

    Returns:
        ToolCall | None: The parsed call, or ``None`` when the block names no
        function.
    """
    name = block.get("name")
    if not isinstance(name, str):
        return None
    block_id = block.get("id")
    call_id = block_id if isinstance(block_id, str) else ""
    if is_server_tool_use_id(call_id):
        return None
    raw_input = block.get("input")
    arguments: str | dict[str, object] = dict(raw_input) if is_json_object(raw_input) else "{}"
    return parse_tool_call(call_id=call_id, function_name=name, raw_arguments=arguments)


def parse_usage(raw: object) -> UsageInfo | None:
    """Parse an Anthropic ``usage`` object.

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
    return UsageInfo(
        prompt_tokens=prompt,
        completion_tokens=completion,
        total_tokens=prompt + completion,
        cache_read_tokens=_as_int(usage.get("cache_read_input_tokens")),
        cache_creation_tokens=_as_int(usage.get("cache_creation_input_tokens")),
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
