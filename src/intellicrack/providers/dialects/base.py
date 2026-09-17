# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""The dialect abstraction: one adapter per wire format.

A provider instance is identified by an arbitrary string id, so the wire
format it speaks can no longer be inferred from its identity. It is stated
instead, as an :class:`~intellicrack.providers.capabilities.ApiDialect`, and
every difference between wire formats lives behind the
:class:`DialectAdapter` interface defined here.

That inversion is what keeps basedpyright's exhaustiveness guarantee: provider
identity is open, dialect is closed, and every dispatch over a dialect ends in
``_assert_never``.

This module also owns the parts that must behave identically on every dialect:
the text fallback a multi-part tool result degrades through, the header rules
(``${apiKey}`` interpolation, user auth headers suppressing the inferred one,
protocol headers hard-denied) and the normalized usage and streaming records.
"""

from __future__ import annotations

import enum
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar, Final

from intellicrack.core.logging import get_logger
from intellicrack.core.types import (
    AudioResultPart,
    EmbeddedResourcePart,
    ImageResultPart,
    ResourceLinkPart,
    StructuredResultPart,
    TextResultPart,
    ToolCall,
)
from intellicrack.providers.capabilities import ApiDialect, ModelCapabilities
from intellicrack.providers.tool_names import from_wire_name, to_wire_name


if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from intellicrack.core.types import (
        Message,
        ReasoningItem,
        ThinkingConfig,
        ToolChoice,
        ToolDefinition,
        ToolResult,
        ToolResultPart,
    )


_logger = get_logger(__name__)

API_KEY_PLACEHOLDER: Final[str] = "${apiKey}"
"""Placeholder a user header uses to request the instance's API key.

Follows VS Code's custom-endpoint contract, where a header value containing
``${apiKey}`` receives the configured key at request time.
"""

AUTH_HEADER_NAMES: Final[frozenset[str]] = frozenset({"authorization", "api-key", "x-api-key"})
"""Headers that carry a credential.

A user-supplied header with one of these names suppresses the adapter's
inferred auth header, so a gateway or APIM front end never receives two
conflicting credentials. This follows VS Code rather than Zed, which forbids
the override outright and makes such gateways unusable.
"""

PROTOCOL_HEADER_NAMES: Final[frozenset[str]] = frozenset({"host", "content-length", "transfer-encoding", "connection"})
"""Headers a caller may never set, because doing so breaks the HTTP transport."""


class ToolNameStyle(enum.Enum):
    """How canonical dotted tool names are written onto the wire.

    Attributes:
        DOUBLE_UNDERSCORE: The default. ``ghidra.decompile`` is sent as
            ``ghidra__decompile`` and reversed on the way back, which every
            provider's ``^[A-Za-z0-9_-]{1,64}$`` rule accepts.
        DOTTED: Pass the canonical dotted name through unchanged. The escape
            hatch for a third-party endpoint that rejects ``__`` names or
            rewrites them when proxying upstream;
            :func:`~intellicrack.providers.tool_names.from_wire_name` is
            already idempotent on canonical names, so reversal still holds.
    """

    DOUBLE_UNDERSCORE = "double_underscore"
    DOTTED = "dotted"


@dataclass(slots=True)
class UsageInfo:
    """Token usage statistics reported by a provider.

    Attributes:
        prompt_tokens: Tokens consumed by the prompt / input messages.
        completion_tokens: Tokens generated in the completion / output.
        total_tokens: Sum of prompt and completion tokens as reported
            by the provider when available.
        cache_read_tokens: Prompt tokens served from a provider-side
            prompt cache (Anthropic ``cache_read_input_tokens``); ``0``
            when the provider reports no cache hit or lacks the field.
        cache_creation_tokens: Prompt tokens written into the
            provider-side prompt cache (Anthropic
            ``cache_creation_input_tokens``); ``0`` when not reported.
        reasoning_tokens: Tokens the model spent reasoning, when the
            endpoint reports them separately; ``0`` otherwise.
    """

    prompt_tokens: int = field(default=0)
    completion_tokens: int = field(default=0)
    total_tokens: int = field(default=0)
    cache_read_tokens: int = field(default=0)
    cache_creation_tokens: int = field(default=0)
    reasoning_tokens: int = field(default=0)


@dataclass(frozen=True, slots=True)
class ToolCallFragment:
    """One streamed piece of a tool call, keyed by an opaque correlation token.

    Every dialect fragments tool calls differently -- Chat Completions by array
    index, Responses by ``call_id``, Messages by content-block index -- so the
    buffer that reassembles them keys on a token the adapter chooses rather
    than on any one dialect's shape.

    Attributes:
        token: Opaque per-dialect correlation token. Fragments sharing a token
            belong to the same tool call.
        call_id: The provider's id for the call, present on the first fragment.
        name: The wire function name, present on the first fragment.
        arguments: A partial JSON argument fragment to append.
    """

    token: str
    call_id: str | None = None
    name: str | None = None
    arguments: str | None = None


@dataclass(frozen=True, slots=True)
class StreamDelta:
    """The normalized output of one streaming event.

    An adapter turns one dialect-native event into zero or more of these, so
    the provider layer above it never sees a dialect's event model.

    Attributes:
        text: Assistant text to append, or the empty string.
        reasoning: Reasoning text to append, or the empty string.
        reasoning_item: A completed reasoning block, emitted when the dialect
            finishes one -- this is where Anthropic's signature arrives, on
            ``content_block_stop`` rather than on the deltas.
        tool_call_fragment: A tool-call fragment to accumulate, if any.
        usage: Token usage, when the event carries it.
        finish: The finish reason, when the event ends the response.
    """

    text: str = ""
    reasoning: str = ""
    reasoning_item: ReasoningItem | None = None
    tool_call_fragment: ToolCallFragment | None = None
    usage: UsageInfo | None = None
    finish: str | None = None


@dataclass(frozen=True, slots=True)
class DialectRequest:
    """A chat request in Intellicrack's own terms, before any dialect shaping.

    Attributes:
        model: Model id to send.
        messages: Conversation history in Intellicrack's message model.
        capabilities: The resolved capability record for ``model``. Every
            routing decision an adapter makes reads from here rather than from
            the model id.
        tools: Tool definitions to advertise, already in final priority order.
            The wire layer never reorders them.
        temperature: Sampling temperature. Omitted from the request when
            ``capabilities.supports_temperature`` is ``False``.
        max_tokens: Output-token limit, written to whichever field
            ``capabilities.token_limit_field`` names.
        tool_choice: How the model should select tools, if constrained.
        thinking: Extended-thinking configuration, if enabled.
        enable_cache: Whether to request prompt caching.
        stream: Whether the request is a streaming one.
        store: Whether the endpoint may retain the request server-side.
            ``None`` leaves the decision to the adapter, which defaults
            Responses to ``False`` so binary-analysis context is not retained.
        extra_body: Per-instance body parameters merged into the request last.
        drop_params: Top-level request keys to remove before sending, for
            gateways that reject parameters the dialect normally includes.
        tool_name_style: How canonical dotted tool names are written.
        system: System instruction override. When ``None`` the adapter derives
            it from the ``system``-role messages.
    """

    model: str
    messages: Sequence[Message]
    capabilities: ModelCapabilities
    tools: Sequence[ToolDefinition] = ()
    temperature: float = 0.7
    max_tokens: int = 4096
    tool_choice: ToolChoice | None = None
    thinking: ThinkingConfig | None = None
    enable_cache: bool = False
    stream: bool = False
    store: bool | None = None
    extra_body: Mapping[str, Any] = field(default_factory=dict)
    drop_params: frozenset[str] = frozenset()
    tool_name_style: ToolNameStyle = ToolNameStyle.DOUBLE_UNDERSCORE
    system: str | None = None


@dataclass(frozen=True, slots=True)
class DialectResponse:
    """A parsed non-streaming response in Intellicrack's own terms.

    Attributes:
        content: Assistant text.
        tool_calls: Tool calls the model requested, in wire order, with
            canonical dotted function names restored.
        reasoning: Reasoning blocks the model emitted, each carrying the
            provider-opaque payload that must be echoed back verbatim.
        usage: Token usage, when reported.
        finish_reason: The provider's finish reason, when reported.
    """

    content: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    reasoning: tuple[ReasoningItem, ...] = ()
    usage: UsageInfo | None = None
    finish_reason: str | None = None


def serialize_tool_result(result: object) -> str:
    """Serialize a tool result value to a string for API consumption.

    Args:
        result: The tool result value, either a string or a
            JSON-serializable object.

    Returns:
        str: The result as a string, JSON-encoded if not already a string.
    """
    return result if isinstance(result, str) else json.dumps(result)


def describe_tool_result_part(part: ToolResultPart) -> str:
    """Render one tool-result part as deterministic text.

    This is the single degradation path every dialect shares: a part a dialect
    cannot carry natively is described here, so the same tool result reads
    identically whichever endpoint it is replayed against, and the description
    is stable across runs rather than depending on payload identity.

    Args:
        part: The part to describe.

    Returns:
        str: A deterministic textual description of ``part``.
    """
    if isinstance(part, TextResultPart):
        return part.text
    if isinstance(part, ImageResultPart):
        return f"[image {part.mime_type}, {len(part.data)} base64 chars]"
    if isinstance(part, AudioResultPart):
        return f"[audio {part.mime_type}, {len(part.data)} base64 chars]"
    if isinstance(part, ResourceLinkPart):
        details = [part.uri]
        if part.name:
            details.append(f"name={part.name}")
        if part.mime_type:
            details.append(f"type={part.mime_type}")
        if part.description:
            details.append(part.description)
        return f"[resource {' '.join(details)}]"
    if isinstance(part, EmbeddedResourcePart):
        if part.text is not None:
            return part.text
        length = len(part.data) if part.data is not None else 0
        return f"[resource {part.uri} {part.mime_type or 'application/octet-stream'}, {length} base64 chars]"
    return json.dumps(part.content, sort_keys=True)


def render_parts_as_text(parts: Iterable[ToolResultPart]) -> str:
    """Join every part's deterministic description into one text block.

    Args:
        parts: The parts to render.

    Returns:
        str: The joined description, blank-line separated.
    """
    rendered = [describe_tool_result_part(part) for part in parts]
    return "\n\n".join(chunk for chunk in rendered if chunk)


def tool_result_text(result: ToolResult) -> str:
    """Resolve the authoritative text form of a tool result.

    Multi-part content wins when present, because an externally-sourced tool
    that supplied parts described its own output more precisely than the
    legacy ``result`` value can. Bridge results, which carry no parts, fall
    through to ``result`` exactly as before -- including on failure, where the
    failure travels as the dialect's own error signal rather than by replacing
    the result text.

    Args:
        result: The tool result to render.

    Returns:
        str: The text a dialect sends when it cannot carry the parts natively.
    """
    if result.content:
        return render_parts_as_text(result.content)
    return serialize_tool_result(result.result)


def image_parts(result: ToolResult) -> list[ImageResultPart]:
    """Collect the image parts of a tool result, in order.

    Args:
        result: The tool result to scan.

    Returns:
        list[ImageResultPart]: Every image part, or an empty list.
    """
    if not result.content:
        return []
    return [part for part in result.content if isinstance(part, ImageResultPart)]


def structured_parts(result: ToolResult) -> list[StructuredResultPart]:
    """Collect the structured parts of a tool result, in order.

    Args:
        result: The tool result to scan.

    Returns:
        list[StructuredResultPart]: Every structured part, or an empty list.
    """
    if not result.content:
        return []
    return [part for part in result.content if isinstance(part, StructuredResultPart)]


def wire_function_name(canonical: str, style: ToolNameStyle) -> str:
    """Write a canonical dotted tool-function name onto the wire.

    Args:
        canonical: Canonical dotted tool-function name.
        style: The instance's configured name style.

    Returns:
        str: The name to send.
    """
    return canonical if style is ToolNameStyle.DOTTED else to_wire_name(canonical)


def parse_tool_call(
    *,
    call_id: str,
    function_name: str,
    raw_arguments: str | dict[str, object],
) -> ToolCall:
    """Parse provider-specific tool-call data into a :class:`ToolCall`.

    Handles JSON argument parsing and tool-namespace extraction from dotted
    function names. ``function_name`` is first restored from its provider-safe
    wire form (``"frida__spawn"``) back to the canonical dotted form
    (``"frida.spawn"``), so every caller downstream -- routing, classification,
    confirmation, persistence -- only ever sees canonical names.

    Args:
        call_id: Unique identifier for the tool call.
        function_name: Function name from the provider response, in the
            provider's wire form.
        raw_arguments: Arguments as a JSON string or pre-parsed dict.

    Returns:
        ToolCall: Parsed ToolCall instance with canonical dotted names.
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

    canonical_name = from_wire_name(function_name)
    tool_name = canonical_name.split(".", maxsplit=1)[0] if "." in canonical_name else canonical_name
    return ToolCall(
        id=call_id,
        tool_name=tool_name,
        function_name=canonical_name,
        arguments=parsed_args,
    )


def interpolate_headers(headers: Mapping[str, str], api_key: str | None) -> dict[str, str]:
    """Substitute the API key into every header value that asks for it.

    Protocol-breaking headers are dropped outright: setting them would corrupt
    the request framing whatever the endpoint expects.

    Args:
        headers: The instance's configured headers.
        api_key: The instance's API key, or ``None`` when it has none. When
            ``None``, a header asking for the key is dropped rather than sent
            with an empty credential.

    Returns:
        dict[str, str]: Headers ready to send.
    """
    resolved: dict[str, str] = {}
    for name, value in headers.items():
        lowered = name.strip().lower()
        if not lowered:
            continue
        if lowered in PROTOCOL_HEADER_NAMES:
            _logger.warning("custom_header_rejected_protocol", header=name)
            continue
        if API_KEY_PLACEHOLDER in value:
            if not api_key:
                _logger.warning("custom_header_dropped_no_api_key", header=name)
                continue
            resolved[name] = value.replace(API_KEY_PLACEHOLDER, api_key)
        else:
            resolved[name] = value
    return resolved


def headers_receiving_api_key(headers: Mapping[str, str]) -> tuple[str, ...]:
    """Name every configured header that will receive the interpolated key.

    The provider settings UI shows this before a save so the user always knows
    exactly where their credential is about to be sent.

    Args:
        headers: The instance's configured headers.

    Returns:
        tuple[str, ...]: Header names carrying the placeholder, in the order
        they were configured.
    """
    return tuple(name for name, value in headers.items() if API_KEY_PLACEHOLDER in value)


def merge_auth_headers(inferred: Mapping[str, str], custom: Mapping[str, str]) -> dict[str, str]:
    """Combine the adapter's inferred auth headers with the user's own.

    When the user supplies any header that carries a credential, every
    inferred auth header is suppressed, so the endpoint receives exactly one
    credential rather than two that disagree. Non-auth custom headers are
    merged normally and win on a name collision.

    Args:
        inferred: Auth headers the adapter derived from the API key.
        custom: The instance's configured headers, already interpolated.

    Returns:
        dict[str, str]: The headers to send.
    """
    custom_auth = {name for name in custom if name.strip().lower() in AUTH_HEADER_NAMES}
    if custom_auth:
        _logger.info("inferred_auth_header_suppressed", overridden_by=sorted(custom_auth))
        merged: dict[str, str] = {}
    else:
        merged = dict(inferred)
    merged.update(custom)
    return merged


class DialectAdapter(ABC):
    """Translates Intellicrack's chat model to and from one wire format.

    Every difference between API families lives in a subclass of this: how
    tools are described, how a request body is shaped, how a response and a
    stream are parsed, how a tool result and a reasoning block are replayed,
    how the endpoint is authenticated and addressed, and which field carries
    the output-token limit.

    Attributes:
        dialect: The wire format this adapter implements.
    """

    dialect: ClassVar[ApiDialect]

    @abstractmethod
    def default_capabilities(self) -> ModelCapabilities:
        """Return this dialect's baseline capability record.

        This is layer one of the three-layer merge: the defaults a model of
        this dialect is assumed to have before the endpoint's own ``/models``
        metadata and the user's per-model override refine them.

        Returns:
            ModelCapabilities: The dialect's baseline record.
        """

    @abstractmethod
    def build_tool_schemas(
        self,
        tools: Sequence[ToolDefinition],
        capabilities: ModelCapabilities,
        *,
        name_style: ToolNameStyle = ToolNameStyle.DOUBLE_UNDERSCORE,
    ) -> list[dict[str, Any]]:
        """Describe every tool function in this dialect's schema format.

        Args:
            tools: Tool definitions in final priority order. The returned list
                preserves that order exactly.
            capabilities: The resolved capability record for the target model.
            name_style: How canonical dotted names are written onto the wire.

        Returns:
            list[dict[str, Any]]: Tool schemas ready to place in a request.
        """

    @abstractmethod
    def build_request(self, request: DialectRequest) -> dict[str, Any]:
        """Shape a normalized request into this dialect's request body.

        Args:
            request: The normalized request.

        Returns:
            dict[str, Any]: The JSON body to send.
        """

    @abstractmethod
    def parse_response(self, payload: Mapping[str, Any]) -> DialectResponse:
        """Parse a non-streaming response body into normalized form.

        Args:
            payload: The decoded response body.

        Returns:
            DialectResponse: The normalized response.
        """

    @abstractmethod
    def parse_stream_event(self, event: Mapping[str, Any]) -> list[StreamDelta]:
        """Translate one streaming event into normalized deltas.

        Args:
            event: One decoded streaming event.

        Returns:
            list[StreamDelta]: Zero or more normalized deltas, in wire order.
        """

    @abstractmethod
    def render_tool_result(
        self,
        result: ToolResult,
        capabilities: ModelCapabilities,
        *,
        function_name: str | None = None,
    ) -> list[dict[str, Any]]:
        """Render a tool result as this dialect's reply items.

        A dialect that carries a part natively emits it; every other part
        degrades through the shared text fallback, so the same result reads
        identically on every endpoint.

        Args:
            result: The tool result to render.
            capabilities: The resolved capability record for the target model,
                consulted for whether an image part can survive as an image.
            function_name: Canonical dotted function name the result answers,
                for dialects that identify a result by name rather than by id.

        Returns:
            list[dict[str, Any]]: Dialect-native items to append to the
            request, in order.
        """

    @abstractmethod
    def render_reasoning(self, reasoning: Sequence[ReasoningItem]) -> list[dict[str, Any]]:
        """Render captured reasoning blocks for replay on a later turn.

        Payloads are echoed verbatim. Nothing here re-serializes, re-orders or
        normalizes a provider-opaque field, because doing so silently breaks
        the provider's ability to resume its own reasoning chain.

        Args:
            reasoning: Reasoning blocks captured from an earlier turn.

        Returns:
            list[dict[str, Any]]: Dialect-native reasoning items, in order.
        """

    @abstractmethod
    def auth_headers(self, api_key: str | None) -> dict[str, str]:
        """Build the auth headers this dialect infers from an API key.

        Args:
            api_key: The instance's API key, or ``None``.

        Returns:
            dict[str, str]: Inferred auth headers, empty when there is no key.
        """

    @abstractmethod
    def endpoint_path(self, *, model: str, stream: bool) -> str:
        """Return the request path relative to the instance's base URL.

        Args:
            model: The target model id, which Gemini encodes into the path.
            stream: Whether the request is a streaming one, which Gemini
                encodes into the path.

        Returns:
            str: The path to append to the base URL, with no leading slash.
        """

    @abstractmethod
    def token_limit_field(self, capabilities: ModelCapabilities) -> str:
        """Return the request field that carries the output-token limit.

        Args:
            capabilities: The resolved capability record for the target model.

        Returns:
            str: The request key to write the limit to.
        """

    def resolve_headers(
        self,
        api_key: str | None,
        custom_headers: Mapping[str, str] | None = None,
    ) -> dict[str, str]:
        """Combine inferred auth headers with the instance's configured ones.

        Args:
            api_key: The instance's API key, or ``None``.
            custom_headers: The instance's configured headers, before
                ``${apiKey}`` interpolation.

        Returns:
            dict[str, str]: The headers to send.
        """
        interpolated = interpolate_headers(custom_headers, api_key) if custom_headers else {}
        return merge_auth_headers(self.auth_headers(api_key), interpolated)

    @staticmethod
    def system_instruction(request: DialectRequest) -> str | None:
        """Resolve the system instruction for a request.

        Args:
            request: The normalized request.

        Returns:
            str | None: The explicit override when set, otherwise every
            ``system``-role message joined with blank lines, or ``None`` when
            the conversation carries no system content.
        """
        if request.system is not None:
            return request.system
        parts = [message.content for message in request.messages if message.role == "system" and message.content]
        return "\n\n".join(parts) if parts else None

    @staticmethod
    def apply_body_overrides(body: dict[str, Any], request: DialectRequest) -> dict[str, Any]:
        """Apply the instance's body parameter policy to a built request body.

        Dropping happens before merging so an instance can drop a parameter
        the dialect emits and then supply its own replacement under the same
        key.

        Args:
            body: The body the adapter built.
            request: The normalized request carrying the instance policy.

        Returns:
            dict[str, Any]: ``body``, mutated in place and returned for
            chaining.
        """
        for key in request.drop_params:
            body.pop(key, None)
        if request.extra_body:
            body.update(request.extra_body)
        return body


__all__ = [
    "API_KEY_PLACEHOLDER",
    "AUTH_HEADER_NAMES",
    "PROTOCOL_HEADER_NAMES",
    "ApiDialect",
    "DialectAdapter",
    "DialectRequest",
    "DialectResponse",
    "ModelCapabilities",
    "StreamDelta",
    "ToolCallFragment",
    "ToolNameStyle",
    "UsageInfo",
    "describe_tool_result_part",
    "headers_receiving_api_key",
    "image_parts",
    "interpolate_headers",
    "merge_auth_headers",
    "parse_tool_call",
    "render_parts_as_text",
    "serialize_tool_result",
    "structured_parts",
    "tool_result_text",
    "wire_function_name",
]
