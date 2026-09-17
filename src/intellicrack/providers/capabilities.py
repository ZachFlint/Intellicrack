# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Per-model capability records and their three-layer merge.

Intellicrack used to guess what a model supported from its id: a context
window fell back to a hardcoded constant, ``supports_tools`` was hardcoded
``True`` and the reasoning family was decided by a string prefix. None of that
survives contact with an arbitrary endpoint, where the same dialect can serve
any model at all.

A :class:`ModelCapabilities` record replaces every one of those guesses.
Records resolve in three layers, following Cherry Studio's preset model:

1. the dialect's (or preset's) default record,
2. metadata ingested from the endpoint's own ``/models`` payload,
3. the per-model user override, which always wins.

:func:`merge_capabilities` applies layers 2 and 3 as :class:`CapabilityOverride`
records, in which an unset field is ``None`` and therefore transparent, so a
later layer only replaces what it actually states.

The tokenizer hint lives here rather than on the dialect on purpose: an
Anthropic-compatible gateway serving Llama is not cl100k, and only the model
record can say so.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, replace
from typing import Any, Final

from intellicrack.core.logging import get_logger


_logger = get_logger(__name__)

TIKTOKEN_O200K: Final[str] = "o200k_base"
TIKTOKEN_CL100K: Final[str] = "cl100k_base"

DEFAULT_TOKENIZER: Final[str] = TIKTOKEN_O200K


class ApiDialect(enum.Enum):
    """The wire format a model endpoint speaks.

    Provider identity is open -- any string instance id is valid -- so the
    exhaustiveness guarantee basedpyright used to derive from the closed
    provider enum lives here instead. Every dispatch over a dialect
    ends in ``_assert_never``, so adding a member without handling it is a type
    error rather than a runtime surprise.

    Attributes:
        CHAT_COMPLETIONS: OpenAI ``/chat/completions`` and every
            OpenAI-compatible gateway that mirrors it.
        RESPONSES: OpenAI ``/responses``, the API OpenAI recommends for new
            projects and the only one that carries reasoning items.
        MESSAGES: Anthropic ``/v1/messages``.
        GEMINI: Google Gemini ``generateContent`` / ``streamGenerateContent``.
    """

    CHAT_COMPLETIONS = "chat-completions"
    RESPONSES = "responses"
    MESSAGES = "messages"
    GEMINI = "gemini"


class TokenLimitField(enum.Enum):
    """Which request field carries the output-token limit.

    The three families disagree, and sending the wrong one is a 400: Chat
    Completions takes ``max_tokens`` except on reasoning models, which require
    ``max_completion_tokens``; Responses always takes ``max_output_tokens``;
    Messages always takes ``max_tokens``.

    Attributes:
        MAX_TOKENS: ``max_tokens`` (Chat Completions non-reasoning, Messages).
        MAX_COMPLETION_TOKENS: ``max_completion_tokens`` (Chat Completions
            reasoning models).
        MAX_OUTPUT_TOKENS: ``max_output_tokens`` (Responses).
    """

    MAX_TOKENS = "max_tokens"
    MAX_COMPLETION_TOKENS = "max_completion_tokens"
    MAX_OUTPUT_TOKENS = "max_output_tokens"


class ReasoningEffortFormat(enum.Enum):
    """How a model's reasoning knob is expressed on the wire.

    Attributes:
        NONE: The model exposes no reasoning knob.
        TOP_LEVEL_EFFORT: Chat Completions ``reasoning_effort`` as a top-level
            string.
        NESTED_EFFORT: Responses ``reasoning: {"effort": ...}``.
        THINKING_BUDGET: Anthropic ``thinking: {"type": "enabled",
            "budget_tokens": ...}``.
        GENERATION_BUDGET: Gemini ``generationConfig.thinkingConfig.thinkingBudget``.
    """

    NONE = "none"
    TOP_LEVEL_EFFORT = "reasoning_effort"
    NESTED_EFFORT = "reasoning.effort"
    THINKING_BUDGET = "thinking.budget_tokens"
    GENERATION_BUDGET = "thinkingConfig.thinkingBudget"


class ToolSearchStyle(enum.Enum):
    """Which native large-toolset mechanism an endpoint offers.

    Attributes:
        NONE: No native tool search; the whole active set ships on every
            request and the count cap applies to all of it.
        ANTHROPIC_DEFERRED: Anthropic's ``tool_search_tool_regex_20251119`` /
            ``tool_search_tool_bm25_20251119`` server tools plus per-tool
            ``defer_loading``.
        OPENAI_TOOL_SEARCH: OpenAI Responses ``{"type": "tool_search"}`` plus
            ``namespace`` grouping and per-function ``defer_loading``.
    """

    NONE = "none"
    ANTHROPIC_DEFERRED = "anthropic-deferred"
    OPENAI_TOOL_SEARCH = "openai-tool-search"


DEFAULT_EFFORT_LEVELS: Final[tuple[str, ...]] = ("low", "medium", "high")
"""Effort levels every OpenAI-compatible reasoning model accepts."""

EXTENDED_EFFORT_LEVELS: Final[tuple[str, ...]] = ("none", "minimal", "low", "medium", "high", "max")
"""The full effort ladder, as exposed by Zed and current OpenAI reasoning models."""


@dataclass(frozen=True, slots=True)
class ReasoningSupport:
    """What a model's reasoning surface looks like.

    Attributes:
        supported: Whether the model reasons at all.
        effort_levels: Accepted effort values, in ascending order. Empty when
            the model takes a token budget rather than a discrete level.
        effort_format: How the knob is expressed on the wire.
        interleaved: Whether reasoning may interleave with tool calls within a
            single assistant turn.
        encrypted_content: Whether the endpoint can return reasoning as
            ``reasoning.encrypted_content``, which is what lets a stateless
            (``store: false``) request keep a multi-turn reasoning chain.
        reasoning_key: Response key carrying reasoning text on an
            OpenAI-compatible endpoint that is not OpenAI itself -- LibreChat's
            ``reasoningKey``, commonly ``reasoning_content``. ``None`` when the
            endpoint emits no such key.
        include_reasoning_history: Whether previously captured reasoning is
            replayed on subsequent requests. LibreChat's
            ``includeReasoningHistory``; some gateways reject it.
        tool_calling_requires_none_effort: Whether the endpoint refuses tool
            calling unless the effort is ``"none"``. True for Chat Completions
            from GPT-5.4 onward, where tool calling and a non-``none``
            ``reasoning_effort`` are mutually exclusive.
    """

    supported: bool = False
    effort_levels: tuple[str, ...] = ()
    effort_format: ReasoningEffortFormat = ReasoningEffortFormat.NONE
    interleaved: bool = False
    encrypted_content: bool = False
    reasoning_key: str | None = None
    include_reasoning_history: bool = True
    tool_calling_requires_none_effort: bool = False


@dataclass(frozen=True, slots=True)
class ToolSearchSupport:
    """What a model's native large-toolset surface looks like.

    Attributes:
        style: Which mechanism the endpoint offers.
        max_deferred_tools: Upper bound on deferred tool definitions. Anthropic
            documents 10,000.
        default_search_results: How many tools a search returns by default.
        namespace_soft_limit: Recommended maximum functions per namespace for
            OpenAI tool search.
        callable_soft_limit: Recommended maximum functions callable at the
            start of a turn for OpenAI tool search.
    """

    style: ToolSearchStyle = ToolSearchStyle.NONE
    max_deferred_tools: int = 0
    default_search_results: int = 5
    namespace_soft_limit: int = 10
    callable_soft_limit: int = 20

    @property
    def supported(self) -> bool:
        """Whether any native large-toolset mechanism is available.

        Returns:
            bool: ``True`` unless :attr:`style` is
            :data:`ToolSearchStyle.NONE`.
        """
        return self.style is not ToolSearchStyle.NONE


@dataclass(frozen=True, slots=True)
class ModelCapabilities:
    """Everything the wire layer needs to know about one model.

    Attributes:
        dialect: The wire format this model is reached over, overriding the
            provider instance's own dialect. Zed's ``chat_completions: false``
            and VS Code's per-model ``apiType`` both land here. ``None`` means
            "use the instance's dialect".
        supports_tools: Whether the model accepts tool definitions.
        supports_vision: Whether the model accepts image input. Decides whether
            an image tool-result part can be re-emitted as an image or must
            degrade to text.
        supports_streaming: Whether the model can stream.
        supports_parallel_tool_calls: Whether the model may emit more than one
            tool call per turn.
        supports_prompt_cache: Whether prompt caching is available.
        supports_prompt_cache_key: Whether the endpoint accepts an explicit
            ``prompt_cache_key``.
        supports_structured_outputs: Whether strict JSON-schema structured
            output is available.
        supports_temperature: Whether the model accepts a temperature other
            than 1. Current OpenAI reasoning families reject one.
        reasoning: The model's reasoning surface.
        tool_search: The model's native large-toolset surface.
        context_window: Total context length in tokens, or ``None`` when the
            endpoint does not advertise one and no override supplies it.
        max_input_tokens: Maximum prompt tokens, when advertised separately.
        max_output_tokens: Maximum completion tokens, when advertised.
        token_limit_field: Which request field carries the output-token limit.
        tool_count_cap: Maximum flattened tool functions the endpoint accepts
            in one request, or ``None`` when it imposes no such limit.
        tokenizer: ``tiktoken`` encoding name used to estimate token counts.
        input_cost_per_1m_tokens: Prompt price per million tokens, when known.
        output_cost_per_1m_tokens: Completion price per million tokens, when
            known.
    """

    dialect: ApiDialect | None = None
    supports_tools: bool = True
    supports_vision: bool = False
    supports_streaming: bool = True
    supports_parallel_tool_calls: bool = True
    supports_prompt_cache: bool = False
    supports_prompt_cache_key: bool = False
    supports_structured_outputs: bool = False
    supports_temperature: bool = True
    reasoning: ReasoningSupport = field(default_factory=ReasoningSupport)
    tool_search: ToolSearchSupport = field(default_factory=ToolSearchSupport)
    context_window: int | None = None
    max_input_tokens: int | None = None
    max_output_tokens: int | None = None
    token_limit_field: TokenLimitField = TokenLimitField.MAX_TOKENS
    tool_count_cap: int | None = None
    tokenizer: str = DEFAULT_TOKENIZER
    input_cost_per_1m_tokens: float | None = None
    output_cost_per_1m_tokens: float | None = None


@dataclass(frozen=True, slots=True)
class CapabilityOverride:
    """A partial capability record: an unset field is ``None`` and transparent.

    Both the metadata ingested from an endpoint's ``/models`` payload and the
    per-model user override are expressed as one of these, so a layer replaces
    only what it actually states and never silently reasserts a default over a
    value a lower layer got right.

    Attributes:
        dialect: Override for :attr:`ModelCapabilities.dialect`.
        supports_tools: Override for :attr:`ModelCapabilities.supports_tools`.
        supports_vision: Override for :attr:`ModelCapabilities.supports_vision`.
        supports_streaming: Override for
            :attr:`ModelCapabilities.supports_streaming`.
        supports_parallel_tool_calls: Override for
            :attr:`ModelCapabilities.supports_parallel_tool_calls`.
        supports_prompt_cache: Override for
            :attr:`ModelCapabilities.supports_prompt_cache`.
        supports_prompt_cache_key: Override for
            :attr:`ModelCapabilities.supports_prompt_cache_key`.
        supports_structured_outputs: Override for
            :attr:`ModelCapabilities.supports_structured_outputs`.
        supports_temperature: Override for
            :attr:`ModelCapabilities.supports_temperature`.
        reasoning: Whole-record override for
            :attr:`ModelCapabilities.reasoning`.
        tool_search: Whole-record override for
            :attr:`ModelCapabilities.tool_search`.
        context_window: Override for
            :attr:`ModelCapabilities.context_window`.
        max_input_tokens: Override for
            :attr:`ModelCapabilities.max_input_tokens`.
        max_output_tokens: Override for
            :attr:`ModelCapabilities.max_output_tokens`.
        token_limit_field: Override for
            :attr:`ModelCapabilities.token_limit_field`.
        tool_count_cap: Override for
            :attr:`ModelCapabilities.tool_count_cap`.
        tokenizer: Override for :attr:`ModelCapabilities.tokenizer`.
        input_cost_per_1m_tokens: Override for
            :attr:`ModelCapabilities.input_cost_per_1m_tokens`.
        output_cost_per_1m_tokens: Override for
            :attr:`ModelCapabilities.output_cost_per_1m_tokens`.
    """

    dialect: ApiDialect | None = None
    supports_tools: bool | None = None
    supports_vision: bool | None = None
    supports_streaming: bool | None = None
    supports_parallel_tool_calls: bool | None = None
    supports_prompt_cache: bool | None = None
    supports_prompt_cache_key: bool | None = None
    supports_structured_outputs: bool | None = None
    supports_temperature: bool | None = None
    reasoning: ReasoningSupport | None = None
    tool_search: ToolSearchSupport | None = None
    context_window: int | None = None
    max_input_tokens: int | None = None
    max_output_tokens: int | None = None
    token_limit_field: TokenLimitField | None = None
    tool_count_cap: int | None = None
    tokenizer: str | None = None
    input_cost_per_1m_tokens: float | None = None
    output_cost_per_1m_tokens: float | None = None

    def is_empty(self) -> bool:
        """Report whether this override states nothing at all.

        Returns:
            bool: ``True`` when every field is unset.
        """
        return all(getattr(self, name) is None for name in _OVERRIDE_FIELD_NAMES)

    def to_mapping(self) -> dict[str, Any]:
        """Serialize the stated fields for ``providers.json``.

        Unset fields are omitted entirely so a stored override never grows
        into a full record that would shadow later metadata improvements.

        Returns:
            dict[str, Any]: JSON-compatible mapping of the stated fields.
        """
        payload: dict[str, Any] = {}
        for name in _OVERRIDE_FIELD_NAMES:
            value: object = getattr(self, name)
            if value is None:
                continue
            if isinstance(value, enum.Enum):
                payload[name] = value.value
            elif isinstance(value, ReasoningSupport):
                payload[name] = _reasoning_to_mapping(value)
            elif isinstance(value, ToolSearchSupport):
                payload[name] = _tool_search_to_mapping(value)
            else:
                payload[name] = value
        return payload

    @classmethod
    def from_mapping(cls, payload: dict[str, Any]) -> CapabilityOverride:
        """Rebuild an override from its ``providers.json`` representation.

        Unknown keys and values that cannot be coerced are skipped with a
        warning rather than rejected, so one bad field in a hand-edited
        settings file cannot cost the user every other override they saved.

        Args:
            payload: Mapping previously produced by :meth:`to_mapping`, or
                hand-written by the user.

        Returns:
            CapabilityOverride: The reconstructed override.
        """
        kwargs: dict[str, Any] = {}
        for name, raw in payload.items():
            if name not in _OVERRIDE_FIELD_NAMES:
                _logger.warning("capability_override_unknown_field", field=name)
                continue
            coerced = _coerce_override_value(name, raw)
            if coerced is not None:
                kwargs[name] = coerced
        return cls(**kwargs)


_OVERRIDE_FIELD_NAMES: Final[tuple[str, ...]] = (
    "dialect",
    "supports_tools",
    "supports_vision",
    "supports_streaming",
    "supports_parallel_tool_calls",
    "supports_prompt_cache",
    "supports_prompt_cache_key",
    "supports_structured_outputs",
    "supports_temperature",
    "reasoning",
    "tool_search",
    "context_window",
    "max_input_tokens",
    "max_output_tokens",
    "token_limit_field",
    "tool_count_cap",
    "tokenizer",
    "input_cost_per_1m_tokens",
    "output_cost_per_1m_tokens",
)

_BOOL_OVERRIDE_FIELDS: Final[frozenset[str]] = frozenset({
    "supports_tools",
    "supports_vision",
    "supports_streaming",
    "supports_parallel_tool_calls",
    "supports_prompt_cache",
    "supports_prompt_cache_key",
    "supports_structured_outputs",
    "supports_temperature",
})

_INT_OVERRIDE_FIELDS: Final[frozenset[str]] = frozenset({
    "context_window",
    "max_input_tokens",
    "max_output_tokens",
    "tool_count_cap",
})

_FLOAT_OVERRIDE_FIELDS: Final[frozenset[str]] = frozenset({
    "input_cost_per_1m_tokens",
    "output_cost_per_1m_tokens",
})


def _reasoning_to_mapping(support: ReasoningSupport) -> dict[str, Any]:
    """Serialize a reasoning record for ``providers.json``.

    Args:
        support: The reasoning record to serialize.

    Returns:
        dict[str, Any]: JSON-compatible mapping.
    """
    return {
        "supported": support.supported,
        "effort_levels": list(support.effort_levels),
        "effort_format": support.effort_format.value,
        "interleaved": support.interleaved,
        "encrypted_content": support.encrypted_content,
        "reasoning_key": support.reasoning_key,
        "include_reasoning_history": support.include_reasoning_history,
        "tool_calling_requires_none_effort": support.tool_calling_requires_none_effort,
    }


def _reasoning_from_mapping(payload: dict[str, Any]) -> ReasoningSupport:
    """Rebuild a reasoning record from its ``providers.json`` representation.

    Args:
        payload: Mapping previously produced by :func:`_reasoning_to_mapping`.

    Returns:
        ReasoningSupport: The reconstructed record, with defaults for every
        field the payload omits or states unusably.
    """
    default = ReasoningSupport()
    raw_levels = payload.get("effort_levels")
    levels = tuple(str(level) for level in raw_levels) if isinstance(raw_levels, list) else default.effort_levels
    return ReasoningSupport(
        supported=bool(payload.get("supported", default.supported)),
        effort_levels=levels,
        effort_format=_coerce_enum(ReasoningEffortFormat, payload.get("effort_format"), default.effort_format),
        interleaved=bool(payload.get("interleaved", default.interleaved)),
        encrypted_content=bool(payload.get("encrypted_content", default.encrypted_content)),
        reasoning_key=_coerce_optional_str(payload.get("reasoning_key")),
        include_reasoning_history=bool(payload.get("include_reasoning_history", default.include_reasoning_history)),
        tool_calling_requires_none_effort=bool(
            payload.get("tool_calling_requires_none_effort", default.tool_calling_requires_none_effort),
        ),
    )


def _tool_search_to_mapping(support: ToolSearchSupport) -> dict[str, Any]:
    """Serialize a tool-search record for ``providers.json``.

    Args:
        support: The tool-search record to serialize.

    Returns:
        dict[str, Any]: JSON-compatible mapping.
    """
    return {
        "style": support.style.value,
        "max_deferred_tools": support.max_deferred_tools,
        "default_search_results": support.default_search_results,
        "namespace_soft_limit": support.namespace_soft_limit,
        "callable_soft_limit": support.callable_soft_limit,
    }


def _tool_search_from_mapping(payload: dict[str, Any]) -> ToolSearchSupport:
    """Rebuild a tool-search record from its ``providers.json`` representation.

    Args:
        payload: Mapping previously produced by
            :func:`_tool_search_to_mapping`.

    Returns:
        ToolSearchSupport: The reconstructed record, with defaults for every
        field the payload omits or states unusably.
    """
    default = ToolSearchSupport()
    return ToolSearchSupport(
        style=_coerce_enum(ToolSearchStyle, payload.get("style"), default.style),
        max_deferred_tools=_coerce_int(payload.get("max_deferred_tools"), default.max_deferred_tools),
        default_search_results=_coerce_int(payload.get("default_search_results"), default.default_search_results),
        namespace_soft_limit=_coerce_int(payload.get("namespace_soft_limit"), default.namespace_soft_limit),
        callable_soft_limit=_coerce_int(payload.get("callable_soft_limit"), default.callable_soft_limit),
    )


def _coerce_enum[EnumT: enum.Enum](enum_type: type[EnumT], raw: object, fallback: EnumT) -> EnumT:
    """Coerce a stored value back to an enum member, falling back on failure.

    Args:
        enum_type: The enum class to build.
        raw: The stored value.
        fallback: Value returned when ``raw`` names no member.

    Returns:
        EnumT: The matching member, or ``fallback``.
    """
    if isinstance(raw, enum_type):
        return raw
    if isinstance(raw, str):
        for member in enum_type:
            if member.value == raw:
                return member
    if raw is not None:
        _logger.warning("capability_enum_value_unknown", enum_type=enum_type.__name__, value=repr(raw))
    return fallback


def _coerce_int(raw: object, fallback: int) -> int:
    """Coerce a stored value to an int, falling back on failure.

    Args:
        raw: The stored value.
        fallback: Value returned when ``raw`` is not a usable integer.

    Returns:
        int: The coerced integer, or ``fallback``.
    """
    if isinstance(raw, bool):
        return fallback
    if isinstance(raw, int):
        return raw
    if isinstance(raw, (str, float)):
        try:
            return int(raw)
        except (TypeError, ValueError):
            return fallback
    return fallback


def _coerce_optional_str(raw: object) -> str | None:
    """Coerce a stored value to a non-empty string, or ``None``.

    Args:
        raw: The stored value.

    Returns:
        str | None: The stripped string when non-empty, otherwise ``None``.
    """
    if isinstance(raw, str):
        stripped = raw.strip()
        return stripped or None
    return None


def _coerce_override_value(name: str, raw: object) -> object | None:
    """Coerce one stored override field to its declared type.

    Args:
        name: The override field name.
        raw: The stored value.

    Returns:
        object | None: The coerced value, or ``None`` when the field should be
        left unset because the stored value is unusable.
    """
    if raw is None:
        return None
    if name == "dialect":
        return _coerce_enum(ApiDialect, raw, ApiDialect.CHAT_COMPLETIONS) if isinstance(raw, (str, ApiDialect)) else None
    if name == "token_limit_field":
        return (
            _coerce_enum(TokenLimitField, raw, TokenLimitField.MAX_TOKENS) if isinstance(raw, (str, TokenLimitField)) else None
        )
    if name == "reasoning":
        return _reasoning_from_mapping(raw) if isinstance(raw, dict) else None
    if name == "tool_search":
        return _tool_search_from_mapping(raw) if isinstance(raw, dict) else None
    if name in _BOOL_OVERRIDE_FIELDS:
        return bool(raw)
    if name in _INT_OVERRIDE_FIELDS:
        coerced = _coerce_int(raw, -1)
        return None if coerced < 0 else coerced
    if name in _FLOAT_OVERRIDE_FIELDS:
        if isinstance(raw, bool):
            return None
        if isinstance(raw, (int, float)):
            return float(raw)
        if isinstance(raw, str):
            try:
                return float(raw)
            except ValueError:
                return None
        return None
    if name == "tokenizer":
        return _coerce_optional_str(raw)
    return None


def merge_capabilities(base: ModelCapabilities, *overrides: CapabilityOverride | None) -> ModelCapabilities:
    """Apply capability overrides in order, later layers winning.

    Args:
        base: The dialect or preset default record.
        *overrides: Layers to apply in ascending precedence -- typically the
            metadata ingested from the endpoint's ``/models`` payload first
            and the per-model user override last. ``None`` layers are skipped.

    Returns:
        ModelCapabilities: A new record carrying every field stated by the
        highest-precedence layer that stated it, and ``base``'s value for
        every field no layer stated.
    """
    merged = base
    for override in overrides:
        if override is None:
            continue
        stated = {name: getattr(override, name) for name in _OVERRIDE_FIELD_NAMES if getattr(override, name) is not None}
        if stated:
            merged = replace(merged, **stated)
    return merged


def capabilities_from_model_flags(
    base: ModelCapabilities,
    *,
    context_window: int | None,
    supports_tools: bool,
    supports_vision: bool,
    supports_streaming: bool,
    input_cost_per_1m_tokens: float | None,
    output_cost_per_1m_tokens: float | None,
) -> ModelCapabilities:
    """Fold a legacy scalar model description into a capability record.

    ``ModelInfo`` carries the scalar fields Intellicrack advertised before
    capability records existed. Providers that build a ``ModelInfo`` by hand
    use this to derive the matching record so the two views never disagree.

    Args:
        base: The dialect default the scalars refine.
        context_window: Total context length in tokens, or ``None``.
        supports_tools: Whether the model accepts tool definitions.
        supports_vision: Whether the model accepts image input.
        supports_streaming: Whether the model can stream.
        input_cost_per_1m_tokens: Prompt price per million tokens, or ``None``.
        output_cost_per_1m_tokens: Completion price per million tokens, or
            ``None``.

    Returns:
        ModelCapabilities: ``base`` refined by the supplied scalars.
    """
    return replace(
        base,
        context_window=context_window if context_window is not None else base.context_window,
        supports_tools=supports_tools,
        supports_vision=supports_vision,
        supports_streaming=supports_streaming,
        input_cost_per_1m_tokens=input_cost_per_1m_tokens,
        output_cost_per_1m_tokens=output_cost_per_1m_tokens,
    )
