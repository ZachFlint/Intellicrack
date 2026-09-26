# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Ingesting what an endpoint says about its own models.

An arbitrary endpoint is the only authority on what its models can do, and several of them say so in their ``/models`` payload: OpenRouter
advertises ``context_length``, ``pricing``, ``modality`` and ``supported_parameters``; LiteLLM and vLLM mirror parts of it; an OpenAI-
compatible gateway may advertise nothing beyond an id.

This module reads whatever is there. It is layer two of the capability merge, between the preset defaults and the user's per-model override,
and it never asserts a field the payload did not state, so a silent payload leaves the preset's answer standing rather than overwriting it
with a guess.

Fetchers are an ordered registry, following Cherry Studio: each strategy declares whether it recognises a payload, the first that does wins,
and an always-match OpenAI-compatible fallback sits last so an unknown endpoint still produces a model list.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar, Final, override

from intellicrack.core.json_payload import is_json_array, is_json_object
from intellicrack.core.logging import get_logger
from intellicrack.core.types import ModelInfo
from intellicrack.providers.capabilities import (
    ANTHROPIC_EFFORT_LEVELS,
    CapabilityOverride,
    ReasoningEffortFormat,
    ReasoningSupport,
)


if TYPE_CHECKING:
    from collections.abc import Sequence


_logger = get_logger(__name__)

TOKENS_PER_MILLION: Final[int] = 1000000
"""Scale factor turning a per-token price into the per-million-token figure shown."""

_TOOL_PARAMETER_NAMES: Final[frozenset[str]] = frozenset({"tools", "tool_choice", "functions", "function_call"})
"""``supported_parameters`` entries that mean the model accepts tool definitions."""

_CONTEXT_KEYS: Final[tuple[str, ...]] = ("context_length", "context_window", "max_context_length", "max_input_tokens")
"""Keys endpoints use for the total context length, in the order they are tried."""

_MAX_OUTPUT_KEYS: Final[tuple[str, ...]] = ("max_completion_tokens", "max_output_tokens", "max_tokens")
"""Keys endpoints use for the output-token ceiling, in the order they are tried."""


@dataclass(frozen=True, slots=True)
class IngestedModel:
    """One model as the endpoint described it.

    Attributes:
        model_id: The model's id.
        display_name: Human-readable name, falling back to the id.
        capabilities: Only the capability fields the payload actually stated.
            Everything else stays unset so a lower layer keeps its answer.
    """

    model_id: str
    display_name: str
    capabilities: CapabilityOverride

    def to_model_info(self, provider_id: str, resolved_context_window: int) -> ModelInfo:
        """Build the scalar ``ModelInfo`` view of this model.

        Args:
            provider_id: Instance id of the provider offering the model.
            resolved_context_window: Context window after the full capability
                merge, which may come from a preset or a user override rather
                than from the payload.

        Returns:
            ModelInfo: The scalar record, carrying the ingested capability
            layer so consumers that want the full picture have it.
        """
        return ModelInfo(
            id=self.model_id,
            name=self.display_name,
            provider=provider_id,
            context_window=resolved_context_window,
            supports_tools=self.capabilities.supports_tools is not False,
            supports_vision=bool(self.capabilities.supports_vision),
            supports_streaming=self.capabilities.supports_streaming is not False,
            input_cost_per_1m_tokens=self.capabilities.input_cost_per_1m_tokens,
            output_cost_per_1m_tokens=self.capabilities.output_cost_per_1m_tokens,
        )


class ModelListFetcher(ABC):
    """A strategy for turning one endpoint's ``/models`` payload into models.

    Strategies are tried in registration order and the first whose
    :meth:`matches` returns ``True`` wins, so a strategy that understands a
    particular endpoint's richer payload gets first refusal and the
    OpenAI-compatible fallback catches everything else.

    Attributes:
        name: Strategy name used in log records.
    """

    name: ClassVar[str]

    @abstractmethod
    def matches(self, payload: dict[str, Any]) -> bool:
        """Report whether this strategy understands a payload.

        Args:
            payload: The decoded ``/models`` response body.

        Returns:
            bool: ``True`` when this strategy should parse the payload.
        """

    @abstractmethod
    def parse(self, payload: dict[str, Any]) -> list[IngestedModel]:
        """Parse a payload into ingested models.

        Args:
            payload: The decoded ``/models`` response body.

        Returns:
            list[IngestedModel]: The models the payload describes, in payload
            order.
        """


def _entries(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract the model entries from a ``/models`` payload.

    Args:
        payload: The decoded response body.

    Returns:
        list[dict[str, Any]]: The entries under ``data`` or ``models``, or an
        empty list when neither is a list of objects.
    """
    for key in ("data", "models"):
        raw = payload.get(key)
        if is_json_array(raw):
            entries: list[Any] = raw
            return [entry for entry in entries if is_json_object(entry)]
    return []


def _as_int(raw: object) -> int | None:
    """Coerce a payload value to a positive int.

    Args:
        raw: The raw value.

    Returns:
        int | None: The coerced value, or ``None`` when it is absent, not a
        number, or not positive.
    """
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        value = int(raw)
        return value if value > 0 else None
    if isinstance(raw, str):
        try:
            value = int(float(raw))
        except ValueError:
            return None
        return value if value > 0 else None
    return None


def _as_price_per_million(raw: object) -> float | None:
    """Coerce a per-token price to a per-million-token figure.

    Args:
        raw: The raw per-token price, which endpoints report as a string as
            often as a number.

    Returns:
        float | None: The per-million price, or ``None`` when unparseable.
    """
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        return float(raw) * TOKENS_PER_MILLION
    if isinstance(raw, str):
        try:
            return float(raw) * TOKENS_PER_MILLION
        except ValueError:
            return None
    return None


def _first_int(entry: dict[str, Any], keys: Sequence[str]) -> int | None:
    """Return the first key in ``keys`` whose value coerces to a positive int.

    Args:
        entry: One model entry.
        keys: Keys to try, in order.

    Returns:
        int | None: The first usable value, or ``None``.
    """
    for key in keys:
        value = _as_int(entry.get(key))
        if value is not None:
            return value
    return None


def ingest_model_entry(entry: dict[str, Any]) -> IngestedModel | None:
    """Read one model entry into the capability fields it actually states.

    This is the generic form of what the OpenRouter provider used to do by
    hand. Nothing here is asserted unless the payload says it: an entry that
    mentions no context length leaves ``context_window`` unset, so the preset
    default survives instead of being replaced by an invented number.

    Args:
        entry: One entry from the ``/models`` payload.

    Returns:
        IngestedModel | None: The ingested model, or ``None`` when the entry
        names no model id.
    """
    model_id = entry.get("id") or entry.get("name") or entry.get("model")
    if not isinstance(model_id, str) or not model_id:
        return None
    display = entry.get("display_name") or entry.get("name")
    display_name = display if isinstance(display, str) and display else model_id

    stated: dict[str, Any] = _stated_limits(entry)
    _add_stated_pricing(entry, stated)

    vision = _states_vision(entry)
    if vision is not None:
        stated["supports_vision"] = vision

    tools = _states_tools(entry)
    if tools is not None:
        stated["supports_tools"] = tools

    temperature = _states_temperature(entry)
    if temperature is not None:
        stated["supports_temperature"] = temperature

    reasoning = _states_reasoning(entry)
    if reasoning is not None:
        stated["reasoning"] = _reasoning_mapping(reasoning)

    structured = _capability_flag(entry, "structured_outputs")
    if structured is not None:
        stated["supports_structured_outputs"] = structured

    return IngestedModel(
        model_id=model_id,
        display_name=display_name,
        capabilities=CapabilityOverride.from_mapping(stated),
    )


def _stated_limits(entry: dict[str, Any]) -> dict[str, Any]:
    """Read the token limits an entry states, including OpenRouter's nested form.

    Args:
        entry: One model entry.

    Returns:
        dict[str, Any]: Only the limit fields the entry actually stated.
    """
    stated: dict[str, Any] = {}
    context_window = _first_int(entry, _CONTEXT_KEYS)
    if context_window is not None:
        stated["context_window"] = context_window
    max_output = _first_int(entry, _MAX_OUTPUT_KEYS)
    if max_output is not None:
        stated["max_output_tokens"] = max_output

    top_provider = entry.get("top_provider")
    if is_json_object(top_provider):
        provider_entry: dict[str, Any] = top_provider
        nested_context = _first_int(provider_entry, _CONTEXT_KEYS)
        if nested_context is not None:
            stated.setdefault("context_window", nested_context)
        nested_output = _first_int(provider_entry, _MAX_OUTPUT_KEYS)
        if nested_output is not None:
            stated.setdefault("max_output_tokens", nested_output)
    return stated


def _add_stated_pricing(entry: dict[str, Any], stated: dict[str, Any]) -> None:
    """Read the prices an entry states into the stated-field mapping.

    Args:
        entry: One model entry.
        stated: The stated-field mapping, mutated in place.
    """
    pricing = entry.get("pricing")
    if not is_json_object(pricing):
        return
    price_entry: dict[str, Any] = pricing
    prompt_price = _as_price_per_million(price_entry.get("prompt") or price_entry.get("input"))
    if prompt_price is not None:
        stated["input_cost_per_1m_tokens"] = prompt_price
    completion_price = _as_price_per_million(price_entry.get("completion") or price_entry.get("output"))
    if completion_price is not None:
        stated["output_cost_per_1m_tokens"] = completion_price


def _states_vision(entry: dict[str, Any]) -> bool | None:
    """Read whether an entry states image-input support.

    Args:
        entry: One model entry.

    Returns:
        bool | None: The stated value, or ``None`` when the entry is silent.
    """
    architecture = entry.get("architecture")
    if is_json_object(architecture):
        arch: dict[str, Any] = architecture
        modality = arch.get("modality")
        if isinstance(modality, str) and modality:
            return "image" in modality
        input_modalities = arch.get("input_modalities")
        if is_json_array(input_modalities):
            modalities: list[Any] = input_modalities
            return any(str(item).lower() == "image" for item in modalities)
    for key in ("vision", "images", "image_input"):
        value = _capability_flag(entry, key)
        if value is not None:
            return value
    return None


def _states_temperature(entry: dict[str, Any]) -> bool | None:
    """Read whether an entry states that the model accepts a temperature.

    OpenRouter lists every request parameter a model honours in
    ``supported_parameters``; a model whose list omits ``temperature``
    rejects or ignores sampling control.

    Args:
        entry: One model entry.

    Returns:
        bool | None: The stated value, or ``None`` when the entry is silent.
    """
    supported = entry.get("supported_parameters")
    if not is_json_array(supported):
        return None
    names: list[Any] = supported
    return any(str(name) == "temperature" for name in names)


def _capability_flag(entry: dict[str, Any], key: str) -> bool | None:
    """Read one flag from an entry's ``capabilities`` object.

    Args:
        entry: One model entry.
        key: The capability name.

    Returns:
        bool | None: The stated value, or ``None`` when the entry is silent.
    """
    capabilities = entry.get("capabilities")
    if not is_json_object(capabilities):
        return None
    caps: dict[str, Any] = capabilities
    return _stated_support(caps.get(key))


def _stated_support(value: object) -> bool | None:
    """Read a capability stated as a boolean or as a ``supported`` object.

    Endpoints state a capability either as a bare boolean or, as Anthropic's
    ``/v1/models`` does, as an object carrying a boolean ``supported``.

    Args:
        value: The capability's stated value.

    Returns:
        bool | None: The stated support, or ``None`` when nothing usable is
        stated.
    """
    if isinstance(value, bool):
        return value
    if is_json_object(value):
        support: dict[str, Any] = value
        supported = support.get("supported")
        if isinstance(supported, bool):
            return supported
    return None


def _states_reasoning(entry: dict[str, Any]) -> ReasoningSupport | None:
    """Read the thinking surface an Anthropic-shaped entry states.

    Anthropic's ``/v1/models`` reports ``capabilities.thinking`` with the
    thinking ``types`` a model accepts and ``capabilities.effort`` with the
    effort levels it accepts. A model that accepts ``adaptive`` thinking is
    driven through it and ``output_config.effort``, because the budget form is
    deprecated where both are accepted and rejected on the models that only
    accept ``adaptive``.

    Args:
        entry: One model entry.

    Returns:
        ReasoningSupport | None: The stated reasoning surface, or ``None``
        when the entry says nothing about thinking.
    """
    capabilities = entry.get("capabilities")
    if not is_json_object(capabilities):
        return None
    caps: dict[str, Any] = capabilities
    raw_thinking = caps.get("thinking")
    if not is_json_object(raw_thinking):
        return None
    thinking: dict[str, Any] = raw_thinking
    supported = _stated_support(thinking)
    if supported is False:
        return ReasoningSupport(supported=False)
    raw_types = thinking.get("types")
    types: dict[str, Any] = raw_types if is_json_object(raw_types) else {}
    if _stated_support(types.get("adaptive")):
        raw_effort = caps.get("effort")
        effort: dict[str, Any] = raw_effort if is_json_object(raw_effort) else {}
        levels = tuple(level for level in ANTHROPIC_EFFORT_LEVELS if _stated_support(effort.get(level)))
        return ReasoningSupport(
            supported=True,
            effort_levels=levels,
            effort_format=ReasoningEffortFormat.ADAPTIVE_EFFORT,
            interleaved=True,
        )
    if _stated_support(types.get("enabled")) or supported:
        return ReasoningSupport(supported=True, effort_format=ReasoningEffortFormat.THINKING_BUDGET, interleaved=True)
    return None


def _reasoning_mapping(reasoning: ReasoningSupport) -> dict[str, Any]:
    """Express a reasoning record in the override mapping form.

    Args:
        reasoning: The reasoning record.

    Returns:
        dict[str, Any]: The mapping :meth:`CapabilityOverride.from_mapping`
        reads back into the same record.
    """
    return CapabilityOverride(reasoning=reasoning).to_mapping()["reasoning"]


def _states_tools(entry: dict[str, Any]) -> bool | None:
    """Read whether an entry states tool-calling support.

    Args:
        entry: One model entry.

    Returns:
        bool | None: The stated value, or ``None`` when the entry is silent.
    """
    supported = entry.get("supported_parameters")
    if is_json_array(supported):
        names: list[Any] = supported
        return any(str(name) in _TOOL_PARAMETER_NAMES for name in names)
    capabilities = entry.get("capabilities")
    if is_json_object(capabilities):
        caps: dict[str, Any] = capabilities
        for key in ("tools", "tool_calling", "function_calling"):
            value = caps.get(key)
            if isinstance(value, bool):
                return value
    return None


class OpenAICompatibleFetcher(ModelListFetcher):
    """The always-match fallback: read whatever an entry happens to state.

    This sits last in the registry and recognises every payload, so an
    endpoint nothing else understands still yields a usable model list.

    Attributes:
        name: Strategy name used in log records.
    """

    name: ClassVar[str] = "openai-compatible"

    @override
    def matches(self, payload: dict[str, Any]) -> bool:
        """Report whether this strategy understands a payload.

        Args:
            payload: The decoded ``/models`` response body.

        Returns:
            bool: Always ``True``; this is the fallback.
        """
        del payload
        return True

    @override
    def parse(self, payload: dict[str, Any]) -> list[IngestedModel]:
        """Parse a payload into ingested models.

        Args:
            payload: The decoded ``/models`` response body.

        Returns:
            list[IngestedModel]: The models the payload describes, in payload
            order, skipping entries that name no model id.
        """
        ingested: list[IngestedModel] = []
        for entry in _entries(payload):
            model = ingest_model_entry(entry)
            if model is not None:
                ingested.append(model)
        return ingested


class ModelFetcherRegistry:
    """The ordered strategy registry that turns a payload into models.

    Attributes:
        fallback: The always-match strategy tried when nothing else matches.
    """

    fallback: ModelListFetcher

    def __init__(self, fallback: ModelListFetcher | None = None) -> None:
        """Initialize the registry with its always-match fallback.

        Args:
            fallback: The strategy tried last. Defaults to
                :class:`OpenAICompatibleFetcher`.
        """
        self._fetchers: list[ModelListFetcher] = []
        self.fallback = fallback if fallback is not None else OpenAICompatibleFetcher()

    def register(self, fetcher: ModelListFetcher) -> None:
        """Add a strategy ahead of the fallback.

        Args:
            fetcher: The strategy to add. Strategies are tried in the order
                they were registered.
        """
        self._fetchers.append(fetcher)
        _logger.debug("model_fetcher_registered", fetcher=fetcher.name)

    def parse(self, payload: dict[str, Any]) -> list[IngestedModel]:
        """Parse a payload with the first strategy that recognises it.

        Args:
            payload: The decoded ``/models`` response body.

        Returns:
            list[IngestedModel]: The models the payload describes.
        """
        for fetcher in self._fetchers:
            if fetcher.matches(payload):
                _logger.debug("model_fetcher_selected", fetcher=fetcher.name)
                return fetcher.parse(payload)
        return self.fallback.parse(payload)


_DEFAULT_REGISTRY = ModelFetcherRegistry()


def default_fetcher_registry() -> ModelFetcherRegistry:
    """Return the process-wide fetcher registry.

    Returns:
        ModelFetcherRegistry: The shared registry, whose fallback already
        handles any OpenAI-compatible payload.
    """
    return _DEFAULT_REGISTRY


def ingest_models(payload: dict[str, Any]) -> list[IngestedModel]:
    """Read an endpoint's ``/models`` payload through the shared registry.

    Args:
        payload: The decoded response body.

    Returns:
        list[IngestedModel]: The models the payload describes.
    """
    return _DEFAULT_REGISTRY.parse(payload)
