# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Provider and model presets: the first layer of the capability merge.

A preset is data, not logic. It records what is already known about an endpoint and its models -- which wire format it speaks, where it
lives, which environment variable holds its key, and what each model family supports -- so the request path never has to infer any of it
from a model id.

That distinction is the point. Deciding at request time that a model is a reasoning model because its id starts with ``"o1"`` is a heuristic
that breaks the moment an endpoint serves a model it did not name that way; looking the same fact up in a preset table, which a user can
correct per model, does not.

Presets are the lowest-precedence layer: metadata the endpoint advertises about itself overrides them, and the user's own per-model override
overrides both.

Built-in providers are presets too. A built-in materializes as an ordinary editable instance, which is what lets a user duplicate OpenAI for
a second account or pin it at a proxy, and lets deleting a built-in restore it from its preset rather than orphan it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from intellicrack.core.logging import get_logger
from intellicrack.providers import ids as provider_ids
from intellicrack.providers.capabilities import (
    EXTENDED_EFFORT_LEVELS,
    TIKTOKEN_CL100K,
    TIKTOKEN_O200K,
    ApiDialect,
    CapabilityOverride,
    ReasoningEffortFormat,
    ReasoningSupport,
    TokenLimitField,
)


_logger = get_logger(__name__)

OPENAI_CONTEXT_WINDOW: Final[int] = 128000
"""Context window shared by the GPT-4o / 4.1 / 4.5 families."""

OPENAI_REASONING_CONTEXT_WINDOW: Final[int] = 200000
"""Context window of the o-series reasoning models."""

GPT5_CONTEXT_WINDOW: Final[int] = 400000
"""Context window of the GPT-5 family."""

ANTHROPIC_CONTEXT_WINDOW: Final[int] = 200000
"""Context window shared by current Claude models."""

GEMINI_CONTEXT_WINDOW: Final[int] = 1048576
"""Context window of the Gemini 1.5+ families."""

OPENAI_TOOL_COUNT_CAP: Final[int] = 128
"""Flattened tool functions OpenAI accepts in one function-calling request."""


@dataclass(frozen=True, slots=True)
class ModelPreset:
    """Known capabilities of one model family.

    Attributes:
        prefixes: Model-id prefixes this preset describes. The first preset
            whose prefix matches wins, so more specific entries are listed
            before more general ones.
        capabilities: The capability fields this family is known to have.
            Fields the preset leaves unset stay open for the endpoint's own
            metadata to supply.
    """

    prefixes: tuple[str, ...]
    capabilities: CapabilityOverride


@dataclass(frozen=True, slots=True)
class ProviderPreset:
    """Everything known in advance about one endpoint.

    Attributes:
        provider_id: The instance id a materialized copy of this preset gets.
        display_name: Human-readable label.
        dialect: The wire format the endpoint speaks, or ``None`` for a
            provider that is not an HTTP endpoint at all.
        default_api_base: Default base URL, or ``None`` when the SDK's own
            default applies.
        api_key_env_var: Primary environment variable holding the key.
        api_key_aliases: Further variables checked when the primary is unset.
        requires_api_key: Whether the endpoint refuses unauthenticated
            requests. A local runtime such as Ollama does not.
        base_capabilities: Capability defaults every model of this endpoint
            starts from, refining the dialect's own defaults.
        model_presets: Per-family capability presets, most specific first.
    """

    provider_id: str
    display_name: str
    dialect: ApiDialect | None
    default_api_base: str | None = None
    api_key_env_var: str | None = None
    api_key_aliases: tuple[str, ...] = ()
    requires_api_key: bool = True
    base_capabilities: CapabilityOverride = field(default_factory=CapabilityOverride)
    model_presets: tuple[ModelPreset, ...] = ()

    def capabilities_for(self, model: str) -> CapabilityOverride:
        """Resolve the preset capabilities for one model id.

        Args:
            model: The model id to look up. Matching ignores case and is
                tolerant of a variant suffix, so ``My-Model:free`` matches a
                preset for ``my-model``.

        Returns:
            CapabilityOverride: The endpoint's base capabilities, refined by
            the first model preset whose prefix matches.
        """
        lowered = model.strip().lower()
        return next(
            (
                _merge_overrides(self.base_capabilities, preset.capabilities)
                for preset in self.model_presets
                if lowered.startswith(preset.prefixes)
            ),
            self.base_capabilities,
        )


def _merge_overrides(base: CapabilityOverride, refinement: CapabilityOverride) -> CapabilityOverride:
    """Combine two partial capability records, the refinement winning.

    Args:
        base: The lower-precedence override.
        refinement: The higher-precedence override.

    Returns:
        CapabilityOverride: A new override carrying every field the refinement
        states and ``base``'s value for the rest.
    """
    merged = base.to_mapping()
    merged.update(refinement.to_mapping())
    return CapabilityOverride.from_mapping(merged)


_OPENAI_REASONING = ReasoningSupport(
    supported=True,
    effort_levels=EXTENDED_EFFORT_LEVELS,
    effort_format=ReasoningEffortFormat.NESTED_EFFORT,
    encrypted_content=True,
)

_ANTHROPIC_REASONING = ReasoningSupport(
    supported=True,
    effort_format=ReasoningEffortFormat.THINKING_BUDGET,
    interleaved=True,
)

_GEMINI_REASONING = ReasoningSupport(
    supported=True,
    effort_format=ReasoningEffortFormat.GENERATION_BUDGET,
)

_OPENAI_RESPONSES_FAMILY = CapabilityOverride(
    dialect=ApiDialect.RESPONSES,
    supports_tools=True,
    supports_vision=True,
    supports_temperature=False,
    supports_structured_outputs=True,
    supports_prompt_cache=True,
    supports_prompt_cache_key=True,
    token_limit_field=TokenLimitField.MAX_OUTPUT_TOKENS,
    reasoning=_OPENAI_REASONING,
    tokenizer=TIKTOKEN_O200K,
    tool_count_cap=OPENAI_TOOL_COUNT_CAP,
)

_OPENAI_CHAT_FAMILY = CapabilityOverride(
    dialect=ApiDialect.CHAT_COMPLETIONS,
    supports_tools=True,
    supports_temperature=True,
    token_limit_field=TokenLimitField.MAX_TOKENS,
    tokenizer=TIKTOKEN_O200K,
    tool_count_cap=OPENAI_TOOL_COUNT_CAP,
)

OPENAI_MODEL_PRESETS: Final[tuple[ModelPreset, ...]] = (
    ModelPreset(
        prefixes=("gpt-5", "gpt-6"),
        capabilities=_merge_overrides(
            _OPENAI_RESPONSES_FAMILY,
            CapabilityOverride(context_window=GPT5_CONTEXT_WINDOW),
        ),
    ),
    ModelPreset(
        prefixes=("o1", "o3", "o4", "o5", "o6"),
        capabilities=_merge_overrides(
            _OPENAI_RESPONSES_FAMILY,
            CapabilityOverride(context_window=OPENAI_REASONING_CONTEXT_WINDOW),
        ),
    ),
    ModelPreset(
        prefixes=("gpt-4o", "chatgpt-4o", "gpt-4.1", "gpt-4.5", "gpt-4-turbo"),
        capabilities=_merge_overrides(
            _OPENAI_CHAT_FAMILY,
            CapabilityOverride(context_window=OPENAI_CONTEXT_WINDOW, supports_vision=True),
        ),
    ),
    ModelPreset(
        prefixes=("gpt-3.5",),
        capabilities=_merge_overrides(_OPENAI_CHAT_FAMILY, CapabilityOverride(context_window=16385)),
    ),
    ModelPreset(
        prefixes=("gpt-4",),
        capabilities=_merge_overrides(_OPENAI_CHAT_FAMILY, CapabilityOverride(context_window=8192)),
    ),
)

BUILTIN_PRESETS: Final[dict[str, ProviderPreset]] = {
    provider_ids.ANTHROPIC: ProviderPreset(
        provider_id=provider_ids.ANTHROPIC,
        display_name="Anthropic",
        dialect=ApiDialect.MESSAGES,
        api_key_env_var="ANTHROPIC_API_KEY",
        base_capabilities=CapabilityOverride(
            supports_tools=True,
            supports_vision=True,
            supports_prompt_cache=True,
            supports_temperature=False,
            context_window=ANTHROPIC_CONTEXT_WINDOW,
            token_limit_field=TokenLimitField.MAX_TOKENS,
            reasoning=_ANTHROPIC_REASONING,
            tokenizer=TIKTOKEN_CL100K,
        ),
    ),
    provider_ids.OPENAI: ProviderPreset(
        provider_id=provider_ids.OPENAI,
        display_name="OpenAI",
        dialect=ApiDialect.CHAT_COMPLETIONS,
        api_key_env_var="OPENAI_API_KEY",
        base_capabilities=CapabilityOverride(
            dialect=ApiDialect.CHAT_COMPLETIONS,
            supports_tools=True,
            context_window=OPENAI_CONTEXT_WINDOW,
            token_limit_field=TokenLimitField.MAX_TOKENS,
            tokenizer=TIKTOKEN_O200K,
            tool_count_cap=OPENAI_TOOL_COUNT_CAP,
        ),
        model_presets=OPENAI_MODEL_PRESETS,
    ),
    provider_ids.GOOGLE: ProviderPreset(
        provider_id=provider_ids.GOOGLE,
        display_name="Google Gemini",
        dialect=ApiDialect.GEMINI,
        api_key_env_var="GOOGLE_API_KEY",
        api_key_aliases=("GEMINI_API_KEY",),
        base_capabilities=CapabilityOverride(
            supports_tools=True,
            supports_vision=True,
            context_window=GEMINI_CONTEXT_WINDOW,
            token_limit_field=TokenLimitField.MAX_OUTPUT_TOKENS,
            reasoning=_GEMINI_REASONING,
            tokenizer=TIKTOKEN_CL100K,
        ),
    ),
    provider_ids.OLLAMA: ProviderPreset(
        provider_id=provider_ids.OLLAMA,
        display_name="Ollama",
        dialect=ApiDialect.CHAT_COMPLETIONS,
        default_api_base="http://localhost:11434",
        api_key_env_var="OLLAMA_API_KEY",
        requires_api_key=False,
        base_capabilities=CapabilityOverride(supports_tools=True, tokenizer=TIKTOKEN_CL100K),
    ),
    provider_ids.OPENROUTER: ProviderPreset(
        provider_id=provider_ids.OPENROUTER,
        display_name="OpenRouter",
        dialect=ApiDialect.CHAT_COMPLETIONS,
        default_api_base="https://openrouter.ai/api/v1",
        api_key_env_var="OPENROUTER_API_KEY",
        base_capabilities=CapabilityOverride(supports_tools=True, tokenizer=TIKTOKEN_CL100K),
    ),
    provider_ids.HUGGINGFACE: ProviderPreset(
        provider_id=provider_ids.HUGGINGFACE,
        display_name="HuggingFace",
        dialect=ApiDialect.CHAT_COMPLETIONS,
        default_api_base="https://api-inference.huggingface.co",
        api_key_env_var="HUGGINGFACE_API_TOKEN",
        base_capabilities=CapabilityOverride(supports_tools=True, tokenizer=TIKTOKEN_CL100K),
    ),
    provider_ids.GROK: ProviderPreset(
        provider_id=provider_ids.GROK,
        display_name="Grok",
        dialect=ApiDialect.CHAT_COMPLETIONS,
        default_api_base="https://api.x.ai/v1",
        api_key_env_var="XAI_API_KEY",
        base_capabilities=CapabilityOverride(supports_tools=True, tokenizer=TIKTOKEN_CL100K),
    ),
    provider_ids.LOCAL_TRANSFORMERS: ProviderPreset(
        provider_id=provider_ids.LOCAL_TRANSFORMERS,
        display_name="Local Transformers",
        dialect=None,
        api_key_env_var="LOCAL_TRANSFORMERS_HF_TOKEN",
        api_key_aliases=("HUGGINGFACE_API_TOKEN",),
        requires_api_key=False,
        base_capabilities=CapabilityOverride(supports_tools=True, tokenizer=TIKTOKEN_CL100K),
    ),
}
"""The eight built-in providers, as presets that materialize into instances."""

COMPATIBLE_PRESETS: Final[dict[str, ProviderPreset]] = {
    "litellm": ProviderPreset(
        provider_id="litellm",
        display_name="LiteLLM proxy",
        dialect=ApiDialect.CHAT_COMPLETIONS,
        default_api_base="http://localhost:4000/v1",
        requires_api_key=False,
        base_capabilities=CapabilityOverride(supports_tools=True),
    ),
    "vllm": ProviderPreset(
        provider_id="vllm",
        display_name="vLLM",
        dialect=ApiDialect.CHAT_COMPLETIONS,
        default_api_base="http://localhost:8000/v1",
        requires_api_key=False,
        base_capabilities=CapabilityOverride(supports_tools=True),
    ),
    "lm-studio": ProviderPreset(
        provider_id="lm-studio",
        display_name="LM Studio",
        dialect=ApiDialect.CHAT_COMPLETIONS,
        default_api_base="http://localhost:1234/v1",
        requires_api_key=False,
        base_capabilities=CapabilityOverride(supports_tools=True),
    ),
    "together": ProviderPreset(
        provider_id="together",
        display_name="Together AI",
        dialect=ApiDialect.CHAT_COMPLETIONS,
        default_api_base="https://api.together.xyz/v1",
        api_key_env_var="TOGETHER_API_KEY",
        base_capabilities=CapabilityOverride(supports_tools=True),
    ),
    "groq": ProviderPreset(
        provider_id="groq",
        display_name="Groq",
        dialect=ApiDialect.CHAT_COMPLETIONS,
        default_api_base="https://api.groq.com/openai/v1",
        api_key_env_var="GROQ_API_KEY",
        base_capabilities=CapabilityOverride(supports_tools=True),
    ),
    "cerebras": ProviderPreset(
        provider_id="cerebras",
        display_name="Cerebras",
        dialect=ApiDialect.CHAT_COMPLETIONS,
        default_api_base="https://api.cerebras.ai/v1",
        api_key_env_var="CEREBRAS_API_KEY",
        base_capabilities=CapabilityOverride(supports_tools=True),
    ),
    "deepseek": ProviderPreset(
        provider_id="deepseek",
        display_name="DeepSeek",
        dialect=ApiDialect.CHAT_COMPLETIONS,
        default_api_base="https://api.deepseek.com/v1",
        api_key_env_var="DEEPSEEK_API_KEY",
        base_capabilities=CapabilityOverride(
            supports_tools=True,
            reasoning=ReasoningSupport(supported=True, reasoning_key="reasoning_content"),
        ),
    ),
    "anthropic-gateway": ProviderPreset(
        provider_id="anthropic-gateway",
        display_name="Anthropic-compatible gateway",
        dialect=ApiDialect.MESSAGES,
        base_capabilities=CapabilityOverride(supports_tools=True, supports_temperature=False),
    ),
    "openai-gateway": ProviderPreset(
        provider_id="openai-gateway",
        display_name="OpenAI-compatible gateway",
        dialect=ApiDialect.CHAT_COMPLETIONS,
        base_capabilities=CapabilityOverride(supports_tools=True),
    ),
}
"""Starting points for the endpoints users most often add by hand.

Each is a starting point, not a constraint: the base URL, headers, key and per-model capabilities all stay editable once an instance is
created from one.
"""


def all_presets() -> dict[str, ProviderPreset]:
    """Return every preset, built-in and compatible-endpoint alike.

    Returns:
        dict[str, ProviderPreset]: Presets keyed by their preset id.
    """
    combined: dict[str, ProviderPreset] = dict(BUILTIN_PRESETS)
    combined |= COMPATIBLE_PRESETS
    return combined


def preset_for(preset_id: str) -> ProviderPreset | None:
    """Look one preset up by id.

    Args:
        preset_id: The preset id, which for a built-in equals its provider id.

    Returns:
        ProviderPreset | None: The preset, or ``None`` when none matches.
    """
    return all_presets().get(preset_id.strip().lower())


def preset_capabilities(preset_id: str, model: str) -> CapabilityOverride:
    """Resolve the preset capability layer for one preset's model.

    Args:
        preset_id: The preset id to look up.
        model: The model id whose capabilities are wanted.

    Returns:
        CapabilityOverride: The preset's capabilities for that model, or an
        empty override when the preset is unknown.
    """
    preset = preset_for(preset_id)
    if preset is None:
        _logger.debug("preset_unknown", preset_id=preset_id)
        return CapabilityOverride()
    return preset.capabilities_for(model)
