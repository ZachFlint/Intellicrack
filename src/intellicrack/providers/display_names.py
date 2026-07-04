# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Human-readable provider labels and credential policy helpers."""

from __future__ import annotations

from intellicrack.core.types import ProviderName


PROVIDER_DISPLAY_NAMES: dict[str, str] = {
    "anthropic": "Anthropic",
    "openai": "OpenAI",
    "google": "Google Gemini",
    "ollama": "Ollama",
    "openrouter": "OpenRouter",
    "huggingface": "HuggingFace",
    "grok": "Grok",
    "local_transformers": "Local Transformers",
}

NO_API_KEY_PROVIDERS: frozenset[ProviderName] = frozenset({
    ProviderName.OLLAMA,
    ProviderName.LOCAL_TRANSFORMERS,
})

NO_API_KEY_PROVIDER_IDS: frozenset[str] = frozenset(provider.value for provider in NO_API_KEY_PROVIDERS)


def provider_display_name(provider: ProviderName | str) -> str:
    """Return a human-readable label for a provider.

    Args:
        provider: Provider enum value or provider identifier string.

    Returns:
        str: Display label with underscores removed and known aliases applied.
    """
    key = provider.value if isinstance(provider, ProviderName) else provider
    return PROVIDER_DISPLAY_NAMES.get(key, key.replace("_", " ").title())
