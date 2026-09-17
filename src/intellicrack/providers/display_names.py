# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Human-readable provider labels and credential policy helpers."""

from __future__ import annotations

from intellicrack.providers import ids as provider_ids


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

NO_API_KEY_PROVIDERS: frozenset[str] = frozenset({
    provider_ids.OLLAMA,
    provider_ids.LOCAL_TRANSFORMERS,
})

NO_API_KEY_PROVIDER_IDS: frozenset[str] = NO_API_KEY_PROVIDERS


def provider_display_name(provider: str) -> str:
    """Return a human-readable label for a provider.

    Args:
        provider: Provider instance id.

    Returns:
        str: Display label with underscores removed and known aliases applied.
    """
    return PROVIDER_DISPLAY_NAMES.get(provider, provider.replace("_", " ").title())
