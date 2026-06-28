# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for provider display names and no-key provider policy."""

from __future__ import annotations

from intellicrack.core.types import ProviderName
from intellicrack.providers.display_names import (
    NO_API_KEY_PROVIDER_IDS,
    NO_API_KEY_PROVIDERS,
    provider_display_name,
)


class TestProviderDisplayName:
    """Human-readable provider labels."""

    @staticmethod
    def test_local_transformers_uses_spaces() -> None:
        """Local Transformers must not expose underscore identifiers in the UI."""
        assert provider_display_name(ProviderName.LOCAL_TRANSFORMERS) == "Local Transformers"
        assert provider_display_name("local_transformers") == "Local Transformers"

    @staticmethod
    def test_known_provider_aliases() -> None:
        """Mapped providers return stable display labels."""
        assert provider_display_name(ProviderName.GOOGLE) == "Google Gemini"
        assert provider_display_name(ProviderName.ANTHROPIC) == "Anthropic"

    @staticmethod
    def test_unknown_provider_fallback_titleizes_underscores() -> None:
        """Unknown provider ids fall back to a readable title."""
        assert provider_display_name("future_provider_name") == "Future Provider Name"


class TestNoApiKeyProviders:
    """Credential-optional provider policy."""

    @staticmethod
    def test_local_transformers_and_ollama_are_no_key() -> None:
        """Local and Ollama providers do not require API keys to connect."""
        assert ProviderName.LOCAL_TRANSFORMERS in NO_API_KEY_PROVIDERS
        assert ProviderName.OLLAMA in NO_API_KEY_PROVIDERS
        assert "local_transformers" in NO_API_KEY_PROVIDER_IDS
        assert "ollama" in NO_API_KEY_PROVIDER_IDS
