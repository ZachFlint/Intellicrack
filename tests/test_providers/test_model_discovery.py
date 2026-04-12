# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Integration tests that display dynamically fetched models from each provider.

These tests fetch and verify the actual models available from each provider's API.
Run with pytest -v -s to see the model output.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from intellicrack.credentials.store import CredentialLoader

from intellicrack.core.types import ProviderCredentials, ProviderName
from intellicrack.providers.anthropic import AnthropicProvider
from intellicrack.providers.google import GoogleProvider
from intellicrack.providers.ollama import OllamaProvider
from intellicrack.providers.openai import OpenAIProvider
from intellicrack.providers.openrouter import OpenRouterProvider


_logger = logging.getLogger(__name__)


@pytest.mark.integration
class TestModelDiscoveryDisplay:
    """Tests that fetch and verify available models from each provider."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_display_openai_models(
        openai_provider: OpenAIProvider,
    ) -> None:
        """Fetch and verify all available OpenAI models.

        Args:
            openai_provider: Connected OpenAI provider fixture.
        """
        models = await openai_provider.list_models()

        _logger.info("OPENAI MODELS: %d total", len(models))
        for model in sorted(models, key=lambda m: m.id):
            assert model.id, "Model ID should not be empty"

        assert len(models) > 0, "OpenAI should return models"

    @pytest.mark.asyncio
    @staticmethod
    async def test_display_google_models(
        google_provider: GoogleProvider,
    ) -> None:
        """Fetch and verify all available Google Gemini models.

        Args:
            google_provider: Connected Google provider fixture.
        """
        models = await google_provider.list_models()

        _logger.info("GOOGLE GEMINI MODELS: %d total", len(models))
        for model in sorted(models, key=lambda m: m.id):
            assert model.id, "Model ID should not be empty"

        assert len(models) > 0, "Google should return models"

    @pytest.mark.asyncio
    @staticmethod
    async def test_display_openrouter_models(
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Fetch and verify all available OpenRouter models.

        Args:
            openrouter_provider: Connected OpenRouter provider fixture.
        """
        models = await openrouter_provider.list_models()

        _logger.info("OPENROUTER MODELS: %d total", len(models))

        by_provider: dict[str, list[str]] = {}
        for model in models:
            provider_prefix = model.id.split("/")[0] if "/" in model.id else "other"
            if provider_prefix not in by_provider:
                by_provider[provider_prefix] = []
            by_provider[provider_prefix].append(model.id)

        for provider_prefix in sorted(by_provider.keys()):
            model_ids = by_provider[provider_prefix]
            _logger.info("[%s] %d models", provider_prefix, len(model_ids))

        assert len(models) > 0, "OpenRouter should return models"

    @pytest.mark.asyncio
    @staticmethod
    async def test_display_anthropic_models(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Fetch and verify all available Anthropic Claude models.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        models = await anthropic_provider.list_models()

        _logger.info("ANTHROPIC CLAUDE MODELS: %d total", len(models))
        for model in sorted(models, key=lambda m: m.id):
            assert model.id, "Model ID should not be empty"

        assert len(models) > 0, "Anthropic should return models"

    @pytest.mark.asyncio
    @staticmethod
    async def test_display_ollama_models(
        ollama_provider: OllamaProvider,
    ) -> None:
        """Fetch and verify all locally installed Ollama models.

        Args:
            ollama_provider: Connected Ollama provider fixture.
        """
        models = await ollama_provider.list_models()

        _logger.info("OLLAMA LOCAL MODELS: %d total", len(models))
        for model in models:
            assert model.id, "Model ID should not be empty"


@pytest.mark.integration
class TestAllProvidersModelCount:
    """Summary test showing model counts across all configured providers."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_summary_all_providers(
        credential_loader: CredentialLoader,
        *,
        has_openai_key: bool,
        has_google_key: bool,
        has_openrouter_key: bool,
        has_anthropic_key: bool,
        has_ollama_available: bool,
    ) -> None:
        """Verify models available from all configured providers.

        Args:
            credential_loader: Credential loader fixture.
            has_openai_key: Whether an OpenAI API key is configured.
            has_google_key: Whether a Google API key is configured.
            has_openrouter_key: Whether an OpenRouter API key is configured.
            has_anthropic_key: Whether an Anthropic API key is configured.
            has_ollama_available: Whether a local Ollama server is running.
        """
        results: dict[str, int | str] = {}

        if has_openai_key:
            openai_prov = OpenAIProvider()
            creds = credential_loader.get_credentials(ProviderName.OPENAI)
            await openai_prov.connect(creds)
            models = await openai_prov.list_models()
            results["OpenAI"] = len(models)
            await openai_prov.disconnect()
        else:
            results["OpenAI"] = "NOT CONFIGURED"

        if has_google_key:
            google_prov = GoogleProvider()
            creds = credential_loader.get_credentials(ProviderName.GOOGLE)
            await google_prov.connect(creds)
            models = await google_prov.list_models()
            results["Google"] = len(models)
            await google_prov.disconnect()
        else:
            results["Google"] = "NOT CONFIGURED"

        if has_openrouter_key:
            openrouter_prov = OpenRouterProvider()
            creds = credential_loader.get_credentials(ProviderName.OPENROUTER)
            await openrouter_prov.connect(creds)
            models = await openrouter_prov.list_models()
            results["OpenRouter"] = len(models)
            await openrouter_prov.disconnect()
        else:
            results["OpenRouter"] = "NOT CONFIGURED"

        if has_anthropic_key:
            anthropic_prov = AnthropicProvider()
            creds = credential_loader.get_credentials(ProviderName.ANTHROPIC)
            await anthropic_prov.connect(creds)
            models = await anthropic_prov.list_models()
            results["Anthropic"] = len(models)
            await anthropic_prov.disconnect()
        else:
            results["Anthropic"] = "NOT CONFIGURED"

        if has_ollama_available:
            ollama_prov = OllamaProvider()
            creds = credential_loader.get_credentials(ProviderName.OLLAMA)
            if creds is None:
                creds = ProviderCredentials(api_base="http://localhost:11434")
            await ollama_prov.connect(creds)
            models = await ollama_prov.list_models()
            results["Ollama"] = len(models)
            await ollama_prov.disconnect()
        else:
            results["Ollama"] = "NOT RUNNING"

        for provider_name, count in results.items():
            if isinstance(count, int):
                _logger.info("%s: %d models", provider_name, count)
            else:
                _logger.info("%s: %s", provider_name, count)

        configured_count = sum(isinstance(v, int) for v in results.values())
        assert configured_count > 0, "At least one provider should be configured"
