# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Integration tests for OllamaProvider model listing.

These tests require Ollama to be running locally at http://localhost:11434.
Tests will be skipped if Ollama is not available.

All tests use LIVE API calls - NO hardcoded model names.
"""

from __future__ import annotations

import pytest

from intellicrack.core.types import (
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    ProviderName,
)
from intellicrack.providers.ollama import OllamaProvider


@pytest.mark.integration
class TestOllamaModelListing:
    """Tests for Ollama model listing functionality.

    These tests validate that OllamaProvider can dynamically fetch
    locally installed models. NO hardcoded model names are used.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_returns_list(
        ollama_provider: OllamaProvider,
    ) -> None:
        """Test list_models returns a list (may be empty if no models installed)."""
        models = await ollama_provider.list_models()

        assert isinstance(models, list), f"Expected list, got {type(models)}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_returns_model_info_instances(
        ollama_provider: OllamaProvider,
    ) -> None:
        """Test all returned items are ModelInfo instances."""
        models = await ollama_provider.list_models()

        for model in models:
            assert isinstance(model, ModelInfo), f"Expected ModelInfo, got {type(model)}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_valid_id_when_present(
        ollama_provider: OllamaProvider,
    ) -> None:
        """Test all models have non-empty string IDs."""
        models = await ollama_provider.list_models()

        for model in models:
            assert isinstance(model.id, str), f"Expected str id, got {type(model.id)}"
            assert len(model.id) > 0, "Model ID should not be empty"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_valid_name_when_present(
        ollama_provider: OllamaProvider,
    ) -> None:
        """Test all models have non-empty string names."""
        models = await ollama_provider.list_models()

        for model in models:
            assert isinstance(model.name, str), f"Expected str name, got {type(model.name)}"
            assert len(model.name) > 0, "Model name should not be empty"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_correct_provider(
        ollama_provider: OllamaProvider,
    ) -> None:
        """Test all models report OLLAMA as provider."""
        models = await ollama_provider.list_models()

        for model in models:
            assert model.provider == ProviderName.OLLAMA, f"Expected OLLAMA provider, got {model.provider}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_positive_context_window(
        ollama_provider: OllamaProvider,
    ) -> None:
        """Test all models have positive context window size."""
        models = await ollama_provider.list_models()

        for model in models:
            assert isinstance(model.context_window, int), f"Expected int context_window, got {type(model.context_window)}"
            assert model.context_window > 0, f"Model {model.id} has invalid context_window: {model.context_window}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_boolean_capabilities(
        ollama_provider: OllamaProvider,
    ) -> None:
        """Test all models have boolean capability flags."""
        models = await ollama_provider.list_models()

        for model in models:
            assert isinstance(model.supports_tools, bool), f"Expected bool supports_tools, got {type(model.supports_tools)}"
            assert isinstance(model.supports_vision, bool), f"Expected bool supports_vision, got {type(model.supports_vision)}"
            assert isinstance(model.supports_streaming, bool), f"Expected bool supports_streaming, got {type(model.supports_streaming)}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_multiple_calls_return_consistent_results(
        ollama_provider: OllamaProvider,
    ) -> None:
        """Test list_models returns consistent results across calls."""
        models1 = await ollama_provider.list_models()
        models2 = await ollama_provider.list_models()

        ids1 = {m.id for m in models1}
        ids2 = {m.id for m in models2}

        assert ids1 == ids2, "Model IDs should be consistent across calls"


@pytest.mark.integration
class TestOllamaConnection:
    """Tests for Ollama provider connection handling."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_is_connected_after_connect(
        ollama_provider: OllamaProvider,
    ) -> None:
        """Test provider reports connected after successful connection."""
        assert ollama_provider.is_connected is True

    @pytest.mark.asyncio
    @staticmethod
    async def test_provider_name_is_ollama(
        ollama_provider: OllamaProvider,
    ) -> None:
        """Test provider name property returns OLLAMA."""
        assert ollama_provider.name == ProviderName.OLLAMA

    @pytest.mark.asyncio
    @staticmethod
    async def test_connection_with_custom_base_url(
        *,
        has_ollama_available: bool,
    ) -> None:
        """Test connection with custom base URL."""
        if not has_ollama_available:
            pytest.skip("Ollama not running locally")

        provider = OllamaProvider()
        creds = ProviderCredentials(
            api_key=None,
            api_base="http://localhost:11434",
        )

        await provider.connect(creds)
        assert provider.is_connected is True
        await provider.disconnect()

    @pytest.mark.asyncio
    @staticmethod
    async def test_connection_with_invalid_url_raises_error() -> None:
        """Test connection with unreachable URL raises ProviderError."""
        provider = OllamaProvider()
        invalid_creds = ProviderCredentials(
            api_key=None,
            api_base="http://localhost:99999",
        )

        with pytest.raises(ProviderError):
            await provider.connect(invalid_creds)

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_without_connection_raises_error() -> None:
        """Test list_models raises error when not connected."""
        provider = OllamaProvider()

        with pytest.raises(ProviderError):
            await provider.list_models()

    @pytest.mark.asyncio
    @staticmethod
    async def test_disconnect_clears_connection_state(
        *,
        has_ollama_available: bool,
    ) -> None:
        """Test disconnect properly clears connection state."""
        if not has_ollama_available:
            pytest.skip("Ollama not running locally")

        provider = OllamaProvider()
        creds = ProviderCredentials(
            api_key=None,
            api_base="http://localhost:11434",
        )

        await provider.connect(creds)
        assert provider.is_connected is True

        await provider.disconnect()
        assert provider.is_connected is False
