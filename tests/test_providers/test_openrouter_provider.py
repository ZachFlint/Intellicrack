"""Integration tests for OpenRouterProvider model listing.

These tests require a valid OPENROUTER_API_KEY in the .env file.
Tests will be skipped if credentials are not available.

All tests use LIVE API calls - NO hardcoded model names.
"""

from __future__ import annotations

import pytest

from intellicrack.core.types import (
    AuthenticationError,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    ProviderName,
)
from intellicrack.providers.openrouter import OpenRouterProvider


@pytest.mark.integration
class TestOpenRouterModelListing:
    """Tests for OpenRouter model listing functionality.

    These tests validate that OpenRouterProvider can dynamically fetch
    models from the OpenRouter API. NO hardcoded model names are used.
    """

    @pytest.mark.asyncio
    async def test_list_models_returns_non_empty_list(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test list_models returns at least one model.

        This validates that the API call works and returns actual data.
        OpenRouter aggregates many providers so should have many models.
        """
        models = await openrouter_provider.list_models()

        assert isinstance(models, list), f"Expected list, got {type(models)}"
        assert len(models) > 0, "Expected at least one model from OpenRouter API"

    @pytest.mark.asyncio
    async def test_list_models_returns_many_models(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test OpenRouter returns many models (it's an aggregator)."""
        models = await openrouter_provider.list_models()

        assert len(models) >= 10, f"Expected at least 10 models from OpenRouter, got {len(models)}"

    @pytest.mark.asyncio
    async def test_list_models_returns_model_info_instances(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test all returned items are ModelInfo instances."""
        models = await openrouter_provider.list_models()

        for model in models[:20]:
            assert isinstance(model, ModelInfo), f"Expected ModelInfo, got {type(model)}"

    @pytest.mark.asyncio
    async def test_model_info_has_valid_id(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test all models have non-empty string IDs."""
        models = await openrouter_provider.list_models()

        for model in models[:20]:
            assert isinstance(model.id, str), f"Expected str id, got {type(model.id)}"
            assert len(model.id) > 0, "Model ID should not be empty"

    @pytest.mark.asyncio
    async def test_model_info_has_valid_name(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test all models have non-empty string names."""
        models = await openrouter_provider.list_models()

        for model in models[:20]:
            assert isinstance(model.name, str), f"Expected str name, got {type(model.name)}"
            assert len(model.name) > 0, "Model name should not be empty"

    @pytest.mark.asyncio
    async def test_model_info_has_correct_provider(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test all models report OPENROUTER as provider."""
        models = await openrouter_provider.list_models()

        for model in models[:20]:
            assert model.provider == ProviderName.OPENROUTER, f"Expected OPENROUTER provider, got {model.provider}"

    @pytest.mark.asyncio
    async def test_model_info_has_positive_context_window(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test all models have positive context window size."""
        models = await openrouter_provider.list_models()

        for model in models[:20]:
            assert isinstance(model.context_window, int), f"Expected int context_window, got {type(model.context_window)}"
            assert model.context_window > 0, f"Model {model.id} has invalid context_window: {model.context_window}"

    @pytest.mark.asyncio
    async def test_model_info_has_boolean_capabilities(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test all models have boolean capability flags."""
        models = await openrouter_provider.list_models()

        for model in models[:20]:
            assert isinstance(model.supports_tools, bool), f"Expected bool supports_tools, got {type(model.supports_tools)}"
            assert isinstance(model.supports_vision, bool), f"Expected bool supports_vision, got {type(model.supports_vision)}"
            assert isinstance(model.supports_streaming, bool), f"Expected bool supports_streaming, got {type(model.supports_streaming)}"

    @pytest.mark.asyncio
    async def test_model_info_may_have_pricing(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test that some models have pricing information."""
        models = await openrouter_provider.list_models()

        models_with_pricing = [m for m in models if m.input_cost_per_1m_tokens is not None]

        assert models_with_pricing, "Expected at least some models to have pricing information"

    @pytest.mark.asyncio
    async def test_multiple_calls_return_consistent_results(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test list_models returns consistent results across calls."""
        models1 = await openrouter_provider.list_models()
        models2 = await openrouter_provider.list_models()

        ids1 = {m.id for m in models1}
        ids2 = {m.id for m in models2}

        assert ids1 == ids2, "Model IDs should be consistent across calls"


@pytest.mark.integration
class TestOpenRouterConnection:
    """Tests for OpenRouter provider connection handling."""

    @pytest.mark.asyncio
    async def test_is_connected_after_connect(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test provider reports connected after successful connection."""
        assert openrouter_provider.is_connected is True

    @pytest.mark.asyncio
    async def test_provider_name_is_openrouter(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test provider name property returns OPENROUTER."""
        assert openrouter_provider.name == ProviderName.OPENROUTER

    @pytest.mark.asyncio
    async def test_connection_with_invalid_key_may_succeed_initially(self) -> None:
        """Test connection with invalid API key may not fail immediately.

        OpenRouter validates API keys when making actual requests, not
        during the initial connection. The models endpoint may return
        results even with an invalid key format.
        """
        provider = OpenRouterProvider()
        invalid_creds = ProviderCredentials(api_key="sk-or-invalid-key-12345")

        try:
            await provider.connect(invalid_creds)
            await provider.disconnect()
        except AuthenticationError:
            pass

    @pytest.mark.asyncio
    async def test_connection_with_empty_key_raises_error(self) -> None:
        """Test connection with empty API key raises AuthenticationError."""
        provider = OpenRouterProvider()
        empty_creds = ProviderCredentials(api_key="")

        with pytest.raises(AuthenticationError):
            await provider.connect(empty_creds)

    @pytest.mark.asyncio
    async def test_list_models_without_connection_raises_error(self) -> None:
        """Test list_models raises error when not connected."""
        provider = OpenRouterProvider()

        with pytest.raises(ProviderError):
            await provider.list_models()

    @pytest.mark.asyncio
    async def test_disconnect_clears_connection_state(
        self,
        credential_loader,
        has_openrouter_key: bool,
    ) -> None:
        """Test disconnect properly clears connection state."""
        if not has_openrouter_key:
            pytest.skip("OPENROUTER_API_KEY not configured")

        provider = OpenRouterProvider()
        credentials = credential_loader.get_credentials(ProviderName.OPENROUTER)
        assert credentials is not None

        await provider.connect(credentials)
        assert provider.is_connected is True

        await provider.disconnect()
        assert provider.is_connected is False
