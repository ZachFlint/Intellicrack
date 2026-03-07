"""Integration tests for OpenAIProvider model listing.

These tests require a valid OPENAI_API_KEY in the .env file.
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
from intellicrack.providers.openai import OpenAIProvider


@pytest.mark.integration
class TestOpenAIModelListing:
    """Tests for OpenAI model listing functionality.

    These tests validate that OpenAIProvider can dynamically fetch
    models from the OpenAI API. NO hardcoded model names are used.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_returns_non_empty_list(
        openai_provider: OpenAIProvider,
    ) -> None:
        """Test list_models returns at least one model.

        This validates that the API call works and returns actual data.
        We don't hardcode model names - just verify we get models.
        """
        models = await openai_provider.list_models()

        assert isinstance(models, list), f"Expected list, got {type(models)}"
        assert len(models) > 0, "Expected at least one model from OpenAI API"

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_returns_model_info_instances(
        openai_provider: OpenAIProvider,
    ) -> None:
        """Test all returned items are ModelInfo instances."""
        models = await openai_provider.list_models()

        for model in models:
            assert isinstance(model, ModelInfo), f"Expected ModelInfo, got {type(model)}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_valid_id(
        openai_provider: OpenAIProvider,
    ) -> None:
        """Test all models have non-empty string IDs."""
        models = await openai_provider.list_models()

        for model in models:
            assert isinstance(model.id, str), f"Expected str id, got {type(model.id)}"
            assert len(model.id) > 0, "Model ID should not be empty"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_valid_name(
        openai_provider: OpenAIProvider,
    ) -> None:
        """Test all models have non-empty string names."""
        models = await openai_provider.list_models()

        for model in models:
            assert isinstance(model.name, str), f"Expected str name, got {type(model.name)}"
            assert len(model.name) > 0, "Model name should not be empty"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_correct_provider(
        openai_provider: OpenAIProvider,
    ) -> None:
        """Test all models report OPENAI as provider."""
        models = await openai_provider.list_models()

        for model in models:
            assert model.provider == ProviderName.OPENAI, f"Expected OPENAI provider, got {model.provider}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_positive_context_window(
        openai_provider: OpenAIProvider,
    ) -> None:
        """Test all models have positive context window size."""
        models = await openai_provider.list_models()

        for model in models:
            assert isinstance(model.context_window, int), f"Expected int context_window, got {type(model.context_window)}"
            assert model.context_window > 0, f"Model {model.id} has invalid context_window: {model.context_window}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_boolean_capabilities(
        openai_provider: OpenAIProvider,
    ) -> None:
        """Test all models have boolean capability flags."""
        models = await openai_provider.list_models()

        for model in models:
            assert isinstance(model.supports_tools, bool), f"Expected bool supports_tools, got {type(model.supports_tools)}"
            assert isinstance(model.supports_vision, bool), f"Expected bool supports_vision, got {type(model.supports_vision)}"
            assert isinstance(model.supports_streaming, bool), f"Expected bool supports_streaming, got {type(model.supports_streaming)}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_models_have_valid_provider(
        openai_provider: OpenAIProvider,
    ) -> None:
        """Test that all returned models have the correct provider set."""
        models = await openai_provider.list_models()

        for model in models:
            assert model.provider == ProviderName.OPENAI, f"Model {model.id} has wrong provider {model.provider}"
            assert model.id, "Model has empty id"
            assert model.context_window > 0, f"Model {model.id} has invalid context window"

    @pytest.mark.asyncio
    @staticmethod
    async def test_multiple_calls_return_consistent_results(
        openai_provider: OpenAIProvider,
    ) -> None:
        """Test list_models returns consistent results across calls."""
        models1 = await openai_provider.list_models()
        models2 = await openai_provider.list_models()

        ids1 = {m.id for m in models1}
        ids2 = {m.id for m in models2}

        assert ids1 == ids2, "Model IDs should be consistent across calls"


@pytest.mark.integration
class TestOpenAIConnection:
    """Tests for OpenAI provider connection handling."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_is_connected_after_connect(
        openai_provider: OpenAIProvider,
    ) -> None:
        """Test provider reports connected after successful connection."""
        assert openai_provider.is_connected is True

    @pytest.mark.asyncio
    @staticmethod
    async def test_provider_name_is_openai(
        openai_provider: OpenAIProvider,
    ) -> None:
        """Test provider name property returns OPENAI."""
        assert openai_provider.name == ProviderName.OPENAI

    @pytest.mark.asyncio
    @staticmethod
    async def test_connection_with_invalid_key_raises_error() -> None:
        """Test connection with invalid API key raises AuthenticationError."""
        provider = OpenAIProvider()
        invalid_creds = ProviderCredentials(api_key="sk-invalid-key-12345")

        with pytest.raises(AuthenticationError):
            await provider.connect(invalid_creds)

    @pytest.mark.asyncio
    @staticmethod
    async def test_connection_with_empty_key_raises_error() -> None:
        """Test connection with empty API key raises AuthenticationError."""
        provider = OpenAIProvider()
        empty_creds = ProviderCredentials(api_key="")

        with pytest.raises(AuthenticationError):
            await provider.connect(empty_creds)

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_without_connection_raises_error() -> None:
        """Test list_models raises error when not connected."""
        provider = OpenAIProvider()

        with pytest.raises(ProviderError):
            await provider.list_models()

    @pytest.mark.asyncio
    @staticmethod
    async def test_disconnect_clears_connection_state(
        credential_loader,
        has_openai_key: bool,
    ) -> None:
        """Test disconnect properly clears connection state."""
        if not has_openai_key:
            pytest.skip("OPENAI_API_KEY not configured")

        provider = OpenAIProvider()
        credentials = credential_loader.get_credentials(ProviderName.OPENAI)
        assert credentials is not None

        await provider.connect(credentials)
        assert provider.is_connected is True

        await provider.disconnect()
        assert provider.is_connected is False
