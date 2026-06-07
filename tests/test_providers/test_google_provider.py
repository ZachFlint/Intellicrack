# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Integration tests for GoogleProvider model listing.

These tests require a valid GOOGLE_API_KEY in the .env file.
Tests will be skipped if credentials are not available.

All tests use LIVE API calls - NO hardcoded model names.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from intellicrack.credentials.store import CredentialLoader

from intellicrack.core.types import (
    AuthenticationError,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    ProviderName,
)
from intellicrack.providers.google import GoogleProvider


@pytest.mark.integration
class TestGoogleModelListing:
    """Tests for Google model listing functionality.

    These tests validate that GoogleProvider can dynamically fetch
    models from the Google AI API. NO hardcoded model names are used.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_returns_non_empty_list(
        google_provider: GoogleProvider,
    ) -> None:
        """Test list_models returns at least one Gemini model with a valid structure.

        Validates that the API call works, returns actual data, and that the returned
        models are Gemini generative models with non-empty string IDs.  The ``len > 0``
        check alone cannot detect an API regression where an empty list is returned.
        The Gemini model ID check ensures the bridge is actually filtering and mapping
        Google API responses to the correct provider and model type.

        Args:
            google_provider: Connected Google provider fixture.
        """
        models = await google_provider.list_models()

        assert isinstance(models, list), f"Expected list, got {type(models)}"
        assert len(models) > 0, "Expected at least one model from Google AI API"

        gemini_models = [m for m in models if "gemini" in m.id.lower()]
        assert len(gemini_models) > 0, (
            f"Expected at least one Gemini model in the response, "
            f"but none of the {len(models)} returned models have 'gemini' in their id. "
            f"IDs returned: {[m.id for m in models[:5]]}"
        )

        first_gemini = gemini_models[0]
        assert isinstance(first_gemini.id, str)
        assert len(first_gemini.id) > 0
        assert first_gemini.provider == ProviderName.GOOGLE
        assert isinstance(first_gemini.context_window, int)
        assert first_gemini.context_window > 0

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_returns_model_info_instances(
        google_provider: GoogleProvider,
    ) -> None:
        """Test all returned items are ModelInfo instances.

        Args:
            google_provider: Connected Google provider fixture.
        """
        models = await google_provider.list_models()

        for model in models:
            assert isinstance(model, ModelInfo), f"Expected ModelInfo, got {type(model)}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_valid_id(
        google_provider: GoogleProvider,
    ) -> None:
        """Test all models have non-empty string IDs.

        Args:
            google_provider: Connected Google provider fixture.
        """
        models = await google_provider.list_models()

        for model in models:
            assert isinstance(model.id, str), f"Expected str id, got {type(model.id)}"
            assert len(model.id) > 0, "Model ID should not be empty"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_valid_name(
        google_provider: GoogleProvider,
    ) -> None:
        """Test all models have non-empty string names.

        Args:
            google_provider: Connected Google provider fixture.
        """
        models = await google_provider.list_models()

        for model in models:
            assert isinstance(model.name, str), f"Expected str name, got {type(model.name)}"
            assert len(model.name) > 0, "Model name should not be empty"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_correct_provider(
        google_provider: GoogleProvider,
    ) -> None:
        """Test all models report GOOGLE as provider.

        Args:
            google_provider: Connected Google provider fixture.
        """
        models = await google_provider.list_models()

        for model in models:
            assert model.provider == ProviderName.GOOGLE, f"Expected GOOGLE provider, got {model.provider}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_positive_context_window(
        google_provider: GoogleProvider,
    ) -> None:
        """Test all models have positive context window size.

        Args:
            google_provider: Connected Google provider fixture.
        """
        models = await google_provider.list_models()

        for model in models:
            assert isinstance(model.context_window, int), f"Expected int context_window, got {type(model.context_window)}"
            assert model.context_window > 0, f"Model {model.id} has invalid context_window: {model.context_window}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_boolean_capabilities(
        google_provider: GoogleProvider,
    ) -> None:
        """Test all models have boolean capability flags.

        Args:
            google_provider: Connected Google provider fixture.
        """
        models = await google_provider.list_models()

        for model in models:
            assert isinstance(model.supports_tools, bool), f"Expected bool supports_tools, got {type(model.supports_tools)}"
            assert isinstance(model.supports_vision, bool), f"Expected bool supports_vision, got {type(model.supports_vision)}"
            assert isinstance(model.supports_streaming, bool), f"Expected bool supports_streaming, got {type(model.supports_streaming)}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_models_are_gemini_models(
        google_provider: GoogleProvider,
    ) -> None:
        """Test that returned models are Gemini generative models.

        Args:
            google_provider: Connected Google provider fixture.
        """
        models = await google_provider.list_models()

        for model in models:
            assert "gemini" in model.id.lower(), f"Model {model.id} doesn't appear to be a Gemini model"

    @pytest.mark.asyncio
    @staticmethod
    async def test_multiple_calls_return_consistent_results(
        google_provider: GoogleProvider,
    ) -> None:
        """Test list_models returns consistent results across calls.

        Args:
            google_provider: Connected Google provider fixture.
        """
        models1 = await google_provider.list_models()
        models2 = await google_provider.list_models()

        ids1 = {m.id for m in models1}
        ids2 = {m.id for m in models2}

        assert ids1 == ids2, "Model IDs should be consistent across calls"


@pytest.mark.integration
class TestGoogleConnection:
    """Tests for Google provider connection handling."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_is_connected_after_connect(
        google_provider: GoogleProvider,
    ) -> None:
        """Test provider reports connected after successful connection.

        Args:
            google_provider: Connected Google provider fixture.
        """
        assert google_provider.is_connected is True

    @pytest.mark.asyncio
    @staticmethod
    async def test_provider_name_is_google(
        google_provider: GoogleProvider,
    ) -> None:
        """Test provider name property returns GOOGLE.

        Args:
            google_provider: Connected Google provider fixture.
        """
        assert google_provider.name == ProviderName.GOOGLE

    @pytest.mark.asyncio
    @staticmethod
    async def test_connection_with_invalid_key_raises_error() -> None:
        """Test connection with invalid API key raises AuthenticationError."""
        provider = GoogleProvider()
        invalid_creds = ProviderCredentials(api_key="invalid-google-key-12345")

        with pytest.raises((AuthenticationError, ProviderError)):
            await provider.connect(invalid_creds)

    @pytest.mark.asyncio
    @staticmethod
    async def test_connection_with_empty_key_raises_error() -> None:
        """Test connection with empty API key raises AuthenticationError."""
        provider = GoogleProvider()
        empty_creds = ProviderCredentials(api_key="")

        with pytest.raises(AuthenticationError):
            await provider.connect(empty_creds)

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_without_connection_raises_error() -> None:
        """Test list_models raises error when not connected."""
        provider = GoogleProvider()

        with pytest.raises(ProviderError):
            await provider.list_models()

    @pytest.mark.asyncio
    @staticmethod
    async def test_disconnect_clears_connection_state(
        credential_loader: CredentialLoader,
        *,
        has_google_key: bool,
    ) -> None:
        """Test disconnect properly clears connection state.

        Args:
            credential_loader: Credential loader fixture.
            has_google_key: Whether a Google API key is configured.
        """
        if not has_google_key:
            pytest.skip("GOOGLE_API_KEY not configured")

        provider = GoogleProvider()
        credentials = credential_loader.get_credentials(ProviderName.GOOGLE)
        assert credentials is not None

        await provider.connect(credentials)
        assert provider.is_connected is True

        await provider.disconnect()
        assert provider.is_connected is False
