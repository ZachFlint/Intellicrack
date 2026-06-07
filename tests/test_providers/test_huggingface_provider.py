# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Integration tests for HuggingFaceProvider model listing.

These tests require a valid HUGGINGFACE_API_TOKEN in the .env file.
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
from intellicrack.providers.huggingface import HuggingFaceProvider


_MIN_HUGGINGFACE_MODELS = 10
_SAMPLE_MODEL_LIMIT = 20


@pytest.mark.integration
class TestHuggingFaceModelListing:
    """Tests for HuggingFace model listing functionality.

    These tests validate that HuggingFaceProvider can dynamically fetch
    models from the HuggingFace Hub API. NO hardcoded model names are used.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_returns_non_empty_list(
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test list_models returns at least one model.

        This validates that the API call works and returns actual data.
        HuggingFace Hub has many text-generation models available.

        Args:
            huggingface_provider: Connected HuggingFace provider fixture.
        """
        models = await huggingface_provider.list_models()

        assert isinstance(models, list), f"Expected list, got {type(models)}"
        assert len(models) > 0, "Expected at least one model from HuggingFace API"

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_returns_many_models(
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test HuggingFace returns many text-generation models.

        Args:
            huggingface_provider: Connected HuggingFace provider fixture.
        """
        models = await huggingface_provider.list_models()

        assert len(models) >= _MIN_HUGGINGFACE_MODELS, f"Expected at least 10 models from HuggingFace, got {len(models)}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_returns_model_info_instances(
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test all returned items are ModelInfo instances.

        Args:
            huggingface_provider: Connected HuggingFace provider fixture.
        """
        models = await huggingface_provider.list_models()

        for model in models[:_SAMPLE_MODEL_LIMIT]:
            assert isinstance(model, ModelInfo), f"Expected ModelInfo, got {type(model)}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_valid_id(
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test all models have non-empty string IDs.

        Args:
            huggingface_provider: Connected HuggingFace provider fixture.
        """
        models = await huggingface_provider.list_models()

        for model in models[:_SAMPLE_MODEL_LIMIT]:
            assert isinstance(model.id, str), f"Expected str id, got {type(model.id)}"
            assert len(model.id) > 0, "Model ID should not be empty"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_valid_name(
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test all models have non-empty string names.

        Args:
            huggingface_provider: Connected HuggingFace provider fixture.
        """
        models = await huggingface_provider.list_models()

        for model in models[:_SAMPLE_MODEL_LIMIT]:
            assert isinstance(model.name, str), f"Expected str name, got {type(model.name)}"
            assert len(model.name) > 0, "Model name should not be empty"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_correct_provider(
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test all models report HUGGINGFACE as provider.

        Args:
            huggingface_provider: Connected HuggingFace provider fixture.
        """
        models = await huggingface_provider.list_models()

        for model in models[:_SAMPLE_MODEL_LIMIT]:
            assert model.provider == ProviderName.HUGGINGFACE, f"Expected HUGGINGFACE provider, got {model.provider}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_positive_context_window(
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test all models have positive context window size.

        Args:
            huggingface_provider: Connected HuggingFace provider fixture.
        """
        models = await huggingface_provider.list_models()

        for model in models[:_SAMPLE_MODEL_LIMIT]:
            assert isinstance(model.context_window, int), f"Expected int context_window, got {type(model.context_window)}"
            assert model.context_window > 0, f"Model {model.id} has invalid context_window: {model.context_window}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_boolean_capabilities(
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test all models have boolean capability flags.

        Args:
            huggingface_provider: Connected HuggingFace provider fixture.
        """
        models = await huggingface_provider.list_models()

        for model in models[:_SAMPLE_MODEL_LIMIT]:
            assert isinstance(model.supports_tools, bool), f"Expected bool supports_tools, got {type(model.supports_tools)}"
            assert isinstance(model.supports_vision, bool), f"Expected bool supports_vision, got {type(model.supports_vision)}"
            assert isinstance(model.supports_streaming, bool), f"Expected bool supports_streaming, got {type(model.supports_streaming)}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_multiple_calls_return_consistent_results(
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test list_models returns consistent results across calls.

        Args:
            huggingface_provider: Connected HuggingFace provider fixture.
        """
        models1 = await huggingface_provider.list_models()
        models2 = await huggingface_provider.list_models()

        ids1 = {m.id for m in models1}
        ids2 = {m.id for m in models2}

        assert ids1 == ids2, "Model IDs should be consistent across calls"

    @pytest.mark.asyncio
    @staticmethod
    async def test_display_all_available_models(
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Verify all available HuggingFace models can be listed for GUI selection.

        Args:
            huggingface_provider: Connected HuggingFace provider fixture.
        """
        models = await huggingface_provider.list_models()

        assert len(models) > 0, "Should have at least one model to display"
        for model in models:
            assert model.id, "Model ID should not be empty"
            assert isinstance(model.context_window, int)
            assert isinstance(model.supports_tools, bool)
            assert isinstance(model.supports_vision, bool)


@pytest.mark.integration
class TestHuggingFaceConnection:
    """Tests for HuggingFace provider connection handling."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_is_connected_after_connect(
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test provider reports connected after successful connection.

        Args:
            huggingface_provider: Connected HuggingFace provider fixture.
        """
        assert huggingface_provider.is_connected is True

    @pytest.mark.asyncio
    @staticmethod
    async def test_provider_name_is_huggingface(
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test provider name property returns HUGGINGFACE.

        Args:
            huggingface_provider: Connected HuggingFace provider fixture.
        """
        assert huggingface_provider.name == ProviderName.HUGGINGFACE

    @pytest.mark.asyncio
    @staticmethod
    async def test_connection_with_empty_key_raises_error() -> None:
        """Test connection with empty API token raises AuthenticationError."""
        provider = HuggingFaceProvider()
        empty_creds = ProviderCredentials(api_key="")

        with pytest.raises(AuthenticationError):
            await provider.connect(empty_creds)

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_without_connection_raises_error() -> None:
        """Test list_models raises error when not connected."""
        provider = HuggingFaceProvider()

        with pytest.raises(ProviderError):
            await provider.list_models()

    @pytest.mark.asyncio
    @staticmethod
    async def test_disconnect_clears_connection_state(
        credential_loader: CredentialLoader,
        *,
        has_huggingface_key: bool,
    ) -> None:
        """Test disconnect properly clears connection state.

        Args:
            credential_loader: Credential loader fixture.
            has_huggingface_key: Whether a HuggingFace API token is configured.
        """
        if not has_huggingface_key:
            pytest.skip("HUGGINGFACE_API_TOKEN not configured")

        provider = HuggingFaceProvider()
        credentials = credential_loader.get_credentials(ProviderName.HUGGINGFACE)
        assert credentials is not None

        await provider.connect(credentials)
        assert provider.is_connected is True

        await provider.disconnect()
        assert provider.is_connected is False
