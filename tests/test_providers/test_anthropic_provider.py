# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Integration tests for AnthropicProvider model listing.

These tests require a valid ANTHROPIC_API_KEY in the .env file.
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
from intellicrack.providers.anthropic import AnthropicProvider


@pytest.mark.integration
class TestAnthropicModelListing:
    """Tests for Anthropic model listing functionality.

    These tests validate that AnthropicProvider can dynamically fetch
    models from the Anthropic API. NO hardcoded model names are used.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_returns_non_empty_list(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Test list_models returns at least one model.

        This validates that the API call works and returns actual data.
        We don't hardcode model names - just verify we get models.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        models = await anthropic_provider.list_models()

        assert isinstance(models, list), f"Expected list, got {type(models)}"
        assert len(models) > 0, "Expected at least one model from Anthropic API"

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_returns_model_info_instances(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Test all returned items are ModelInfo instances.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        models = await anthropic_provider.list_models()

        for model in models:
            assert isinstance(model, ModelInfo), f"Expected ModelInfo, got {type(model)}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_valid_id(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Test all models have non-empty string IDs.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        models = await anthropic_provider.list_models()

        for model in models:
            assert isinstance(model.id, str), f"Expected str id, got {type(model.id)}"
            assert len(model.id) > 0, "Model ID should not be empty"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_valid_name(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Test all models have non-empty string names.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        models = await anthropic_provider.list_models()

        for model in models:
            assert isinstance(model.name, str), f"Expected str name, got {type(model.name)}"
            assert len(model.name) > 0, "Model name should not be empty"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_correct_provider(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Test all models report ANTHROPIC as provider.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        models = await anthropic_provider.list_models()

        for model in models:
            assert model.provider == ProviderName.ANTHROPIC, f"Expected ANTHROPIC provider, got {model.provider}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_positive_context_window(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Test all models have positive context window size.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        models = await anthropic_provider.list_models()

        for model in models:
            assert isinstance(model.context_window, int), f"Expected int context_window, got {type(model.context_window)}"
            assert model.context_window > 0, f"Model {model.id} has invalid context_window: {model.context_window}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_boolean_capabilities(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Test all models have boolean capability flags.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        models = await anthropic_provider.list_models()

        for model in models:
            assert isinstance(model.supports_tools, bool), f"Expected bool supports_tools, got {type(model.supports_tools)}"
            assert isinstance(model.supports_vision, bool), f"Expected bool supports_vision, got {type(model.supports_vision)}"
            assert isinstance(model.supports_streaming, bool), f"Expected bool supports_streaming, got {type(model.supports_streaming)}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_multiple_calls_return_consistent_results(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Test list_models returns consistent results across calls.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        models1 = await anthropic_provider.list_models()
        models2 = await anthropic_provider.list_models()

        ids1 = {m.id for m in models1}
        ids2 = {m.id for m in models2}

        assert ids1 == ids2, "Model IDs should be consistent across calls"


@pytest.mark.integration
class TestAnthropicConnection:
    """Tests for Anthropic provider connection handling."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_is_connected_after_connect(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Test provider reports connected after successful connection.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        assert anthropic_provider.is_connected is True

    @pytest.mark.asyncio
    @staticmethod
    async def test_provider_name_is_anthropic(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Test provider name property returns ANTHROPIC.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        assert anthropic_provider.name == ProviderName.ANTHROPIC

    @pytest.mark.asyncio
    @staticmethod
    async def test_connection_with_invalid_key_raises_error() -> None:
        """Test connection with invalid API key raises AuthenticationError."""
        provider = AnthropicProvider()
        invalid_creds = ProviderCredentials(api_key="sk-ant-invalid-key-12345")

        with pytest.raises(AuthenticationError):
            await provider.connect(invalid_creds)

    @pytest.mark.asyncio
    @staticmethod
    async def test_connection_with_empty_key_raises_error() -> None:
        """Test connection with empty API key raises AuthenticationError."""
        provider = AnthropicProvider()
        empty_creds = ProviderCredentials(api_key="")

        with pytest.raises(AuthenticationError):
            await provider.connect(empty_creds)

    @pytest.mark.asyncio
    @staticmethod
    async def test_connection_with_none_key_raises_error() -> None:
        """Test connection with None API key raises AuthenticationError."""
        provider = AnthropicProvider()
        none_creds = ProviderCredentials(api_key=None)

        with pytest.raises(AuthenticationError):
            await provider.connect(none_creds)

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_without_connection_raises_error() -> None:
        """Test list_models raises error when not connected."""
        provider = AnthropicProvider()

        with pytest.raises(ProviderError):
            await provider.list_models()

    @pytest.mark.asyncio
    @staticmethod
    async def test_disconnect_clears_connection_state(
        credential_loader: CredentialLoader,
        *,
        has_anthropic_key: bool,
    ) -> None:
        """Test disconnect properly clears connection state.

        Args:
            credential_loader: Credential loader fixture.
            has_anthropic_key: Whether an Anthropic API key is configured.
        """
        if not has_anthropic_key:
            pytest.skip("ANTHROPIC_API_KEY not configured")

        provider = AnthropicProvider()
        credentials = credential_loader.get_credentials(ProviderName.ANTHROPIC)
        assert credentials is not None

        await provider.connect(credentials)
        assert provider.is_connected is True

        await provider.disconnect()
        assert provider.is_connected is False
