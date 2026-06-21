# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Integration tests for HuggingFaceProvider model listing.

These tests require a valid HUGGINGFACE_API_TOKEN in the .env file.
Tests will be skipped if credentials are not available or if the
sandbox is running without network access.

All tests use LIVE API calls - NO hardcoded model names.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
import pytest
import pytest_asyncio


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from intellicrack.credentials.env_loader import CredentialLoader

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
_HUGGINGFACE_DEFAULT_CONTEXT_WINDOW = 4096

_OFFLINE_SKIP_REASON = "HuggingFace Hub unreachable (offline sandbox or no network)"


@pytest_asyncio.fixture
async def huggingface_provider(
    credential_loader: CredentialLoader,
    *,
    has_huggingface_key: bool,
) -> AsyncGenerator[HuggingFaceProvider]:
    """Get a connected HuggingFace provider, skipping on missing key or no network.

    Extends the conftest fixture to also catch ``httpx.NetworkError`` raised
    during ``connect()`` when the sandbox runs with ``network='none'``. The
    key-presence check skips before any network attempt; the ``httpx.NetworkError``
    guard skips when a key is present but the Hub endpoint is unreachable.
    Automatically disconnects after test completion.

    Args:
        credential_loader: The credential loader instance.
        has_huggingface_key: Whether HuggingFace token is configured.

    Yields:
        AsyncGenerator[HuggingFaceProvider]: A connected HuggingFaceProvider instance.
    """
    if not has_huggingface_key:
        pytest.skip("HUGGINGFACE_API_TOKEN not configured in .env")

    provider = HuggingFaceProvider()
    credentials = credential_loader.get_credentials(ProviderName.HUGGINGFACE)
    assert credentials is not None, "Expected credentials after validation"

    try:
        await provider.connect(credentials)
    except httpx.NetworkError:
        pytest.skip(_OFFLINE_SKIP_REASON)

    yield provider
    await provider.disconnect()


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
        try:
            models = await huggingface_provider.list_models()
        except httpx.NetworkError:
            pytest.skip(_OFFLINE_SKIP_REASON)

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
        try:
            models = await huggingface_provider.list_models()
        except httpx.NetworkError:
            pytest.skip(_OFFLINE_SKIP_REASON)

        assert len(models) >= _MIN_HUGGINGFACE_MODELS, f"Expected at least 10 models from HuggingFace, got {len(models)}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_returns_model_info_instances(
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test all returned items are ModelInfo instances with correct field values.

        Asserts the builder's three hard-coded invariants (streaming always enabled,
        context window always 4096, provider always HUGGINGFACE) hold across every
        sampled live record, and that the short name is derived correctly from the
        slash-separated model id.

        Args:
            huggingface_provider: Connected HuggingFace provider fixture.
        """
        try:
            models = await huggingface_provider.list_models()
        except httpx.NetworkError:
            pytest.skip(_OFFLINE_SKIP_REASON)

        sample = models[:_SAMPLE_MODEL_LIMIT]

        assert len(sample) > 0, "Live listing returned no models"

        for model in sample:
            assert isinstance(model, ModelInfo), f"Expected ModelInfo, got {type(model)}"
            assert model.provider is ProviderName.HUGGINGFACE, (
                f"Model {model.id!r} has provider {model.provider!r}, expected HUGGINGFACE"
            )
            assert model.supports_streaming is True, (
                f"Model {model.id!r} has supports_streaming={model.supports_streaming!r}; "
                "HuggingFace builder always sets this True"
            )
            assert model.context_window == _HUGGINGFACE_DEFAULT_CONTEXT_WINDOW, (
                f"Model {model.id!r} has context_window={model.context_window!r}, "
                f"expected {_HUGGINGFACE_DEFAULT_CONTEXT_WINDOW}"
            )
            expected_name = model.id.rsplit("/", maxsplit=1)[-1] if "/" in model.id else model.id
            assert model.name == expected_name, (
                f"Model {model.id!r} has name={model.name!r}, "
                f"expected short component {expected_name!r}"
            )

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_valid_id(
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test all models have non-empty string IDs.

        Args:
            huggingface_provider: Connected HuggingFace provider fixture.
        """
        try:
            models = await huggingface_provider.list_models()
        except httpx.NetworkError:
            pytest.skip(_OFFLINE_SKIP_REASON)

        for model in models[:_SAMPLE_MODEL_LIMIT]:
            assert isinstance(model.id, str), f"Expected str id, got {type(model.id)}"
            assert len(model.id) > 0, "Model ID should not be empty"

    @pytest.mark.asyncio
    @staticmethod
    async def test_multiple_calls_return_consistent_results(
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test list_models returns consistent results across calls.

        Args:
            huggingface_provider: Connected HuggingFace provider fixture.
        """
        try:
            models1 = await huggingface_provider.list_models()
            models2 = await huggingface_provider.list_models()
        except httpx.NetworkError:
            pytest.skip(_OFFLINE_SKIP_REASON)

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
        try:
            models = await huggingface_provider.list_models()
        except httpx.NetworkError:
            pytest.skip(_OFFLINE_SKIP_REASON)

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

        try:
            await provider.connect(credentials)
        except httpx.NetworkError:
            pytest.skip(_OFFLINE_SKIP_REASON)

        assert provider.is_connected is True

        await provider.disconnect()
        assert provider.is_connected is False
