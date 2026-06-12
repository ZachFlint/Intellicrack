# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Integration tests for OpenAIProvider model listing.

These tests require a valid OPENAI_API_KEY in the .env file.
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
from intellicrack.providers.openai import OpenAIProvider


_ERR_KEY_REQUIRED = "OpenAI API key is required"
_ERR_INVALID_KEY_PREFIX = "Invalid OpenAI API key:"
_ERR_NOT_CONNECTED = "Not connected to OpenAI API"


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

        Args:
            openai_provider: Connected OpenAI provider fixture.
        """
        models = await openai_provider.list_models()

        assert isinstance(models, list), f"Expected list, got {type(models)}"
        assert len(models) > 0, "Expected at least one model from OpenAI API"

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_returns_model_info_instances(
        openai_provider: OpenAIProvider,
    ) -> None:
        """Test all returned items are ModelInfo instances.

        Args:
            openai_provider: Connected OpenAI provider fixture.
        """
        models = await openai_provider.list_models()

        for model in models:
            assert isinstance(model, ModelInfo), f"Expected ModelInfo, got {type(model)}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_valid_id(
        openai_provider: OpenAIProvider,
    ) -> None:
        """Test all models have non-empty string IDs.

        Args:
            openai_provider: Connected OpenAI provider fixture.
        """
        models = await openai_provider.list_models()

        for model in models:
            assert isinstance(model.id, str), f"Expected str id, got {type(model.id)}"
            assert len(model.id) > 0, "Model ID should not be empty"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_valid_name(
        openai_provider: OpenAIProvider,
    ) -> None:
        """Test all models have non-empty string names.

        Args:
            openai_provider: Connected OpenAI provider fixture.
        """
        models = await openai_provider.list_models()

        for model in models:
            assert isinstance(model.name, str), f"Expected str name, got {type(model.name)}"
            assert len(model.name) > 0, "Model name should not be empty"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_correct_provider(
        openai_provider: OpenAIProvider,
    ) -> None:
        """Test all models report OPENAI as provider.

        Args:
            openai_provider: Connected OpenAI provider fixture.
        """
        models = await openai_provider.list_models()

        for model in models:
            assert model.provider == ProviderName.OPENAI, f"Expected OPENAI provider, got {model.provider}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_positive_context_window(
        openai_provider: OpenAIProvider,
    ) -> None:
        """Test all models have positive context window size.

        Args:
            openai_provider: Connected OpenAI provider fixture.
        """
        models = await openai_provider.list_models()

        for model in models:
            assert isinstance(model.context_window, int), f"Expected int context_window, got {type(model.context_window)}"
            assert model.context_window > 0, f"Model {model.id} has invalid context_window: {model.context_window}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_boolean_capabilities(
        openai_provider: OpenAIProvider,
    ) -> None:
        """Test all models have boolean capability flags.

        Args:
            openai_provider: Connected OpenAI provider fixture.
        """
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
        """Test that all returned models have the correct provider set.

        Args:
            openai_provider: Connected OpenAI provider fixture.
        """
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
        """Test list_models returns consistent results across calls.

        Args:
            openai_provider: Connected OpenAI provider fixture.
        """
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
        """Test provider reports connected after successful connection.

        Args:
            openai_provider: Connected OpenAI provider fixture.
        """
        assert openai_provider.is_connected is True

    @pytest.mark.asyncio
    @staticmethod
    async def test_provider_name_is_openai(
        openai_provider: OpenAIProvider,
    ) -> None:
        """Test provider name property returns OPENAI.

        Args:
            openai_provider: Connected OpenAI provider fixture.
        """
        assert openai_provider.name == ProviderName.OPENAI

    @pytest.mark.asyncio
    @staticmethod
    async def test_connection_with_invalid_key_raises_error() -> None:
        """Test that connecting with a syntactically-valid but rejected key raises AuthenticationError.

        The production code issues a real ``models.list()`` probe against the OpenAI
        API after constructing the client. An invalid key triggers a 401 response,
        which is translated to :class:`AuthenticationError` carrying the
        ``"Invalid OpenAI API key:"`` prefix. After the failure the provider must
        be fully reset: ``is_connected`` must be ``False`` and ``client`` must be
        ``None`` so no stale state leaks to subsequent calls.
        """
        provider = OpenAIProvider()
        invalid_creds = ProviderCredentials(api_key="sk-invalid-key-12345")

        assert provider.is_connected is False, "Provider must start disconnected"
        assert provider.client is None, "Provider must start with no client"

        with pytest.raises(AuthenticationError) as exc_info:
            await provider.connect(invalid_creds)

        raised = exc_info.value
        assert _ERR_INVALID_KEY_PREFIX in str(raised), (
            f"AuthenticationError message must contain {_ERR_INVALID_KEY_PREFIX!r}; got: {raised!s}"
        )
        assert provider.is_connected is False, "Provider must not be connected after an invalid-key failure"
        assert provider.client is None, (
            "Provider.client must be None after an invalid-key failure; stale client would allow unauthenticated calls"
        )

    @pytest.mark.asyncio
    @staticmethod
    async def test_connection_with_empty_key_raises_error() -> None:
        """Test that connecting with an empty API key raises AuthenticationError before any network call.

        The production code guards with ``if not credentials.api_key`` and raises
        :class:`AuthenticationError` with the exact message
        ``"OpenAI API key is required"`` — no OpenAI SDK call is ever made.
        This distinguishes the empty-key path from the invalid-key-rejected path
        (which goes through the API and carries a different message prefix).
        After the failure the provider must remain fully disconnected.
        """
        provider = OpenAIProvider()
        empty_creds = ProviderCredentials(api_key="")

        assert provider.is_connected is False, "Provider must start disconnected"
        assert provider.client is None, "Provider must start with no client"

        with pytest.raises(AuthenticationError) as exc_info:
            await provider.connect(empty_creds)

        raised = exc_info.value
        assert str(raised) == _ERR_KEY_REQUIRED, f"Empty-key error must be exactly {_ERR_KEY_REQUIRED!r}; got: {raised!s}"
        assert provider.is_connected is False, "Provider must not be connected after an empty-key failure"
        assert provider.client is None, "Provider.client must be None after an empty-key failure"

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_without_connection_raises_error() -> None:
        """Test list_models raises ProviderError when the provider has never connected.

        The guard ``if not self.connected or self.client is None`` at the top of
        ``list_models`` must fire *before* any network call is attempted.
        This test independently confirms that ``is_connected`` starts ``False``
        on a fresh instance, and that the resulting :class:`ProviderError` carries
        the ``"Not connected"`` sentinel so callers can distinguish an unconnected
        state from a network failure.
        """
        provider = OpenAIProvider()

        assert provider.is_connected is False, "Fresh OpenAIProvider must report is_connected=False before connect() is called"
        assert provider.client is None, "Fresh OpenAIProvider must have client=None before connect() is called"

        with pytest.raises(ProviderError) as exc_info:
            await provider.list_models()

        raised = exc_info.value
        assert _ERR_NOT_CONNECTED in str(raised), (
            f"ProviderError from unconnected list_models must contain {_ERR_NOT_CONNECTED!r}; got: {raised!s}"
        )

    @pytest.mark.asyncio
    @staticmethod
    async def test_disconnect_clears_connection_state(
        credential_loader: CredentialLoader,
        *,
        has_openai_key: bool,
    ) -> None:
        """Test disconnect properly clears all connection state and prevents further API calls.

        Verifies the full teardown sequence: after ``disconnect()`` the boolean
        flag is cleared, the underlying SDK client is set to ``None``, and a
        subsequent ``list_models()`` call raises :class:`ProviderError` with the
        ``"Not connected"`` sentinel — confirming that the provider's guard logic
        is operating on the now-reset state, not on a stale client.

        Args:
            credential_loader: Credential loader fixture.
            has_openai_key: Whether an OpenAI API key is configured.
        """
        if not has_openai_key:
            pytest.skip("OPENAI_API_KEY not configured")

        provider = OpenAIProvider()
        credentials = credential_loader.get_credentials(ProviderName.OPENAI)
        assert credentials is not None

        await provider.connect(credentials)
        assert provider.is_connected is True, "Provider must be connected after connect()"
        assert provider.client is not None, "Provider must have a live client after connect()"

        await provider.disconnect()

        assert provider.is_connected is False, "Provider must report is_connected=False after disconnect()"
        assert provider.client is None, (
            "Provider.client must be None after disconnect(); a live client here would allow unauthenticated calls"
        )

        with pytest.raises(ProviderError) as exc_info:
            await provider.list_models()

        raised = exc_info.value
        assert _ERR_NOT_CONNECTED in str(raised), (
            f"list_models() after disconnect must raise ProviderError with {_ERR_NOT_CONNECTED!r}; got: {raised!s}"
        )
