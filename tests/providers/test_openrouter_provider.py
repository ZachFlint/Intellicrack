# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Integration tests for OpenRouterProvider model listing.

These tests require a valid OPENROUTER_API_KEY in the .env file.
Tests will be skipped if credentials are not available.

All tests use LIVE API calls against the real OpenRouter API.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import pytest_asyncio


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from intellicrack.credentials.env_loader import CredentialLoader

from intellicrack.core.types import (
    AuthenticationError,
    ProviderCredentials,
    ProviderError,
    ProviderName,
)
from intellicrack.providers.openrouter import OpenRouterProvider


_NETWORK_OFFLINE_SIGNALS: tuple[str, ...] = (
    "getaddrinfo",
    "name or service not known",
    "network is unreachable",
    "connection refused",
    "nodename nor servname provided",
    "temporary failure in name resolution",
    "failed to establish a new connection",
    "connection timed out",
)


def _is_network_offline_error(exc: BaseException) -> bool:
    """Return True when an exception chain signals a DNS or network-down failure.

    Walks the ``__cause__`` / ``__context__`` chain of a provider failure and
    tests each stringified exception against :data:`_NETWORK_OFFLINE_SIGNALS`.
    This distinguishes transient connectivity absences (sandbox ``network=none``,
    no internet) from genuine Intellicrack defects.

    Args:
        exc: The exception raised by a provider connection attempt.

    Returns:
        bool: ``True`` when at least one network-offline signal is found in
        the exception chain; ``False`` otherwise.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        text = str(current).lower()
        if any(signal in text for signal in _NETWORK_OFFLINE_SIGNALS):
            return True
        current = current.__cause__ or current.__context__
    return False


@pytest_asyncio.fixture
async def openrouter_provider(
    credential_loader: CredentialLoader,
    *,
    has_openrouter_key: bool,
) -> AsyncGenerator[OpenRouterProvider]:
    """Get a connected OpenRouter provider instance.

    Skips when ``OPENROUTER_API_KEY`` is absent or when the sandbox runs
    without network access (``network=none``).  Automatically disconnects
    after test completion.

    Args:
        credential_loader: The credential loader instance.
        has_openrouter_key: Whether an OpenRouter API key is configured.

    Yields:
        OpenRouterProvider: A connected OpenRouterProvider instance.

    Raises:
        ProviderError: Re-raised when the connection failure is not due to network
            being offline.
    """
    if not has_openrouter_key:
        pytest.skip("OPENROUTER_API_KEY not configured in .env")

    provider = OpenRouterProvider()
    credentials = credential_loader.get_credentials(ProviderName.OPENROUTER)
    assert credentials is not None, "Expected credentials after validation"

    try:
        await provider.connect(credentials)
    except ProviderError as exc:
        if _is_network_offline_error(exc):
            pytest.skip(f"OpenRouter unreachable (no network): {exc}")
        raise

    yield provider
    await provider.disconnect()


_MIN_OPENROUTER_MODELS = 10
_SAMPLE_MODEL_LIMIT = 20


@pytest.mark.integration
class TestOpenRouterModelListing:
    """Tests for OpenRouter model listing functionality.

    These tests validate that OpenRouterProvider can dynamically fetch
    models from the OpenRouter API and correctly parse their fields.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_returns_non_empty_list(
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test list_models returns at least one model.

        This validates that the API call works and returns actual data.
        OpenRouter aggregates many providers so should have many models.

        Args:
            openrouter_provider: Connected OpenRouter provider fixture.
        """
        models = await openrouter_provider.list_models()

        assert isinstance(models, list), f"Expected list, got {type(models)}"
        assert len(models) > 0, "Expected at least one model from OpenRouter API"

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_returns_many_models(
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test OpenRouter returns many models (it's an aggregator).

        Args:
            openrouter_provider: Connected OpenRouter provider fixture.
        """
        models = await openrouter_provider.list_models()

        assert len(models) >= _MIN_OPENROUTER_MODELS, f"Expected at least 10 models from OpenRouter, got {len(models)}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_known_model_present_with_correct_fields(
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test that a known model is present with correct parsed fields.

        Asserts that ``openai/gpt-4o-mini`` appears in the listing and that the
        bridge correctly sets provider, streaming support, tool support, and a
        positive context window.  ``supports_streaming`` is always ``True``
        because OpenRouter routes every model through its streaming proxy;
        ``supports_tools`` is ``True`` for gpt-family models either from the
        ``supported_parameters`` field or the family-name fallback in
        ``_build_model_info``.  These values are derived from the API response
        and the bridge's parsing logic, not injected by this test.

        Args:
            openrouter_provider: Connected OpenRouter provider fixture.
        """
        models = await openrouter_provider.list_models()

        known_id = "openai/gpt-4o-mini"
        matching = [m for m in models if m.id == known_id]
        assert matching, f"Expected to find '{known_id}' in OpenRouter model listing, got {[m.id for m in models[:10]]}"

        model = matching[0]
        assert model.provider == ProviderName.OPENROUTER, f"Expected provider OPENROUTER, got {model.provider}"
        assert model.supports_tools is True, f"Expected {known_id} to have supports_tools=True (gpt-family + documented tool support)"
        assert model.supports_streaming is True, f"Expected {known_id} to have supports_streaming=True (OpenRouter universal streaming)"
        assert model.context_window > 0, f"Expected {known_id} to have positive context_window, got {model.context_window}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_valid_id(
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test all models have non-empty string IDs.

        Args:
            openrouter_provider: Connected OpenRouter provider fixture.
        """
        models = await openrouter_provider.list_models()

        for model in models[:_SAMPLE_MODEL_LIMIT]:
            assert isinstance(model.id, str), f"Expected str id, got {type(model.id)}"
            assert len(model.id) > 0, "Model ID should not be empty"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_valid_name(
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test all models have non-empty string names.

        Args:
            openrouter_provider: Connected OpenRouter provider fixture.
        """
        models = await openrouter_provider.list_models()

        for model in models[:_SAMPLE_MODEL_LIMIT]:
            assert isinstance(model.name, str), f"Expected str name, got {type(model.name)}"
            assert len(model.name) > 0, "Model name should not be empty"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_positive_context_window(
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test all models have positive context window size.

        Args:
            openrouter_provider: Connected OpenRouter provider fixture.
        """
        models = await openrouter_provider.list_models()

        for model in models[:_SAMPLE_MODEL_LIMIT]:
            assert isinstance(model.context_window, int), f"Expected int context_window, got {type(model.context_window)}"
            assert model.context_window > 0, f"Model {model.id} has invalid context_window: {model.context_window}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_may_have_pricing(
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test that some models have pricing information.

        Args:
            openrouter_provider: Connected OpenRouter provider fixture.
        """
        models = await openrouter_provider.list_models()

        models_with_pricing = [m for m in models if m.input_cost_per_1m_tokens is not None]

        assert models_with_pricing, "Expected at least some models to have pricing information"

    @pytest.mark.asyncio
    @staticmethod
    async def test_multiple_calls_return_consistent_results(
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test list_models returns consistent results across calls.

        Args:
            openrouter_provider: Connected OpenRouter provider fixture.
        """
        models1 = await openrouter_provider.list_models()
        models2 = await openrouter_provider.list_models()

        ids1 = {m.id for m in models1}
        ids2 = {m.id for m in models2}

        assert ids1 == ids2, "Model IDs should be consistent across calls"


@pytest.mark.integration
class TestOpenRouterConnection:
    """Tests for OpenRouter provider connection handling."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_is_connected_after_connect(
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test provider reports connected after successful connection.

        Args:
            openrouter_provider: Connected OpenRouter provider fixture.
        """
        assert openrouter_provider.is_connected is True

    @pytest.mark.asyncio
    @staticmethod
    async def test_provider_name_is_openrouter(
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Test provider name property returns OPENROUTER.

        Args:
            openrouter_provider: Connected OpenRouter provider fixture.
        """
        assert openrouter_provider.name == ProviderName.OPENROUTER

    @pytest.mark.asyncio
    @staticmethod
    async def test_connection_with_invalid_key_may_succeed_initially() -> None:
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
    @staticmethod
    async def test_connection_with_empty_key_raises_error() -> None:
        """Test connection with empty API key raises AuthenticationError."""
        provider = OpenRouterProvider()
        empty_creds = ProviderCredentials(api_key="")

        with pytest.raises(AuthenticationError):
            await provider.connect(empty_creds)

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_without_connection_raises_error() -> None:
        """Test list_models raises error when not connected."""
        provider = OpenRouterProvider()

        with pytest.raises(ProviderError):
            await provider.list_models()

    @pytest.mark.asyncio
    @staticmethod
    async def test_disconnect_clears_connection_state(
        credential_loader: CredentialLoader,
        *,
        has_openrouter_key: bool,
    ) -> None:
        """Test disconnect properly clears connection state.

        Args:
            credential_loader: Credential loader fixture.
            has_openrouter_key: Whether an OpenRouter API key is configured.
        """
        if not has_openrouter_key:
            pytest.skip("OPENROUTER_API_KEY not configured")

        provider = OpenRouterProvider()
        credentials = credential_loader.get_credentials(ProviderName.OPENROUTER)
        assert credentials is not None

        await provider.connect(credentials)
        assert provider.is_connected is True

        await provider.disconnect()
        assert provider.is_connected is False
