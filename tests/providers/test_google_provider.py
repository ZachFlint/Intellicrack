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

import socket
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.types import (
    AuthenticationError,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    ProviderName,
)
from intellicrack.providers.google import GoogleProvider


if TYPE_CHECKING:
    from intellicrack.credentials.store import CredentialLoader

_GOOGLE_API_HOST: str = "generativelanguage.googleapis.com"
_GOOGLE_API_PORT: int = 443
_NETWORK_PROBE_TIMEOUT_S: float = 3.0


def _google_api_reachable() -> bool:
    """Probe whether the Google Generative Language API is reachable via TCP.

    Attempts a non-blocking TCP connection to the Google AI REST endpoint.
    Returns False on any socket or OS error, including DNS failures that
    occur when the container runs with network isolation (``--network none``).

    Returns:
        bool: True when a TCP connection to the API endpoint succeeds.
    """
    try:
        with socket.create_connection(
            (_GOOGLE_API_HOST, _GOOGLE_API_PORT),
            timeout=_NETWORK_PROBE_TIMEOUT_S,
        ):
            return True
    except OSError:
        return False


@pytest.fixture(name="google_network_required")
def google_network_required_fixture() -> None:
    """Skip the test when the Google AI API is not reachable.

    This guard fires during fixture setup — before ``google_provider``
    attempts ``connect()``. When the sandbox runs with ``--network none``
    or any other network-isolated environment, DNS resolution for
    ``generativelanguage.googleapis.com`` fails and
    ``ConnectError: getaddrinfo failed`` surfaces as an ERROR in fixture
    setup rather than a SKIP. This fixture converts that environment
    precondition absence into a clean SKIP so the test suite stays green
    in offline containers while still asserting real behavior when the
    network is available.
    """
    if not _google_api_reachable():
        pytest.skip("Google AI API not reachable (offline or network='none')")


_KNOWN_GEMINI_MODELS: frozenset[str] = frozenset({
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
    "gemini-2.5-pro",
    "gemini-2.0-flash",
    "gemini-2.0-flash-lite",
    "gemini-1.5-flash",
    "gemini-1.5-flash-8b",
    "gemini-1.5-pro",
    "gemini-flash-latest",
    "gemini-pro",
})

_WELL_DOCUMENTED_GEMINI_ID: str = "gemini-2.5-flash"

_GEMINI_2_5_FLASH_MIN_CONTEXT: int = 1_000_000


@pytest.mark.integration
class TestGoogleModelListing:
    """Tests for Google model listing functionality.

    These tests validate that GoogleProvider can dynamically fetch
    models from the Google AI API. NO hardcoded model names are used.
    """

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("google_network_required")
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
        assert gemini_models, (
            f"Expected at least one Gemini model in the response, but none of the {len(models)} returned models have 'gemini' in their id. IDs returned: {[m.id for m in models[:5]]}"
        )

        first_gemini = gemini_models[0]
        assert isinstance(first_gemini.id, str)
        assert len(first_gemini.id) > 0
        assert first_gemini.provider == ProviderName.GOOGLE
        assert isinstance(first_gemini.context_window, int)
        assert first_gemini.context_window > 0

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("google_network_required")
    @staticmethod
    async def test_list_models_structural_well_formedness(
        google_provider: GoogleProvider,
    ) -> None:
        """Test every returned model has correct types and provider tag.

        Collapses the N8 structural-only individual field tests into one
        consolidated gate so the seven separate isinstance-only checks are
        replaced by a single well-formedness assertion that remains paired with
        the value gate below.  If any model is returned with a wrong type on any
        field this test fails immediately.

        Args:
            google_provider: Connected Google provider fixture.
        """
        models: list[ModelInfo] = await google_provider.list_models()

        assert models, "list_models must return at least one model"

        for model in models:
            assert isinstance(model, ModelInfo), f"Expected ModelInfo, got {type(model)}"
            assert isinstance(model.id, str), f"Model id must be str; got {type(model.id)}"
            assert len(model.id) > 0, f"Model id must not be empty; got {model.id!r}"
            assert isinstance(model.name, str), f"Model name must be str; got {type(model.name)}"
            assert len(model.name) > 0, f"Model name must not be empty; got {model.name!r}"
            assert model.provider == ProviderName.GOOGLE, f"Model {model.id} has wrong provider {model.provider!r}"
            assert isinstance(model.context_window, int), f"Model {model.id} context_window must be int; got {type(model.context_window)}"
            assert model.context_window > 0, f"Model {model.id} has invalid context_window {model.context_window!r}"
            assert isinstance(model.supports_tools, bool), f"Model {model.id} supports_tools must be bool, got {type(model.supports_tools)}"
            assert isinstance(model.supports_vision, bool), (
                f"Model {model.id} supports_vision must be bool, got {type(model.supports_vision)}"
            )
            assert isinstance(model.supports_streaming, bool), (
                f"Model {model.id} supports_streaming must be bool, got {type(model.supports_streaming)}"
            )
            assert "gemini" in model.id.lower(), f"Bridge filter should only return Gemini models; got {model.id!r}"

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("google_network_required")
    @staticmethod
    async def test_list_models_includes_known_production_model_with_capabilities(
        google_provider: GoogleProvider,
    ) -> None:
        """Assert a documented Gemini model appears with its independently-known capability profile.

        The set of known IDs represents publicly-documented Gemini generative models
        confirmed available via the Google AI Gemini API.  The capability profile of
        ``gemini-2.5-flash`` is independently known from Google's public documentation:
        it supports ``generateContent`` (tools and vision) and ``streamGenerateContent``
        (streaming), and its ``input_token_limit`` is at least one million tokens.

        The bridge derives all three boolean flags from the ``supported_generation_methods``
        list returned by the Google API (see ``_fetch_and_sort_models``).  If the bridge
        silently dropped ``generateContent`` from the method list, ``supports_tools``
        and ``supports_vision`` would both be ``False`` and this test would fail.  If
        ``streamGenerateContent`` were dropped, ``supports_streaming`` would be ``False``.
        If the context window were fabricated or zeroed, the ``>= _GEMINI_2_5_FLASH_MIN_CONTEXT``
        assertion would fail.  No assertion depends on data the test itself injected.

        Args:
            google_provider: Connected Google provider fixture.
        """
        models: list[ModelInfo] = await google_provider.list_models()
        returned_ids: set[str] = {m.id for m in models}

        matching_ids: set[str] = returned_ids & _KNOWN_GEMINI_MODELS
        assert matching_ids, (
            f"At least one known production Gemini model must appear in the API response. Known: {_KNOWN_GEMINI_MODELS}. Got: {returned_ids}"
        )

        if _WELL_DOCUMENTED_GEMINI_ID in returned_ids:
            target = next(m for m in models if m.id == _WELL_DOCUMENTED_GEMINI_ID)

            assert target.supports_tools is True, (
                f"{_WELL_DOCUMENTED_GEMINI_ID} must support tools "
                f"(generateContent in supported_generation_methods); got supports_tools=False"
            )
            assert target.supports_vision is True, (
                f"{_WELL_DOCUMENTED_GEMINI_ID} must support vision "
                f"(same flag as supports_tools for Google bridge); got supports_vision=False"
            )
            assert target.supports_streaming is True, (
                f"{_WELL_DOCUMENTED_GEMINI_ID} must support streaming "
                f"(streamGenerateContent in supported_generation_methods); got supports_streaming=False"
            )
            assert target.context_window >= _GEMINI_2_5_FLASH_MIN_CONTEXT, (
                f"{_WELL_DOCUMENTED_GEMINI_ID} must have context_window >= {_GEMINI_2_5_FLASH_MIN_CONTEXT:,} "
                f"(Google API reports input_token_limit=1048576 for this model); "
                f"got {target.context_window}"
            )

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("google_network_required")
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
    @pytest.mark.usefixtures("google_network_required")
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
    @pytest.mark.usefixtures("google_network_required")
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
    @pytest.mark.usefixtures("google_network_required")
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
    @pytest.mark.usefixtures("google_network_required")
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
