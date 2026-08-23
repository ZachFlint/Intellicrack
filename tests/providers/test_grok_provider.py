# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Integration tests for GrokProvider model listing.

These tests require a valid XAI_API_KEY in the .env file.
Tests will be skipped if credentials are not available.

All tests use LIVE API calls - NO hardcoded model names.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import openai
import pytest
import pytest_asyncio


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from intellicrack.credentials.store import CredentialLoader

from intellicrack.core.types import (
    AuthenticationError,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    ProviderName,
)
from intellicrack.providers.grok import GrokProvider


_GROK_3_CONTEXT_WINDOW_EXPECTED: int = 131072
_GROK_4_CONTEXT_WINDOW_EXPECTED: int = 256000


@pytest_asyncio.fixture
async def grok_provider(
    credential_loader: CredentialLoader,
    *,
    has_grok_key: bool,
) -> AsyncGenerator[GrokProvider]:
    """Get a connected Grok (X.AI) provider, skipping when offline or key is absent.

    Extends the shared ``grok_provider`` fixture from the providers conftest
    with a network-absence guard: when ``connect()`` raises
    ``openai.APIConnectionError`` the test is skipped rather than erroring,
    because the sandbox runs with ``network='none'`` and cannot reach the
    X.AI API even when a key is configured.

    Args:
        credential_loader: The credential loader instance.
        has_grok_key: Whether a Grok (X.AI) API key is configured.

    Yields:
        GrokProvider: A connected GrokProvider instance.
    """
    if not has_grok_key:
        pytest.skip("XAI_API_KEY not configured in .env")

    provider = GrokProvider()
    credentials = credential_loader.get_credentials(ProviderName.GROK)
    assert credentials is not None, "Expected credentials after validation"

    try:
        await provider.connect(credentials)
    except openai.APIConnectionError as exc:
        pytest.skip(f"X.AI API unreachable (network offline): {exc}")

    yield provider
    await provider.disconnect()


def _expected_context_window(model_id: str) -> int:
    """Compute the expected context window for a Grok model using an independent oracle.

    Mirrors the production branching logic but uses hand-encoded constants so
    that a regression in the production function is caught by comparison.
    The values are independently verified from X.AI's published documentation:
    grok-4 → 256 000, grok-3 / grok-2 / default → 131 072, grok-1 → 8 192.

    Args:
        model_id: Grok model identifier string.

    Returns:
        int: The expected context window in tokens.
    """
    if "grok-4" in model_id:
        return _GROK_4_CONTEXT_WINDOW_EXPECTED
    if "grok-3" in model_id or "grok-2" in model_id:
        return _GROK_3_CONTEXT_WINDOW_EXPECTED
    return 8192 if "grok-1" in model_id else _GROK_3_CONTEXT_WINDOW_EXPECTED


def _expected_supports_vision(model_id: str) -> bool:
    """Compute whether a Grok model should report vision support.

    Uses the same pattern rule as the production implementation (vision support
    is inferred from the presence of ``"vision"`` or ``"image"`` substrings in
    the model identifier) but applied independently as an oracle.

    Args:
        model_id: Grok model identifier string.

    Returns:
        bool: True when the model id contains ``"vision"`` or ``"image"``.
    """
    return "vision" in model_id or "image" in model_id


@pytest.mark.integration
class TestGrokModelListing:
    """Tests for Grok model listing functionality.

    These tests validate that GrokProvider can dynamically fetch
    models from the X.AI API. NO hardcoded model names are used.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_returns_non_empty_list(
        grok_provider: GrokProvider,
    ) -> None:
        """Test list_models returns at least one model.

        This validates that the API call works and returns actual data.
        We don't hardcode model names - just verify we get models.

        Args:
            grok_provider: Connected Grok provider fixture.
        """
        models = await grok_provider.list_models()

        assert isinstance(models, list), f"Expected list, got {type(models)}"
        assert len(models) > 0, "Expected at least one model from Grok API"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_fields_structural_sanity(
        grok_provider: GrokProvider,
    ) -> None:
        """Test all returned models satisfy basic structural contracts.

        Validates that every ModelInfo has a non-empty string id and name,
        GROK as provider, a positive integer context window, and boolean
        capability flags.  The capability values themselves are checked against
        an independent oracle in ``test_model_capability_values_match_published_profile``.

        Args:
            grok_provider: Connected Grok provider fixture.
        """
        models = await grok_provider.list_models()

        assert len(models) > 0, "Expected at least one model from Grok API"

        for model in models:
            assert isinstance(model, ModelInfo), f"Expected ModelInfo, got {type(model)}"
            assert isinstance(model.id, str), f"Model id must be str, got {type(model.id)}"
            assert len(model.id) > 0, f"Model id must be non-empty, got {model.id!r}"
            assert isinstance(model.name, str), f"Model name must be str, got {type(model.name)}"
            assert len(model.name) > 0, f"Model name must be non-empty, got {model.name!r}"
            assert model.provider == ProviderName.GROK, f"Expected ProviderName.GROK, got {model.provider!r}"
            assert isinstance(model.context_window, int), f"context_window must be int, got {type(model.context_window)}"
            assert model.context_window > 0, f"context_window must be positive, got {model.context_window!r}"
            assert isinstance(model.supports_tools, bool), f"supports_tools must be bool, got {type(model.supports_tools)}"
            assert isinstance(model.supports_vision, bool), f"supports_vision must be bool, got {type(model.supports_vision)}"
            assert isinstance(model.supports_streaming, bool), f"supports_streaming must be bool, got {type(model.supports_streaming)}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_capability_values_match_published_profile(
        grok_provider: GrokProvider,
    ) -> None:
        """Test that model capability values match the published X.AI capability profile.

        This is the value gate: for each model returned by the live API, the
        production bridge must assign context_window, supports_tools,
        supports_vision, and supports_streaming values that exactly match an
        independently-computed oracle derived from X.AI's published
        documentation.

        Oracle rules (independent of the src constants):
        - context_window: grok-4 → 256 000; grok-3 / grok-2 / default → 131 072; grok-1 → 8 192.
        - supports_tools: True for all chat models (X.AI documents that all
          Grok chat models support function calling).
        - supports_vision: True only when ``"vision"`` or ``"image"`` appears
          in the model identifier.
        - supports_streaming: True for all chat models (X.AI documents
          streaming for all completion endpoints).

        Args:
            grok_provider: Connected Grok provider fixture.
        """
        models = await grok_provider.list_models()

        assert len(models) > 0, "Expected at least one model from Grok API"

        model_index: dict[str, ModelInfo] = {m.id: m for m in models}

        for model_id, model in model_index.items():
            expected_ctx = _expected_context_window(model_id)
            assert model.context_window == expected_ctx, (
                f"Model {model_id!r}: context_window={model.context_window}, expected {expected_ctx} per published X.AI documentation"
            )

            assert model.supports_tools is True, (
                f"Model {model_id!r}: supports_tools must be True; all Grok chat models support function calling per X.AI documentation"
            )

            expected_vision = _expected_supports_vision(model_id)
            assert model.supports_vision is expected_vision, (
                f"Model {model_id!r}: supports_vision={model.supports_vision}, expected {expected_vision} (based on 'vision'/'image' in id)"
            )

            assert model.supports_streaming is True, (
                f"Model {model_id!r}: supports_streaming must be True; all Grok chat models support streaming per X.AI documentation"
            )

        if grok3_models := [m for m in models if "grok-3" in m.id]:
            representative = grok3_models[0]
            assert representative.context_window == _GROK_3_CONTEXT_WINDOW_EXPECTED, (
                f"grok-3 model {representative.id!r}: context_window="
                f"{representative.context_window}, expected {_GROK_3_CONTEXT_WINDOW_EXPECTED}"
            )
            assert representative.supports_vision is False, (
                f"grok-3 model {representative.id!r} must not report vision support "
                "('vision'/'image' absent from standard grok-3 identifiers)"
            )

    @pytest.mark.asyncio
    @staticmethod
    async def test_multiple_calls_return_consistent_results(
        grok_provider: GrokProvider,
    ) -> None:
        """Test list_models returns consistent results across calls.

        Args:
            grok_provider: Connected Grok provider fixture.
        """
        models1 = await grok_provider.list_models()
        models2 = await grok_provider.list_models()

        ids1 = {m.id for m in models1}
        ids2 = {m.id for m in models2}

        assert ids1 == ids2, "Model IDs should be consistent across calls"


@pytest.mark.integration
class TestGrokConnection:
    """Tests for Grok provider connection handling."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_is_connected_after_connect(
        grok_provider: GrokProvider,
    ) -> None:
        """Test provider reports connected after successful connection.

        Args:
            grok_provider: Connected Grok provider fixture.
        """
        assert grok_provider.is_connected is True

    @pytest.mark.asyncio
    @staticmethod
    async def test_provider_name_is_grok(
        grok_provider: GrokProvider,
    ) -> None:
        """Test provider name property returns GROK.

        Args:
            grok_provider: Connected Grok provider fixture.
        """
        assert grok_provider.name == ProviderName.GROK

    @pytest.mark.asyncio
    @staticmethod
    async def test_connection_with_invalid_key_raises_error() -> None:
        """Test connection with invalid API key raises AuthenticationError."""
        provider = GrokProvider()
        invalid_creds = ProviderCredentials(api_key="xai-invalid-key-12345")

        with pytest.raises(AuthenticationError):
            await provider.connect(invalid_creds)

    @pytest.mark.asyncio
    @staticmethod
    async def test_connection_with_empty_key_raises_error() -> None:
        """Test connection with empty API key raises AuthenticationError."""
        provider = GrokProvider()
        empty_creds = ProviderCredentials(api_key="")

        with pytest.raises(AuthenticationError):
            await provider.connect(empty_creds)

    @pytest.mark.asyncio
    @staticmethod
    async def test_connection_with_none_key_raises_error() -> None:
        """Test connection with None API key raises AuthenticationError."""
        provider = GrokProvider()
        none_creds = ProviderCredentials(api_key=None)

        with pytest.raises(AuthenticationError):
            await provider.connect(none_creds)

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_without_connection_raises_error() -> None:
        """Test list_models raises error when not connected."""
        provider = GrokProvider()

        with pytest.raises(ProviderError):
            await provider.list_models()

    @pytest.mark.asyncio
    @staticmethod
    async def test_disconnect_clears_connection_state(
        credential_loader: CredentialLoader,
        *,
        has_grok_key: bool,
    ) -> None:
        """Test disconnect properly clears connection state.

        Args:
            credential_loader: Credential loader fixture.
            has_grok_key: Whether a Grok (X.AI) API key is configured.
        """
        if not has_grok_key:
            pytest.skip("XAI_API_KEY not configured")

        provider = GrokProvider()
        credentials = credential_loader.get_credentials(ProviderName.GROK)
        assert credentials is not None

        await provider.connect(credentials)
        assert provider.is_connected is True

        await provider.disconnect()
        assert provider.is_connected is False
