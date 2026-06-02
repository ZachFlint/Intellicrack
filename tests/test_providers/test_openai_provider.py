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

import socket
from typing import TYPE_CHECKING

import openai
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


# Known-correct production error strings. These mirror the user-visible
# contract of OpenAIProvider; asserting against the literal text (rather than
# importing the private module constant) keeps the test an independent oracle:
# if the production message regresses, the assertion fails.
_KEY_REQUIRED_MESSAGE = "OpenAI API key is required"
_INVALID_KEY_PREFIX = "Invalid OpenAI API key:"
_NOT_CONNECTED_MESSAGE = "Not connected to OpenAI API"

# A syntactically plausible OpenAI secret key that is guaranteed to be rejected
# by the live ``/models`` endpoint with HTTP 401. It is not a real key.
_BOGUS_API_KEY = "sk-intellicrack-invalid-key-000000000000000000000000"

_OPENAI_API_HOST = "api.openai.com"
_OPENAI_API_PORT = 443


def _openai_api_reachable() -> bool:
    """Return whether ``api.openai.com:443`` accepts a TCP connection.

    The invalid-key path can only be exercised against the live OpenAI
    authentication endpoint. Network reachability is a genuine environment
    precondition (not an Intellicrack defect), so the live test skips only when
    the endpoint cannot be reached.

    Returns:
        bool: ``True`` when a TCP connection to the OpenAI API host succeeds.
    """
    try:
        with socket.create_connection((_OPENAI_API_HOST, _OPENAI_API_PORT), timeout=5.0):
            return True
    except OSError:
        return False


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
    async def test_connection_with_invalid_key_maps_live_401_to_authentication_error() -> None:
        """Test a live invalid-key connection maps OpenAI's 401 to AuthenticationError.

        Drives the full real ``connect`` path against the live OpenAI
        ``/models`` endpoint with a bogus key. The endpoint returns HTTP 401,
        which the provider must surface as ``AuthenticationError`` carrying the
        ``Invalid OpenAI API key:`` message and chaining the underlying
        ``openai.AuthenticationError`` (whose ``status_code`` is 401). The
        provider must also reset its connection state so no half-open client
        leaks. Skips only when the OpenAI API host is unreachable - a genuine
        environment precondition.
        """
        if not _openai_api_reachable():
            pytest.skip(f"{_OPENAI_API_HOST} unreachable; live 401 path cannot be exercised")

        provider = OpenAIProvider()
        invalid_creds = ProviderCredentials(api_key=_BOGUS_API_KEY)

        with pytest.raises(AuthenticationError) as exc_info:
            await provider.connect(invalid_creds)

        message = str(exc_info.value)
        assert message.startswith(_INVALID_KEY_PREFIX), f"unexpected AuthenticationError text: {message!r}"

        cause = exc_info.value.__cause__
        assert isinstance(cause, openai.AuthenticationError), f"expected chained openai.AuthenticationError, got {type(cause)!r}"
        assert cause.status_code == 401, f"live invalid key must yield HTTP 401, got {cause.status_code}"

        assert provider.is_connected is False, "failed auth must leave provider disconnected"
        assert provider.client is None, "failed auth must clear the underlying OpenAI client"

    @pytest.mark.asyncio
    @staticmethod
    async def test_connection_with_empty_key_rejected_before_any_network_call() -> None:
        """Test an empty API key is rejected by local validation before connecting.

        An empty key must fail fast with ``AuthenticationError`` carrying the
        exact ``OpenAI API key is required`` message, and the provider must
        never construct an OpenAI client or mark itself connected. This proves
        the local pre-connection key guard runs (rather than deferring to a
        network round-trip that would surface a different error).
        """
        provider = OpenAIProvider()
        empty_creds = ProviderCredentials(api_key="")

        with pytest.raises(AuthenticationError) as exc_info:
            await provider.connect(empty_creds)

        assert str(exc_info.value) == _KEY_REQUIRED_MESSAGE
        assert provider.client is None, "empty key must not construct an OpenAI client"
        assert provider.is_connected is False, "empty key must not mark the provider connected"

    @pytest.mark.asyncio
    @staticmethod
    async def test_connection_with_none_key_rejected_before_any_network_call() -> None:
        """Test a ``None`` API key is rejected with the same fast-fail guard.

        Boundary companion to the empty-string case: a ``None`` key (the
        dataclass default) must also raise ``AuthenticationError`` with the
        exact required-key message and leave no client behind.
        """
        provider = OpenAIProvider()
        none_creds = ProviderCredentials(api_key=None)

        with pytest.raises(AuthenticationError) as exc_info:
            await provider.connect(none_creds)

        assert str(exc_info.value) == _KEY_REQUIRED_MESSAGE
        assert provider.client is None
        assert provider.is_connected is False

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_without_connection_raises_specific_error() -> None:
        """Test list_models on a fresh provider raises the not-connected error.

        A newly constructed provider must report ``is_connected is False`` and
        hold no client. Calling ``list_models`` in that state must raise
        ``ProviderError`` with the exact ``Not connected to OpenAI API``
        message - proving the not-connected guard fired rather than an
        unrelated failure.
        """
        provider = OpenAIProvider()

        assert provider.is_connected is False, "a fresh provider must start disconnected"
        assert provider.client is None, "a fresh provider must hold no OpenAI client"

        with pytest.raises(ProviderError) as exc_info:
            await provider.list_models()

        assert str(exc_info.value) == _NOT_CONNECTED_MESSAGE
        assert provider.is_connected is False, "a failed list_models must not flip the connection flag"

    @pytest.mark.asyncio
    @staticmethod
    async def test_disconnect_clears_connection_state(
        credential_loader: CredentialLoader,
        *,
        has_openai_key: bool,
    ) -> None:
        """Test disconnect releases the client, not just the connected flag.

        After a real connect (which performs a live ``/models`` round-trip and
        leaves ``provider.client`` populated), ``disconnect`` must tear down the
        underlying OpenAI client, not merely toggle a boolean. The gate proves
        real teardown two ways: ``provider.client`` becomes ``None``, and a
        subsequent ``list_models`` raises ``ProviderError`` with the exact
        ``Not connected to OpenAI API`` message - which can only happen if the
        not-connected guard sees a genuinely torn-down client. A disconnect that
        flipped only the flag would leave ``provider.client`` non-``None`` and
        fail these assertions.

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
        assert provider.is_connected is True
        assert provider.client is not None, "a live connect must construct the OpenAI client"

        await provider.disconnect()

        assert provider.is_connected is False
        assert provider.client is None, "disconnect must release the underlying OpenAI client"

        with pytest.raises(ProviderError) as exc_info:
            await provider.list_models()
        assert str(exc_info.value) == _NOT_CONNECTED_MESSAGE
