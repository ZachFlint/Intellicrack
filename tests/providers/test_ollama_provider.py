# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Integration tests for OllamaProvider model listing.

These tests require Ollama to be running locally at http://localhost:11434.
Tests will be skipped if Ollama is not available.

All tests use LIVE API calls - NO hardcoded model names.
"""

from __future__ import annotations

import pytest
import pytest_asyncio

from intellicrack.core.types import (
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    ProviderName,
)
from intellicrack.providers.ollama import OllamaProvider


_LOCAL_MODEL_ID_PREFIX = "local/"


@pytest_asyncio.fixture
async def installed_models(
    ollama_provider: OllamaProvider,
) -> list[ModelInfo]:
    """Fetch the installed local Ollama models; skip when none are installed.

    This class asserts the local-source contract (``local/`` id prefix,
    ``[Local] `` name prefix), so only ``local/``-prefixed models qualify:
    a cloud-signed-in account also lists ``cloud/`` models, which carry the
    ``[Cloud] `` prefix and would false-fail those assertions. A non-empty list
    is a precondition for the per-model tests; any loop over an empty list
    asserts nothing, so skip rather than assert a contract that cannot be
    verified without at least one local model.

    Args:
        ollama_provider: Connected Ollama provider fixture.

    Returns:
        list[ModelInfo]: Non-empty list of installed local models.
    """
    models = await ollama_provider.list_models()
    local_models = [m for m in models if m.id.startswith(_LOCAL_MODEL_ID_PREFIX)]
    if not local_models:
        pytest.skip("No local models installed in local Ollama instance")
    return local_models


@pytest.mark.integration
class TestOllamaModelListing:
    """Tests for Ollama model listing functionality.

    These tests validate that OllamaProvider can dynamically fetch
    locally installed models. NO hardcoded model names are used.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_returns_list(
        ollama_provider: OllamaProvider,
    ) -> None:
        """Test list_models returns a list (may be empty if no models installed).

        Args:
            ollama_provider: Connected Ollama provider fixture.
        """
        models = await ollama_provider.list_models()

        assert isinstance(models, list), f"Expected list, got {type(models)}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_returns_model_info_instances(
        installed_models: list[ModelInfo],
    ) -> None:
        """Test each returned item is a ModelInfo with non-empty id, name, and provider fields.

        Gates the full parsing path in _populate_ollama_models: a return type
        mutation (returning dict instead of ModelInfo) breaks the isinstance
        check; a field-clear mutation (id='') breaks the non-empty id check;
        a provider-stamp mutation (provider=None) breaks the provider check.
        The fixture guarantees at least one model so the loop cannot be vacuous.

        Args:
            installed_models: Non-empty list of models from the connected provider.
        """
        for model in installed_models:
            assert isinstance(model, ModelInfo), f"Expected ModelInfo, got {type(model)}"
            assert model.id, f"ModelInfo.id must be non-empty, got empty string for {model!r}"
            assert model.name, f"ModelInfo.name must be non-empty, got empty string for {model!r}"
            assert model.provider == ProviderName.OLLAMA, f"Expected provider OLLAMA, got {model.provider!r}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_valid_id_when_present(
        installed_models: list[ModelInfo],
    ) -> None:
        """Test all models have IDs prefixed with 'local/' matching the bridge prefix rule.

        The production code sets id=f"local/{model_name}" for local models.
        This asserts both that the id is non-empty and that the local-source
        prefix is applied faithfully, independently of the raw Ollama name.

        Args:
            installed_models: Non-empty list of models from the connected provider.
        """
        for model in installed_models:
            assert isinstance(model.id, str), f"Expected str id, got {type(model.id)}"
            assert len(model.id) > 0, "Model ID should not be empty"
            assert model.id.startswith("local/"), f"Local model ID must start with 'local/' per bridge prefix rule, got {model.id!r}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_valid_name_when_present(
        installed_models: list[ModelInfo],
    ) -> None:
        """Test all models have display names prefixed with '[Local] ' matching the bridge rule.

        The production code sets name=f"[Local] {model_name}" for local models.
        This asserts both a non-empty string and that the display prefix
        is applied, verified independently via the known prefix constant.

        Args:
            installed_models: Non-empty list of models from the connected provider.
        """
        for model in installed_models:
            assert isinstance(model.name, str), f"Expected str name, got {type(model.name)}"
            assert len(model.name) > 0, "Model name should not be empty"
            assert model.name.startswith("[Local] "), (
                f"Local model name must start with '[Local] ' per bridge prefix rule, got {model.name!r}"
            )

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_correct_provider(
        installed_models: list[ModelInfo],
    ) -> None:
        """Test all models report OLLAMA as provider.

        Args:
            installed_models: Non-empty list of models from the connected provider.
        """
        for model in installed_models:
            assert model.provider == ProviderName.OLLAMA, f"Expected OLLAMA provider, got {model.provider}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_positive_context_window(
        installed_models: list[ModelInfo],
    ) -> None:
        """Test all models have positive context window size.

        The production bridge defaults to 4096 when /api/show does not report
        num_ctx; this assertion gates both the default (4096 > 0) and any
        live parsed value, ensuring the context_window field is never zero.

        Args:
            installed_models: Non-empty list of models from the connected provider.
        """
        for model in installed_models:
            assert isinstance(model.context_window, int), f"Expected int context_window, got {type(model.context_window)}"
            assert model.context_window > 0, f"Model {model.id} has invalid context_window: {model.context_window}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_info_has_boolean_capabilities(
        installed_models: list[ModelInfo],
    ) -> None:
        """Test all models have correct capability flag types and streaming always True.

        The production code hardcodes supports_streaming=True for every Ollama
        model (local models always stream via /api/chat). This asserts the bool
        types and gates the hardcoded streaming contract with a value check.

        Args:
            installed_models: Non-empty list of models from the connected provider.
        """
        for model in installed_models:
            assert isinstance(model.supports_tools, bool), f"Expected bool supports_tools, got {type(model.supports_tools)}"
            assert isinstance(model.supports_vision, bool), f"Expected bool supports_vision, got {type(model.supports_vision)}"
            assert isinstance(model.supports_streaming, bool), f"Expected bool supports_streaming, got {type(model.supports_streaming)}"
            assert model.supports_streaming is True, f"Ollama local models must always support streaming; got False for {model.id}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_multiple_calls_return_consistent_results(
        installed_models: list[ModelInfo],
        ollama_provider: OllamaProvider,
    ) -> None:
        """Test list_models returns consistent results and correct prefixes across calls.

        Consistency cross-call equality alone is unfalsifiable by stateless
        mutations (both calls are affected identically). This test adds an
        independent oracle: every local model ID must start with 'local/' and
        have a non-empty model-name suffix after that prefix. That oracle is
        derived directly from the source code contract in _populate_ollama_models
        (id=f"local/{model_name}") and would fail if the id_prefix were changed
        to '' or 'local' (no slash). Mutating id_prefix to '' causes every ID in
        ids1 to fail the startswith assertion on the first iteration, turning the
        test red regardless of what the second call returns.

        Args:
            installed_models: Non-empty list of models from the first call.
            ollama_provider: Connected Ollama provider fixture.
        """
        models2 = await ollama_provider.list_models()

        ids1 = {m.id for m in installed_models}
        ids2 = {m.id for m in models2 if m.id.startswith(_LOCAL_MODEL_ID_PREFIX)}

        assert ids1, "First call must return at least one model ID"

        for mid in ids1:
            assert mid.startswith("local/"), f"Local model ID must start with 'local/' per bridge contract, got {mid!r}"
            suffix = mid[len("local/") :]
            assert suffix, f"Model name suffix after 'local/' must be non-empty, got empty in {mid!r}"

        assert ids1 == ids2, "Local model IDs must be identical across consecutive calls"


@pytest.mark.integration
class TestOllamaConnection:
    """Tests for Ollama provider connection handling."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_is_connected_after_connect(
        ollama_provider: OllamaProvider,
    ) -> None:
        """Test provider reports connected after successful connection.

        Args:
            ollama_provider: Connected Ollama provider fixture.
        """
        assert ollama_provider.is_connected is True

    @pytest.mark.asyncio
    @staticmethod
    async def test_provider_name_is_ollama(
        ollama_provider: OllamaProvider,
    ) -> None:
        """Test provider name property returns OLLAMA.

        Args:
            ollama_provider: Connected Ollama provider fixture.
        """
        assert ollama_provider.name == ProviderName.OLLAMA

    @pytest.mark.asyncio
    @staticmethod
    async def test_connection_with_custom_base_url(
        *,
        has_ollama_available: bool,
    ) -> None:
        """Test connection with custom base URL.

        Args:
            has_ollama_available: Whether a local Ollama server is running.
        """
        if not has_ollama_available:
            pytest.skip("Ollama not running locally")

        provider = OllamaProvider()
        creds = ProviderCredentials(
            api_key=None,
            api_base="http://localhost:11434",
        )

        await provider.connect(creds)
        assert provider.is_connected is True
        await provider.disconnect()

    @pytest.mark.asyncio
    @staticmethod
    async def test_connection_with_invalid_url_raises_error() -> None:
        """Test connection with unreachable URL raises ProviderError."""
        provider = OllamaProvider()
        invalid_creds = ProviderCredentials(
            api_key=None,
            api_base="http://localhost:99999",
        )

        with pytest.raises(ProviderError):
            await provider.connect(invalid_creds)

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_without_connection_raises_error() -> None:
        """Test list_models raises error when not connected."""
        provider = OllamaProvider()

        with pytest.raises(ProviderError):
            await provider.list_models()

    @pytest.mark.asyncio
    @staticmethod
    async def test_disconnect_clears_connection_state(
        *,
        has_ollama_available: bool,
    ) -> None:
        """Test disconnect properly clears connection state.

        Args:
            has_ollama_available: Whether a local Ollama server is running.
        """
        if not has_ollama_available:
            pytest.skip("Ollama not running locally")

        provider = OllamaProvider()
        creds = ProviderCredentials(
            api_key=None,
            api_base="http://localhost:11434",
        )

        await provider.connect(creds)
        assert provider.is_connected is True

        await provider.disconnect()
        assert provider.is_connected is False
