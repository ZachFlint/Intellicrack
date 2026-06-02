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
from huggingface_hub import ModelInfo as HfModelInfo


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
    async def test_list_models_returns_fully_valid_model_records(
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test every returned record is a well-formed, unique ModelInfo.

        Drives the real HuggingFace Hub bridge and asserts that EVERY item (not a
        sampled prefix) is a ``ModelInfo`` carrying a non-empty, non-whitespace id,
        a non-empty name, the ``HUGGINGFACE`` provider, a positive context window,
        boolean capability flags, and ``supports_streaming`` True (which the
        provider hard-codes for every HF model). Also asserts all ids are unique,
        matching the de-duplication contract of ``_build_model_info_list``. A
        parser that emitted ``[None, None]`` or duplicates would fail here.

        Args:
            huggingface_provider: Connected HuggingFace provider fixture.
        """
        models = await huggingface_provider.list_models()

        assert isinstance(models, list), f"Expected list, got {type(models)}"
        assert len(models) >= 1, "Expected at least one model from HuggingFace API"

        ids: list[str] = []
        for model in models:
            assert isinstance(model, ModelInfo), f"Expected ModelInfo, got {type(model)}"
            assert isinstance(model.id, str), f"id not str: {model.id!r}"
            assert model.id.strip(), f"Invalid id: {model.id!r}"
            assert isinstance(model.name, str), f"name not str: {model.name!r}"
            assert model.name.strip(), f"Invalid name: {model.name!r}"
            assert model.provider == ProviderName.HUGGINGFACE, f"Wrong provider: {model.provider}"
            assert isinstance(model.context_window, int), f"ctx not int: {model.context_window!r}"
            assert model.context_window > 0, f"ctx not positive: {model.context_window}"
            assert isinstance(model.supports_tools, bool)
            assert isinstance(model.supports_vision, bool)
            assert model.supports_streaming is True, "HF provider marks all models streamable"
            ids.append(model.id)

        assert len(ids) == len(set(ids)), "Model ids must be unique (de-duplicated)"

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
    async def test_all_model_ids_match_hub_naming_and_derive_name(
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test EVERY model id is a valid Hub identifier and drives the short name.

        Iterates the entire returned list (not a 20-item prefix) so a corrupted id
        anywhere fails. Each id must be a non-whitespace string with no embedded
        spaces and at most one path separator, matching real HuggingFace repo
        naming (``org/model`` or a bare name). Independently re-derives the
        expected short name as the segment after the final ``/`` and asserts the
        provider's ``ModelInfo.name`` equals it for every record.

        Args:
            huggingface_provider: Connected HuggingFace provider fixture.
        """
        models = await huggingface_provider.list_models()

        for model in models:
            assert isinstance(model.id, str), f"Expected str id, got {type(model.id)}"
            assert model.id == model.id.strip(), f"id has surrounding whitespace: {model.id!r}"
            assert model.id, "Model ID should not be empty"
            assert " " not in model.id, f"Hub ids contain no spaces: {model.id!r}"
            assert model.id.count("/") <= 1, f"Hub ids have at most one separator: {model.id!r}"

            expected_short = model.id.rsplit("/", maxsplit=1)[-1] if "/" in model.id else model.id
            assert model.name == expected_short, f"name {model.name!r} should be tail of id {model.id!r}"

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


_HF_DEFAULT_CONTEXT_WINDOW = 4096


class TestModelInfoNormalization:
    """Deterministic gates for the Hub-record normalization bridge.

    These tests exercise the real production normaliser
    ``HuggingFaceProvider.build_model_info_list`` against genuine
    ``huggingface_hub.ModelInfo`` records (the exact record type ``HfApi``
    yields), with no network access and no mocking of the operation under
    test. Expected ``ModelInfo`` values are derived independently from the
    HuggingFace tag conventions, not copied from the implementation output.
    """

    @staticmethod
    def test_text_model_maps_to_expected_model_info() -> None:
        """A plain text-generation record normalises to exact ModelInfo fields."""
        raw = [HfModelInfo(id="meta-llama/Meta-Llama-3-8B-Instruct", pipeline_tag="text-generation", tags=["text-generation"])]

        result = HuggingFaceProvider.build_model_info_list(raw)

        assert len(result) == 1
        info = result[0]
        assert info.id == "meta-llama/Meta-Llama-3-8B-Instruct"
        assert info.name == "Meta-Llama-3-8B-Instruct"
        assert info.provider == ProviderName.HUGGINGFACE
        assert info.context_window == _HF_DEFAULT_CONTEXT_WINDOW
        assert info.supports_tools is False
        assert info.supports_vision is False
        assert info.supports_streaming is True
        assert info.input_cost_per_1m_tokens is None
        assert info.output_cost_per_1m_tokens is None

    @staticmethod
    def test_function_calling_tag_sets_supports_tools() -> None:
        """A record tagged for function calling enables supports_tools only."""
        raw = [HfModelInfo(id="org/tooling-model", pipeline_tag="text-generation", tags=["text-generation", "function-calling"])]

        info = HuggingFaceProvider.build_model_info_list(raw)[0]

        assert info.supports_tools is True
        assert info.supports_vision is False

    @staticmethod
    def test_vision_pipeline_sets_supports_vision() -> None:
        """An image-text-to-text pipeline enables supports_vision via pipeline tag."""
        raw = [HfModelInfo(id="org/vlm-model", pipeline_tag="image-text-to-text", tags=["multimodal"])]

        info = HuggingFaceProvider.build_model_info_list(raw)[0]

        assert info.supports_vision is True
        assert info.supports_tools is False

    @staticmethod
    def test_bare_id_without_separator_uses_full_id_as_name() -> None:
        """A separator-less id is used verbatim as the model name."""
        raw = [HfModelInfo(id="gpt2", pipeline_tag="text-generation", tags=[])]

        info = HuggingFaceProvider.build_model_info_list(raw)[0]

        assert info.id == "gpt2"
        assert info.name == "gpt2"

    @staticmethod
    def test_duplicate_ids_are_deduplicated_preserving_order() -> None:
        """Duplicate ids collapse to one entry, keeping first-seen order."""
        raw = [
            HfModelInfo(id="org/a", pipeline_tag="text-generation", tags=[]),
            HfModelInfo(id="org/b", pipeline_tag="text-generation", tags=[]),
            HfModelInfo(id="org/a", pipeline_tag="text-generation", tags=[]),
        ]

        result = HuggingFaceProvider.build_model_info_list(raw)

        assert [m.id for m in result] == ["org/a", "org/b"]

    @staticmethod
    def test_empty_id_record_is_dropped() -> None:
        """A record whose id is the empty string is excluded entirely."""
        raw = [
            HfModelInfo(id="", pipeline_tag="text-generation", tags=[]),
            HfModelInfo(id="org/keep", pipeline_tag="text-generation", tags=[]),
        ]

        result = HuggingFaceProvider.build_model_info_list(raw)

        assert [m.id for m in result] == ["org/keep"]

    @staticmethod
    def test_empty_input_yields_empty_list() -> None:
        """Normalising an empty record list returns an empty list."""
        assert HuggingFaceProvider.build_model_info_list([]) == []
