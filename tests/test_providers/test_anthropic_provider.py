# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Integration tests for the Anthropic provider bridge.

The credential-validation and not-connected error paths run unconditionally
with no network or API key and assert the exact provider error contract, so
they gate real behaviour even on a machine with no credentials.

The live model-listing tests drive the real Anthropic ``/v1/models`` endpoint
through :class:`AnthropicProvider` and assert against independently-known
facts about Anthropic's catalogue (every id is a ``claude-*`` slug, the
opus/sonnet/haiku families are represented, display names come from the API)
plus the provider's own ``ModelInfo`` mapping contract (200k context window,
tool / vision / streaming capabilities). They require ``ANTHROPIC_API_KEY``;
the ``anthropic_provider`` fixture skips with an explicit message when it is
absent rather than passing vacuously.
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


# Independently-known facts about Anthropic's published model catalogue. These
# are not read from the provider implementation; they describe the live API's
# naming scheme and the model families Anthropic ships, which the bridge must
# surface faithfully.
_CLAUDE_ID_PREFIX: str = "claude-"
_CLAUDE_DISPLAY_PREFIX: str = "Claude"
_REQUIRED_MODEL_FAMILIES: tuple[str, ...] = ("opus", "sonnet", "haiku")

# Provider mapping contract asserted on every live model. _build_model_info
# maps each API model into a ModelInfo with these exact values; a regression
# that zeroed the context window or dropped a capability flag breaks here.
_EXPECTED_CONTEXT_WINDOW: int = 200000

# Exact provider error-contract strings (anthropic._MSG_* constants).
_MSG_API_KEY_REQUIRED: str = "API key required"
_MSG_INVALID_API_KEY: str = "Invalid API key"
_MSG_NOT_CONNECTED: str = "Not connected"


@pytest.mark.integration
class TestAnthropicModelListing:
    """Live model-listing gates for :class:`AnthropicProvider`.

    Every test drives the real Anthropic ``/v1/models`` endpoint and asserts
    against independently-known catalogue facts and the provider's
    ``ModelInfo`` mapping contract. No model names are copied from the
    implementation; the IDs and display names are produced by the live API.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_live_catalogue_exposes_claude_families_with_api_display_names(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Listed models are real Claude slugs with API display names across families.

        Asserts the bridge returns a non-empty list of distinct
        :class:`ModelInfo` whose ids all follow Anthropic's ``claude-*``
        slug scheme, whose display names are the API-supplied human labels
        (independent of the provider, which only forwards ``display_name``),
        and that the opus, sonnet and haiku families are all represented -
        an independently-known fact about Anthropic's live catalogue.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        models = await anthropic_provider.list_models()

        assert models, "live Anthropic catalogue returned no models"
        assert all(isinstance(m, ModelInfo) for m in models), "every entry must be a ModelInfo"

        ids = [m.id for m in models]
        assert len(ids) == len(set(ids)), f"model ids must be unique, got {ids}"
        assert all(model_id.startswith(_CLAUDE_ID_PREFIX) for model_id in ids), (
            f"every Anthropic model id must start with {_CLAUDE_ID_PREFIX!r}; got {ids}"
        )
        assert all(m.name.startswith(_CLAUDE_DISPLAY_PREFIX) for m in models), (
            f"display names come from the API and start with {_CLAUDE_DISPLAY_PREFIX!r}; got {[m.name for m in models]}"
        )

        joined = " ".join(ids)
        for family in _REQUIRED_MODEL_FAMILIES:
            assert family in joined, f"Anthropic catalogue must include a {family!r} model; got {ids}"

    @pytest.mark.asyncio
    @staticmethod
    async def test_every_live_model_maps_to_full_capability_contract(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Each live model is mapped to the provider's full ModelInfo contract.

        The bridge maps every API model into a ``ModelInfo`` reporting the
        Anthropic provider, a 200k-token context window and tool / vision /
        streaming support. Asserting the full record on every live model
        catches any regression in :meth:`AnthropicProvider._build_model_info`
        (a zeroed context window, a dropped capability, a mislabelled
        provider) rather than merely that fields exist.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        models = await anthropic_provider.list_models()

        assert models, "live Anthropic catalogue returned no models"
        for model in models:
            assert model.provider == ProviderName.ANTHROPIC, f"{model.id}: wrong provider {model.provider}"
            assert model.context_window == _EXPECTED_CONTEXT_WINDOW, (
                f"{model.id}: context_window {model.context_window} != {_EXPECTED_CONTEXT_WINDOW}"
            )
            assert model.supports_tools is True, f"{model.id}: supports_tools must be True"
            assert model.supports_vision is True, f"{model.id}: supports_vision must be True"
            assert model.supports_streaming is True, f"{model.id}: supports_streaming must be True"
            assert model.id, f"{model.id!r}: id must be non-empty"
            assert model.name, f"{model.id}: name must be non-empty"

    @pytest.mark.asyncio
    @staticmethod
    async def test_pagination_collects_full_catalogue_consistently(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Repeated listings return the identical, fully-paginated id set.

        ``_fetch_all_models`` paginates the endpoint until ``has_more`` is
        false. Two back-to-back calls must therefore yield the exact same
        set of ids; a pagination bug that dropped the final page or looped
        would surface as a mismatch.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        first = await anthropic_provider.list_models()
        second = await anthropic_provider.list_models()

        ids_first = {m.id for m in first}
        ids_second = {m.id for m in second}

        assert ids_first == ids_second, f"pagination must be stable: {ids_first ^ ids_second} differed"
        assert len(first) == len(ids_first), "a single listing must not contain duplicate ids"


@pytest.mark.integration
class TestAnthropicConnectionContract:
    """Provider connection / error-path gates.

    The credential-rejection and not-connected paths require no network and
    no API key, so they gate the real provider contract unconditionally and
    assert the exact error type and message string the provider raises.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_empty_key_rejected_before_any_network_call() -> None:
        """An empty API key is rejected synchronously with the exact contract message.

        ``connect`` must reject a blank key before constructing a client or
        touching the network, raising ``AuthenticationError`` with the
        ``"API key required"`` message and leaving the provider disconnected.
        """
        provider = AnthropicProvider()

        with pytest.raises(AuthenticationError) as exc_info:
            await provider.connect(ProviderCredentials(api_key=""))

        assert str(exc_info.value) == _MSG_API_KEY_REQUIRED
        assert provider.is_connected is False

    @pytest.mark.asyncio
    @staticmethod
    async def test_none_key_rejected_before_any_network_call() -> None:
        """A ``None`` API key is rejected synchronously with the exact contract message.

        A missing key must raise ``AuthenticationError("API key required")``
        without a network call, leaving the provider disconnected.
        """
        provider = AnthropicProvider()

        with pytest.raises(AuthenticationError) as exc_info:
            await provider.connect(ProviderCredentials(api_key=None))

        assert str(exc_info.value) == _MSG_API_KEY_REQUIRED
        assert provider.is_connected is False

    @pytest.mark.asyncio
    @staticmethod
    async def test_invalid_key_rejected_by_live_api_with_contract_message() -> None:
        """A well-formed but invalid key is rejected by the live API and surfaced.

        A syntactically valid ``sk-ant-`` key that the live API does not
        recognise must be rejected by the real ``/v1/models`` probe inside
        ``connect`` and re-raised as ``AuthenticationError("Invalid API
        key")`` - proving the provider both performs the live validation and
        normalises the SDK error to its own contract. The provider must
        remain disconnected.
        """
        provider = AnthropicProvider()

        with pytest.raises(AuthenticationError) as exc_info:
            await provider.connect(ProviderCredentials(api_key="sk-ant-api03-invalid-key-for-rejection-test"))

        assert str(exc_info.value) == _MSG_INVALID_API_KEY
        assert provider.is_connected is False

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_without_connection_raises_not_connected() -> None:
        """Listing models before connecting raises the exact not-connected error.

        ``list_models`` must guard on the connection state and raise
        ``ProviderError("Not connected")`` rather than attempting an
        API call against a ``None`` client.
        """
        provider = AnthropicProvider()

        with pytest.raises(ProviderError) as exc_info:
            await provider.list_models()

        assert str(exc_info.value) == _MSG_NOT_CONNECTED

    @pytest.mark.asyncio
    @staticmethod
    async def test_connected_provider_reports_identity_then_clears_on_disconnect(
        credential_loader: CredentialLoader,
        *,
        has_anthropic_key: bool,
    ) -> None:
        """A live connect reports Anthropic identity; disconnect clears the state.

        Drives the real connect/disconnect lifecycle: after connecting with
        the configured key the provider reports ``ProviderName.ANTHROPIC``
        and ``is_connected`` True; after ``disconnect`` it reports
        ``is_connected`` False and refuses further model listings with the
        not-connected contract error.

        Args:
            credential_loader: Credential loader fixture.
            has_anthropic_key: Whether an Anthropic API key is configured.
        """
        if not has_anthropic_key:
            pytest.skip("ANTHROPIC_API_KEY not configured in .env")

        provider = AnthropicProvider()
        credentials = credential_loader.get_credentials(ProviderName.ANTHROPIC)
        assert credentials is not None, "expected credentials once has_anthropic_key is True"

        await provider.connect(credentials)
        assert provider.is_connected is True
        assert provider.name == ProviderName.ANTHROPIC

        await provider.disconnect()
        assert provider.is_connected is False

        with pytest.raises(ProviderError) as exc_info:
            await provider.list_models()
        assert str(exc_info.value) == _MSG_NOT_CONNECTED
